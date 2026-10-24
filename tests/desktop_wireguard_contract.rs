use std::fs;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;

#[path = "desktop_wireguard/fixture.rs"]
mod fixture;
use fixture::{private_file, private_secret_file, Behavior, Fixture};

#[cfg(target_os = "linux")]
#[path = "desktop_wireguard/linux.rs"]
mod linux;

#[test]
fn review_is_local_only_and_confirmation_binds_every_identity() {
    let fixture = Fixture::new(Behavior::default());
    let output = fixture.temp.path().join("custom/missing/client.conf");
    let before = fs::read_dir(&fixture.home).unwrap().count();
    let plan = fixture.plan(Some(&output));
    assert_eq!(plan["plan_version"], 1);
    assert_eq!(plan["output"]["action"], "create");
    assert_eq!(
        plan["output"]["missing_directories"],
        json!(["custom", "missing"])
    );
    assert_eq!(
        plan["output"]["anchor_identity"].as_str().unwrap().len(),
        64
    );
    assert!(plan["output"]["target_identity"].is_null());
    assert!(!output.parent().unwrap().exists());
    assert!(!fixture.private_path().exists());
    assert!(!fixture.temp.path().join("locks").exists());
    assert_eq!(fs::read_dir(&fixture.home).unwrap().count(), before);
    assert!(fixture.requests.lock().unwrap().is_empty());
    let (ok, denied) = fixture.invoke(
        "wireguard.config.apply",
        json!({"confirmed":false,"expected_plan":plan}),
    );
    assert!(!ok);
    assert_eq!(denied["error"]["code"], "confirmation_required");
    let mut changed = plan.clone();
    changed["context"]["active_device_id"] = json!("other-device");
    let (ok, denied) = fixture.invoke(
        "wireguard.config.apply",
        json!({"confirmed":true,"expected_plan":changed}),
    );
    assert!(!ok);
    assert_eq!(denied["error"]["code"], "configuration_changed");
    let mut changed = plan;
    changed["output"]["anchor_identity"] = json!("0".repeat(64));
    let (ok, denied) = fixture.invoke(
        "wireguard.config.apply",
        json!({"confirmed":true,"expected_plan":changed}),
    );
    assert!(!ok);
    assert_eq!(denied["error"]["code"], "output_changed");
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(!fixture.private_path().exists());
    assert!(!output.parent().unwrap().exists());
}

#[test]
fn confirmed_plan_requires_explicit_target_identity_even_for_new_files() {
    let fixture = Fixture::new(Behavior::default());
    let mut plan = fixture.plan(None);
    plan["output"]
        .as_object_mut()
        .unwrap()
        .remove("target_identity");
    let (ok, result) = fixture.invoke(
        "wireguard.config.apply",
        json!({"confirmed":true,"expected_plan":plan}),
    );
    assert!(!ok);
    assert_eq!(result["error"]["code"], "invalid_params");
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(!fixture.private_path().exists());
}

#[test]
fn malformed_or_oversized_success_bodies_preserve_known_enrollment_stage() {
    for body in ["{malformed-json".to_owned(), " ".repeat(1024 * 1024 + 1)] {
        for after_enrollment in [false, true] {
            let behavior = if after_enrollment {
                Behavior {
                    config_body: Some(body.clone()),
                    ..Default::default()
                }
            } else {
                Behavior {
                    enroll_body: Some(body.clone()),
                    ..Default::default()
                }
            };
            let fixture = Fixture::new(behavior);
            let output = fixture.home.join("wireguard/agent-remote.conf");
            private_file(&output, b"retained-old-config");
            let result = fixture.apply(fixture.plan(None));
            assert_eq!(result["complete"], false);
            assert_eq!(result["key_state"], "created");
            assert_eq!(result["publication"], "not_attempted");
            assert_eq!(
                result["enrollment"],
                if after_enrollment {
                    "not_attempted"
                } else {
                    "unknown"
                }
            );
            assert_eq!(
                result["code"],
                if after_enrollment {
                    "wireguard_config_unavailable"
                } else {
                    "wireguard_enrollment_unknown"
                }
            );
            assert_eq!(
                fixture.requests.lock().unwrap().len(),
                if after_enrollment { 1 } else { 2 }
            );
            assert_eq!(fs::read(&output).unwrap(), b"retained-old-config");
            assert!(fixture.private_path().is_file());
        }
    }
}

#[test]
fn new_custom_output_and_replacement_share_a_retained_private_key() {
    let fixture = Fixture::new(Behavior::default());
    let output = fixture.temp.path().join("custom/client.conf");
    let first = fixture.apply(fixture.plan(Some(&output)));
    assert_eq!(first["complete"], true);
    assert_eq!(first["key_state"], "created");
    assert_eq!(first["enrollment"], "confirmed");
    assert_eq!(first["publication"], "published");
    assert_eq!(first["peer_count"], 0);
    let key = fs::read_to_string(fixture.private_path()).unwrap();
    let contents = fs::read_to_string(&output).unwrap();
    assert!(contents.contains(&format!("PrivateKey = {key}")));
    assert!(!first.to_string().contains(&key));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let second_plan = fixture.plan(Some(&output));
    assert_eq!(second_plan["output"]["action"], "replace");
    assert_eq!(
        second_plan["output"]["target_identity"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let second = fixture.apply(second_plan);
    assert_eq!(second["complete"], true);
    assert_eq!(second["key_state"], "reused");
    assert_eq!(fs::read_to_string(fixture.private_path()).unwrap(), key);
    assert_eq!(fs::read_to_string(&output).unwrap(), contents);
    let calls = fixture.requests.lock().unwrap();
    assert_eq!(calls.len(), 6);
    for (_, body) in calls
        .iter()
        .filter(|(path, _)| path.contains("/wireguard/peer"))
    {
        assert_eq!(body.as_object().unwrap().len(), 4);
        assert_eq!(
            body["public_key"],
            agent_remote_cli::wireguard::public_key_from_private(&key).unwrap()
        );
        assert_eq!(body["expected_peer_id"], "peer-test");
        assert_eq!(body["expected_peer_version"], 1);
        let expected_public_key = body["expected_public_key"].as_str().unwrap();
        assert_eq!(STANDARD.decode(expected_public_key).unwrap().len(), 32);
        assert!(!body.to_string().contains(&key));
    }
}

#[test]
fn enroll_rejection_or_uncertainty_never_fetches_or_publishes_or_retries() {
    for (behavior, stage, code) in [
        (
            Behavior {
                enroll_status: Some(403),
                ..Default::default()
            },
            "rejected",
            "wireguard_enrollment_rejected",
        ),
        (
            Behavior {
                enroll_status: Some(503),
                ..Default::default()
            },
            "unknown",
            "wireguard_enrollment_unknown",
        ),
        (
            Behavior {
                drop_enroll: true,
                ..Default::default()
            },
            "unknown",
            "wireguard_enrollment_unknown",
        ),
        (
            Behavior {
                wrong_enroll_device: true,
                ..Default::default()
            },
            "unknown",
            "wireguard_enrollment_unknown",
        ),
    ] {
        let fixture = Fixture::new(behavior);
        let output = fixture.home.join("wireguard/agent-remote.conf");
        private_file(&output, b"retained-old-config");
        let result = fixture.apply(fixture.plan(None));
        assert_eq!(result["complete"], false);
        assert_eq!(result["enrollment"], stage);
        assert_eq!(result["publication"], "not_attempted");
        assert_eq!(result["code"], code);
        assert!(result["peer_count"].is_null());
        assert_eq!(fs::read(&output).unwrap(), b"retained-old-config");
        assert!(fixture.private_path().is_file());
        assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    }
}

#[test]
fn accepted_enrollment_and_failed_or_injected_config_preserve_old_file() {
    for behavior in [
        Behavior {
            invalid_config: true,
            ..Default::default()
        },
        Behavior {
            config_status: Some(503),
            ..Default::default()
        },
    ] {
        let invalid = behavior.invalid_config;
        let fixture = Fixture::new(behavior);
        let output = fixture.home.join("wireguard/agent-remote.conf");
        private_file(&output, b"old-config");
        let result = fixture.apply(fixture.plan(None));
        assert_eq!(result["complete"], false);
        assert_eq!(result["enrollment"], "not_attempted");
        assert_eq!(result["publication"], "not_attempted");
        assert_eq!(
            result["code"],
            if invalid {
                "wireguard_config_invalid"
            } else {
                "wireguard_config_unavailable"
            }
        );
        assert_eq!(fs::read(&output).unwrap(), b"old-config");
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn changed_target_after_review_prevents_enrollment() {
    let fixture = Fixture::new(Behavior::default());
    let output = fixture.home.join("wireguard/agent-remote.conf");
    private_file(&output, b"old-config");
    let plan = fixture.plan(None);
    private_file(&output, b"new-config");
    let (ok, error) = fixture.invoke(
        "wireguard.config.apply",
        json!({"confirmed":true,"expected_plan":plan}),
    );
    assert!(!ok);
    assert_eq!(error["error"]["code"], "output_changed");
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert_eq!(fs::read(&output).unwrap(), b"new-config");
}

#[test]
fn target_changed_during_fetch_is_not_overwritten_after_confirmed_enrollment() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("target.conf");
    private_file(&output, b"old-config");
    let fixture = Fixture::new(Behavior {
        change_output: Some(output.clone()),
        ..Default::default()
    });
    let result = fixture.apply(fixture.plan(Some(&output)));
    assert_eq!(result["complete"], false);
    assert_eq!(result["enrollment"], "confirmed");
    assert_eq!(result["publication"], "not_attempted");
    assert_eq!(result["code"], "output_changed");
    assert_eq!(result["peer_count"], 0);
    assert_eq!(fs::read(output).unwrap(), b"concurrent-user-edit");
}

#[cfg(unix)]
#[test]
fn sigterm_during_enrollment_returns_unknown_and_preserves_the_key() {
    use std::io::Write;
    use std::process::Stdio;
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("enroll-observed");
    let fixture = Fixture::new(Behavior {
        enroll_barrier: Some(marker.clone()),
        ..Default::default()
    });
    let plan = fixture.plan(None);
    let mut child = fixture
        .command()
        .arg("--desktop-control")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"cancel-wg","method":"wireguard.config.apply","params":{"confirmed":true,"expected_plan":plan}});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(marker.exists());
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("CLI did not terminate after SIGTERM");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "wireguard_outcome_unknown");
    assert_eq!(value["error"]["retryable"], false);
    assert!(fixture.private_path().is_file());
    assert!(!fixture.home.join("wireguard/agent-remote.conf").exists());
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
}

#[test]
fn bad_existing_private_key_is_never_replaced_or_enrolled() {
    let fixture = Fixture::new(Behavior::default());
    private_secret_file(&fixture.private_path(), b"invalid-private-key");
    let result = fixture.apply(fixture.plan(None));
    assert_eq!(result["code"], "wireguard_key_invalid");
    assert_eq!(result["key_state"], "not_checked");
    assert_eq!(result["enrollment"], "not_attempted");
    assert_eq!(
        fs::read(fixture.private_path()).unwrap(),
        b"invalid-private-key"
    );
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn ordinary_cli_uses_the_same_checked_service() {
    let fixture = Fixture::new(Behavior::default());
    let output = fixture.temp.path().join("human.conf");
    let result = fixture
        .command()
        .args(["--color", "never", "wireguard", "config", "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("WireGuard configuration written"));
    assert!(output.is_file());
    let key = fs::read_to_string(fixture.private_path()).unwrap();
    assert!(!String::from_utf8_lossy(&result.stdout).contains(&key));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(&key));
}

#[cfg(unix)]
#[test]
fn symlink_and_special_output_or_private_key_cannot_be_followed() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(Behavior::default());
    let outside = fixture.temp.path().join("outside");
    private_file(&outside, b"retain");
    let output = fixture.home.join("wireguard/agent-remote.conf");
    symlink(&outside, &output).unwrap();
    let (ok, error) = fixture.invoke(
        "wireguard.config.plan",
        json!({"expected_home":fixture.home,"output":null}),
    );
    assert!(!ok);
    assert_eq!(error["error"]["code"], "output_invalid");
    fs::remove_file(&output).unwrap();
    fs::hard_link(&outside, &output).unwrap();
    let (ok, error) = fixture.invoke(
        "wireguard.config.plan",
        json!({"expected_home":fixture.home,"output":null}),
    );
    assert!(!ok);
    assert_eq!(error["error"]["code"], "output_invalid");
    fs::remove_file(&output).unwrap();
    let fifo = std::ffi::CString::new(output.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let (ok, error) = fixture.invoke(
        "wireguard.config.plan",
        json!({"expected_home":fixture.home,"output":null}),
    );
    assert!(!ok);
    assert_eq!(error["error"]["code"], "output_invalid");
    fs::remove_file(&output).unwrap();
    symlink(&outside, fixture.private_path()).unwrap();
    let result = fixture.apply(fixture.plan(None));
    assert_eq!(result["code"], "credential_unavailable");
    assert_eq!(fs::read(&outside).unwrap(), b"retain");
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[test]
fn rendering_rejects_injected_fields_and_low_order_public_keys() {
    use agent_remote_cli::api::{WireGuardConfigData, WireGuardNodePeerData};
    let key = STANDARD.encode([7; 32]);
    let mut config = WireGuardConfigData {
        device_id: "device-test".into(),
        peer_id: "peer-test".into(),
        peer_public_key: STANDARD.encode([6; 32]),
        peer_version: 1,
        interface_address: "10.77.0.2".into(),
        _private_key_ref: "local".into(),
        dns: vec![],
        peers: vec![WireGuardNodePeerData {
            node_id: "node-test".into(),
            name: "name".into(),
            region_code: "US".into(),
            public_key: STANDARD.encode([0; 32]),
            endpoint: "example.test:51820".into(),
            allowed_ips: vec!["10.42.0.2/32".into()],
            persistent_keepalive_seconds: 25,
        }],
    };
    assert!(agent_remote_cli::wireguard::render_config(&config, &key).is_err());
    config.peers[0].public_key = STANDARD.encode([8; 32]);
    assert!(agent_remote_cli::wireguard::render_config(&config, &key).is_ok());
    config.peers[0].name = "name\nPostUp = malicious".into();
    assert!(agent_remote_cli::wireguard::render_config(&config, &key).is_err());
    config.peers[0].name = "name".into();
    config.peers[0].endpoint = "example.test:51820\nPostUp = malicious".into();
    assert!(agent_remote_cli::wireguard::render_config(&config, &key).is_err());
}
