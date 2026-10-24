use serde_json::json;

#[test]
fn skills_catalog_is_declared_as_user_read_only_and_rejects_ambiguous_scope() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, value) = super::invoke(
        temp.path(),
        &super::request(
            "skills.list",
            json!({"tool":"claude","account_id":"11111111-1111-4111-8111-111111111111"}),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!temp.path().exists() || std::fs::read_dir(temp.path()).unwrap().next().is_none());
}

#[test]
fn skill_info_is_user_read_only_and_rejects_ambiguous_scope() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, value) = super::invoke(
        temp.path(),
        &super::request(
            "skills.info",
            json!({
                "skill": "review-helper",
                "tool": "claude",
                "account_id": "11111111-1111-4111-8111-111111111111"
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!temp.path().exists() || std::fs::read_dir(temp.path()).unwrap().next().is_none());

    let (ok, value) = super::invoke(temp.path(), &super::request("capabilities", json!({})));
    assert!(ok);
    let operation = value["result"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["method"] == "skills.info")
        .expect("skills.info capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "user");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn skills_change_is_declared_as_confirmed_user_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, value) = super::invoke(temp.path(), &super::request("capabilities", json!({})));
    assert!(ok);
    let operations = value["result"]["operations"].as_array().unwrap();
    let operation = operations
        .iter()
        .find(|operation| operation["method"] == "skills.change")
        .expect("skills.change capability");
    assert_eq!(operation["effect"], "write");
    assert_eq!(operation["credential"], "user");
    assert_eq!(operation["confirmation"], "exact_request");
}

#[test]
fn skill_state_conflicts_is_user_read_only_and_strictly_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, value) = super::invoke(
        temp.path(),
        &super::request(
            "skills.state.conflicts",
            serde_json::json!({
                "account_id": "11111111-1111-4111-8111-111111111111",
                "scope": "account-directory",
                "skill": "11111111-1111-4111-8111-111111111111"
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!temp.path().exists() || std::fs::read_dir(temp.path()).unwrap().next().is_none());

    let (ok, value) = super::invoke(temp.path(), &super::request("capabilities", json!({})));
    assert!(ok);
    let operation = value["result"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["method"] == "skills.state.conflicts")
        .expect("skills.state.conflicts capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "user");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn skill_state_list_is_user_read_only_and_strictly_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, value) = super::invoke(
        temp.path(),
        &super::request(
            "skills.state.list",
            serde_json::json!({
                "account_id": "11111111-1111-4111-8111-111111111111",
                "scope": "account-directory",
                "skill": "11111111-1111-4111-8111-111111111111"
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!temp.path().exists() || std::fs::read_dir(temp.path()).unwrap().next().is_none());

    let (ok, value) = super::invoke(temp.path(), &super::request("capabilities", json!({})));
    assert!(ok);
    let operation = value["result"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["method"] == "skills.state.list")
        .expect("skills.state.list capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "user");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn skill_state_info_is_user_read_only_and_requires_canonical_checkpoint_id() {
    let temp = tempfile::tempdir().unwrap();
    for checkpoint_id in ["not-a-uuid", "55555555-5555-4555-8555-55555555555A"] {
        let (ok, value) = super::invoke(
            temp.path(),
            &super::request("skills.state.info", json!({"checkpoint_id": checkpoint_id})),
        );
        assert!(!ok);
        assert_eq!(value["error"]["code"], "invalid_params");
    }
    assert!(!temp.path().exists() || std::fs::read_dir(temp.path()).unwrap().next().is_none());

    let (ok, value) = super::invoke(temp.path(), &super::request("capabilities", json!({})));
    assert!(ok);
    let operation = value["result"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["method"] == "skills.state.info")
        .expect("skills.state.info capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "user");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn skills_catalog_requires_user_login_without_initializing_home() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(&home, &super::request("skills.list", json!({})));
    assert!(!ok);
    assert_eq!(value["error"]["code"], "authentication_required");
    assert!(!home.exists());
}

#[test]
fn skills_change_requires_explicit_confirmation_and_canonical_scope() {
    let temp = tempfile::tempdir().unwrap();
    let context = serde_json::json!({
        "home": temp.path(),
        "server_url": "https://test.invalid",
        "active_device_id": null,
    });
    let mut params = serde_json::json!({
        "confirmed": false,
        "expected_context": context,
        "expected_generation": 7,
        "skill": "11111111-1111-4111-8111-111111111111",
        "action": "enable",
        "scope": {"tools": [], "account_id": null},
    });
    let (ok, value) = super::invoke(
        temp.path(),
        &super::request("skills.change", params.clone()),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");

    params["confirmed"] = serde_json::json!(true);
    params["scope"] = serde_json::json!({"tools": ["zeta", "alpha"], "account_id": null});
    let (ok, value) = super::invoke(temp.path(), &super::request("skills.change", params));
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!temp.path().exists() || std::fs::read_dir(temp.path()).unwrap().next().is_none());
}
