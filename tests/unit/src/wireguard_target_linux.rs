use super::*;

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let size = value.len() + 4;
    let mut bytes = vec![0; align(size)];
    bytes[..2].copy_from_slice(&(size as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
    bytes[4..size].copy_from_slice(value);
    bytes
}
fn link_message(name: &str, kind: &str) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[4..6].copy_from_slice(&libc::RTM_NEWLINK.to_ne_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_ne_bytes());
    bytes[20..24].copy_from_slice(&42u32.to_ne_bytes());
    bytes.extend(attribute(libc::IFLA_IFNAME, format!("{name}\0").as_bytes()));
    bytes.extend(attribute(
        libc::IFLA_LINKINFO,
        &attribute(libc::IFLA_INFO_KIND, format!("{kind}\0").as_bytes()),
    ));
    let len = bytes.len() as u32;
    bytes[..4].copy_from_slice(&len.to_ne_bytes());
    bytes
}
fn error_message(error: i32) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[..4].copy_from_slice(&20u32.to_ne_bytes());
    bytes[4..6].copy_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_ne_bytes());
    bytes[16..20].copy_from_slice(&error.to_ne_bytes());
    bytes
}

#[test]
fn kernel_identity_requires_exact_name_wireguard_kind_and_positive_index() {
    assert_eq!(
        response(&link_message("wg0", "wireguard"), "wg0").unwrap(),
        Some(Some(42))
    );
    assert_eq!(
        response(&link_message("wg0", "veth"), "wg0").unwrap_err(),
        TargetReason::InterfaceNotWireguard
    );
    assert!(response(&link_message("other", "wireguard"), "wg0").is_err());
    let mut bytes = link_message("wg0", "wireguard");
    bytes[20..24].copy_from_slice(&0u32.to_ne_bytes());
    assert!(response(&bytes, "wg0").is_err());
}

#[test]
fn permission_and_malformed_netlink_responses_are_never_absence() {
    assert_eq!(
        response(&error_message(-libc::ENODEV), "wg0").unwrap(),
        Some(None)
    );
    for error in [-libc::EPERM, -libc::EACCES, -libc::EIO] {
        assert!(response(&error_message(error), "wg0").is_err());
    }
    let bytes = link_message("wg0", "wireguard");
    for length in 0..bytes.len() {
        if length != 0 {
            assert!(response(&bytes[..length], "wg0").is_err());
        }
    }
    let mut wrong_sequence = bytes.clone();
    wrong_sequence[8..12].copy_from_slice(&99u32.to_ne_bytes());
    assert!(response(&wrong_sequence, "wg0").is_err());
    let mut duplicate = bytes.clone();
    duplicate.extend(&bytes);
    assert!(response(&duplicate, "wg0").is_err());
}

#[test]
fn native_read_only_query_observes_missing_name_and_rejects_loopback_as_wireguard() {
    let name = format!(
        "ar{:08x}",
        rand_core::RngCore::next_u32(&mut rand_core::OsRng)
    );
    let missing = observe(&name, &AtomicBool::new(false));
    assert_eq!(missing.state, TargetState::Absent);
    let loopback = observe("lo", &AtomicBool::new(false));
    assert_eq!(loopback.state, TargetState::Conflict);
    assert_eq!(loopback.reason, Some(TargetReason::InterfaceNotWireguard));
    let id = namespace().unwrap();
    assert_eq!(id.len(), 64);
    assert_eq!(id, namespace().unwrap());
}
