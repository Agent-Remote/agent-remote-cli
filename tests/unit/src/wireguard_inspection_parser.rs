use base64::{engine::general_purpose::STANDARD, Engine};

use super::parse;

fn interface() -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.2/24,2001:db8::2/64\nMTU = 1000\n",
        STANDARD.encode([7; 32])
    )
}

fn peer() -> String {
    format!("[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0,::/0\nEndpoint = [2001:db8::1]:51820\nPersistentKeepalive = 25\n", STANDARD.encode([8; 32]), STANDARD.encode([9; 32]))
}

#[test]
fn parses_generated_and_common_numeric_fields_without_returning_secret_fields() {
    let text = format!(
        "# comment\n{}DNS = 1.1.1.1,2001:4860:4860::8888\nListenPort = 51820\nFwMark = 0x10\n{}",
        interface(),
        peer()
    )
    .replace('\n', "\r\n");
    let summary = parse(text.as_bytes()).unwrap_or_else(|_| panic!("valid configuration rejected"));
    assert_eq!(summary.addresses, ["10.77.0.2/24", "2001:db8::2/64"]);
    assert_eq!(summary.dns.len(), 2);
    assert_eq!(summary.mtu, Some(1000));
    assert_eq!(summary.peer_count, 1);
    assert!(summary.unsupported_directives.is_empty());
}

#[test]
fn reports_only_fixed_unsupported_names_and_never_their_values() {
    let input = format!(
        "{}PostUp = SECRET_COMMAND_PAYLOAD\nPreDown = ignored\nSaveConfig = true\nTable = auto\n",
        interface()
    );
    let summary = parse(input.as_bytes()).unwrap_or_else(|_| panic!("unsupported directives lost"));
    assert_eq!(
        summary.unsupported_directives,
        ["PostUp", "PreDown", "SaveConfig", "Table"]
    );
    assert!(parse(format!("{input}Table = 3\n").as_bytes()).is_err());
}

#[test]
fn rejects_malformed_duplicate_and_excessive_values() {
    for suffix in [
        "MTU = 1400\n",
        "Unknown = value\n",
        "[Interface]\n",
        "ListenPort = 65536\n",
        "ListenPort = +1\n",
        "FwMark = 0x100000000\n",
        "DNS = search.example\n",
        "Address = 10.0.0.1/33\n",
        "DNS = 1.1.1.1\0\n",
        "DNS = 1.1.1.1\rAddress = 10.0.0.1\n",
    ] {
        assert!(
            parse(format!("{}{suffix}", interface()).as_bytes()).is_err(),
            "accepted {suffix:?}"
        );
    }
    assert!(parse(format!("{}{}{}", interface(), peer(), peer()).as_bytes()).is_err());
    assert!(parse(b"[Peer]\nPublicKey = bad\n").is_err());
    assert!(parse(b"[Interface]\nAddress = 10.0.0.1\n").is_err());
    assert!(
        parse(format!("{}DNS = {}\n", interface(), vec!["1.1.1.1"; 17].join(",")).as_bytes())
            .is_err()
    );
    assert!(parse(
        format!(
            "{}Address = {}\n",
            interface(),
            vec!["10.0.0.1"; 65].join(",")
        )
        .as_bytes()
    )
    .is_err());
    assert!(parse(
        format!(
            "{}{}AllowedIPs = {}\n",
            interface(),
            peer(),
            vec!["10.0.0.1/32"; 256].join(",")
        )
        .as_bytes()
    )
    .is_err());
}
