use super::*;

fn encoded(n: u32) -> String {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    STANDARD.encode(bytes)
}

fn interface(name: &str) -> String {
    format!("{name}\t{}\t{}\t51820\t0xca6c\n", encoded(1), encoded(2))
}

fn peer(name: &str, id: u32, ips: &str) -> String {
    format!(
        "{name}\t{}\t{}\t[::1]:51820\t{ips}\t253402300799\t18446744073709551615\t42\toff\n",
        encoded(id),
        encoded(3)
    )
}

#[test]
fn public_snapshot_discards_both_secret_columns_and_preserves_integer_bounds() {
    let input = interface("wg0") + &peer("wg0", 4, "10.0.0.1/32,::/0");
    let result = parse(input.as_bytes()).unwrap();
    assert_eq!(result[0].fwmark, 51820);
    assert_eq!(result[0].peers[0].received_bytes, u64::MAX);
    assert_eq!(result[0].peers[0].persistent_keepalive, 0);
    assert_eq!(result[0].peers[0].latest_handshake, 253_402_300_799);
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains(&encoded(1)));
    assert!(!json.contains(&encoded(3)));
    assert!(!json.contains("private_key"));
    assert!(!json.contains("preshared"));
    assert!(json.contains(&encoded(4)));
}

#[test]
fn empty_unconfigured_and_crlf_snapshots_are_valid() {
    assert!(parse(b"").unwrap().is_empty());
    let input = "wg0\t(none)\t(none)\t0\toff\r\n".to_owned()
        + &peer("wg0", 4, "(none)").replace("[::1]:51820", "(none)");
    let result = parse(input.as_bytes()).unwrap();
    assert!(result[0].public_key.is_none());
    assert_eq!(result[0].fwmark, 0);
    assert!(result[0].peers[0].endpoint.is_none());
    assert!(result[0].peers[0].allowed_ips.is_empty());
}

#[test]
fn malformed_rows_or_duplicates_reject_the_entire_snapshot() {
    let header = interface("wg0");
    let item = peer("wg0", 4, "0.0.0.0/0");
    for input in [
        "\n".to_owned(),
        header.trim_end().to_owned(),
        header.clone() + "\n",
        header.clone() + "bad\trow\n",
        header.clone() + &header,
        item.clone(),
        header.clone() + &item + &item,
        header.clone() + &item.replace("wg0", "orphan"),
        header.replace("wg0", ""),
        interface(&"x".repeat(256)),
        interface("bad\u{7f}"),
        interface("wg0") + &item.replace("\t42\t", "\t42\textra\t"),
    ] {
        assert!(parse(input.as_bytes()).is_err());
    }
    assert!(parse(b"\xff\n").is_err());
    assert!(parse(&vec![b'\n'; probe::MAX_OUTPUT + 1]).is_err());
}

#[test]
fn invalid_numeric_key_endpoint_and_cidr_fields_fail_closed() {
    let header = interface("wg0");
    let item = peer("wg0", 4, "0.0.0.0/0");
    for (old, new) in [
        ("253402300799", "253402300800"),
        ("253402300799", "-1"),
        ("18446744073709551615", "18446744073709551616"),
        ("\toff\n", "\t65536\n"),
        ("\toff\n", "\t+1\n"),
        ("[::1]:51820", "[::1]:0"),
        ("[::1]:51820", "::1:51820"),
        ("[::1]:51820", "bad host:10"),
        ("[::1]:51820", "-bad.test:10"),
        ("0.0.0.0/0", "0.0.0.0/33"),
        ("0.0.0.0/0", "::/129"),
        ("0.0.0.0/0", "10.0.0.1"),
        ("0.0.0.0/0", "::/0,"),
    ] {
        assert!(
            parse((header.clone() + &item.replace(old, new)).as_bytes()).is_err(),
            "{old} => {new}"
        );
    }
    for changed in [
        header.replace("51820", "65536"),
        header.replace("0xca6c", "0x100000000"),
        header.replace("0xca6c", "0x"),
        header.replace(&encoded(1), "not-a-key"),
        header.replace(&encoded(2), &STANDARD.encode([2u8; 31])),
    ] {
        assert!(parse(changed.as_bytes()).is_err());
    }
    assert!(parse((header.clone() + &item.replace(&encoded(4), "(none)")).as_bytes()).is_err());
    assert!(parse((header + &item.replace(&encoded(3), "invalid-psk")).as_bytes()).is_err());
    for endpoint in [
        "127.0.0.1:65535",
        "vpn.example.org:1",
        "[fe80::1%en0]:51820",
    ] {
        assert!(valid_endpoint(endpoint));
    }
}

#[test]
fn interface_peer_and_allowed_ip_limits_are_whole_snapshot_bounds() {
    let mut input = (0..64)
        .map(|n| interface(&format!("wg{n}")))
        .collect::<String>();
    assert_eq!(parse(input.as_bytes()).unwrap().len(), 64);
    input += &interface("too-many");
    assert!(parse(input.as_bytes()).is_err());
    input = interface("wg0");
    for n in 1..=1024 {
        input += &peer("wg0", n, "(none)");
    }
    assert_eq!(parse(input.as_bytes()).unwrap()[0].peers.len(), 1024);
    input += &peer("wg0", 1025, "(none)");
    assert!(parse(input.as_bytes()).is_err());
    let ips = vec!["::/0"; 256].join(",");
    input = interface("wg0");
    for n in 1..=16 {
        input += &peer("wg0", n, &ips);
    }
    assert!(parse(input.as_bytes()).is_ok());
    input += &peer("wg0", 17, "::/0");
    assert!(parse(input.as_bytes()).is_err());
    assert!(parse((interface("wg0") + &peer("wg0", 4, &(ips + ",::/0"))).as_bytes()).is_err());
}

#[test]
fn zero_public_keys_are_rejected_but_secret_columns_are_only_syntax_checked() {
    let header = interface("wg0");
    let item = peer("wg0", 4, "(none)");
    assert!(parse(header.replace(&encoded(2), &encoded(0)).as_bytes()).is_err());
    assert!(parse((header.clone() + &item.replace(&encoded(4), &encoded(0))).as_bytes()).is_err());
    assert!(parse(
        (header.replace(&encoded(1), &encoded(0)) + &item.replace(&encoded(3), &encoded(0)))
            .as_bytes()
    )
    .is_ok());
}
