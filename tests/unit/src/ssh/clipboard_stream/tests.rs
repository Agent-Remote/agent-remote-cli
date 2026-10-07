use super::*;

fn sequence(text: &str, ending: &str) -> Vec<u8> {
    format!("\x1b]52;c;{}{ending}", STANDARD.encode(text)).into_bytes()
}

#[test]
fn receives_complete_unicode_multiline_selection_across_every_split() {
    let text = "第一行\n  code && value\n结尾 😀\n";
    for end in ["\x07", "\x1b\\"] {
        let bytes = sequence(text, end);
        for split in 0..bytes.len() {
            let mut stream = ClipboardStream::default();
            assert!(stream.process(&bytes[..split]).is_empty());
            assert_eq!(stream.take_copy(), None);
            assert!(stream.process(&bytes[split..]).is_empty());
            assert_eq!(stream.take_copy().as_deref(), Some(text));
        }
    }
}

#[test]
fn preserves_text_colors_hyperlinks_and_other_control_strings() {
    let bytes = b"hello\x1b[31mworld\x1b[0m\r\n\x1b]8;;https://example.test\x1b\\link\x1b]8;;\x07\x1bPopaque\x1b]52;c;aGk=\x07\x1b\\\x1b[?1006h";
    let mut stream = ClipboardStream::default();
    let output: Vec<_> = bytes.iter().flat_map(|b| stream.process(&[*b])).collect();
    assert_eq!(output, bytes);
    assert_eq!(stream.take_copy(), None);
}

#[test]
fn ignores_reads_empty_invalid_binary_and_oversized_clipboard_payloads() {
    for data in [
        "?".to_owned(),
        String::new(),
        "not-base64!".into(),
        STANDARD.encode([0xff]),
        STANDARD.encode(b"a\0b"),
        STANDARD.encode(vec![b'a'; MAX_TEXT + 1]),
    ] {
        let mut stream = ClipboardStream::default();
        let input = format!("before\x1b]52;c;{data}\x07after");
        assert_eq!(stream.process(input.as_bytes()), b"beforeafter");
        assert_eq!(stream.take_copy(), None);
    }
    let mut stream = ClipboardStream::default();
    let huge = format!("\x1b]52;c;{}\x07", "a".repeat(MAX_SEQUENCE * 2));
    for chunk in huge.as_bytes().chunks(300) {
        assert!(stream.process(chunk).is_empty());
    }
    assert_eq!(stream.take_copy(), None);
    assert!(stream
        .process(&sequence("next valid copy", "\x07"))
        .is_empty());
    assert_eq!(stream.take_copy().as_deref(), Some("next valid copy"));
}

#[test]
fn repeated_manual_copies_are_not_deduplicated_and_latest_pending_wins() {
    let mut stream = ClipboardStream::default();
    for _ in 0..2 {
        stream.process(&sequence("same text", "\x07"));
        assert_eq!(stream.take_copy().as_deref(), Some("same text"));
    }
    stream.process(&sequence("first", "\x07"));
    stream.process(&sequence("second", "\x07"));
    assert_eq!(stream.take_copy().as_deref(), Some("second"));
}

#[test]
fn default_clipboard_and_unpadded_base64_are_supported() {
    let mut stream = ClipboardStream::default();
    assert!(stream.process(b"\x1b]52;;aGk\x1b\\").is_empty());
    assert_eq!(stream.take_copy().as_deref(), Some("hi"));
    assert!(stream.process(b"\x1b]52;p;aGk=\x07").is_empty());
    assert_eq!(stream.take_copy(), None);
}

#[test]
fn incomplete_clipboard_is_discarded_but_non_clipboard_eof_bytes_survive() {
    let mut stream = ClipboardStream::default();
    assert!(stream.process(b"\x1b]52;c;aGVs").is_empty());
    assert!(stream.finish().is_empty());
    assert_eq!(stream.take_copy(), None);
    assert!(stream.process(b"\x1b]").is_empty());
    assert_eq!(stream.finish(), b"\x1b]");
    assert!(stream.process(b"\x1b]52;c;partial").is_empty());
    assert_eq!(stream.process(b"\x1b[31mred"), b"\x1b[31mred");
    assert_eq!(stream.take_copy(), None);
}
