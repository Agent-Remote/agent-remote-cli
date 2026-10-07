// Tests for src/attachments/input.rs.

use super::*;
#[test]
fn incomplete_prefixes_and_pastes_are_lossless_at_eof() {
    for bytes in [b"\x1b[".as_slice(), b"\x1b[200~abc\x1b[20", b"hello"] {
        let mut decoder = InputDecoder::default();
        let mut events = decoder.feed(bytes);
        events.extend(decoder.finish());
        let output: Vec<_> = events
            .into_iter()
            .flat_map(|e| match e {
                InputEvent::Bytes(b) => b,
                _ => panic!(),
            })
            .collect();
        assert_eq!(output, bytes);
    }
}
#[test]
fn large_pastes_never_trigger_clipboard_reads_and_preserve_every_byte() {
    let mut bytes = BRACKETED_PASTE_START.to_vec();
    bytes.extend(vec![b'x'; 1024 * 1024 + 4]);
    bytes.extend(b"\x16\x1b[118;5u\x02d");
    bytes.extend(BRACKETED_PASTE_END);
    let mut decoder = InputDecoder::default();
    let mut output = Vec::new();
    for chunk in bytes.chunks(8191) {
        for event in decoder.feed(chunk) {
            match event {
                InputEvent::Bytes(data) => output.extend(data),
                _ => panic!("large paste escaped its framing"),
            }
        }
    }
    assert_eq!(output, bytes);
    assert!(decoder.finish().is_empty());
    assert_eq!(decoder.feed(b"\x16"), vec![InputEvent::ClipboardPaste]);
}
#[test]
fn shortcuts_and_bracketed_paste_survive_every_split() {
    for sequence in CLIPBOARD_KEYS
        .iter()
        .copied()
        .chain(std::iter::once(b"\x16".as_slice()))
    {
        for split in 0..=sequence.len() {
            let mut decoder = InputDecoder::default();
            let mut events = decoder.feed(&sequence[..split]);
            events.extend(decoder.feed(&sequence[split..]));
            assert_eq!(events, vec![InputEvent::ClipboardPaste]);
        }
    }
    let mut decoder = InputDecoder::default();
    assert_eq!(
        decoder.feed(b"\x1b[200~\x16\x1b[118;5u\x1b[201~"),
        vec![InputEvent::BracketedPaste(b"\x16\x1b[118;5u".to_vec())]
    );
}
#[test]
fn standalone_escape_can_be_flushed_without_finishing_a_paste() {
    let mut decoder = InputDecoder::default();
    assert!(decoder.feed(b"\x1b").is_empty());
    assert!(decoder.has_pending_prefix());
    assert_eq!(decoder.flush_prefix(), b"\x1b");
    assert_eq!(decoder.feed(b"a"), vec![InputEvent::Bytes(b"a".to_vec())]);
    assert!(decoder.feed(b"\x1b[200~abc").is_empty());
    assert!(!decoder.has_pending_prefix());
    assert_eq!(
        decoder.feed(b"\x1b[201~"),
        vec![InputEvent::BracketedPaste(b"abc".to_vec())]
    );
}
