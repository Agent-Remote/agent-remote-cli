// Tests for src/ssh/stdin.rs.

use super::ConsoleUtf16;

#[test]
fn console_input_preserves_unicode_and_terminal_bytes_at_every_split() {
    let text = "中😀\u{2}d\u{1b}[<0;45;50m\u{16}";
    let units: Vec<_> = text.encode_utf16().collect();
    for split in 0..=units.len() {
        let mut decoder = ConsoleUtf16::default();
        let mut bytes = decoder.feed(&units[..split]);
        bytes.extend(decoder.feed(&units[split..]));
        assert_eq!(bytes, text.as_bytes());
    }
}
