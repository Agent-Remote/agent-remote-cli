// Tests for src/api/skill_state/download.rs.

use super::Utf8Text;

#[test]
fn streaming_text_classification_matches_whole_file_at_every_boundary() {
    for bytes in [
        "ASCIIé学😄end".as_bytes(),
        b"bad\xff",
        b"zero\0",
        b"\xf0\x9f",
        b"",
    ] {
        for split in 0..=bytes.len() {
            let mut text = Utf8Text::default();
            text.update(&bytes[..split]);
            text.update(&bytes[split..]);
            assert_eq!(
                text.finish(),
                std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0)
            );
        }
        let mut text = Utf8Text::default();
        for byte in bytes {
            text.update(&[*byte]);
        }
        assert_eq!(
            text.finish(),
            std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0)
        );
    }
}
