// Tests for src/ssh/exit.rs.

use super::*;
#[test]
fn pasted_and_escaped_prefixes_never_detach() {
    for bytes in [b"\x02\x02d".as_slice(), b"\x1b[200~\x02d\x1b[201~"] {
        for split in 0..=bytes.len() {
            let mut input = Input::default();
            let exit = ExitState::default();
            assert_eq!(input.filter(&bytes[..split], &exit), &bytes[..split]);
            assert_eq!(input.filter(&bytes[split..], &exit), &bytes[split..]);
            assert!(!exit.started());
        }
    }
}
#[test]
fn screen_exit_is_detected_across_every_chunk_boundary() {
    let bytes = b"\x1b[?1049l[detached]";
    for split in 0..=bytes.len() {
        let exit = ExitState::default();
        let mut output = Output::default();
        output.observe(&bytes[..split], &exit);
        output.observe(&bytes[split..], &exit);
        assert!(exit.started());
    }
}
