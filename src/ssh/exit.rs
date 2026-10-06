//! Stop terminal reports before tmux/SSH restore cooked input and echo.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub(super) const RESET: &[u8] =
    b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l";

#[derive(Clone, Default)]
pub(super) struct ExitState(Arc<ExitInner>);

#[derive(Default)]
struct ExitInner {
    started: AtomicBool,
    changed: tokio::sync::Notify,
}

impl ExitState {
    pub(super) fn begin(&self) {
        self.0.started.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
    pub(super) fn started(&self) -> bool {
        self.0.started.load(Ordering::Acquire)
    }
    pub(super) async fn cancelled(&self) {
        let changed = self.0.changed.notified();
        if !self.started() {
            changed.await;
        }
    }
    pub(super) fn reset(&self) {
        use std::io::Write;
        self.begin();
        let mut output = std::io::stdout().lock();
        let _ = output.write_all(RESET);
        let _ = output.flush();
    }
}

#[derive(Default)]
pub(super) struct Input {
    prefix: bool,
    in_paste: bool,
    marker: Vec<u8>,
}

impl Input {
    // Forward the managed tmux detach key once, then discard reports in flight.
    // A literal prefix sent with Ctrl+B Ctrl+B, or a pasted Ctrl+B d, is data.
    pub(super) fn filter<'a>(&mut self, bytes: &'a [u8], exit: &ExitState) -> &'a [u8] {
        if exit.started() {
            return &[];
        }
        for (index, &byte) in bytes.iter().enumerate() {
            if !self.in_paste {
                if self.prefix && byte == b'd' {
                    exit.reset();
                    return &bytes[..=index];
                }
                self.prefix = !self.prefix && byte == 2;
            }
            self.marker.push(byte);
            let expected: &[u8] = if self.in_paste {
                b"\x1b[201~"
            } else {
                b"\x1b[200~"
            };
            while !expected.starts_with(&self.marker) {
                self.marker.remove(0);
            }
            if self.marker == expected {
                self.in_paste = !self.in_paste;
                self.marker.clear();
                self.prefix = false;
            }
        }
        bytes
    }
}

#[derive(Default)]
pub(super) struct Output {
    matched: usize,
}

impl Output {
    pub(super) fn observe(&mut self, bytes: &[u8], exit: &ExitState) {
        const LEAVE_SCREEN: &[u8] = b"\x1b[?1049l";
        for &byte in bytes {
            if byte == LEAVE_SCREEN[self.matched] {
                self.matched += 1;
            } else {
                self.matched = usize::from(byte == 0x1b);
            }
            if self.matched == LEAVE_SCREEN.len() {
                exit.begin();
                self.matched = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
}
