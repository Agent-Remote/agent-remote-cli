//! Bounded terminal paste framing and explicit clipboard shortcuts.
use super::{BRACKETED_PASTE_END, BRACKETED_PASTE_START};
/// Events emitted by a terminal input stream.  Keeping bracketed paste
/// framing intact lets normal text paste retain Claude's native behavior while
/// allowing file drops to be replaced with verified remote paths.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputEvent {
    Bytes(Vec<u8>),
    ClipboardPaste,
    BracketedPaste(Vec<u8>),
}

#[derive(Default)]
pub(crate) struct InputDecoder {
    pending: Vec<u8>,
    in_paste: bool,
    paste: Vec<u8>,
    streaming_paste: bool,
}

impl InputDecoder {
    pub(crate) fn feed(&mut self, input: &[u8]) -> Vec<InputEvent> {
        let mut events = Vec::new();
        for &byte in input {
            if self.in_paste {
                self.paste.push(byte);
                if self.paste.ends_with(BRACKETED_PASTE_END) {
                    if self.streaming_paste {
                        push_bytes(&mut events, &std::mem::take(&mut self.paste));
                    } else {
                        self.paste
                            .truncate(self.paste.len() - BRACKETED_PASTE_END.len());
                        events.push(InputEvent::BracketedPaste(std::mem::take(&mut self.paste)));
                    }
                    self.in_paste = false;
                    self.streaming_paste = false;
                } else if self.streaming_paste {
                    if self.paste.len() > BRACKETED_PASTE_END.len() {
                        push_bytes(&mut events, &[self.paste.remove(0)]);
                    }
                } else if self.paste.len() > 1024 * 1024 {
                    // Keep framing active until the matching end marker. In
                    // particular, pasted Ctrl+V must never read the clipboard.
                    self.streaming_paste = true;
                    push_bytes(&mut events, BRACKETED_PASTE_START);
                    let tail = self
                        .paste
                        .split_off(self.paste.len() - BRACKETED_PASTE_END.len());
                    push_bytes(&mut events, &self.paste);
                    self.paste = tail;
                }
                continue;
            }
            if self.pending.is_empty() && byte == 0x16 {
                events.push(InputEvent::ClipboardPaste);
                continue;
            }
            self.pending.push(byte);
            while !prefixes().any(|sequence| sequence.starts_with(&self.pending)) {
                let first = self.pending.remove(0);
                if let Some(InputEvent::Bytes(bytes)) = events.last_mut() {
                    bytes.push(first);
                } else {
                    events.push(InputEvent::Bytes(vec![first]));
                }
                if self.pending.is_empty() {
                    break;
                }
            }
            if CLIPBOARD_KEYS.contains(&self.pending.as_slice()) {
                self.pending.clear();
                events.push(InputEvent::ClipboardPaste);
            } else if self.pending == BRACKETED_PASTE_START {
                self.pending.clear();
                self.in_paste = true;
            }
        }
        events
    }

    pub(crate) fn has_pending_prefix(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(crate) fn flush_prefix(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    pub(crate) fn finish(&mut self) -> Vec<InputEvent> {
        let mut events = Vec::new();
        if self.in_paste {
            let mut bytes = if self.streaming_paste {
                Vec::new()
            } else {
                BRACKETED_PASTE_START.to_vec()
            };
            bytes.extend(std::mem::take(&mut self.paste));
            events.push(InputEvent::Bytes(bytes));
            self.in_paste = false;
            self.streaming_paste = false;
        }
        if !self.pending.is_empty() {
            events.push(InputEvent::Bytes(std::mem::take(&mut self.pending)));
        }
        events
    }
}

const CLIPBOARD_KEYS: &[&[u8]] = &[b"\x1b[118;5u", b"\x1b[118;5:1u", b"\x1b[27;5;118~"];
fn prefixes() -> impl Iterator<Item = &'static [u8]> {
    std::iter::once(BRACKETED_PASTE_START).chain(CLIPBOARD_KEYS.iter().copied())
}
fn push_bytes(events: &mut Vec<InputEvent>, value: &[u8]) {
    if let Some(InputEvent::Bytes(bytes)) = events.last_mut() {
        bytes.extend_from_slice(value);
    } else {
        events.push(InputEvent::Bytes(value.to_vec()));
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/attachments/input.rs"]
mod tests;
