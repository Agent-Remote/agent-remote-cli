//! Bounded OSC 52 write-only clipboard transport. Other terminal bytes pass through.

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};

const MAX_TEXT: usize = 64 * 1024;
const MAX_SEQUENCE: usize = MAX_TEXT.div_ceil(3) * 4 + 32;

#[derive(Default)]
enum State {
    #[default]
    Ground,
    Escape,
    Header(Vec<u8>),
    Clipboard {
        bytes: Vec<u8>,
        escaped: bool,
        oversized: bool,
    },
    Passthrough {
        bell: bool,
        escaped: bool,
    },
}

#[derive(Default)]
pub(super) struct ClipboardStream {
    state: State,
    pending: Option<String>,
    rejected: bool,
}

impl ClipboardStream {
    pub(super) fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        for &byte in input {
            self.byte(byte, &mut output);
        }
        output
    }

    pub(super) fn take_copy(&mut self) -> Option<String> {
        self.pending.take()
    }

    pub(super) fn take_rejected(&mut self) -> bool {
        std::mem::take(&mut self.rejected)
    }

    // Only an incomplete non-clipboard prefix may be flushed on EOF. Never
    // expose a truncated clipboard payload as terminal text.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        match std::mem::take(&mut self.state) {
            State::Escape => vec![0x1b],
            State::Header(bytes) => [b"\x1b]".as_slice(), &bytes].concat(),
            State::Clipboard { .. } => {
                self.rejected = true;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn byte(&mut self, byte: u8, output: &mut Vec<u8>) {
        match std::mem::take(&mut self.state) {
            State::Ground => {
                if byte == 0x1b {
                    self.state = State::Escape;
                } else {
                    output.push(byte);
                }
            }
            State::Escape => match byte {
                b']' => self.state = State::Header(Vec::new()),
                b'P' | b'X' | b'^' | b'_' => {
                    output.extend([0x1b, byte]);
                    self.state = State::Passthrough {
                        bell: false,
                        escaped: false,
                    };
                }
                0x1b => {
                    output.push(0x1b);
                    self.state = State::Escape;
                }
                _ => output.extend([0x1b, byte]),
            },
            State::Header(mut bytes) => {
                bytes.push(byte);
                if bytes == b"52;" {
                    self.state = State::Clipboard {
                        bytes: Vec::new(),
                        escaped: false,
                        oversized: false,
                    };
                } else if b"52;".starts_with(&bytes) {
                    self.state = State::Header(bytes);
                } else {
                    output.extend(b"\x1b]");
                    output.extend(&bytes);
                    if byte != 7 {
                        self.state = State::Passthrough {
                            bell: true,
                            escaped: byte == 0x1b,
                        };
                    }
                }
            }
            State::Clipboard {
                mut bytes,
                escaped,
                mut oversized,
            } => {
                if byte == 7 || (escaped && byte == b'\\') {
                    if !oversized {
                        if let Some(text) = decode(&bytes) {
                            self.pending = Some(text);
                        } else if !bytes.ends_with(b";?") {
                            self.rejected = true;
                        }
                    } else {
                        self.rejected = true;
                    }
                } else if escaped {
                    // ESC cancels OSC unless followed by ST. Reprocess the new
                    // escape normally, without leaking the discarded OSC.
                    self.state = State::Escape;
                    self.byte(byte, output);
                } else {
                    if byte != 0x1b && !oversized {
                        if bytes.len() == MAX_SEQUENCE {
                            bytes.clear();
                            oversized = true;
                        } else {
                            bytes.push(byte);
                        }
                    }
                    self.state = State::Clipboard {
                        bytes,
                        escaped: byte == 0x1b,
                        oversized,
                    };
                }
            }
            State::Passthrough { bell, escaped } => {
                output.push(byte);
                if !(bell && byte == 7 || escaped && byte == b'\\') {
                    self.state = State::Passthrough {
                        bell,
                        escaped: byte == 0x1b,
                    };
                }
            }
        }
    }
}

fn decode(sequence: &[u8]) -> Option<String> {
    let separator = sequence.iter().position(|&b| b == b';')?;
    let target = &sequence[..separator];
    if !target.is_empty() && target != b"c" {
        return None;
    }
    let data = &sequence[separator + 1..];
    // Never read or respond with the local clipboard. Empty/malformed writes
    // also must not clear a user's existing clipboard.
    if data.is_empty() || data == b"?" {
        return None;
    }
    let bytes = STANDARD
        .decode(data)
        .or_else(|_| STANDARD_NO_PAD.decode(data))
        .ok()?;
    if bytes.len() > MAX_TEXT || bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests;
