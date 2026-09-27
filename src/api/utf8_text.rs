//! Incremental whole-file UTF-8 and NUL classification shared by verified transports.

#[derive(Default)]
pub(crate) struct Utf8Text {
    invalid: bool,
    pending: Vec<u8>,
}

impl Utf8Text {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        if self.invalid {
            return;
        }
        if bytes.contains(&0) {
            self.invalid = true;
            return;
        }
        let mut offset = 0;
        while !self.pending.is_empty() && offset < bytes.len() {
            self.pending.push(bytes[offset]);
            offset += 1;
            match std::str::from_utf8(&self.pending) {
                Ok(_) => self.pending.clear(),
                Err(error) if error.error_len().is_some() => {
                    self.invalid = true;
                    return;
                }
                Err(_) => {}
            }
        }
        if !self.pending.is_empty() {
            return;
        }
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(_) => {}
            Err(error) if error.error_len().is_some() => self.invalid = true,
            Err(error) => self
                .pending
                .extend_from_slice(&bytes[offset + error.valid_up_to()..]),
        }
    }

    pub(crate) fn finish(self) -> bool {
        !self.invalid && self.pending.is_empty()
    }
}
