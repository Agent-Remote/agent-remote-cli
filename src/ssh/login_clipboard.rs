//! Best-effort local clipboard delivery for the remote Claude login screen.

const MAX_URL_BYTES: usize = 8192;

pub(super) struct LoginScreen {
    parser: vt100::Parser,
    last_url: Option<String>,
}

impl LoginScreen {
    pub(super) fn new(rows: u16, cols: u16) -> Self {
        Self {
            parser: vt100::Parser::new(rows.clamp(1, 512), cols.clamp(1, 512), 0),
            last_url: None,
        }
    }

    pub(super) fn process(&mut self, bytes: &[u8], rows: u16, cols: u16) {
        self.parser
            .screen_mut()
            .set_size(rows.clamp(1, 512), cols.clamp(1, 512));
        self.parser.process(bytes);
    }

    // Called only after output settles: a repaint may otherwise mix an old URL's
    // tail with a new URL's prefix. Never infer a URL from an incomplete line.
    pub(super) fn take_url(&mut self) -> Option<String> {
        let screen = self.parser.screen();
        let lines: Vec<_> = screen.rows(0, screen.size().1).collect();
        let url = login_url(&lines)?;
        if self.last_url.as_deref() == Some(&url) {
            return None;
        }
        self.last_url = Some(url.clone());
        Some(url)
    }
}

fn login_url(lines: &[String]) -> Option<String> {
    let prompt = lines
        .iter()
        .position(|line| line.contains("Paste code here"))?;
    if !lines[..prompt]
        .iter()
        .any(|line| line.contains("Browser didn't open?"))
    {
        return None;
    }
    for (index, line) in lines[..prompt].iter().enumerate() {
        let Some(start) = line.find("https://") else {
            continue;
        };
        let mut url = line[start..].trim_end().to_owned();
        let mut terminated = false;
        for next in &lines[index + 1..prompt] {
            let next = next.trim();
            if next.is_empty() {
                terminated = true;
                break;
            }
            if next.bytes().any(|byte| byte.is_ascii_whitespace()) {
                break;
            }
            url.push_str(next);
            if url.len() > MAX_URL_BYTES {
                break;
            }
        }
        if terminated && valid_login_url(&url) {
            return Some(url);
        }
    }
    None
}

fn valid_login_url(value: &str) -> bool {
    if value.len() > MAX_URL_BYTES
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
        || !matches!(
            (url.host_str(), url.path()),
            (
                Some("claude.ai" | "claude.com"),
                "/oauth/authorize" | "/cai/oauth/authorize"
            ) | (
                Some("console.anthropic.com" | "platform.claude.com"),
                "/oauth/authorize"
            )
        )
    {
        return false;
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    for key in [
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "state",
    ] {
        let values: Vec<_> = pairs.iter().filter(|(name, _)| name == key).collect();
        if values.len() != 1 || values[0].1.is_empty() {
            return false;
        }
    }
    let parameter = |name| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_ref())
    };
    parameter("response_type") == Some("code")
        && parameter("code_challenge_method") == Some("S256")
        && parameter("code_challenge").is_some_and(|v| {
            v.len() == 43
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
#[cfg(test)]
#[path = "../../tests/unit/src/ssh/login_clipboard/tests.rs"]
mod tests;
