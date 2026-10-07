//! Parse explicit file drops without shell execution or implicit text uploads.
use super::MAX_FILES_PER_PASTE;
use std::path::PathBuf;

/// Resolve all dropped paths, including shell-quoted lists and local file URIs.
/// Ordinary text and partially resolvable lists remain ordinary terminal input.
pub async fn parse_dropped_paths(input: &str) -> Option<Vec<PathBuf>> {
    let lines: Vec<_> = input
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    let mut paths = Vec::new();
    for line in lines {
        // Some terminals send one unquoted path containing spaces per line.
        if let Some(path) = resolve(line).await {
            paths.push(path);
        } else {
            for token in tokens(line)? {
                paths.push(resolve(&token).await?);
            }
        }
        if paths.len() > MAX_FILES_PER_PASTE {
            return None;
        }
    }
    (!paths.is_empty()).then_some(paths)
}

pub(super) async fn resolve(value: &str) -> Option<PathBuf> {
    let value = decode_uri(value)?;
    let value = if let Some(suffix) = value.strip_prefix("~/") {
        format!(
            "{}/{}",
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?.to_string_lossy(),
            suffix
        )
    } else {
        value
    };
    if !explicit_path(&value) {
        return None;
    }
    #[cfg(target_os = "linux")]
    let value = if windows_path(&value) && super::capture::is_wsl() {
        super::capture::run_text("wslpath", &["-u", "--", &value])
            .await?
            .trim_end_matches(['\r', '\n'])
            .to_owned()
    } else {
        value
    };
    let path = PathBuf::from(value);
    tokio::fs::metadata(&path).await.ok().map(|_| path)
}

fn explicit_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || windows_path(value)
}

fn windows_path(value: &str) -> bool {
    value.starts_with(r"\\")
        || (value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'\\' | b'/'))
}

fn decode_uri(value: &str) -> Option<String> {
    if !value.starts_with("file:") {
        return Some(value.to_owned());
    }
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "file"
        || url.host_str().is_some_and(|host| host != "localhost")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let mut bytes = Vec::new();
    let mut input = url.path().as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        bytes.push(if byte == b'%' {
            let high = (input.next()? as char).to_digit(16)?;
            let low = (input.next()? as char).to_digit(16)?;
            (high * 16 + low) as u8
        } else {
            byte
        });
    }
    let path = String::from_utf8(bytes).ok()?;
    if path.contains('\0') {
        return None;
    }
    if path.starts_with('/') && windows_path(&path[1..]) {
        Some(path[1..].into())
    } else {
        Some(path)
    }
}

fn tokens(value: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut text = String::new();
    let mut quote = None;
    let mut chars = value.chars().peekable();
    // Windows drive and UNC prefixes use literal backslashes, even in quotes.
    let mut windows = false;
    while let Some(ch) = chars.next() {
        if text.is_empty() && quote.is_none() {
            let remainder = format!("{ch}{}", chars.clone().take(5).collect::<String>());
            windows = windows_path(remainder.trim_start_matches(['\'', '"']));
        }
        if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if ch == '\\' && !windows && quote != Some('\'') {
            text.push(chars.next()?);
        } else if ch.is_whitespace() && quote.is_none() {
            if !text.is_empty() {
                result.push(std::mem::take(&mut text));
            }
            if result.len() > MAX_FILES_PER_PASTE {
                return None;
            }
        } else {
            text.push(ch);
        }
    }
    if quote.is_some() {
        return None;
    }
    if !text.is_empty() {
        result.push(text);
    }
    Some(result)
}

#[cfg(test)]
#[path = "../../tests/unit/src/attachments/paths.rs"]
mod tests;
