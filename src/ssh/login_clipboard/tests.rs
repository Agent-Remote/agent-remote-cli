use super::*;

fn url(state: &str) -> String {
    format!("https://claude.com/cai/oauth/authorize?code=true&client_id=test-client&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback&scope=user%3Aprofile&code_challenge={}&code_challenge_method=S256&state={state}", "a".repeat(43))
}

fn paint(url: &str, width: usize) -> Vec<u8> {
    let mut output = b"\x1b[2J\x1b[HClaude Code\r\n\r\nLogin\r\nBrowser didn't open? Use the url below to sign in\r\n(Copied to tmux buffer)\r\n\r\n\x1b[4m".to_vec();
    for chunk in url.as_bytes().chunks(width) {
        output.extend(chunk);
        output.extend(b"\r\n");
    }
    output.extend(b"\x1b[0m\r\nHold Shift while selecting\r\n\r\nPaste code here if prompted > ");
    output
}

#[test]
fn copies_complete_wrapped_urls_at_multiple_terminal_widths() {
    for width in [60, 80, 120, 160, 240] {
        let mut screen = LoginScreen::new(48, width);
        let expected = url("first-login");
        screen.process(&paint(&expected, width as usize), 48, width);
        assert_eq!(screen.take_url(), Some(expected));
        assert_eq!(screen.take_url(), None);
    }
}

#[test]
fn fragmented_output_is_not_copied_until_the_login_page_is_complete() {
    let expected = url("fragmented");
    let bytes = paint(&expected, 80);
    let mut screen = LoginScreen::new(48, 80);
    let prompt = bytes
        .windows(b"Paste code here".len())
        .position(|v| v == b"Paste code here")
        .unwrap();
    for byte in &bytes[..prompt] {
        screen.process(&[*byte], 48, 80);
        assert_eq!(screen.take_url(), None);
    }
    for chunk in bytes[prompt..].chunks(3) {
        screen.process(chunk, 48, 80);
    }
    assert_eq!(screen.take_url(), Some(expected));
}

#[test]
fn redraw_does_not_overwrite_clipboard_but_relogin_copies_new_url() {
    let mut screen = LoginScreen::new(48, 120);
    let first = url("first");
    screen.process(&paint(&first, 120), 48, 120);
    assert_eq!(screen.take_url(), Some(first.clone()));
    screen.process(&paint(&first, 80), 48, 80);
    assert_eq!(screen.take_url(), None);
    let next = url("second");
    screen.process(&paint(&next, 80), 48, 80);
    assert_eq!(screen.take_url(), Some(next));
}

#[test]
fn terminal_soft_wrap_and_ansi_colors_preserve_exact_url() {
    let expected = url("soft-wrap");
    let mut screen = LoginScreen::new(48, 80);
    let bytes = format!("\x1b[2J\x1b[HBrowser didn't open?\r\n\r\n\x1b[34m{expected}\x1b[0m\r\n\r\nPaste code here if prompted > ");
    screen.process(bytes.as_bytes(), 48, 80);
    assert_eq!(screen.take_url(), Some(expected));
}

#[test]
fn rejects_non_login_pages_untrusted_origins_and_partial_parameters() {
    let good = url("state");
    assert!(valid_login_url(&good));
    for bad in [
        good.replace("claude.com/cai", "evil.test/cai"),
        good.replace("claude.com/cai", "claude.com.evil.test/cai"),
        good.replace("https://claude.com", "https://user@claude.com"),
        good.replace("https://claude.com", "http://claude.com"),
        good.replace("/cai/oauth/authorize", "/unrelated"),
        good.replace("state=state", "state="),
        good.replace("response_type=code", "response_type=token"),
        good.replace("code_challenge_method=S256", "code_challenge_method=plain"),
        good.replace(&"a".repeat(43), "incomplete"),
        format!("{good}&state=duplicate"),
        format!("{good}#fragment"),
        format!("{good}\x07"),
        format!("{good}&extra={}", "x".repeat(MAX_URL_BYTES)),
    ] {
        assert!(!valid_login_url(&bad), "accepted invalid fixture");
    }
    let mut screen = LoginScreen::new(48, 160);
    screen.process(good.as_bytes(), 48, 160);
    assert_eq!(screen.take_url(), None);
    // An OSC 8 hyperlink target or arbitrary OSC 52 payload must not trigger copying.
    screen.process(
        format!("\x1b]8;;{good}\x07click here\x1b]8;;\x07").as_bytes(),
        48,
        160,
    );
    assert_eq!(screen.take_url(), None);
}
