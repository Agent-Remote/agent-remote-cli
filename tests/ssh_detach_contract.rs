//! Run the actual attach future and runtime under a terminal with stdin held open.
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
fn attach_probe() {
    if std::env::var("DETACH_PROBE").as_deref() != Ok("attach") {
        return;
    }
    let mode = std::env::var("DETACH_MODE").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    if mode == "spawn-error" {
        let root = tempfile::tempdir().unwrap();
        let mut command = tokio::process::Command::new(root.path().join("missing-ssh"));
        assert!(runtime
            .block_on(agent_remote_cli::ssh::execute_interactive(&mut command))
            .is_err());
        assert!(!crossterm::terminal::is_raw_mode_enabled().unwrap());
        drop(runtime);
        println!("RUNTIME_EXITED");
        return;
    }
    let missing_command = tempfile::tempdir().unwrap();
    for attempt in 0..2 {
        println!("ATTACH_START_{attempt}");
        let program = if mode == "spawn-error-followup" {
            missing_command.path().join("missing-ssh")
        } else {
            std::env::current_exe().unwrap()
        };
        let mut command = tokio::process::Command::new(program);
        command.args(["--exact", "remote_probe", "--nocapture"]);
        command.env("DETACH_PROBE", "remote");
        let result = runtime.block_on(agent_remote_cli::ssh::execute_interactive(&mut command));
        println!("ATTACH_RETURNED_{attempt}");
        if mode == "spawn-error-followup" {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().code(), Some(23));
        }
        assert!(!crossterm::terminal::is_raw_mode_enabled().unwrap());
        if matches!(mode.as_str(), "followup" | "spawn-error-followup") {
            // The attach reader must be gone before another local consumer
            // starts. A detached blocking thread would steal this byte.
            crossterm::terminal::enable_raw_mode().unwrap();
            print!("LOCAL_INPUT_READY\r\n");
            std::io::stdout().flush().unwrap();
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
            assert_eq!(byte, [b'x']);
            println!("LOCAL_INPUT_RECEIVED");
            crossterm::terminal::disable_raw_mode().unwrap();
        }
    }
    drop(runtime); // Must not wait for a newline or for the outer PTY to close.
    println!("RUNTIME_EXITED");
}

#[test]
fn remote_probe() {
    if std::env::var("DETACH_PROBE").as_deref() != Ok("remote") {
        return;
    }
    crossterm::terminal::enable_raw_mode().unwrap();
    let mode = std::env::var("DETACH_MODE").unwrap();
    if mode == "remote-close" {
        print!("\x1b[?1049h");
    }
    print!("\x1b[?1000h\x1b[?1006hREMOTE_READY\r\n");
    std::io::stdout().flush().unwrap();
    if !matches!(mode.as_str(), "quiet" | "remote-close") {
        let mut input = [0; 2];
        std::io::stdin().read_exact(&mut input).unwrap();
        assert_eq!(input, [2, b'd']);
    } else {
        std::thread::sleep(Duration::from_millis(100));
    }
    if matches!(mode.as_str(), "mouse-motion" | "remote-close") {
        if mode == "remote-close" {
            print!("\x1b[?1049l");
        }
        crossterm::terminal::disable_raw_mode().unwrap();
        println!("REMOTE_COOKED");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_millis(250));
    }
    // Simulate abrupt disconnect: no mouse or raw-mode reset from the child.
    std::process::exit(23);
}

fn exercise(mode: &str) {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    let pair = native_pty_system().openpty(PtySize::default()).unwrap();
    let mut command = CommandBuilder::new(std::env::current_exe().unwrap());
    command.args(["--exact", "attach_probe", "--nocapture"]);
    command.env("DETACH_PROBE", "attach");
    command.env("DETACH_MODE", mode);
    command.env("AGENT_REMOTE_LOGIN_CLIPBOARD", "0");
    command.env("AGENT_REMOTE_CLIPBOARD", "1");
    command.env_remove("AGENT_REMOTE_LOGIN_CLIPBOARD_ACTIVE");
    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let output_thread = std::thread::spawn(move || {
        let mut buffer = [0; 8192];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 || send.send(buffer[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut output = String::new();
    let mut remote_sent = 0;
    let mut local_sent = 0;
    let mut cursor_replies = 0;
    let mut cooked_count = 0;
    let mut motion_until = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Ok(bytes) = receive.recv_timeout(Duration::from_millis(20)) {
            output.push_str(&String::from_utf8_lossy(&bytes));
        }
        // ConPTY can ask the containing terminal for its initial cursor position.
        let queries = output.matches("\x1b[6n").count();
        while cursor_replies < queries {
            writer.write_all(b"\x1b[1;1R").unwrap();
            writer.flush().unwrap();
            cursor_replies += 1;
        }
        let ready = output.matches("REMOTE_READY").count();
        while remote_sent < ready {
            if !matches!(mode, "quiet" | "remote-close") {
                // No newline. Include a release report in flight at detach.
                writer.write_all(b"\x02d\x1b[<0;45;50m").unwrap();
                writer.flush().unwrap();
            }
            remote_sent += 1;
        }
        let cooked = output.matches("REMOTE_COOKED").count();
        if cooked > cooked_count {
            cooked_count = cooked;
            motion_until = Instant::now() + Duration::from_millis(100);
        }
        if matches!(mode, "mouse-motion" | "remote-close") && Instant::now() < motion_until {
            let _ = writer.write_all(b"\x1b[<35;33;50M\x1b[<35;32;51M");
            let _ = writer.flush();
        }
        let ready = output.matches("LOCAL_INPUT_READY").count();
        while local_sent < ready {
            writer.write_all(b"x").unwrap();
            writer.flush().unwrap();
            local_sent += 1;
        }
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
    };
    drop(writer);
    drop(pair.master);
    output_thread.join().unwrap();
    for bytes in receive.try_iter() {
        output.push_str(&String::from_utf8_lossy(&bytes));
    }
    assert!(
        status.is_some_and(|status| status.success()),
        "{mode}: {output}"
    );
    assert_eq!(
        remote_sent,
        if mode.starts_with("spawn-error") {
            0
        } else {
            2
        },
        "{output}"
    );
    assert!(output.contains("RUNTIME_EXITED"), "{output}");
    assert!(
        !output.contains("[<35;"),
        "mouse motion leaked after detach: {output}"
    );
    #[cfg(unix)]
    {
        assert!(
            output.matches("\x1b[?1006l").count() >= if mode == "spawn-error" { 1 } else { 2 },
            "{output}"
        );
        assert!(!output.contains("^[[<0;45;50m"), "{output}");
    }
}

#[test]
fn remote_exit_needs_no_input_or_newline() {
    exercise("quiet");
}

#[test]
fn detach_with_mouse_release_needs_no_enter() {
    exercise("detach");
}

#[test]
fn repeated_attach_leaves_local_input_available() {
    exercise("followup");
}

#[test]
fn failed_ssh_spawn_restores_terminal_and_stops_reader() {
    exercise("spawn-error");
}

#[test]
fn failed_ssh_spawn_leaves_local_input_available() {
    exercise("spawn-error-followup");
}

#[test]
fn mouse_motion_during_cooked_ssh_shutdown_is_discarded() {
    exercise("mouse-motion");
}

#[test]
fn remote_screen_exit_stops_mouse_before_ssh_finishes() {
    exercise("remote-close");
}
