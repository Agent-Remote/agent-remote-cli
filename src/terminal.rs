use std::io::{self, IsTerminal};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use clap::ValueEnum;
use unicode_width::UnicodeWidthStr;

static COLOR_CHOICE: AtomicU8 = AtomicU8::new(0);
static OUTPUT_SUPPRESSED: AtomicBool = AtomicBool::new(false);

/// Restores the prior terminal-output mode when a machine-readable command ends.
pub struct OutputSuppressionGuard {
    previous: bool,
}

impl Drop for OutputSuppressionGuard {
    fn drop(&mut self) {
        OUTPUT_SUPPRESSED.store(self.previous, Ordering::Relaxed);
    }
}

pub fn suppress_output(suppressed: bool) -> OutputSuppressionGuard {
    OutputSuppressionGuard {
        previous: OUTPUT_SUPPRESSED.swap(suppressed, Ordering::Relaxed),
    }
}

pub(crate) fn output_suppressed() -> bool {
    OUTPUT_SUPPRESSED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

pub fn configure(choice: ColorChoice) {
    let value = match choice {
        ColorChoice::Auto => 0,
        ColorChoice::Always => 1,
        ColorChoice::Never => 2,
    };
    COLOR_CHOICE.store(value, Ordering::Relaxed);
}

pub fn colors_enabled() -> bool {
    match COLOR_CHOICE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none()
                && std::env::var("TERM").map_or(true, |term| term != "dumb")
        }
    }
}

fn paint(value: impl std::fmt::Display, code: &str) -> String {
    if colors_enabled() {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

pub fn heading(value: impl std::fmt::Display) -> String {
    paint(value, "1;36")
}

pub fn label(value: impl std::fmt::Display) -> String {
    paint(value, "36")
}

pub fn success(value: impl std::fmt::Display) -> String {
    paint(value, "32")
}

pub fn warning(value: impl std::fmt::Display) -> String {
    paint(value, "33")
}

pub fn failure(value: impl std::fmt::Display) -> String {
    paint(value, "31")
}

pub fn muted(value: impl std::fmt::Display) -> String {
    paint(value, "2")
}

pub fn command(value: impl std::fmt::Display) -> String {
    paint(value, "1")
}

pub fn prompt(value: impl std::fmt::Display) -> String {
    paint(value, "1;36")
}

pub fn status(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "ok" | "ready" | "running" | "active" | "online" | "present" | "completed" => {
            success(value)
        }
        "warn"
        | "warning"
        | "starting"
        | "stopping"
        | "pending"
        | "waiting_user_login"
        | "waiting for approval" => warning(value),
        "fail" | "failed" | "error" | "missing" | "disabled" | "offline" | "interrupted" => {
            failure(value)
        }
        "stopped" | "none" | "inactive" | "unknown" | "not configured" | "not registered" => {
            muted(value)
        }
        _ => value.to_string(),
    }
}

pub fn section(title: &str) {
    if output_suppressed() {
        return;
    }
    println!("{}", heading(title));
}

pub fn success_line(message: impl std::fmt::Display) {
    if output_suppressed() {
        return;
    }
    println!("{} {message}", success("OK"));
}

pub fn warning_line(message: impl std::fmt::Display) {
    if output_suppressed() {
        return;
    }
    println!("{} {message}", warning("WARN"));
}

pub fn failure_line(message: impl std::fmt::Display) {
    if output_suppressed() {
        return;
    }
    println!("{} {message}", failure("FAIL"));
}

pub fn note(message: impl std::fmt::Display) {
    if output_suppressed() {
        return;
    }
    println!("{} {message}", muted("NOTE"));
}

/// Discard bytes that arrived while an interactive attach was shutting down.
///
/// A terminal can deliver the mouse-release part of an SGR mouse report just
/// after tmux has processed `Ctrl-B d`. Call after stopping the input reader
/// and disabling mouse reporting, before restoring cooked mode, to keep these
/// terminal protocol bytes out of the shell. Non-terminal handles are ignored
/// by the platform API.
pub fn flush_input() {
    #[cfg(unix)]
    {
        // SAFETY: tcflush only operates on the process' stdin descriptor and
        // does not dereference any Rust pointer.
        unsafe {
            let _ = libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
        }
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{
            FlushConsoleInputBuffer, GetStdHandle, STD_INPUT_HANDLE,
        };

        // SAFETY: GetStdHandle returns the process-owned console input handle;
        // FlushConsoleInputBuffer validates the handle before using it.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                let _ = FlushConsoleInputBuffer(handle);
            }
        }
    }
}

#[derive(Default)]
pub struct Details {
    rows: Vec<(String, String, bool)>,
}

impl Details {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field(mut self, name: impl Into<String>, value: impl std::fmt::Display) -> Self {
        self.rows.push((name.into(), value.to_string(), false));
        self
    }

    pub fn status(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.rows.push((name.into(), value.into(), true));
        self
    }

    pub fn render(&self) {
        if output_suppressed() {
            return;
        }
        let width = self
            .rows
            .iter()
            .map(|(name, _, _)| UnicodeWidthStr::width(name.as_str()))
            .max()
            .unwrap_or_default();
        for (name, value, is_status) in &self.rows {
            let name = format!(
                "{name}{}",
                " ".repeat(width.saturating_sub(UnicodeWidthStr::width(name.as_str())))
            );
            let value = if *is_status {
                status(value)
            } else {
                value.clone()
            };
            println!("{}  {value}", label(name));
        }
    }
}

pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    status_columns: Vec<usize>,
}

impl Table {
    pub fn new(headers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let headers: Vec<String> = headers.into_iter().map(Into::into).collect();
        let status_columns = headers
            .iter()
            .enumerate()
            .filter_map(|(index, header)| header.eq_ignore_ascii_case("status").then_some(index))
            .collect();
        Self {
            headers,
            rows: Vec::new(),
            status_columns,
        }
    }

    pub fn row(&mut self, values: impl IntoIterator<Item = impl Into<String>>) {
        let row: Vec<_> = values.into_iter().map(Into::into).collect();
        assert_eq!(row.len(), self.headers.len(), "table row width mismatch");
        self.rows.push(row);
    }

    pub fn render(&self) {
        if output_suppressed() {
            return;
        }
        let mut widths: Vec<_> = self
            .headers
            .iter()
            .map(|value| UnicodeWidthStr::width(value.as_str()))
            .collect();
        for row in &self.rows {
            for (index, value) in row.iter().enumerate() {
                widths[index] = widths[index].max(UnicodeWidthStr::width(value.as_str()));
            }
        }
        render_table_row(&self.headers, &widths, true, &self.status_columns);
        for row in &self.rows {
            render_table_row(row, &widths, false, &self.status_columns);
        }
    }
}

fn render_table_row(values: &[String], widths: &[usize], header: bool, status_columns: &[usize]) {
    for (index, value) in values.iter().enumerate() {
        let padding = if index + 1 == values.len() {
            String::new()
        } else {
            " ".repeat(widths[index].saturating_sub(UnicodeWidthStr::width(value.as_str())))
        };
        let rendered = if header {
            heading(value)
        } else if status_columns.contains(&index) {
            status(value)
        } else {
            value.clone()
        };
        if index + 1 == values.len() {
            println!("{rendered}");
        } else {
            print!("{rendered}{padding}  ");
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/src/terminal.rs"]
mod tests;
