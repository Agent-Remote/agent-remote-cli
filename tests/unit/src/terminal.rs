// Tests for src/terminal.rs.

use std::sync::Mutex;

use super::{colors_enabled, configure, status, ColorChoice, Details, Table};

static COLOR_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn forced_color_wraps_status_values() {
    let _guard = COLOR_LOCK.lock().unwrap();
    configure(ColorChoice::Always);
    assert!(status("running").contains("\x1b[32m"));
    configure(ColorChoice::Never);
    assert_eq!(status("running"), "running");
    configure(ColorChoice::Auto);
}

#[test]
fn details_and_tables_accept_empty_and_populated_data() {
    let _guard = COLOR_LOCK.lock().unwrap();
    Details::new()
        .field("Home", "/tmp/home")
        .status("Status", "active");
    let mut table = Table::new(["ID", "STATUS"]);
    table.row(["abc", "running"]);
    configure(ColorChoice::Auto);
    let _ = colors_enabled();
}
