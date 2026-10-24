mod account_binding;
mod account_defaults;
#[allow(dead_code)]
mod account_import;
#[allow(dead_code)]
mod account_operations;
use agent_remote_cli::skills;

mod api;
mod attachments;
mod auth;
mod bridge_release;
mod broker_credentials;
mod cli;
mod config;
mod dependencies;
mod device;
mod doctor;
mod ego_browser;
mod identifiers;
// Legacy APIs remain used by the library/fclaude; the human binary uses confirmed sync.
#[allow(dead_code)]
mod local_state;
mod managed_releases;
// Legacy APIs remain used by the library/fclaude; the human binary uses confirmed sync.
#[allow(dead_code)]
mod mutagen;
mod mutagen_environment;
mod node_install_state;
mod node_release;
mod platform;
mod port_forward;
mod runtime_recovery;
mod runtime_recovery_commands;
mod secrets;
mod setup;
mod skill_commands;
mod ssh;
mod sync_operations;
mod terminal;
mod wireguard;
// Legacy APIs remain used by the library/fclaude; the human binary uses confirmed sync.
#[allow(dead_code)]
mod workspace;

mod app;
pub(crate) use app::{normalize_server_url, prompt_line, prompt_yes_no};

fn main() {
    // Windows gives the PE entry thread a much smaller stack than Unix. The
    // generated command tree and desktop-control future are intentionally
    // large, so polling them there can overflow before Tokio workers exist.
    let result = std::thread::Builder::new()
        .name("agent-remote-main".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(async_main)
        .and_then(|thread| {
            thread
                .join()
                .map_err(|_| std::io::Error::other("main thread panicked"))
        });
    if let Err(error) = result {
        eprintln!("agent-remote failed to start: {error}");
        std::process::exit(1);
    }
}

fn async_main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to initialize async runtime");
    runtime.block_on(async {
        if agent_remote_cli::desktop_control::requested() {
            std::process::exit(agent_remote_cli::desktop_control::run_stdio().await);
        }
        if agent_remote_cli::desktop_schema::requested() {
            use clap::CommandFactory;
            if let Err(error) = agent_remote_cli::desktop_schema::write(cli::Cli::command()) {
                eprintln!("failed to write desktop command schema: {error}");
                std::process::exit(1);
            }
            return;
        }
        app::run_entry().await;
    });
}
