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

#[tokio::main]
async fn main() {
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
}
