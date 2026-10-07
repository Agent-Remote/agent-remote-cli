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
mod local_state;
mod managed_releases;
mod mutagen;
mod node_install_state;
mod node_release;
mod platform;
mod port_forward;
mod runtime_recovery_commands;
mod secrets;
mod skill_commands;
mod ssh;
mod terminal;
mod wireguard;
mod workspace;

mod app;
pub(crate) use app::{normalize_server_url, prompt_line, prompt_yes_no};

#[tokio::main]
async fn main() {
    app::run_entry().await;
}
