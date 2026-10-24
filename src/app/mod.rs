use std::ffi::OsStr;
use std::fs::File;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    auth, device, ego_browser, node_install_state, node_release, platform, port_forward,
    runtime_recovery_commands, skill_commands, ssh, terminal, wireguard, workspace,
};
use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command as AsyncCommand;
use tokio::time::sleep;
use uuid::Uuid;

use crate::api::{
    ApiClient, AuthToken, BindingStatusData, CreateDeveloperCredentialProfileRequest,
    CreateToolAccountRequest, DeveloperCredentialGitHubCli, DeveloperCredentialGitIdentity,
    DeveloperCredentialProfileData, DeveloperCredentialSsh, NodeData, NodeJoinCodeRevokeState,
    ToolAccountData,
};
use crate::auth::login::RegistrationOptions as DeviceRegistrationOptions;
use crate::auth::{
    clear_device_token_refresh, has_device_token, load_device_token, store_device_token,
};
use crate::broker_credentials::delete_broker_credential_if_matches;
use crate::cli::{
    AccountCommand, AccountDefaultCommand, Cli, Command, CredentialsCommand, DepsCommand,
    DeviceCommand, DeviceRevokeArgs, DeviceRotateTokenArgs, DeviceUninstallArgs, LoginMethod,
    NodeCommand, NodeInstallArgs, SshCommand, SyncCommand, WireGuardCommand,
};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::doctor::Doctor;
use crate::local_state::LocalState;
use crate::node_install_state::{NodeInstallExchangeState, NodeInstallStage};
use crate::node_release::MANAGED_NODE_VERSION;
use crate::secrets::{device_token_key, user_token_key, SecretStore};
use crate::terminal::{Details, Table};
use agent_remote_cli::identifiers::{resolve_id, short_id};

const CONFIG_IMPORT_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

// Keep workflow files in one private namespace so existing cross-workflow helpers stay private.
include!("entry.rs");
include!("device_node.rs");
include!("account.rs");
include!("sync.rs");
include!("mutagen_environment.rs");
include!("support.rs");

#[cfg(test)]
#[path = "../../tests/unit/src/app/mod.rs"]
mod tests;
