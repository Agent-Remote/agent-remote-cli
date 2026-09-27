//! Read-only upstream checks against complete immutable source packages.

use super::{
    remote_result,
    update_result::{self, Row},
    update_source,
};
use crate::api::ApiClient;
use crate::auth::{load_user_token, user_login_error};
use crate::cli::skills::SkillCheckArgs;
use crate::config::{AppPaths, Config};
use anyhow::Result;
use serde_json::json;

pub(super) async fn run(paths: AppPaths, args: SkillCheckArgs, json_mode: bool) -> Result<()> {
    let server = Config::load(&paths)?
        .server_url
        .ok_or_else(|| anyhow::anyhow!("server profile missing"))?;
    let token = load_user_token(&paths, &server)
        .await?
        .ok_or_else(user_login_error)?;
    let client = ApiClient::new(server)?;
    let selection = update_result::interruptible(async {
        Ok(match args.skill {
            Some(name) => vec![update_source::details(&client, &token, &name).await?],
            None => {
                remote_result::data(client.list_skills(&token, None, None, false).await?)?.items
            }
        })
    })
    .await;
    let items = match selection {
        Ok(items) => items,
        Err(error) => {
            let (result, code) = update_result::failed(error);
            return update_result::render(&result, code, json_mode);
        }
    };
    let mut rows = Vec::new();
    for item in items.into_iter().filter(|item| !item.removed) {
        let checked = update_result::interruptible(async {
            update_source::validate(&item)?;
            if let Some(reason) = update_source::skipped(&item) {
                return Ok(update_result::envelope(
                    reason,
                    json!({"revision_id":item.default_revision_id}),
                ));
            }
            let source = update_source::observe(&item, None, None).await?;
            let current = update_source::current(&item)?;
            Ok::<_, anyhow::Error>(update_result::envelope(
                if current.content_digest == source.item.tree_digest {
                    "up_to_date"
                } else {
                    "update_available"
                },
                json!({
                    "revision_id":current.id,"current_digest":current.content_digest,
                    "observed":source.item,"bytes":source.snapshot.total_bytes()
                }),
            ))
        })
        .await;
        let (result, code) = match checked {
            Ok(result) => (result, 0),
            Err(error) => update_result::failed(error),
        };
        rows.push(Row {
            skill_id: item.id,
            name: item.name,
            status: result.status.clone(),
            exit_code: code,
            result,
        });
        if code == 130 {
            break;
        }
    }
    update_result::batch(rows, false, json_mode)
}
