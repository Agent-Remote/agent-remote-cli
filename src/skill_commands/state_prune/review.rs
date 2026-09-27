//! Complete traversal checks bind displayed rows to one stable plan before accepting a credential.

use anyhow::{bail, Result};

use crate::api::skill_state::{PruneDisclosure, PruneSummary};

#[derive(Default)]
pub(super) struct Counts {
    losses: u64,
    blocked: u64,
    groups: u64,
    directories: u64,
    items: u64,
    last_history: Option<(String, String)>,
    past_histories: bool,
}

impl Counts {
    pub fn include(&mut self, rows: &[PruneDisclosure]) -> Result<()> {
        for row in rows {
            match row {
                PruneDisclosure::History {
                    history,
                    selected,
                    group,
                    dependency_blocked,
                    ..
                } => {
                    let key = (history.kind.clone(), history.id.clone());
                    if self.past_histories
                        || self.last_history.as_ref().is_some_and(|old| old >= &key)
                    {
                        bail!("prune histories are duplicated or out of order");
                    }
                    self.last_history = Some(key);
                    self.losses += u64::from(*selected);
                    self.blocked += u64::from(*dependency_blocked);
                    if let Some(group) = group {
                        if *group > self.groups + 1 {
                            bail!("prune loss group is missing");
                        }
                        self.groups = self.groups.max(*group);
                    }
                }
                PruneDisclosure::Compaction { scope, .. } => {
                    self.past_histories = true;
                    if scope == "item" {
                        self.items += 1;
                    } else {
                        self.directories += 1;
                    }
                }
                _ => self.past_histories = true,
            }
        }
        Ok(())
    }

    pub fn finish(&self, summary: &PruneSummary) -> Result<()> {
        if self.losses != summary.history_losses
            || self.blocked != summary.blocked_histories
            || self.groups != summary.groups
            || self.directories != summary.compacted_directories
            || self.items != summary.compacted_items
        {
            bail!("prune disclosure counts differ from the original summary");
        }
        Ok(())
    }
}
