//! Sync engine for SCIM provisioning.
//!
//! Handles full sync on startup and incremental sync on interval,
//! with persistent cursor for delta synchronization.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::error::{ProvisioningError, Result};
use crate::scim::{ScimClient, ScimFilter, ScimListResponse, ScimUser, ScimGroup, parse_filter};
use crate::workspace::index::{WorkspaceIndex, WorkspaceChanges};
use crate::config::ProvisioningConfig;
use crate::sync::cursor::{SyncCursorStore, SyncCursor};
use zeroclaw_api::principal::WorkspaceId;

/// Events emitted by the sync engine.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Full sync completed successfully
    FullSyncComplete { stats: SyncStats },
    /// Incremental sync completed
    IncrementalSyncComplete { stats: SyncStats },
    /// A principal was added to a workspace
    PrincipalAdded { principal_id: String, workspace_id: String },
    /// A principal was removed from a workspace
    PrincipalRemoved { principal_id: String, workspace_id: String },
    /// Workspace mapping changed for a tenant
    TenantMappingChanged { tenant_id: String, workspace_id: String },
    /// Sync error occurred
    SyncError { error: String, is_incremental: bool },
}

/// Statistics from a sync operation.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncStats {
    pub users_processed: usize,
    pub users_added: usize,
    pub users_removed: usize,
    pub groups_processed: usize,
    pub groups_added: usize,
    pub groups_removed: usize,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

/// Sync engine for SCIM provisioning.
pub struct SyncEngine {
    client: ScimClient,
    index: Arc<WorkspaceIndex>,
    cursor_store: Arc<SyncCursorStore>,
    config: ProvisioningConfig,
    event_tx: broadcast::Sender<SyncEvent>,
    user_cursor: Arc<Mutex<SyncCursor>>,
    group_cursor: Arc<Mutex<SyncCursor>>,
}

impl SyncEngine {
    /// Create a new sync engine.
    pub fn new(
        client: ScimClient,
        index: Arc<WorkspaceIndex>,
        cursor_store: Arc<SyncCursorStore>,
        config: ProvisioningConfig,
        event_tx: broadcast::Sender<SyncEvent>,
    ) -> Result<Self> {
        let user_cursor = Arc::new(Mutex::new(cursor_store.get("users")?));
        let group_cursor = Arc::new(Mutex::new(cursor_store.get("groups")?));

        Ok(Self {
            client,
            index,
            cursor_store,
            config,
            event_tx,
            user_cursor,
            group_cursor,
        })
    }

    /// Run a full sync (all users and groups).
    pub async fn run_full_sync(&self) -> Result<SyncStats> {
        let start = std::time::Instant::now();
        info!("Starting full SCIM sync");

        let mut stats = SyncStats::default();
        let mut changes = WorkspaceChanges::default();

        // Sync users
        let user_stats = self.sync_users_full(&mut changes).await?;
        stats.users_processed = user_stats.users_processed;
        stats.users_added = user_stats.users_added;
        stats.users_removed = user_stats.users_removed;

        // Sync groups
        let group_stats = self.sync_groups_full(&mut changes).await?;
        stats.groups_processed = group_stats.groups_processed;
        stats.groups_added = group_stats.groups_added;
        stats.groups_removed = group_stats.groups_removed;

        // Apply changes atomically
        self.index.apply_changes(changes);

        // Update cursors
        let now = Utc::now();
        self.user_cursor.lock().unwrap().update(now, stats.users_processed, None);
        self.group_cursor.lock().unwrap().update(now, stats.groups_processed, None);
        self.cursor_store.set("users", &*self.user_cursor.lock().unwrap())?;
        self.cursor_store.set("groups", &*self.group_cursor.lock().unwrap())?;

        stats.duration_ms = start.elapsed().as_millis() as u64;
        stats.timestamp = Utc::now();

        info!("Full sync complete: users={}, groups={}, duration={}ms", 
              stats.users_processed, stats.groups_processed, stats.duration_ms);

        let _ = self.event_tx.send(SyncEvent::FullSyncComplete { stats: stats.clone() });
        Ok(stats)
    }

    /// Run an incremental sync using cursors.
    pub async fn run_incremental_sync(&self) -> Result<SyncStats> {
        let start = std::time::Instant::now();
        debug!("Starting incremental SCIM sync");

        let mut stats = SyncStats::default();
        let mut changes = WorkspaceChanges::default();

        // Sync users with filter for last modified
        let user_stats = self.sync_users_incremental(&mut changes).await?;
        stats.users_processed = user_stats.users_processed;
        stats.users_added = user_stats.users_added;
        stats.users_removed = user_stats.users_removed;

        // Sync groups
        let group_stats = self.sync_groups_incremental(&mut changes).await?;
        stats.groups_processed = group_stats.groups_processed;
        stats.groups_added = group_stats.groups_added;
        stats.groups_removed = group_stats.groups_removed;

        // Apply changes
        self.index.apply_changes(changes);

        // Update cursors
        let now = Utc::now();
        self.user_cursor.lock().unwrap().update(now, stats.users_processed, None);
        self.group_cursor.lock().unwrap().update(now, stats.groups_processed, None);
        self.cursor_store.set("users", &*self.user_cursor.lock().unwrap())?;
        self.cursor_store.set("groups", &*self.group_cursor.lock().unwrap())?;

        stats.duration_ms = start.elapsed().as_millis() as u64;
        stats.timestamp = now;

        debug!("Incremental sync complete: users={}, groups={}, duration={}ms", 
               stats.users_processed, stats.groups_processed, stats.duration_ms);

        let _ = self.event_tx.send(SyncEvent::IncrementalSyncComplete { stats: stats.clone() });
        Ok(stats)
    }

    async fn sync_users_full(&self, changes: &mut WorkspaceChanges) -> Result<SyncStats> {
        let mut stats = SyncStats::default();
        let mut seen_principals = HashMap::new();
        let mut start_index = 1;
        let count = 100;

        loop {
            let resp: ScimListResponse<ScimUser> = self.client
                .list_users(None, start_index, count)
                .await?;

            if resp.resources.is_empty() {
                break;
            }

            for user in &resp.resources {
                stats.users_processed += 1;
                if let Some(id) = &user.id {
                    let principal_id = id.clone();
                    let workspace_id = self.resolve_workspace_for_user(user);
                    seen_principals.insert(principal_id.clone(), workspace_id.clone());
                    
                    // Check if this is a new or changed mapping
                    if !self.index.principal_in_workspace(
                        &zeroclaw_api::principal::PrincipalId(principal_id.clone()),
                        &workspace_id
                    ) {
                        changes.added.push((workspace_id.clone(), zeroclaw_api::principal::PrincipalId(principal_id.clone())));
                        stats.users_added += 1;
                        let _ = self.event_tx.send(SyncEvent::PrincipalAdded {
                            principal_id: principal_id.clone(),
                            workspace_id: workspace_id.as_str().to_string(),
                        });
                    }
                }
            }

            if resp.resources.len() < count {
                break;
            }
            start_index += count;
        }

        // Find removed users (principals no longer in IdP)
        let current_principals: Vec<_> = self.index.all_principals()
            .into_iter()
            .map(|p| p.0)
            .collect();

        for principal_id in current_principals {
            if !seen_principals.contains_key(&principal_id) {
                if let Some(ws) = self.index.workspace_for_principal(
                    &zeroclaw_api::principal::PrincipalId(principal_id.clone())
                ) {
                    changes.removed.push((ws.clone(), zeroclaw_api::principal::PrincipalId(principal_id.clone())));
                    stats.users_removed += 1;
                    let _ = self.event_tx.send(SyncEvent::PrincipalRemoved {
                        principal_id: principal_id.clone(),
                        workspace_id: ws.as_str().to_string(),
                    });
                }
            }
        }

        Ok(stats)
    }

    async fn sync_users_incremental(&self, changes: &mut WorkspaceChanges) -> Result<SyncStats> {
        // Use filter for lastModified if cursor exists
        let filter = self.user_cursor.lock().unwrap().last_sync.map(|ts| {
            crate::scim::filter::parse_filter(&format!("meta.lastModified gt \"{}\"", ts.to_rfc3339())).ok()
        }).flatten();

        let mut stats = SyncStats::default();
        let mut start_index = 1;
        let count = 100;

        loop {
            let resp: ScimListResponse<ScimUser> = self.client
                .list_users(filter.as_ref(), start_index, count)
                .await?;

            if resp.resources.is_empty() {
                break;
            }

            for user in &resp.resources {
                stats.users_processed += 1;
                if let Some(id) = &user.id {
                    let principal_id = id.clone();
                    let workspace_id = self.resolve_workspace_for_user(user);
                    
                    // Check if mapping changed
                    let current_ws = self.index.workspace_for_principal(
                        &zeroclaw_api::principal::PrincipalId(principal_id.clone())
                    );
                    
                    if current_ws != Some(workspace_id.clone()) {
                        if let Some(old_ws) = current_ws {
                            let old_ws_clone = old_ws.clone();
                            changes.removed.push((old_ws, zeroclaw_api::principal::PrincipalId(principal_id.clone())));
                            stats.users_removed += 1;
                            let _ = self.event_tx.send(SyncEvent::PrincipalRemoved {
                                principal_id: principal_id.clone(),
                                workspace_id: old_ws_clone.as_str().to_string(),
                            });
                        }
                        changes.added.push((workspace_id.clone(), zeroclaw_api::principal::PrincipalId(principal_id.clone())));
                        stats.users_added += 1;
                        let _ = self.event_tx.send(SyncEvent::PrincipalAdded {
                            principal_id: principal_id.clone(),
                            workspace_id: workspace_id.as_str().to_string(),
                        });
                    }
                }
            }

            if resp.resources.len() < count {
                break;
            }
            start_index += count;
        }

        Ok(stats)
    }

    async fn sync_groups_full(&self, _changes: &mut WorkspaceChanges) -> Result<SyncStats> {
        let mut stats = SyncStats::default();
        let mut start_index = 1;
        let count = 100;

        loop {
            let resp: ScimListResponse<ScimGroup> = self.client
                .list_groups(None, start_index, count)
                .await?;

            if resp.resources.is_empty() {
                break;
            }

            for group in &resp.resources {
                stats.groups_processed += 1;
                if let Some(display_name) = &group.display_name {
                    stats.groups_added += 1;
                }
            }

            if resp.resources.len() < count {
                break;
            }
            start_index += count;
        }

        Ok(stats)
    }

    async fn sync_groups_incremental(&self, _changes: &mut WorkspaceChanges) -> Result<SyncStats> {
        let filter = self.group_cursor.lock().unwrap().last_sync.map(|ts| {
            crate::scim::filter::parse_filter(&format!("meta.lastModified gt \"{}\"", ts.to_rfc3339())).ok()
        }).flatten();

        let mut stats = SyncStats::default();
        let mut start_index = 1;
        let count = 100;

        loop {
            let resp: ScimListResponse<ScimGroup> = self.client
                .list_groups(filter.as_ref(), start_index, count)
                .await?;

            if resp.resources.is_empty() {
                break;
            }

            for group in &resp.resources {
                stats.groups_processed += 1;
                if let Some(display_name) = &group.display_name {
                    stats.groups_added += 1;
                }
            }

            if resp.resources.len() < count {
                break;
            }
            start_index += count;
        }

        Ok(stats)
    }

    fn resolve_workspace_for_user(&self, user: &ScimUser) -> WorkspaceId {
        // Use department from enterprise user
        if let Some(enterprise) = user.enterprise_user.as_ref() {
            if let Some(dept) = enterprise.department.as_ref() {
                if let Some(ws) = self.config.static_workspace_mapping.get(dept) {
                    return WorkspaceId(ws.clone());
                }
            }
        }
        WorkspaceId::DEFAULT.into()
    }

    /// Spawn background sync task.
    pub fn spawn_background_sync(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Initial full sync
            if self.config.full_sync_on_startup {
                if let Err(e) = self.run_full_sync().await {
                    error!("Initial full sync failed: {}", e);
                    let _ = self.event_tx.send(SyncEvent::SyncError {
                        error: e.to_string(),
                        is_incremental: false,
                    });
                }
            }

            // Periodic incremental sync
            let mut interval = interval(Duration::from_secs(self.config.sync_interval_seconds));
            loop {
                interval.tick().await;
                if let Err(e) = self.run_incremental_sync().await {
                    error!("Incremental sync failed: {}", e);
                    let _ = self.event_tx.send(SyncEvent::SyncError {
                        error: e.to_string(),
                        is_incremental: true,
                    });
                }
            }
        })
    }

    /// Subscribe to sync events.
    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::index::WorkspaceIndex;
    use crate::config::ProvisioningConfig;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cursor_store() {
        let dir = tempdir().unwrap();
        let store = SyncCursorStore::new(dir.path()).unwrap();
        
        let mut cursor = SyncCursor::new();
        cursor.update(Utc::now(), 42, Some("etag123".into()));
        
        store.set("test", &cursor).unwrap();
        let retrieved = store.get("test").unwrap();
        
        assert_eq!(retrieved.last_count, 42);
        assert_eq!(retrieved.last_etag, Some("etag123".into()));
        assert!(retrieved.last_sync.is_some());
    }

    #[tokio::test]
    async fn test_sync_cursor_default() {
        let cursor = SyncCursor::new();
        assert!(cursor.last_sync.is_none());
        assert_eq!(cursor.last_count, 0);
    }
}