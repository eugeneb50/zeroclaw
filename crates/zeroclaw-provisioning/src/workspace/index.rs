//! Workspace membership index - the single authoritative source for
//! PrincipalId <-> WorkspaceId mappings.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
pub use zeroclaw_api::principal::{PrincipalId, WorkspaceId};
use serde::{Deserialize, Serialize};

/// Changes to apply atomically to the workspace index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceChanges {
    /// Added (workspace_id, principal_id) pairs.
    pub added: Vec<(WorkspaceId, PrincipalId)>,
    /// Removed (workspace_id, principal_id) pairs.
    pub removed: Vec<(WorkspaceId, PrincipalId)>,
    /// Tenant ID -> WorkspaceId mappings.
    pub tenant_mappings: Vec<(String, WorkspaceId)>,
}

/// Thread-safe workspace membership index.
///
/// Single authoritative source for:
/// - Which principals belong to which workspace (for MemoryVisibility::Workspace filtering)
/// - Which workspace a principal belongs to (for auth providers setting Principal.workspace_id)
/// - Which workspaces exist for a tenant (multi-tenant support)
#[derive(Clone, Debug)]
pub struct WorkspaceIndex {
    /// WorkspaceId -> Set of PrincipalIds
    forward: Arc<RwLock<HashMap<WorkspaceId, HashMap<PrincipalId, ()>>>>,
    /// PrincipalId -> WorkspaceId (reverse lookup for O(1) principal->workspace)
    reverse: Arc<RwLock<HashMap<PrincipalId, WorkspaceId>>>,
    /// TenantId -> WorkspaceId (for multi-tenant deployments)
    tenant_map: Arc<RwLock<HashMap<String, WorkspaceId>>>,
}

impl WorkspaceIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self {
            forward: Arc::new(RwLock::new(HashMap::new())),
            reverse: Arc::new(RwLock::new(HashMap::new())),
            tenant_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Apply a batch of changes atomically.
    pub fn apply_changes(&self, changes: WorkspaceChanges) {
        // Apply removals first
        for (ws_id, principal_id) in changes.removed {
            if let Ok(mut fwd) = self.forward.write() {
                if let Some(principals) = fwd.get_mut(&ws_id) {
                    principals.remove(&principal_id);
                }
            }
            if let Ok(mut rev) = self.reverse.write() {
                rev.remove(&principal_id);
            }
        }

        // Apply additions
        for (ws_id, principal_id) in changes.added {
            if let Ok(mut fwd) = self.forward.write() {
                fwd.entry(ws_id.clone()).or_default().insert(principal_id.clone(), ());
            }
            if let Ok(mut rev) = self.reverse.write() {
                rev.insert(principal_id, ws_id);
            }
        }

        // Apply tenant mappings
        for (tenant_id, ws_id) in changes.tenant_mappings {
            if let Ok(mut tm) = self.tenant_map.write() {
                tm.insert(tenant_id, ws_id);
            }
        }
    }

    /// Get all principals in a workspace (for MemoryVisibility::Workspace filtering).
    pub fn principals_in_workspace(&self, workspace_id: &WorkspaceId) -> HashMap<PrincipalId, ()> {
        self.forward.read()
            .map(|fwd| fwd.get(workspace_id).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Get workspace for a principal (for auth providers setting Principal.workspace_id).
    pub fn workspace_for_principal(&self, principal_id: &PrincipalId) -> Option<WorkspaceId> {
        self.reverse.read().ok()?.get(principal_id).cloned()
    }

    /// Get workspace for a tenant (multi-tenant).
    pub fn workspace_for_tenant(&self, tenant_id: &str) -> Option<WorkspaceId> {
        self.tenant_map.read().ok()?.get(tenant_id).cloned()
    }

    /// Get workspace for a tenant with default fallback.
    pub fn workspace_for_tenant_or_default(&self, tenant_id: &str, default: WorkspaceId) -> WorkspaceId {
        self.workspace_for_tenant(tenant_id).unwrap_or(default)
    }

    /// List all known workspaces.
    pub fn workspaces(&self) -> Vec<WorkspaceId> {
        self.forward.read()
            .map(|fwd| fwd.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all principals across all workspaces.
    pub fn all_principals(&self) -> Vec<PrincipalId> {
        self.reverse.read()
            .map(|rev| rev.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Check if a principal is in a workspace.
    pub fn principal_in_workspace(&self, principal_id: &PrincipalId, workspace_id: &WorkspaceId) -> bool {
        self.forward.read()
            .map(|fwd| {
                fwd.get(workspace_id)
                    .map(|ps| ps.contains_key(principal_id))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Get stats for monitoring.
    pub fn stats(&self) -> WorkspaceIndexStats {
        let fwd = self.forward.read().ok();
        let rev = self.reverse.read().ok();
        let tm = self.tenant_map.read().ok();

        WorkspaceIndexStats {
            workspace_count: fwd.as_ref().map(|f| f.len()).unwrap_or(0),
            principal_count: rev.as_ref().map(|r| r.len()).unwrap_or(0),
            tenant_count: tm.as_ref().map(|t| t.len()).unwrap_or(0),
        }
    }

    /// Clear all data (used for testing).
    pub fn clear(&self) {
        if let Ok(mut fwd) = self.forward.write() { fwd.clear(); }
        if let Ok(mut rev) = self.reverse.write() { rev.clear(); }
        if let Ok(mut tm) = self.tenant_map.write() { tm.clear(); }
    }
}

impl Default for WorkspaceIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the workspace index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceIndexStats {
    pub workspace_count: usize,
    pub principal_count: usize,
    pub tenant_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_api::principal::{PrincipalId, WorkspaceId};

    #[test]
    fn test_add_and_lookup() {
        let index = WorkspaceIndex::new();
        let ws = WorkspaceId("eng".into());
        let p1 = PrincipalId("user1".into());
        let p2 = PrincipalId("user2".into());

        index.apply_changes(WorkspaceChanges {
            added: vec![(ws.clone(), p1.clone()), (ws.clone(), p2.clone())],
            ..Default::default()
        });

        assert_eq!(index.workspace_for_principal(&p1), Some(ws.clone()));
        assert_eq!(index.workspace_for_principal(&p2), Some(ws.clone()));
        assert!(index.principal_in_workspace(&p1, &ws));
        assert!(index.principal_in_workspace(&p2, &ws));

        let principals = index.principals_in_workspace(&ws);
        assert_eq!(principals.len(), 2);
        assert!(principals.contains_key(&p1));
        assert!(principals.contains_key(&p2));
    }

    #[test]
    fn test_remove() {
        let index = WorkspaceIndex::new();
        let ws = WorkspaceId("eng".into());
        let p1 = PrincipalId("user1".into());

        index.apply_changes(WorkspaceChanges {
            added: vec![(ws.clone(), p1.clone())],
            ..Default::default()
        });
        assert!(index.principal_in_workspace(&p1, &ws));

        index.apply_changes(WorkspaceChanges {
            removed: vec![(ws.clone(), p1.clone())],
            ..Default::default()
        });
        assert!(!index.principal_in_workspace(&p1, &ws));
        assert_eq!(index.workspace_for_principal(&p1), None);
    }

    #[test]
    fn test_tenant_mapping() {
        let index = WorkspaceIndex::new();
        let ws = WorkspaceId("eng".into());

        index.apply_changes(WorkspaceChanges {
            tenant_mappings: vec![("acme-corp".to_string(), ws.clone())],
            ..Default::default()
        });

        assert_eq!(index.workspace_for_tenant("acme-corp"), Some(ws.clone()));
        assert_eq!(index.workspace_for_tenant("unknown"), None);
        assert_eq!(index.workspace_for_tenant_or_default("unknown", WorkspaceId::DEFAULT.into()), WorkspaceId::DEFAULT.into());
    }

    #[test]
    fn test_stats() {
        let index = WorkspaceIndex::new();
        let stats = index.stats();
        assert_eq!(stats.workspace_count, 0);
        assert_eq!(stats.principal_count, 0);
        assert_eq!(stats.tenant_count, 0);

        let ws1 = WorkspaceId("eng".into());
        let ws2 = WorkspaceId("sales".into());
        let p1 = PrincipalId("user1".into());
        let p2 = PrincipalId("user2".into());
        let p3 = PrincipalId("user3".into());

        index.apply_changes(WorkspaceChanges {
            added: vec![
                (ws1.clone(), p1.clone()),
                (ws1.clone(), p2.clone()),
                (ws2.clone(), p3.clone()),
            ],
            tenant_mappings: vec![("acme".to_string(), ws1.clone())],
            ..Default::default()
        });

        let stats = index.stats();
        assert_eq!(stats.workspace_count, 2);
        assert_eq!(stats.principal_count, 3);
        assert_eq!(stats.tenant_count, 1);
    }
}