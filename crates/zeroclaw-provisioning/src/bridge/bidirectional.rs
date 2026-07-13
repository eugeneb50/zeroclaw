//! Bidirectional bridge orchestrates inbound and outbound sync.

use std::collections::HashMap;
use std::sync::Arc;
use crate::config::{ProvisioningConfig, DownstreamConfig};
use crate::workspace::index::WorkspaceIndex;
use crate::bridge::{OutboundBridge, ConflictResolver, LastWriteWinsResolver};
use crate::error::Result;

/// Bidirectional bridge coordinates inbound (IdP → ZeroClaw) and outbound (ZeroClaw → downstreams) sync.
pub struct BidirectionalBridge {
    outbound_bridges: HashMap<String, Arc<OutboundBridge>>,
    conflict_resolver: Arc<dyn ConflictResolver>,
    index: Arc<WorkspaceIndex>,
}

impl BidirectionalBridge {
    pub fn new(config: ProvisioningConfig, index: Arc<WorkspaceIndex>) -> Result<Self> {
        let mut outbound_bridges = HashMap::new();
        
        for downstream in &config.downstream {
            let bridge = Arc::new(OutboundBridge::new(downstream.clone(), index.clone())?);
            outbound_bridges.insert(downstream.name.clone(), bridge);
        }

        let conflict_resolver = Arc::new(LastWriteWinsResolver::default()) as Arc<dyn ConflictResolver>;

        Ok(Self {
            outbound_bridges,
            conflict_resolver,
            index,
        })
    }

    /// Handle an inbound change from SCIM sync - push to all relevant downstreams.
    pub async fn on_inbound_change(&self, user: &crate::scim::schema::ScimUser) -> Result<()> {
        // Get workspace for this user
        let workspace_id = if let Some(enterprise_user) = &user.enterprise_user {
            if let Some(dept) = &enterprise_user.department {
                crate::workspace::index::WorkspaceId(dept.clone())
            } else {
                crate::workspace::index::WorkspaceId(zeroclaw_api::principal::WorkspaceId::DEFAULT.to_owned())
            }
        } else {
            crate::workspace::index::WorkspaceId(zeroclaw_api::principal::WorkspaceId::DEFAULT.to_owned())
        };

        // Push to all downstreams that should receive this workspace
        for (name, bridge) in &self.outbound_bridges {
            if bridge.should_push_workspace(workspace_id.as_str(), &self.index).await {
                if let Err(e) = bridge.push_user(user).await {
                    tracing::warn!("Failed to push user to downstream {}: {}", name, e);
                }
            }
        }

        Ok(())
    }

    /// Handle an outbound change from a downstream - check for conflicts with inbound state.
    pub async fn on_outbound_change(&self, downstream: &str, user: &crate::scim::schema::ScimUser) -> Result<()> {
        // Would check for conflicts with inbound state
        // For now, just log
        tracing::debug!("Outbound change from {}: {:?}", downstream, user.id);
        Ok(())
    }
}