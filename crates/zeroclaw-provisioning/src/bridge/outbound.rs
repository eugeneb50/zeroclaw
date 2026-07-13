//! Outbound SCIM bridge - pushes changes to downstream applications.

use crate::config::DownstreamConfig;
use crate::scim::schema::ScimUser;
use crate::scim::schema::ScimGroup;
use crate::workspace::index::WorkspaceIndex;
use zeroclaw_api::principal::PrincipalId;
use std::sync::Arc;

/// Trait for pushing SCIM changes to downstream applications.
#[async_trait::async_trait]
pub trait OutboundPusher: Send + Sync {
    async fn push_user(&self, user: &ScimUser) -> crate::error::Result<()>;
    async fn push_group(&self, group: &ScimGroup) -> crate::error::Result<()>;
    async fn delete_user(&self, id: &str) -> crate::error::Result<()>;
    async fn delete_group(&self, id: &str) -> crate::error::Result<()>;
}

/// Bridge for pushing SCIM changes to a single downstream application.
pub struct OutboundBridge {
    config: Arc<DownstreamConfig>,
    client: crate::scim::ScimClient,
    index: Arc<WorkspaceIndex>,
}

impl OutboundBridge {
    pub fn new(config: DownstreamConfig, index: Arc<WorkspaceIndex>) -> crate::error::Result<Self> {
        let client = crate::scim::ScimClient::new(
            config.scim_endpoint.clone(),
            config.scim_token.clone(),
        )?;
        
        Ok(Self {
            config: Arc::new(config),
            client,
            index,
        })
    }

    /// Check if a principal should be pushed to this downstream.
    pub async fn should_push(&self, principal_id: &str, index: &WorkspaceIndex) -> bool {
        // Check workspace filter
        if self.config.workspace_filter.contains(&"all".to_string()) {
            return true;
        }
        
        // Check if principal's workspace is in filter
        let pid = crate::workspace::index::PrincipalId(principal_id.to_string());
        if let Some(ws) = index.workspace_for_principal(&pid) {
            return self.config.workspace_filter.contains(&ws.as_str().to_string());
        }
        
        false
    }
    
    /// Check if a workspace should be pushed to this downstream.
    pub async fn should_push_workspace(&self, workspace_id: &str, _index: &WorkspaceIndex) -> bool {
        // Check workspace filter
        if self.config.workspace_filter.contains(&"all".to_string()) {
            return true;
        }
        
        // Check if workspace is in filter
        self.config.workspace_filter.contains(&workspace_id.to_string())
    }

    /// Push a user to the downstream.
    pub async fn push_user(&self, user: &ScimUser) -> crate::error::Result<()> {
        if let Some(existing_id) = &user.id {
            self.client.replace_user(existing_id, user).await?;
        } else {
            self.client.create_user(user).await?;
        }
        Ok(())
    }

    /// Push a group to the downstream.
    pub async fn push_group(&self, group: &ScimGroup) -> crate::error::Result<()> {
        if let Some(existing_id) = &group.id {
            self.client.replace_group(existing_id, group).await?;
        } else {
            self.client.create_group(group).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl OutboundPusher for OutboundBridge {
    async fn push_user(&self, user: &ScimUser) -> crate::error::Result<()> {
        self.push_user(user).await
    }
    
    async fn push_group(&self, group: &ScimGroup) -> crate::error::Result<()> {
        self.push_group(group).await
    }
    
    async fn delete_user(&self, id: &str) -> crate::error::Result<()> {
        self.client.delete_user(id).await
    }
    
    async fn delete_group(&self, id: &str) -> crate::error::Result<()> {
        self.client.delete_group(id).await
    }
}
