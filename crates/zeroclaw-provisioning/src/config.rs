//! Provisioning configuration types.

use std::collections::BTreeMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Top-level provisioning configuration (`[provisioning]` in config.toml).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ProvisioningConfig {
    // ───── Inbound SCIM (ZeroClaw as Consumer) ─────

    /// IdP SCIM 2.0 endpoint (e.g., "https://idp.example.com/scim/v2")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_endpoint: Option<String>,

    /// Bearer token for SCIM endpoint (supports `op://` references)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_token: Option<String>,

    /// SCIM attribute path that identifies workspace membership.
    /// Examples:
    ///   - "urn:scim:schemas:extension:enterprise:2.0:User:department"
    ///   - "groups[?type eq 'workspace'].value"
    ///   - "userName" (for username-based mapping)
    #[serde(default = "default_workspace_attribute")]
    pub workspace_attribute: String,

    /// Full sync on startup before serving requests.
    #[serde(default = "default_true")]
    pub full_sync_on_startup: bool,

    /// Incremental sync interval in seconds.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_seconds: u64,

    /// Static fallback mapping when SCIM is unavailable.
    /// Key = SCIM attribute value, Value = WorkspaceId.
    #[serde(default)]
    pub static_workspace_mapping: BTreeMap<String, String>,

    // ───── Outbound SCIM (ZeroClaw as Provider) ─────

    /// Downstream applications that consume SCIM from ZeroClaw.
    #[serde(default)]
    pub downstream: Vec<DownstreamConfig>,

    // ───── Multi-Tenant Settings ─────

    #[serde(default)]
    pub multi_tenant: MultiTenantConfig,

    // ───── Conflict Resolution ─────

    #[serde(default)]
    pub conflict: ConflictConfig,
}

fn default_workspace_attribute() -> String {
    "urn:scim:schemas:extension:enterprise:2.0:User:department".to_string()
}

fn default_true() -> bool {
    true
}

fn default_sync_interval() -> u64 {
    300
}

impl ProvisioningConfig {
    /// Returns true if inbound SCIM is configured.
    pub fn has_inbound_scim(&self) -> bool {
        self.scim_endpoint.is_some() && self.scim_token.is_some()
    }

    /// Returns true if any downstream is configured.
    pub fn has_downstreams(&self) -> bool {
        !self.downstream.is_empty()
    }
}

/// Configuration for a single downstream SCIM consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DownstreamConfig {
    /// Unique name for this downstream (used in logs, metrics).
    pub name: String,

    /// SCIM 2.0 endpoint of the downstream application.
    pub scim_endpoint: String,

    /// Bearer token for authenticating to downstream (supports `op://`).
    pub scim_token: String,

    /// Workspaces to push to this downstream.
    /// Use `["all"]` to push all workspaces, or list specific workspace IDs.
    #[serde(default = "default_all_workspaces")]
    pub workspace_filter: Vec<String>,

    /// Attribute mapping from ZeroClaw principal to downstream SCIM User.
    /// Key = downstream SCIM attribute, Value = source path (e.g., "email", "displayName").
    #[serde(default)]
    pub attribute_mapping: BTreeMap<String, String>,

    /// Push changes in real-time as they arrive (vs batch on interval).
    #[serde(default = "default_true")]
    pub push_on_change: bool,

    /// Optional: custom SCIM schemas/extensions this downstream expects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schemas: Vec<String>,
}

fn default_all_workspaces() -> Vec<String> {
    vec!["all".to_string()]
}

/// Multi-tenant context extraction settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MultiTenantConfig {
    /// Enable multi-tenant mode (extract tenant from requests).
    #[serde(default)]
    pub enabled: bool,

    /// HTTP header containing tenant ID.
    #[serde(default = "default_tenant_header")]
    pub tenant_header: String,

    /// Fallback header if primary is missing (e.g., "X-Forwarded-Host").
    #[serde(default = "default_tenant_fallback_header")]
    pub tenant_header_fallback: String,

    /// Sentinel tenant ID for single-tenant / shared-operator deployments.
    #[serde(default = "default_default_tenant")]
    pub default_tenant: String,
}

fn default_tenant_header() -> String {
    "X-ZeroClaw-Tenant".to_string()
}

fn default_tenant_fallback_header() -> String {
    "X-Forwarded-Host".to_string()
}

fn default_default_tenant() -> String {
    "default".to_string()
}

/// Conflict resolution configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConflictConfig {
    /// Resolution strategy.
    #[serde(default = "default_conflict_strategy")]
    pub strategy: ConflictStrategy,

    /// Optional path to WASM module implementing custom ConflictResolver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_resolver: Option<PathBuf>,
}

fn default_conflict_strategy() -> ConflictStrategy {
    ConflictStrategy::LastWriteWins
}

/// Conflict resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ConflictStrategy {
    /// Last-write-wins based on `meta.lastModified` timestamps.
    #[default]
    LastWriteWins,

    /// Queue for manual review (not yet implemented).
    ManualReview,

    /// Custom resolver via WASM plugin.
    Custom,
}

impl std::fmt::Display for ConflictStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LastWriteWins => write!(f, "last_write_wins"),
            Self::ManualReview => write!(f, "manual_review"),
            Self::Custom => write!(f, "custom"),
        }
    }
}