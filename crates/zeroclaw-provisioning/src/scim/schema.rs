use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroclaw_api::principal::{PrincipalId, WorkspaceId};

/// SCIM 2.0 User resource (RFC 7643 §4.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// SCIM schemas URIs.
    #[serde(default = "default_user_schemas")]
    pub schemas: Vec<String>,

    /// Unique identifier (set by server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// External ID from source system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// User name (typically email or UPN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,

    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Nickname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nick_name: Option<String>,

    /// Profile URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,

    /// Title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// User type (e.g., "Employee", "Contractor").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,

    /// Preferred language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,

    /// Locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Timezone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,

    /// Active status.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub active: bool,

    /// Emails.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,

    /// Phone numbers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phone_numbers: Vec<ScimPhoneNumber>,

    /// Instant messaging addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ims: Vec<ScimIm>,

    /// Photos.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub photos: Vec<ScimPhoto>,

    /// Addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<ScimAddress>,

    /// Groups membership.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScimGroupRef>,

    /// Entitlements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entitlements: Vec<ScimEntitlement>,

    /// Roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<ScimRole>,

    /// X.509 certificates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x509_certificates: Vec<ScimCertificate>,

    /// Metadata (set by server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    /// Enterprise User extension (RFC 7643 §4.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_user: Option<ScimEnterpriseUser>,

    /// Catch-all for custom attributes.
    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_user_schemas() -> Vec<String> {
    vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()]
}

fn default_true() -> bool {
    true
}

fn is_true(val: &bool) -> bool {
    *val
}

/// SCIM 2.0 Group resource (RFC 7643 §4.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    #[serde(default = "default_group_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Display name (required for groups).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimMember>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_group_schemas() -> Vec<String> {
    vec!["urn:ietf:params:scim:schemas:core:2.0:Group".to_string()]
}

/// SCIM Enterprise User extension (RFC 7643 §4.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimEnterpriseUser {
    /// Employee number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,

    /// Cost center.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_center: Option<String>,

    /// Organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Division.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub division: Option<String>,

    /// Department — primary workspace attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,

    /// Manager reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<ScimManager>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
pub struct ScimManager {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// SCIM metadata (server-managed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    /// Resource type ("User" or "Group").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,

    /// Creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<chrono::DateTime<chrono::Utc>>,

    /// Last modification timestamp — key for incremental sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<chrono::DateTime<chrono::Utc>>,

    /// Resource location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// Resource version (ETag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// SCIM ListResponse for paginated results (RFC 7644 §3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    #[serde(default = "default_list_schemas")]
    pub schemas: Vec<String>,

    pub total_results: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub items_per_page: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<i64>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<T>,
}

fn default_list_schemas() -> Vec<String> {
    vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()]
}

/// SCIM ServiceProviderConfig (RFC 7644 §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimServiceProviderConfig {
    #[serde(default = "default_spc_schemas")]
    pub schemas: Vec<String>,

    pub patch: ScimFeature,
    pub bulk: ScimBulkFeature,
    pub filter: ScimFilterFeature,
    pub change_password: ScimFeature,
    pub sort: ScimFeature,
    pub etag: ScimFeature,
    #[serde(rename = "authenticationSchemes")]
    pub authentication_schemes: Vec<ScimAuthScheme>,
}

fn default_spc_schemas() -> Vec<String> {
    vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimFeature {
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimBulkFeature {
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_operations: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_payload_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimFilterFeature {
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_results: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimAuthScheme {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub spec_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
    #[serde(rename = "type")]
    pub auth_type: String,
    pub primary: bool,
}

/// SCIM Email.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

fn is_false(val: &bool) -> bool {
    !*val
}

/// SCIM PhoneNumber.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimPhoneNumber {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM InstantMessage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimIm {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Photo.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimPhoto {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Address.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Group reference (in User.groups).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// SCIM Member (in Group.members).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimMember {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// SCIM Entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimEntitlement {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Role.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimRole {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimCertificate {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// ============================================================================
/// ZeroClaw Custom SCIM Extension Resources (urn:zeroclaw:schemas:extension:*)
/// ============================================================================

/// SCIM Channel resource — messaging platform integration.
/// Maps to Config.channels table entries.
/// Schema: urn:zeroclaw:schemas:extension:Channel:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimChannel {
    #[serde(default = "default_channel_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Channel type identifier (e.g., "slack", "discord", "telegram", "matrix", "gmail", "whatsapp").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_type: Option<String>,

    /// Human-readable display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Whether this channel is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    /// Configuration specific to the channel type (serialized as JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,

    /// Peer group this channel belongs to (for routing/ACL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_group: Option<String>,

    /// Allowed users/principals for this channel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_users: Vec<String>,

    /// Webhook URL for inbound messages (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,

    /// Media pipeline configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_pipeline: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_channel_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:Channel:1.0".to_string()]
}

/// SCIM ChannelBinding resource — binds a channel to a peer group with routing rules.
/// Schema: urn:zeroclaw:schemas:extension:ChannelBinding:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimChannelBinding {
    #[serde(default = "default_channel_binding_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Channel ID this binding applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Peer group ID this binding targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_group_id: Option<String>,

    /// Inbound routing priority (lower = higher priority).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_priority: Option<i32>,

    /// Outbound routing enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub outbound_enabled: bool,

    /// Message transformation rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform_rules: Option<serde_json::Value>,

    /// Rate limiting configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_channel_binding_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:ChannelBinding:1.0".to_string()]
}

/// SCIM Agent resource — autonomous agent instance configuration.
/// Schema: urn:zeroclaw:schemas:extension:Agent:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimAgent {
    #[serde(default = "default_agent_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Agent name/identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Model provider reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,

    /// Model name/identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// System prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,

    /// Temperature for sampling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,

    /// Max tokens per response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    /// Enabled tools (by tool spec name).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,

    /// Enabled skills.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,

    /// Memory strategy configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_strategy: Option<String>,

    /// Peer groups this agent can access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_groups: Vec<String>,

    /// Whether the agent is active.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub active: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_agent_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:Agent:1.0".to_string()]
}

/// SCIM Skill resource — reusable agent capability package.
/// Schema: urn:zeroclaw:schemas:extension:Skill:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimSkill {
    #[serde(default = "default_skill_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Skill name/identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Entry point (module:function or WASM path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,

    /// Configuration schema (JSON Schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<serde_json::Value>,

    /// Default configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_config: Option<serde_json::Value>,

    /// Required permissions/capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_permissions: Vec<String>,

    /// Whether skill is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_skill_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:Skill:1.0".to_string()]
}

/// SCIM CronJob resource — scheduled task definition.
/// Schema: urn:zeroclaw:schemas:extension:CronJob:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimCronJob {
    #[serde(default = "default_cron_job_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Job name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Cron expression (standard or Quartz).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,

    /// Timezone for schedule evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,

    /// Command to execute (tool call or skill invocation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Arguments for the command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,

    /// Target channel for output (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_channel: Option<String>,

    /// Whether job is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    /// Maximum concurrent runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u32>,

    /// Timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_cron_job_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:CronJob:1.0".to_string()]
}

/// SCIM Tool resource — tool specification available to agents.
/// Schema: urn:zeroclaw:schemas:extension:Tool:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimTool {
    #[serde(default = "default_tool_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Tool name (unique identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tool kind: "shell", "file", "memory", "browser", "custom", "wasm".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// JSON Schema for parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters_schema: Option<serde_json::Value>,

    /// Required permissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_permissions: Vec<String>,

    /// Whether tool is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    /// Execution timeout (seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,

    /// Shared state key prefix (for stateful tools).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_key_prefix: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_tool_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:Tool:1.0".to_string()]
}

/// SCIM Memory resource — memory backend configuration.
/// Schema: urn:zeroclaw:schemas:extension:Memory:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimMemory {
    #[serde(default = "default_memory_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Memory backend name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Backend type: "markdown", "sqlite", "vector", "hybrid".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<String>,

    /// Connection string / path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,

    /// Embedding model for vector search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,

    /// Vector dimensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,

    /// Retention policy (days).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,

    /// Maximum entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<u64>,

    /// Whether backend is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_memory_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:Memory:1.0".to_string()]
}

/// SCIM ModelProvider resource — LLM provider configuration.
/// Schema: urn:zeroclaw:schemas:extension:ModelProvider:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimModelProvider {
    #[serde(default = "default_model_provider_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Provider name (e.g., "openai", "anthropic", "ollama", "vllm", "openrouter").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Provider type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_type: Option<String>,

    /// API base URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,

    /// API key (sensitive — write-only in responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Default model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,

    /// Available models.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,

    /// Request timeout (seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,

    /// Max retries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,

    /// Whether provider is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_model_provider_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:ModelProvider:1.0".to_string()]
}

/// SCIM PeerGroup resource — access control grouping.
/// Schema: urn:zeroclaw:schemas:extension:PeerGroup:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimPeerGroup {
    #[serde(default = "default_peer_group_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Group name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Member principal IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,

    /// Allowed channels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_channels: Vec<String>,

    /// Allowed agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_agents: Vec<String>,

    /// Allowed tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<String>,

    /// Whether group is active.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub active: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_peer_group_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:PeerGroup:1.0".to_string()]
}

/// SCIM RuntimeConfig resource — agent runtime configuration.
/// Schema: urn:zeroclaw:schemas:extension:RuntimeConfig:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimRuntimeConfig {
    #[serde(default = "default_runtime_config_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Configuration name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Max loop iterations per turn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_iterations: Option<u32>,

    /// Turn timeout (seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_timeout_seconds: Option<u64>,

    /// Enable tool call validation.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub validate_tool_calls: bool,

    /// Enable streaming responses.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub streaming: bool,

    /// Default system prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_system_prompt: Option<String>,

    /// Security policy profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_policy: Option<String>,

    /// Observability sampling rate (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observability_sampling: Option<f32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_runtime_config_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:RuntimeConfig:1.0".to_string()]
}

/// SCIM Peripheral resource — hardware peripheral configuration.
/// Schema: urn:zeroclaw:schemas:extension:Peripheral:1.0
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ScimPeripheral {
    #[serde(default = "default_peripheral_schemas")]
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Peripheral name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Peripheral type: "gpio", "i2c", "spi", "uart", "usb", "camera", "sensor", "actuator".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peripheral_type: Option<String>,

    /// Device path or identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_path: Option<String>,

    /// Driver name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Configuration parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,

    /// Assigned agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_agent: Option<String>,

    /// Whether peripheral is enabled.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    #[serde(flatten, default)]
    pub custom: HashMap<String, serde_json::Value>,
}

fn default_peripheral_schemas() -> Vec<String> {
    vec!["urn:zeroclaw:schemas:extension:Peripheral:1.0".to_string()]
}