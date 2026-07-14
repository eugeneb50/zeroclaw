//! SCIM 2.0 endpoints mounted on the gateway.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde_json::Value;
use tracing::debug;
use uuid::Uuid;

use zeroclaw_provisioning::scim::schema::{
    ScimListResponse, ScimUser, ScimGroup, ScimServiceProviderConfig,
    ScimFeature, ScimBulkFeature, ScimFilterFeature, ScimAuthScheme, ScimMeta,
};

/// Create SCIM v2 routes for the gateway
pub fn scim_routes() -> Router<crate::AppState> {
    Router::new()
        // Standard SCIM resources
        .route("/Users", get(list_users).post(create_user))
        .route(
            "/Users/{id}",
            get(get_user)
                .put(update_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/Groups", get(list_groups).post(create_group))
        .route(
            "/Groups/{id}",
            get(get_group)
                .put(update_group)
                .patch(patch_group)
                .delete(delete_group),
        )
        // ZeroClaw custom resources
        .route("/Channels", get(list_channels).post(create_channel))
        .route(
            "/Channels/{id}",
            get(get_channel)
                .put(update_channel)
                .patch(patch_channel)
                .delete(delete_channel),
        )
        .route("/ChannelBindings", get(list_channel_bindings).post(create_channel_binding))
        .route(
            "/ChannelBindings/{id}",
            get(get_channel_binding)
                .put(update_channel_binding)
                .patch(patch_channel_binding)
                .delete(delete_channel_binding),
        )
        .route("/Agents", get(list_agents).post(create_agent))
        .route(
            "/Agents/{id}",
            get(get_agent)
                .put(update_agent)
                .patch(patch_agent)
                .delete(delete_agent),
        )
        .route("/Skills", get(list_skills).post(create_skill))
        .route(
            "/Skills/{id}",
            get(get_skill)
                .put(update_skill)
                .patch(patch_skill)
                .delete(delete_skill),
        )
        .route("/CronJobs", get(list_cron_jobs).post(create_cron_job))
        .route(
            "/CronJobs/{id}",
            get(get_cron_job)
                .put(update_cron_job)
                .patch(patch_cron_job)
                .delete(delete_cron_job),
        )
        .route("/Tools", get(list_tools).post(create_tool))
        .route(
            "/Tools/{id}",
            get(get_tool)
                .put(update_tool)
                .patch(patch_tool)
                .delete(delete_tool),
        )
        .route("/Memories", get(list_memories).post(create_memory))
        .route(
            "/Memories/{id}",
            get(get_memory)
                .put(update_memory)
                .patch(patch_memory)
                .delete(delete_memory),
        )
        .route("/ModelProviders", get(list_model_providers).post(create_model_provider))
        .route(
            "/ModelProviders/{id}",
            get(get_model_provider)
                .put(update_model_provider)
                .patch(patch_model_provider)
                .delete(delete_model_provider),
        )
        .route("/PeerGroups", get(list_peer_groups).post(create_peer_group))
        .route(
            "/PeerGroups/{id}",
            get(get_peer_group)
                .put(update_peer_group)
                .patch(patch_peer_group)
                .delete(delete_peer_group),
        )
        .route("/RuntimeConfigs", get(list_runtime_configs).post(create_runtime_config))
        .route(
            "/RuntimeConfigs/{id}",
            get(get_runtime_config)
                .put(update_runtime_config)
                .patch(patch_runtime_config)
                .delete(delete_runtime_config),
        )
        .route("/Peripherals", get(list_peripherals).post(create_peripheral))
        .route(
            "/Peripherals/{id}",
            get(get_peripheral)
                .put(update_peripheral)
                .patch(patch_peripheral)
                .delete(delete_peripheral),
        )
        // Service Provider Config
        .route("/ServiceProviderConfig", get(service_provider_config))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Macro-generated handlers for all resources
// ═══════════════════════════════════════════════════════════════════════════════

macro_rules! scim_list_handler {
    ($name:ident, $resource:ty, $log_name:expr) => {
        async fn $name(
            State(_state): State<crate::AppState>,
        ) -> Response {
            let response = zeroclaw_provisioning::scim::schema::ScimListResponse::<$resource> {
                schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
                total_results: 0,
                items_per_page: Some(0),
                start_index: Some(1),
                resources: vec![],
            };

            (StatusCode::OK, Json(response)).into_response()
        }
    };
}

macro_rules! scim_create_handler {
    ($name:ident, $resource:ty, $log_name:expr, $resource_type:expr) => {
        async fn $name(
            State(_state): State<crate::AppState>,
            Json(mut resource): Json<$resource>,
        ) -> Response {
            resource.id = Some(Uuid::new_v4().to_string());
            resource.meta = Some(zeroclaw_provisioning::scim::schema::ScimMeta {
                resource_type: Some($resource_type.to_string()),
                created: Some(chrono::Utc::now()),
                last_modified: Some(chrono::Utc::now()),
                version: None,
                location: None,
            });

            (StatusCode::CREATED, Json(resource)).into_response()
        }
    };
}

macro_rules! scim_get_handler {
    ($name:ident, $log_name:expr) => {
        async fn $name(
            State(_state): State<crate::AppState>,
            Path(id): Path<String>,
        ) -> Response {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": 404,
                "detail": format!("{} {} not found", $log_name, id)
            }))).into_response()
        }
    };
}

macro_rules! scim_update_handler {
    ($name:ident, $resource:ty, $log_name:expr) => {
        async fn $name(
            State(_state): State<crate::AppState>,
            Path(id): Path<String>,
            Json(mut resource): Json<$resource>,
        ) -> Response {
            resource.id = Some(id.clone());
            resource.meta = Some(zeroclaw_provisioning::scim::schema::ScimMeta {
                resource_type: Some($log_name.to_string()),
                created: None,
                last_modified: Some(chrono::Utc::now()),
                version: None,
                location: None,
            });

            (StatusCode::OK, Json(resource)).into_response()
        }
    };
}

macro_rules! scim_patch_handler {
    ($name:ident, $log_name:expr) => {
        async fn $name(
            State(_state): State<crate::AppState>,
            Path(id): Path<String>,
            Json(_patch): Json<Value>,
        ) -> Response {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": 404,
                "detail": format!("{} {} not found", $log_name, id)
            }))).into_response()
        }
    };
}

macro_rules! scim_delete_handler {
    ($name:ident, $log_name:expr) => {
        async fn $name(
            State(_state): State<crate::AppState>,
            Path(id): Path<String>,
        ) -> Response {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": 404,
                "detail": format!("{} {} not found", $log_name, id)
            }))).into_response()
        }
    };
}

// ── Users (Standard SCIM) ──

async fn list_users(
    State(_state): State<crate::AppState>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    debug!("SCIM list_users");
    
    let response = ScimListResponse::<ScimUser> {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 0,
        items_per_page: Some(0),
        start_index: Some(1),
        resources: vec![],
    };
    
    (StatusCode::OK, Json(response)).into_response()
}

async fn create_user(
    State(_state): State<crate::AppState>,
    Json(mut user): Json<ScimUser>,
) -> Response {
    debug!("SCIM create_user: {:?}", user.user_name);
    
    user.id = Some(Uuid::new_v4().to_string());
    user.meta = Some(ScimMeta {
        resource_type: Some("User".to_string()),
        created: Some(chrono::Utc::now()),
        last_modified: Some(chrono::Utc::now()),
        version: None,
        location: None,
    });
    
    (StatusCode::CREATED, Json(user)).into_response()
}

async fn get_user(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
) -> Response {
    debug!("SCIM get_user: id={}", id);
    
    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": 404,
        "detail": format!("User {} not found", id)
    }))).into_response()
}

async fn update_user(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
    Json(mut user): Json<ScimUser>,
) -> Response {
    debug!("SCIM update_user: id={}", id);
    
    user.id = Some(id.clone());
    user.meta = Some(ScimMeta {
        resource_type: Some("User".to_string()),
        created: None,
        last_modified: Some(chrono::Utc::now()),
        version: None,
        location: None,
    });
    
    (StatusCode::OK, Json(user)).into_response()
}

async fn patch_user(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
    Json(_patch): Json<Value>,
) -> Response {
    debug!("SCIM patch_user: id={}", id);
    
    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": 404,
        "detail": format!("User {} not found", id)
    }))).into_response()
}

async fn delete_user(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
) -> Response {
    debug!("SCIM delete_user: id={}", id);
    
    StatusCode::NO_CONTENT.into_response()
}

// ── Groups (Standard SCIM) ──

async fn list_groups(
    State(_state): State<crate::AppState>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    debug!("SCIM list_groups");
    
    let response = ScimListResponse::<ScimGroup> {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 0,
        items_per_page: Some(0),
        start_index: Some(1),
        resources: vec![],
    };
    
    (StatusCode::OK, Json(response)).into_response()
}

async fn create_group(
    State(_state): State<crate::AppState>,
    Json(mut group): Json<ScimGroup>,
) -> Response {
    debug!("SCIM create_group: {:?}", group.display_name);
    
    group.id = Some(Uuid::new_v4().to_string());
    group.meta = Some(ScimMeta {
        resource_type: Some("Group".to_string()),
        created: Some(chrono::Utc::now()),
        last_modified: Some(chrono::Utc::now()),
        version: None,
        location: None,
    });
    
    (StatusCode::CREATED, Json(group)).into_response()
}

async fn get_group(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
) -> Response {
    debug!("SCIM get_group: id={}", id);
    
    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": 404,
        "detail": format!("Group {} not found", id)
    }))).into_response()
}

async fn update_group(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
    Json(mut group): Json<ScimGroup>,
) -> Response {
    debug!("SCIM update_group: id={}", id);
    
    group.id = Some(id.clone());
    group.meta = Some(ScimMeta {
        resource_type: Some("Group".to_string()),
        created: None,
        last_modified: Some(chrono::Utc::now()),
        version: None,
        location: None,
    });
    
    (StatusCode::OK, Json(group)).into_response()
}

async fn patch_group(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
    Json(_patch): Json<Value>,
) -> Response {
    debug!("SCIM patch_group: id={}", id);
    
    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": 404,
        "detail": format!("Group {} not found", id)
    }))).into_response()
}

async fn delete_group(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
) -> Response {
    debug!("SCIM delete_group: id={}", id);
    
    StatusCode::NO_CONTENT.into_response()
}

// ── Service Provider Config ──

async fn service_provider_config(
    State(_state): State<crate::AppState>,
) -> Response {
    debug!("SCIM service_provider_config");
    
    let config = ScimServiceProviderConfig {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_string()],
        patch: ScimFeature { supported: true },
        bulk: ScimBulkFeature { 
            supported: true, 
            max_operations: Some(1000), 
            max_payload_size: Some(1048576) 
        },
        filter: ScimFilterFeature { 
            supported: true, 
            max_results: Some(200) 
        },
        change_password: ScimFeature { supported: false },
        sort: ScimFeature { supported: false },
        etag: ScimFeature { supported: true },
        authentication_schemes: vec![
            ScimAuthScheme {
                name: "OAuth Bearer Token".to_string(),
                description: Some("Authentication using OAuth 2.0 Bearer Token".to_string()),
                spec_uri: "https://www.rfc-editor.org/info/rfc6750".to_string(),
                documentation_uri: None,
                auth_type: "oauthbearertoken".to_string(),
                primary: true,
            },
        ],
    };
    
    (StatusCode::OK, Json(config)).into_response()
}

// ── ZeroClaw Custom Resources (generated via macros) ──

// Channels
scim_list_handler!(list_channels, zeroclaw_provisioning::scim::schema::ScimChannel, "channels");
scim_create_handler!(create_channel, zeroclaw_provisioning::scim::schema::ScimChannel, "channel", "Channel");
scim_get_handler!(get_channel, "Channel");
scim_update_handler!(update_channel, zeroclaw_provisioning::scim::schema::ScimChannel, "Channel");
scim_patch_handler!(patch_channel, "Channel");
scim_delete_handler!(delete_channel, "Channel");

// ChannelBindings
scim_list_handler!(list_channel_bindings, zeroclaw_provisioning::scim::schema::ScimChannelBinding, "channel_bindings");
scim_create_handler!(create_channel_binding, zeroclaw_provisioning::scim::schema::ScimChannelBinding, "channel_binding", "ChannelBinding");
scim_get_handler!(get_channel_binding, "ChannelBinding");
scim_update_handler!(update_channel_binding, zeroclaw_provisioning::scim::schema::ScimChannelBinding, "ChannelBinding");
scim_patch_handler!(patch_channel_binding, "ChannelBinding");
scim_delete_handler!(delete_channel_binding, "ChannelBinding");

// Agents
scim_list_handler!(list_agents, zeroclaw_provisioning::scim::schema::ScimAgent, "agents");
scim_create_handler!(create_agent, zeroclaw_provisioning::scim::schema::ScimAgent, "agent", "Agent");
scim_get_handler!(get_agent, "Agent");
scim_update_handler!(update_agent, zeroclaw_provisioning::scim::schema::ScimAgent, "Agent");
scim_patch_handler!(patch_agent, "Agent");
scim_delete_handler!(delete_agent, "Agent");

// Skills
scim_list_handler!(list_skills, zeroclaw_provisioning::scim::schema::ScimSkill, "skills");
scim_create_handler!(create_skill, zeroclaw_provisioning::scim::schema::ScimSkill, "skill", "Skill");
scim_get_handler!(get_skill, "Skill");
scim_update_handler!(update_skill, zeroclaw_provisioning::scim::schema::ScimSkill, "Skill");
scim_patch_handler!(patch_skill, "Skill");
scim_delete_handler!(delete_skill, "Skill");

// CronJobs
scim_list_handler!(list_cron_jobs, zeroclaw_provisioning::scim::schema::ScimCronJob, "cron_jobs");
scim_create_handler!(create_cron_job, zeroclaw_provisioning::scim::schema::ScimCronJob, "cron_job", "CronJob");
scim_get_handler!(get_cron_job, "CronJob");
scim_update_handler!(update_cron_job, zeroclaw_provisioning::scim::schema::ScimCronJob, "CronJob");
scim_patch_handler!(patch_cron_job, "CronJob");
scim_delete_handler!(delete_cron_job, "CronJob");

// Tools
scim_list_handler!(list_tools, zeroclaw_provisioning::scim::schema::ScimTool, "tools");
scim_create_handler!(create_tool, zeroclaw_provisioning::scim::schema::ScimTool, "tool", "Tool");
scim_get_handler!(get_tool, "Tool");
scim_update_handler!(update_tool, zeroclaw_provisioning::scim::schema::ScimTool, "Tool");
scim_patch_handler!(patch_tool, "Tool");
scim_delete_handler!(delete_tool, "Tool");

// Memories
scim_list_handler!(list_memories, zeroclaw_provisioning::scim::schema::ScimMemory, "memories");
scim_create_handler!(create_memory, zeroclaw_provisioning::scim::schema::ScimMemory, "memory", "Memory");
scim_get_handler!(get_memory, "Memory");
scim_update_handler!(update_memory, zeroclaw_provisioning::scim::schema::ScimMemory, "Memory");
scim_patch_handler!(patch_memory, "Memory");
scim_delete_handler!(delete_memory, "Memory");

// ModelProviders
scim_list_handler!(list_model_providers, zeroclaw_provisioning::scim::schema::ScimModelProvider, "model_providers");
scim_create_handler!(create_model_provider, zeroclaw_provisioning::scim::schema::ScimModelProvider, "model_provider", "ModelProvider");
scim_get_handler!(get_model_provider, "ModelProvider");
scim_update_handler!(update_model_provider, zeroclaw_provisioning::scim::schema::ScimModelProvider, "ModelProvider");
scim_patch_handler!(patch_model_provider, "ModelProvider");
scim_delete_handler!(delete_model_provider, "ModelProvider");

// PeerGroups
scim_list_handler!(list_peer_groups, zeroclaw_provisioning::scim::schema::ScimPeerGroup, "peer_groups");
scim_create_handler!(create_peer_group, zeroclaw_provisioning::scim::schema::ScimPeerGroup, "peer_group", "PeerGroup");
scim_get_handler!(get_peer_group, "PeerGroup");
scim_update_handler!(update_peer_group, zeroclaw_provisioning::scim::schema::ScimPeerGroup, "PeerGroup");
scim_patch_handler!(patch_peer_group, "PeerGroup");
scim_delete_handler!(delete_peer_group, "PeerGroup");

// RuntimeConfigs
scim_list_handler!(list_runtime_configs, zeroclaw_provisioning::scim::schema::ScimRuntimeConfig, "runtime_configs");
scim_create_handler!(create_runtime_config, zeroclaw_provisioning::scim::schema::ScimRuntimeConfig, "runtime_config", "RuntimeConfig");
scim_get_handler!(get_runtime_config, "RuntimeConfig");
scim_update_handler!(update_runtime_config, zeroclaw_provisioning::scim::schema::ScimRuntimeConfig, "RuntimeConfig");
scim_patch_handler!(patch_runtime_config, "RuntimeConfig");
scim_delete_handler!(delete_runtime_config, "RuntimeConfig");

// Peripherals
scim_list_handler!(list_peripherals, zeroclaw_provisioning::scim::schema::ScimPeripheral, "peripherals");
scim_create_handler!(create_peripheral, zeroclaw_provisioning::scim::schema::ScimPeripheral, "peripheral", "Peripheral");
scim_get_handler!(get_peripheral, "Peripheral");
scim_update_handler!(update_peripheral, zeroclaw_provisioning::scim::schema::ScimPeripheral, "Peripheral");
scim_patch_handler!(patch_peripheral, "Peripheral");
scim_delete_handler!(delete_peripheral, "Peripheral");