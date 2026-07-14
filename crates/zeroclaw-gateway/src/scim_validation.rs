//! SCIM resource validation — allowlist-based field filtering.
//!
//! Each SCIM resource type has a known schema. Any keys not in the allowlist
//! are rejected to prevent mass-assignment / config-injection attacks.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Build an allowlist of known top-level field names for each SCIM resource type.
/// Keys not in the allowlist are rejected during validation.
macro_rules! resource_allowlist {
    ($name:ident, $($field:expr),+ $(,)?) => {
        fn $name() -> &'static HashSet<&'static str> {
            static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
            SET.get_or_init(|| {
                let mut set = HashSet::new();
                $(set.insert($field);)+
                set
            })
        }
    };
}

// Standard SCIM User attributes (RFC 7643 §4.1)
resource_allowlist!(USER_ALLOWLIST,
    "schemas", "id", "externalId", "userName", "displayName", "nickName",
    "profileUrl", "title", "userType", "preferredLanguage", "locale",
    "timezone", "active", "emails", "phoneNumbers", "ims", "photos",
    "addresses", "groups", "entitlements", "roles", "x509Certificates",
    "meta", "enterpriseUser"
);

// Standard SCIM Group attributes (RFC 7643 §4.2)
resource_allowlist!(GROUP_ALLOWLIST,
    "schemas", "id", "externalId", "displayName", "members", "meta"
);

// ZeroClaw custom resources
resource_allowlist!(CHANNEL_ALLOWLIST,
    "schemas", "id", "externalId", "channelType", "displayName", "enabled",
    "config", "peerGroup", "allowedUsers", "webhookUrl", "mediaPipeline", "meta"
);

resource_allowlist!(CHANNEL_BINDING_ALLOWLIST,
    "schemas", "id", "externalId", "channelId", "peerGroupId",
    "inboundPriority", "outboundEnabled", "transformRules", "rateLimit", "meta"
);

resource_allowlist!(AGENT_ALLOWLIST,
    "schemas", "id", "externalId", "name", "description", "modelProvider",
    "model", "systemPrompt", "temperature", "maxTokens", "tools", "skills",
    "memoryStrategy", "peerGroups", "active", "meta"
);

resource_allowlist!(SKILL_ALLOWLIST,
    "schemas", "id", "externalId", "name", "description", "version",
    "entryPoint", "configSchema", "defaultConfig", "requiredPermissions",
    "enabled", "meta"
);

resource_allowlist!(CRON_JOB_ALLOWLIST,
    "schemas", "id", "externalId", "name", "schedule", "timezone",
    "command", "args", "targetChannel", "enabled", "maxConcurrent",
    "timeoutSeconds", "meta"
);

resource_allowlist!(TOOL_ALLOWLIST,
    "schemas", "id", "externalId", "name", "description", "kind",
    "parametersSchema", "requiredPermissions", "enabled", "timeoutSeconds",
    "stateKeyPrefix", "meta"
);

resource_allowlist!(MEMORY_ALLOWLIST,
    "schemas", "id", "externalId", "name", "backendType", "connection",
    "embeddingModel", "dimensions", "retentionDays", "maxEntries",
    "enabled", "meta"
);

resource_allowlist!(MODEL_PROVIDER_ALLOWLIST,
    "schemas", "id", "externalId", "name", "providerType", "apiBase",
    "apiKey", "defaultModel", "models", "timeoutSeconds", "maxRetries",
    "enabled", "meta"
);

resource_allowlist!(PEER_GROUP_ALLOWLIST,
    "schemas", "id", "externalId", "name", "description", "members",
    "allowedChannels", "allowedAgents", "allowedTools", "active", "meta"
);

resource_allowlist!(RUNTIME_CONFIG_ALLOWLIST,
    "schemas", "id", "externalId", "name", "maxIterations",
    "turnTimeoutSeconds", "validateToolCalls", "streaming",
    "defaultSystemPrompt", "securityPolicy", "observabilitySampling", "meta"
);

resource_allowlist!(PERIPHERAL_ALLOWLIST,
    "schemas", "id", "externalId", "name", "peripheralType",
    "devicePath", "driver", "config", "assignedAgent", "enabled", "meta"
);

/// Validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    UnknownField { resource: &'static str, field: String },
    MissingRequired { resource: &'static str, field: &'static str },
}

/// Validate a SCIM resource's top-level keys against its allowlist.
/// Returns `Ok(())` if all keys are allowed, or a `ValidationError` for the first violation.
pub fn validate_resource_keys(
    resource_type: &'static str,
    value: &serde_json::Value,
) -> Result<(), ValidationError> {
    let allowlist = match resource_type {
        "User" => USER_ALLOWLIST(),
        "Group" => GROUP_ALLOWLIST(),
        "Channel" => CHANNEL_ALLOWLIST(),
        "ChannelBinding" => CHANNEL_BINDING_ALLOWLIST(),
        "Agent" => AGENT_ALLOWLIST(),
        "Skill" => SKILL_ALLOWLIST(),
        "CronJob" => CRON_JOB_ALLOWLIST(),
        "Tool" => TOOL_ALLOWLIST(),
        "Memory" => MEMORY_ALLOWLIST(),
        "ModelProvider" => MODEL_PROVIDER_ALLOWLIST(),
        "PeerGroup" => PEER_GROUP_ALLOWLIST(),
        "RuntimeConfig" => RUNTIME_CONFIG_ALLOWLIST(),
        "Peripheral" => PERIPHERAL_ALLOWLIST(),
        _ => return Err(ValidationError::UnknownField {
            resource: resource_type,
            field: "unknown resource type".to_string(),
        }),
    };

    if let Some(obj) = value.as_object() {
        for key in obj.keys() {
            if !allowlist.contains(key.as_str()) {
                return Err(ValidationError::UnknownField {
                    resource: resource_type,
                    field: key.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Convenience: validate a typed SCIM resource by serializing to JSON first.
pub fn validate_scim_resource<T: serde::Serialize>(
    resource_type: &'static str,
    resource: &T,
) -> Result<(), ValidationError> {
    let value = serde_json::to_value(resource).map_err(|_| ValidationError::UnknownField {
        resource: resource_type,
        field: "serialization_failed".to_string(),
    })?;
    validate_resource_keys(resource_type, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_allowlist_allows_standard_fields() {
        let json = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "jdoe",
            "displayName": "John Doe",
            "active": true,
            "emails": [{"value": "jdoe@example.com", "primary": true}]
        });
        assert!(validate_resource_keys("User", &json).is_ok());
    }

    #[test]
    fn user_allowlist_rejects_unknown_field() {
        let json = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "jdoe",
            "evilField": "injection"
        });
        assert!(matches!(
            validate_resource_keys("User", &json),
            Err(ValidationError::UnknownField { resource: "User", field }) if field == "evilField"
        ));
    }

    #[test]
    fn channel_allowlist_allows_known_fields() {
        let json = serde_json::json!({
            "schemas": ["urn:zeroclaw:schemas:extension:Channel:1.0"],
            "channelType": "slack",
            "displayName": "Team Channel",
            "enabled": true,
            "peerGroup": "engineering"
        });
        assert!(validate_resource_keys("Channel", &json).is_ok());
    }

    #[test]
    fn channel_allowlist_rejects_unknown() {
        let json = serde_json::json!({
            "schemas": ["urn:zeroclaw:schemas:extension:Channel:1.0"],
            "channelType": "slack",
            "dangerousConfig": {"rm": "-rf /"}
        });
        assert!(matches!(
            validate_resource_keys("Channel", &json),
            Err(ValidationError::UnknownField { resource: "Channel", field }) if field == "dangerousConfig"
        ));
    }
}