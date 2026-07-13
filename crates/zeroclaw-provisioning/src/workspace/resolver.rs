//! Workspace resolver - maps IdP claims to WorkspaceId.

use std::collections::HashMap;
use std::sync::Arc as StdArc;
use zeroclaw_api::principal::{PrincipalId, WorkspaceId};
use crate::workspace::index::WorkspaceIndex;
use crate::config::ProvisioningConfig;
use crate::error::Result;

/// Parser for SCIM attribute paths like "emails[primary eq true].value" or "groups[?type eq 'workspace'].value"
#[derive(Debug, Clone)]
pub struct AttributePathParser {
    /// Raw attribute path from config (e.g., "urn:scim:schemas:extension:enterprise:2.0:User:department")
    raw_path: String,
    /// Parsed path components
    components: Vec<PathComponent>,
}

#[derive(Debug, Clone)]
enum PathComponent {
    /// Simple attribute name (e.g., "department", "userName")
    Attribute(String),
    /// Array filter: attribute[?filter].value
    ArrayFilter {
        array_attr: String,
        filter: ArrayFilter,
        value_attr: String,
    },
}

#[derive(Debug, Clone)]
struct ArrayFilter {
    attr: String,
    op: String,
    value: String,
}

impl AttributePathParser {
    /// Parse an attribute path string.
    pub fn new(path: String) -> Self {
        let components = Self::parse_path(&path);
        Self { raw_path: path, components }
    }

    fn parse_path(path: &str) -> Vec<PathComponent> {
        // Handle SCIM URN paths: urn:scim:schemas:extension:enterprise:2.0:User:department
        if path.starts_with("urn:") {
            // Extract the final component after the last colon
            let final_component = path.split(':').last().unwrap_or(path);
            return vec![PathComponent::Attribute(final_component.to_string())];
        }

        // Handle dot notation: emails.value, groups[?type eq 'workspace'].value
        let mut components = Vec::new();
        let mut remaining = path;

        while !remaining.is_empty() {
            if let Some(idx) = remaining.find('[') {
                // Array filter
                let array_attr = remaining[..idx].trim_end_matches('.').to_string();
                let filter_end = remaining.find(']').unwrap_or(remaining.len());
                let filter_str = &remaining[idx + 1..filter_end];
                
                // Parse filter: ?type eq 'workspace'
                let filter = if filter_str.starts_with('?') {
                    let filter_str = &filter_str[1..];
                    // Simple parsing: attr op 'value'
                    let parts: Vec<&str> = filter_str.split_whitespace().collect();
                    if parts.len() >= 3 {
                        Some(ArrayFilter {
                            attr: parts[0].to_string(),
                            op: parts[1].to_string(),
                            value: parts[2].trim_matches('\'').trim_matches('"').to_string(),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                let value_attr = if filter_end + 1 < remaining.len() && remaining.chars().nth(filter_end + 1) == Some('.') {
                    let rest = &remaining[filter_end + 2..];
                    let end = rest.find(&['[', '.'][..]).unwrap_or(rest.len());
                    rest[..end].to_string()
                } else {
                    "value".to_string()
                };

                if let Some(filter) = filter {
                    components.push(PathComponent::ArrayFilter {
                        array_attr,
                        filter,
                        value_attr,
                    });
                }

                remaining = if filter_end + 1 < remaining.len() {
                    &remaining[filter_end + 1..]
                } else {
                    ""
                };
            } else {
                // Simple attribute
                let attr = remaining.to_string();
                components.push(PathComponent::Attribute(attr));
                break;
            }
        }

        if components.is_empty() {
            components.push(PathComponent::Attribute(path.to_string()));
        }
        components
    }

    /// Extract workspace ID from SCIM User claims.
    pub fn extract_workspace(&self, user: &crate::scim::schema::ScimUser) -> Option<WorkspaceId> {
        for component in &self.components {
            if let Some(ws) = self.extract_from_component(user, component) {
                return Some(ws);
            }
        }
        None
    }

    fn extract_from_component(
        &self,
        user: &crate::scim::schema::ScimUser,
        component: &PathComponent,
    ) -> Option<WorkspaceId> {
        match component {
            PathComponent::Attribute(attr) => {
                // Direct attribute access
                let value = match attr.as_str() {
                    "userName" => user.user_name.as_ref().map(|s| s.as_str()),
                    "displayName" => user.display_name.as_ref().map(|s| s.as_str()),
                    "department" => user.enterprise_user.as_ref()?.department.as_ref().map(|s| s.as_str()),
                    "organization" => user.enterprise_user.as_ref()?.organization.as_ref().map(|s| s.as_str()),
                    "division" => user.enterprise_user.as_ref()?.division.as_ref().map(|s| s.as_str()),
                    "costCenter" => user.enterprise_user.as_ref()?.cost_center.as_ref().map(|s| s.as_str()),
                    "employeeNumber" => user.enterprise_user.as_ref()?.employee_number.as_ref().map(|s| s.as_str()),
                    _ => {
                        // Check custom attributes
                        user.custom.get(attr).and_then(|v| v.as_str())
                    }
                };
                value.map(|v| WorkspaceId(v.to_string()))
            }
            PathComponent::ArrayFilter { array_attr, filter, value_attr } => {
                // Array filter: groups[?type eq 'workspace'].value
                let array = match array_attr.as_str() {
                    "groups" => &user.groups,
                    "emails" => {
                        // Convert emails to a similar structure for filtering
                        return None; // Not implemented for emails yet
                    }
                    _ => return None,
                };

                for item in array {
                    // Check if item matches filter
                    let item_value: Option<&str> = match filter.attr.as_str() {
                        "type" => {
                            item.custom.get("type")
                                .and_then(|v| v.as_str())
                                .or_else(|| item.display.as_deref())
                        }
                        "value" => Some(&item.value),
                        _ => item.custom.get(&filter.attr).and_then(|v| v.as_str()),
                    };

                    if let Some(val) = item_value {
                        if Self::matches_filter(val, &filter.op, &filter.value) {
                            // Extract the value attribute
                            let result: Option<String> = match value_attr.as_str() {
                                "value" => Some(item.value.clone()),
                                "display" => item.display.clone(),
                                _ => item.custom.get(value_attr.as_str()).and_then(|v| v.as_str().map(String::from)),
                            };
                            return result.map(|v| WorkspaceId(v));
                        }
                    }
                }
                None
            }
        }
    }

    fn matches_filter(value: &str, op: &str, expected: &str) -> bool {
        match op {
            "eq" => value == expected,
            "ne" => value != expected,
            "co" => value.contains(expected),
            "sw" => value.starts_with(expected),
            "ew" => value.ends_with(expected),
            "pr" => !value.is_empty(),
            _ => false,
        }
    }
}

/// Resolves WorkspaceId from IdP claims using configured attribute path.
#[derive(Clone)]
pub struct WorkspaceResolver {
    index: StdArc<WorkspaceIndex>,
    config: ProvisioningConfig,
    attribute_parser: AttributePathParser,
    static_mapping: HashMap<String, WorkspaceId>,
}

impl WorkspaceResolver {
    /// Create a new workspace resolver.
    pub fn new(index: StdArc<WorkspaceIndex>, config: ProvisioningConfig) -> Self {
        let attribute_parser = AttributePathParser::new(config.workspace_attribute.clone());
        let static_mapping = config.static_workspace_mapping.iter()
            .map(|(k, v)| (k.clone(), WorkspaceId(v.clone())))
            .collect();

        Self {
            index,
            config,
            attribute_parser,
            static_mapping,
        }
    }

    /// Resolve WorkspaceId from SCIM User claims (inbound provisioning).
    pub fn resolve_from_scim_user(&self, user: &crate::scim::schema::ScimUser) -> WorkspaceId {
        // Try SCIM attribute path first
        if let Some(ws) = self.attribute_parser.extract_workspace(user) {
            return ws;
        }

        // Fall back to static mapping using userName or department
        if let Some(username) = &user.user_name {
            if let Some(ws) = self.static_mapping.get(username) {
                return ws.clone();
            }
        }
        if let Some(enterprise) = user.enterprise_user.as_ref() {
            if let Some(dept) = enterprise.department.as_ref() {
                if let Some(ws) = self.static_mapping.get(dept) {
                    return ws.clone();
                }
            }
        }

        // Default workspace
        WorkspaceId::DEFAULT.into()
    }

    /// Resolve WorkspaceId from arbitrary IdP claims (OIDC, SAML, etc.).
    pub fn resolve_from_claims(&self, claims: &serde_json::Value) -> WorkspaceId {
        // Try the configured attribute path
        if let Some(ws) = self.extract_from_json(claims, &self.attribute_parser.raw_path) {
            return ws;
        }

        // Fall back to static mapping using common claim names
        for claim_name in ["department", "org", "organization", "workspace", "team"] {
            if let Some(val) = claims.get(claim_name).and_then(|v| v.as_str()) {
                if let Some(ws) = self.static_mapping.get(val) {
                    return ws.clone();
                }
            }
        }

        // Default workspace
        WorkspaceId::DEFAULT.into()
    }

    fn extract_from_json(&self, claims: &serde_json::Value, path: &str) -> Option<WorkspaceId> {
        // Handle SCIM URN paths
        if path.starts_with("urn:") {
            let attr = path.split(':').last()?;
            return claims.get(attr).and_then(|v| v.as_str()).map(|s| WorkspaceId(s.into()));
        }

        // Handle dot notation
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = claims;
        for part in parts {
            if let Some(idx) = part.find('[') {
                // Array filter - simplified
                let array_attr = &part[..idx];
                current = current.get(array_attr)?;
                // Would need full filter implementation
                return None;
            }
            current = current.get(part)?;
        }
        current.as_str().map(|s| WorkspaceId(s.into()))
    }

    /// Resolve WorkspaceId for a tenant (multi-tenant).
    pub fn resolve_for_tenant(&self, tenant_id: &str) -> WorkspaceId {
        self.index.workspace_for_tenant_or_default(tenant_id, WorkspaceId::DEFAULT.into())
    }

    /// Get workspace for a principal (from index).
    pub fn workspace_for_principal(&self, principal_id: &PrincipalId) -> Option<WorkspaceId> {
        self.index.workspace_for_principal(principal_id)
    }

    /// Get the underlying workspace index.
    pub fn index(&self) -> &StdArc<WorkspaceIndex> {
        &self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::schema::{ScimUser, ScimEnterpriseUser};
    use crate::workspace::index::WorkspaceIndex;
    use crate::config::ProvisioningConfig;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn make_test_user(department: Option<&str>) -> ScimUser {
        let mut user = ScimUser::default();
        user.user_name = Some("john@example.com".into());
        user.enterprise_user = Some(ScimEnterpriseUser {
            department: department.map(|s| s.into()),
            ..Default::default()
        });
        user
    }

    #[test]
    fn test_resolve_from_department() {
        let index = Arc::new(WorkspaceIndex::new());
        let config = ProvisioningConfig {
            workspace_attribute: "urn:scim:schemas:extension:enterprise:2.0:User:department".into(),
            static_workspace_mapping: {
                let mut m = BTreeMap::new();
                m.insert("engineering".into(), "eng-team".into());
                m.insert("sales".into(), "sales-team".into());
                m
            },
            ..Default::default()
        };
        let resolver = WorkspaceResolver::new(index, config);

        let user = make_test_user(Some("engineering"));
        let ws = resolver.resolve_from_scim_user(&user);
        assert_eq!(ws.as_str(), "eng-team");

        let user = make_test_user(Some("sales"));
        let ws = resolver.resolve_from_scim_user(&user);
        assert_eq!(ws.as_str(), "sales-team");

        let user = make_test_user(Some("marketing"));
        let ws = resolver.resolve_from_scim_user(&user);
        assert_eq!(ws.as_str(), "default"); // Falls back to default
    }

    #[test]
    fn test_resolve_from_static_mapping_username() {
        let index = Arc::new(WorkspaceIndex::new());
        let config = ProvisioningConfig {
            workspace_attribute: "userName".into(),
            static_workspace_mapping: {
                let mut m = BTreeMap::new();
                m.insert("admin".into(), "admin-ws".into());
                m
            },
            ..Default::default()
        };
        let resolver = WorkspaceResolver::new(index, config);

        let mut user = make_test_user(None);
        user.user_name = Some("admin".into());
        let ws = resolver.resolve_from_scim_user(&user);
        assert_eq!(ws.as_str(), "admin-ws");
    }
}