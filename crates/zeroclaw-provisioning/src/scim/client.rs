//! SCIM 2.0 client for inbound provisioning (RFC 7644).

use std::time::Duration;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use url::Url;

use crate::error::{ProvisioningError, Result, ScimClientError};
use crate::scim::schema::{ScimListResponse, ScimUser, ScimGroup, ScimServiceProviderConfig};
use crate::scim::filter::ScimFilter;

/// SCIM client for communicating with IdP SCIM endpoints.
#[derive(Clone)]
pub struct ScimClient {
    http: Client,
    base_url: Url,
    token: String,
}

impl ScimClient {
    /// Create a new SCIM client.
    pub fn new(base_url: String, token: String) -> Result<Self> {
        let base_url = Url::parse(&base_url)
            .map_err(|e| ProvisioningError::UrlParse(e))?;
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ProvisioningError::Http(e))?;
        Ok(Self { http, base_url, token })
    }

    /// Build a request with authentication.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = self.base_url.join(path).expect("valid path");
        self.http.request(method, url)
            .bearer_auth(&self.token)
            .header("Accept", "application/scim+json")
            .header("Content-Type", "application/scim+json")
    }

    /// GET request expecting JSON response.
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let resp = self.request(reqwest::Method::GET, path).send().await?;
        self.handle_response(resp).await
    }

    /// Handle response, check status, parse JSON.
    async fn handle_response<T: DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            let text = resp.text().await?;
            if text.trim().is_empty() {
return Err(ProvisioningError::ScimClient(
                ScimClientError::InvalidResponse("Empty response".to_string())
            ));
            }
            serde_json::from_str(&text).map_err(ProvisioningError::Serialization)
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(ProvisioningError::ScimServer {
                status: status.as_u16(),
                body: text,
            })
        }
    }

    // ───── Users ─────

    /// List users with optional filter and pagination.
    pub async fn list_users(
        &self,
        filter: Option<&ScimFilter>,
        start_index: usize,
        count: usize,
    ) -> Result<ScimListResponse<ScimUser>> {
        let mut url = self.base_url.join("Users")?;
        url.query_pairs_mut()
            .append_pair("startIndex", &start_index.to_string())
            .append_pair("count", &count.to_string());
        if let Some(f) = filter {
            url.query_pairs_mut().append_pair("filter", &f.to_query_string());
        }
        let path = url.path();
        if let Some(query) = url.query() {
            self.get_json(&format!("{}?{}", path, query)).await
        } else {
            self.get_json(path).await
        }
    }

    /// Get a single user by ID.
    pub async fn get_user(&self, id: &str) -> Result<ScimUser> {
        self.get_json(&format!("Users/{}", id)).await
    }

    /// Create a new user.
    pub async fn create_user(&self, user: &ScimUser) -> Result<ScimUser> {
        let resp = self.request(reqwest::Method::POST, "Users")
            .json(user)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Replace a user (PUT).
    pub async fn replace_user(&self, id: &str, user: &ScimUser) -> Result<ScimUser> {
        let resp = self.request(reqwest::Method::PUT, &format!("Users/{}", id))
            .json(user)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Update a user (PATCH).
    pub async fn update_user(&self, id: &str, operations: &serde_json::Value) -> Result<ScimUser> {
        let resp = self.request(reqwest::Method::PATCH, &format!("Users/{}", id))
            .json(operations)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Delete a user.
    pub async fn delete_user(&self, id: &str) -> Result<()> {
        let resp = self.request(reqwest::Method::DELETE, &format!("Users/{}", id))
            .send()
            .await?;
        let status = resp.status();
        if status == StatusCode::NO_CONTENT || status == StatusCode::OK {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(ProvisioningError::ScimServer {
                status: status.as_u16(),
                body: text,
            })
        }
    }

    // ───── Groups ─────

    /// List groups with optional filter and pagination.
    pub async fn list_groups(
        &self,
        filter: Option<&ScimFilter>,
        start_index: usize,
        count: usize,
    ) -> Result<ScimListResponse<ScimGroup>> {
        let mut url = self.base_url.join("Groups")?;
        url.query_pairs_mut()
            .append_pair("startIndex", &start_index.to_string())
            .append_pair("count", &count.to_string());
        if let Some(f) = filter {
            url.query_pairs_mut().append_pair("filter", &f.to_query_string());
        }
        let path = url.path();
        if let Some(query) = url.query() {
            self.get_json(&format!("{}?{}", path, query)).await
        } else {
            self.get_json(path).await
        }
    }

    /// Get a single group by ID.
    pub async fn get_group(&self, id: &str) -> Result<ScimGroup> {
        self.get_json(&format!("Groups/{}", id)).await
    }

    /// Create a new group.
    pub async fn create_group(&self, group: &ScimGroup) -> Result<ScimGroup> {
        let resp = self.request(reqwest::Method::POST, "Groups")
            .json(group)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Replace a group (PUT).
    pub async fn replace_group(&self, id: &str, group: &ScimGroup) -> Result<ScimGroup> {
        let resp = self.request(reqwest::Method::PUT, &format!("Groups/{}", id))
            .json(group)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Update a group (PATCH).
    pub async fn update_group(&self, id: &str, operations: &serde_json::Value) -> Result<ScimGroup> {
        let resp = self.request(reqwest::Method::PATCH, &format!("Groups/{}", id))
            .json(operations)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Delete a group.
    pub async fn delete_group(&self, id: &str) -> Result<()> {
        let resp = self.request(reqwest::Method::DELETE, &format!("Groups/{}", id))
            .send()
            .await?;
        let status = resp.status();
        if status == StatusCode::NO_CONTENT || status == StatusCode::OK {
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(ProvisioningError::ScimServer {
                status: status.as_u16(),
                body: text,
            })
        }
    }

    // ───── Service Provider Config ─────

    /// Get ServiceProviderConfig.
    pub async fn get_service_provider_config(&self) -> Result<ScimServiceProviderConfig> {
        self.get_json("ServiceProviderConfig").await
    }

    // ───── Bulk operations ─────

    /// Bulk operations (RFC 7644 §3.7).
    pub async fn bulk(&self, operations: &serde_json::Value) -> Result<serde_json::Value> {
        let resp = self.request(reqwest::Method::POST, "Bulk")
            .json(operations)
            .send()
            .await?;
        self.handle_response(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ScimClient::new("https://example.com/scim/v2".to_string(), "token".to_string());
        assert!(client.is_ok());
    }
}