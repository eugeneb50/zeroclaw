//! Downstream authentication for SCIM endpoints.

use actix_web::{HttpRequest, HttpResponse, Result, error::ErrorUnauthorized};

/// Validate downstream bearer token.
pub fn validate_downstream(req: &HttpRequest, _config: &crate::config::ProvisioningConfig) -> Result<()> {
    let auth_header = req.headers().get("Authorization");
    
    match auth_header {
        Some(h) if h.to_str().unwrap_or("").starts_with("Bearer ") => {
            // In real implementation, validate token against configured downstream
            Ok(())
        }
        _ => Err(ErrorUnauthorized(serde_json::json!({
            "error": "Unauthorized",
            "message": "Missing or invalid Bearer token"
        }))),
    }
}
