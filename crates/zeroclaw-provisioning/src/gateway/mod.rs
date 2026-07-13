//! Gateway SCIM endpoints for outbound provisioning.

pub mod endpoints;
pub mod auth;
pub mod router;

pub use endpoints::scim_routes;
pub use endpoints::service_provider_config;
pub use auth::validate_downstream;
