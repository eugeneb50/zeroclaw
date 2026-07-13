//! Router factory for SCIM gateway endpoints.

use actix_web::{web, Scope};
use crate::config::DownstreamConfig;
use crate::workspace::index::WorkspaceIndex;
use std::sync::Arc;

/// Create SCIM v2 routes for a downstream application.
pub fn scim_routes(
    _downstream: Arc<DownstreamConfig>,
    _index: Arc<WorkspaceIndex>,
) -> Scope {
    web::scope("/scim/v2")
        .route("/Users", web::get().to(super::endpoints::list_users))
        .route("/Users", web::post().to(super::endpoints::create_user))
        .route("/Users/{id}", web::get().to(super::endpoints::get_user))
        .route("/Users/{id}", web::put().to(super::endpoints::update_user))
        .route("/Users/{id}", web::patch().to(super::endpoints::update_user))
        .route("/Users/{id}", web::delete().to(super::endpoints::delete_user))
        .route("/Groups", web::get().to(super::endpoints::list_groups))
        .route("/Groups", web::post().to(super::endpoints::create_group))
        .route("/Groups/{id}", web::get().to(super::endpoints::get_group))
        .route("/Groups/{id}", web::put().to(super::endpoints::update_group))
        .route("/Groups/{id}", web::patch().to(super::endpoints::update_group))
        .route("/Groups/{id}", web::delete().to(super::endpoints::delete_group))
        .route("/ServiceProviderConfig", web::get().to(super::endpoints::service_provider_config))
}
