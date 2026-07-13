//! SCIM 2.0 gateway endpoints for outbound provisioning (minimal stub).

use actix_web::{web, HttpResponse, Responder, Scope};
use serde_json::Value;

pub fn scim_routes() -> Scope {
    web::scope("/scim/v2")
        .service(
            web::resource("/Users")
                .route(web::get().to(list_users))
                .route(web::post().to(create_user))
        )
        .service(
            web::resource("/Users/{id}")
                .route(web::get().to(get_user))
                .route(web::put().to(update_user))
                .route(web::patch().to(update_user))
                .route(web::delete().to(delete_user))
        )
        .service(
            web::resource("/Groups")
                .route(web::get().to(list_groups))
                .route(web::post().to(create_group))
        )
        .service(
            web::resource("/Groups/{id}")
                .route(web::get().to(get_group))
                .route(web::put().to(update_group))
                .route(web::patch().to(update_group))
                .route(web::delete().to(delete_group))
        )
        .service(web::resource("/ServiceProviderConfig").route(web::get().to(service_provider_config)))
}

pub async fn list_users() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}

pub async fn get_user() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}

pub async fn create_user() -> impl Responder {
    HttpResponse::Created().json(Value::Null)
}

pub async fn update_user() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}

pub async fn delete_user() -> impl Responder {
    HttpResponse::NoContent().finish()
}

pub async fn list_groups() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}

pub async fn get_group() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}

pub async fn create_group() -> impl Responder {
    HttpResponse::Created().json(Value::Null)
}

pub async fn update_group() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}

pub async fn delete_group() -> impl Responder {
    HttpResponse::NoContent().finish()
}

pub async fn service_provider_config() -> impl Responder {
    HttpResponse::Ok().json(Value::Null)
}
