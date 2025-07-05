use actix_web::web;
use crate::handlers::{register, login, protected_endpoint};

pub fn configure_public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/register")
            .route(web::post().to(register))
    )
    .service(
        web::resource("/login")
            .route(web::post().to(login))
    );
}

pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/protected")
            .route(web::get().to(protected_endpoint))
    );
}