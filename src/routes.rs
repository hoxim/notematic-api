use actix_web::web;
use crate::handlers::{
    register, login, refresh_token, protected_endpoint, health_check,
    create_notebook_handler, get_notebooks_handler, update_notebook_handler, delete_notebook_handler,
    create_note_handler, get_notes_handler, get_all_notes_handler, update_note_handler,
    delete_note_handler, create_note_without_notebook_handler,
};
use crate::middleware::AdminRoleMiddlewareFactory;

pub fn configure_public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/health")
            .route(web::get().to(health_check))
    )
    .service(
        web::resource("/register")
            .route(web::post().to(register))
    )
    .service(
        web::resource("/login")
            .route(web::post().to(login))
    )
    .service(
        web::resource("/refresh")
            .route(web::post().to(refresh_token))
    );
}

pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/protected")
            .route(web::get().to(protected_endpoint))
    )
    .service(
        web::resource("/notebooks")
            .route(web::post().to(create_notebook_handler))
            .route(web::get().to(get_notebooks_handler))
    )
    .service(
        web::resource("/notebooks/{notebook_id}")
            .route(web::put().to(update_notebook_handler))
            .route(web::delete().to(delete_notebook_handler))
    )
    .service(
        web::resource("/notebooks/{notebook_id}/notes")
            .route(web::post().to(create_note_handler))
            .route(web::get().to(get_notes_handler))
    )
    .service(
        web::resource("/notes")
            .route(web::get().to(get_all_notes_handler))
            .route(web::post().to(create_note_without_notebook_handler))
    )
    .service(
        web::resource("/notes/{note_id}")
            .route(web::put().to(update_note_handler))
            .route(web::delete().to(delete_note_handler))
    );
}

pub fn configure_admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .wrap(AdminRoleMiddlewareFactory)
            .service(
                web::resource("/logs").route(web::get().to(crate::handlers::admin_logs_handler))
            )
            .service(
                web::resource("/logfiles").route(web::get().to(crate::handlers::admin_logfiles_handler))
            )
    );
}