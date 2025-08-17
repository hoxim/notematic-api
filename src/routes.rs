use actix_web::web;
use crate::handlers::{
    // Auth handlers
    register, login, refresh_token, protected_endpoint, health_check, oauth_login,
    
    // Notebook handlers
    create_notebook, get_notebooks, get_notebook, update_notebook, delete_notebook,
    create_note_in_notebook, get_notes_from_notebook,
    create_note_standalone, get_all_notes, get_note, update_note, delete_note,
    
    // Sync handlers
    sync_notes, sync_notebooks, get_sync_status,
    
    // Admin handlers
    admin_logs, admin_logfiles,
    
    // Version handlers
    get_api_version, get_api_status,
    
    // Sharing handlers
    share_note_handler, get_shared_notes_handler, get_shared_note_handler, delete_share_handler,
};
use crate::middleware::AdminRoleMiddlewareFactory;

pub fn configure_public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/health")
            .route(web::get().to(health_check))
    )
    .service(
        web::resource("/version")
            .route(web::get().to(get_api_version))
    )
    .service(
        web::resource("/status")
            .route(web::get().to(get_api_status))
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
        web::resource("/oauth/login")
            .route(web::post().to(oauth_login))
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
    // Notebooks - pełny CRUD
    .service(
        web::resource("/notebooks")
            .route(web::post().to(create_notebook))
            .route(web::get().to(get_notebooks))
    )
    .service(
        web::resource("/notebooks/{notebook_id}")
            .route(web::get().to(get_notebook))
            .route(web::put().to(update_notebook))
            .route(web::delete().to(delete_notebook))
    )
    // Notes w notebookach
    .service(
        web::resource("/notebooks/{notebook_id}/notes")
            .route(web::post().to(create_note_in_notebook))
            .route(web::get().to(get_notes_from_notebook))
    )
    // Notes standalone - pełny CRUD
    .service(
        web::resource("/notes")
            .route(web::post().to(create_note_standalone))
            .route(web::get().to(get_all_notes))
    )
    .service(
        web::resource("/notes/{note_id}")
            .route(web::get().to(get_note))
            .route(web::put().to(update_note))
            .route(web::delete().to(delete_note))
    )
    // Sync endpoints
    .service(
        web::resource("/sync/notes")
            .route(web::post().to(sync_notes))
    )
    .service(
        web::resource("/sync/notebooks")
            .route(web::post().to(sync_notebooks))
    )
    .service(
        web::resource("/sync/status")
            .route(web::get().to(get_sync_status))
    )
    // Sharing endpoints
    .service(
        web::resource("/notes/{note_id}/share")
            .route(web::post().to(share_note_handler))
    )
    .service(
        web::resource("/shares")
            .route(web::get().to(get_shared_notes_handler))
    )
    .service(
        web::resource("/shares/{share_id}")
            .route(web::get().to(get_shared_note_handler))
            .route(web::delete().to(delete_share_handler))
    );
}

pub fn configure_admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .wrap(AdminRoleMiddlewareFactory)
            .service(
                web::resource("/logs").route(web::get().to(admin_logs))
            )
            .service(
                web::resource("/logfiles").route(web::get().to(admin_logfiles))
            )
    );
}