use actix_web::{App, HttpServer, middleware as actix_middleware}; // Alias for Actix Web's built-in middleware
use actix_cors::Cors;
use log::info;
use flexi_logger::{Logger, Duplicate, Criterion, Naming, Cleanup, FileSpec};

use actix_web::web::{self};
use dotenv::dotenv;
use std::env;
use std::fs;

mod routes;
mod models;
mod handlers;
mod utils;
mod middleware;

use crate::routes::configure_admin_routes;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Ensure ./logs directory exists
    let _ = fs::create_dir_all("./logs");
    // Initialize flexi_logger for file and stdout logging (single file, no timestamp, no rotation)
    Logger::try_with_env_or_str("info")
        .unwrap()
        .log_to_file(FileSpec::default().directory("./logs").basename("api").suffix("log"))
        .start()
        .expect("Failed to initialize logger in ./logs");
    
    dotenv().ok(); // load vars form .env
    let port = env::var("API_PORT").unwrap_or_else(|_| "8080".to_string());

    info!("Starting Notematic API server");
    info!("Server will be available at http://localhost:{}", port);
    info!("Environment: {}", env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string()));
    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .wrap(actix_middleware::Logger::default()) // Logger for routes

            .service(
                web::scope("/protected") // Middleware only for protected routes
                    .wrap(middleware::JwtMiddlewareFactory)
                    .configure(routes::configure_protected_routes), // protected routes
            )
            .configure(routes::configure_public_routes) // public routes
            .configure(handlers::configure_routes) // endpoint /users/{username}
            .configure(configure_admin_routes) // admin endpoints
    })
    .bind(("0.0.0.0", port.parse::<u16>().unwrap()))?
    .run()
    .await
}