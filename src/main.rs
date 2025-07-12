use actix_web::{App, HttpServer, middleware as actix_middleware}; // Alias for Actix Web's built-in middleware
use actix_cors::Cors;
use log::info;

use actix_web::web::{self};
use dotenv::dotenv;
use std::env;

mod routes;
mod models;
mod handlers;
mod utils;
mod middleware;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init();
    
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
    })
    .bind(("127.0.0.1", port.parse::<u16>().unwrap()))?
    .run()
    .await
}