use actix_web::{App, HttpServer, middleware as actix_middleware}; // Alias dla middleware z Actix Web
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
    dotenv().ok(); // load vars form .env
    let port = env::var("API_PORT").unwrap_or_else(|_| "8080".to_string());

    println!("Starting server at http://localhost:{}", port);

    HttpServer::new(|| {
        App::new()
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