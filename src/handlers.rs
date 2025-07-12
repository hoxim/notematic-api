use actix_web::{web, HttpResponse, HttpRequest};
use bcrypt::{hash, verify};
use reqwest::Client;
use serde_json::json;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;
use log::{info, error, warn, debug};

use crate::models::{User, LoginRequest, TokenResponse, RefreshTokenRequest, Notebook, Note};
use crate::utils::{
    generate_access_token,
    generate_refresh_token,
    verify_refresh_token,
    verify_jwt,
    find_user_in_database,
    get_couchdb_client,
    validate_user_input,
    check_rate_limit,
    create_notebook,
    get_user_notebooks,
    create_note,
    get_notebook_notes
};

pub async fn register(user: web::Json<User>, req: HttpRequest) -> HttpResponse {
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    info!("Registration attempt from IP: {}", peer_addr);
    debug!("Registration data: username={}", user.username);
    
    // Rate limiting - 5 requests per minute for registration
    if !check_rate_limit(&peer_addr, 5, Duration::from_secs(60)) {
        warn!("Rate limit exceeded for IP: {}", peer_addr);
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many registration attempts, please try again later"
        }));
    }

    if let Err(err) = validate_user_input(&user.username, &user.password) {
        warn!("Invalid user input: {}", err);
        return HttpResponse::BadRequest().json(json!({"error": err}));
    }

    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();

    let check_response = client
        .get(format!("{}/users/{}", couchdb_url, user.username))
        .basic_auth(couchdb_user.clone(), Some(couchdb_password.clone()))
        .send()
        .await;

    if let Ok(res) = check_response {
        if res.status().is_success() {
            warn!("User already exists: {}", user.username);
            return HttpResponse::Conflict().json(json!({"error": "User already exists"}));
        }
    }

    let hashed_password = hash(&user.password, 4).unwrap();
    debug!("Password hashed successfully");

    let user_data = json!({
        "_id": user.username.clone(),
        "username": user.username.clone(),
        "password": hashed_password,
    });

    debug!("Sending data to CouchDB: {:?}", user_data);

    let response = client
        .put(format!("{}/users/{}", couchdb_url, user.username))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .json(&user_data)
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            info!("User registered successfully: {}", user.username);
            
            // Generate tokens for the newly registered user
            let access_token = generate_access_token(&user.username);
            let refresh_token = generate_refresh_token(&user.username);
            
            let token_response = TokenResponse {
                access_token,
                refresh_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600, // 1 hour in seconds
            };
            
            HttpResponse::Ok().json(token_response)
        }
        Ok(res) => {
            let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            error!("Error during registration: {}", error_message);
            HttpResponse::InternalServerError().json(json!({"error": error_message}))
        }
        Err(err) => {
            error!("Error connecting to CouchDB: {}", err);
            HttpResponse::InternalServerError().json(json!({"error": err.to_string()}))
        }
    }
}

pub async fn login(credentials: web::Json<LoginRequest>, req: HttpRequest) -> HttpResponse {
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    info!("Login attempt from IP: {} for user: {}", peer_addr, credentials.username);
    
    // Rate limiting - 10 requests per minute for login
    if !check_rate_limit(&peer_addr, 10, Duration::from_secs(60)) {
        warn!("Rate limit exceeded for login from IP: {}", peer_addr);
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many login attempts, please try again later"
        }));
    }
    
    let couchdb_url = env::var("COUCHDB_URL").unwrap();
    let couchdb_user = env::var("COUCHDB_USER").unwrap();
    let couchdb_password = env::var("COUCHDB_PASSWORD").unwrap();

    let client = Client::new();
    let response = client
        .get(format!("{}/users/{}", couchdb_url, credentials.username))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            let user_data: serde_json::Value = res.json().await.unwrap();
            let stored_password = user_data["password"].as_str().unwrap();

            if verify(&credentials.password, stored_password).unwrap() {
                let access_token = generate_access_token(&credentials.username);
                let refresh_token = generate_refresh_token(&credentials.username);
                
                let token_response = TokenResponse {
                    access_token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 3600, // 1 hour in seconds
                };
                
                HttpResponse::Ok().json(token_response)
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}))
            }
        }
        Ok(_) => HttpResponse::Unauthorized().json(json!({"error": "User not found"})),
        Err(err) => HttpResponse::InternalServerError().json(json!({"error": err.to_string()})),
    }
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/users/{username}").route(web::get().to(get_user)));
}

async fn get_user(username: web::Path<String>) -> HttpResponse {
    let user = find_user_in_database(&username).await;
    match user {
        Some(u) => HttpResponse::Ok().json(u),
        None => HttpResponse::NotFound().finish(),
    }
}

pub async fn refresh_token(request: web::Json<RefreshTokenRequest>, req: HttpRequest) -> HttpResponse {
    // Rate limiting - 20 requests per minute for refresh tokens
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    if !check_rate_limit(&peer_addr, 20, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many refresh token requests, please try again later"
        }));
    }
    
    match verify_refresh_token(&request.refresh_token) {
        Ok(claims) => {
            let access_token = generate_access_token(&claims.sub);
            let refresh_token = generate_refresh_token(&claims.sub);
            
            let token_response = TokenResponse {
                access_token,
                refresh_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600, // 1 hour in seconds
            };
            
            HttpResponse::Ok().json(token_response)
        }
        Err(_) => {
            HttpResponse::Unauthorized().json(json!({
                "error": "Invalid refresh token"
            }))
        }
    }
}

pub async fn protected_endpoint() -> HttpResponse {
    HttpResponse::Ok().json(json!({"message": "Access granted"}))
}

pub async fn health_check() -> HttpResponse {
    let environment = env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string());
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let api_port = env::var("API_PORT").unwrap_or_else(|_| "8080".to_string());
    
    // Check database connection
    let db_status = check_database_connection().await;
    
    // Get system info
    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "environment": environment,
        "version": version,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "api": {
            "port": api_port,
            "uptime_seconds": uptime
        },
        "database": {
            "status": db_status.status,
            "message": db_status.message
        },
        "services": {
            "auth": "operational",
            "notebooks": "operational",
            "notes": "operational"
        }
    }))
}

#[derive(Serialize, Deserialize)]
struct DatabaseStatus {
    status: String,
    message: String,
}

async fn check_database_connection() -> DatabaseStatus {
    let (client, url, _user, _pass) = get_couchdb_client();
    
    // Try to connect to CouchDB
    match client.get(&format!("{}/", url)).send().await {
        Ok(response) => {
            if response.status().is_success() {
                DatabaseStatus {
                    status: "connected".to_string(),
                    message: "Database connection successful".to_string(),
                }
            } else {
                DatabaseStatus {
                    status: "error".to_string(),
                    message: format!("Database returned status: {}", response.status()),
                }
            }
        }
        Err(e) => DatabaseStatus {
            status: "error".to_string(),
            message: format!("Database connection failed: {}", e),
        },
    }
}

// Notebook handlers
pub async fn create_notebook_handler(notebook: web::Json<Notebook>, req: HttpRequest) -> HttpResponse {
    // Rate limiting - 10 requests per minute for notebook creation
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    if !check_rate_limit(&peer_addr, 10, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many notebook creation requests, please try again later"
        }));
    }
    
    // Get username from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(claims) = verify_jwt(token) {
                    match create_notebook(&claims.sub, &serde_json::to_value(&notebook.into_inner()).unwrap()).await {
                        Ok(notebook_id) => {
                            HttpResponse::Created().json(json!({
                                "message": "Notebook created successfully",
                                "notebook_id": notebook_id
                            }))
                        }
                        Err(err) => {
                            HttpResponse::InternalServerError().json(json!({
                                "error": "Failed to create notebook",
                                "message": err
                            }))
                        }
                    }
                } else {
                    HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}))
                }
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header"}))
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"error": "Missing Authorization header"}))
    }
}

pub async fn get_notebooks_handler(req: HttpRequest) -> HttpResponse {
    // Get username from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(claims) = verify_jwt(token) {
                    match get_user_notebooks(&claims.sub).await {
                        Ok(notebooks) => {
                            HttpResponse::Ok().json(json!({
                                "notebooks": notebooks
                            }))
                        }
                        Err(err) => {
                            HttpResponse::InternalServerError().json(json!({
                                "error": "Failed to fetch notebooks",
                                "message": err
                            }))
                        }
                    }
                } else {
                    HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}))
                }
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header"}))
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"error": "Missing Authorization header"}))
    }
}

// Note handlers
pub async fn create_note_handler(
    notebook_id: web::Path<String>,
    note: web::Json<Note>,
    req: HttpRequest
) -> HttpResponse {
    // Rate limiting - 20 requests per minute for note creation
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    if !check_rate_limit(&peer_addr, 20, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many note creation requests, please try again later"
        }));
    }
    
    // Get username from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(claims) = verify_jwt(token) {
                    match create_note(&claims.sub, &notebook_id, &serde_json::to_value(&note.into_inner()).unwrap()).await {
                        Ok(note_id) => {
                            HttpResponse::Created().json(json!({
                                "message": "Note created successfully",
                                "note_id": note_id
                            }))
                        }
                        Err(err) => {
                            HttpResponse::InternalServerError().json(json!({
                                "error": "Failed to create note",
                                "message": err
                            }))
                        }
                    }
                } else {
                    HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}))
                }
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header"}))
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"error": "Missing Authorization header"}))
    }
}

pub async fn get_notes_handler(notebook_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    // Get username from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(_claims) = verify_jwt(token) {
                    match get_notebook_notes(&notebook_id).await {
                        Ok(notes) => {
                            HttpResponse::Ok().json(json!({
                                "notes": notes
                            }))
                        }
                        Err(err) => {
                            HttpResponse::InternalServerError().json(json!({
                                "error": "Failed to fetch notes",
                                "message": err
                            }))
                        }
                    }
                } else {
                    HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}))
                }
            } else {
                HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            HttpResponse::Unauthorized().json(json!({"error": "Invalid Authorization header"}))
        }
    } else {
        HttpResponse::Unauthorized().json(json!({"error": "Missing Authorization header"}))
    }
}