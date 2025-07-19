use actix_web::{web, HttpResponse, HttpRequest};
use bcrypt::{hash, verify};
use reqwest::Client;
use serde_json::json;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;
use log::{info, error, warn, debug};
use uuid::Uuid;
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::models::{User, LoginRequest, TokenResponse, RefreshTokenRequest, Notebook, Note};
use crate::utils::{
    generate_access_token,
    generate_refresh_token,
    generate_access_token_with_role,
    generate_refresh_token_with_role,
    verify_refresh_token,
    verify_jwt,
    find_user_in_database,
    get_couchdb_client,
    validate_user_input,
    check_rate_limit,
    create_notebook,
    get_user_notebooks,
    create_note,
    get_notebook_notes,
    get_all_user_notes
};

#[derive(Deserialize)]
pub struct GoogleLoginRequest {
    pub id_token: String,
}

pub async fn register(user: web::Json<User>, req: HttpRequest) -> HttpResponse {
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    info!("Registration attempt from IP: {}", peer_addr);
    debug!("Registration data: email={}", user.email);
    
    // Rate limiting - 5 requests per minute for registration
    if !check_rate_limit(&peer_addr, 5, Duration::from_secs(60)) {
        warn!("Rate limit exceeded for IP: {}", peer_addr);
        return HttpResponse::TooManyRequests().json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many registration attempts, please try again later"
        }));
    }

    // Walidacja formatu emaila
    let email_regex = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
    if !email_regex.is_match(&user.email) {
        return HttpResponse::BadRequest().json(json!({"error": "Invalid email format"}));
    }

    if user.password.len() < 8 {
        return HttpResponse::BadRequest().json(json!({"error": "Password must be at least 8 characters long"}));
    }

    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();

    // Sprawdź unikalność emaila (po _id)
    let check_response = client
        .get(format!("{}/users/{}", couchdb_url, user.email))
        .basic_auth(couchdb_user.clone(), Some(couchdb_password.clone()))
        .send()
        .await;

    if let Ok(res) = check_response {
        if res.status().is_success() {
            warn!("Email already exists: {}", user.email);
            return HttpResponse::Conflict().json(json!({"error": "Email already in use"}));
        }
    }

    let hashed_password = hash(&user.password, 4).unwrap();
    debug!("Password hashed successfully");

    // Set role to 'user' by default if not provided
    let user_role = user.role.clone().unwrap_or(crate::models::UserRole::User);

    let user_data = json!({
        "_id": user.email.clone(),
        "email": user.email.clone(),
        "password": hashed_password,
        "role": match user_role {
            crate::models::UserRole::Admin => "admin",
            _ => "user",
        }
    });

    debug!("Sending data to CouchDB: {:?}", user_data);

    let response = client
        .put(format!("{}/users/{}", couchdb_url, user.email))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .json(&user_data)
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            info!("User registered successfully: {}", user.email);
            
            // Generate tokens for the newly registered user
            let access_token = generate_access_token_with_role(&user.email, &user_role);
            let refresh_token = generate_refresh_token_with_role(&user.email, &user_role);
            
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
    
    info!("Login attempt from IP: {} for email: {}", peer_addr, credentials.email);
    
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
        .get(format!("{}/users/{}", couchdb_url, credentials.email))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            let user_data: serde_json::Value = res.json().await.unwrap();
            let stored_password = user_data["password"].as_str().unwrap();
            let user_role = match user_data["role"].as_str() {
                Some("admin") => crate::models::UserRole::Admin,
                Some("user") => crate::models::UserRole::User,
                Some(other) => {
                    debug!("Unknown role '{}' for user {}, defaulting to 'user'", other, credentials.email);
                    crate::models::UserRole::User
                },
                None => {
                    debug!("No role field for user {}, defaulting to 'user'", credentials.email);
                    crate::models::UserRole::User
                }
            };
            debug!("User {} has role: {:?}", credentials.email, user_role);
            if verify(&credentials.password, stored_password).unwrap() {
                let access_token = generate_access_token_with_role(&credentials.email, &user_role);
                let refresh_token = generate_refresh_token_with_role(&credentials.email, &user_role);
                
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
    cfg.service(web::resource("/users/{email}").route(web::get().to(get_user)));
}

async fn get_user(email: web::Path<String>) -> HttpResponse {
    let user = find_user_in_database(&email).await;
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
    let version_base = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let patch = env::var("API_PATCH_VERSION").unwrap_or_else(|_| "0".to_string());
    let version = format!("{}.{}", version_base.trim_end_matches(",0"), patch);
    let api_port = env::var("API_PORT").unwrap_or_else(|_| "8080".to_string());
    let build_hash = env::var("GIT_COMMIT_HASH").unwrap_or_else(|_| "unknown".to_string());
    let build_date = env::var("BUILD_DATE").unwrap_or_else(|_| chrono::Utc::now().to_rfc3339());
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
        "build": {
            "hash": build_hash,
            "date": build_date
        },
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
    
    // Get email from JWT token
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
    // Get email from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            log::info!("[DEBUG] Authorization header: {}", auth_str);
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                log::info!("[DEBUG] JWT token: {}", token);
                match verify_jwt(token) {
                    Ok(claims) => {
                        log::info!("[API] get_notebooks_handler: user={} (email), endpoint=/notebooks, method=GET", claims.sub);
                    match get_user_notebooks(&claims.sub).await {
                        Ok(notebooks) => {
                                log::info!("[API] get_notebooks_handler: user={} (email), returned {} notebooks", claims.sub, notebooks.len());
                            debug!("[API] get_notebooks_handler: notebooks for user={}: {:?}", claims.sub, notebooks);
                                HttpResponse::Ok().json(serde_json::json!({
                                "notebooks": notebooks
                            }))
                        }
                        Err(err) => {
                                log::error!("[API] get_notebooks_handler: error for user={}: {}", claims.sub, err);
                                HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Failed to fetch notebooks",
                                "message": err
                            }))
                        }
                    }
                    }
                    Err(e) => {
                        log::warn!("[API] get_notebooks_handler: invalid token: {}", e);
                        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
                    }
                }
            } else {
                log::warn!("[API] get_notebooks_handler: invalid Authorization header format: {}", auth_str);
                HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            log::warn!("[API] get_notebooks_handler: invalid Authorization header (not a string)");
            HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header"}))
        }
    } else {
        log::warn!("[API] get_notebooks_handler: missing Authorization header");
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing Authorization header"}))
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
    
    // Get email from JWT token
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
    // Get email from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            log::info!("[DEBUG] Authorization header: {}", auth_str);
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                log::info!("[DEBUG] JWT token: {}", token);
                match verify_jwt(token) {
                    Ok(claims) => {
                        log::info!("[API] get_notes_handler: user={} (email), endpoint=/notebooks/{}/notes, method=GET", claims.sub, notebook_id);
                    // Pobierz query param 'tags' jeśli jest
                    let query_map = web::Query::<std::collections::HashMap<String, String>>::from_query(req.query_string()).ok();
                    let tags: Option<Vec<String>> = query_map
                        .as_ref()
                        .and_then(|q| q.get("tags"))
                        .map(|tags_str| tags_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
                    match get_notebook_notes(&notebook_id).await {
                        Ok(mut notes) => {
                            if let Some(tags) = tags {
                                notes = notes.into_iter().filter(|note| {
                                    note.get("tags")
                                        .and_then(|tags_val| tags_val.as_array())
                                        .map(|tags_arr| tags_arr.iter().any(|t| t.as_str().map(|tag| tags.contains(&tag.to_string())).unwrap_or(false)))
                                        .unwrap_or(false)
                                }).collect();
                            }
                                log::info!("[API] get_notes_handler: user={} (email), notebook_id={}, returned {} notes", claims.sub, notebook_id, notes.len());
                                debug!("[API] get_notes_handler: notes for user={} notebook_id={}: {:?}", claims.sub, notebook_id, notes);
                                HttpResponse::Ok().json(serde_json::json!({
                                "notes": notes
                            }))
                        }
                        Err(err) => {
                                log::error!("[API] get_notes_handler: error for user={} notebook_id={}: {}", claims.sub, notebook_id, err);
                                HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Failed to fetch notes",
                                "message": err
                            }))
                        }
                    }
                    }
                    Err(e) => {
                        log::warn!("[API] get_notes_handler: invalid token: {}", e);
                        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
                    }
                }
            } else {
                log::warn!("[API] get_notes_handler: invalid Authorization header format: {}", auth_str);
                HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            log::warn!("[API] get_notes_handler: invalid Authorization header (not a string)");
            HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header"}))
        }
    } else {
        log::warn!("[API] get_notes_handler: missing Authorization header");
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing Authorization header"}))
    }
}

/// Handler for /admin/logs (admin only)
pub async fn admin_logs_handler(_req: HttpRequest) -> HttpResponse {
    let logs_dir = "./logs";
    let pattern = "api_";
    let mut newest_path: Option<std::path::PathBuf> = None;
    let mut newest_mtime = std::time::UNIX_EPOCH;
    if let Ok(entries) = fs::read_dir(logs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                if fname.starts_with(pattern) && fname.ends_with(".log") {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(mtime) = meta.modified() {
                            if mtime > newest_mtime {
                                newest_mtime = mtime;
                                newest_path = Some(path);
                            }
                        }
                    }
                }
            }
        }
    }
    let lines: Vec<String> = if let Some(log_path) = newest_path {
        if let Ok(file) = File::open(&log_path) {
            let reader = BufReader::new(file);
            let all_lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();
            let total = all_lines.len();
            let result = if total > 100 {
                all_lines[total - 100..].to_vec()
            } else {
                all_lines
            };
            result
        } else {
            vec!["Could not open log file.".to_string()]
        }
    } else {
        vec!["No log file found.".to_string()]
    };
    HttpResponse::Ok().json(serde_json::json!({
        "logs": lines
    }))
}

/// Handler for /admin/logfiles (admin only)
pub async fn admin_logfiles_handler(_req: HttpRequest) -> HttpResponse {
    let logs_dir = "./logs";
    let pattern = "api_";
    let mut files: Vec<(String, std::time::SystemTime)> = vec![];
    if let Ok(entries) = std::fs::read_dir(logs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                if fname.starts_with(pattern) && fname.ends_with(".log") {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(mtime) = meta.modified() {
                            files.push((fname.to_string(), mtime));
                        }
                    }
                }
            }
        }
    }
    // Sortuj od najnowszego
    files.sort_by(|a, b| b.1.cmp(&a.1));
    let result: Vec<_> = files.into_iter().map(|(name, mtime)| {
        let ts = chrono::DateTime::<chrono::Local>::from(mtime).to_rfc3339();
        serde_json::json!({"name": name, "modified": ts})
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({"logfiles": result}))
}

/// Handler for /protected/notes - get all notes for user
pub async fn get_all_notes_handler(req: HttpRequest) -> HttpResponse {
    // Get email from JWT token
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            log::info!("[DEBUG] Authorization header: {}", auth_str);
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                log::info!("[DEBUG] JWT token: {}", token);
                match verify_jwt(token) {
                    Ok(claims) => {
                        log::info!("[API] get_all_notes_handler: user={} (email), endpoint=/protected/notes, method=GET", claims.sub);
                        
                        match get_all_user_notes(&claims.sub).await {
                            Ok(notes) => {
                                log::info!("[API] get_all_notes_handler: user={} (email), returned {} notes", claims.sub, notes.len());
                                debug!("[API] get_all_notes_handler: notes for user={}: {:?}", claims.sub, notes);
                                HttpResponse::Ok().json(serde_json::json!({
                                    "notes": notes
                                }))
                            }
                            Err(err) => {
                                log::error!("[API] get_all_notes_handler: error for user={}: {}", claims.sub, err);
                                HttpResponse::InternalServerError().json(serde_json::json!({
                                    "error": "Failed to fetch notes",
                                    "message": err
                                }))
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("[API] get_all_notes_handler: invalid token: {}", e);
                        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
                    }
                }
            } else {
                log::warn!("[API] get_all_notes_handler: invalid Authorization header format: {}", auth_str);
                HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header format"}))
            }
        } else {
            log::warn!("[API] get_all_notes_handler: invalid Authorization header (not a string)");
            HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header"}))
        }
    } else {
        log::warn!("[API] get_all_notes_handler: missing Authorization header");
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing Authorization header"}))
    }
}