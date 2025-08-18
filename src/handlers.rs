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
// Unused imports removed - will be needed when implementing admin functions

use crate::models::{User, LoginRequest, TokenResponse, RefreshTokenRequest, Notebook, Note, OAuthLoginRequest, AuthProvider, OAuthData};
use crate::utils::Claims;
use crate::utils::{
    generate_access_token,
    generate_refresh_token,
    generate_access_token_with_role,
    generate_refresh_token_with_role,
    verify_refresh_token,
    verify_jwt,
    find_user_in_database,
    get_couchdb_client,
    check_rate_limit,
    create_notebook as create_notebook_util,
    get_user_notebooks,
    create_note,
    get_notebook_notes,
    get_all_user_notes,
    delete_note as delete_note_util
};

// Rate limiting constants
const RATE_LIMITS: &[(&str, u32, u64)] = &[
    ("auth", 5, 60),      // 5/min dla auth
    ("notebooks", 10, 60), // 10/min dla notebooków
    ("notes", 20, 60),     // 20/min dla notatek
    ("sync", 30, 60),      // 30/min dla sync
];

// Helper functions
pub fn create_error(error: &str, message: &str, code: &str) -> serde_json::Value {
    json!({
        "error": error.to_string(),
        "message": message.to_string(),
        "code": code.to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
}

pub fn validate_notebook(notebook: &Notebook) -> Result<(), String> {
    if notebook.name.trim().is_empty() {
        return Err("Notebook name cannot be empty".to_string());
    }
    if notebook.name.len() > 100 {
        return Err("Notebook name too long (max 100 characters)".to_string());
    }
    if let Some(desc) = &notebook.description {
        if desc.len() > 500 {
            return Err("Notebook description too long (max 500 characters)".to_string());
        }
    }
    Ok(())
}

pub fn validate_note(note: &Note) -> Result<(), String> {
    if note.title.trim().is_empty() {
        return Err("Note title cannot be empty".to_string());
    }
    if note.title.len() > 200 {
        return Err("Note title too long (max 200 characters)".to_string());
    }
    if note.content.len() > 10000 {
        return Err("Note content too long (max 10000 characters)".to_string());
    }
    Ok(())
}

/// OAuth link request (reuse OAuthLoginRequest fields)
#[derive(Deserialize)]
pub struct OAuthLinkRequest {
    pub email: String,
    pub oauth_token: String,
    pub provider: AuthProvider,
    pub oauth_data: Option<OAuthData>,
}

pub fn log_api_call(user: &str, method: &str, endpoint: &str, status: u16, duration_ms: u64) {
    info!("API: {} {} {} {} {}ms", user, method, endpoint, status, duration_ms);
}

/// Link an OAuth provider to the currently authenticated user
pub async fn oauth_link(link_request: web::Json<OAuthLinkRequest>, req: HttpRequest) -> HttpResponse {
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    info!("OAuth link attempt from IP: {} for email: {} with provider: {:?}",
          peer_addr, link_request.email, link_request.provider);

    // Require valid access token
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => h.to_str().ok(),
        None => None,
    };
    if auth_header.is_none() || !auth_header.unwrap().starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(create_error(
            "missing_header",
            "Missing or invalid Authorization header",
            "AUTH_ERROR"
        ));
    }
    let token = &auth_header.unwrap()[7..];
    let claims = match verify_jwt(token) {
        Ok(c) => c,
        Err(_) => {
            return HttpResponse::Unauthorized().json(create_error(
                "invalid_token",
                "Invalid token",
                "AUTH_ERROR"
            ));
        }
    };

    // Ensure the linking email matches the authenticated user
    if claims.sub != link_request.email {
        return HttpResponse::Forbidden().json(create_error(
            "email_mismatch",
            "Authenticated user does not match link email",
            "FORBIDDEN"
        ));
    }

    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();

    // Load user document
    let user_res = client
        .get(format!("{}/users/{}", couchdb_url, link_request.email))
        .basic_auth(couchdb_user.clone(), Some(couchdb_password.clone()))
        .send()
        .await;

    match user_res {
        Ok(res) if res.status().is_success() => {
            let mut user_doc: serde_json::Value = res.json().await.unwrap_or_default();
            let rev = user_doc["_rev"].as_str().unwrap_or("").to_string();

            // Set OAuth fields
            user_doc["auth_provider"] = serde_json::Value::String(format!("{:?}", link_request.provider).to_lowercase());
            if let Some(ref d) = link_request.oauth_data {
                user_doc["oauth_id"] = serde_json::Value::String(d.provider_id.clone());
                user_doc["oauth_data"] = serde_json::to_value(d).unwrap_or(serde_json::Value::Null);
            }

            // Update doc
            let mut updated_doc = user_doc.clone();
            updated_doc["_rev"] = serde_json::Value::String(rev);
            let put_res = client
                .put(format!("{}/users/{}", couchdb_url, link_request.email))
                .basic_auth(couchdb_user, Some(couchdb_password))
                .json(&updated_doc)
                .send()
                .await;

            match put_res {
                Ok(r) if r.status().is_success() => {
                    info!("Linked provider for user: {}", link_request.email);
                    HttpResponse::Ok().json(serde_json::json!({ "status": "linked" }))
                }
                Ok(r) => {
                    let text = r.text().await.unwrap_or_else(|_| "unknown".to_string());
                    error!("Failed to update user during link: {} => {}", link_request.email, text);
                    HttpResponse::InternalServerError().json(create_error(
                        "link_update_failed",
                        "Failed to link provider",
                        "INTERNAL_ERROR"
                    ))
                }
                Err(e) => {
                    error!("Error updating user during link: {} => {}", link_request.email, e);
                    HttpResponse::InternalServerError().json(create_error(
                        "link_update_error",
                        &e.to_string(),
                        "INTERNAL_ERROR"
                    ))
                }
            }
        }
        Ok(_) => HttpResponse::NotFound().json(create_error(
            "user_not_found",
            "User not found",
            "NOT_FOUND"
        )),
        Err(e) => {
            error!("Error fetching user for link: {} => {}", link_request.email, e);
            HttpResponse::InternalServerError().json(create_error(
                "couchdb_error",
                &e.to_string(),
                "INTERNAL_ERROR"
            ))
        }
    }
}
// Helper functions do redukcji boilerplate
pub fn extract_auth_token(req: &HttpRequest) -> Result<String, serde_json::Value> {
    let auth_header = req.headers().get("Authorization")
        .ok_or_else(|| create_error("missing_header", "Missing Authorization header", "AUTH_ERROR"))?;
    
    let auth_str = auth_header.to_str()
        .map_err(|_| create_error("invalid_header", "Invalid Authorization header", "AUTH_ERROR"))?;
    
    if !auth_str.starts_with("Bearer ") {
        return Err(create_error("invalid_header", "Invalid Authorization header format", "AUTH_ERROR"));
    }
    
    Ok(auth_str[7..].to_string())
}

pub fn verify_user_token(token: &str) -> Result<Claims, serde_json::Value> {
    verify_jwt(token)
        .map_err(|_| create_error("invalid_token", "Invalid or expired token", "AUTH_ERROR"))
}

pub fn check_rate_limit_for_operation(peer_addr: &str, operation: &str) -> Result<(), serde_json::Value> {
    let limits = RATE_LIMITS.iter().find(|(op, _, _)| *op == operation);
    
    if let Some((_, limit, window)) = limits {
        if !check_rate_limit(peer_addr, *limit, Duration::from_secs(*window)) {
            return Err(create_error(
                "rate_limit_exceeded",
                &format!("Too many {} requests, please try again later", operation),
                "RATE_LIMIT"
            ));
        }
    }
    
    Ok(())
}

pub fn get_peer_address(req: &HttpRequest) -> String {
    req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// Wrapper dla handlerów z automatycznym auth i rate limiting
pub async fn with_auth_and_rate_limit<F, Fut>(
    req: HttpRequest,
    operation: &str,
    handler: F
) -> HttpResponse 
where
    F: FnOnce(String, Claims) -> Fut,
    Fut: std::future::Future<Output = Result<HttpResponse, serde_json::Value>>,
{
    let start = std::time::Instant::now();
    let peer_addr = get_peer_address(&req);
    
    // Rate limiting
    if let Err(error) = check_rate_limit_for_operation(&peer_addr, operation) {
        return HttpResponse::TooManyRequests().json(error);
    }
    
    // Auth
    let token = match extract_auth_token(&req) {
        Ok(token) => token,
        Err(error) => return HttpResponse::Unauthorized().json(error),
    };
    
    let claims = match verify_user_token(&token) {
        Ok(claims) => claims,
        Err(error) => return HttpResponse::Unauthorized().json(error),
    };
    
    // Execute handler
    let user_id = claims.sub.clone();
    match handler(peer_addr, claims).await {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            log_api_call(&user_id, "UNKNOWN", "UNKNOWN", 200, duration);
            response
        }
        Err(error) => {
            let duration = start.elapsed().as_millis() as u64;
            log_api_call(&user_id, "UNKNOWN", "UNKNOWN", 500, duration);
            HttpResponse::InternalServerError().json(error)
        }
    }
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
        return HttpResponse::TooManyRequests().json(create_error(
            "rate_limit_exceeded",
            "Too many registration attempts, please try again later",
            "RATE_LIMIT"
        ));
    }

    // Walidacja formatu emaila
    let email_regex = Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
    if !email_regex.is_match(&user.email) {
        return HttpResponse::BadRequest().json(create_error(
            "invalid_email",
            "Invalid email format",
            "VALIDATION"
        ));
    }

    if let Some(password) = &user.password {
        if password.len() < 8 {
            return HttpResponse::BadRequest().json(create_error(
                "invalid_password",
                "Password must be at least 8 characters long",
                "VALIDATION"
            ));
        }
    } else {
        return HttpResponse::BadRequest().json(create_error(
            "invalid_password",
            "Password is required for local registration",
            "VALIDATION"
        ));
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
            return HttpResponse::Conflict().json(create_error(
                "email_in_use",
                "Email already in use",
                "CONFLICT"
            ));
        }
    }

    let hashed_password = hash(&user.password.as_ref().unwrap(), 4).unwrap();
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
                api_version: crate::version::API_VERSION.to_string(),
            };
            
            HttpResponse::Ok().json(token_response)
        }
        Ok(res) => {
            let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            error!("Error during registration: {}", error_message);
            HttpResponse::InternalServerError().json(create_error(
                "registration_failed",
                &error_message,
                "INTERNAL_ERROR"
            ))
        }
        Err(err) => {
            error!("Error connecting to CouchDB: {}", err);
            HttpResponse::InternalServerError().json(create_error(
                "couchdb_error",
                &err.to_string(),
                "INTERNAL_ERROR"
            ))
        }
    }
}

/// OAuth login handler
pub async fn oauth_login(oauth_request: web::Json<OAuthLoginRequest>, req: HttpRequest) -> HttpResponse {
    let peer_addr = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    info!("OAuth login attempt from IP: {} for email: {} with provider: {:?}", 
          peer_addr, oauth_request.email, oauth_request.provider);
    
    // Rate limiting - 10 requests per minute for OAuth login
    if !check_rate_limit(&peer_addr, 10, Duration::from_secs(60)) {
        warn!("Rate limit exceeded for OAuth login from IP: {}", peer_addr);
        return HttpResponse::TooManyRequests().json(create_error(
            "rate_limit_exceeded",
            "Too many OAuth login attempts, please try again later",
            "RATE_LIMIT"
        ));
    }

    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();

    // TODO: Verify OAuth token with provider (Google, GitHub, Facebook)
    // For now, we'll trust the token and proceed

    // Check if user exists
    let response = client
        .get(format!("{}/users/{}", couchdb_url, oauth_request.email))
        .basic_auth(couchdb_user.clone(), Some(couchdb_password.clone()))
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            // User exists, check if OAuth provider matches
            let user_data: serde_json::Value = res.json().await.unwrap();
            let existing_provider = user_data["auth_provider"].as_str();
            
            if let Some(provider) = existing_provider {
                if provider == format!("{:?}", oauth_request.provider).to_lowercase() {
                    // Provider matches, generate tokens
                    let user_role = match user_data["role"].as_str() {
                        Some("admin") => crate::models::UserRole::Admin,
                        _ => crate::models::UserRole::User,
                    };
                    
                    let access_token = generate_access_token_with_role(&oauth_request.email, &user_role);
                    let refresh_token = generate_refresh_token_with_role(&oauth_request.email, &user_role);
                    
                    let token_response = TokenResponse {
                        access_token,
                        refresh_token,
                        token_type: "Bearer".to_string(),
                        expires_in: 3600,
                        api_version: crate::version::API_VERSION.to_string(),
                    };
                    
                    HttpResponse::Ok().json(token_response)
                } else {
                    // Provider mismatch
                    HttpResponse::Conflict().json(create_error(
                        "oauth_provider_mismatch",
                        "Account exists with different OAuth provider",
                        "CONFLICT"
                    ))
                }
            } else {
                // User exists but no OAuth provider set
                HttpResponse::Conflict().json(create_error(
                    "account_exists",
                    "Account exists with local authentication",
                    "CONFLICT"
                ))
            }
        }
        Ok(_) => {
            // User doesn't exist, create new OAuth user
            let user_data = json!({
                "_id": oauth_request.email.clone(),
                "email": oauth_request.email.clone(),
                "password": null, // No password for OAuth users
                "role": "user",
                "auth_provider": format!("{:?}", oauth_request.provider).to_lowercase(),
                "oauth_id": oauth_request.oauth_data.as_ref().map(|d| d.provider_id.clone()),
                "oauth_data": oauth_request.oauth_data,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "last_login": chrono::Utc::now().to_rfc3339(),
            });

            let create_response = client
                .put(format!("{}/users/{}", couchdb_url, oauth_request.email))
                .basic_auth(couchdb_user, Some(couchdb_password))
                .json(&user_data)
                .send()
                .await;

            match create_response {
                Ok(res) if res.status().is_success() => {
                    info!("OAuth user created successfully: {}", oauth_request.email);
                    
                    let access_token = generate_access_token_with_role(&oauth_request.email, &crate::models::UserRole::User);
                    let refresh_token = generate_refresh_token_with_role(&oauth_request.email, &crate::models::UserRole::User);
                    
                    let token_response = TokenResponse {
                        access_token,
                        refresh_token,
                        token_type: "Bearer".to_string(),
                        expires_in: 3600,
                        api_version: crate::version::API_VERSION.to_string(),
                    };
                    
                    HttpResponse::Ok().json(token_response)
                }
                _ => {
                    error!("Failed to create OAuth user: {}", oauth_request.email);
                    HttpResponse::InternalServerError().json(create_error(
                        "oauth_user_creation_failed",
                        "Failed to create OAuth user",
                        "INTERNAL_ERROR"
                    ))
                }
            }
        }
        Err(err) => {
            error!("Error connecting to CouchDB during OAuth login: {}", err);
            HttpResponse::InternalServerError().json(create_error(
                "couchdb_error",
                &err.to_string(),
                "INTERNAL_ERROR"
            ))
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
        return HttpResponse::TooManyRequests().json(create_error(
            "rate_limit_exceeded",
            "Too many login attempts, please try again later",
            "RATE_LIMIT"
        ));
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
                    api_version: crate::version::API_VERSION.to_string(),
                };
                
                HttpResponse::Ok().json(token_response)
            } else {
                HttpResponse::Unauthorized().json(create_error(
                    "invalid_credentials",
                    "Invalid credentials",
                    "AUTH_ERROR"
                ))
            }
        }
        Ok(_) => HttpResponse::Unauthorized().json(create_error(
            "user_not_found",
            "User not found",
            "AUTH_ERROR"
        )),
        Err(err) => HttpResponse::InternalServerError().json(create_error(
            "couchdb_error",
            &err.to_string(),
            "INTERNAL_ERROR"
        )),
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
        return HttpResponse::TooManyRequests().json(create_error(
            "rate_limit_exceeded",
            "Too many refresh token requests, please try again later",
            "RATE_LIMIT"
        ));
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
                api_version: crate::version::API_VERSION.to_string(),
            };
            
            HttpResponse::Ok().json(token_response)
        }
        Err(_) => {
            HttpResponse::Unauthorized().json(create_error(
                "invalid_refresh_token",
                "Invalid refresh token",
                "AUTH_ERROR"
            ))
        }
    }
}

pub async fn protected_endpoint() -> HttpResponse {
    HttpResponse::Ok().json(json!({"message": "Access granted"}))
}

pub async fn health_check() -> HttpResponse {
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
        "environment": crate::version::API_ENVIRONMENT,
        "version": crate::version::API_VERSION,
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

// OLD HANDLERS REMOVED - replaced with new simplified handlers below

// Nowe uproszczone handlery
pub async fn get_notebooks(req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notebooks", |_peer_addr, claims| async move {
        match get_user_notebooks(&claims.sub).await {
            Ok(notebooks) => {
                Ok(HttpResponse::Ok().json(json!({
                    "notebooks": notebooks,
                    "count": notebooks.len()
                })))
            }
            Err(err) => {
                Err(create_error(
                    "fetch_failed",
                    &format!("Failed to fetch notebooks: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn create_notebook(notebook: web::Json<Notebook>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notebooks", |_peer_addr, claims| async move {
        // Validate input
        if let Err(validation_error) = validate_notebook(&notebook) {
            return Err(create_error("validation_error", &validation_error, "VALIDATION"));
        }
        
        let notebook_uuid = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        
        let notebook_data = json!({
            "_id": notebook_uuid,
            "uuid": notebook_uuid,
            "name": notebook.name,
            "description": notebook.description,
            "color": notebook.color,
            "user": claims.sub,
            "created_at": now,
            "updated_at": now,
            "version": 1,
        });
        
        match create_notebook_util(&claims.sub, &serde_json::to_value(&notebook_data).unwrap()).await {
            Ok(notebook_id) => {
                Ok(HttpResponse::Created().json(json!({
                    "message": "Notebook created successfully",
                    "uuid": notebook_id,
                    "version": 1
                })))
            }
            Err(err) => {
                Err(create_error(
                    "creation_failed",
                    &format!("Failed to create notebook: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn get_all_notes(req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, claims| async move {
        match get_all_user_notes(&claims.sub).await {
            Ok(notes) => {
                Ok(HttpResponse::Ok().json(json!({
                    "notes": notes,
                    "count": notes.len()
                })))
            }
            Err(err) => {
                Err(create_error(
                    "fetch_failed",
                    &format!("Failed to fetch notes: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn sync_notes(req: HttpRequest, sync_data: web::Json<crate::models::SyncRequest>) -> HttpResponse {
    with_auth_and_rate_limit(req, "sync", |_peer_addr, _claims| async move {
        let sync_timestamp = chrono::Utc::now().to_rfc3339();
        let conflicts = Vec::new(); // TODO: implement conflict resolution
        let applied_changes = sync_data.changes.len();
        
        let response = crate::models::SyncResponse {
            sync_timestamp,
            conflicts,
            applied_changes,
        };
        
        Ok(HttpResponse::Ok().json(response))
    }).await
}

pub async fn sync_notebooks(req: HttpRequest, sync_data: web::Json<crate::models::SyncRequest>) -> HttpResponse {
    sync_notes(req, sync_data).await
}

pub async fn get_sync_status(req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "sync", |_peer_addr, _claims| async move {
        let status = crate::models::SyncStatus {
            last_sync: None, // TODO: implement last sync tracking
            device_id: "unknown".to_string(),
            pending_changes: 0,
            conflicts: 0,
        };
        
        Ok(HttpResponse::Ok().json(status))
    }).await
}

// Rename existing handlers to new names
pub async fn create_note_in_notebook(
    notebook_id: web::Path<String>,
    note: web::Json<Note>,
    req: HttpRequest
) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, claims| async move {
        // Validate input
        if let Err(validation_error) = validate_note(&note) {
            return Err(create_error("validation_error", &validation_error, "VALIDATION"));
        }
        
        let notebook_id_str = notebook_id.into_inner();
        let note_uuid = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        
        let note_data = json!({
            "_id": note_uuid,
            "uuid": note_uuid,
            "title": note.title,
            "content": note.content,
            "tags": note.tags,
            "notebook": notebook_id_str,
            "user": claims.sub,
            "created_at": now,
            "updated_at": now,
            "version": 1,
        });
        
        match create_note(&claims.sub, &notebook_id_str, &serde_json::to_value(&note_data).unwrap()).await {
            Ok(note_id) => {
                Ok(HttpResponse::Created().json(json!({
                    "message": "Note created successfully",
                    "uuid": note_id,
                    "version": 1
                })))
            }
            Err(err) => {
                Err(create_error(
                    "creation_failed",
                    &format!("Failed to create note: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn get_notes_from_notebook(notebook_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, _claims| async move {
        match get_notebook_notes(&notebook_id).await {
            Ok(notes) => {
                Ok(HttpResponse::Ok().json(json!({
                    "notes": notes,
                    "count": notes.len()
                })))
            }
            Err(err) => {
                Err(create_error(
                    "fetch_failed",
                    &format!("Failed to fetch notes: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn create_note_standalone(note: web::Json<Note>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, claims| async move {
        // Validate input
        if let Err(validation_error) = validate_note(&note) {
            return Err(create_error("validation_error", &validation_error, "VALIDATION"));
        }
        
        let note_uuid = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        
        let notebook_uuid = match note.notebook_uuid.as_ref() {
            Some(uuid) => uuid,
            None => {
                return Err(create_error(
                    "missing_notebook_uuid",
                    "Notebook UUID is required",
                    "VALIDATION"
                ));
            }
        };
        
        let note_data = json!({
            "_id": note_uuid,
            "uuid": note_uuid,
            "title": note.title,
            "content": note.content,
            "tags": note.tags,
            "notebook": notebook_uuid,
            "user": claims.sub,
            "created_at": now,
            "updated_at": now,
            "version": 1,
        });
        
        match create_note(&claims.sub, notebook_uuid, &serde_json::to_value(&note_data).unwrap()).await {
            Ok(note_id) => {
                Ok(HttpResponse::Created().json(json!({
                    "message": "Note created successfully",
                    "uuid": note_id,
                    "version": 1
                })))
            }
            Err(err) => {
                Err(create_error(
                    "creation_failed",
                    &format!("Failed to create note: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn get_note(_note_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, _claims| async move {
        // TODO: implement get single note
        Err(create_error(
            "not_implemented",
            "Get single note not yet implemented",
            "NOT_IMPLEMENTED"
        ))
    }).await
}

pub async fn update_note(note_id: web::Path<String>, note: web::Json<Note>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, claims| async move {
        // Validate input
        if let Err(validation_error) = validate_note(&note) {
            return Err(create_error("validation_error", &validation_error, "VALIDATION"));
        }
        
        let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
        let now = chrono::Utc::now().to_rfc3339();
        
        let note_data = json!({
            "_id": note_id.as_str(),
            "uuid": note_id.as_str(),
            "type": "note",
            "email": claims.sub,
            "title": note.title,
            "content": note.content,
            "tags": note.tags,
            "is_pinned": note.is_pinned,
            "updated_at": now
        });

        let response = client
            .put(format!("{}/notes/{}", couchdb_url, note_id.as_str()))
            .basic_auth(couchdb_user, Some(couchdb_password))
            .json(&note_data)
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Note updated successfully",
                    "note_id": note_id.as_str()
                })))
            }
            Ok(res) => {
                let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                Err(create_error("update_failed", &error_message, "INTERNAL_ERROR"))
            }
            Err(err) => {
                Err(create_error("update_failed", &err.to_string(), "INTERNAL_ERROR"))
            }
        }
    }).await
}

pub async fn delete_note(note_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notes", |_peer_addr, _claims| async move {
        match delete_note_util(&note_id).await {
            Ok(_) => {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Note deleted successfully",
                    "note_id": note_id.as_str()
                })))
            }
            Err(e) => {
                Err(create_error(
                    "deletion_failed",
                    &format!("Failed to delete note: {}", e),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn get_notebook(_notebook_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notebooks", |_peer_addr, _claims| async move {
        // TODO: implement get single notebook
        Err(create_error(
            "not_implemented",
            "Get single notebook not yet implemented",
            "NOT_IMPLEMENTED"
        ))
    }).await
}

pub async fn update_notebook(notebook_id: web::Path<String>, notebook: web::Json<Notebook>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notebooks", |_peer_addr, claims| async move {
        // Validate input
        if let Err(validation_error) = validate_notebook(&notebook) {
            return Err(create_error("validation_error", &validation_error, "VALIDATION"));
        }
        
        let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
        let now = chrono::Utc::now().to_rfc3339();
        
        let notebook_data = json!({
            "_id": notebook_id.as_str(),
            "uuid": notebook_id.as_str(),
            "type": "notebook",
            "email": claims.sub,
            "name": notebook.name,
            "description": notebook.description,
            "color": notebook.color,
            "updated_at": now
        });

        let response = client
            .put(format!("{}/notebooks/{}", couchdb_url, notebook_id.as_str()))
            .basic_auth(couchdb_user, Some(couchdb_password))
            .json(&notebook_data)
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Notebook updated successfully",
                    "notebook_id": notebook_id.as_str()
                })))
            }
            Ok(res) => {
                let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                Err(create_error("update_failed", &error_message, "INTERNAL_ERROR"))
            }
            Err(err) => {
                Err(create_error("update_failed", &err.to_string(), "INTERNAL_ERROR"))
            }
        }
    }).await
}

pub async fn delete_notebook(notebook_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "notebooks", |_peer_addr, _claims| async move {
        let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
        
        let response = client
            .delete(format!("{}/notebooks/{}", couchdb_url, notebook_id.as_str()))
            .basic_auth(couchdb_user, Some(couchdb_password))
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Notebook deleted successfully",
                    "notebook_id": notebook_id.as_str()
                })))
            }
            Ok(res) => {
                let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                Err(create_error("deletion_failed", &error_message, "INTERNAL_ERROR"))
            }
            Err(err) => {
                Err(create_error("deletion_failed", &err.to_string(), "INTERNAL_ERROR"))
            }
        }
    }).await
}

// Rename admin handlers
pub async fn admin_logs(_req: HttpRequest) -> HttpResponse {
    // TODO: implement admin logs handler
    HttpResponse::Ok().json(json!({
        "message": "Admin logs endpoint - not yet implemented"
    }))
}

pub async fn admin_logfiles(_req: HttpRequest) -> HttpResponse {
    // TODO: implement admin logfiles handler
    HttpResponse::Ok().json(json!({
        "message": "Admin logfiles endpoint not yet implemented",
        "status": "not_implemented"
    }))
}

// Version handlers
pub async fn get_api_version() -> HttpResponse {
    let version_info = crate::version::get_api_version();
    HttpResponse::Ok().json(version_info)
}

pub async fn get_api_status() -> HttpResponse {
    let status_info = crate::version::get_api_status();
    HttpResponse::Ok().json(status_info)
}

// Sharing handlers
pub async fn share_note_handler(
    note_id: web::Path<String>,
    share_request: web::Json<crate::models::ShareRequest>,
    req: HttpRequest,
) -> HttpResponse {
    with_auth_and_rate_limit(req, "shares", |_peer_addr, claims| async move {
        // Validate input
        if share_request.note_id != note_id.as_str() {
            return Err(create_error(
                "validation_error",
                "Note ID mismatch",
                "VALIDATION"
            ));
        }
        
        match crate::utils::share_note(&note_id, &claims.sub, &share_request).await {
            Ok(share_id) => {
                let share_url = format!("{}/shared/{}", crate::version::API_VERSION, share_id);
                let response = crate::models::ShareResponse {
                    share_id,
                    share_url: Some(share_url),
                    message: "Note shared successfully".to_string(),
                };
                
                Ok(HttpResponse::Created().json(response))
            }
            Err(err) => {
                Err(create_error(
                    "share_failed",
                    &format!("Failed to share note: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn get_shared_notes_handler(req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "shares", |_peer_addr, claims| async move {
        match crate::utils::get_shared_notes(&claims.sub).await {
            Ok(shares) => {
                Ok(HttpResponse::Ok().json(json!({
                    "shares": shares,
                    "count": shares.len()
                })))
            }
            Err(err) => {
                Err(create_error(
                    "fetch_failed",
                    &format!("Failed to fetch shared notes: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn get_shared_note_handler(share_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "shares", |_peer_addr, _claims| async move {
        match crate::utils::get_shared_note_by_id(&share_id).await {
            Ok(share_data) => {
                Ok(HttpResponse::Ok().json(share_data))
            }
            Err(err) => {
                Err(create_error(
                    "fetch_failed",
                    &format!("Failed to fetch shared note: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}

pub async fn delete_share_handler(share_id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    with_auth_and_rate_limit(req, "shares", |_peer_addr, claims| async move {
        match crate::utils::delete_share(&share_id, &claims.sub).await {
            Ok(_) => {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Share deleted successfully",
                    "share_id": share_id.as_str()
                })))
            }
            Err(err) => {
                Err(create_error(
                    "deletion_failed",
                    &format!("Failed to delete share: {}", err),
                    "INTERNAL_ERROR"
                ))
            }
        }
    }).await
}