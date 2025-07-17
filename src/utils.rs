use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::sync::Arc;
use log::{info, error, warn, debug};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claims {
    pub sub: String, // user ID
    pub exp: usize,  // expiration date
    pub token_type: String, // "access" or "refresh"
    pub role: String, // "user" or "admin"
}

/// Generates an access token with user role
pub fn generate_access_token_with_role(user_id: &str, role: &crate::models::UserRole) -> String {
    debug!("Generating access token for user: {} with role: {:?}", user_id, role);
    let hours: u64 = env::var("ACCESS_TOKEN_LIFETIME_IN_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1); // default 1 hour
    let exp = chrono::Utc::now().timestamp() as usize + (hours * 3600) as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        token_type: "access".to_string(),
        role: match role {
            crate::models::UserRole::Admin => "admin".to_string(),
            _ => "user".to_string(),
        },
    };
    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your_secret_key".as_ref()),
    ) {
        Ok(token) => {
            info!("Access token generated successfully for user: {}", user_id);
            token
        }
        Err(e) => {
            error!("Failed to generate access token for user {}: {}", user_id, e);
            panic!("JWT encoding failed");
        }
    }
}

/// Generates a refresh token with user role
pub fn generate_refresh_token_with_role(user_id: &str, role: &crate::models::UserRole) -> String {
    let hours: u64 = env::var("REFRESH_TOKEN_LIFETIME_IN_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(720); // default 30 days
    let exp = chrono::Utc::now().timestamp() as usize + (hours * 3600) as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        token_type: "refresh".to_string(),
        role: match role {
            crate::models::UserRole::Admin => "admin".to_string(),
            _ => "user".to_string(),
        },
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your_secret_key".as_ref()),
    )
    .unwrap()
}

pub fn generate_access_token(user_id: &str) -> String {
    debug!("Generating access token for user: {}", user_id);
    let hours: u64 = env::var("ACCESS_TOKEN_LIFETIME_IN_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1); // default 1 hour
    let exp = chrono::Utc::now().timestamp() as usize + (hours * 3600) as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        token_type: "access".to_string(),
        role: "user".to_string(), // Default to user role
    };
    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your_secret_key".as_ref()),
    ) {
        Ok(token) => {
            info!("Access token generated successfully for user: {}", user_id);
            token
        }
        Err(e) => {
            error!("Failed to generate access token for user {}: {}", user_id, e);
            panic!("JWT encoding failed");
        }
    }
}

pub fn generate_refresh_token(user_id: &str) -> String {
    let hours: u64 = env::var("REFRESH_TOKEN_LIFETIME_IN_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(720); // default 30 days
    let exp = chrono::Utc::now().timestamp() as usize + (hours * 3600) as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        token_type: "refresh".to_string(),
        role: "user".to_string(), // Default to user role
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your_secret_key".as_ref()),
    )
    .unwrap()
}

pub fn get_couchdb_client() -> (reqwest::Client, String, String, String) {
    let client = reqwest::Client::new();
    let couchdb_url = env::var("COUCHDB_URL").expect("COUCHDB_URL must be set");
    let couchdb_user = env::var("COUCHDB_USER").expect("COUCHDB_USER must be set");
    let couchdb_password = env::var("COUCHDB_PASSWORD").expect("COUCHDB_PASSWORD must be set");
    (client, couchdb_url, couchdb_user, couchdb_password)
}

pub fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    debug!("Verifying JWT token");
    match decode::<Claims>(
        token,
        &DecodingKey::from_secret("your_secret_key".as_ref()),
        &Validation::default(),
    ) {
        Ok(data) => {
            debug!("JWT token verified successfully for user: {} with role: {}", data.claims.sub, data.claims.role);
            Ok(data.claims)
        }
        Err(e) => {
            warn!("JWT token verification failed: {}", e);
            Err(e)
        }
    }
}

pub fn verify_refresh_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let claims = verify_jwt(token)?;
    if claims.token_type != "refresh" {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken
        ));
    }
    Ok(claims)
}

pub async fn find_user_in_database(email: &str) -> Option<Value> {
    let (_client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();

    let client = Client::new();
    let response = client
        .get(format!("{}/users/{}", couchdb_url, email))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => res.json().await.ok(),
        _ => None,
    }
}

pub fn validate_user_input(email: &str, password: &str) -> Result<(), &'static str> {
    if !email.contains('@') {
        return Err("Invalid email address");
    }
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long");
    }
    Ok(())
}

// Rate limiting storage
lazy_static::lazy_static! {
    static ref RATE_LIMIT_STORE: Arc<Mutex<HashMap<String, (u32, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub fn check_rate_limit(ip: &str, max_requests: u32, window_duration: Duration) -> bool {
    let now = Instant::now();
    let mut store = RATE_LIMIT_STORE.lock().unwrap();
    
    if let Some((count, window_start)) = store.get_mut(ip) {
        if now.duration_since(*window_start) > window_duration {
            // Reset window
            debug!("Rate limit window reset for IP: {}", ip);
            *count = 1;
            *window_start = now;
            true
        } else if *count >= max_requests {
            // Rate limit exceeded
            warn!("Rate limit exceeded for IP: {} ({} requests in window)", ip, count);
            false
        } else {
            *count += 1;
            debug!("Rate limit check passed for IP: {} ({} requests)", ip, count);
            true
        }
    } else {
        // First request from this IP
        debug!("First request from IP: {}", ip);
        store.insert(ip.to_string(), (1, now));
        true
    }
}

// Notebook and Note utilities
pub async fn create_notebook(email: &str, notebook: &serde_json::Value) -> Result<String, String> {
    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
    
    let notebook_id = format!("notebook_{}_{}", email, chrono::Utc::now().timestamp());
    let now = chrono::Utc::now().to_rfc3339();
    
    let notebook_data = serde_json::json!({
        "_id": notebook_id,
        "type": "notebook",
        "email": email,
        "name": notebook["name"],
        "description": notebook["description"],
        "color": notebook["color"],
        "created_at": now,
        "updated_at": now,
        "note_count": 0
    });
    
    let response = client
        .put(format!("{}/notebooks/{}", couchdb_url, notebook_id))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .json(&notebook_data)
        .send()
        .await;
    
    match response {
        Ok(res) if res.status().is_success() => Ok(notebook_id),
        Ok(res) => {
            let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(error_message)
        }
        Err(err) => Err(err.to_string()),
    }
}

pub async fn get_user_notebooks(email: &str) -> Result<Vec<serde_json::Value>, String> {
    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
    
    let response = client
        .get(format!("{}/notebooks/_design/notebooks/_view/by_email", couchdb_url))
        .query(&[("key", format!("\"{}\"", email))])
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;
    
    match response {
        Ok(res) if res.status().is_success() => {
            let data: serde_json::Value = res.json().await.unwrap_or_default();
            if let Some(rows) = data["rows"].as_array() {
                let notebooks: Vec<serde_json::Value> = rows
                    .iter()
                    .filter_map(|row| row["value"].as_object().cloned())
                    .map(|obj| serde_json::Value::Object(obj))
                    .collect();
                Ok(notebooks)
            } else {
                Ok(vec![])
            }
        }
        Ok(_) => Ok(vec![]),
        Err(err) => Err(err.to_string()),
    }
}

pub async fn create_note(email: &str, notebook_id: &str, note: &serde_json::Value) -> Result<String, String> {
    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
    
    let note_id = format!("note_{}_{}", notebook_id, chrono::Utc::now().timestamp());
    let now = chrono::Utc::now().to_rfc3339();
    
    let note_data = serde_json::json!({
        "_id": note_id,
        "type": "note",
        "email": email,
        "notebook_id": notebook_id,
        "title": note["title"],
        "content": note["content"],
        "tags": note["tags"],
        "is_pinned": note["is_pinned"],
        "created_at": now,
        "updated_at": now
    });
    
    let response = client
        .put(format!("{}/notes/{}", couchdb_url, note_id))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .json(&note_data)
        .send()
        .await;
    
    match response {
        Ok(res) if res.status().is_success() => {
            // Update notebook note count
            update_notebook_note_count(notebook_id).await;
            Ok(note_id)
        }
        Ok(res) => {
            let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(error_message)
        }
        Err(err) => Err(err.to_string()),
    }
}

pub async fn get_notebook_notes(notebook_id: &str) -> Result<Vec<serde_json::Value>, String> {
    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
    
    let response = client
        .get(format!("{}/notes/_design/notes/_view/by_notebook", couchdb_url))
        .query(&[("key", format!("\"{}\"", notebook_id))])
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;
    
    match response {
        Ok(res) if res.status().is_success() => {
            let data: serde_json::Value = res.json().await.unwrap_or_default();
            if let Some(rows) = data["rows"].as_array() {
                let notes: Vec<serde_json::Value> = rows
                    .iter()
                    .filter_map(|row| row["value"].as_object().cloned())
                    .map(|obj| serde_json::Value::Object(obj))
                    .collect();
                Ok(notes)
            } else {
                Ok(vec![])
            }
        }
        Ok(_) => Ok(vec![]),
        Err(err) => Err(err.to_string()),
    }
}

async fn update_notebook_note_count(notebook_id: &str) {
    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
    
    // Get current notebook
    if let Ok(notebook) = get_notebook_by_id(notebook_id).await {
        let current_count = notebook["note_count"].as_u64().unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();
        
        let updated_notebook = serde_json::json!({
            "_id": notebook_id,
            "_rev": notebook["_rev"],
            "type": "notebook",
            "email": notebook["email"],
            "name": notebook["name"],
            "description": notebook["description"],
            "color": notebook["color"],
            "created_at": notebook["created_at"],
            "updated_at": now,
            "note_count": current_count + 1
        });
        
        let _ = client
            .put(format!("{}/notebooks/{}", couchdb_url, notebook_id))
            .basic_auth(couchdb_user, Some(couchdb_password))
            .json(&updated_notebook)
            .send()
            .await;
    }
}

async fn get_notebook_by_id(notebook_id: &str) -> Result<serde_json::Value, String> {
    let (client, couchdb_url, couchdb_user, couchdb_password) = get_couchdb_client();
    
    let response = client
        .get(format!("{}/notebooks/{}", couchdb_url, notebook_id))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;
    
    match response {
        Ok(res) if res.status().is_success() => res.json().await.map_err(|e| e.to_string()),
        Ok(_) => Err("Notebook not found".to_string()),
        Err(err) => Err(err.to_string()),
    }
}