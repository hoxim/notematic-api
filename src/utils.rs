use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user ID
    pub exp: usize,  // expiration date
}

pub fn generate_jwt(user_id: &str) -> String {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: chrono::Utc::now().timestamp() as usize + 3600, // Token valid for 1 hour
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your_secret_key".as_ref()), // private key
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
    decode::<Claims>(
        token,
        &DecodingKey::from_secret("your_secret_key".as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
}

pub async fn find_user_in_database(username: &str) -> Option<Value> {
    let couchdb_url = env::var("COUCHDB_URL").unwrap();
    let couchdb_user = env::var("COUCHDB_USER").unwrap();
    let couchdb_password = env::var("COUCHDB_PASSWORD").unwrap();

    let client = Client::new();
    let response = client
        .get(format!("{}/users/{}", couchdb_url, username))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => res.json().await.ok(),
        _ => None,
    }
}

pub fn validate_user_input(username: &str, password: &str) -> Result<(), &'static str> {
    if username.len() < 3 || username.len() > 32 {
        return Err("Username must be between 3 and 32 characters");
    }
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long");
    }
    if !username.chars().all(|c| c.is_alphanumeric()) {
        return Err("Username must contain only alphanumeric characters");
    }
    Ok(())
}