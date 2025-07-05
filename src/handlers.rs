use actix_web::{web, HttpResponse};
use bcrypt::{hash, verify};
use reqwest::Client;
use serde_json::json;
use std::env;

use crate::models::{User, LoginRequest};
use crate::utils::{
    generate_jwt, 
    find_user_in_database,
    get_couchdb_client,
    validate_user_input
};

pub async fn register(user: web::Json<User>) -> HttpResponse {
    println!("Register endpoint hit");

    if let Err(err) = validate_user_input(&user.username, &user.password) {
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
            println!("User already exists: {}", user.username);
            return HttpResponse::Conflict().json(json!({"error": "User already exists"}));
        }
    }

    let hashed_password = hash(&user.password, 4).unwrap();
    println!("Password hashed successfully");

    let user_data = json!({
        "_id": user.username.clone(),
        "username": user.username.clone(),
        "password": hashed_password,
    });

    println!("Sending data to CouchDB: {:?}", user_data);

    let response = client
        .put(format!("{}/users/{}", couchdb_url, user.username))
        .basic_auth(couchdb_user, Some(couchdb_password))
        .json(&user_data)
        .send()
        .await;

    match response {
        Ok(res) if res.status().is_success() => {
            println!("User registered successfully");
            HttpResponse::Ok().json(json!({"message": "User registered successfully"}))
        }
        Ok(res) => {
            let error_message = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            println!("Error during registration: {}", error_message);
            HttpResponse::InternalServerError().json(json!({"error": error_message}))
        }
        Err(err) => {
            println!("Error connecting to CouchDB: {}", err);
            HttpResponse::InternalServerError().json(json!({"error": err.to_string()}))
        }
    }
}

pub async fn login(credentials: web::Json<LoginRequest>) -> HttpResponse {
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
                let token = generate_jwt(&credentials.username);
                HttpResponse::Ok().json(json!({"token": token}))
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

pub async fn protected_endpoint() -> HttpResponse {
    HttpResponse::Ok().json(json!({"message": "Access granted"}))
}