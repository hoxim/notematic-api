use serde::{Deserialize, Serialize};

/// User role (user/admin)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum UserRole {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "admin")]
    Admin,
}

///user model
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub password: String,
    pub role: Option<UserRole>, // None = user by default
}

///Login Request model
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

///Refresh Token Request model
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

///Token Response model
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

///Notebook model
#[derive(Debug, Serialize, Deserialize)]
pub struct Notebook {
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
}

///Note model
#[derive(Debug, Serialize, Deserialize)]
pub struct Note {
    pub title: String,
    pub content: String,
    pub tags: Option<Vec<String>>,
    pub is_pinned: Option<bool>,
}

///Notebook with ID (for responses)
#[derive(Debug, Serialize, Deserialize)]
pub struct NotebookWithId {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub note_count: u32,
}

///Note with ID (for responses)
#[derive(Debug, Serialize, Deserialize)]
pub struct NoteWithId {
    pub id: String,
    pub notebook_id: String,
    pub title: String,
    pub content: String,
    pub tags: Option<Vec<String>>,
    pub is_pinned: Option<bool>,
    pub created_at: String,
    pub updated_at: String,
}