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
    pub api_version: String,
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
    pub notebook_uuid: Option<String>,
}

///Notebook with ID (for responses)
#[derive(Debug, Serialize, Deserialize)]
pub struct NotebookWithUuid {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub note_count: u32,
}

///Note with ID (for responses)
#[derive(Debug, Serialize, Deserialize)]
pub struct NoteWithUuid {
    pub uuid: String,
    pub notebook_uuid: String,
    pub title: String,
    pub content: String,
    pub tags: Option<Vec<String>>,
    pub is_pinned: Option<bool>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncRequest {
    pub last_sync: Option<String>,  // ISO 8601 timestamp
    pub device_id: String,
    pub changes: Vec<Change>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Change {
    pub id: String,
    pub operation: Operation,
    pub timestamp: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Operation {
    CREATE,
    UPDATE,
    DELETE,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncResponse {
    pub sync_timestamp: String,
    pub conflicts: Vec<Conflict>,
    pub applied_changes: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Conflict {
    pub id: String,
    pub local_version: String,
    pub server_version: String,
    pub resolution: Option<String>, // "local", "server", "merge"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncStatus {
    pub last_sync: Option<String>,
    pub device_id: String,
    pub pending_changes: usize,
    pub conflicts: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub code: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiLog {
    pub timestamp: String,
    pub user: String,
    pub endpoint: String,
    pub method: String,
    pub status: u16,
    pub duration_ms: u64,
}

/// API Version information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiVersion {
    pub version: String,
    pub build_date: String,
    pub git_commit: Option<String>,
    pub environment: String,
    pub features: Vec<String>,
}

/// API Status response
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiStatus {
    pub status: String,
    pub version: ApiVersion,
    pub uptime: String,
    pub database_status: String,
}
/// Share permissions for notes
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharePermissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_share: bool,
    pub can_delete: bool,
}

/// Share type for notes
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ShareType {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "email")]
    Email,
}

/// Share request model
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareRequest {
    pub note_id: String,
    pub share_type: ShareType,
    pub permissions: SharePermissions,
    pub expires_at: Option<String>, // ISO 8601
    pub password: Option<String>, // for public links
}

/// Shared note model
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharedNote {
    pub share_id: String,
    pub note_id: String,
    pub owner_id: String,
    pub shared_by: String,
    pub share_type: ShareType,
    pub permissions: SharePermissions,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub access_count: u32,
    pub note_title: Option<String>,
    pub note_content: Option<String>,
}

/// Share response model
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareResponse {
    pub share_id: String,
    pub share_url: Option<String>,
    pub message: String,
}