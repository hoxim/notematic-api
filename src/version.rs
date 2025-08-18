// Unused imports removed - will be needed for future features

/// API Version constants
pub const API_VERSION: &str = "1.0.3";
#[allow(dead_code)]
pub const API_BUILD_DATE: &str = env!("CARGO_PKG_VERSION");
pub const API_ENVIRONMENT: &str = if cfg!(debug_assertions) { "development" } else { "production" };

/// Get current API version information
pub fn get_api_version() -> crate::models::ApiVersion {
    let build_date = chrono::Utc::now().to_rfc3339();
    
    crate::models::ApiVersion {
        version: API_VERSION.to_string(),
        build_date,
        git_commit: get_git_commit_hash(),
        environment: API_ENVIRONMENT.to_string(),
        features: vec![
            "authentication".to_string(),
            "notebooks_crud".to_string(),
            "notes_crud".to_string(),
            "sync".to_string(),
            "rate_limiting".to_string(),
        ],
    }
}

/// Get git commit hash if available
fn get_git_commit_hash() -> Option<String> {
    // Try to get git commit hash from environment variable
    std::env::var("GIT_COMMIT_HASH").ok()
        .or_else(|| {
            // Fallback: try to get from git command
            std::process::Command::new("git")
                .args(&["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        String::from_utf8(output.stdout).ok()
                    } else {
                        None
                    }
                })
        })
}

/// Get API uptime
pub fn get_uptime() -> String {
    // This is a simple implementation - in production you might want to track actual start time
    "0s".to_string()
}

/// Check if client version is compatible
#[allow(dead_code)]
pub fn is_client_compatible(client_version: &str) -> bool {
    // Simple version check - can be enhanced with semantic versioning
    client_version == API_VERSION
}

/// Get API status information
pub fn get_api_status() -> crate::models::ApiStatus {
    crate::models::ApiStatus {
        status: "ok".to_string(),
        version: get_api_version(),
        uptime: get_uptime(),
        database_status: "connected".to_string(), // TODO: implement actual DB status check
    }
} 