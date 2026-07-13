use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProvisioningError {
    #[error("SCIM client error: {0}")]
    ScimClient(#[from] ScimClientError),

    #[error("SCIM server error: status={status}, body={body}")]
    ScimServer { status: u16, body: String },

    #[error("Filter parse error: {0}")]
    FilterParse(String),

    #[error("Workspace resolution failed: {0}")]
    WorkspaceResolution(String),

    #[error("Sync error: {0}")]
    Sync(String),

    #[error("Cursor persistence error: {0}")]
    Cursor(#[from] rusqlite::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Downstream auth failed: {0}")]
    DownstreamAuth(String),

    #[error("Conflict resolution failed: {0}")]
    ConflictResolution(String),

    #[error("Middleware error: {0}")]
    Middleware(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Tenant not found: {0}")]
    TenantNotFound(String),

    #[error("Workspace not found: {0}")]
    WorkspaceNotFound(String),

    #[error("Principal not found: {0}")]
    PrincipalNotFound(String),
}

#[derive(Debug, Error)]
pub enum ScimClientError {
    #[error("Invalid SCIM response: {0}")]
    InvalidResponse(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Pagination error: {0}")]
    Pagination(String),
}

pub type Result<T> = std::result::Result<T, ProvisioningError>;