//! Persistent cursor storage using SQLite.

use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use crate::error::Result;

/// Cursor for incremental SCIM sync (tracks last modified timestamp).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncCursor {
    /// Last successful sync timestamp
    pub last_sync: Option<DateTime<Utc>>,
    /// Last seen resource version (ETag)
    pub last_etag: Option<String>,
    /// Total resources processed in last sync
    pub last_count: usize,
}

impl SyncCursor {
    pub fn new() -> Self {
        Self {
            last_sync: None,
            last_etag: None,
            last_count: 0,
        }
    }

/// Update cursor after successful sync.
    pub fn update(&mut self, timestamp: DateTime<Utc>, count: usize, etag: Option<String>) {
        self.last_sync = Some(timestamp);
        self.last_count = count;
        self.last_etag = etag;
    }
}

impl Default for SyncCursor {
    fn default() -> Self {
        Self::new()
    }
}

/// Persistent cursor storage using SQLite.
/// Uses Arc<Mutex<Connection>> for thread-safe access.
pub struct SyncCursorStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SyncCursorStore {
    /// Create new cursor store (opens or creates database).
    pub fn new(data_dir: &std::path::Path) -> Result<Self> {
        let db_path = data_dir.join("provisioning_cursors.db");
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(crate::error::ProvisioningError::Cursor)?;
        
        // Create cursor table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sync_cursors (
                key TEXT PRIMARY KEY,
                last_sync TEXT,
                last_etag TEXT,
                last_count INTEGER,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            [],
        ).map_err(crate::error::ProvisioningError::Cursor)?;

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Get cursor for a sync key.
    pub fn get(&self, key: &str) -> Result<SyncCursor> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT last_sync, last_etag, last_count FROM sync_cursors WHERE key = ?"
        ).map_err(crate::error::ProvisioningError::Cursor)?;

        let cursor = stmt.query_row([key], |row| {
            Ok(SyncCursor {
                last_sync: row.get::<_, Option<String>>(0)?
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                last_etag: row.get(1)?,
                last_count: row.get(2)?,
            })
        }).map_err(crate::error::ProvisioningError::Cursor);

        Ok(cursor.unwrap_or_else(|_| SyncCursor::new()))
    }

    /// Set cursor for a sync key.
    pub fn set(&self, key: &str, cursor: &SyncCursor) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let last_sync = cursor.last_sync.map(|dt| dt.to_rfc3339());
        
conn.execute(
            "INSERT OR REPLACE INTO sync_cursors (key, last_sync, last_etag, last_count, updated_at) 
             VALUES (?, ?, ?, ?, datetime('now'))",
            [
                key, 
                &last_sync.unwrap_or_default(), 
                &cursor.last_etag.clone().unwrap_or_default(), 
                &cursor.last_count.to_string()
            ],
        ).map_err(crate::error::ProvisioningError::Cursor)?;

        Ok(())
    }
}