//! Sync engine for SCIM provisioning.
//!
//! Handles full sync on startup and incremental sync on interval,
//! with persistent cursor for delta synchronization.

pub mod engine;
pub mod cursor;

pub use engine::{SyncEngine, SyncEvent, SyncStats};
pub use cursor::{SyncCursorStore, SyncCursor};