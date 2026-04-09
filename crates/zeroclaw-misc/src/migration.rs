use zeroclaw_config::schema::Config;
use zeroclaw_memory::{self, Memory, MemoryCategory};
use anyhow::{Context, Result, bail};
use directories::UserDirs;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct SourceEntry {
    key: String,
    content: String,
    category: MemoryCategory,
}

#[derive(Debug, Default)]
struct MigrationStats {
    from_sqlite: usize,
    from_markdown: usize,
    imported: usize,
    skipped_unchanged: usize,
    renamed_conflicts: usize,
}

