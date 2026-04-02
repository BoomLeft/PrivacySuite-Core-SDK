//! Encrypted on-device storage backed by `SQLCipher`.
//!
//! Every database created by this module is encrypted at rest using a
//! [`VaultKey`]-derived key. `SQLCipher`'s `cipher_memory_security` pragma
//! is enabled so that internal buffers are zeroized when no longer needed.
//!
//! # Security Properties
//!
//! - Database files are indistinguishable from random data without the key.
//! - The hex-encoded key string is zeroized immediately after PRAGMA key.
//! - `Debug` output never reveals connection details or key material.

use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::Connection;
use zeroize::Zeroize;

use crate::crypto::keys::VaultKey;
use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by encrypted storage operations.
#[derive(Debug)]
pub enum StorageError {
    /// Database operation failed.
    Database(String),
    /// Crypto operation failed.
    Crypto(CryptoError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "storage error: {msg}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(_) => None,
            Self::Crypto(e) => Some(e),
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<CryptoError> for StorageError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

// ---------------------------------------------------------------------------
// Encrypted database
// ---------------------------------------------------------------------------

/// An encrypted `SQLCipher` database handle.
///
/// Wraps a [`rusqlite::Connection`] that has already been keyed with a
/// [`VaultKey`]. All data written through this handle is transparently
/// encrypted on disk.
pub struct EncryptedDb {
    conn: Connection,
}

impl fmt::Debug for EncryptedDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedDb(***)")
    }
}

/// Apply the encryption key and hardened pragmas to a freshly opened
/// connection.
fn apply_key(conn: &Connection, key: &VaultKey) -> Result<(), StorageError> {
    // PEN-01/PEN-08: Build the PRAGMA statement in a single zeroizable buffer.
    // We avoid format!() which would create an intermediate String containing
    // the key that we cannot zeroize.
    let mut pragma = String::with_capacity(80);
    pragma.push_str("PRAGMA key = \"x'");
    for b in key.as_bytes() {
        let _ = write!(pragma, "{b:02x}");
    }
    pragma.push_str("'\";");

    conn.execute_batch(&pragma)?;

    // Zeroize the PRAGMA string — it contains the full hex key.
    pragma.zeroize();

    // Tell SQLCipher to zeroize its own internal memory allocations.
    conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;

    Ok(())
}

impl EncryptedDb {
    /// Opens (or creates) an encrypted database at `path`.
    ///
    /// The file is encrypted with `SQLCipher` using the provided [`VaultKey`].
    /// If the file already exists it must have been encrypted with the same
    /// key; otherwise subsequent operations will fail.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Database`] if the file cannot be opened or the
    /// key pragmas fail.
    pub fn open(path: &Path, key: &VaultKey) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        apply_key(&conn, key)?;
        Ok(Self { conn })
    }

    /// Opens an in-memory encrypted database.
    ///
    /// Useful for tests and ephemeral sessions. The database vanishes when
    /// the `EncryptedDb` is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Database`] if the in-memory connection cannot
    /// be created or the key pragmas fail.
    pub fn open_in_memory(key: &VaultKey) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        apply_key(&conn, key)?;
        Ok(Self { conn })
    }

    /// Executes a write statement (INSERT, UPDATE, DELETE, CREATE, etc.).
    ///
    /// Returns the number of rows modified.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Database`] if the statement fails.
    pub fn execute(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::types::ToSql],
    ) -> Result<usize, StorageError> {
        self.conn.execute(sql, params).map_err(Into::into)
    }

    /// Queries a single row and maps it with the provided closure.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Database`] if the query fails or returns no
    /// rows.
    pub fn query_row<T, F>(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::types::ToSql],
        f: F,
    ) -> Result<T, StorageError>
    where
        F: FnOnce(&rusqlite::Row<'_>) -> Result<T, rusqlite::Error>,
    {
        self.conn.query_row(sql, params, f).map_err(Into::into)
    }

    /// Queries multiple rows and collects mapped results into a `Vec`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Database`] if the query or any row mapping
    /// fails.
    pub fn query_map<T, F>(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::types::ToSql],
        f: F,
    ) -> Result<Vec<T>, StorageError>
    where
        F: FnMut(&rusqlite::Row<'_>) -> Result<T, rusqlite::Error>,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, f)?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{VaultKey, KEY_LEN};

    fn test_key() -> VaultKey {
        VaultKey::from_bytes([0xAA; KEY_LEN])
    }

    fn other_key() -> VaultKey {
        VaultKey::from_bytes([0xBB; KEY_LEN])
    }

    #[test]
    fn open_in_memory_create_insert_query() {
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        let _ = db
            .execute(
                "CREATE TABLE kv (key TEXT PRIMARY KEY, value BLOB)",
                &[],
            )
            .expect("create table");
        let _ = db
            .execute(
                "INSERT INTO kv (key, value) VALUES (?1, ?2)",
                &[&"hello" as &dyn rusqlite::types::ToSql, &"world"],
            )
            .expect("insert");

        let val: String = db
            .query_row("SELECT value FROM kv WHERE key = ?1", &[&"hello"], |row| {
                row.get(0)
            })
            .expect("query_row");
        assert_eq!(val, "world");
    }

    #[test]
    fn query_map_returns_multiple_rows() {
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        let _ = db
            .execute("CREATE TABLE nums (n INTEGER)", &[])
            .expect("create");
        for i in 1..=5_i64 {
            let _ = db
                .execute("INSERT INTO nums (n) VALUES (?1)", &[&i])
                .expect("insert");
        }

        let vals: Vec<i64> = db
            .query_map("SELECT n FROM nums ORDER BY n", &[], |row| row.get(0))
            .expect("query_map");
        assert_eq!(vals, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn wrong_key_fails() {
        // Create a DB with one key, reopen with another, expect failure on read.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");

        {
            let db = EncryptedDb::open(&path, &test_key()).expect("open with correct key");
            let _ = db
                .execute("CREATE TABLE t (x TEXT)", &[])
                .expect("create");
            let _ = db
                .execute("INSERT INTO t (x) VALUES ('secret')", &[])
                .expect("insert");
        }

        {
            let db = EncryptedDb::open(&path, &other_key()).expect("open with wrong key");
            let result: Result<String, _> =
                db.query_row("SELECT x FROM t", &[], |row| row.get(0));
            assert!(result.is_err(), "reading with wrong key should fail");
        }
    }

    #[test]
    fn execute_returns_modified_count() {
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        let _ = db
            .execute("CREATE TABLE t (x INTEGER)", &[])
            .expect("create");
        let _ = db
            .execute("INSERT INTO t (x) VALUES (1)", &[])
            .expect("insert 1");
        let _ = db
            .execute("INSERT INTO t (x) VALUES (2)", &[])
            .expect("insert 2");

        let modified = db
            .execute("UPDATE t SET x = x + 10", &[])
            .expect("update");
        assert_eq!(modified, 2);
    }

    #[test]
    fn debug_does_not_leak_connection() {
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        let debug = format!("{db:?}");
        assert_eq!(debug, "EncryptedDb(***)");
        assert!(!debug.contains("Connection"));
        assert!(!debug.contains("memory"));
    }
}
