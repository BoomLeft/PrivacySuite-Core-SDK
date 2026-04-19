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
//!
//! # Concurrency model
//!
//! [`EncryptedDb`] wraps a [`rusqlite::Connection`] which is `Send` but
//! **not** `Sync` — the underlying SQLite handle uses interior mutability
//! (`RefCell`) and cannot be shared across threads without external
//! serialisation. Callers that need a multi-reader/writer model should
//! wrap the handle in `Arc<Mutex<EncryptedDb>>` (or a connection pool).
//! Do not `unsafe impl Sync` on this type — SQLite will panic or corrupt
//! state under concurrent access.

use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::Connection;
use zeroize::Zeroize;

use crate::crypto::keys::VaultKey;

/// SECURITY: Upper bound on a single Automerge blob shipped to
/// `EncryptedDocument::load_encrypted`. See the crdt module for the same
/// constant; re-exported here for callers persisting blobs directly.
#[doc(hidden)]
pub const MAX_ENCRYPTED_BLOB_BYTES: usize = 16 * 1024 * 1024;

/// Errors returned by encrypted storage operations.
///
/// The variants are intentionally coarse-grained. In particular, the
/// `Database` variant carries a sanitised string (see
/// [`sanitise_sqlite_error`]) — not the raw `rusqlite` message — because
/// SQLite error strings often include table and column names that reveal
/// the vault's schema to anyone with access to the app's log sink. For
/// a privacy-focused vault, the schema itself is sensitive (it reveals
/// which data categories the user stores).
#[derive(Debug)]
pub enum StorageError {
    /// Database operation failed. The attached string is a sanitised
    /// short label (e.g. `"constraint"`, `"io"`, `"corrupt"`,
    /// `"not found"`, `"database"`) rather than the raw `rusqlite`
    /// error text. See [`sanitise_sqlite_error`].
    Database(String),
    /// An input exceeded the configured safety cap (e.g. blob-size
    /// bound on `load_encrypted`-style paths).
    InputTooLarge,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "storage error: {msg}"),
            Self::InputTooLarge => f.write_str("storage input too large"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(sanitise_sqlite_error(&err))
    }
}

/// Map a raw [`rusqlite::Error`] to a short, schema-free label.
///
/// SQLite error strings routinely embed table, column, and index names
/// (e.g. `"UNIQUE constraint failed: passwords.email"`). For a vault
/// whose schema is itself sensitive, we must not hand that string to
/// callers who may log it. The sanitised labels here are:
///
/// - `"constraint"` — any `SqliteFailure` whose extended code indicates
///   a constraint violation.
/// - `"io"` — disk / IO-class failures.
/// - `"corrupt"` — on-disk format corruption.
/// - `"not found"` — `QueryReturnedNoRows` and friends.
/// - `"type mismatch"` / `"invalid column"` — schema mismatches.
/// - `"database"` — fallback for everything else.
///
/// The raw error is **not** preserved in the returned string. If a
/// caller needs the original error for debugging, it must enable the
/// platform's debug-assertion build where the `Debug` impl of
/// `rusqlite::Error` is still accessible at the call site before
/// conversion.
fn sanitise_sqlite_error(err: &rusqlite::Error) -> String {
    use rusqlite::Error as E;
    use rusqlite::ErrorCode;

    match err {
        E::SqliteFailure(sqlite_err, _) => match sqlite_err.code {
            ErrorCode::ConstraintViolation => "constraint",
            ErrorCode::DatabaseCorrupt => "corrupt",
            ErrorCode::DiskFull
            | ErrorCode::CannotOpen
            | ErrorCode::FileLockingProtocolFailed
            | ErrorCode::ReadOnly
            | ErrorCode::SystemIoFailure => "io",
            ErrorCode::NotFound => "not found",
            _ => "database",
        }
        .to_owned(),
        E::QueryReturnedNoRows => "not found".to_owned(),
        E::IntegralValueOutOfRange(..)
        | E::InvalidColumnType(..)
        | E::FromSqlConversionFailure(..)
        | E::ToSqlConversionFailure(..) => "type mismatch".to_owned(),
        E::InvalidColumnIndex(_) | E::InvalidColumnName(_) => "invalid column".to_owned(),
        E::InvalidParameterName(_) | E::InvalidParameterCount(..) => {
            "invalid parameter".to_owned()
        }
        _ => "database".to_owned(),
    }
}

/// An encrypted `SQLCipher` database handle.
///
/// Wraps a [`rusqlite::Connection`] that has already been keyed with a
/// [`VaultKey`]. All data written through this handle is transparently
/// encrypted on disk.
///
/// # Concurrency
///
/// `EncryptedDb` is `Send` but **not** `Sync` — the underlying
/// `rusqlite::Connection` uses interior mutability and cannot be
/// shared across threads without external serialisation. To drive
/// multiple readers/writers, wrap the handle in
/// `Arc<Mutex<EncryptedDb>>` (or `tokio::sync::Mutex` in async
/// contexts) or adopt a connection-pool pattern. Do **not** paper over
/// the `!Sync` bound with `unsafe impl Sync` — SQLite will corrupt
/// internal state under concurrent access. See Audit 2 Finding #12
/// for the full rationale.
pub struct EncryptedDb {
    conn: Connection,
}

impl fmt::Debug for EncryptedDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedDb(***)")
    }
}

/// Build the full SQLCipher init PRAGMA sequence into a single buffer sized
/// exactly once.
///
/// `cipher_memory_security = ON` is issued before `PRAGMA key` per
/// SQLCipher requirements: memory security must be configured before the
/// key is parsed so SQLCipher's zeroization covers the keying buffers.
///
/// `cipher_compatibility = 4` pins the SQLCipher on-disk format to
/// major version 4. Without this pin, a future major-version bump in
/// the bundled SQLCipher (e.g. 5) would silently rewrite file format
/// semantics — either making v0.1-written databases unreadable, or
/// (worse) opening them with weaker compile-time defaults. The caller-
/// provided 256-bit key is passed via `PRAGMA key = "x'<hex>'"`, which
/// bypasses SQLCipher's own PBKDF2 KDF, so `kdf_iter` is irrelevant;
/// compatibility, page size, and HMAC algorithm defaults for SQLCipher
/// 4 are the correct fixed set.
///
/// A pre-sized buffer avoids Vec reallocation mid-build — a reallocation
/// would deallocate a partially-written buffer without zeroizing it,
/// leaking partial hex-key bytes onto the heap.
fn apply_key(conn: &Connection, key: &VaultKey) -> Result<(), StorageError> {
    const PREFIX: &str = "PRAGMA cipher_memory_security = ON; \
                          PRAGMA cipher_compatibility = 4; \
                          PRAGMA key = \"x'";
    const SUFFIX: &str = "'\";";
    let capacity = PREFIX.len() + key.as_bytes().len() * 2 + SUFFIX.len();

    let mut pragma = String::with_capacity(capacity);
    pragma.push_str(PREFIX);
    for b in key.as_bytes() {
        let _ = write!(pragma, "{b:02x}");
    }
    pragma.push_str(SUFFIX);
    debug_assert_eq!(pragma.len(), capacity);
    debug_assert_eq!(pragma.capacity(), capacity);

    let result = conn.execute_batch(&pragma);
    pragma.zeroize();
    result?;
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

    // --- Finding #8: StorageError::Database carries a sanitised label ---

    #[test]
    fn storage_error_does_not_leak_schema_on_constraint_violation() {
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        let _ = db
            .execute(
                "CREATE TABLE secrets (email TEXT PRIMARY KEY, password TEXT)",
                &[],
            )
            .expect("create");
        let _ = db
            .execute(
                "INSERT INTO secrets (email, password) VALUES ('a@b', 'x')",
                &[],
            )
            .expect("insert");

        // Duplicate insertion triggers a UNIQUE constraint violation.
        // The raw rusqlite message is "UNIQUE constraint failed: secrets.email".
        // Our sanitised variant must NOT carry the table/column name.
        let err = db
            .execute(
                "INSERT INTO secrets (email, password) VALUES ('a@b', 'y')",
                &[],
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("constraint"));
        assert!(!msg.contains("secrets"));
        assert!(!msg.contains("email"));
        assert!(!msg.contains("password"));
    }

    #[test]
    fn storage_error_not_found_is_sanitised() {
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        let _ = db
            .execute("CREATE TABLE t (x TEXT)", &[])
            .expect("create");
        let err: StorageError = db
            .query_row("SELECT x FROM t WHERE x = 'missing'", &[], |r| {
                r.get::<_, String>(0)
            })
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found"));
    }

    // --- Finding #9: cipher_compatibility = 4 is applied ---

    #[test]
    fn cipher_compatibility_pragma_is_issued_without_error() {
        // SQLCipher's `cipher_compatibility` is effectively a write-only
        // configuration knob — issuing `PRAGMA cipher_compatibility = 4`
        // succeeds silently during open, but a subsequent
        // `PRAGMA cipher_compatibility` SELECT returns no rows on
        // recent SQLCipher releases. We can't round-trip the value the
        // way we can with most pragmas.
        //
        // The next-best lock-in: confirm that open-with-key succeeds
        // through the full `apply_key` pragma sequence (which includes
        // `cipher_compatibility = 4`). A regression that dropped the
        // line would still open; a regression that introduced a
        // syntactically invalid pragma would be caught here because
        // `execute_batch` aborts on the first error.
        //
        // Deeper coverage would require writing a canary, closing, and
        // re-opening at a different compat level to confirm the on-disk
        // header pins the format — that's a bigger integration test and
        // lives in a separate PR alongside cross-compat migration work.
        let db = EncryptedDb::open_in_memory(&test_key()).expect("open");
        // Side-effect SELECT just to prove the connection is usable
        // post-PRAGMA sequence.
        let one: i64 = db
            .query_row("SELECT 1", &[], |row| row.get(0))
            .expect("query_row SELECT 1");
        assert_eq!(one, 1);
    }

    // --- Finding #14: error types are Send + Sync (compile-time assertion) ---

    #[test]
    fn storage_error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StorageError>();
    }
}
