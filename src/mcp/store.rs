use super::{McpResult, Proposal, now};
use crate::{PublicKey, crypto};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    time::Duration,
};

fn sql_time() -> McpResult<i64> {
    Ok(i64::try_from(now()?)?)
}

pub(super) struct Store {
    db: Connection,
    _lock: File,
}

impl Store {
    pub fn open_workspace(directory: &Path, root: &Path, owner: &str) -> McpResult<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::open(directory, root, owner)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            fs::create_dir_all(directory)?;
            let canonical = directory.canonicalize()?;
            if canonical.starts_with(root) || root.starts_with(&canonical) {
                return Err("state and workspace must be separate non-nested paths".into());
            }
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(directory.join("service.lock"))?;
            let database = directory.join("state.sqlite3");
            if database.exists()
                && (!fs::symlink_metadata(&database)?.is_file()
                    || fs::symlink_metadata(&database)?.file_type().is_symlink())
            {
                return Err("workspace database must be a regular file".into());
            }
            let db = Connection::open(database)?;
            Self::initialize(db, lock, root, owner)
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = (directory, root, owner);
            Err("workspace service supports Windows and Linux".into())
        }
    }

    pub fn open(directory: &Path, root: &Path, owner: &str) -> McpResult<Self> {
        if !directory.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(directory)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(directory)?;
        }
        let canonical = directory.canonicalize()?;
        if canonical.starts_with(root) || root.starts_with(&canonical) {
            return Err("state and data directories must be separate, non-nested paths".into());
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(
                    "state directory must be a service-owned directory, not a symlink".into(),
                );
            }
            // Provision permissions explicitly; never silently fix an existing shared directory.
            if metadata.mode() & 0o077 != 0 {
                return Err("state directory requires mode 0700".into());
            }
            let _ = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join("service.lock"));
            let lock = File::from(rustix::fs::open(
                directory.join("service.lock"),
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?);
            if lock.metadata()?.nlink() != 1 {
                return Err("invalid state lock".into());
            }
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| "another instance is using this state directory")?;
            let path = directory.join("state.sqlite3");
            if !path.exists() {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?
                    .sync_all()?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err("database requires a service-owned private regular file".into());
            }
            let db = Connection::open(&path)?;
            Self::initialize(db, lock, root, owner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = owner;
            Err("durable service requires Linux".into())
        }
    }

    fn initialize(db: Connection, lock: File, root: &Path, owner: &str) -> McpResult<Self> {
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA max_page_count=16384;")?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 1 {
            return Err("database schema is newer than this binary".into());
        }
        db.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY, body TEXT NOT NULL, expires INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','executing','applied','uncertain','aborted')),
                receipt TEXT, updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, proposal_id TEXT NOT NULL, event TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS proposal_expiry ON proposals(expires);
            CREATE INDEX IF NOT EXISTS audit_time ON audit(timestamp);
            PRAGMA user_version=1; COMMIT;")?;
        let mut store = Self { db, _lock: lock };
        let identity = serde_json::to_string(&(root.to_str().ok_or("non-UTF8 data root")?, owner))?;
        let existing: Option<String> = store
            .db
            .query_row("SELECT value FROM metadata WHERE key='identity'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(existing) = existing {
            if existing != identity {
                return Err("database belongs to a different owner or data root".into());
            }
        } else {
            store
                .db
                .execute("INSERT INTO metadata VALUES ('identity',?1)", [&identity])?;
        }
        store.check_clock(now()?)?;
        let tx = store.db.transaction()?;
        tx.execute("INSERT INTO audit(timestamp,proposal_id,event) SELECT ?1,id,'recovery_required' FROM proposals WHERE status='executing'", [sql_time()?])?;
        tx.execute(
            "UPDATE proposals SET status='uncertain' WHERE status='executing'",
            [],
        )?;
        tx.commit()?;
        Ok(store)
    }

    pub fn check_clock(&mut self, time: u64) -> McpResult<()> {
        let previous: Option<String> = self
            .db
            .query_row("SELECT value FROM metadata WHERE key='clock'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if previous.is_some_and(|v| v.parse::<u64>().map_or(true, |t| t > time)) {
            return Err("server clock rollback detected".into());
        }
        self.db.execute("INSERT INTO metadata VALUES ('clock',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [time.to_string()])?;
        Ok(())
    }

    pub fn insert(&mut self, proposal: &Proposal) -> McpResult<()> {
        let time = sql_time()?;
        self.check_clock(u64::try_from(time)?)?;
        let tx = self.db.transaction()?;
        // Never garbage-collect unresolved writes. Other expired records retain 30 days of evidence.
        let cutoff = time.saturating_sub(30 * 86400);
        tx.execute(
            "DELETE FROM proposals WHERE expires < ?1 AND status NOT IN ('executing','uncertain')",
            [cutoff],
        )?;
        tx.execute("DELETE FROM audit WHERE timestamp < ?1", [cutoff])?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM proposals", [], |r| r.get(0))?;
        let recent: i64 = tx.query_row(
            "SELECT COUNT(*) FROM audit WHERE event='proposed' AND timestamp >= ?1",
            [time.saturating_sub(60)],
            |r| r.get(0),
        )?;
        if count >= 10000 || recent >= 60 {
            return Err("proposal capacity or per-minute quota exceeded".into());
        }
        tx.execute(
            "INSERT INTO proposals VALUES (?1,?2,?3,'pending',NULL,?4)",
            params![
                proposal.id,
                serde_json::to_string(proposal)?,
                i64::try_from(proposal.expires_at)?,
                time
            ],
        )?;
        tx.execute(
            "INSERT INTO audit(timestamp,proposal_id,event) VALUES (?1,?2,'proposed')",
            params![time, proposal.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> McpResult<(Proposal, String)> {
        let (body, status): (String, String) =
            self.db
                .query_row("SELECT body,status FROM proposals WHERE id=?1", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        if body.len() > 65536 {
            return Err("stored proposal is oversized".into());
        }
        let proposal: Proposal = serde_json::from_str(&body)?;
        if proposal.id != id {
            return Err("stored proposal identity mismatch".into());
        }
        Ok((proposal, status))
    }

    pub fn check_file_available(&self, path: &str) -> McpResult<()> {
        let count: i64 = self.db.query_row(
            "SELECT count(*) FROM proposals WHERE status IN ('executing','uncertain') AND json_extract(body,'$.path')=?1",
            [path], |r| r.get(0))?;
        if count != 0 {
            return Err("file has an unresolved execution; operator recovery is required".into());
        }
        Ok(())
    }

    pub fn reserve(&mut self, id: &str, receipt: &str) -> McpResult<()> {
        let time = sql_time()?;
        self.check_clock(u64::try_from(time)?)?;
        let tx = self.db.transaction()?;
        if tx.execute("UPDATE proposals SET status='executing',receipt=?1,updated=?2 WHERE id=?3 AND status='pending' AND expires>?2", params![receipt,time,id])? != 1 {
            return Err("proposal is expired, completed or already executing".into());
        }
        tx.execute(
            "INSERT INTO audit(timestamp,proposal_id,event) VALUES (?1,?2,'execution_started')",
            params![time, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish(&mut self, id: &str, status: &str) -> McpResult<()> {
        if !["applied", "uncertain", "aborted"].contains(&status) {
            return Err("invalid terminal state".into());
        }
        let tx = self.db.transaction()?;
        if tx.execute("UPDATE proposals SET status=?1,updated=?2 WHERE id=?3 AND status IN ('executing','uncertain')", params![status,sql_time()?,id])? != 1 { return Err("invalid execution state".into()); }
        tx.execute(
            "INSERT INTO audit(timestamp,proposal_id,event) VALUES (?1,?2,?3)",
            params![sql_time()?, id, status],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn approved(&self, id: &str, approver: &PublicKey) -> McpResult<Proposal> {
        let receipt: String =
            self.db
                .query_row("SELECT receipt FROM proposals WHERE id=?1", [id], |r| {
                    r.get(0)
                })?;
        let approved: Proposal =
            crypto::decode(&receipt, approver, super::APPROVAL_TYPE, "approver")?;
        if self.get(id)?.0 != approved {
            return Err("stored approval does not match proposal".into());
        }
        Ok(approved)
    }

    pub fn audit(&self) -> McpResult<serde_json::Value> {
        let mut stmt = self.db.prepare(
            "SELECT seq,timestamp,proposal_id,event FROM audit ORDER BY seq DESC LIMIT 1000",
        )?;
        let rows = stmt.query_map([], |r| Ok(serde_json::json!({"sequence":r.get::<_,i64>(0)?,"timestamp":r.get::<_,i64>(1)?,"proposal_id":r.get::<_,String>(2)?,"event":r.get::<_,String>(3)?})))?;
        Ok(serde_json::Value::Array(
            rows.collect::<Result<Vec<_>, _>>()?,
        ))
    }

    pub fn backup(&self, destination: &Path) -> McpResult<()> {
        if destination.exists() {
            return Err("backup target already exists".into());
        }
        super::create_file(destination, b"", true)?;
        self.db.backup(rusqlite::MAIN_DB, destination, None)?;
        File::open(destination)?.sync_all()?;
        Ok(())
    }
}
