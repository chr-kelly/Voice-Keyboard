use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use uuid::Uuid;
use crate::{err, fail, Result, protocol::{Ack, RETENTION_MS}};

pub struct Journal { db: Connection, key: zeroize::Zeroizing<Vec<u8>> }
impl Journal {
    pub fn open(path: &str, key: &[u8], now: u64) -> Result<Self> {
        if path != ":memory:" {
            let p = std::path::Path::new(path);
            let dir = p.parent().ok_or_else(|| err("invalid_journal_path"))?;
            std::fs::create_dir_all(dir).map_err(|_| err("storage_error"))?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|_| err("storage_error"))?;
            }
        }
        let db = Connection::open(path).map_err(|_| err("storage_error"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, peer TEXT NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS chunks(session TEXT NOT NULL, seq INTEGER NOT NULL, digest BLOB NOT NULL, status TEXT NOT NULL,
            PRIMARY KEY(session,seq));
            UPDATE chunks SET status='unknown' WHERE status='received';").map_err(|_| err("storage_error"))?;
        // Expire bodies' keyed digests, but retain session tombstones to reject old replays.
        db.execute("DELETE FROM chunks WHERE session IN (SELECT id FROM sessions WHERE expires < ?1)", [now]).map_err(|_| err("storage_error"))?;
        #[cfg(unix)] if path != ":memory:" {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| err("storage_error"))?;
        }
        Ok(Self { db, key: zeroize::Zeroizing::new(key.to_vec()) })
    }
    pub fn session(&self, id: Uuid, peer: &str, now: u64) -> Result<()> {
        let count: i64 = self.db.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0)).map_err(|_| err("storage_error"))?;
        if count >= 100_000 { return fail("journal_capacity"); }
        self.db.execute("INSERT INTO sessions VALUES(?1,?2,?3)", params![id.to_string(), peer, now + RETENTION_MS])
            .map_err(|_| err("session_replay"))?;
        Ok(())
    }
    pub fn authorize(&self, id: Uuid, peer: &str, now: u64) -> Result<()> {
        let expires: Option<u64> = self.db.query_row("SELECT expires FROM sessions WHERE id=?1 AND peer=?2", params![id.to_string(), peer], |r| r.get(0))
            .optional().map_err(|_| err("storage_error"))?;
        if expires.is_none_or(|t| now > t) { return fail("expired_session"); }
        Ok(())
    }
    fn digest(&self, text: &str) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"voice-keyboard/chunk/v1\0"); mac.update(text.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
    // Persist BEFORE exposing an injection action to the platform.
    pub fn register(&self, id: Uuid, seq: u64, text: &str) -> Result<Option<Ack>> {
        let digest = self.digest(text);
        let old: Option<(Vec<u8>, String)> = self.db.query_row("SELECT digest,status FROM chunks WHERE session=?1 AND seq=?2", params![id.to_string(), seq], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional().map_err(|_| err("storage_error"))?;
        if let Some((previous, status)) = old {
            if previous != digest { return fail("chunk_content_conflict"); }
            return Ok(Some(Ack::parse(&status)));
        }
        self.db.execute("INSERT INTO chunks VALUES(?1,?2,?3,'received')", params![id.to_string(), seq, digest]).map_err(|_| err("storage_error"))?;
        Ok(None)
    }
    pub fn record(&self, id: Uuid, seq: u64, status: Ack) -> Result<()> {
        let changed = self.db.execute("UPDATE chunks SET status=?3 WHERE session=?1 AND seq=?2", params![id.to_string(), seq, status.as_str()]).map_err(|_| err("storage_error"))?;
        if changed != 1 { return fail("unknown_chunk"); }
        Ok(())
    }
    pub fn query(&self, id: Uuid, seq: u64) -> Result<Ack> {
        let status: Option<String> = self.db.query_row("SELECT status FROM chunks WHERE session=?1 AND seq=?2", params![id.to_string(), seq], |r| r.get(0))
            .optional().map_err(|_| err("storage_error"))?;
        // Absence is not proof of non-injection after a restart or retention expiry.
        Ok(status.map(|s| Ack::parse(&s)).unwrap_or(Ack::Unknown))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn duplicate_and_conflicting_content() {
        let j = Journal::open(":memory:", b"test", 0).unwrap(); let id = Uuid::new_v4();
        j.session(id, "peer", 0).unwrap();
        assert_eq!(j.register(id, 1, "中文").unwrap(), None);
        j.record(id, 1, Ack::Applied).unwrap();
        assert_eq!(j.register(id, 1, "中文").unwrap(), Some(Ack::Applied));
        assert!(j.register(id, 1, "different").is_err());
        assert!(j.session(id, "peer", 0).is_err());
    }
    #[test] fn crash_window_recovers_unknown_without_plaintext() {
        let dir = tempfile::tempdir().unwrap(); let p = dir.path().join("ledger.db"); let p = p.to_str().unwrap();
        let id = Uuid::new_v4();
        { let j = Journal::open(p, b"key", 0).unwrap(); j.session(id, "peer", 0).unwrap(); j.register(id, 1, "SECRET_DICTATION_NEVER_PERSIST").unwrap(); }
        let j = Journal::open(p, b"key", 1).unwrap();
        assert_eq!(j.query(id, 1).unwrap(), Ack::Unknown);
        assert!(!String::from_utf8_lossy(&std::fs::read(p).unwrap()).contains("SECRET_DICTATION_NEVER_PERSIST"));
    }
    #[test] fn expiry_and_unknown_query_are_fail_closed() {
        let j = Journal::open(":memory:", b"key", 0).unwrap(); let id = Uuid::new_v4(); j.session(id, "peer", 0).unwrap();
        assert!(j.authorize(id, "attacker", 0).is_err());
        assert!(j.authorize(id, "peer", RETENTION_MS + 1).is_err());
        assert_eq!(j.query(id, 99).unwrap(), Ack::Unknown);
    }
}
