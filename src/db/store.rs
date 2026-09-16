use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::path::Path;

pub struct DbStore {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub threat_name: String,
    pub detected_engine: String,
    pub file_size: u64,
    pub sha256: String,
    pub date: String,
}

#[derive(Debug, Clone)]
pub struct SignatureStats {
    pub total_signatures: usize,
    pub malwarebazaar_count: usize,
    pub threatfox_count: usize,
    pub clamav_count: usize,
    pub custom_count: usize,
}

impl DbStore {
    pub fn new(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)?;
        let store = Self { conn };
        store.init_tables()?;
        store.seed_initial_signatures()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT PRIMARY KEY,
                hash_type TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                source TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS quarantine (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                quarantined_path TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                detected_engine TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                date TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_path TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                infected_files INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                scan_date TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS c2_iocs (
                ip TEXT PRIMARY KEY,
                port INTEGER NOT NULL,
                malware TEXT NOT NULL,
                c2_status TEXT NOT NULL,
                source TEXT NOT NULL,
                added_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    fn seed_initial_signatures(&self) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        // Standart EICAR Antivirus Test Dosyası Hash'leri (SHA256 ve MD5)
        self.add_signature_if_missing(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "sha256",
            "EICAR-Standard-AV-Test-File",
            "builtin",
            &now,
        )?;
        self.add_signature_if_missing(
            "44d88612fea8a8f36de82e1278abb02f",
            "md5",
            "EICAR-Standard-AV-Test-File",
            "builtin",
            &now,
        )?;
        // WannaCry Ransomware SHA256 bilinen hash örneği
        self.add_signature_if_missing(
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "sha256",
            "Ransom.WannaCry.WanaCrypt0r",
            "MalwareBazaar",
            &now,
        )?;
        // Emotet Dropper SHA256 bilinen hash örneği
        self.add_signature_if_missing(
            "34200632a67e6cda710928e46dd70c65ba992764de3916298dd9e944ef71fbcf",
            "sha256",
            "Trojan.Emotet.Dropper",
            "MalwareBazaar",
            &now,
        )?;
        // LockBit Ransomware SHA256 örneği
        self.add_signature_if_missing(
            "d9b897914619ee65b706c64188b2a59a7f3ec3dfb5cfeb3709b1f09c6691456d",
            "sha256",
            "Ransom.LockBit3",
            "MalwareBazaar",
            &now,
        )?;

        Ok(())
    }

    fn add_signature_if_missing(
        &self,
        hash: &str,
        hash_type: &str,
        threat_name: &str,
        source: &str,
        added_at: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO signatures (hash, hash_type, threat_name, source, added_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash.to_lowercase(), hash_type.to_lowercase(), threat_name, source, added_at],
        )?;
        Ok(())
    }

    pub fn insert_signature(
        &self,
        hash: &str,
        hash_type: &str,
        threat_name: &str,
        source: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO signatures (hash, hash_type, threat_name, source, added_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash.to_lowercase(), hash_type.to_lowercase(), threat_name, source, now],
        )?;
        Ok(())
    }

    pub fn insert_signatures_batch(
        &mut self,
        signatures: &[(&str, &str, &str, &str)],
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO signatures (hash, hash_type, threat_name, source, added_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (hash, hash_type, threat_name, source) in signatures {
                if stmt.execute(params![
                    hash.to_lowercase(),
                    hash_type.to_lowercase(),
                    threat_name,
                    source,
                    now
                ])? > 0
                {
                    count += 1;
                }
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn insert_signatures_batch_owned(
        &mut self,
        signatures: &[(String, String, String, String)],
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO signatures (hash, hash_type, threat_name, source, added_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for (hash, hash_type, threat_name, source) in signatures {
                if stmt.execute(params![
                    hash.to_lowercase(),
                    hash_type.to_lowercase(),
                    threat_name,
                    source,
                    now
                ])? > 0
                {
                    count += 1;
                }
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn find_signature(&self, hash: &str) -> Result<Option<(String, String)>> {
        let hash_lower = hash.to_lowercase();
        let mut stmt = self.conn.prepare(
            "SELECT threat_name, source FROM signatures WHERE hash = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![hash_lower])?;
        if let Some(row) = rows.next()? {
            let threat_name: String = row.get(0)?;
            let source: String = row.get(1)?;
            Ok(Some((threat_name, source)))
        } else {
            Ok(None)
        }
    }

    pub fn load_all_hashes_to_set(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT hash FROM signatures")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut set = HashSet::new();
        for r in rows {
            set.insert(r?);
        }
        Ok(set)
    }

    pub fn get_signature_stats(&self) -> Result<SignatureStats> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM signatures", [], |r| r.get(0))?;
        let mb: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM signatures WHERE source LIKE '%MalwareBazaar%'",
            [],
            |r| r.get(0),
        )?;
        let tf: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM signatures WHERE source LIKE '%ThreatFox%'",
            [],
            |r| r.get(0),
        )?;
        let clam: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM signatures WHERE source LIKE '%ClamAV%'",
            [],
            |r| r.get(0),
        )?;
        let custom = (total - (mb + tf + clam)).max(0) as usize;

        Ok(SignatureStats {
            total_signatures: total as usize,
            malwarebazaar_count: mb as usize,
            threatfox_count: tf as usize,
            clamav_count: clam as usize,
            custom_count: custom,
        })
    }

    // --- Quarantine Operations ---

    pub fn insert_quarantine(&self, entry: &QuarantineEntry) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO quarantine 
            (id, original_path, quarantined_path, threat_name, detected_engine, file_size, sha256, date)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                entry.id,
                entry.original_path,
                entry.quarantined_path,
                entry.threat_name,
                entry.detected_engine,
                entry.file_size as i64,
                entry.sha256,
                entry.date
            ],
        )?;
        Ok(())
    }

    pub fn list_quarantine(&self) -> Result<Vec<QuarantineEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_path, quarantined_path, threat_name, detected_engine, file_size, sha256, date FROM quarantine ORDER BY date DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            let size: i64 = row.get(5)?;
            Ok(QuarantineEntry {
                id: row.get(0)?,
                original_path: row.get(1)?,
                quarantined_path: row.get(2)?,
                threat_name: row.get(3)?,
                detected_engine: row.get(4)?,
                file_size: size as u64,
                sha256: row.get(6)?,
                date: row.get(7)?,
            })
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        Ok(entries)
    }

    pub fn get_quarantine_entry(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_path, quarantined_path, threat_name, detected_engine, file_size, sha256, date FROM quarantine WHERE id = ?1"
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let size: i64 = row.get(5)?;
            Ok(Some(QuarantineEntry {
                id: row.get(0)?,
                original_path: row.get(1)?,
                quarantined_path: row.get(2)?,
                threat_name: row.get(3)?,
                detected_engine: row.get(4)?,
                file_size: size as u64,
                sha256: row.get(6)?,
                date: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn remove_quarantine_entry(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM quarantine WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn log_scan(
        &self,
        target_path: &str,
        total_files: usize,
        infected_files: usize,
        duration_ms: u128,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO scan_history (target_path, total_files, infected_files, duration_ms, scan_date) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![target_path, total_files as i64, infected_files as i64, duration_ms as i64, now],
        )?;
        Ok(())
    }

    /// Feodo Tracker ve C2 tehdit istihbaratından gelen IP blok listesini toplu kaydeder
    pub fn insert_c2_iocs_batch(&mut self, iocs: &[(&str, u16, &str, &str, &str)]) -> Result<usize> {
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction()?;
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO c2_iocs (ip, port, malware, c2_status, source, added_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;

            for &(ip, port, malware, c2_status, source) in iocs {
                stmt.execute(params![ip, port as i64, malware, c2_status, source, now])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Bir IP adresinin bilinen bir C2 botnet sunucusu olup olmadığını sorgular
    pub fn lookup_c2_ip(&self, ip: &str) -> Result<Option<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT malware, c2_status FROM c2_iocs WHERE ip = ?1")?;
        let mut rows = stmt.query(params![ip])?;
        if let Some(row) = rows.next()? {
            let malware: String = row.get(0)?;
            let status: String = row.get(1)?;
            Ok(Some((malware, status)))
        } else {
            Ok(None)
        }
    }

    /// Toplam C2 IOC sayısını döndürür
    pub fn get_c2_iocs_count(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row("SELECT count(*) FROM c2_iocs", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Hızlı arama için belleğe yüklenecek tüm C2 IP -> Malware haritasını çeker
    pub fn get_all_c2_ips(&self) -> Result<std::collections::HashMap<String, String>> {
        let mut stmt = self.conn.prepare("SELECT ip, malware FROM c2_iocs")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut map = std::collections::HashMap::new();
        for r in rows {
            let (ip, mal): (String, String) = r?;
            map.insert(ip, mal);
        }
        Ok(map)
    }
}

