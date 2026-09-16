use super::trait_engine::{FileHashes, ScanEngine, Severity, ThreatDetection};
use crate::db::DbStore;
use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

pub struct HashEngine {
    db: Arc<Mutex<DbStore>>,
    in_memory_hashes: Arc<RwLock<HashSet<String>>>,
}

impl HashEngine {
    pub fn new(db: Arc<Mutex<DbStore>>) -> Result<Self> {
        let set = {
            let db_guard = db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.load_all_hashes_to_set()?
        };
        Ok(Self {
            db,
            in_memory_hashes: Arc::new(RwLock::new(set)),
        })
    }

    pub fn reload_cache(&self) -> Result<()> {
        let set = {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.load_all_hashes_to_set()?
        };
        let mut cache_guard = self
            .in_memory_hashes
            .write()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        *cache_guard = set;
        Ok(())
    }
}

impl ScanEngine for HashEngine {
    fn name(&self) -> &'static str {
        "Hash-ThreatIntel-Engine"
    }

    fn description(&self) -> &'static str {
        "MalwareBazaar, ThreatFox ve yerel tehdit hash imza eslestirme motoru"
    }

    fn scan(
        &self,
        _path: &Path,
        _content: &[u8],
        hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>> {
        let sha256_lower = hashes.sha256.to_lowercase();
        let md5_lower = hashes.md5.to_lowercase();

        let hit = {
            let cache = self
                .in_memory_hashes
                .read()
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            cache.contains(&sha256_lower) || cache.contains(&md5_lower)
        };

        if hit {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            if let Some((threat, source)) = db_guard.find_signature(&sha256_lower)? {
                return Ok(Some(ThreatDetection {
                    threat_name: threat,
                    engine_name: self.name().to_string(),
                    severity: Severity::Critical,
                    details: format!("Tehdit Istihbarat Eslesmesi (Kaynak: {}) - SHA256: {}", source, sha256_lower),
                    rule_name: Some(format!("hash:{}", sha256_lower)),
                }));
            }

            if let Some((threat, source)) = db_guard.find_signature(&md5_lower)? {
                return Ok(Some(ThreatDetection {
                    threat_name: threat,
                    engine_name: self.name().to_string(),
                    severity: Severity::Critical,
                    details: format!("Tehdit Istihbarat Eslesmesi (Kaynak: {}) - MD5: {}", source, md5_lower),
                    rule_name: Some(format!("hash:{}", md5_lower)),
                }));
            }
        }

        Ok(None)
    }
}
