use crate::db::DbStore;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct ClamAvFeed {
    db: Arc<Mutex<DbStore>>,
}

impl ClamAvFeed {
    pub fn new(db: Arc<Mutex<DbStore>>) -> Self {
        Self { db }
    }

    /// ClamAV .hdb (Hash Database) dosyalarini ayristirir ve veritabanina ekler
    /// Format: MD5:FILE_SIZE:VIRUS_NAME
    pub fn import_hdb_file(&self, path: &Path) -> Result<usize> {
        let file = File::open(path).with_context(|| format!("ClamAV HDB dosyasi acilamadi: {:?}", path))?;
        let reader = BufReader::new(file);

        let mut signatures: Vec<(String, String, String, String)> = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let md5 = parts[0].to_string();
                let virus_name = parts[2].to_string();
                if md5.len() == 32 {
                    signatures.push((md5, "md5".to_string(), virus_name, "ClamAV-CVD".to_string()));
                }
            }
        }

        let added = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_signatures_batch_owned(&signatures)?
        };

        Ok(added)
    }

    /// Ornek ClamAV bilinen yaygin virus imzalarini yerel olarak tohumlar
    pub fn seed_sample_clamav_signatures(&self) -> Result<usize> {
        let sample_sigs = [
            ("52d6c60f19d45ec45f0f3138cb715f5d", "md5", "Win.Trojan.Agent-142857", "ClamAV"),
            ("44d88612fea8a8f36de82e1278abb02f", "md5", "Eicar-Test-Signature", "ClamAV"),
            ("9b71d224bd62f3785d96d46ad3ea3d73", "md5", "Win.Ransomware.Locky-2", "ClamAV"),
            ("ec1f2d65377f070183041fb82bf4f9d4", "md5", "Win.Trojan.Zeus-102", "ClamAV"),
        ];

        let added = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_signatures_batch(&sample_sigs)?
        };

        Ok(added)
    }
}
