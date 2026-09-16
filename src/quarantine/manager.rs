use crate::db::{DbStore, QuarantineEntry};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const VAULT_XOR_KEY: &[u8] = b"ProjectGuardVaultSecureObfuscationKey2026";

pub struct QuarantineManager {
    vault_dir: PathBuf,
    db: Arc<Mutex<DbStore>>,
}

impl QuarantineManager {
    pub fn new(vault_dir: PathBuf, db: Arc<Mutex<DbStore>>) -> Result<Self> {
        if !vault_dir.exists() {
            fs::create_dir_all(&vault_dir)?;
        }
        Ok(Self { vault_dir, db })
    }

    /// Dosyayi zararsiz hale getirmek icin XOR maskelemesi uygular
    fn obfuscate_bytes(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let key_len = VAULT_XOR_KEY.len();
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ VAULT_XOR_KEY[i % key_len]);
        }
        result
    }

    /// Bir tehdit dosyasini karantinaya alir
    pub fn quarantine_file(
        &self,
        original_path: &Path,
        threat_name: &str,
        detected_engine: &str,
        sha256: &str,
    ) -> Result<QuarantineEntry> {
        if !original_path.exists() {
            bail!("Karantinaya alinacak dosya bulunamadi: {:?}", original_path);
        }

        let content = fs::read(original_path)
            .with_context(|| format!("Dosya okunamadi: {:?}", original_path))?;
        let file_size = content.len() as u64;

        let entry_id = format!(
            "QUAR_{}_{}",
            Utc::now().format("%Y%m%d_%H%M%S"),
            &sha256[..8.min(sha256.len())]
        );

        let quarantined_filename = format!("{}.quar", entry_id);
        let quarantined_path = self.vault_dir.join(&quarantined_filename);

        // Dosya baytlarini maskele ve kasaya yaz
        let masked = Self::obfuscate_bytes(&content);
        fs::write(&quarantined_path, masked)
            .with_context(|| format!("Karantina dosyasina yazilamadi: {:?}", quarantined_path))?;

        // Orijinal tehdit dosyasini diskten sil
        fs::remove_file(original_path)
            .with_context(|| format!("Orijinal zararli dosya silinemedi: {:?}", original_path))?;

        let entry = QuarantineEntry {
            id: entry_id,
            original_path: original_path.to_string_lossy().to_string(),
            quarantined_path: quarantined_path.to_string_lossy().to_string(),
            threat_name: threat_name.to_string(),
            detected_engine: detected_engine.to_string(),
            file_size,
            sha256: sha256.to_string(),
            date: Utc::now().to_rfc3339(),
        };

        {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_quarantine(&entry)?;
        }

        Ok(entry)
    }

    /// Karantinadaki bir dosyayi orijinal yerine geri yukler
    pub fn restore_file(&self, id: &str) -> Result<PathBuf> {
        let entry = {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard
                .get_quarantine_entry(id)?
                .ok_or_else(|| anyhow::anyhow!("Karantina kaydi bulunamadi: {}", id))?
        };

        let quar_path = PathBuf::from(&entry.quarantined_path);
        if !quar_path.exists() {
            bail!("Karantina kaset dosyasi bulunamadi: {:?}", quar_path);
        }

        let masked_content = fs::read(&quar_path)?;
        let original_content = Self::obfuscate_bytes(&masked_content);

        let orig_path = PathBuf::from(&entry.original_path);
        if let Some(parent) = orig_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&orig_path, original_content)?;
        let _ = fs::remove_file(&quar_path);

        {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.remove_quarantine_entry(id)?;
        }

        Ok(orig_path)
    }

    /// Karantinadaki dosyayi ve kaydini kalici olarak siler
    pub fn purge_file(&self, id: &str) -> Result<()> {
        let entry = {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard
                .get_quarantine_entry(id)?
                .ok_or_else(|| anyhow::anyhow!("Karantina kaydi bulunamadi: {}", id))?
        };

        let quar_path = PathBuf::from(&entry.quarantined_path);
        if quar_path.exists() {
            let _ = fs::remove_file(&quar_path);
        }

        let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        db_guard.remove_quarantine_entry(id)?;
        Ok(())
    }

    pub fn list_entries(&self) -> Result<Vec<QuarantineEntry>> {
        let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        db_guard.list_quarantine()
    }
}
