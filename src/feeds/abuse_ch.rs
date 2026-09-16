use crate::db::DbStore;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct AbuseChFeed {
    db: Arc<Mutex<DbStore>>,
}

impl AbuseChFeed {
    pub fn new(db: Arc<Mutex<DbStore>>) -> Self {
        Self { db }
    }

    /// MalwareBazaar en son eklenen zararli yazilim CSV akisini ceker ve yerel veritabanina isler
    pub fn sync_malware_bazaar(&self, limit: usize) -> Result<usize> {
        let url = "https://bazaar.abuse.ch/export/csv/recent/";
        println!("MalwareBazaar acik istihbarat kaynagina baglaniliyor: {}", url);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("ProjectGuard-OpenAV/1.0")
            .build()?;

        let response = client
            .get(url)
            .send()
            .with_context(|| "MalwareBazaar sunucusuna erisilemedi")?;

        if !response.status().is_success() {
            anyhow::bail!("MalwareBazaar HTTP hatasi: {}", response.status());
        }

        let text = response.text()?;
        let mut signatures = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            // CSV Formati:
            // "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
            let cols: Vec<&str> = line.split(',').map(|c| c.trim_matches('"')).collect();
            if cols.len() >= 9 {
                let sha256 = cols[1];
                let md5 = cols[2];
                let signature = if cols[8] != "n/a" && !cols[8].is_empty() {
                    cols[8]
                } else if cols.len() > 9 && cols[9] != "n/a" && !cols[9].is_empty() {
                    cols[9]
                } else {
                    "Generic.Malware.Bazaar"
                };

                if sha256.len() == 64 {
                    signatures.push((sha256, "sha256", signature, "MalwareBazaar"));
                }
                if md5.len() == 32 {
                    signatures.push((md5, "md5", signature, "MalwareBazaar"));
                }
            }

            if signatures.len() >= limit {
                break;
            }
        }

        let added = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_signatures_batch(&signatures)?
        };

        Ok(added)
    }

    /// ThreatFox en son IOC (Indicator of Compromise) akisindan payload hashlerini ceker
    pub fn sync_threatfox(&self, limit: usize) -> Result<usize> {
        let url = "https://threatfox.abuse.ch/export/csv/recent/";
        println!("ThreatFox acik istihbarat kaynagina baglaniliyor: {}", url);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("ProjectGuard-OpenAV/1.0")
            .build()?;

        let response = client
            .get(url)
            .send()
            .with_context(|| "ThreatFox sunucusuna erisilemedi")?;

        if !response.status().is_success() {
            anyhow::bail!("ThreatFox HTTP hatasi: {}", response.status());
        }

        let text = response.text()?;
        let mut signatures = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            let cols: Vec<&str> = line.split(',').map(|c| c.trim_matches('"')).collect();
            if cols.len() >= 8 {
                let ioc_value = cols[2];
                let ioc_type = cols[3];
                let malware_name = if !cols[7].is_empty() {
                    cols[7]
                } else {
                    "ThreatFox.Payload"
                };

                if ioc_type == "sha256_hash" && ioc_value.len() == 64 {
                    signatures.push((ioc_value, "sha256", malware_name, "ThreatFox"));
                } else if ioc_type == "md5_hash" && ioc_value.len() == 32 {
                    signatures.push((ioc_value, "md5", malware_name, "ThreatFox"));
                }
            }

            if signatures.len() >= limit {
                break;
            }
        }

        let added = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_signatures_batch(&signatures)?
        };

        Ok(added)
    }
}
