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

    /// ThreatFox en son IOC (Indicator of Compromise) akisindan payload hashlerini ve C2 IP:Port adreslerini ceker
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
        self.process_threatfox_data(&text, limit)
    }

    /// ThreatFox CSV metnini ayrıştırarak hem dosya hash imzalarını hem de C2 IP:Port göstergelerini yerel veritabanına kaydeder
    pub fn process_threatfox_data(&self, text: &str, limit: usize) -> Result<usize> {
        let mut signatures = Vec::new();
        let mut c2_iocs = Vec::new();

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
                } else if ioc_type == "ip:port" {
                    if let Some((ip, port_str)) = ioc_value.split_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            c2_iocs.push((ip, port, malware_name, "Active", "ThreatFox"));
                        }
                    }
                }
            }

            if signatures.len() + c2_iocs.len() >= limit {
                break;
            }
        }

        let (added_sig, added_c2) = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            let sig_count = if !signatures.is_empty() {
                db_guard.insert_signatures_batch(&signatures)?
            } else {
                0
            };
            let c2_count = if !c2_iocs.is_empty() {
                db_guard.insert_c2_iocs_batch(&c2_iocs)?
            } else {
                0
            };
            (sig_count, c2_count)
        };

        println!(
            "ThreatFox senkronizasyonu tamamlandi: {} yeni imza, {} aktif C2 gostergesi kaydedildi.",
            added_sig, added_c2
        );

        Ok(added_sig + added_c2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_threatfox_data_dual_iocs() {
        let dir = std::env::temp_dir().join("guard_threatfox_test");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test_threatfox.db");
        let _ = std::fs::remove_file(&db_path);
        let db = Arc::new(Mutex::new(DbStore::new(&db_path).unwrap()));
        let feed = AbuseChFeed::new(db.clone());

        let sample_csv = r#"
# ThreatFox Recent Export
"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","confidence_level","tags"
"2026-09-17 10:00:00","1001","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","sha256_hash","payload","win.stealc","StealC","StealC Infostealer","100","stealer,infostealer"
"2026-09-17 10:05:00","1002","198.51.100.45:8080","ip:port","botnet_cc","win.asyncrat","AsyncRAT","AsyncRAT C2","90","rat,c2"
"#;

        let total_added = feed.process_threatfox_data(sample_csv, 100).unwrap();
        assert_eq!(total_added, 2);

        // Doğrula: Veritabanında imza ve C2 bulunuyor mu
        let db_guard = db.lock().unwrap();
        let sig = db_guard.find_signature("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert!(sig.is_some());
        let (threat, source) = sig.unwrap();
        assert_eq!(threat, "StealC Infostealer");
        assert_eq!(source, "ThreatFox");

        let c2 = db_guard.lookup_c2_ip("198.51.100.45").unwrap();
        assert!(c2.is_some());
        let (malware, status) = c2.unwrap();
        assert_eq!(malware, "AsyncRAT C2");
        assert_eq!(status, "Active");
    }
}
