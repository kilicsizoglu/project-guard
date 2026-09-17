use crate::db::DbStore;
use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SansTopIpRecord {
    #[serde(default)]
    pub rank: serde_json::Value,
    pub source: String,
    #[serde(default)]
    pub reports: serde_json::Value,
    #[serde(default)]
    pub targets: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SansTopIp {
    pub ip: String,
    pub reports: u64,
    pub targets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SansSyncStats {
    pub total_fetched: usize,
    pub total_inserted: usize,
    pub top_ips: Vec<SansTopIp>,
    pub source: String,
}

pub struct SansFeed {
    db: Arc<Mutex<DbStore>>,
}

impl SansFeed {
    pub fn new(db: Arc<Mutex<DbStore>>) -> Self {
        Self { db }
    }

    /// SANS ISC DShield API'sinden en çok saldırı gerçekleştiren global IP'leri çeker ve SQLite c2_iocs tablosuna ekler
    pub fn sync_dshield(&self, limit: usize) -> Result<SansSyncStats> {
        let url = format!("https://isc.sans.edu/api/topips/records/{}?json", limit.clamp(5, 100));

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("ProjectGuard-OpenAV/1.1 (Windows EDR Security Agent)")
            .build()?;

        let mut ip_records = Vec::new();
        let mut source_desc = "SANS ISC DShield Canlı API".to_string();

        let live_res = client.get(&url).send();

        match live_res {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(records) = resp.json::<Vec<SansTopIpRecord>>() {
                    for r in records {
                        let ip = r.source.trim().to_string();
                        if !ip.is_empty() && ip.contains('.') {
                            let reports = match r.reports {
                                serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
                                serde_json::Value::String(s) => s.parse().unwrap_or(0),
                                _ => 0,
                            };
                            let targets = match r.targets {
                                serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
                                serde_json::Value::String(s) => s.parse().unwrap_or(0),
                                _ => 0,
                            };
                            ip_records.push(SansTopIp { ip, reports, targets });
                        }
                    }
                }
            }
            _ => {
                // Yerleşik yedek SANS ISC en aktif saldırgan IP listesi (Offline dayanıklılık)
                source_desc = "SANS ISC DShield Yerleşik Yedek Veri (Offline)".to_string();
                ip_records = Self::get_curated_sans_iocs();
            }
        }

        if ip_records.is_empty() {
            ip_records = Self::get_curated_sans_iocs();
            source_desc = "SANS ISC DShield Yerleşik Yedek Veri (Offline)".to_string();
        }

        // SQLite c2_iocs tablosuna kaydet
        let db_payload: Vec<(&str, u16, &str, &str, &str)> = ip_records
            .iter()
            .map(|item| (item.ip.as_str(), 0u16, "SANS.DShield.Attacker", "active", "SANS_ISC_DShield"))
            .collect();

        let inserted = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_c2_iocs_batch(&db_payload)?
        };

        Ok(SansSyncStats {
            total_fetched: ip_records.len(),
            total_inserted: inserted,
            top_ips: ip_records,
            source: source_desc,
        })
    }

    /// Çevrimdışı ve yalıtılmış ağlar için SANS ISC DShield bal küplerince tespit edilen en aktif küresel saldırgan IP'leri
    pub fn get_curated_sans_iocs() -> Vec<SansTopIp> {
        vec![
            SansTopIp { ip: "13.94.254.200".to_string(), reports: 319739, targets: 1 },
            SansTopIp { ip: "194.224.249.214".to_string(), reports: 309508, targets: 1 },
            SansTopIp { ip: "52.157.207.201".to_string(), reports: 194780, targets: 1 },
            SansTopIp { ip: "89.248.163.109".to_string(), reports: 96279, targets: 150 },
            SansTopIp { ip: "143.244.186.35".to_string(), reports: 92007, targets: 8 },
            SansTopIp { ip: "18.116.198.191".to_string(), reports: 59907, targets: 1 },
            SansTopIp { ip: "152.89.198.163".to_string(), reports: 41378, targets: 478 },
            SansTopIp { ip: "152.89.198.103".to_string(), reports: 41346, targets: 479 },
            SansTopIp { ip: "152.89.198.187".to_string(), reports: 41332, targets: 477 },
            SansTopIp { ip: "185.122.204.71".to_string(), reports: 41221, targets: 479 },
        ]
    }

    /// Terminale SANS senkronizasyon raporunu basar
    pub fn print_sync_report(stats: &SansSyncStats) {
        println!();
        println!("{}", "================================================================================".cyan());
        println!(
            "{} - DShield Honeypot Intelligence",
            "🛡️  PROJECT GUARD | SANS INTERNET STORM CENTER".bold().bright_yellow()
        );
        println!("{}", "================================================================================".cyan());
        println!("  • Kaynak            : {}", stats.source.italic().white());
        println!("  • Çekilen Tehdit IP : {}", stats.total_fetched.to_string().bold().green());
        println!("  • Veri Tabanı Kaydı : {} gösterge c2_iocs tablosuna işlendi", stats.total_inserted.to_string().bold().cyan());
        println!();
        println!("  {} (Saldırı Kayıtları ve Hedef Sayısı):", "En Çok Saldıran Global Tehdit IP'leri".bold().white());

        for (i, top) in stats.top_ips.iter().take(10).enumerate() {
            println!(
                "   [{:02}] {:<18} | Rapor: {:<8} | Hedef: {:<4}",
                i + 1,
                top.ip.bold().red(),
                top.reports.to_string().yellow(),
                top.targets.to_string().cyan()
            );
        }
        println!("{}", "--------------------------------------------------------------------------------".cyan());
        println!("  ℹ️  Bu IP'ler 'guard scan-network' tarafından aktif soket denetimlerinde engellenecektir.");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_sans_curated_iocs() {
        let iocs = SansFeed::get_curated_sans_iocs();
        assert!(iocs.len() >= 5);
        assert!(iocs[0].ip.contains('.'));
        assert!(iocs[0].reports > 0);
    }

    #[test]
    fn test_sans_db_integration() {
        let temp_dir = std::env::temp_dir().join(format!("guard_sans_test_{}", std::process::id()));
        let db_path = temp_dir.join("test_guard.db");
        let store = DbStore::new(&db_path).unwrap();
        let db = Arc::new(Mutex::new(store));

        let feed = SansFeed::new(db.clone());
        let stats = feed.sync_dshield(10).unwrap();

        assert!(stats.total_fetched >= 5);
        assert!(stats.total_inserted >= 5);

        // c2_iocs içinde lookup yapalım
        let db_guard = db.lock().unwrap();
        let lookup = db_guard.lookup_c2_ip("13.94.254.200").unwrap();
        assert!(lookup.is_some());
        let (malware, status) = lookup.unwrap();
        assert_eq!(malware, "SANS.DShield.Attacker");
        assert_eq!(status, "active");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
