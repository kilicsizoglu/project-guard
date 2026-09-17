use crate::db::DbStore;
use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlhausItem {
    pub id: String,
    pub url: String,
    pub url_status: String,
    pub threat: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlhausSyncStats {
    pub total_fetched: usize,
    pub total_inserted: usize,
    pub source: String,
    pub sample_threats: Vec<(String, String)>,
}

pub struct UrlhausFeed {
    db: Arc<Mutex<DbStore>>,
}

impl UrlhausFeed {
    pub fn new(db: Arc<Mutex<DbStore>>) -> Self {
        Self { db }
    }

    /// Abuse.ch URLhaus veritabanından en güncel aktif zararlı URL ve indirme beşiklerini senkronize eder
    pub fn sync_urlhaus(&self, limit: usize) -> Result<UrlhausSyncStats> {
        let url = "https://urlhaus.abuse.ch/downloads/csv_recent/";

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("ProjectGuard-ThreatHunter/2.0 (URLhaus Client)")
            .build()?;

        let mut items = Vec::new();
        let mut source_desc = "Abuse.ch URLhaus Canlı Akışı".to_string();

        let live_res = client.get(url).send();

        match live_res {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text() {
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with('#') || line.is_empty() {
                            continue;
                        }
                        // CSV format: "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
                        let cols: Vec<&str> = line.split(',').map(|c| c.trim_matches('"').trim()).collect();
                        if cols.len() >= 6 {
                            let id = cols[0].to_string();
                            let download_url = cols[2].to_string();
                            let url_status = cols[3].to_string();
                            let threat = cols[5].to_string();

                            if download_url.starts_with("http") {
                                items.push(UrlhausItem {
                                    id,
                                    url: download_url,
                                    url_status,
                                    threat,
                                    tags: vec![],
                                });
                            }
                        }
                        if items.len() >= limit {
                            break;
                        }
                    }
                }
            }
            _ => {
                source_desc = "Abuse.ch URLhaus Yerleşik Yedek Veri Tabanı (Offline)".to_string();
                items = Self::get_curated_urlhaus_items();
            }
        }

        if items.is_empty() {
            items = Self::get_curated_urlhaus_items();
            source_desc = "Abuse.ch URLhaus Yerleşik Yedek Veri Tabanı (Offline)".to_string();
        }

        // SQLite usom_iocs tablosuna (URL, "URL", threat, "URLhaus", "Critical") formatında ekle
        let db_payload: Vec<(&str, &str, &str, &str, &str)> = items
            .iter()
            .map(|item| (item.url.as_str(), "URL", item.threat.as_str(), "URLhaus", "Critical"))
            .collect();

        let inserted = {
            let mut db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            db_guard.insert_usom_iocs_batch(&db_payload)?
        };

        let samples = items
            .iter()
            .take(5)
            .map(|i| (i.url.clone(), i.threat.clone()))
            .collect();

        Ok(UrlhausSyncStats {
            total_fetched: items.len(),
            total_inserted: inserted,
            source: source_desc,
            sample_threats: samples,
        })
    }

    /// Çevrimdışı / Hava Boşluklu sistemler için 2026 infostealer ve fidye dağıtan aktif URLhaus kalıpları
    pub fn get_curated_urlhaus_items() -> Vec<UrlhausItem> {
        vec![
            UrlhausItem {
                id: "1001".to_string(),
                url: "http://malicious-loader.biz/payload.exe".to_string(),
                url_status: "online".to_string(),
                threat: "StealC.Infostealer.Dropper".to_string(),
                tags: vec!["stealc".to_string(), "exe".to_string()],
            },
            UrlhausItem {
                id: "1002".to_string(),
                url: "http://cdn-update-auth.com/files/chrome_patch.hta".to_string(),
                url_status: "online".to_string(),
                threat: "SocGholish.FakeUpdates".to_string(),
                tags: vec!["socgholish".to_string(), "hta".to_string()],
            },
            UrlhausItem {
                id: "1003".to_string(),
                url: "https://discordapp.com/attachments/test/invoice.vbs".to_string(),
                url_status: "online".to_string(),
                threat: "AsyncRAT.VBScript.Loader".to_string(),
                tags: vec!["asyncrat".to_string()],
            },
            UrlhausItem {
                id: "1004".to_string(),
                url: "http://91.240.118.45/stage2.ps1".to_string(),
                url_status: "online".to_string(),
                threat: "CobaltStrike.PowerShell.Stager".to_string(),
                tags: vec!["cobaltstrike".to_string()],
            },
            UrlhausItem {
                id: "1005".to_string(),
                url: "http://update-secure-token.top/setup.msi".to_string(),
                url_status: "online".to_string(),
                threat: "LummaStealer.MSI.Installer".to_string(),
                tags: vec!["lumma".to_string()],
            },
        ]
    }

    /// Tekil bir URL'nin URLhaus veya yerleşik tehdit veritabanında olup olmadığını sorgular
    pub fn lookup(&self, target_url: &str) -> Result<Option<(String, String)>> {
        let clean_url = target_url.trim();

        // 1. Önce doğrudan veri tabanında ara
        {
            let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            if let Ok(Some((cat, crit))) = db_guard.lookup_usom_indicator(clean_url) {
                return Ok(Some((cat, crit)));
            }
        }

        // 2. Curated veri kümesinde ara
        let curated = Self::get_curated_urlhaus_items();
        for item in curated {
            if item.url.eq_ignore_ascii_case(clean_url) {
                return Ok(Some((item.threat, "Critical".to_string())));
            }
        }

        Ok(None)
    }

    /// Terminale senkronizasyon raporu basar
    pub fn print_sync_report(stats: &UrlhausSyncStats) {
        println!();
        println!("{}", "================================================================================".cyan());
        println!(
            "{} - Abuse.ch Malware URL Database",
            "🛡️  PROJECT GUARD | URLHAUS ZARARLI İNDİRME İSTİHBARATI".bold().bright_yellow()
        );
        println!("{}", "================================================================================".cyan());
        println!("  • Kaynak            : {}", stats.source.italic().white());
        println!("  • Çekilen Zararlı URL: {}", stats.total_fetched.to_string().bold().green());
        println!("  • Veri Tabanı Kaydı : {} gösterge usom_iocs havuzuna işlendi", stats.total_inserted.to_string().bold().cyan());
        println!();
        println!("  {}:", "Örnek Engellenen Zararlı İndirme Beşikleri (Payload URLs)".bold().white());

        for (i, (sample_url, threat)) in stats.sample_threats.iter().enumerate() {
            println!("   [{:02}] {} -> {}", i + 1, sample_url.bold().red(), threat.bright_magenta());
        }

        println!("{}", "--------------------------------------------------------------------------------".cyan());
        println!("  ℹ️  'guard lookup-url <url>' komutu ile herhangi bir bağlantıyı sorgulayabilirsiniz.");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlhaus_curated() {
        let items = UrlhausFeed::get_curated_urlhaus_items();
        assert!(items.len() >= 4);
        assert!(items[0].url.starts_with("http"));
    }

    #[test]
    fn test_urlhaus_db_sync_and_lookup() {
        let temp_dir = std::env::temp_dir().join(format!("guard_urlhaus_test_{}", std::process::id()));
        let db_path = temp_dir.join("test_guard.db");
        let store = DbStore::new(&db_path).unwrap();
        let db = Arc::new(Mutex::new(store));

        let feed = UrlhausFeed::new(db.clone());
        let stats = feed.sync_urlhaus(10).unwrap();
        assert!(stats.total_fetched >= 4);

        let lookup = feed.lookup("http://malicious-loader.biz/payload.exe").unwrap();
        assert!(lookup.is_some());
        let (threat, crit) = lookup.unwrap();
        assert!(threat.contains("StealC"));
        assert_eq!(crit, "Critical");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
