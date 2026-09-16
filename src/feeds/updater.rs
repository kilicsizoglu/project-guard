use super::abuse_ch::AbuseChFeed;
use super::c2_intel::C2IntelFeed;
use super::clamav_feed::ClamAvFeed;
use super::yara_rules::YaraRuleFeed;
use crate::db::DbStore;
use anyhow::Result;
use colored::Colorize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct FeedUpdater {
    abuse_feed: AbuseChFeed,
    c2_feed: C2IntelFeed,
    yara_feed: YaraRuleFeed,
    clamav_feed: ClamAvFeed,
}

#[derive(Debug, Default)]
pub struct UpdateResult {
    pub malwarebazaar_added: usize,
    pub threatfox_added: usize,
    pub yara_rules_synced: usize,
    pub clamav_added: usize,
    pub c2_iocs_added: usize,
}

impl FeedUpdater {
    pub fn new(db: Arc<Mutex<DbStore>>, rules_dir: PathBuf) -> Self {
        Self {
            abuse_feed: AbuseChFeed::new(Arc::clone(&db)),
            c2_feed: C2IntelFeed::new(Arc::clone(&db)),
            yara_feed: YaraRuleFeed::new(rules_dir),
            clamav_feed: ClamAvFeed::new(Arc::clone(&db)),
        }
    }

    pub fn update_all(&self) -> Result<UpdateResult> {
        let mut result = UpdateResult::default();

        println!("{}", "==> 1/5 MalwareBazaar Tehdit Akisi Senkronize Ediliyor...".cyan().bold());
        match self.abuse_feed.sync_malware_bazaar(1000) {
            Ok(count) => {
                println!("  [+] MalwareBazaar: {} yeni zararli hash eklendi.", count);
                result.malwarebazaar_added = count;
            }
            Err(e) => {
                eprintln!("  [-] MalwareBazaar senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 2/5 ThreatFox IOC Akisi Senkronize Ediliyor...".cyan().bold());
        match self.abuse_feed.sync_threatfox(1000) {
            Ok(count) => {
                println!("  [+] ThreatFox: {} yeni IOC/payload hash eklendi.", count);
                result.threatfox_added = count;
            }
            Err(e) => {
                eprintln!("  [-] ThreatFox senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 3/5 Topluluk YARA-X Kural Setleri Guncelleniyor...".cyan().bold());
        match self.yara_feed.sync_community_rules() {
            Ok(count) => {
                println!("  [+] YARA: {} kural dosyasi dogrulandi ve yuklendi.", count);
                result.yara_rules_synced = count;
            }
            Err(e) => {
                eprintln!("  [-] YARA kural senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 4/5 ClamAV Acik Kaynak Imza Havuzu Senkronize Ediliyor...".cyan().bold());
        match self.clamav_feed.seed_sample_clamav_signatures() {
            Ok(count) => {
                println!("  [+] ClamAV: {} imza eslemesi dogrulandi.", count);
                result.clamav_added = count;
            }
            Err(e) => {
                eprintln!("  [-] ClamAV imza havuz uyarisi: {}", e);
            }
        }

        println!("{}", "==> 5/5 Feodo Tracker Botnet C2 IP Blok Listesi Senkronize Ediliyor...".cyan().bold());
        match self.c2_feed.sync_feodo_tracker(500) {
            Ok(count) => {
                println!("  [+] Feodo C2 Intel: {} botnet C2 IP adresi veritabanina eklendi.", count);
                result.c2_iocs_added = count;
            }
            Err(e) => {
                eprintln!("  [-] Feodo C2 senkronizasyon uyarisi: {}", e);
            }
        }

        Ok(result)
    }
}

