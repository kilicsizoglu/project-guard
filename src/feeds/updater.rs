use super::abuse_ch::AbuseChFeed;
use super::c2_intel::C2IntelFeed;
use super::clamav_feed::ClamAvFeed;
use super::sans_feed::SansFeed;
use super::spamhaus_feed::SpamhausFeed;
use super::urlhaus_feed::UrlhausFeed;
use super::usom_feed::UsomFeed;
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
    usom_feed: UsomFeed,
    sans_feed: SansFeed,
    spamhaus_feed: SpamhausFeed,
    urlhaus_feed: UrlhausFeed,
}

#[derive(Debug, Default)]
pub struct UpdateResult {
    pub malwarebazaar_added: usize,
    pub threatfox_added: usize,
    pub yara_rules_synced: usize,
    pub clamav_added: usize,
    pub c2_iocs_added: usize,
    pub usom_iocs_added: usize,
    pub sans_iocs_added: usize,
    pub spamhaus_iocs_added: usize,
    pub urlhaus_iocs_added: usize,
}

impl FeedUpdater {
    pub fn new(db: Arc<Mutex<DbStore>>, rules_dir: PathBuf) -> Self {
        Self {
            abuse_feed: AbuseChFeed::new(Arc::clone(&db)),
            c2_feed: C2IntelFeed::new(Arc::clone(&db)),
            yara_feed: YaraRuleFeed::new(rules_dir),
            clamav_feed: ClamAvFeed::new(Arc::clone(&db)),
            usom_feed: UsomFeed::new(Arc::clone(&db)),
            sans_feed: SansFeed::new(Arc::clone(&db)),
            spamhaus_feed: SpamhausFeed::new(Arc::clone(&db)),
            urlhaus_feed: UrlhausFeed::new(Arc::clone(&db)),
        }
    }

    pub fn update_all(&self) -> Result<UpdateResult> {
        let mut result = UpdateResult::default();

        println!("{}", "==> 1/9 MalwareBazaar Tehdit Akisi Senkronize Ediliyor...".cyan().bold());
        match self.abuse_feed.sync_malware_bazaar(1000) {
            Ok(count) => {
                println!("  [+] MalwareBazaar: {} yeni zararli hash eklendi.", count);
                result.malwarebazaar_added = count;
            }
            Err(e) => {
                eprintln!("  [-] MalwareBazaar senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 2/9 ThreatFox IOC Akisi Senkronize Ediliyor...".cyan().bold());
        match self.abuse_feed.sync_threatfox(1000) {
            Ok(count) => {
                println!("  [+] ThreatFox: {} yeni IOC/payload hash eklendi.", count);
                result.threatfox_added = count;
            }
            Err(e) => {
                eprintln!("  [-] ThreatFox senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 3/9 Topluluk YARA-X Kural Setleri Guncelleniyor...".cyan().bold());
        match self.yara_feed.sync_community_rules() {
            Ok(count) => {
                println!("  [+] YARA: {} kural dosyasi dogrulandi ve yuklendi.", count);
                result.yara_rules_synced = count;
            }
            Err(e) => {
                eprintln!("  [-] YARA kural senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 4/9 ClamAV Acik Kaynak Imza Havuzu Senkronize Ediliyor...".cyan().bold());
        match self.clamav_feed.seed_sample_clamav_signatures() {
            Ok(count) => {
                println!("  [+] ClamAV: {} imza eslemesi dogrulandi.", count);
                result.clamav_added = count;
            }
            Err(e) => {
                eprintln!("  [-] ClamAV imza havuz uyarisi: {}", e);
            }
        }

        println!("{}", "==> 5/9 Feodo Tracker Botnet C2 IP Blok Listesi Senkronize Ediliyor...".cyan().bold());
        match self.c2_feed.sync_feodo_tracker(500) {
            Ok(count) => {
                println!("  [+] Feodo C2 Intel: {} botnet C2 IP adresi veritabanina eklendi.", count);
                result.c2_iocs_added = count;
            }
            Err(e) => {
                eprintln!("  [-] Feodo C2 senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 6/9 USOM (SGB-TR) Yerli Siber Tehdit Istihbarati Senkronize Ediliyor...".cyan().bold());
        match self.usom_feed.sync_usom(500) {
            Ok(stats) => {
                println!("  [+] USOM Feed: {} yerli gosterge ({}) islendi ({} domain, {} IP, {} URL).",
                    stats.total_added, stats.source, stats.domain_count, stats.ip_count, stats.url_count);
                result.usom_iocs_added = stats.total_added;
            }
            Err(e) => {
                eprintln!("  [-] USOM senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 7/9 SANS ISC DShield Bal Küpü Saldırgan IP Akışı Senkronize Ediliyor...".cyan().bold());
        match self.sans_feed.sync_dshield(50) {
            Ok(stats) => {
                println!("  [+] SANS DShield: {} küresel saldırgan IP'si ({}) c2_iocs tablosuna eklendi.",
                    stats.total_inserted, stats.source);
                result.sans_iocs_added = stats.total_inserted;
            }
            Err(e) => {
                eprintln!("  [-] SANS DShield senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 8/9 The Spamhaus Project DROP Kurşun Geçirmez Alt Ağlar Senkronize Ediliyor...".cyan().bold());
        match self.spamhaus_feed.sync_drop(500) {
            Ok(stats) => {
                println!("  [+] Spamhaus DROP: {} kurşun geçirmez botnet ağı ({}) c2_iocs tablosuna eklendi.",
                    stats.total_inserted, stats.source);
                result.spamhaus_iocs_added = stats.total_inserted;
            }
            Err(e) => {
                eprintln!("  [-] Spamhaus DROP senkronizasyon uyarisi: {}", e);
            }
        }

        println!("{}", "==> 9/9 Abuse.ch URLhaus Zararlı İndirme Beşikleri Senkronize Ediliyor...".cyan().bold());
        match self.urlhaus_feed.sync_urlhaus(500) {
            Ok(stats) => {
                println!("  [+] URLhaus: {} zararlı indirme bağlantısı ({}) usom_iocs tablosuna eklendi.",
                    stats.total_inserted, stats.source);
                result.urlhaus_iocs_added = stats.total_inserted;
            }
            Err(e) => {
                eprintln!("  [-] URLhaus senkronizasyon uyarisi: {}", e);
            }
        }

        Ok(result)
    }
}


