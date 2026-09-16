use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::db::DbStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub indicator: String,
    pub ioc_type: String,
    pub threat_tag: Option<String>,
    pub is_confirmed_c2: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocReport {
    pub target_name: String,
    pub total_strings_extracted: usize,
    pub public_ips: Vec<String>,
    pub confirmed_c2_ips: Vec<IocMatch>,
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub crypto_wallets: Vec<IocMatch>,
    pub base64_payloads: Vec<String>,
    pub suspicious_keywords: Vec<String>,
}

pub struct IocExtractor;

impl IocExtractor {
    /// Ham baytlardan hem ASCII hem de UTF-16LE dizelerini ayıklar
    pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
        let mut strings = Vec::new();

        // 1. ASCII (7-bit printable) dizeler
        let mut current_ascii = Vec::new();
        for &b in data {
            if (32..=126).contains(&b) || b == b'\t' {
                current_ascii.push(b);
            } else {
                if current_ascii.len() >= min_len {
                    if let Ok(s) = std::str::from_utf8(&current_ascii) {
                        strings.push(s.to_string());
                    }
                }
                current_ascii.clear();
            }
        }
        if current_ascii.len() >= min_len {
            if let Ok(s) = std::str::from_utf8(&current_ascii) {
                strings.push(s.to_string());
            }
        }

        // 2. UTF-16LE dizeler (Windows PE ikililerinde çok yaygındır: harf + 0x00)
        let mut current_u16 = Vec::new();
        let mut i = 0;
        while i + 1 < data.len() {
            let lo = data[i];
            let hi = data[i + 1];
            if hi == 0 && ((32..=126).contains(&lo) || lo == b'\t') {
                current_u16.push(lo);
                i += 2;
            } else {
                if current_u16.len() >= min_len {
                    if let Ok(s) = std::str::from_utf8(&current_u16) {
                        strings.push(s.to_string());
                    }
                }
                current_u16.clear();
                i += 1;
            }
        }
        if current_u16.len() >= min_len {
            if let Ok(s) = std::str::from_utf8(&current_u16) {
                strings.push(s.to_string());
            }
        }

        strings
    }

    /// Bir IP adresinin yerel veya özel (private/loopback) olup olmadığını denetler
    pub fn is_public_ipv4(ip: &str) -> bool {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return false;
        }

        let nums: Vec<u8> = parts.iter().filter_map(|p| p.parse::<u8>().ok()).collect();
        if nums.len() != 4 {
            return false;
        }

        // Loopback (127.0.0.1), Zero (0.0.0.0), Broadcast (255.255.255.255)
        if nums[0] == 127 || nums[0] == 0 || (nums[0] == 255 && nums[1] == 255 && nums[2] == 255 && nums[3] == 255) {
            return false;
        }

        // Özel Ağlar: 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 169.254.0.0/16
        if nums[0] == 10 {
            return false;
        }
        if nums[0] == 192 && nums[1] == 168 {
            return false;
        }
        if nums[0] == 172 && (16..=31).contains(&nums[1]) {
            return false;
        }
        if nums[0] == 169 && nums[1] == 254 {
            return false;
        }

        true
    }

    /// Metinden veya dizelerden tüm IOC'leri ayıklar ve ThreatIntel veritabanıyla çapraz sorgular
    pub fn analyze_content(content_text: &str, target_name: &str, db: Option<&DbStore>) -> IocReport {
        let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
        let url_regex = Regex::new(r#"(?i)https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+"#).unwrap();
        let btc_regex = Regex::new(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b").unwrap();
        let xmr_regex = Regex::new(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b").unwrap();

        let mut ips_set = HashSet::new();
        let mut confirmed_c2 = Vec::new();

        for mat in ip_regex.find_iter(content_text) {
            let ip = mat.as_str();
            if Self::is_public_ipv4(ip) {
                ips_set.insert(ip.to_string());

                // SQLite C2 Botnet havuzunda sorgula
                if let Some(store) = db {
                    if let Ok(Some((malware, status))) = store.lookup_c2_ip(ip) {
                        confirmed_c2.push(IocMatch {
                            indicator: ip.to_string(),
                            ioc_type: "IPv4 C2 Botnet".to_string(),
                            threat_tag: Some(format!("{} (Status: {})", malware, status)),
                            is_confirmed_c2: true,
                        });
                    }
                }
            }
        }

        let mut urls_set = HashSet::new();
        let mut domains_set = HashSet::new();

        for mat in url_regex.find_iter(content_text) {
            let url = mat.as_str().to_string();
            // Temiz olmayan, şüpheli URL'ler
            if !url.contains("schemas.microsoft.com") && !url.contains("w3.org") {
                if let Some(domain_part) = url.split("://").nth(1).and_then(|s| s.split('/').next()) {
                    let clean_domain = domain_part.split(':').next().unwrap_or("");
                    if clean_domain.contains('.') && !clean_domain.ends_with(".microsoft.com") {
                        domains_set.insert(clean_domain.to_string());
                    }
                }
                urls_set.insert(url);
            }
        }

        let mut crypto_wallets = Vec::new();
        for mat in btc_regex.find_iter(content_text) {
            crypto_wallets.push(IocMatch {
                indicator: mat.as_str().to_string(),
                ioc_type: "Bitcoin (BTC) Cüzdanı".to_string(),
                threat_tag: Some("Fidye / Kripto Hırsızlığı".to_string()),
                is_confirmed_c2: false,
            });
        }
        for mat in xmr_regex.find_iter(content_text) {
            crypto_wallets.push(IocMatch {
                indicator: mat.as_str().to_string(),
                ioc_type: "Monero (XMR) Cüzdanı".to_string(),
                threat_tag: Some("Gizli Madenci (CoinMiner)".to_string()),
                is_confirmed_c2: false,
            });
        }

        // Base64 blokları
        let b64_regex = Regex::new(r"[A-Za-z0-9+/=]{28,}").unwrap();
        let mut base64_payloads = Vec::new();
        for mat in b64_regex.find_iter(content_text) {
            let b64 = mat.as_str();
            if let Ok(decoded) = BASE64_STANDARD.decode(b64) {
                let dec_str = String::from_utf8_lossy(&decoded);
                if dec_str.chars().any(|c| c.is_alphabetic()) && (dec_str.contains("http") || dec_str.contains("powershell") || dec_str.contains("cmd") || dec_str.contains(".exe") || dec_str.contains("dll")) {
                    base64_payloads.push(format!("Payload ({} B): {}", decoded.len(), dec_str.chars().take(120).collect::<String>()));
                }
            }
        }

        // Şüpheli anahtar kelimeler
        let suspicious_keywords_list = [
            "mimikatz", "sekurlsa", "logonpasswords", "cobaltstrike", "meterpreter",
            "powershell -enc", "vssadmin delete shadows", "bcdedit /set", "wmic shadowcopy delete",
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
            "samlib.dll", "lsasrv.dll", "MiniDumpWriteDump", "autorun.inf"
        ];
        let mut suspicious_keywords = Vec::new();
        let lower = content_text.to_lowercase();
        for kw in suspicious_keywords_list {
            if lower.contains(&kw.to_lowercase()) {
                suspicious_keywords.push(kw.to_string());
            }
        }

        IocReport {
            target_name: target_name.to_string(),
            total_strings_extracted: content_text.lines().count(),
            public_ips: ips_set.into_iter().collect(),
            confirmed_c2_ips: confirmed_c2,
            urls: urls_set.into_iter().collect(),
            domains: domains_set.into_iter().collect(),
            crypto_wallets,
            base64_payloads,
            suspicious_keywords,
        }
    }

    /// Bir dosyanın ham baytlarını okur, dizeleri ayıklar ve tam IOC raporu üretir
    pub fn analyze_file(path: &Path, db: Option<&DbStore>) -> Result<IocReport> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let strings = Self::extract_strings(&buffer, 4);
        let joined_strings = strings.join("\n");
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.to_string_lossy().to_string());

        let mut report = Self::analyze_content(&joined_strings, &name, db);
        report.total_strings_extracted = strings.len();
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_public_ips_and_filter_private() {
        let text = "Baglanti yapilan IP'ler: 192.168.1.50 (local), 127.0.0.1 (loopback), 185.220.101.5 (public evil).";
        let report = IocExtractor::analyze_content(text, "test.txt", None);
        assert_eq!(report.public_ips.len(), 1);
        assert_eq!(report.public_ips[0], "185.220.101.5");
    }

    #[test]
    fn test_extract_urls_and_domains() {
        let text = "C2 sunucusu: http://malware-drop.top/stage2.bin ve https://backup-c2.net:8080/gate.php";
        let report = IocExtractor::analyze_content(text, "test.txt", None);
        assert!(report.urls.iter().any(|u| u.contains("malware-drop.top")));
        assert!(report.domains.iter().any(|d| d == "malware-drop.top" || d == "backup-c2.net"));
    }

    #[test]
    fn test_extract_btc_wallet() {
        let text = "Lutfen fidyeyi su adrese gonderin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa tesekkurler.";
        let report = IocExtractor::analyze_content(text, "ransom_note.txt", None);
        assert_eq!(report.crypto_wallets.len(), 1);
        assert_eq!(report.crypto_wallets[0].indicator, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_base64_payload_extraction() {
        // "powershell.exe -enc evil" in base64: cG93ZXJzaGVsbC5leGUgLWVuYyBldmls
        let text = "Yukleyici dizesi: cG93ZXJzaGVsbC5leGUgLWVuYyBldmlsMTIzNDU2Nzg5MA==";
        let report = IocExtractor::analyze_content(text, "test.txt", None);
        assert!(!report.base64_payloads.is_empty());
    }
}
