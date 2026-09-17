use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisaKevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub known_ransomware_campaign_use: bool,
    pub mitre_attack: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevAuditReport {
    pub total_kev_rules: usize,
    pub critical_vulnerabilities: usize,
    pub ransomware_associated_count: usize,
    pub entries: Vec<CisaKevEntry>,
    pub endpoint_warnings: Vec<String>,
}

pub struct CisaKevEngine;

impl CisaKevEngine {
    /// CISA KEV (Known Exploited Vulnerabilities) kataloğundaki en kritik Windows ve uç nokta zafiyetlerini döner
    pub fn get_curated_catalog() -> Vec<CisaKevEntry> {
        vec![
            CisaKevEntry {
                cve_id: "CVE-2024-21338".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows Kernel / AppLocker".to_string(),
                vulnerability_name: "Windows Kernel Privilege Escalation (BYOVD Weaponized)".to_string(),
                date_added: "2024-02-29".to_string(),
                short_description: "Lazarus ve fidye gruplarınca EDR/AV süreçlerini çekirdekten körleştirmek ve silmek için aktif olarak istismar edilen sürücü zafiyeti.".to_string(),
                required_action: "En son Windows güvenlik güncellemesini yükleyin ve sürücü blok listesini (WDAC) etkinleştirin.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1068, T1562.001".to_string(),
                severity: "Critical".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2024-30051".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows Desktop Window Manager (DWM)".to_string(),
                vulnerability_name: "Windows DWM Core Library Elevation of Privilege".to_string(),
                date_added: "2024-05-14".to_string(),
                short_description: "Qakbot fidye grubu tarafından SYSTEM yetkisi elde etmek için yaygın biçimde istismar edilen zafiyet.".to_string(),
                required_action: "KB5037768 ve sonrası güvenlik yamalarını uygulayın.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1068".to_string(),
                severity: "Critical".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2024-38063".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows TCP/IP Stack".to_string(),
                vulnerability_name: "Windows TCP/IP Remote Code Execution Vulnerability".to_string(),
                date_added: "2024-08-13".to_string(),
                short_description: "Özel olarak hazırlanmış IPv6 paketleri ile kimlik doğrulaması olmadan uzaktan kod yürütme zafiyeti.".to_string(),
                required_action: "Ağ arabirimlerinde IPv6 korumasını güncelleyin ve KB5041585 yamasını uygulayın.".to_string(),
                known_ransomware_campaign_use: false,
                mitre_attack: "T1210".to_string(),
                severity: "Critical".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2024-43461".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows MSHTML Platform".to_string(),
                vulnerability_name: "Windows MSHTML Platform Spoofing Vulnerability".to_string(),
                date_added: "2024-09-10".to_string(),
                short_description: "Void Banshee APT grubu tarafından dosya uzantılarını gizleyerek zararlı HTA/JS çalıştırmak için sıfır gün olarak istismar edildi.".to_string(),
                required_action: "KB5043064 yamasını yükleyin ve dosya uzantısı gizleme anomalilerini denetleyin.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1204.002, T1036".to_string(),
                severity: "Critical".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2023-36884".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows Office / HTML Remote Code Execution".to_string(),
                vulnerability_name: "Office and Windows HTML Remote Code Execution".to_string(),
                date_added: "2023-07-11".to_string(),
                short_description: "RomCom fidye aktörü tarafından Microsoft Office belgelerine gömülü zararlı iframe/HTML yoluyla kod yürütme.".to_string(),
                required_action: "FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION kayıt defteri ayarını etkinleştirin.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1203, T1566".to_string(),
                severity: "Critical".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2023-38831".to_string(),
                vendor_project: "RARLAB".to_string(),
                product: "WinRAR".to_string(),
                vulnerability_name: "WinRAR File Extension Processing Spoofing / RCE".to_string(),
                date_added: "2023-08-23".to_string(),
                short_description: "WinRAR arşiv dosyalarında uzantı spoofing yapılarak resim/PDF arkasında gizli script çalıştırma zafiyeti.".to_string(),
                required_action: "WinRAR 6.23 veya daha yeni bir sürüme yükseltin.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1204.002".to_string(),
                severity: "High".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2021-34527".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows Print Spooler".to_string(),
                vulnerability_name: "PrintNightmare Remote Code Execution".to_string(),
                date_added: "2021-11-03".to_string(),
                short_description: "Spoolsv servisi üzerinden yetkisiz sürücü yükleme ve tam SYSTEM yetkisi elde etme.".to_string(),
                required_action: "Point and Print kısıtlamalarını uygulayın veya Print Spooler servisini devre dışı bırakın.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1068".to_string(),
                severity: "Critical".to_string(),
            },
            CisaKevEntry {
                cve_id: "CVE-2020-1472".to_string(),
                vendor_project: "Microsoft".to_string(),
                product: "Windows Netlogon (Zerologon)".to_string(),
                vulnerability_name: "Netlogon Elevation of Privilege Vulnerability".to_string(),
                date_added: "2021-11-03".to_string(),
                short_description: "Active Directory etki alanı denetleyicisinde parola sıfırlayarak anında Domain Admin olma açığı.".to_string(),
                required_action: "Güvenli RPC kanalı zorunluluğunu (Full Enforcement) devreye alın.".to_string(),
                known_ransomware_campaign_use: true,
                mitre_attack: "T1068, T1078".to_string(),
                severity: "Critical".to_string(),
            },
        ]
    }

    /// Sistemde potansiyel KEV tehditlerini ve uç nokta savunma risklerini denetler
    pub fn audit_system() -> Result<KevAuditReport> {
        let catalog = Self::get_curated_catalog();
        let total = catalog.len();
        let critical = catalog.iter().filter(|c| c.severity == "Critical").count();
        let ransomware = catalog.iter().filter(|c| c.known_ransomware_campaign_use).count();

        let mut endpoint_warnings = Vec::new();

        // Print Spooler servisi aktif mi denetle
        #[cfg(target_os = "windows")]
        {
            if let Ok(out) = crate::engines::create_hidden_command("sc.exe").args(["query", "Spooler"]).output() {
                let s = String::from_utf8_lossy(&out.stdout);
                if s.contains("RUNNING") {
                    endpoint_warnings.push("Print Spooler servisi calisiyor (CVE-2021-34527 PrintNightmare riskine karsi Point&Print kisitlamalarini dogrulayin).".to_string());
                }
            }

            // WDAC / Sürücü blok listesi uyarısı
            endpoint_warnings.push("BYOVD (Bring Your Own Vulnerable Driver) risklerine karsi Microsoft Onerilen Surucu Blok Listesi (Driver Blocklist) denetlenmelidir (CVE-2024-21338).".to_string());
        }

        #[cfg(not(target_os = "windows"))]
        {
            endpoint_warnings.push("Non-Windows ortamda simule edildi.".to_string());
        }

        Ok(KevAuditReport {
            total_kev_rules: total,
            critical_vulnerabilities: critical,
            ransomware_associated_count: ransomware,
            entries: catalog,
            endpoint_warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cisa_kev_catalog_integrity() {
        let catalog = CisaKevEngine::get_curated_catalog();
        assert!(!catalog.is_empty());
        assert!(catalog.iter().any(|c| c.cve_id == "CVE-2024-21338"));
        assert!(catalog.iter().any(|c| c.cve_id == "CVE-2024-30051"));
        assert!(catalog.iter().any(|c| c.known_ransomware_campaign_use));
    }

    #[test]
    fn test_cisa_kev_audit_execution() {
        let rep = CisaKevEngine::audit_system().unwrap();
        assert!(rep.total_kev_rules >= 8);
        assert!(rep.critical_vulnerabilities >= 5);
        assert!(rep.ransomware_associated_count >= 5);
    }
}
