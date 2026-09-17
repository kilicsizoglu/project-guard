use colored::Colorize;
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalkerwareSignature {
    pub name: &'static str,
    pub pattern: &'static str,
    pub vendor_or_brand: &'static str,
    pub category: &'static str, // "Ticari Casus Yazilim", "Gizli Klavye Dinleyici", "Ekran Gozetleme"
    pub mitre_technique: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalkerwareThreatFinding {
    pub pid: u32,
    pub process_name: String,
    pub command_line: String,
    pub app_name: String,
    pub category: String,
    pub severity: String,
    pub mitre_technique: String,
    pub description: String,
    pub recommendation: String,
    pub killed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalkerwareReport {
    pub total_scanned: usize,
    pub threats_found: usize,
    pub threats_killed: usize,
    pub threats: Vec<StalkerwareThreatFinding>,
}

pub struct StalkerwareHunter;

impl StalkerwareHunter {
    /// EFF Coalition Against Stalkerware ve Citizen Lab kriterlerine gore tanimlanan bilinen ticari casus yazilim kaliplari
    pub fn get_known_stalkerware_signatures() -> Vec<StalkerwareSignature> {
        vec![
            StalkerwareSignature {
                name: "FlexiSPY Monitoring Agent",
                pattern: "flexispy",
                vendor_or_brand: "FlexiSPY Ltd.",
                category: "Ticari Casus Yazilim (Commercial Spyware)",
                mitre_technique: "T1056.001 / T1113",
            },
            StalkerwareSignature {
                name: "FlexiSPY Background Daemon",
                pattern: "fs_service",
                vendor_or_brand: "FlexiSPY Ltd.",
                category: "Ticari Casus Yazilim (Commercial Spyware)",
                mitre_technique: "T1056.001 / T1059",
            },
            StalkerwareSignature {
                name: "mSpy Desktop Monitor",
                pattern: "mspy",
                vendor_or_brand: "mSpy / Altercon Group",
                category: "Ticari Casus Yazilim (Commercial Spyware)",
                mitre_technique: "T1056.001 / T1005",
            },
            StalkerwareSignature {
                name: "Spyera Surveillance Agent",
                pattern: "spyera",
                vendor_or_brand: "Spyera",
                category: "Ticari Casus Yazilim (Commercial Spyware)",
                mitre_technique: "T1056.001 / T1113",
            },
            StalkerwareSignature {
                name: "Hoverwatch Stealth Tracker",
                pattern: "hoverwatch",
                vendor_or_brand: "Refog / Hoverwatch",
                category: "Gizli Takip ve Klavye Dinleyici",
                mitre_technique: "T1056.001",
            },
            StalkerwareSignature {
                name: "Refog Free Keylogger / Employee Monitor",
                pattern: "refog",
                vendor_or_brand: "Refog Inc.",
                category: "Gizli Klavye Dinleyici (Keylogger)",
                mitre_technique: "T1056.001",
            },
            StalkerwareSignature {
                name: "WebWatcher Monitoring Client",
                pattern: "webwatcher",
                vendor_or_brand: "Awareness Technologies",
                category: "Ekran Gozetleme ve Veri Toplayici",
                mitre_technique: "T1113 / T1056.001",
            },
            StalkerwareSignature {
                name: "KidLogger Stealth Activity Recorder",
                pattern: "kidlogger",
                vendor_or_brand: "KidLogger",
                category: "Gizli Takip ve Ekran Yakalayici",
                mitre_technique: "T1113 / T1056.001",
            },
            StalkerwareSignature {
                name: "SpyAgent Remote Monitoring",
                pattern: "spyagent",
                vendor_or_brand: "SpyTech",
                category: "Gizli Casusluk ve Dinleme Paketi",
                mitre_technique: "T1056.001 / T1113",
            },
            StalkerwareSignature {
                name: "Elite Keylogger Hidden Agent",
                pattern: "elitekeylogger",
                vendor_or_brand: "WideStep",
                category: "Cekirdek/Sistem Seviyesi Klavye Dinleyici",
                mitre_technique: "T1056.001",
            },
            StalkerwareSignature {
                name: "Actual Spy Invisible Surveillance",
                pattern: "actualspy",
                vendor_or_brand: "Actual Spy Software",
                category: "Gizli Klavye ve Ekran Kaydedici",
                mitre_technique: "T1056.001 / T1113",
            },
        ]
    }

    /// EFF & Citizen Lab: Sürecin gizli izleme / casusluk davranış gösterip göstermediğini heuristik inceler
    pub fn analyze_stalkerware_heuristic(
        process_name: &str,
        cmdline: &str,
        exe_path: Option<&str>,
    ) -> Option<StalkerwareThreatFinding> {
        let name_lower = process_name.to_lowercase();
        let cmd_lower = cmdline.to_lowercase();
        let path_lower = exe_path.unwrap_or("").to_lowercase();

        // 1. Bilinen ticari casus yazılım imzaları kontrolü
        let signatures = Self::get_known_stalkerware_signatures();
        for sig in signatures {
            if name_lower.contains(sig.pattern)
                || cmd_lower.contains(sig.pattern)
                || path_lower.contains(sig.pattern)
            {
                return Some(StalkerwareThreatFinding {
                    pid: 0,
                    process_name: process_name.to_string(),
                    command_line: cmdline.to_string(),
                    app_name: sig.name.to_string(),
                    category: sig.category.to_string(),
                    severity: "Kritik".to_string(),
                    mitre_technique: sig.mitre_technique.to_string(),
                    description: format!(
                        "EFF Coalition Against Stalkerware tarafindan tanimlanan ticari casus yazilim ({}) tespit edildi. Saglayici: {}",
                        sig.name, sig.vendor_or_brand
                    ),
                    recommendation: "Sureci sonlandirin (guard scan-stalkerware --kill) ve kisisel hesaplarinizin sifrelerini baska guvenli bir cihazdan degistirin.".to_string(),
                    killed: false,
                });
            }
        }

        // 2. EFF Heuristic: Kullanıcıdan gizlenen arka plan izleme parametreleri
        // Örnek: --stealth, -stealth, -hidden, --hidden, /silent /stealth, --invisible-mode
        let stealth_flags = [
            "-stealth",
            "--stealth",
            "-hidden_mode",
            "--invisible",
            "--surveillance",
            "keylog",
            "screen_capture_interval",
        ];

        for flag in &stealth_flags {
            if cmd_lower.contains(flag) {
                return Some(StalkerwareThreatFinding {
                    pid: 0,
                    process_name: process_name.to_string(),
                    command_line: cmdline.to_string(),
                    app_name: "Supheli Gizli Takip / Stalkerware Modulu".to_string(),
                    category: "Gizli Izleme Parametresi (Stealth Surveillance)".to_string(),
                    severity: "Yuksek".to_string(),
                    mitre_technique: "T1562.001 / T1056.001".to_string(),
                    description: format!(
                        "Surec kullanici arayuzunu gizleyerek arka planda izleme/dinleme argumaniyla ('{}') calisiyor.",
                        flag
                    ),
                    recommendation: "Surecin amacini ve imzasini arastirin; yetkisiz ise sonlandirin.".to_string(),
                    killed: false,
                });
            }
        }

        // 3. Citizen Lab Heuristic: Gizlenmiş sahte Windows güncelleme veya sistem dosyası
        // Örn: AppData altında çalışan ve 'svchost.exe', 'winlogon.exe', 'taskhost.exe' adını taklit eden süreçler
        if (name_lower == "svchost.exe" || name_lower == "winlogon.exe" || name_lower == "csrss.exe")
            && !path_lower.is_empty()
            && !path_lower.contains("windows\\system32")
            && !path_lower.contains("windows\\syswow64")
        {
            return Some(StalkerwareThreatFinding {
                pid: 0,
                process_name: process_name.to_string(),
                command_line: cmdline.to_string(),
                app_name: "Taklitci Casus Surec (Masqueraded Stalkerware)".to_string(),
                category: "Sistem Sureci Taklidi (Masquerading)".to_string(),
                severity: "Kritik".to_string(),
                mitre_technique: "T1036.005".to_string(),
                description: format!(
                    "Mesru Windows sistem sureci '{}' System32 disinda (Supheli Konum: '{}') calisiyor.",
                    process_name, path_lower
                ),
                recommendation: "Bu surec bir Truva ati veya stalkerware taklididir; derhal sonlandirin.".to_string(),
                killed: false,
            });
        }

        None
    }

    /// Canlı çalışan tüm Windows süreçlerini EFF & Citizen Lab casus yazılım kurallarına göre denetler
    pub fn scan_stalkerware(system: &System, kill_active: bool) -> StalkerwareReport {
        let mut threats = Vec::new();
        let mut total_scanned = 0;
        let mut total_killed = 0;

        for (pid, process) in system.processes() {
            total_scanned += 1;
            let proc_name = process.name().to_string_lossy().to_string();
            let cmdline: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let full_cmd = cmdline.join(" ");
            let exe_path = process.exe().map(|p| p.to_string_lossy().to_string());

            if let Some(mut finding) = Self::analyze_stalkerware_heuristic(
                &proc_name,
                &full_cmd,
                exe_path.as_deref(),
            ) {
                finding.pid = pid.as_u32();

                if kill_active {
                    let killed_success = process.kill();
                    finding.killed = killed_success;
                    if killed_success {
                        total_killed += 1;
                    }
                }

                threats.push(finding);
            }
        }

        StalkerwareReport {
            total_scanned,
            threats_found: threats.len(),
            threats_killed: total_killed,
            threats,
        }
    }

    /// Terminal raporlama çıktısı
    pub fn print_report(report: &StalkerwareReport) {
        println!();
        println!("{}", "================================================================================".cyan());
        println!(
            "{} - EFF Coalition Against Stalkerware & Citizen Lab",
            "🛡️  PROJECT GUARD | CASUS VE TAKİP YAZILIMI (STALKERWARE) TARAMASI".bold().bright_yellow()
        );
        println!("{}", "================================================================================".cyan());
        println!("  • Taranan Süreç Sayısı   : {}", report.total_scanned.to_string().bold().white());
        println!(
            "  • Tespit Edilen Casusluk : {}",
            if report.threats_found == 0 {
                "0 (Temiz - Casus Yazılım Bulunamadı)".bold().green()
            } else {
                format!("{} TEHDİT BULUNDU!", report.threats_found).bold().red()
            }
        );
        if report.threats_killed > 0 {
            println!("  • Sonlandırılan Süreçler : {}", report.threats_killed.to_string().bold().yellow());
        }
        println!();

        if report.threats.is_empty() {
            println!("  {} Sistemde gizli klavye dinleyici, ticari gözetleme ajanı veya sahte sistem süreci saptanmadı.", "✔".green());
        } else {
            for (i, threat) in report.threats.iter().enumerate() {
                println!(
                    "  {} [{}] {} (PID: {})",
                    "⚠️".red(),
                    i + 1,
                    threat.app_name.bold().bright_red(),
                    threat.pid.to_string().bold().cyan()
                );
                println!("     ├─ Süreç Adı    : {}", threat.process_name.yellow());
                println!("     ├─ Kategori     : {}", threat.category.white());
                println!("     ├─ Önem Seviyesi: {}", threat.severity.bright_red());
                println!("     ├─ MITRE ATT&CK : {}", threat.mitre_technique.bright_cyan());
                println!("     ├─ Açıklama     : {}", threat.description.white());
                println!("     ├─ Tavsiye      : {}", threat.recommendation.bright_white());
                println!(
                    "     └─ Durum        : {}",
                    if threat.killed {
                        "SÜREÇ BAŞARIYLA SONLANDIRILDI".bold().green()
                    } else {
                        "Çalışıyor (Sonlandırmak için: guard scan-stalkerware --kill)".yellow()
                    }
                );
                println!();
            }
        }

        println!("{}", "--------------------------------------------------------------------------------".cyan());
        println!("  ℹ️  Referans: Electronic Frontier Foundation (EFF) & The Citizen Lab Anti-Spyware Guides");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_stalkerware_detection() {
        let finding = StalkerwareHunter::analyze_stalkerware_heuristic(
            "flexispy_monitor.exe",
            "flexispy_monitor.exe --run",
            Some("C:\\Program Files\\FlexiSPY\\flexispy_monitor.exe"),
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.app_name.contains("FlexiSPY"));
        assert_eq!(f.severity, "Kritik");
    }

    #[test]
    fn test_refog_keylogger_detection() {
        let finding = StalkerwareHunter::analyze_stalkerware_heuristic(
            "refog_svc.exe",
            "refog_svc.exe /background",
            Some("C:\\ProgramData\\Refog\\refog_svc.exe"),
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.category.contains("Klavye Dinleyici"));
    }

    #[test]
    fn test_stealth_flag_heuristic() {
        let finding = StalkerwareHunter::analyze_stalkerware_heuristic(
            "audioservice.exe",
            "audioservice.exe --stealth --surveillance",
            Some("C:\\Users\\victim\\AppData\\Local\\Temp\\audioservice.exe"),
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.description.contains("gizleyerek"));
    }

    #[test]
    fn test_masqueraded_svchost() {
        let finding = StalkerwareHunter::analyze_stalkerware_heuristic(
            "svchost.exe",
            "svchost.exe",
            Some("C:\\Users\\victim\\AppData\\Roaming\\svchost.exe"),
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.mitre_technique, "T1036.005");
    }

    #[test]
    fn test_legitimate_svchost() {
        let finding = StalkerwareHunter::analyze_stalkerware_heuristic(
            "svchost.exe",
            "svchost.exe -k netsvcs",
            Some("C:\\Windows\\System32\\svchost.exe"),
        );
        assert!(finding.is_none());
    }
}
