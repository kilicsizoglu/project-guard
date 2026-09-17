use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealerTargetVault {
    pub name: &'static str,
    pub path_pattern: &'static str,
    pub category: &'static str, // "Tarayici Sifreleri", "Kripto Cuzdan", "Oturum Tokeni", "FTP Kimlikleri"
    pub mitre_technique: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealerThreatFinding {
    pub pid: u32,
    pub process_name: String,
    pub command_line: String,
    pub target_asset: String,
    pub category: String,
    pub severity: String,
    pub mitre_technique: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealerScanReport {
    pub total_processes_scanned: usize,
    pub vaults_protected_count: usize,
    pub threats: Vec<StealerThreatFinding>,
}

pub struct StealerHunter;

impl StealerHunter {
    /// Shadowserver 2026 StealC/Operation Endgame bülteninde tanımlanan hedeflenen hassas veri depoları
    pub fn get_sensitive_vaults() -> Vec<StealerTargetVault> {
        vec![
            StealerTargetVault {
                name: "Google Chrome & Edge Login Data (Sifre Deposu)",
                path_pattern: "Login Data",
                category: "Tarayici Sifreleri",
                mitre_technique: "T1555.003",
            },
            StealerTargetVault {
                name: "Tarayici Oturum Cerezleri (Cookies)",
                path_pattern: "Cookies",
                category: "Oturum Tokeni",
                mitre_technique: "T1539",
            },
            StealerTargetVault {
                name: "Tarayici DPAPI Master Key Deposu (Local State)",
                path_pattern: "Local State",
                category: "Tarayici Sifreleri",
                mitre_technique: "T1555.003",
            },
            StealerTargetVault {
                name: "MetaMask Kripto Cuzdan Eklentisi",
                path_pattern: "nkbihfbeogaeaoehlefnkodbefgpgknn",
                category: "Kripto Cuzdan",
                mitre_technique: "T1005",
            },
            StealerTargetVault {
                name: "Phantom Kripto Cuzdan Eklentisi",
                path_pattern: "bfnaelmomeimhlpmgjnjophhpkkoljpa",
                category: "Kripto Cuzdan",
                mitre_technique: "T1005",
            },
            StealerTargetVault {
                name: "TronLink Kripto Cuzdan Eklentisi",
                path_pattern: "ibnejdfjmmkpcnlpebklmnkoeoihofec",
                category: "Kripto Cuzdan",
                mitre_technique: "T1005",
            },
            StealerTargetVault {
                name: "Telegram Masaustu Oturum Deposu (tdata)",
                path_pattern: "tdata",
                category: "Oturum Tokeni",
                mitre_technique: "T1552.001",
            },
            StealerTargetVault {
                name: "Discord Token Deposu (leveldb)",
                path_pattern: "discord\\Local Storage\\leveldb",
                category: "Oturum Tokeni",
                mitre_technique: "T1552.004",
            },
            StealerTargetVault {
                name: "FileZilla FTP Kayitli Sunucular",
                path_pattern: "sitemanager.xml",
                category: "FTP Kimlikleri",
                mitre_technique: "T1552.001",
            },
        ]
    }

    /// Meşru tarayıcı ve sistem süreçleri (Beyaz Liste)
    fn is_legitimate_browser_process(process_name: &str) -> bool {
        let name = process_name.to_lowercase();
        name == "chrome.exe"
            || name == "msedge.exe"
            || name == "brave.exe"
            || name == "opera.exe"
            || name == "firefox.exe"
            || name == "vivaldi.exe"
            || name == "telegram.exe"
            || name == "discord.exe"
            || name == "filezilla.exe"
    }

    /// Çalışan süreçleri Shadowserver 2026 StealC/Lumma/RedLine infostealer göstergelerine karşı tarar
    pub fn scan_processes(system: &System) -> StealerScanReport {
        let vaults = Self::get_sensitive_vaults();
        let mut threats = Vec::new();
        let mut scanned = 0;

        for (pid, process) in system.processes() {
            scanned += 1;
            let proc_name = process.name().to_string_lossy().to_string();
            let cmdline: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let full_cmd = cmdline.join(" ");
            let full_cmd_lower = full_cmd.to_lowercase();

            // Meşru tarayıcılar kendi dosyalarını açabilir, bu nedenle onları hariç tutuyoruz
            if Self::is_legitimate_browser_process(&proc_name) {
                continue;
            }

            for vault in &vaults {
                let pattern_lower = vault.path_pattern.to_lowercase();

                // 1. Komut satırında veya argümanlarında hassas kasa yolunu hedefleme
                if full_cmd_lower.contains(&pattern_lower) {
                    threats.push(StealerThreatFinding {
                        pid: pid.as_u32(),
                        process_name: proc_name.clone(),
                        command_line: full_cmd.clone(),
                        target_asset: vault.name.to_string(),
                        category: vault.category.to_string(),
                        severity: "Kritik".to_string(),
                        mitre_technique: vault.mitre_technique.to_string(),
                        description: format!(
                            "Guvensiz surec ({}) dogrudan '{}' veri kasasini komut satiri parametresi olarak hedefliyor (Shadowserver StealC Taktigi).",
                            proc_name, vault.name
                        ),
                        recommendation: "Sureci aninda sonlandirin (guard kill-process) ve sistemde tam antivirus taramasi baslatin.".to_string(),
                    });
                    break;
                }

                // 2. PowerShell / CMD veya WScript üzerinden SQLite / CryptUnprotectData veya Tarayıcı kopyalama scriptleri
                if (proc_name.eq_ignore_ascii_case("powershell.exe")
                    || proc_name.eq_ignore_ascii_case("pwsh.exe")
                    || proc_name.eq_ignore_ascii_case("cmd.exe"))
                    && (full_cmd_lower.contains("copy-item") || full_cmd_lower.contains("copy ") || full_cmd_lower.contains("xcopy") || full_cmd_lower.contains("robocopy"))
                    && (full_cmd_lower.contains("user data") || full_cmd_lower.contains("appdata"))
                {
                    threats.push(StealerThreatFinding {
                        pid: pid.as_u32(),
                        process_name: proc_name.clone(),
                        command_line: full_cmd.clone(),
                        target_asset: "Tarayici Profil & Veri Dizini".to_string(),
                        category: "Toplu Kimlik Hirsizligi (Data Harvesting)".to_string(),
                        severity: "Kritik".to_string(),
                        mitre_technique: "T1005 / T1555".to_string(),
                        description: format!(
                            "Betik yorumlayici ({}) tarayici profil ve kimlik verilerini kopyalamaya calisiyor (Infostealer Harvest).",
                            proc_name
                        ),
                        recommendation: "Betik surecini aninda durdurun ve calistiran ebeveyn sureci inceleyin.".to_string(),
                    });
                    break;
                }
            }
        }

        StealerScanReport {
            total_processes_scanned: scanned,
            vaults_protected_count: vaults.len(),
            threats,
        }
    }

    /// Tek bir komut satırını test ve analiz amacıyla inceler
    pub fn analyze_command_line(process_name: &str, cmdline: &str) -> Option<StealerThreatFinding> {
        if Self::is_legitimate_browser_process(process_name) {
            return None;
        }

        let vaults = Self::get_sensitive_vaults();
        let cmd_lower = cmdline.to_lowercase();

        for vault in vaults {
            if cmd_lower.contains(&vault.path_pattern.to_lowercase()) {
                return Some(StealerThreatFinding {
                    pid: 9999,
                    process_name: process_name.to_string(),
                    command_line: cmdline.to_string(),
                    target_asset: vault.name.to_string(),
                    category: vault.category.to_string(),
                    severity: "Kritik".to_string(),
                    mitre_technique: vault.mitre_technique.to_string(),
                    description: format!(
                        "Zararli/Yetkisiz surec '{}' hassas depoya erismeye calisiyor.",
                        process_name
                    ),
                    recommendation: "Sureci karantinaya alin.".to_string(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealer_detection_on_chrome_login_data() {
        let finding = StealerHunter::analyze_command_line(
            "stealc_payload.exe",
            "C:\\Temp\\stealc_payload.exe --target C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.category, "Tarayici Sifreleri");
        assert_eq!(f.mitre_technique, "T1555.003");
    }

    #[test]
    fn test_stealer_detection_on_metamask_vault() {
        let finding = StealerHunter::analyze_command_line(
            "unknown_miner.exe",
            "unknown_miner.exe -dump C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\nkbihfbeogaeaoehlefnkodbefgpgknn",
        );
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.category, "Kripto Cuzdan");
    }

    #[test]
    fn test_legitimate_browser_whitelisted() {
        let finding = StealerHunter::analyze_command_line(
            "chrome.exe",
            "chrome.exe --profile-directory=Default --flag Login Data",
        );
        assert!(finding.is_none());
    }
}
