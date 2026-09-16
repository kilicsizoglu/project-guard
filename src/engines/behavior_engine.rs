use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorDetection {
    pub rule_id: String,
    pub rule_name: String,
    pub mitre_attack_id: String,
    pub severity: String,
    pub description: String,
    pub matched_pattern: String,
}

pub struct BehaviorEngine;

impl BehaviorEngine {
    /// Komut satiri veya süreç davranışını Sigma-benzeri davranış kurallarıyla analiz eder.
    pub fn analyze_command_line(cmd: &str) -> Vec<BehaviorDetection> {
        let mut detections = Vec::new();
        let cmd_lower = cmd.to_lowercase();

        // 1. T1490: Inhibit System Recovery (Gölge kopyaları silme / kurtarma engelleme)
        if (cmd_lower.contains("vssadmin") && (cmd_lower.contains("delete") && cmd_lower.contains("shadows")))
            || (cmd_lower.contains("wmic") && cmd_lower.contains("shadowcopy") && cmd_lower.contains("delete"))
            || (cmd_lower.contains("wbadmin") && cmd_lower.contains("delete") && cmd_lower.contains("catalog"))
            || (cmd_lower.contains("bcdedit") && cmd_lower.contains("bootstatuspolicy") && cmd_lower.contains("ignoreallfailures"))
        {
            detections.push(BehaviorDetection {
                rule_id: "SIGMA-T1490-SHADOWS".to_string(),
                rule_name: "Sistem Kurtarma ve Golge Kopyalari Yok Etme (Ransomware Onculu)".to_string(),
                mitre_attack_id: "T1490".to_string(),
                severity: "Critical".to_string(),
                description: "Sistem geri yukleme noktalarini ve VSS golge kopyalarini silerek fidye yaziliminin cozumunu engelleme teknigi.".to_string(),
                matched_pattern: cmd.to_string(),
            });
        }

        // 2. T1070.001: Indicator Removal on Host (Olay günlüklerini temizleme)
        if (cmd_lower.contains("wevtutil") && (cmd_lower.contains("cl ") || cmd_lower.contains("clear-log")))
            || cmd_lower.contains("clear-eventlog")
            || (cmd_lower.contains("fsutil") && cmd_lower.contains("usn") && cmd_lower.contains("deletejournal"))
        {
            detections.push(BehaviorDetection {
                rule_id: "SIGMA-T1070-LOGCLEAR".to_string(),
                rule_name: "Windows Olay Gunluklerini ve Adli Izleri Temizleme".to_string(),
                mitre_attack_id: "T1070.001".to_string(),
                severity: "High".to_string(),
                description: "Saldirganin sistemde geride biraktigi guvenlik ve denetim loglarini sifirlama girisimi.".to_string(),
                matched_pattern: cmd.to_string(),
            });
        }

        // 3. T1059.001: Obfuscated / Bypassed PowerShell Execution
        let has_ps = cmd_lower.contains("powershell") || cmd_lower.contains("pwsh");
        if has_ps {
            let is_encoded = cmd_lower.contains("-enc ")
                || cmd_lower.contains("-encodedcommand")
                || cmd_lower.contains("-e ");
            let is_hidden = cmd_lower.contains("-w hidden")
                || cmd_lower.contains("-windowstyle hidden");
            let is_bypassed = cmd_lower.contains("-ep bypass")
                || cmd_lower.contains("-executionpolicy bypass");
            let is_download_cradle = cmd_lower.contains("downloadstring")
                || cmd_lower.contains("invoke-webrequest")
                || cmd_lower.contains("iwr ")
                || (cmd_lower.contains("iex") && cmd_lower.contains("http"));

            if is_encoded || (is_hidden && is_bypassed) || is_download_cradle {
                detections.push(BehaviorDetection {
                    rule_id: "SIGMA-T1059-POWERSHELL".to_string(),
                    rule_name: "Gizlenmis / Guvenlik Atlatmali PowerShell Komutu (LOLBin)".to_string(),
                    mitre_attack_id: "T1059.001".to_string(),
                    severity: if is_encoded || is_download_cradle { "Critical" } else { "High" }.to_string(),
                    description: "Base64 sifrelenmis, gizli pencereli veya dogrudan bellekten betik calistiran PowerShell suistimali.".to_string(),
                    matched_pattern: cmd.to_string(),
                });
            }
        }

        // 4. T1105: Ingress Tool Transfer (Uzak araci yerel sisteme indirme)
        if (cmd_lower.contains("certutil") && (cmd_lower.contains("-urlcache") || cmd_lower.contains("-split")))
            || (cmd_lower.contains("bitsadmin") && cmd_lower.contains("/transfer"))
            || (cmd_lower.contains("curl") && (cmd_lower.contains(" -o") || cmd_lower.contains(" -o")))
        {
            detections.push(BehaviorDetection {
                rule_id: "SIGMA-T1105-INGRESS".to_string(),
                rule_name: "LOLBin ile Zararli Yazilim Indirme (Ingress Transfer)".to_string(),
                mitre_attack_id: "T1105".to_string(),
                severity: "High".to_string(),
                description: "Mesru sistem araclari (certutil, bitsadmin) kullanilarak uzaktan zararlı payload indirme.".to_string(),
                matched_pattern: cmd.to_string(),
            });
        }

        // 5. T1003: OS Credential Dumping (Bellekten sifre sizdirma)
        if (cmd_lower.contains("procdump") && cmd_lower.contains("lsass"))
            || (cmd_lower.contains("comsvcs.dll") && (cmd_lower.contains("minidump") || cmd_lower.contains("#24")))
            || cmd_lower.contains("sekurlsa")
            || cmd_lower.contains("mimikatz")
        {
            detections.push(BehaviorDetection {
                rule_id: "SIGMA-T1003-CREDDUMP".to_string(),
                rule_name: "LSASS Kimlik Bilgisi ve Bellek Dökümü (Credential Dumping)".to_string(),
                mitre_attack_id: "T1003".to_string(),
                severity: "Critical".to_string(),
                description: "Sistem oturum sifrelerini ve hashlerini bellekten calma girisimi.".to_string(),
                matched_pattern: cmd.to_string(),
            });
        }

        // 6. T1218: System Binary Proxy Execution (Mesru ikili araclar uzerinden kod calistirma)
        if (cmd_lower.contains("mshta") && (cmd_lower.contains("http://") || cmd_lower.contains("https://") || cmd_lower.contains("vbscript:")))
            || (cmd_lower.contains("rundll32") && (cmd_lower.contains("javascript:") || cmd_lower.contains("url.dll")))
            || (cmd_lower.contains("regsvr32") && cmd_lower.contains("/s") && cmd_lower.contains("/i:http"))
        {
            detections.push(BehaviorDetection {
                rule_id: "SIGMA-T1218-PROXYEXEC".to_string(),
                rule_name: "Proxy İkili Yurutme ile Guvenlik Atlatma (LOLBin)".to_string(),
                mitre_attack_id: "T1218".to_string(),
                severity: "High".to_string(),
                description: "mshta, rundll32 veya regsvr32 uzerinden guvenlik mekanizmalarini atlatarak kod calistirma.".to_string(),
                matched_pattern: cmd.to_string(),
            });
        }

        detections
    }
}
