use colored::Colorize;
use serde::{Deserialize, Serialize};
use crate::engines::create_hidden_command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Webcam,
    Microphone,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Webcam => "Kamera (Webcam)",
            DeviceType::Microphone => "Mikrofon",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            DeviceType::Webcam => "📷",
            DeviceType::Microphone => "🎙️",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAccessRecord {
    pub device_type: DeviceType,
    pub app_id: String,
    pub executable_path: String,
    pub process_name: String,
    pub is_packaged: bool,
    pub is_active: bool,
    pub is_suspicious: bool,
    pub suspicion_reason: Option<String>,
    pub start_time_raw: u64,
    pub stop_time_raw: u64,
    pub last_active_human: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAuditReport {
    pub total_webcam_records: usize,
    pub total_mic_records: usize,
    pub active_webcam_count: usize,
    pub active_mic_count: usize,
    pub suspicious_count: usize,
    pub records: Vec<PrivacyAccessRecord>,
}

pub struct PrivacyGuard;

impl PrivacyGuard {
    /// Windows FILETIME (100-nanosaniyeden 1 Ocak 1601) değerini okunabilir tarih formatına dönüştürür
    pub fn filetime_to_human(filetime: u64) -> String {
        if filetime == 0 {
            return "Hic kullanilmadi".to_string();
        }
        // 116444736000000000 = 1601 ile 1970 arasındaki 100ns adımları
        if filetime < 116444736000000000 {
            return "Gecersiz zaman".to_string();
        }
        let unix_secs = (filetime - 116444736000000000) / 10_000_000;
        match chrono::DateTime::from_timestamp(unix_secs as i64, 0) {
            Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            None => "Gecersiz tarih".to_string(),
        }
    }

    /// Kayıt defterindeki '#' ile şifrelenmiş dosya yollarını çözer (NonPackaged)
    pub fn decode_registry_path(encoded: &str) -> String {
        encoded.replace('#', "\\")
    }

    /// Bir uygulamanın meşru görüntülü/sesli iletişim aracı olup olmadığını doğrular
    pub fn is_whitelisted_communication_app(proc_name: &str, full_path: &str) -> bool {
        let name = proc_name.to_lowercase();
        let path = full_path.to_lowercase();

        let trusted_names = [
            "chrome.exe",
            "msedge.exe",
            "msedgewebview2.exe",
            "firefox.exe",
            "brave.exe",
            "opera.exe",
            "zoom.exe",
            "teams.exe",
            "msteams.exe",
            "discord.exe",
            "slack.exe",
            "skype.exe",
            "obs64.exe",
            "obs32.exe",
            "whatsapp.exe",
            "telegram.exe",
        ];

        for trusted in &trusted_names {
            if name == *trusted {
                // Temp klasöründen çalışan şüpheli taklitçiler hariç tutulur
                if path.contains("\\appdata\\local\\temp\\") || path.contains("\\temp\\") {
                    return false;
                }
                return true;
            }
        }

        // UWP Kamera ve Xbox uygulamaları
        if name.contains("windowscamera")
            || name.contains("xboxgamingoverlay")
            || name.contains("whatsappdesktop")
        {
            return true;
        }

        false
    }

    /// Uygulamanın şüpheli olup olmadığını değerlendirir
    pub fn evaluate_suspicion(proc_name: &str, full_path: &str, is_packaged: bool) -> (bool, Option<String>) {
        let name = proc_name.to_lowercase();
        let path = full_path.to_lowercase();

        // 1. Temp veya geçici dizinden çalışan kamera/mikrofon erişimleri
        if path.contains("\\appdata\\local\\temp\\") || path.contains("\\windows\\temp\\") {
            return (
                true,
                Some("Uygulama gecici sistem/kullanici dizininden (Temp) calisarak donanima erisiyor.".to_string()),
            );
        }

        // 2. Betik yorumlayıcıları ve yönetimsel kabuklar
        if name == "powershell.exe"
            || name == "pwsh.exe"
            || name == "cmd.exe"
            || name == "wscript.exe"
            || name == "cscript.exe"
            || name == "mshta.exe"
        {
            return (
                true,
                Some(format!("Sistem komut kabugu '{}' dogrudan kamera/mikrofon kaydi baslatiyor (Casus Betik Taktigi).", proc_name)),
            );
        }

        // 3. Bilinen casus yazılım isimleri
        let stalkerware_keywords = ["keylog", "spy", "stealth", "monitor", "surveillance", "flexispy", "mspy"];
        for kw in &stalkerware_keywords {
            if name.contains(kw) || path.contains(kw) {
                return (
                    true,
                    Some(format!("Uygulama adi veya yolu bilinen casus yazilim kalibi ('{}') iceriyor.", kw)),
                );
            }
        }

        // 4. Meşru listede olmayan ve paketlenmemiş rastgele Win32 yürütülebilirleri
        if !is_packaged && !Self::is_whitelisted_communication_app(proc_name, full_path) {
            // Python veya geliştirici araçları için bilgilendirici uyarı
            if name.contains("python") || name.contains("qemu") {
                return (
                    false,
                    None,
                );
            }
            return (
                true,
                Some("Bilinmeyen ucuncu parti masaustu uygulamasi kamera/mikrofon yetkisi almis.".to_string()),
            );
        }

        (false, None)
    }

    /// Windows Kayıt Defteri ConsentStore çıktısını ayrıştırır
    pub fn parse_consent_store_output(raw_output: &str, device: DeviceType) -> Vec<PrivacyAccessRecord> {
        let mut records = Vec::new();
        let mut current_key = String::new();
        let mut current_start: u64 = 0;
        let mut current_stop: u64 = 0;
        let mut has_timestamps = false;

        let flush_record = |key: &str, start: u64, stop: u64, records: &mut Vec<PrivacyAccessRecord>| {
            if key.is_empty() {
                return;
            }

            // Kök anahtarları atla
            let key_trimmed = key.trim();
            if key_trimmed.ends_with("\\webcam")
                || key_trimmed.ends_with("\\microphone")
                || key_trimmed.ends_with("\\NonPackaged")
            {
                return;
            }

            let is_packaged = !key_trimmed.contains("\\NonPackaged\\");
            let subkey = key_trimmed.split('\\').last().unwrap_or("");
            if subkey.is_empty() {
                return;
            }

            let (executable_path, process_name) = if is_packaged {
                (subkey.to_string(), subkey.to_string())
            } else {
                let decoded = Self::decode_registry_path(subkey);
                let p_name = decoded.split('\\').last().unwrap_or(&decoded).to_string();
                (decoded, p_name)
            };

            // Aktiflik kuralı:
            // stop == 0 veya start > stop ise şu anda AÇIK ve KULLANILIYOR
            let is_active = (start > 0 && stop == 0) || (start > stop && start > 0);

            let (is_suspicious, suspicion_reason) = Self::evaluate_suspicion(&process_name, &executable_path, is_packaged);

            let last_active_human = if is_active {
                "ŞU ANDA AKTİF (KULLANILIYOR)".to_string()
            } else if start > 0 {
                Self::filetime_to_human(start)
            } else {
                "Hiç kullanılmadı".to_string()
            };

            records.push(PrivacyAccessRecord {
                device_type: device,
                app_id: subkey.to_string(),
                executable_path,
                process_name,
                is_packaged,
                is_active,
                is_suspicious,
                suspicion_reason,
                start_time_raw: start,
                stop_time_raw: stop,
                last_active_human,
            });
        };

        for line in raw_output.lines() {
            let line_trimmed = line.trim();
            if line_trimmed.starts_with("HKEY_CURRENT_USER") || line_trimmed.starts_with("HKEY_LOCAL_MACHINE") {
                if has_timestamps {
                    flush_record(&current_key, current_start, current_stop, &mut records);
                }
                current_key = line_trimmed.to_string();
                current_start = 0;
                current_stop = 0;
                has_timestamps = false;
            } else if line_trimmed.starts_with("LastUsedTimeStart") {
                let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    let hex_str = parts[2].trim_start_matches("0x");
                    if let Ok(val) = u64::from_str_radix(hex_str, 16) {
                        current_start = val;
                        has_timestamps = true;
                    }
                }
            } else if line_trimmed.starts_with("LastUsedTimeStop") {
                let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    let hex_str = parts[2].trim_start_matches("0x");
                    if let Ok(val) = u64::from_str_radix(hex_str, 16) {
                        current_stop = val;
                        has_timestamps = true;
                    }
                }
            }
        }

        if has_timestamps {
            flush_record(&current_key, current_start, current_stop, &mut records);
        }

        records
    }

    /// Canlı Windows sisteminde kamera ve mikrofon kayıt defteri durumunu sorgular
    pub fn audit_privacy() -> PrivacyAuditReport {
        let mut all_records = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // 1. Webcam (Kamera) Telemetrisi
            if let Ok(out) = create_hidden_command("reg")
                .args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam", "/s"])
                .output()
            {
                let text = String::from_utf8_lossy(&out.stdout);
                let recs = Self::parse_consent_store_output(&text, DeviceType::Webcam);
                all_records.extend(recs);
            }

            // 2. Microphone (Mikrofon) Telemetrisi
            if let Ok(out) = create_hidden_command("reg")
                .args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone", "/s"])
                .output()
            {
                let text = String::from_utf8_lossy(&out.stdout);
                let recs = Self::parse_consent_store_output(&text, DeviceType::Microphone);
                all_records.extend(recs);
            }
        }

        let total_webcam = all_records.iter().filter(|r| r.device_type == DeviceType::Webcam).count();
        let total_mic = all_records.iter().filter(|r| r.device_type == DeviceType::Microphone).count();
        let active_webcam = all_records.iter().filter(|r| r.device_type == DeviceType::Webcam && r.is_active).count();
        let active_mic = all_records.iter().filter(|r| r.device_type == DeviceType::Microphone && r.is_active).count();
        let suspicious = all_records.iter().filter(|r| r.is_suspicious).count();

        PrivacyAuditReport {
            total_webcam_records: total_webcam,
            total_mic_records: total_mic,
            active_webcam_count: active_webcam,
            active_mic_count: active_mic,
            suspicious_count: suspicious,
            records: all_records,
        }
    }

    /// Raporu konsola renkli ve detaylı formatta basar
    pub fn print_report(report: &PrivacyAuditReport) {
        println!();
        println!("{}", "================================================================================".cyan());
        println!(
            "{} - Windows Donanım Gizlilik Koruması & Yetkisiz Erişim Tespiti",
            "🛡️  PROJECT GUARD | KAMERA & MİKROFON GİZLİLİK RAPORU".bold().bright_yellow()
        );
        println!("{}", "================================================================================".cyan());
        println!(
            "  • Aktif Kamera Durumu  : {}",
            if report.active_webcam_count > 0 {
                format!("{} KAMERA ŞU ANDA AÇIK!", report.active_webcam_count).bold().bright_red()
            } else {
                "0 (Kapalı - Kamera Boşta)".bold().green()
            }
        );
        println!(
            "  • Aktif Mikrofon Durumu: {}",
            if report.active_mic_count > 0 {
                format!("{} MİKROFON ŞU ANDA SES KAYDEDİYOR!", report.active_mic_count).bold().bright_red()
            } else {
                "0 (Kapalı - Mikrofon Boşta)".bold().green()
            }
        );
        println!(
            "  • Şüpheli Uygulama     : {}",
            if report.suspicious_count > 0 {
                format!("{} ŞÜPHELİ ERİŞİM BULUNDU!", report.suspicious_count).bold().red()
            } else {
                "0 (Güvenli)".bold().green()
            }
        );
        println!("  • Kayıtlı Kamera İzni  : {} uygulama", report.total_webcam_records);
        println!("  • Kayıtlı Mikrofon İzni: {} uygulama", report.total_mic_records);
        println!();

        println!("  {}:", "Uygulama Donanım Erişim Geçmişi ve Anlık Durum".bold().white());

        for (i, rec) in report.records.iter().enumerate() {
            let status_badge = if rec.is_active {
                format!("{} [ŞU ANDA AKTİF / ÇEKİM YAPIYOR]", rec.device_type.icon()).bold().bright_red()
            } else {
                format!("{} [Kapalı / Boşta]", rec.device_type.icon()).green()
            };

            let suspicion_badge = if rec.is_suspicious {
                "⚠️ [ŞÜPHELİ / YETKİSİZ]".bold().red()
            } else {
                "✔ [Meşru]".cyan()
            };

            println!(
                "   [{:02}] {} | {} | {}",
                i + 1,
                rec.process_name.bold().yellow(),
                status_badge,
                suspicion_badge
            );
            println!("        ├─ Donanım     : {}", rec.device_type.as_str().white());
            println!("        ├─ Yol/Kimlik  : {}", rec.executable_path.bright_black());
            println!("        ├─ Son Kullanım: {}", rec.last_active_human.cyan());
            if let Some(ref reason) = rec.suspicion_reason {
                println!("        └─ Uyarı Nedeni: {}", reason.bright_red());
            } else {
                println!("        └─ Güvenlik    : Doğrulanmış uygulama kimliği.");
            }
            println!();
        }

        println!("{}", "--------------------------------------------------------------------------------".cyan());
        println!("  ℹ️  'guard privacy-watch' komutu ile kamera açıldığı anda ekrana Toast bildirimi alabilirsiniz.");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_registry_path() {
        let encoded = r"C:#Program Files (x86)#Microsoft#Edge#Application#msedge.exe";
        let decoded = PrivacyGuard::decode_registry_path(encoded);
        assert_eq!(decoded, r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
    }

    #[test]
    fn test_whitelisted_communication_apps() {
        assert!(PrivacyGuard::is_whitelisted_communication_app(
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ));
        assert!(PrivacyGuard::is_whitelisted_communication_app(
            "teams.exe",
            r"C:\Users\user\AppData\Local\Microsoft\Teams\current\teams.exe"
        ));
        // Temp folder disguise should NOT be whitelisted
        assert!(!PrivacyGuard::is_whitelisted_communication_app(
            "teams.exe",
            r"C:\Users\user\AppData\Local\Temp\teams.exe"
        ));
    }

    #[test]
    fn test_suspicious_script_and_temp() {
        let (is_sus, reason) = PrivacyGuard::evaluate_suspicion(
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            false,
        );
        assert!(is_sus);
        assert!(reason.unwrap().contains("komut kabugu"));

        let (is_temp, reason_temp) = PrivacyGuard::evaluate_suspicion(
            "recorder.exe",
            r"C:\Users\user\AppData\Local\Temp\recorder.exe",
            false,
        );
        assert!(is_temp);
        assert!(reason_temp.unwrap().contains("Temp"));
    }

    #[test]
    fn test_parse_consent_store_active_camera() {
        let sample = r#"
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Program Files#EvilTool#cam_grab.exe
    LastUsedTimeStart    REG_QWORD    0x1dd42b0bc08a525
    LastUsedTimeStop    REG_QWORD    0x0
"#;
        let records = PrivacyGuard::parse_consent_store_output(sample, DeviceType::Webcam);
        assert_eq!(records.len(), 1);
        assert!(records[0].is_active);
        assert_eq!(records[0].process_name, "cam_grab.exe");
        assert!(records[0].is_suspicious);
    }

    #[test]
    fn test_parse_consent_store_stopped_camera() {
        let sample = r#"
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Program Files#Google#Chrome#Application#chrome.exe
    LastUsedTimeStart    REG_QWORD    0x1dd42b0bc08a525
    LastUsedTimeStop    REG_QWORD    0x1dd42b0c3e13c2b
"#;
        let records = PrivacyGuard::parse_consent_store_output(sample, DeviceType::Webcam);
        assert_eq!(records.len(), 1);
        assert!(!records[0].is_active);
        assert_eq!(records[0].process_name, "chrome.exe");
        assert!(!records[0].is_suspicious);
    }
}
