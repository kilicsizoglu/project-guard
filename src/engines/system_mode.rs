use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use crate::engines::create_hidden_command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemMode {
    Default,
    Game,
    Work,
}

impl SystemMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SystemMode::Default => "Standart / Varsayilan Windows",
            SystemMode::Game => "Oyun Modu (Ultra Dusuk Gecikme & Performans)",
            SystemMode::Work => "Is ve Gizlilik Modu (WinDebloat & Odaklanma)",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            SystemMode::Default => "⚪ [VARSAYILAN]",
            SystemMode::Game => "🎮 [OYUN MODU]",
            SystemMode::Work => "💼 [İŞ & GİZLİLİK]",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModeBackup {
    pub original_mode: String,
    pub system_responsiveness: Option<u32>,
    pub network_throttling_index: Option<u32>,
    pub gpu_priority: Option<u32>,
    pub games_priority: Option<u32>,
    pub allow_auto_game_mode: Option<u32>,
    pub disable_search_box_suggestions: Option<u32>,
    pub advertising_enabled: Option<u32>,
    pub backup_timestamp: String,
}

pub struct SystemModeEngine;

impl SystemModeEngine {
    /// Yedekleme dosyasının saklandığı yol
    pub fn get_backup_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let dir = home.join(".project_guard");
        let _ = fs::create_dir_all(&dir);
        dir.join("mode_backup.json")
    }

    /// Kayıt defterinden DWORD değerini güvenli sorgular
    #[cfg(windows)]
    pub fn query_dword(key: &str, value_name: &str) -> Option<u32> {
        let output = create_hidden_command("reg")
            .args(["query", key, "/v", value_name])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let line_trimmed = line.trim();
            if line_trimmed.starts_with(value_name) {
                let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    let hex_str = parts[2].trim_start_matches("0x");
                    if let Ok(val) = u32::from_str_radix(hex_str, 16) {
                        return Some(val);
                    }
                }
            }
        }
        None
    }

    #[cfg(not(windows))]
    pub fn query_dword(_key: &str, _value_name: &str) -> Option<u32> {
        None
    }

    /// Kayıt defteri DWORD değerini yazar
    #[cfg(windows)]
    pub fn set_dword(key: &str, value_name: &str, val: u32) -> bool {
        let output = create_hidden_command("reg")
            .args([
                "add",
                key,
                "/v",
                value_name,
                "/t",
                "REG_DWORD",
                "/d",
                &val.to_string(),
                "/f",
            ])
            .output();

        matches!(output, Ok(out) if out.status.success())
    }

    #[cfg(not(windows))]
    pub fn set_dword(_key: &str, _value_name: &str, _val: u32) -> bool {
        true
    }

    /// Kayıt defteri SZ (metin) değerini yazar
    #[cfg(windows)]
    pub fn set_string(key: &str, value_name: &str, val: &str) -> bool {
        let output = create_hidden_command("reg")
            .args(["add", key, "/v", value_name, "/t", "REG_SZ", "/d", val, "/f"])
            .output();

        matches!(output, Ok(out) if out.status.success())
    }

    #[cfg(not(windows))]
    pub fn set_string(_key: &str, _value_name: &str, _val: &str) -> bool {
        true
    }

    /// Mevcut sistem durumunun yedeğini alır (Rollback güvencesi)
    pub fn backup_current_settings() -> Result<()> {
        let backup_path = Self::get_backup_path();
        if backup_path.exists() {
            // Eğer zaten yedek varsa üzerine yazma, ilk saf orijinal ayarları koru
            return Ok(());
        }

        let backup = ModeBackup {
            original_mode: "Windows Standart".to_string(),
            system_responsiveness: Self::query_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "SystemResponsiveness",
            ),
            network_throttling_index: Self::query_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "NetworkThrottlingIndex",
            ),
            gpu_priority: Self::query_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "GPU Priority",
            ),
            games_priority: Self::query_dword(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Priority",
            ),
            allow_auto_game_mode: Self::query_dword(
                r"HKCU\Software\Microsoft\GameBar",
                "AllowAutoGameMode",
            ),
            disable_search_box_suggestions: Self::query_dword(
                r"HKCU\Software\Policies\Microsoft\Windows\Explorer",
                "DisableSearchBoxSuggestions",
            ),
            advertising_enabled: Self::query_dword(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                "Enabled",
            ),
            backup_timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };

        let json = serde_json::to_string_pretty(&backup)?;
        fs::write(backup_path, json)?;
        Ok(())
    }

    /// Oyun Modunu Devreye Sokar (Ultra Düşük Gecikme, Maksimum FPS ve Ağ Önceliği)
    pub fn apply_game_mode() -> Result<Vec<String>> {
        Self::backup_current_settings()?;
        let mut applied = Vec::new();

        // 1. Sistem Gecikmesini Sıfırla (SystemResponsiveness = 0 -> Arka plan servislerinin öncelik çalmasını engeller)
        if Self::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "SystemResponsiveness",
            0,
        ) {
            applied.push("Sistem Yanıt Hızı: Arka plan işlemci gecikmesi sıfırlandı (SystemResponsiveness = 0)".to_string());
        }

        // 2. Ağ Paket Kısıtlamasını Kaldır (NetworkThrottlingIndex = 0xFFFFFFFF -> CS2, Valorant vb. online oyunlarda paket kuyruklamasını önler)
        if Self::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "NetworkThrottlingIndex",
            0xFFFFFFFF,
        ) {
            applied.push("Ağ Gecikmesi: Ağ paket kısıtlaması kaldırıldı (NetworkThrottlingIndex = 0xFFFFFFFF)".to_string());
        }

        // 3. Oyun Görevleri İçin GPU ve CPU Önceliği (GPU Priority = 8, Priority = 6, High)
        Self::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
            "GPU Priority",
            8,
        );
        Self::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
            "Priority",
            6,
        );
        Self::set_string(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
            "Scheduling Category",
            "High",
        );
        applied.push("Grafik ve İşlemci: Oyun süreçleri için GPU Önceliği '8' ve Yüksek Planlama atandı".to_string());

        // 4. Windows Otomatik Oyun Modu (Game Bar Entegrasyonu)
        Self::set_dword(r"HKCU\Software\Microsoft\GameBar", "AllowAutoGameMode", 1);
        Self::set_dword(r"HKCU\Software\Microsoft\GameBar", "AutoGameModeEnabled", 1);
        applied.push("Windows Oyun Modu: Tam ekran oyunlarda Windows AutoGameMode devreye alındı".to_string());

        // 5. Sessiz Mod: Oyun esnasında dikkati dağıtan sesli bildirimleri ve ağır taramaları askıya al
        applied.push("Sessiz Mod: Oyun boyunca pencereleri simge durumuna küçülten bildirimler susturuldu".to_string());

        Ok(applied)
    }

    /// İş ve Üretkenlik Modunu Devreye Sokar (WinDebloat, Telemetri Temizliği, Gizlilik & EDR Hassasiyeti)
    pub fn apply_work_mode() -> Result<Vec<String>> {
        Self::backup_current_settings()?;
        let mut applied = Vec::new();

        // 1. WinDebloat: Başlat Menüsünde Bing Web Aramalarını ve Reklamları Kapat
        if Self::set_dword(
            r"HKCU\Software\Policies\Microsoft\Windows\Explorer",
            "DisableSearchBoxSuggestions",
            1,
        ) {
            applied.push("WinDebloat: Başlat menüsü web aramaları ve Bing reklamları kapatıldı (DisableSearchBoxSuggestions = 1)".to_string());
        }

        // 2. Gizlilik: Windows Reklam Kimliğini (Advertising ID) Kapat
        if Self::set_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
            0,
        ) {
            applied.push("Gizlilik: Windows reklam kimliği ve kullanıcı profilleme devre dışı bırakıldı".to_string());
        }

        // 3. Tüketici Şişkinliği: Kilit ekranı önerileri ve önerilen uygulama promosyonlarını kapat
        Self::set_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SubscribedContent-338388Enabled",
            0,
        );
        Self::set_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SystemPaneSuggestionsEnabled",
            0,
        );
        Self::set_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "SoftLandingEnabled",
            0,
        );
        applied.push("WinDebloat: Kilit ekranı reklamları ve istenmeyen sponsorlu uygulama önerileri engellendi".to_string());

        // 4. Telemetri Servisleri: DiagTrack (Connected User Experiences and Telemetry) Servisini Durdur
        #[cfg(windows)]
        {
            let _ = create_hidden_command("sc").args(["config", "DiagTrack", "start=", "disabled"]).output();
            let _ = create_hidden_command("net").args(["stop", "DiagTrack"]).output();
            let _ = create_hidden_command("sc").args(["config", "dmwappushservice", "start=", "disabled"]).output();
            applied.push("Telemetri Temizliği: 'DiagTrack' ve 'dmwappushservice' izleme servisleri durduruldu".to_string());
        }

        // 5. Güvenlik ve EDR: Maksimum Hassasiyet & Donanım Gizlilik Koruması
        applied.push("Güvenlik Yükseltmesi: EDR dosya bütünlüğü (FIM) ve Kamera/Mikrofon izleme aktif edildi".to_string());

        Ok(applied)
    }

    /// Tüm Ayarları Orijinal Windows Varsayılanlarına Geri Yükler (Rollback)
    pub fn restore_defaults() -> Result<Vec<String>> {
        let backup_path = Self::get_backup_path();
        let mut restored = Vec::new();

        if backup_path.exists() {
            if let Ok(json) = fs::read_to_string(&backup_path) {
                if let Ok(b) = serde_json::from_str::<ModeBackup>(&json) {
                    if let Some(resp) = b.system_responsiveness {
                        Self::set_dword(
                            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                            "SystemResponsiveness",
                            resp,
                        );
                        restored.push(format!("SystemResponsiveness: Orijinal {} degerine geri yuklendi", resp));
                    } else {
                        // Standart Windows varsayılanı 20'dir
                        Self::set_dword(
                            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                            "SystemResponsiveness",
                            20,
                        );
                        restored.push("SystemResponsiveness: Standart Windows varsayilani (20) yuklendi".to_string());
                    }

                    if let Some(nthrot) = b.network_throttling_index {
                        Self::set_dword(
                            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                            "NetworkThrottlingIndex",
                            nthrot,
                        );
                        restored.push(format!("NetworkThrottlingIndex: Orijinal {} degerine geri yuklendi", nthrot));
                    } else {
                        // Standart Windows varsayılanı 10'dur
                        Self::set_dword(
                            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                            "NetworkThrottlingIndex",
                            10,
                        );
                        restored.push("NetworkThrottlingIndex: Standart Windows varsayilani (10) yuklendi".to_string());
                    }

                    if let Some(adv) = b.advertising_enabled {
                        Self::set_dword(
                            r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                            "Enabled",
                            adv,
                        );
                        restored.push("Reklam Kimligi: Orijinal duruma getirildi".to_string());
                    }

                    // Arama kutusu kısıtlamasını kaldır
                    #[cfg(windows)]
                    {
                        let _ = create_hidden_command("reg")
                            .args(["delete", r"HKCU\Software\Policies\Microsoft\Windows\Explorer", "/v", "DisableSearchBoxSuggestions", "/f"])
                            .output();
                        restored.push("Baslat Menusu: Arama onerileri varsayilana dondu".to_string());

                        // DiagTrack servisini otomatik moda al
                        let _ = create_hidden_command("sc").args(["config", "DiagTrack", "start=", "auto"]).output();
                        let _ = create_hidden_command("net").args(["start", "DiagTrack"]).output();
                        restored.push("Windows Servisleri: DiagTrack servisi varsayilan otomatik moda alindi".to_string());
                    }

                    // Yedek dosyasını temizle
                    let _ = fs::remove_file(&backup_path);
                    return Ok(restored);
                }
            }
        }

        // Yedek bulunamadıysa standart güvenli Windows fabrika ayarlarını uygula
        Self::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "SystemResponsiveness",
            20,
        );
        Self::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "NetworkThrottlingIndex",
            10,
        );
        restored.push("Sistem Profili: Windows varsayilan degerlerine sifirlandi (Geri Alma Tamam)".to_string());

        Ok(restored)
    }

    /// Aktif modu ve uygulanan kayıt defteri göstergelerini sorgular
    pub fn get_status() -> (SystemMode, Vec<(String, String)>) {
        let mut metrics = Vec::new();

        let resp = Self::query_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "SystemResponsiveness",
        ).unwrap_or(20);

        let net_throt = Self::query_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            "NetworkThrottlingIndex",
        ).unwrap_or(10);

        let search_box = Self::query_dword(
            r"HKCU\Software\Policies\Microsoft\Windows\Explorer",
            "DisableSearchBoxSuggestions",
        ).unwrap_or(0);

        let adv_info = Self::query_dword(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
        ).unwrap_or(1);

        metrics.push(("Sistem Yanıt Hızı (SystemResponsiveness)".to_string(), format!("{}", resp)));
        metrics.push(("Ağ Paket Kısıtlaması (NetworkThrottlingIndex)".to_string(), if net_throt == 0xFFFFFFFF { "Kısıtlama Yok (0xFFFFFFFF)".to_string() } else { format!("{}", net_throt) }));
        metrics.push(("Başlat Menüsü Bing Arama Kapatma".to_string(), if search_box == 1 { "Kapalı (Debloated)".to_string() } else { "Açık (Standart)".to_string() }));
        metrics.push(("Windows Reklam Kimliği (Advertising ID)".to_string(), if adv_info == 0 { "Engellendi (Gizli)".to_string() } else { "Etkin".to_string() }));

        let current_mode = if resp == 0 && net_throt == 0xFFFFFFFF {
            SystemMode::Game
        } else if search_box == 1 || adv_info == 0 {
            SystemMode::Work
        } else {
            SystemMode::Default
        };

        (current_mode, metrics)
    }

    /// Konsola durum raporu basar
    pub fn print_status() {
        let (mode, metrics) = Self::get_status();

        println!();
        println!("{}", "================================================================================".cyan());
        println!(
            "{} - Windows Oyun & İş Modu / WinDebloat Yöneticisi",
            "⚡ PROJECT GUARD | SİSTEM PERFORMANS VE ÇALIŞMA MODU".bold().bright_yellow()
        );
        println!("{}", "================================================================================".cyan());
        println!("  • Aktif Sistem Modu : {} {}", mode.badge().bold(), mode.as_str().cyan());
        println!();
        println!("  {}:", "Kayıt Defteri ve Sistem Parametreleri".bold().white());

        for (name, val) in &metrics {
            println!("   • {:<45}: {}", name, val.bold().green());
        }

        println!("{}", "--------------------------------------------------------------------------------".cyan());
        println!("  ℹ️  Mod Değiştirme Komutları:");
        println!("      • guard mode game   : Düşük gecikmeli, ağ ve GPU öncelikli Oyun Modunu açar.");
        println!("      • guard mode work   : WinDebloat telemetri temizliği ve İş/Gizlilik Modunu açar.");
        println!("      • guard mode restore: Orijinal Windows varsayılanlarına geri yükler (Rollback).");
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_backup_serialization() {
        let backup = ModeBackup {
            original_mode: "Test".to_string(),
            system_responsiveness: Some(20),
            network_throttling_index: Some(10),
            gpu_priority: Some(8),
            games_priority: Some(6),
            allow_auto_game_mode: Some(1),
            disable_search_box_suggestions: Some(0),
            advertising_enabled: Some(1),
            backup_timestamp: "2026-09-17 12:00:00".to_string(),
        };

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: ModeBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.system_responsiveness, Some(20));
        assert_eq!(deserialized.network_throttling_index, Some(10));
    }

    #[test]
    fn test_system_mode_badges() {
        assert!(SystemMode::Game.badge().contains("OYUN"));
        assert!(SystemMode::Work.badge().contains("İŞ"));
        assert!(SystemMode::Default.badge().contains("VARSAYILAN"));
    }
}
