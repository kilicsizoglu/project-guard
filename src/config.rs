use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Project Guard Merkezi Yapılandırma Şeması Versiyonu
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Ana Yapılandırma Kök Modeli
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuardConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub rtp: RtpConfig,

    #[serde(default)]
    pub exclusions: ExclusionConfig,

    #[serde(default)]
    pub privacy: PrivacyConfig,

    #[serde(default)]
    pub system_mode: SystemModeConfig,

    #[serde(default)]
    pub feeds: ThreatFeedsConfig,

    #[serde(default)]
    pub edr: EdrPoliciesConfig,
}

fn default_schema_version() -> u32 {
    CONFIG_SCHEMA_VERSION
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            general: GeneralConfig::default(),
            rtp: RtpConfig::default(),
            exclusions: ExclusionConfig::default(),
            privacy: PrivacyConfig::default(),
            system_mode: SystemModeConfig::default(),
            feeds: ThreatFeedsConfig::default(),
            edr: EdrPoliciesConfig::default(),
        }
    }
}

/// 1. Genel ve Sistem Yapılandırması
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeneralConfig {
    /// Arayüz ve bildirim dili: "tr" | "en"
    pub language: String,
    /// Windows başlangıcında otomatik başlatma (Run anahtarı)
    pub start_with_windows: bool,
    /// Kapatıldığında arka planda korumayı sürdür
    pub minimize_to_tray: bool,
    /// Arka plan hizmeti olarak 7/24 çalışma tercihi
    pub run_as_service: bool,
    /// Günlükleme seviyesi: "info" | "debug" | "warn" | "error"
    pub log_level: String,
    /// Harici SIEM / Webhook bildirimi (Opsiyonel HTTP/HTTPS URL)
    pub remote_syslog_webhook: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            language: "tr".to_string(),
            start_with_windows: false,
            minimize_to_tray: true,
            run_as_service: false,
            log_level: "info".to_string(),
            remote_syslog_webhook: None,
        }
    }
}

/// 2. Gerçek Zamanlı Koruma (RTP) Yapılandırması
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RtpConfig {
    /// Gerçek zamanlı dosya izleme ana anahtarı
    pub enabled: bool,
    /// Gerçek zamanlı izlenen dizinler
    pub monitored_paths: Vec<String>,
    /// Tehdit tespit edildiğinde uygulanacak aksiyon:
    /// "auto_quarantine" (varsayılan) | "block_and_alert" | "log_only"
    pub action_on_threat: String,
    /// Anlık taranacak azami dosya boyutu (Megabayt, varsayılan: 250 MB)
    pub max_file_size_mb: u64,
    /// Arşiv dosyalarının (.zip, .rar, .7z) içini tara
    pub scan_archives: bool,
    /// Arşiv tarama azami derinliği (Zip-bomb koruması)
    pub archive_max_depth: u32,
    /// Sezgisel (Heuristic) davranış motorunu RTP'de etkinleştir
    pub scan_heuristics: bool,
    /// Dosya yazma anında YARA kurallarını değerlendir
    pub scan_yara: bool,
}

impl Default for RtpConfig {
    fn default() -> Self {
        let mut default_paths = Vec::new();
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            let base = PathBuf::from(user_profile);
            let downloads = base.join("Downloads");
            let desktop = base.join("Desktop");
            if let Some(s) = downloads.to_str() {
                default_paths.push(s.to_string());
            }
            if let Some(s) = desktop.to_str() {
                default_paths.push(s.to_string());
            }
        }
        if let Some(temp) = std::env::var_os("TEMP") {
            if let Some(s) = PathBuf::from(temp).to_str() {
                default_paths.push(s.to_string());
            }
        }
        if default_paths.is_empty() {
            default_paths.push(r"C:\Users\Public".to_string());
        }

        Self {
            enabled: true,
            monitored_paths: default_paths,
            action_on_threat: "auto_quarantine".to_string(),
            max_file_size_mb: 250,
            scan_archives: true,
            archive_max_depth: 3,
            scan_heuristics: true,
            scan_yara: true,
        }
    }
}

/// 3. Dışlamalar ve Beyaz Liste (Exclusions & Whitelist)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExclusionConfig {
    /// Taramadan muaf tutulan klasör ve dosya yolları
    pub excluded_paths: Vec<String>,
    /// Taramadan muaf tutulan dosya uzantıları
    pub excluded_extensions: Vec<String>,
    /// Taramadan muaf tutulan güvenilir süreç adları
    pub excluded_processes: Vec<String>,
    /// Güvenilir kabul edilen SHA-256 karma listesi
    pub trusted_hashes_sha256: Vec<String>,
}

impl Default for ExclusionConfig {
    fn default() -> Self {
        Self {
            excluded_paths: vec![
                r"C:\Program Files\Git".to_string(),
                r"node_modules".to_string(),
                r".git".to_string(),
                r"target".to_string(),
            ],
            excluded_extensions: vec![
                ".iso".to_string(),
                ".vmdk".to_string(),
                ".vhdx".to_string(),
                ".log".to_string(),
            ],
            excluded_processes: vec![
                "code.exe".to_string(),
                "devenv.exe".to_string(),
                "cargo.exe".to_string(),
                "rustc.exe".to_string(),
            ],
            trusted_hashes_sha256: Vec::new(),
        }
    }
}

/// 4. Donanım ve Kamera/Mikrofon Gizliliği (Privacy Guard)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrivacyConfig {
    /// Donanım gizlilik izleyicisi aktif mi
    pub enabled: bool,
    /// Kayıt defteri polling denetim sıklığı (saniye)
    pub poll_interval_seconds: u64,
    /// Kamera açıldığında bildirim ver
    pub alert_on_camera: bool,
    /// Mikrofon açıldığında bildirim ver
    pub alert_on_microphone: bool,
    /// Windows İşlem Merkezi yerel Toast bildirimi fırlat
    pub notify_toast: bool,
    /// Güvenilir kabul edilen görüntülü görüşme / medya uygulamaları
    pub whitelisted_apps: Vec<String>,
    /// Bilinmeyen/şüpheli süreçlerin kamera erişiminde sert uyarı ver
    pub strict_untrusted_alert: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_seconds: 2,
            alert_on_camera: true,
            alert_on_microphone: true,
            notify_toast: true,
            whitelisted_apps: vec![
                "zoom.exe".to_string(),
                "teams.exe".to_string(),
                "discord.exe".to_string(),
                "slack.exe".to_string(),
                "chrome.exe".to_string(),
                "msedge.exe".to_string(),
                "firefox.exe".to_string(),
                "obs64.exe".to_string(),
                "skype.exe".to_string(),
            ],
            strict_untrusted_alert: true,
        }
    }
}

/// 5. Windows Oyun ve İş Modu (WinDebloat & Performance)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemModeConfig {
    /// Tam ekran oyun veya 3D uygulama açıldığında otomatik Oyun Modu devreye girsin
    pub auto_game_mode: bool,
    /// İş Moduna geçildiğinde telemetri, Bing ve kilit ekranı önerilerini debloat et
    pub debloat_on_work_mode: bool,
    /// Arka plan tarayıcısının tüketebileceği azami CPU yüzdesi (10% - 100%)
    pub background_cpu_limit_percent: u32,
    /// Cihaz pilde çalışırken derin arka plan taramalarını beklemeye al
    pub pause_scans_on_battery: bool,
}

impl Default for SystemModeConfig {
    fn default() -> Self {
        Self {
            auto_game_mode: false,
            debloat_on_work_mode: true,
            background_cpu_limit_percent: 40,
            pause_scans_on_battery: true,
        }
    }
}

/// 6. Tehdit İstihbaratı Akışları (Threat Feeds)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatFeedsConfig {
    /// Otomatik periyodik imza güncellemesi aktif mi
    pub auto_update_enabled: bool,
    /// Güncelleme sıklığı (saat)
    pub update_interval_hours: u32,
    /// USOM (Ulusal Siber Olaylara Müdahale Merkezi) feed'i
    pub usom_enabled: bool,
    /// Abuse.ch MalwareBazaar aktif hash feed'i
    pub malwarebazaar_enabled: bool,
    /// Abuse.ch ThreatFox IOC feed'i
    pub threatfox_enabled: bool,
    /// Abuse.ch URLhaus zararlı link feed'i
    pub urlhaus_enabled: bool,
    /// The Spamhaus Project DROP / eDROP botnet feed'i
    pub spamhaus_enabled: bool,
    /// SANS ISC DShield en çok saldıran IP'ler feed'i
    pub sans_dshield_enabled: bool,
    /// YARA-Forge topluluk kuralları feed'i
    pub yara_forge_enabled: bool,
    /// Kurumsal hava boşluğu (Air-gapped) / İnternetsiz çalışma modu
    pub offline_airgapped_mode: bool,
}

impl Default for ThreatFeedsConfig {
    fn default() -> Self {
        Self {
            auto_update_enabled: true,
            update_interval_hours: 6,
            usom_enabled: true,
            malwarebazaar_enabled: true,
            threatfox_enabled: true,
            urlhaus_enabled: true,
            spamhaus_enabled: true,
            sans_dshield_enabled: true,
            yara_forge_enabled: true,
            offline_airgapped_mode: false,
        }
    }
}

/// 7. EDR Otomatik Yanıt Politikaları (EDR Automated Response)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdrPoliciesConfig {
    /// Fidye yazılımı yem (Canary) tuzağı tetiklendiğinde:
    /// "kill_process" (anında sonlandır) | "alert_only" (yalnızca uyar)
    pub canary_trip_action: String,
    /// Bellek içi unbacked RWX enjeksiyon tespitinde:
    /// "suspend_thread" (iş parçacığını askıya al) | "kill_process" | "log_only"
    pub memory_injection_action: String,
    /// Kritik LOLBAS kötüye kullanımında süreci otomatik sonlandır
    pub lolbas_auto_kill: bool,
    /// Kötüye kullanılan çekirdek sürücüsü (BYOVD) tespitinde alarm üret
    pub byovd_driver_alert: bool,
    /// Bilinen C2 IP bağlantılarını yerel güvenlik duvarı ile blokla
    pub network_c2_block: bool,
}

impl Default for EdrPoliciesConfig {
    fn default() -> Self {
        Self {
            canary_trip_action: "kill_process".to_string(),
            memory_injection_action: "suspend_thread".to_string(),
            lolbas_auto_kill: false,
            byovd_driver_alert: true,
            network_c2_block: true,
        }
    }
}

// -----------------------------------------------------------------------------
// GuardConfig Dosya I/O ve Yönetim Metotları
// -----------------------------------------------------------------------------

impl GuardConfig {
    /// Yapılandırma dosyasının saklanacağı birincil ve güvenli konumu belirler
    pub fn config_file_path() -> PathBuf {
        // 1. Kullanıcı profili: %USERPROFILE%\.project_guard\config.json
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            let user_dir = PathBuf::from(user_profile).join(".project_guard");
            return user_dir.join("config.json");
        }

        // 2. Sistem genelinde fallback: C:\ProgramData\ProjectGuard\config.json
        let sys_dir = PathBuf::from(r"C:\ProgramData\ProjectGuard");
        sys_dir.join("config.json")
    }

    /// Yapılandırmayı diskten okur. Dosya yoksa veya bozuksa güvenli varsayılanları döner ve kaydeder.
    pub fn load() -> Self {
        let path = Self::config_file_path();
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<GuardConfig>(&content) {
                    Ok(mut cfg) => {
                        // Şema versiyon güncellemesi ve eksik alanların validasyonu
                        if cfg.schema_version != CONFIG_SCHEMA_VERSION {
                            cfg.schema_version = CONFIG_SCHEMA_VERSION;
                            let _ = cfg.save();
                        }
                        return cfg;
                    }
                    Err(e) => {
                        eprintln!(
                            "[UYARI] Yapılandırma dosyası okunamadı veya bozulmuş ({}). Varsayılan ayarlara geçiliyor.",
                            e
                        );
                    }
                },
                Err(e) => {
                    eprintln!("[UYARI] Yapılandırma dosyası okunamadı: {}", e);
                }
            }
        }

        // Dosya bulunamadı veya geçersiz; fabrika varsayılanlarını oluştur ve kaydet
        let default_cfg = Self::default();
        let _ = default_cfg.save();
        default_cfg
    }

    /// Yapılandırmayı atomik olarak diske kaydeder (.tmp dosyası oluşturup rename eder)
    pub fn save(&self) -> Result<()> {
        self.validate()
            .map_err(|e| anyhow::anyhow!("Yapılandırma doğrulanamadı: {}", e))?;

        let target_path = Self::config_file_path();
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Yapılandırma dizini oluşturulamadı: {:?}", parent))?;
        }

        let tmp_path = target_path.with_extension("json.tmp");
        let json_str = serde_json::to_string_pretty(self)
            .context("Yapılandırma JSON formatına serileştirilemedi")?;

        fs::write(&tmp_path, json_str.as_bytes())
            .with_context(|| format!("Geçici yapılandırma dosyası yazılamadı: {:?}", tmp_path))?;

        // Atomik rename
        if let Err(e) = fs::rename(&tmp_path, &target_path) {
            // Windows'ta hedef dosya varsa rename bazen başarısız olabilir, fallback remove + rename
            let _ = fs::remove_file(&target_path);
            fs::rename(&tmp_path, &target_path).with_context(|| {
                format!(
                    "Atomik yapılandırma dosyası taşınamadı: {:?} -> {:?}, hata: {}",
                    tmp_path, target_path, e
                )
            })?;
        }

        Ok(())
    }

    /// Yapılandırmayı fabrika ayarlarına sıfırlar ve kaydeder
    pub fn reset() -> Result<Self> {
        let default_cfg = Self::default();
        default_cfg.save()?;
        Ok(default_cfg)
    }

    /// Alanların sınırlarını ve tutarlılığını doğrular
    pub fn validate(&self) -> Result<(), String> {
        // Dil kontrolü
        if self.general.language != "tr" && self.general.language != "en" {
            return Err("Dil seçeneği yalnızca 'tr' veya 'en' olabilir.".to_string());
        }

        // RTP aksiyon kontrolü
        match self.rtp.action_on_threat.as_str() {
            "auto_quarantine" | "block_and_alert" | "log_only" => {}
            other => {
                return Err(format!(
                    "Geçersiz RTP aksiyonu: '{}'. Kabul edilenler: auto_quarantine, block_and_alert, log_only",
                    other
                ));
            }
        }

        // Dosya boyutu kontrolü (en az 1 MB, en fazla 5000 MB)
        if self.rtp.max_file_size_mb == 0 || self.rtp.max_file_size_mb > 5000 {
            return Err("Azami RTP dosya boyutu 1 ile 5000 MB arasında olmalıdır.".to_string());
        }

        // CPU limiti kontrolü (10% - 100%)
        if self.system_mode.background_cpu_limit_percent < 10
            || self.system_mode.background_cpu_limit_percent > 100
        {
            return Err("Arka plan CPU sınırı %10 ile %100 arasında olmalıdır.".to_string());
        }

        // Gizlilik polling kontrolü (en az 1 saniye, en fazla 60 saniye)
        if self.privacy.poll_interval_seconds == 0 || self.privacy.poll_interval_seconds > 60 {
            return Err("Gizlilik denetim aralığı 1 ile 60 saniye arasında olmalıdır.".to_string());
        }

        // EDR yanıt politikaları kontrolü
        match self.edr.canary_trip_action.as_str() {
            "kill_process" | "alert_only" => {}
            other => return Err(format!("Geçersiz Canary aksiyonu: '{}'", other)),
        }

        match self.edr.memory_injection_action.as_str() {
            "suspend_thread" | "kill_process" | "log_only" => {}
            other => return Err(format!("Geçersiz bellek enjeksiyon aksiyonu: '{}'", other)),
        }

        Ok(())
    }

    /// Anahtar-değer yoluyla (path.to.key) ayar değerini string olarak sorgular
    pub fn get_value_by_key(&self, key: &str) -> Option<String> {
        let value = serde_json::to_value(self).ok()?;
        let parts: Vec<&str> = key.split('.').collect();
        let mut curr = &value;
        for part in parts {
            curr = curr.get(part)?;
        }
        if let Some(s) = curr.as_str() {
            Some(s.to_string())
        } else {
            Some(curr.to_string())
        }
    }

    /// Anahtar-değer yoluyla (path.to.key) ayarı günceller
    pub fn set_value_by_key(&mut self, key: &str, raw_val: &str) -> Result<()> {
        let mut value = serde_json::to_value(&*self)
            .context("Yapılandırma JSON değerine dönüştürülemedi")?;

        let parts: Vec<&str> = key.split('.').collect();
        if parts.is_empty() {
            bail!("Geçersiz ayar anahtarı");
        }

        // Pointer mantığıyla JSON'u güncelle
        let mut curr = &mut value;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                let parsed_val: serde_json::Value = if let Ok(b) = raw_val.parse::<bool>() {
                    serde_json::Value::Bool(b)
                } else if let Ok(n) = raw_val.parse::<u64>() {
                    serde_json::Value::Number(n.into())
                } else if let Ok(n) = raw_val.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else {
                    // String veya tırnakları temizle
                    let clean = raw_val.trim_matches('"');
                    serde_json::Value::String(clean.to_string())
                };
                if let Some(obj) = curr.as_object_mut() {
                    obj.insert(part.to_string(), parsed_val);
                } else {
                    bail!("Ayar ağacında hedef alan bir nesne değil: {}", key);
                }
            } else {
                curr = curr.get_mut(*part).ok_or_else(|| {
                    anyhow::anyhow!("Ayar anahtarı yolunda kategori bulunamadı: {}", part)
                })?;
            }
        }

        let updated_cfg: GuardConfig = serde_json::from_value(value)
            .context("Ayar değeri uygulandıktan sonra yapılandırma şeması doğrulanamadı")?;
        updated_cfg
            .validate()
            .map_err(|e| anyhow::anyhow!("Doğrulama hatası: {}", e))?;

        *self = updated_cfg;
        self.save()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Birim Testleri
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validity() {
        let cfg = GuardConfig::default();
        assert_eq!(cfg.schema_version, CONFIG_SCHEMA_VERSION);
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.general.language, "tr");
        assert!(cfg.rtp.enabled);
        assert_eq!(cfg.rtp.action_on_threat, "auto_quarantine");
        assert_eq!(cfg.privacy.poll_interval_seconds, 2);
        assert!(cfg.feeds.usom_enabled);
        assert!(!cfg.feeds.offline_airgapped_mode);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let mut cfg = GuardConfig::default();
        cfg.general.language = "en".to_string();
        cfg.rtp.max_file_size_mb = 500;
        cfg.system_mode.background_cpu_limit_percent = 60;
        cfg.exclusions.excluded_paths.push(r"D:\SafeCode".to_string());

        let json = serde_json::to_string_pretty(&cfg).expect("Serialization failed");
        let deserialized: GuardConfig =
            serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(cfg, deserialized);
        assert_eq!(deserialized.general.language, "en");
        assert_eq!(deserialized.rtp.max_file_size_mb, 500);
        assert_eq!(deserialized.system_mode.background_cpu_limit_percent, 60);
        assert!(deserialized
            .exclusions
            .excluded_paths
            .contains(&r"D:\SafeCode".to_string()));
    }

    #[test]
    fn test_config_validation_rejects_invalid() {
        let mut cfg = GuardConfig::default();

        // Geçersiz dil
        cfg.general.language = "de".to_string();
        assert!(cfg.validate().is_err());
        cfg.general.language = "tr".to_string();

        // Geçersiz dosya boyutu (0 MB veya aşırı büyük)
        cfg.rtp.max_file_size_mb = 0;
        assert!(cfg.validate().is_err());
        cfg.rtp.max_file_size_mb = 10000;
        assert!(cfg.validate().is_err());
        cfg.rtp.max_file_size_mb = 250;

        // Geçersiz CPU sınırı (%5)
        cfg.system_mode.background_cpu_limit_percent = 5;
        assert!(cfg.validate().is_err());
        cfg.system_mode.background_cpu_limit_percent = 120;
        assert!(cfg.validate().is_err());
        cfg.system_mode.background_cpu_limit_percent = 40;

        // Geçersiz RTP aksiyonu
        cfg.rtp.action_on_threat = "format_disk".to_string();
        assert!(cfg.validate().is_err());
        cfg.rtp.action_on_threat = "auto_quarantine".to_string();

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_get_and_set_by_key() {
        let mut cfg = GuardConfig::default();

        let lang = cfg.get_value_by_key("general.language");
        assert_eq!(lang, Some("tr".to_string()));

        let rtp_max = cfg.get_value_by_key("rtp.max_file_size_mb");
        assert_eq!(rtp_max, Some("250".to_string()));

        // Değer güncelleme testi
        let res = cfg.set_value_by_key("general.language", "en");
        assert!(res.is_ok());
        assert_eq!(cfg.general.language, "en");

        let res_num = cfg.set_value_by_key("rtp.max_file_size_mb", "350");
        assert!(res_num.is_ok());
        assert_eq!(cfg.rtp.max_file_size_mb, 350);

        // Hatalı anahtar testi
        let res_invalid = cfg.set_value_by_key("nonexistent.key", "val");
        assert!(res_invalid.is_err());
    }
}
