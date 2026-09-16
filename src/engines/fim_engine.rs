use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimItem {
    pub path: String,
    pub description: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub modified_at: String,
    pub is_critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimCheckReport {
    pub path: String,
    pub description: String,
    pub status: String,
    pub baseline_hash: Option<String>,
    pub current_hash: Option<String>,
    pub severity: String,
    pub details: String,
}

pub struct FimEngine {
    baseline_file: PathBuf,
}

impl FimEngine {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            baseline_file: base_dir.join("fim_baseline.json"),
        }
    }

    /// Varsayılan kritik sistem ve güvenlik dosyalarının listesini döner
    pub fn get_default_monitored_paths() -> Vec<(&'static str, &'static str, bool)> {
        vec![
            (
                r"C:\Windows\System32\drivers\etc\hosts",
                "DNS Çözümleme Dosyası (Zararlı DNS Hijacking ve AV bloklama hedefi)",
                true,
            ),
            (
                r"C:\Windows\System32\drivers\etc\networks",
                "Ağ Yapılandırma Dosyası",
                false,
            ),
            (
                r"C:\Windows\System32\cmd.exe",
                "Windows Komut İstemi İkilisi",
                true,
            ),
            (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "Windows PowerShell Ana İkilisi",
                true,
            ),
            (
                r"C:\Windows\System32\dnsapi.dll",
                "DNS İstemci API Kütüphanesi",
                true,
            ),
        ]
    }

    /// Bir dosyanın SHA256 hash değerini hesaplar
    pub fn calculate_sha256(path: &Path) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hash_bytes = hasher.finalize();
        Ok(hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
    }

    /// İzlenen dosyalar için temiz kriptografik referans (baseline) oluşturur ve kaydeder
    pub fn create_baseline(&self) -> Result<Vec<FimItem>> {
        let mut items = Vec::new();
        let monitored = Self::get_default_monitored_paths();

        for (path_str, desc, is_crit) in monitored {
            let p = Path::new(path_str);
            if p.exists() && p.is_file() {
                if let Ok(hash) = Self::calculate_sha256(p) {
                    let meta = p.metadata().ok();
                    let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    let modified = meta
                        .and_then(|m| m.modified().ok())
                        .map(|t| {
                            let datetime: chrono::DateTime<Utc> = t.into();
                            datetime.to_rfc3339()
                        })
                        .unwrap_or_else(|| Utc::now().to_rfc3339());

                    items.push(FimItem {
                        path: path_str.to_string(),
                        description: desc.to_string(),
                        sha256: hash,
                        size_bytes: size,
                        modified_at: modified,
                        is_critical: is_crit,
                    });
                }
            }
        }

        // JSON olarak diske kaydet
        if let Some(parent) = self.baseline_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json_str = serde_json::to_string_pretty(&items)
            .with_context(|| "FIM referans verisi JSON'a donusturulemedi")?;
        std::fs::write(&self.baseline_file, json_str)?;

        Ok(items)
    }

    /// Mevcut referans (baseline) verilerini okur
    pub fn load_baseline(&self) -> Result<Vec<FimItem>> {
        if !self.baseline_file.exists() {
            return self.create_baseline();
        }
        let content = std::fs::read_to_string(&self.baseline_file)?;
        let items: Vec<FimItem> = serde_json::from_str(&content)?;
        Ok(items)
    }

    /// Sistemin mevcut durumunu kayıtlı referansla karşılaştırır (Bütünlük Doğrulama)
    pub fn check_integrity(&self) -> Result<Vec<FimCheckReport>> {
        let baseline = self.load_baseline()?;
        let mut reports = Vec::new();

        for item in baseline {
            let p = Path::new(&item.path);
            if !p.exists() {
                reports.push(FimCheckReport {
                    path: item.path.clone(),
                    description: item.description.clone(),
                    status: "Eksik / Silinmiş (Deleted)".to_string(),
                    baseline_hash: Some(item.sha256.clone()),
                    current_hash: None,
                    severity: if item.is_critical { "Critical".to_string() } else { "High".to_string() },
                    details: "Kritik sistem dosyası diskte bulunamadı. Silinmiş veya taşınmış olabilir!".to_string(),
                });
                continue;
            }

            match Self::calculate_sha256(p) {
                Ok(current_hash) => {
                    if current_hash == item.sha256 {
                        reports.push(FimCheckReport {
                            path: item.path.clone(),
                            description: item.description.clone(),
                            status: "Bozulmamış (Intact)".to_string(),
                            baseline_hash: Some(item.sha256.clone()),
                            current_hash: Some(current_hash),
                            severity: "Clean".to_string(),
                            details: "Kriptografik SHA-256 hash değeri referansla tam eşleşiyor. Dosya orijinal.".to_string(),
                        });
                    } else {
                        reports.push(FimCheckReport {
                            path: item.path.clone(),
                            description: item.description.clone(),
                            status: "Yetkisiz Değiştirilmiş (Tampered)".to_string(),
                            baseline_hash: Some(item.sha256.clone()),
                            current_hash: Some(current_hash),
                            severity: if item.is_critical { "Critical".to_string() } else { "High".to_string() },
                            details: "UYARI: Dosya içeriği referans oluşturulduktan sonra değiştirilmiş! Zararlı kod enjeksiyonu veya DNS hijacking şüphesi!".to_string(),
                        });
                    }
                }
                Err(e) => {
                    reports.push(FimCheckReport {
                        path: item.path.clone(),
                        description: item.description.clone(),
                        status: "Erişim Hatası (Locked/Denied)".to_string(),
                        baseline_hash: Some(item.sha256.clone()),
                        current_hash: None,
                        severity: "High".to_string(),
                        details: format!("Dosya okunamadı: {}", e),
                    });
                }
            }
        }

        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fim_baseline_and_tamper_detection() {
        let temp_dir = std::env::temp_dir().join("guard_fim_test");
        let _ = std::fs::create_dir_all(&temp_dir);

        let test_file = temp_dir.join("test_critical.txt");
        std::fs::write(&test_file, b"Original Authentic Content").unwrap();

        let fim = FimEngine::new(&temp_dir);
        let hash1 = FimEngine::calculate_sha256(&test_file).unwrap();

        // Modifiye et
        std::fs::write(&test_file, b"Tampered Content Injected").unwrap();
        let hash2 = FimEngine::calculate_sha256(&test_file).unwrap();

        assert_ne!(hash1, hash2);

        // Temizle
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
