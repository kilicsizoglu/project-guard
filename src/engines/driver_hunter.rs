use anyhow::Result;
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha256Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverThreatReport {
    pub driver_path: String,
    pub driver_name: String,
    pub sha256: String,
    pub md5: String,
    pub cve: Option<String>,
    pub category: String,
    pub mitre_id: String,
    pub severity: String,
    pub description: String,
    pub is_staging: bool,
}

pub struct DriverHunter;

impl DriverHunter {
    /// Bilinen en kritik savunmasız (BYOVD) sürücülerin imza kütüphanesini oluşturur
    fn get_curated_loldrivers() -> HashMap<&'static str, (&'static str, &'static str, &'static str)> {
        // Driver Name -> (CVE, Severity, Açıklama)
        let mut m = HashMap::new();
        m.insert("gdrv.sys", ("CVE-2018-19320", "Critical", "Gigabyte kernel sürücüsü. Ring0 rastgele bellek okuma/yazma ve EDR sonlandırma yeteneği."));
        m.insert("mhyprot2.sys", ("N/A (Genshin Anti-Cheat)", "Critical", "Ransomware (LockBit) tarafından antivirüsleri devre dışı bırakmak için kullanılan imzalı sürücü."));
        m.insert("dbutil_2_3.sys", ("CVE-2021-21551", "Critical", "Dell firmware update sürücüsü. Yetki yükseltme ve çekirdek seviyesi arbitrer kod yürütme."));
        m.insert("rtcore64.sys", ("CVE-2019-16098", "Critical", "MSI Afterburner çekirdek sürücüsü. Korumalı süreçleri ve antivirüsleri bellekten silme açığı."));
        m.insert("procexp.sys", ("Sysinternals Abuse", "High", "Process Explorer sürücüsü. Kötü amaçlı yazılımlar tarafından güvenlik servislerini öldürmek için suistimal edilir."));
        m.insert("procexp152.sys", ("Sysinternals Abuse", "High", "Process Explorer 15.2 sürücüsü. Arbitrer süreç sonlandırma istismarı."));
        m.insert("asiodrv.sys", ("CVE-2020-12928", "High", "ASUS ASUSTeK Winbond Hardware Doctor sürücüsü. Yetki yükseltme açığı."));
        m.insert("kprocesshacker.sys", ("ProcessHacker Abuse", "High", "Process Hacker çekirdek sürücüsü. Antivirüs korumalı süreçleri sonlandırmak için kullanılır."));
        m.insert("cpuz141.sys", ("CVE-2017-15303", "High", "CPU-Z sürücüsü. Çekirdek bellek manipülasyonu açığı."));
        m.insert("winring0x64.sys", ("CVE-2020-14979", "High", "WinRing0 donanım erişim sürücüsü. Arbitrer fiziksel bellek okuma/yazma."));
        m.insert("atsiv.sys", ("Kernel Code Injection", "Critical", "İmzasız çekirdek kodlarını yüklemek için istismar edilen sürücü."));
        m.insert("gmer.sys", ("Rootkit Detector Abuse", "High", "GMER sürücüsü. Kötü niyetli aktörlerce güvenlik hook'larını kaldırmak için kullanılır."));
        m.insert("echo.sys", ("Echotrail Vulnerable", "High", "Yetki yükseltme ve sürücü bloğu atlatma sürücüsü."));
        m.insert("iqvw64e.sys", ("CVE-2015-2291", "Critical", "Intel Network Adapter Diagnostics sürücüsü. Çekirdek bellek bozma açığı."));
        m.insert("speedfan.sys", ("CVE-2007-5633", "High", "SpeedFan sıcaklık sürücüsü. Arbitrer bellek erişim istismarı."));
        m.insert("amifldrv64.sys", ("AMI Flasher Abuse", "High", "AMI BIOS güncelleme sürücüsü. Arbitrer fiziksel adres yazma."));
        m
    }

    /// Bilinen kritik BYOVD SHA-256 hash listesi (LOLDrivers.io)
    fn get_known_loldriver_hashes() -> HashMap<&'static str, (&'static str, &'static str, &'static str)> {
        let mut m = HashMap::new();
        // Hash -> (DriverName, CVE, Açıklama)
        m.insert("32f34aab87f6cac866307a14297155681648a5609e7345869f8b8860e4cb47f5", ("gdrv.sys", "CVE-2018-19320", "Gigabyte Vulnerable Driver"));
        m.insert("0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5", ("dbutil_2_3.sys", "CVE-2021-21551", "Dell Vulnerable Driver"));
        m.insert("046e1bcdf2b3c38bd373884215372938f222d543c15f048d54724116e6428e3d", ("mhyprot2.sys", "Ransomware Weaponized", "Genshin Anti-Cheat BYOVD"));
        m.insert("012781423719ff8b438257008cfc2b7405c12330b62b76fcad4eb7c5690b9b32", ("rtcore64.sys", "CVE-2019-16098", "MSI Afterburner Driver"));
        m.insert("b467cb54c5b369528646b5a324cae42ff3d22e0325b7b6294eb84e56598c19a9", ("iqvw64e.sys", "CVE-2015-2291", "Intel Diagnostics Driver"));
        m
    }

    /// Bir dosyanın SHA256 ve MD5 hash'lerini hesaplar
    pub fn hash_file(path: &Path) -> Result<(String, String)> {
        let mut file = File::open(path)?;
        let mut sha256_hasher = Sha256::new();
        let mut md5_hasher = Md5::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            sha256_hasher.update(&buffer[..bytes_read]);
            md5_hasher.update(&buffer[..bytes_read]);
        }

        let sha256_bytes = sha256_hasher.finalize();
        let md5_bytes = md5_hasher.finalize();
        let sha256 = sha256_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let md5 = md5_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        Ok((sha256, md5))
    }

    /// Tek bir sürücü dosyasını analiz eder
    pub fn inspect_driver_file(path: &Path, is_staging: bool) -> Option<DriverThreatReport> {
        let filename = path.file_name()?.to_string_lossy().to_string();
        let ext = path.extension()?.to_string_lossy().to_lowercase();
        if ext != "sys" {
            return None;
        }

        let (sha256, md5) = Self::hash_file(path).ok()?;
        let curated_names = Self::get_curated_loldrivers();
        let curated_hashes = Self::get_known_loldriver_hashes();

        let filename_lower = filename.to_lowercase();

        // 1. Hash Eşleşmesi (En Kesin Doğrulama)
        if let Some(&(name, cve, desc)) = curated_hashes.get(sha256.as_str()) {
            return Some(DriverThreatReport {
                driver_path: path.to_string_lossy().to_string(),
                driver_name: filename,
                sha256,
                md5,
                cve: Some(cve.to_string()),
                category: "LOLDrivers Bilinen Savunmasız Çekirdek Sürücüsü (BYOVD)".to_string(),
                mitre_id: "T1068".to_string(),
                severity: "Critical".to_string(),
                description: format!("[DOĞRULANMIŞ HASH] {} - {}. Ring0 ayrıcalık yükseltme ve güvenlik yazılımlarını sonlandırma tehdidi!", name, desc),
                is_staging,
            });
        }

        // 2. İsim ve İmza Eşleşmesi
        for (&known_name, &(cve, sev, desc)) in &curated_names {
            if filename_lower == known_name || filename_lower.starts_with(&known_name.replace(".sys", "")) {
                let severity = if is_staging { "Critical" } else { sev };
                let staging_note = if is_staging {
                    " [DİKKAT: Geçici hazırlık dizininde bulundu! Aktif saldırı şüphesi!]"
                } else {
                    ""
                };

                return Some(DriverThreatReport {
                    driver_path: path.to_string_lossy().to_string(),
                    driver_name: filename,
                    sha256,
                    md5,
                    cve: Some(cve.to_string()),
                    category: "Potansiyel Savunmasız Çekirdek Sürücüsü (BYOVD)".to_string(),
                    mitre_id: "T1068".to_string(),
                    severity: severity.to_string(),
                    description: format!("{}{}. Saldırganlar bu sürücüyü kullanarak çekirdek korumalarını kapatabilir.", desc, staging_note),
                    is_staging,
                });
            }
        }

        // 3. Geçici Dizinde SYS Dosyası Tespiti (Staging Anomali)
        if is_staging {
            return Some(DriverThreatReport {
                driver_path: path.to_string_lossy().to_string(),
                driver_name: filename,
                sha256,
                md5,
                cve: None,
                category: "Şüpheli Sürücü Hazırlama (Driver Staging)".to_string(),
                mitre_id: "T1562.001".to_string(),
                severity: "High".to_string(),
                description: "Kullanıcı / Geçici dizinde .SYS çekirdek sürücüsü tespit edildi. Meşru sürücüler geçici klasörlerde bulunmamalıdır.".to_string(),
                is_staging: true,
            });
        }

        None
    }

    /// Windows Sürücü Dizinini ve Geçici Hazırlık (Staging) Alanlarını tarar
    pub fn scan_all() -> Result<Vec<DriverThreatReport>> {
        let mut reports = Vec::new();

        // 1. Windows Sistem Sürücüler Klasörü: C:\Windows\System32\drivers
        let drivers_dir = PathBuf::from(r"C:\Windows\System32\drivers");
        if drivers_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&drivers_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(rep) = Self::inspect_driver_file(&path, false) {
                            reports.push(rep);
                        }
                    }
                }
            }
        }

        // 2. Geçici Hazırlık Dizinleri (Staging Areas)
        let mut staging_dirs = Vec::new();
        if let Ok(temp) = std::env::var("TEMP") {
            staging_dirs.push(PathBuf::from(temp));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            staging_dirs.push(PathBuf::from(appdata));
        }
        staging_dirs.push(PathBuf::from(r"C:\Users\Public"));
        staging_dirs.push(PathBuf::from(r"C:\Windows\Temp"));

        for dir in staging_dirs {
            if dir.exists() {
                // Sadece kök ve 1 alt seviyeyi tara (performans için)
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(rep) = Self::inspect_driver_file(&path, true) {
                                reports.push(rep);
                            }
                        }
                    }
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
    fn test_known_gdrv_by_name() {
        let dummy_path = Path::new(r"C:\test\gdrv.sys");
        // İsim kontrolü
        let names = DriverHunter::get_curated_loldrivers();
        assert!(names.contains_key("gdrv.sys"));
        let (cve, sev, _) = names.get("gdrv.sys").unwrap();
        assert_eq!(*cve, "CVE-2018-19320");
        assert_eq!(*sev, "Critical");
    }

    #[test]
    fn test_known_mhyprot2_byovd() {
        let names = DriverHunter::get_curated_loldrivers();
        assert!(names.contains_key("mhyprot2.sys"));
    }

    #[test]
    fn test_known_driver_hash_lookup() {
        let hashes = DriverHunter::get_known_loldriver_hashes();
        let hash = "32f34aab87f6cac866307a14297155681648a5609e7345869f8b8860e4cb47f5";
        assert!(hashes.contains_key(hash));
        let (name, cve, _) = hashes.get(hash).unwrap();
        assert_eq!(*name, "gdrv.sys");
        assert_eq!(*cve, "CVE-2018-19320");
    }
}
