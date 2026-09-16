use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

use super::win_api::*;
use crate::core::ScanOrchestrator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbThreatItem {
    pub file_path: String,
    pub filename: String,
    pub threat_type: String,
    pub severity: String,
    pub details: String,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDriveScanReport {
    pub drive_path: String,
    pub drive_type: String,
    pub scanned_files: usize,
    pub infected_count: usize,
    pub threats: Vec<UsbThreatItem>,
}

pub struct UsbGuard {
    orchestrator: Arc<ScanOrchestrator>,
}

impl UsbGuard {
    pub fn new(orchestrator: Arc<ScanOrchestrator>) -> Self {
        Self { orchestrator }
    }

    /// Takılı olan tüm çıkarılabilir (USB) sürücüleri otomatik algılar ve tarar
    pub fn scan_all_removable(&self, quarantine: bool) -> Result<Vec<UsbDriveScanReport>> {
        let removable_drives = get_removable_drives();
        let mut reports = Vec::new();

        for drive in removable_drives {
            let rep = self.scan_drive(&drive, "Cikarilabilir USB", quarantine)?;
            reports.push(rep);
        }

        Ok(reports)
    }

    /// Belirtilen bir sürücüyü veya dizini USB/Solucan vektörlerine karşı derinlemesine tarar
    pub fn scan_drive(&self, drive_path: &Path, drive_type_str: &str, quarantine: bool) -> Result<UsbDriveScanReport> {
        let mut threats = Vec::new();
        let mut scanned_files = 0;

        if !drive_path.exists() {
            return Ok(UsbDriveScanReport {
                drive_path: drive_path.display().to_string(),
                drive_type: drive_type_str.to_string(),
                scanned_files: 0,
                infected_count: 0,
                threats: Vec::new(),
            });
        }

        // 1. Autorun.inf Özel İncelemesi (Klasik USB solucan başlatıcı)
        let autorun_path = drive_path.join("autorun.inf");
        if autorun_path.exists() {
            scanned_files += 1;
            if let Ok(content) = fs::read_to_string(&autorun_path) {
                let content_lower = content.to_lowercase();
                if content_lower.contains("open=") || content_lower.contains("shellexecute=") || content_lower.contains("action=") {
                    let mut was_quarantined = false;
                    if quarantine {
                        if let Ok(rep) = self.orchestrator.scan_single_file(&autorun_path, true) {
                            was_quarantined = rep.quarantined;
                        }
                    }

                    threats.push(UsbThreatItem {
                        file_path: autorun_path.display().to_string(),
                        filename: "autorun.inf".to_string(),
                        threat_type: "Worm.USB.MaliciousAutorun".to_string(),
                        severity: "Critical".to_string(),
                        details: "Otomatik calistirma (Autorun.inf) komutu iceren USB solucan mekanizmasi tespit edildi.".to_string(),
                        quarantined: was_quarantined,
                    });
                }
            }
        }

        // 2. Sürücüdeki dosyaları yinelemeli tara (Maksimum 2 seviye derinlik - USB hızı için)
        for entry in WalkDir::new(drive_path).max_depth(3).into_iter().flatten() {
            let path = entry.path();
            if path.is_file() {
                scanned_files += 1;
                let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                let lower_name = filename.to_lowercase();

                // LNK Kısayol Solucan Analizi
                if lower_name.ends_with(".lnk") {
                    if let Ok(bytes) = fs::read(path) {
                        let content_str = String::from_utf8_lossy(&bytes).to_lowercase();
                        if content_str.contains("cmd.exe") || content_str.contains("powershell") || content_str.contains("mshta") || content_str.contains("wscript") {
                            threats.push(UsbThreatItem {
                                file_path: path.display().to_string(),
                                filename: filename.clone(),
                                threat_type: "Worm.USB.LnkShortcutExploit".to_string(),
                                severity: "High".to_string(),
                                details: "Mesru gibi gorunen ancak komut satiri/LOLBin calistiran sahte kisayol solucani.".to_string(),
                                quarantined: false,
                            });
                        }
                    }
                }

                // Çoklu motor taraması (YARA-X, Hash, Sezgisel)
                if lower_name.ends_with(".exe") || lower_name.ends_with(".scr") || lower_name.ends_with(".vbs") || lower_name.ends_with(".bat") {
                    if let Ok(report) = self.orchestrator.scan_single_file(path, quarantine) {
                        if report.is_infected {
                            let det = report.detections.first().cloned();
                            threats.push(UsbThreatItem {
                                file_path: path.display().to_string(),
                                filename: filename.clone(),
                                threat_type: det.as_ref().map(|d| d.threat_name.clone()).unwrap_or_else(|| "Infected.Malware".to_string()),
                                severity: det.as_ref().map(|d| d.severity.to_string()).unwrap_or_else(|| "High".to_string()),
                                details: det.as_ref().map(|d| d.details.clone()).unwrap_or_default(),
                                quarantined: report.quarantined,
                            });
                        }
                    }
                }
            }
        }

        let infected_count = threats.len();
        Ok(UsbDriveScanReport {
            drive_path: drive_path.display().to_string(),
            drive_type: drive_type_str.to_string(),
            scanned_files,
            infected_count,
            threats,
        })
    }
}
