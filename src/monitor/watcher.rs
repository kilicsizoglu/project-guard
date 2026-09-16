use crate::core::ScanOrchestrator;
use anyhow::Result;
use colored::Colorize;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::Duration;

pub struct RealTimeMonitor {
    orchestrator: Arc<ScanOrchestrator>,
}

impl RealTimeMonitor {
    pub fn new(orchestrator: Arc<ScanOrchestrator>) -> Self {
        Self { orchestrator }
    }

    pub fn start_monitoring(&self, watch_dir: &Path, auto_quarantine: bool) -> Result<()> {
        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        )?;

        watcher.watch(watch_dir, RecursiveMode::Recursive)?;

        println!(
            "{}",
            format!(
                "[*] Gercek Zamanli Koruma (RTP) Aktif! Izlenen Dizin: {:?}",
                watch_dir
            )
            .green()
            .bold()
        );
        println!(
            "[*] Otomatik Karantina: {}",
            if auto_quarantine {
                "ETKIN (Zararlilar aninda izole edilecek)".yellow().bold()
            } else {
                "PASIF (Yalnizca uyari uretilecek)".white()
            }
        );
        println!("{}", "[*] Cikis icin Ctrl+C tuslarina basiniz...\n".bright_black());

        for event in rx {
            // Dosya oluşturulma veya değiştirilme olaylarını filtrele
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        // Karantina veya gizli dosyalardaki değişiklikleri yoksay
                        let path_str = path.to_string_lossy();
                        if path_str.contains(".project_guard") || path_str.contains(".git") {
                            continue;
                        }

                        if path.is_file() {
                            // Dosya yazımının bitmesi için kısa bir süre bekle (Windows dosya kilidi)
                            std::thread::sleep(Duration::from_millis(50));

                            match self.orchestrator.scan_single_file(&path, auto_quarantine) {
                                Ok(report) => {
                                    if report.is_infected {
                                        println!(
                                            "\n{}",
                                            "=================== [ ! ] TEHDIT TESPIT EDILDI [ ! ] ==================="
                                                .red()
                                                .bold()
                                        );
                                        println!("Dosya: {}", path.display().to_string().yellow());
                                        println!("Boyut: {} bayt", report.file_size);
                                        println!("SHA256: {}", report.sha256);

                                        for det in &report.detections {
                                            println!(
                                                "Motor: {} | Tehdit: {} | Seviye: {}",
                                                det.engine_name.cyan(),
                                                det.threat_name.red().bold(),
                                                det.severity.to_string().magenta()
                                            );
                                            println!("Detay: {}", det.details);
                                        }

                                        if report.quarantined {
                                            println!(
                                                "{}",
                                                "[+] TEHDIT BASARIYLA KARANTINAYA ALINDI VE ETKISIZ HALE GETIRILDI."
                                                    .green()
                                                    .bold()
                                            );
                                        } else if auto_quarantine {
                                            println!(
                                                "{}",
                                                "[-] TEHDIT KARANTINAYA ALINAMADI (Kilitli veya erisim reddedildi)."
                                                    .red()
                                            );
                                        }
                                        println!(
                                            "{}\n",
                                            "========================================================================"
                                                .red()
                                                .bold()
                                        );
                                    }
                                }
                                Err(_) => {
                                    // Dosya hala yazılıyor veya kilitli olabilir, sessiz kal
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
