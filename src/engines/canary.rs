use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryFileRecord {
    pub path: String,
    pub filename: String,
    pub initial_sha256: String,
    pub deployed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryStatus {
    pub total_deployed: usize,
    pub intact_count: usize,
    pub compromised_count: usize,
    pub files: Vec<CanaryFileStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryFileStatus {
    pub path: String,
    pub filename: String,
    pub status: String, // "Guvenli", "Modifiye Edildi (Saldiri)", "Silindi"
    pub is_compromised: bool,
}

pub struct CanaryManager {
    state_file: PathBuf,
}

impl CanaryManager {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            state_file: base_dir.join("canaries.json"),
        }
    }

    fn calculate_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let res = hasher.finalize();
        let mut s = String::with_capacity(64);
        for b in res {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Belirtilen dizine stratejik yem (canary/decoy) tuzak dosyaları yerleştirir
    pub fn deploy_canaries(&self, target_dir: &Path) -> Result<Vec<CanaryFileRecord>> {
        if !target_dir.exists() {
            fs::create_dir_all(target_dir)?;
        }

        let decoys: [(&str, &[u8]); 3] = [
            (
                "!00_financial_records_confidential.docx",
                b"CONFIDENTIAL CORPORATE BALANCE SHEET 2026 - DO NOT MODIFY OR SHARE.",
            ),
            (
                "!00_passwords_vault_backup.xlsx",
                b"MASTER CREDENTIAL BACKUP DATABASE ENCRYPTED CONTAINER 2026.",
            ),
            (
                "!00_accounting_ledger_tax_audit.pdf",
                b"%PDF-1.4 %CANARY-TRAP-FILE-FOR-PROJECT-GUARD-RANSOMWARE-DETECTION",
            ),
        ];

        let now = chrono::Utc::now().to_rfc3339();
        let mut existing = self.load_records()?;
        let mut newly_deployed = Vec::new();

        for (filename, content) in decoys {
            let file_path = target_dir.join(filename);
            fs::write(&file_path, content)
                .with_context(|| format!("Yem dosyasi yazilamadi: {:?}", file_path))?;

            let sha256 = Self::calculate_sha256(content);
            let path_str = file_path.to_string_lossy().to_string();

            let record = CanaryFileRecord {
                path: path_str.clone(),
                filename: filename.to_string(),
                initial_sha256: sha256,
                deployed_at: now.clone(),
            };

            existing.insert(path_str, record.clone());
            newly_deployed.push(record);
        }

        self.save_records(&existing)?;
        Ok(newly_deployed)
    }

    /// Mevcut tüm yem dosyalarının bütünlüğünü denetler
    pub fn check_status(&self) -> Result<CanaryStatus> {
        let records = self.load_records()?;
        let mut files = Vec::new();
        let mut intact = 0;
        let mut compromised = 0;

        for (_, rec) in records {
            let p = Path::new(&rec.path);
            if !p.exists() {
                compromised += 1;
                files.push(CanaryFileStatus {
                    path: rec.path.clone(),
                    filename: rec.filename.clone(),
                    status: "Silindi (Supheli Fidye Saldirisi!)".to_string(),
                    is_compromised: true,
                });
            } else {
                match fs::read(p) {
                    Ok(bytes) => {
                        let cur_hash = Self::calculate_sha256(&bytes);
                        if cur_hash != rec.initial_sha256 {
                            compromised += 1;
                            files.push(CanaryFileStatus {
                                path: rec.path.clone(),
                                filename: rec.filename.clone(),
                                status: "Sifrelendi / Degistirildi (Fidye Yazilimi Tespiti!)".to_string(),
                                is_compromised: true,
                            });
                        } else {
                            intact += 1;
                            files.push(CanaryFileStatus {
                                path: rec.path.clone(),
                                filename: rec.filename.clone(),
                                status: "Guvenli (Bozulmadi)".to_string(),
                                is_compromised: false,
                            });
                        }
                    }
                    Err(_) => {
                        compromised += 1;
                        files.push(CanaryFileStatus {
                            path: rec.path.clone(),
                            filename: rec.filename.clone(),
                            status: "Erisim Engellendi (Kilitli)".to_string(),
                            is_compromised: true,
                        });
                    }
                }
            }
        }

        Ok(CanaryStatus {
            total_deployed: intact + compromised,
            intact_count: intact,
            compromised_count: compromised,
            files,
        })
    }

    /// Gerçek zamanlı olarak yem dosyalarına yapılacak saldırıları dinler
    pub fn watch_canaries(&self, watch_dir: &Path) -> Result<()> {
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
                "[+] FIDYE YAZILIMI KAPANI (CANARY TRAP) DEVREDE! Izlenen Dizin: {:?}",
                watch_dir
            )
            .red()
            .bold()
        );
        println!("{}", "[*] Yem dosyalarina yapilacak sifreleme veya silme aninda yakalanacaktir.\n".yellow());

        for event in rx {
            match event.kind {
                EventKind::Modify(_) | EventKind::Remove(_) => {
                    for path in event.paths {
                        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                        if filename.starts_with("!00_") {
                            println!(
                                "\n{}",
                                "!!!!!!!!!!!!!!!!!!! [ RANSOMWARE SALDIRI TESPITI ] !!!!!!!!!!!!!!!!!!!"
                                    .red()
                                    .bold()
                            );
                            println!("Yem Dosyasi Kurcalandi: {}", path.display().to_string().yellow().bold());
                            println!("Olay Turu: {:?}", event.kind);
                            println!("ACIL UYARI: Sistemdeki bir surec dosyalari sifrelemeye veya silmeye basladi!");
                            println!(
                                "{}\n",
                                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                                    .red()
                                    .bold()
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn load_records(&self) -> Result<HashMap<String, CanaryFileRecord>> {
        if !self.state_file.exists() {
            return Ok(HashMap::new());
        }
        let content = fs::read_to_string(&self.state_file)?;
        let map: HashMap<String, CanaryFileRecord> = serde_json::from_str(&content).unwrap_or_default();
        Ok(map)
    }

    fn save_records(&self, map: &HashMap<String, CanaryFileRecord>) -> Result<()> {
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(map)?;
        fs::write(&self.state_file, json)?;
        Ok(())
    }
}
