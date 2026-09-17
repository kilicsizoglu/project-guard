use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;

fn default_decoy_type() -> String {
    "Ransomware Canary / Lure".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryFileRecord {
    pub path: String,
    pub filename: String,
    #[serde(default = "default_decoy_type")]
    pub decoy_type: String,
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
    pub decoy_type: String,
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

    /// CISA (Cybersecurity and Infrastructure Security Agency) 16 Eylül 2026 "Using Cyber Decoys" doktrinine
    /// uygun olarak hem dosya tuzakları hem de Honeytoken kimlik/erişim belirteçleri yerleştirir.
    pub fn deploy_canaries(&self, target_dir: &Path) -> Result<Vec<CanaryFileRecord>> {
        if !target_dir.exists() {
            fs::create_dir_all(target_dir)?;
        }

        let decoys: [(&str, &[u8], &str); 8] = [
            (
                "!00_financial_records_confidential.docx",
                b"CONFIDENTIAL CORPORATE BALANCE SHEET 2026 - DO NOT MODIFY OR SHARE.",
                "Ransomware Canary / Document Lure",
            ),
            (
                "!00_passwords_vault_backup.xlsx",
                b"MASTER CREDENTIAL BACKUP DATABASE ENCRYPTED CONTAINER 2026.",
                "Ransomware Canary / Document Lure",
            ),
            (
                "!00_accounting_ledger_tax_audit.pdf",
                b"%PDF-1.4 %CANARY-TRAP-FILE-FOR-PROJECT-GUARD-RANSOMWARE-DETECTION",
                "Ransomware Canary / Document Lure",
            ),
            (
                "!00_aws_cloud_credentials.env",
                b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n# CISA HONEYTOKEN DECOY - PROJECT GUARD SURVEILLANCE",
                "CISA Honeytoken / Cloud Credentials",
            ),
            (
                "!00_corporate_master_vault.kdbx",
                b"\x03\xd9\xa2\x9a\x02\x00\x01\x00KDBX-CANARY-HONEYTOKEN-TRAP-PROJECT-GUARD-SECURITY",
                "CISA Honeytoken / Password Vault Container",
            ),
            (
                "!00_production_db_connection.config",
                b"Server=prod-sql-cluster.corp.internal;Database=EnterpriseCore;User Id=sa_canary;Password=DecoySecretTrapKey2026!;",
                "CISA Honeytoken / Database Secrets",
            ),
            (
                "!00_github_deploy_tokens.env",
                b"GITHUB_TOKEN=ghp_CanaryDecoyTrapTokenForProjectGuard2026\nGITHUB_ORG=CorpInternalOps\n# CISA HONEYTOKEN - TRIPWIRE SURVEILLANCE",
                "CISA Honeytoken / GitHub Access Token",
            ),
            (
                "!00_azure_service_principal.json",
                b"{\n  \"clientId\": \"c15a-canary-0000-0000-000000000000\",\n  \"clientSecret\": \"DecoySecretTrapValue~ProjectGuard2026\",\n  \"tenantId\": \"tenant-honeytoken-guard\"\n}",
                "CISA Honeytoken / Azure Service Principal",
            ),
        ];

        let now = chrono::Utc::now().to_rfc3339();
        let mut existing = self.load_records()?;
        let mut newly_deployed = Vec::new();

        for (filename, content, decoy_type) in decoys {
            let file_path = target_dir.join(filename);
            fs::write(&file_path, content)
                .with_context(|| format!("Yem dosyasi yazilamadi: {:?}", file_path))?;

            let sha256 = Self::calculate_sha256(content);
            let path_str = file_path.to_string_lossy().to_string();

            let record = CanaryFileRecord {
                path: path_str.clone(),
                filename: filename.to_string(),
                decoy_type: decoy_type.to_string(),
                initial_sha256: sha256,
                deployed_at: now.clone(),
            };

            existing.insert(path_str, record.clone());
            newly_deployed.push(record);
        }

        self.save_records(&existing)?;
        Ok(newly_deployed)
    }

    /// CISA Breadcrumbs (Ekmek Kırıntıları) mimarisi gereği sistemdeki genel dizinlere (C:\Users\Public vb.) tuzaklar serper
    pub fn deploy_breadcrumbs(&self) -> Result<Vec<CanaryFileRecord>> {
        let mut deployed = Vec::new();
        let public_docs = PathBuf::from(r"C:\Users\Public\Documents");
        if public_docs.exists() {
            if let Ok(mut recs) = self.deploy_canaries(&public_docs) {
                deployed.append(&mut recs);
            }
        }
        Ok(deployed)
    }

    /// Mevcut tüm yem dosyalarının ve Honeytoken'ların bütünlüğünü denetler
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
                    decoy_type: rec.decoy_type.clone(),
                    status: "Silindi (Supheli Fidye / Veri Silme Saldirisi!)".to_string(),
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
                                decoy_type: rec.decoy_type.clone(),
                                status: "Sifrelendi / Degistirildi (Fidye Yazilimi / Honeytoken Erisimi!)".to_string(),
                                is_compromised: true,
                            });
                        } else {
                            intact += 1;
                            files.push(CanaryFileStatus {
                                path: rec.path.clone(),
                                filename: rec.filename.clone(),
                                decoy_type: rec.decoy_type.clone(),
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
                            decoy_type: rec.decoy_type.clone(),
                            status: "Erisim Engellendi (Kilitli / Sifreleniyor)".to_string(),
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
                "[+] FIDYE YAZILIMI VE CISA HONEYTOKEN TUZAKLARI DEVREDE! Izlenen Dizin: {:?}",
                watch_dir
            )
            .red()
            .bold()
        );
        println!("{}", "[*] Yem dosyalarina yapilacak sifreleme, silme veya bal belirteci erisimi aninda yakalanacaktir.\n".yellow());

        for event in rx {
            match event.kind {
                EventKind::Modify(_) | EventKind::Remove(_) => {
                    for path in event.paths {
                        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                        if filename.starts_with("!00_") {
                            println!(
                                "\n{}",
                                "!!!!!!!!!!!!!!!!!!! [ CISA CYBER DECOY / RANSOMWARE SALDIRI TESPITI ] !!!!!!!!!!!!!!!!!!!"
                                    .red()
                                    .bold()
                            );
                            println!("Tuzak / Honeytoken Kurcalandi: {}", path.display().to_string().yellow().bold());
                            println!("Olay Turu: {:?}", event.kind);
                            println!("ACIL UYARI: Sistemdeki bir surec dosyalari sifrelemeye, silmeye veya Honeytoken calmaya basladi!");
                            println!(
                                "{}\n",
                                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_deployment_and_cisa_honeytokens() {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("guard_canary_test_{}", unique_id));
        let _ = fs::create_dir_all(&tmp);

        let mgr = CanaryManager::new(&tmp);

        let target_dir = tmp.join("traps");
        let deployed = mgr.deploy_canaries(&target_dir).unwrap();

        assert_eq!(deployed.len(), 8);
        assert!(deployed.iter().any(|d| d.filename.contains("aws_cloud_credentials")));
        assert!(deployed.iter().any(|d| d.filename.contains("corporate_master_vault")));
        assert!(deployed.iter().any(|d| d.filename.contains("financial_records")));
        assert!(deployed.iter().any(|d| d.filename.contains("github_deploy_tokens")));
        assert!(deployed.iter().any(|d| d.filename.contains("azure_service_principal")));

        // İlk denetimde hepsi sağlam olmalı
        let status = mgr.check_status().unwrap();
        assert_eq!(status.total_deployed, 8);
        assert_eq!(status.intact_count, 8);
        assert_eq!(status.compromised_count, 0);

        // Bir dosyayı tahrif et (şifrelenmiş gibi yap)
        let aws_file = target_dir.join("!00_aws_cloud_credentials.env");
        fs::write(&aws_file, b"ENCRYPTED BY RANSOMWARE GANG").unwrap();

        let status2 = mgr.check_status().unwrap();
        assert_eq!(status2.intact_count, 7);
        assert_eq!(status2.compromised_count, 1);
        let tampered = status2.files.iter().find(|f| f.is_compromised).unwrap();
        assert!(tampered.status.contains("Sifrelendi"));

        // Bir dosyayı sil (saldırganın iz silmesi gibi)
        let doc_file = target_dir.join("!00_financial_records_confidential.docx");
        fs::remove_file(&doc_file).unwrap();

        let status3 = mgr.check_status().unwrap();
        assert_eq!(status3.intact_count, 6);
        assert_eq!(status3.compromised_count, 2);

        // Temizlik
        let _ = fs::remove_dir_all(&tmp);
    }
}
