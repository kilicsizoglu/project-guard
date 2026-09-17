use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use yara_x::Compiler;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraSyncStats {
    pub total_rules_files: usize,
    pub successfully_added: usize,
    pub failed_validation: usize,
    pub current_on_disk_files: Vec<String>,
    pub message: String,
}

pub struct YaraSyncManager {
    rules_dir: PathBuf,
}

impl YaraSyncManager {
    pub fn new(rules_dir: PathBuf) -> Self {
        Self { rules_dir }
    }

    /// Tüm yerleşik ve uzak topluluk YARA kurallarını senkronize eder
    pub fn sync_all_rules(&self) -> Result<YaraSyncStats> {
        if !self.rules_dir.exists() {
            fs::create_dir_all(&self.rules_dir)?;
        }

        let mut added = 0;
        let mut failed = 0;

        // 1. Cobalt Strike Beacon & C2 Stager İmzaları
        let cobalt_strike_rules = format!(
            "rule Cobalt_Strike_Beacon_Signatures {{\n    meta:\n        description = \"Cobalt Strike Beacon memory\"\n        threat_level = \"Critical\"\n        author = \"Community / Project Guard DFIR\"\n    strings:\n        $pipe1 = \"\\\\\\\\.\\\\pipe\\\\{}\" ascii nocase\n        $pipe2 = \"\\\\\\\\.\\\\pipe\\\\{}\" ascii nocase\n        $pipe3 = \"\\\\\\\\.\\\\pipe\\\\{}\" ascii nocase\n        $cs1 = \"%s as %s\\\\%s: %d\" ascii\n        $cs2 = \"Started service %s on %s\" ascii\n        $cs3 = \"{}\" ascii\n        $cs4 = \"beacon.{}.dll\" ascii nocase\n        $cs5 = \"beacon.{}.dll\" ascii nocase\n    condition:\n        2 of them\n}}",
            "MSSE-", "status_", "postex_", "ReflectiveLoader", "x64", "x86"
        );
        if self.validate_and_save("cobalt_strike.yar", &cobalt_strike_rules).is_ok() {
            added += 1;
        } else {
            failed += 1;
        }

        // 2. Fidye Yazılımı (Ransomware) Not ve Şifreleme İmzaları
        let ransomware_rules = format!(
            "rule Modern_Ransomware_Family_Indicators {{\n    meta:\n        description = \"Modern Ransomware Defense Matrix\"\n        threat_level = \"Critical\"\n        author = \"Community / Project Guard DFIR\"\n    strings:\n        $note1 = \"All your files have been {}\" ascii nocase wide\n        $note2 = \"Restore-My-{}\" ascii nocase\n        $note3 = \"readme_for_{}.txt\" ascii nocase\n        $note4 = \"{}_INFORMATION.html\" ascii nocase\n        $cmd1 = \"vssadmin {} shadows /all /quiet\" ascii nocase\n        $cmd2 = \"wbadmin {} catalog -quiet\" ascii nocase\n        $cmd3 = \"bcdedit /set {{default}} bootstatuspolicy {}\" ascii nocase\n        $cmd4 = \"bcdedit /set {{default}} recoveryenabled {}\" ascii nocase\n    condition:\n        2 of them\n}}",
            "encrypted", "Files", "decrypt", "DECRYPT", "delete", "delete", "ignoreallfailures", "no"
        );
        if self.validate_and_save("ransomware_families.yar", &ransomware_rules).is_ok() {
            added += 1;
        } else {
            failed += 1;
        }

        // 3. Bilgi Çalıcılar (Infostealers: RedLine, Vidar, Lumma, Racoon)
        let infostealer_rules = format!(
            "rule Infostealer_Target_Artifacts {{\n    meta:\n        description = \"Browser and credential vault artifacts\"\n        threat_level = \"High\"\n        author = \"Community / Project Guard DFIR\"\n    strings:\n        $path1 = \"\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\{}\" ascii nocase wide\n        $path2 = \"\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles\" ascii nocase wide\n        $path3 = \"\\\\AppData\\\\Local\\\\Microsoft\\\\Edge\\\\User Data\" ascii nocase wide\n        $path4 = \"\\\\AppData\\\\Roaming\\\\Telegram Desktop\\\\{}\" ascii nocase wide\n        $path5 = \"\\\\AppData\\\\Roaming\\\\discord\\\\Local Storage\" ascii nocase wide\n        $func1 = \"{}\" ascii\n        $func2 = \"sqlite3_open\" ascii\n    condition:\n        3 of them\n}}",
            "Login Data", "tdata", "CryptUnprotectData"
        );
        if self.validate_and_save("infostealers.yar", &infostealer_rules).is_ok() {
            added += 1;
        } else {
            failed += 1;
        }


        // 4. Uzak Topluluk Kural Havuzları (YARA-Forge & GitHub Vetted Rules)
        let remote_repos = [
            (
                "community_webshells.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/Webshells/Wshell_PHP.yar",
            ),
            (
                "community_exploit_kits.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/Exploit-Kits/EK_Blackhole.yar",
            ),
        ];

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("ProjectGuard-ThreatHunter/2.0")
            .build();

        if let Ok(client) = client {
            for (fname, url) in remote_repos {
                if let Ok(resp) = client.get(url).send() {
                    if resp.status().is_success() {
                        if let Ok(content) = resp.text() {
                            if self.validate_and_save(fname, &content).is_ok() {
                                added += 1;
                            } else {
                                failed += 1;
                            }
                        }
                    }
                }
            }
        }

        let disk_files = self.list_disk_rules();

        Ok(YaraSyncStats {
            total_rules_files: disk_files.len(),
            successfully_added: added,
            failed_validation: failed,
            current_on_disk_files: disk_files,
            message: format!(
                "YARA kurallari basariyla senkronize edildi: {} yeni kural eklendi/guncellendi, {} hatali kural elendi.",
                added, failed
            ),
        })
    }

    /// Kuralı YARA-X ile derleyip doğrular, ardından kaydeder
    pub fn validate_and_save(&self, filename: &str, content: &str) -> Result<()> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(content)
            .with_context(|| format!("YARA kural derleme hatasi: {}", filename))?;

        let path = self.rules_dir.join(filename);
        fs::write(&path, content)?;
        Ok(())
    }

    /// Disk üzerindeki aktif kural dosyalarını listeler
    pub fn list_disk_rules(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.rules_dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        if let Some(ext) = entry.path().extension() {
                            if ext == "yar" || ext == "yara" {
                                names.push(entry.file_name().to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }
        names.sort();
        names
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_yara_sync_rule_validation_and_storage() {
        let temp_dir = std::env::temp_dir().join(format!("guard_yara_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let manager = YaraSyncManager::new(temp_dir.clone());
        let valid_rule = r#"
rule Unit_Test_Rule {
    meta:
        description = "Test kurali"
    strings:
        $s1 = "EvilPayloadTest123"
    condition:
        $s1
}
"#;
        assert!(manager.validate_and_save("test.yar", valid_rule).is_ok());

        let invalid_rule = r#"
rule Invalid_Syntax_Rule {
    broken_syntax_here
}
"#;
        assert!(manager.validate_and_save("invalid.yar", invalid_rule).is_err());

        let files = manager.list_disk_rules();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], "test.yar");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
