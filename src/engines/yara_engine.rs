use super::trait_engine::{FileHashes, ScanEngine, Severity, ThreatDetection};
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    rules: Arc<RwLock<Rules>>,
    rules_dir: PathBuf,
}

const BUILTIN_RULES: &str = r#"
rule EICAR_Test_File {
    meta:
        description = "Standart Antivirus Test Dosyasi (EICAR)"
        threat_level = "Test"
        author = "Project Guard"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Webshell_PHP {
    meta:
        description = "PHP Webshell veya Arka Kapi Deseni"
        threat_level = "High"
    strings:
        $p1 = "passthru($_" ascii nocase
        $p2 = "shell_exec($_" ascii nocase
        $p3 = "system($_" ascii nocase
        $p4 = "eval(base64_decode(" ascii nocase
        $p5 = "assert($_POST" ascii nocase
        $p6 = "assert($_REQUEST" ascii nocase
    condition:
        any of them
}

rule Suspicious_PowerShell_Obfuscation {
    meta:
        description = "Gizlenmis PowerShell Calistirici / Dropper"
        threat_level = "High"
    strings:
        $ps1 = "powershell -enc" ascii nocase
        $ps2 = "powershell.exe -encodedcommand" ascii nocase
        $ps3 = "powershell -w hidden" ascii nocase
        $ps4 = "FromBase64String(" ascii nocase
        $ps5 = "IEX (New-Object Net.WebClient)" ascii nocase
        $ps6 = "DownloadString(\"http" ascii nocase
    condition:
        2 of them
}

rule Ransomware_Note_Signatures {
    meta:
        description = "Fidye Yazilimi (Ransomware) Notu Sablonlari"
        threat_level = "Critical"
    strings:
        $r1 = "all your files have been encrypted" ascii nocase
        $r2 = "your personal files are encrypted" ascii nocase
        $r3 = "pay bitcoin to the following address" ascii nocase
        $r4 = "decrypt your files" ascii nocase
        $r5 = ".onion" ascii nocase
    condition:
        3 of them
}
"#;

impl YaraEngine {
    pub fn new(rules_dir: PathBuf) -> Result<Self> {
        let rules = Self::compile_rules(&rules_dir)?;
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            rules_dir,
        })
    }

    fn compile_rules(rules_dir: &Path) -> Result<Rules> {
        let mut compiler = Compiler::new();

        // Built-in kuralları derle
        compiler
            .add_source(BUILTIN_RULES)
            .map_err(|e| anyhow::anyhow!("Built-in YARA kurali derleme hatasi: {}", e))?;

        // Kurallar dizini varsa oradaki tüm .yar/.yara dosyalarını ekle
        if rules_dir.exists() {
            if let Ok(entries) = fs::read_dir(rules_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                        if ext == "yar" || ext == "yara" {
                            if let Ok(source) = fs::read_to_string(&path) {
                                let _ = compiler.add_source(source.as_str());
                            }
                        }
                    }
                }
            }
        }

        let compiled = compiler.build();
        Ok(compiled)
    }

    pub fn reload_rules(&self) -> Result<()> {
        let new_rules = Self::compile_rules(&self.rules_dir)?;
        let mut guard = self
            .rules
            .write()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        *guard = new_rules;
        Ok(())
    }
}

impl ScanEngine for YaraEngine {
    fn name(&self) -> &'static str {
        "YARA-X-Rule-Engine"
    }

    fn description(&self) -> &'static str {
        "VirusTotal YARA-X ile derin bayt paterni ve acik kural seti tarayicisi"
    }

    fn scan(
        &self,
        _path: &Path,
        content: &[u8],
        _hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>> {
        let rules_guard = self
            .rules
            .read()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let mut scanner = Scanner::new(&rules_guard);
        let scan_results = scanner
            .scan(content)
            .map_err(|e| anyhow::anyhow!("YARA tarama hatasi: {:?}", e))?;

        let mut matches = scan_results.matching_rules();
        if let Some(matched_rule) = matches.next() {
            let rule_name = matched_rule.identifier().to_string();
            let severity = if rule_name.contains("Ransom") {
                Severity::Critical
            } else if rule_name.contains("EICAR") {
                Severity::Suspicious
            } else {
                Severity::High
            };

            return Ok(Some(ThreatDetection {
                threat_name: format!("Yara.Match.{}", rule_name),
                engine_name: self.name().to_string(),
                severity,
                details: format!("YARA-X Kural Deseni Eslesmesi: [{}]", rule_name),
                rule_name: Some(rule_name),
            }));
        }

        Ok(None)
    }
}
