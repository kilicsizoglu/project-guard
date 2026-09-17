use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainThreat {
    pub file_path: String,
    pub package_ecosystem: String, // "npm (package.json)", "PyPI (setup.py/requirements.txt)"
    pub threat_type: String,       // "Zararli Lifecycle Scripti", "Obfuscated / Base64 Kod Yurutme", "Gizli Indirme Bileseni (Download Cradle)"
    pub severity: String,          // "Kritik", "Yuksek", "Orta"
    pub indicator: String,
    pub snippet: String,
    pub mitre_technique: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainReport {
    pub total_files_scanned: usize,
    pub vulnerable_packages_count: usize,
    pub threats: Vec<SupplyChainThreat>,
}

pub struct SupplyChainScanner;

impl SupplyChainScanner {
    /// Belirtilen proje dizininde OpenSSF & OWASP A03 standartlarına göre tedarik zinciri taraması yapar
    pub fn scan_directory(dir_path: &Path) -> SupplyChainReport {
        let mut threats = Vec::new();
        let mut files_scanned = 0;

        for entry in WalkDir::new(dir_path)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy().to_lowercase();
                // node_modules, .git, target, dist gibi klasörlerin içine gereksiz derin dalışı engelle
                name != "node_modules" && name != ".git" && name != "target" && name != "dist" && name != "build"
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();

            if file_name == "package.json" {
                files_scanned += 1;
                if let Ok(content) = fs::read_to_string(path) {
                    Self::analyze_package_json(path, &content, &mut threats);
                }
            } else if file_name == "setup.py" || file_name == "setup.cfg" {
                files_scanned += 1;
                if let Ok(content) = fs::read_to_string(path) {
                    Self::analyze_python_setup(path, &content, &mut threats);
                }
            } else if file_name == "requirements.txt" {
                files_scanned += 1;
                if let Ok(content) = fs::read_to_string(path) {
                    Self::analyze_python_requirements(path, &content, &mut threats);
                }
            }
        }

        SupplyChainReport {
            total_files_scanned: files_scanned,
            vulnerable_packages_count: threats.len(),
            threats,
        }
    }

    /// package.json içeriğini OpenSSF zararlı paket pratiklerine göre analiz eder
    pub fn analyze_package_json(path: &Path, content: &str, threats: &mut Vec<SupplyChainThreat>) {
        let val: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return,
        };

        // 1. "scripts" lifecycle kontrolleri (preinstall, postinstall, install vb.)
        if let Some(scripts) = val.get("scripts").and_then(|s| s.as_object()) {
            let dangerous_hooks = ["preinstall", "postinstall", "install", "prepublish", "prepare"];

            for &hook in &dangerous_hooks {
                if let Some(cmd_val) = scripts.get(hook).and_then(|c| c.as_str()) {
                    let cmd_lower = cmd_val.to_lowercase();

                    // Tehlikeli kabuk ve indirme kalıpları
                    let is_malicious = cmd_lower.contains("powershell")
                        && (cmd_lower.contains("-enc") || cmd_lower.contains("-w hidden") || cmd_lower.contains("downloadstring") || cmd_lower.contains("iex"));
                    let is_curl_sh = (cmd_lower.contains("curl ") || cmd_lower.contains("wget "))
                        && (cmd_lower.contains("| bash") || cmd_lower.contains("| sh") || cmd_lower.contains("|bash") || cmd_lower.contains("|sh"));
                    let is_certutil = cmd_lower.contains("certutil") && cmd_lower.contains("-urlcache");
                    let is_bitsadmin = cmd_lower.contains("bitsadmin") && cmd_lower.contains("/transfer");
                    let is_base64_eval = cmd_lower.contains("buffer.from") && cmd_lower.contains("base64") && cmd_lower.contains("eval(");

                    if is_malicious || is_curl_sh || is_certutil || is_bitsadmin || is_base64_eval {
                        threats.push(SupplyChainThreat {
                            file_path: path.to_string_lossy().to_string(),
                            package_ecosystem: "npm (package.json)".to_string(),
                            threat_type: "Zararli Lifecycle Scripti (Supply Chain Attack)".to_string(),
                            severity: "Kritik".to_string(),
                            indicator: format!("\"{}\": \"{}\"", hook, cmd_val),
                            snippet: cmd_val.chars().take(120).collect(),
                            mitre_technique: "T1195.001 / T1059.001".to_string(),
                            recommendation: format!(
                                "'{}' script kancasi sistem komutlari veya disaridan dosya indirme cradle'i calistiriyor. Paketi derhal kaldirin!",
                                hook
                            ),
                        });
                    }
                }
            }
        }

        // 2. Bilinen kötü niyetli veya typosquatted paketler
        let suspicious_pkgs = [
            "cross-env.js",
            "babelcli",
            "color-convert-js",
            "lodas-es",
            "reqwest-node",
            "electron-native-notify",
            "flatmap-stream",
            "event-stream-malicious",
        ];

        let mut check_deps = |dep_obj: Option<&serde_json::Map<String, serde_json::Value>>| {
            if let Some(deps) = dep_obj {
                for (name, _) in deps {
                    for &bad in &suspicious_pkgs {
                        if name.eq_ignore_ascii_case(bad) {
                            threats.push(SupplyChainThreat {
                                file_path: path.to_string_lossy().to_string(),
                                package_ecosystem: "npm (package.json)".to_string(),
                                threat_type: "Bilinen Zararli / Typosquatted Paket (OpenSSF)".to_string(),
                                severity: "Kritik".to_string(),
                                indicator: name.clone(),
                                snippet: format!("Dependency: {}", name),
                                mitre_technique: "T1195.001".to_string(),
                                recommendation: format!("'{}' paketi OpenSSF / GitHub Advisory veritabaninda bilinen zararli yazilim olarak listelenmistir.", name),
                            });
                        }
                    }
                }
            }
        };

        check_deps(val.get("dependencies").and_then(|d| d.as_object()));
        check_deps(val.get("devDependencies").and_then(|d| d.as_object()));
    }

    /// Python setup.py analizini yapar
    pub fn analyze_python_setup(path: &Path, content: &str, threats: &mut Vec<SupplyChainThreat>) {
        let content_lower = content.to_lowercase();

        // setup.py içinde kod çalıştırma ve ters kabuk / indirme
        let has_os_system_download = (content_lower.contains("os.system(") || content_lower.contains("subprocess.popen(") || content_lower.contains("subprocess.call("))
            && (content_lower.contains("curl") || content_lower.contains("powershell") || content_lower.contains("certutil") || content_lower.contains("wget"));

        let has_base64_exec = content_lower.contains("base64.b64decode(") && content_lower.contains("exec(");
        let has_socket_reverse_shell = content_lower.contains("socket.socket(") && (content_lower.contains("os.dup2") || content_lower.contains("connect(("));

        if has_os_system_download || has_base64_exec || has_socket_reverse_shell {
            threats.push(SupplyChainThreat {
                file_path: path.to_string_lossy().to_string(),
                package_ecosystem: "PyPI (setup.py)".to_string(),
                threat_type: "Gizli Kurulum Zamani Saldirisi (PyPI Install Hook)".to_string(),
                severity: "Kritik".to_string(),
                indicator: "setup.py icinde yetkisiz kabuk veya ters baglanti calistirma".to_string(),
                snippet: content.lines().find(|l| l.contains("exec(") || l.contains("os.system") || l.contains("base64")).unwrap_or("Zararli setup.py mantigi").trim().chars().take(120).collect(),
                mitre_technique: "T1195.001 / T1059.006".to_string(),
                recommendation: "Paket kurulum aninda arka planda sistem komutu yurutuyor. Kurulumu derhal iptal edin.".to_string(),
            });
        }
    }

    /// Python requirements.txt analizini yapar
    pub fn analyze_python_requirements(path: &Path, content: &str, threats: &mut Vec<SupplyChainThreat>) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Doğrudan bilinmeyen git/http repo URL'si yüklemeleri veya shai-hulud kalıpları
            if (line.starts_with("git+http://") || line.starts_with("http://")) && !line.contains("github.com") && !line.contains("gitlab.com") {
                threats.push(SupplyChainThreat {
                    file_path: path.to_string_lossy().to_string(),
                    package_ecosystem: "PyPI (requirements.txt)".to_string(),
                    threat_type: "Guvenli Olmayan Dis Kaynak Bagimliligi (HTTP Git)".to_string(),
                    severity: "Yuksek".to_string(),
                    indicator: line.to_string(),
                    snippet: line.to_string(),
                    mitre_technique: "T1195.001".to_string(),
                    recommendation: "Bagimlilik sifresiz HTTP veya guvenilmeyen bir git deposundan cekiliyor.".to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_json_malicious_preinstall() {
        let malicious_json = r#"{
            "name": "fake-utility",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "powershell -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A..."
            }
        }"#;

        let mut threats = Vec::new();
        SupplyChainScanner::analyze_package_json(Path::new("dummy/package.json"), malicious_json, &mut threats);

        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].severity, "Kritik");
        assert!(threats[0].threat_type.contains("Lifecycle Scripti"));
    }

    #[test]
    fn test_package_json_clean() {
        let clean_json = r#"{
            "name": "clean-app",
            "version": "1.0.0",
            "scripts": {
                "build": "tsc",
                "test": "jest"
            },
            "dependencies": {
                "react": "^18.2.0"
            }
        }"#;

        let mut threats = Vec::new();
        SupplyChainScanner::analyze_package_json(Path::new("dummy/package.json"), clean_json, &mut threats);

        assert!(threats.is_empty());
    }

    #[test]
    fn test_python_setup_malicious_exec() {
        let malicious_py = r#"
import os, base64
from setuptools import setup

exec(base64.b64decode('cHJpbnQoImhhY2tlZCIp'))
setup(name='evil_pkg', version='0.1')
"#;

        let mut threats = Vec::new();
        SupplyChainScanner::analyze_python_setup(Path::new("dummy/setup.py"), malicious_py, &mut threats);

        assert_eq!(threats.len(), 1);
        assert!(threats[0].threat_type.contains("Kurulum Zamani"));
    }
}
