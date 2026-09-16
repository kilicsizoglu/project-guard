use super::pe_analyzer::PeAnalyzer;
use super::trait_engine::{FileHashes, ScanEngine, Severity, ThreatDetection};
use anyhow::Result;
use std::path::Path;

pub struct HeuristicEngine;

impl HeuristicEngine {
    pub fn new() -> Self {
        Self
    }

    /// Shannon entropi hesaplama (0.0 - 8.0 araligi)
    /// 7.2'nin uzeri genellikle sikistirilmis, paketlenmis (packed) veya sifrelenmis zararli yukleri gosterir.
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequencies = [0usize; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequencies {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Cift uzanti (Double Extension) tespiti (Orn: invoice.pdf.exe)
    fn check_double_extension(file_name: &str) -> bool {
        let parts: Vec<&str> = file_name.split('.').collect();
        if parts.len() >= 3 {
            let dangerous_exts = ["exe", "vbs", "bat", "cmd", "scr", "ps1", "js", "hta", "pif"];
            let decoy_exts = ["pdf", "docx", "xlsx", "jpg", "jpeg", "png", "zip", "txt"];

            let last_ext = parts.last().unwrap_or(&"").to_lowercase();
            let second_last_ext = parts[parts.len() - 2].to_lowercase();

            if dangerous_exts.contains(&last_ext.as_str())
                && decoy_exts.contains(&second_last_ext.as_str())
            {
                return true;
            }
        }
        false
    }
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanEngine for HeuristicEngine {
    fn name(&self) -> &'static str {
        "Heuristic-Behavior-Engine"
    }

    fn description(&self) -> &'static str {
        "Statik PE baslik, derin bolum analizi, entropi ve anomali tespit motoru"
    }

    fn scan(
        &self,
        path: &Path,
        content: &[u8],
        _hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>> {
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        // 1. Cift uzanti kontrolu
        if Self::check_double_extension(&file_name) {
            return Ok(Some(ThreatDetection {
                threat_name: "Heur.Suspicious.DoubleExtension".to_string(),
                engine_name: self.name().to_string(),
                severity: Severity::High,
                details: format!(
                    "Gizlenmis cift dosya uzantisi tespit edildi: '{}'",
                    file_name
                ),
                rule_name: Some("double_extension".to_string()),
            }));
        }

        // 2. Windows PE Derin Statik Analizi (Bölümler, Packer, W^X İhlali, API Kümeleri)
        if content.len() > 64 && content.starts_with(b"MZ") {
            if let Some(pe_info) = PeAnalyzer::analyze(content) {
                // W^X İhlali kontrolü (Hem yazılabilir hem çalıştırılabilir bellek)
                if pe_info.has_wx_section {
                    return Ok(Some(ThreatDetection {
                        threat_name: "Heur.PE.DangerousSectionPermissions".to_string(),
                        engine_name: self.name().to_string(),
                        severity: Severity::Critical,
                        details: format!(
                            "Kritik W^X Ihlali: Calistirilabilir kod bolumleri ayni zamanda yazilabilir. Shellcode/Crypter gostergesi: {:?}",
                            pe_info.suspicious_sections
                        ),
                        rule_name: Some("wx_section_violation".to_string()),
                    }));
                }

                // Şüpheli API Kümeleri (Process Injection / Keylogger vb.)
                if !pe_info.suspicious_api_indicators.is_empty() {
                    return Ok(Some(ThreatDetection {
                        threat_name: "Heur.PE.MaliciousApiCluster".to_string(),
                        engine_name: self.name().to_string(),
                        severity: Severity::High,
                        details: format!(
                            "Tehlikeli Win32 API Kumesi: {}",
                            pe_info.suspicious_api_indicators.join(" | ")
                        ),
                        rule_name: Some("malicious_api_cluster".to_string()),
                    }));
                }

                // Bilinen Packer tespiti (UPX, ASPack vb.)
                if let Some(ref packer) = pe_info.detected_packer {
                    let entropy = Self::calculate_entropy(content);
                    return Ok(Some(ThreatDetection {
                        threat_name: format!("Heur.PE.Packer.{}", packer),
                        engine_name: self.name().to_string(),
                        severity: Severity::Suspicious,
                        details: format!(
                            "Paketlenmis (Packed) PE dosyasi: '{}' tespit edildi (Entropi: {:.2}/8.00)",
                            packer, entropy
                        ),
                        rule_name: Some(format!("packer:{}", packer)),
                    }));
                }
            }

            // Anormal Yüksek Entropi Kontrolü
            let entropy = Self::calculate_entropy(content);
            if entropy > 7.35 {
                return Ok(Some(ThreatDetection {
                    threat_name: "Heur.Packed.HighEntropy".to_string(),
                    engine_name: self.name().to_string(),
                    severity: Severity::Suspicious,
                    details: format!(
                        "PE calistirilabilir dosyasinda anormal yuksek entropi ({:.2}/8.00). Dosya ozel bir crypter veya gomulu zararli yuk barindiriyor olabilir.",
                        entropy
                    ),
                    rule_name: Some("high_entropy_pe".to_string()),
                }));
            }
        }

        Ok(None)
    }
}
