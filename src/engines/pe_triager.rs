use anyhow::Result;
use object::{pe, File, Object, ObjectSection, SectionFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropyInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_suspicious: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreCapability {
    pub category: String,
    pub tactic: String,
    pub technique: String,
    pub matched_apis: Vec<String>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeTriageReport {
    pub file_name: String,
    pub file_size: u64,
    pub is_pe: bool,
    pub is_64bit: bool,
    pub entry_point: u64,
    pub overall_entropy: f64,
    pub sections: Vec<SectionEntropyInfo>,
    pub capabilities: Vec<MitreCapability>,
    pub threat_score: u32,
    pub verdict: String,
    pub summary_notes: Vec<String>,
}

pub struct PeTriager;

impl PeTriager {
    /// Bir dosyayı okur ve kapsamlı PE Triyaj analizi üretir
    pub fn triage_file(path: &Path) -> Result<PeTriageReport> {
        let bytes = fs::read(path)?;
        let file_name = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown.bin".to_string());

        Self::triage_bytes(&bytes, &file_name)
    }

    /// Ham bayt verisi üzerinde PE Triyaj analizi gerçekleştirir
    pub fn triage_bytes(data: &[u8], file_name: &str) -> Result<PeTriageReport> {
        let file_size = data.len() as u64;
        let overall_entropy = Self::calculate_entropy(data);

        // PE Başlık kontrolü
        if data.len() < 128 || !data.starts_with(b"MZ") {
            return Ok(PeTriageReport {
                file_name: file_name.to_string(),
                file_size,
                is_pe: false,
                is_64bit: false,
                entry_point: 0,
                overall_entropy,
                sections: Vec::new(),
                capabilities: Vec::new(),
                threat_score: 0,
                verdict: "BENIGN / NON-PE".to_string(),
                summary_notes: vec!["Dosya standart bir Windows PE (MZ) ikilisi değil.".to_string()],
            });
        }

        let (is_pe, is_64bit, entry_point, sections_info, mut notes, mut score) = match File::parse(data) {
            Ok(parsed) => {
                let is_64bit = parsed.is_64();
                let entry_point = parsed.entry();
                let mut sections_info = Vec::new();
                let mut notes = Vec::new();
                let mut score: u32 = 0;

                for section in parsed.sections() {
                    let name = section.name().unwrap_or("unnamed").to_string();
                    let raw_data = section.data().unwrap_or(&[]);
                    let entropy = Self::calculate_entropy(raw_data);
                    let virtual_size = section.size();
                    let raw_size = raw_data.len() as u64;

                    let (is_exec, is_write) = match section.flags() {
                        SectionFlags::Coff { characteristics } => (
                            characteristics.contains(pe::IMAGE_SCN_MEM_EXECUTE),
                            characteristics.contains(pe::IMAGE_SCN_MEM_WRITE),
                        ),
                        _ => (false, false),
                    };

                    let mut is_suspicious = false;
                    let mut status = "Normal".to_string();

                    if entropy > 7.1 {
                        is_suspicious = true;
                        status = "Yüksek Entropi (Şifreli / Paketlenmiş)".to_string();
                        score += 20;
                        notes.push(format!("'{}' bölümü yüksek entropiye sahip ({:.2}) - Zararlı kod veya paketlenmiş yük barındırabilir.", name, entropy));
                    } else if is_exec && is_write && !name.contains(".data") {
                        is_suspicious = true;
                        status = "W^X Güvenlik İhlali (RWX Bölüm)".to_string();
                        score += 25;
                        notes.push(format!("'{}' bölümü hem yazılabilir hem çalıştırılabilir (W^X ihlali).", name));
                    }

                    sections_info.push(SectionEntropyInfo {
                        name,
                        virtual_size,
                        raw_size,
                        entropy,
                        is_executable: is_exec,
                        is_writable: is_write,
                        is_suspicious,
                        status,
                    });
                }
                (true, is_64bit, entry_point, sections_info, notes, score)
            }
            Err(_) => {
                (
                    true,
                    false,
                    0,
                    Vec::new(),
                    vec!["MZ başlığı mevcut ancak PE bölüm tablosu bozuk veya obfuscate edilmiş.".to_string()],
                    30,
                )
            }
        };

        // MITRE ATT&CK & Capa tarzı yetenek analizi
        let capabilities = Self::evaluate_capabilities(data);
        for cap in &capabilities {
            match cap.severity.as_str() {
                "Critical" => score += 30,
                "High" => score += 20,
                "Medium" => score += 10,
                _ => score += 5,
            }
            notes.push(format!("[{}] {}: {}", cap.category, cap.technique, cap.matched_apis.join(", ")));
        }

        // Genel entropi skoru
        if overall_entropy > 7.2 {
            score += 15;
            notes.push(format!("Tüm dosya entropisi çok yüksek ({:.2}/8.00) - Muhtemel Crypter / Packer.", overall_entropy));
        }

        score = score.min(100);

        let verdict = if score >= 70 {
            "CRITICAL MALWARE / HIGH RISK"
        } else if score >= 45 {
            "SUSPICIOUS / ELEVATED RISK"
        } else if score >= 20 {
            "MODERATE SUSPICIOUS"
        } else {
            "CLEAN / LOW RISK"
        }.to_string();

        Ok(PeTriageReport {
            file_name: file_name.to_string(),
            file_size,
            is_pe: true,
            is_64bit,
            entry_point,
            overall_entropy,
            sections: sections_info,
            capabilities,
            threat_score: score,
            verdict,
            summary_notes: notes,
        })
    }

    /// Shannon Entropisi hesaplama (0.00 ile 8.00 arası)
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Ham verideki içe aktarmalar ve dizeler üzerinden MITRE ATT&CK yeteneklerini tespit eder
    fn evaluate_capabilities(data: &[u8]) -> Vec<MitreCapability> {
        let mut caps = Vec::new();

        // 1. Process Injection & Hollowing
        let injection_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "QueueUserAPC",
            "SetThreadContext",
            "NtUnmapViewOfSection",
        ];
        let found_inj: Vec<String> = injection_apis
            .iter()
            .filter(|api| Self::contains_ascii(data, api.as_bytes()))
            .map(|s| s.to_string())
            .collect();
        if found_inj.len() >= 2 {
            caps.push(MitreCapability {
                category: "Process Injection".to_string(),
                tactic: "Defense Evasion / Privilege Escalation".to_string(),
                technique: "T1055 - Process Injection".to_string(),
                matched_apis: found_inj,
                severity: "Critical".to_string(),
            });
        }

        // 2. Credential Dumping
        let cred_apis = [
            "MiniDumpWriteDump",
            "CryptUnprotectData",
            "LsaRetrievePrivateData",
            "VaultOpenVault",
            "SamOpenUser",
        ];
        let found_cred: Vec<String> = cred_apis
            .iter()
            .filter(|api| Self::contains_ascii(data, api.as_bytes()))
            .map(|s| s.to_string())
            .collect();
        if !found_cred.is_empty() {
            caps.push(MitreCapability {
                category: "Credential Access".to_string(),
                tactic: "Credential Access".to_string(),
                technique: "T1003 - OS Credential Dumping".to_string(),
                matched_apis: found_cred,
                severity: "Critical".to_string(),
            });
        }

        // 3. Anti-Debugging & Evasion
        let anti_debug_apis = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugStringA",
            "NtQueryInformationProcess",
        ];
        let found_debug: Vec<String> = anti_debug_apis
            .iter()
            .filter(|api| Self::contains_ascii(data, api.as_bytes()))
            .map(|s| s.to_string())
            .collect();
        if found_debug.len() >= 2 {
            caps.push(MitreCapability {
                category: "Anti-Analysis".to_string(),
                tactic: "Defense Evasion".to_string(),
                technique: "T1497 - Virtualization/Sandbox Evasion".to_string(),
                matched_apis: found_debug,
                severity: "High".to_string(),
            });
        }

        // 4. Ransomware & Shadow Copy Deletion
        let shadow_indicators = [
            "vssadmin delete shadows",
            "wmic shadowcopy delete",
            "recoveryenabled no",
            "CryptEncrypt",
            "BCryptEncrypt",
        ];
        let found_ransom: Vec<String> = shadow_indicators
            .iter()
            .filter(|ind| Self::contains_ascii(data, ind.as_bytes()))
            .map(|s| s.to_string())
            .collect();
        if !found_ransom.is_empty() {
            caps.push(MitreCapability {
                category: "Ransomware / Destruction".to_string(),
                tactic: "Impact".to_string(),
                technique: "T1490 - Inhibit System Recovery".to_string(),
                matched_apis: found_ransom,
                severity: "Critical".to_string(),
            });
        }

        // 5. C2 Network Communication
        let net_apis = [
            "InternetOpenA",
            "InternetOpenW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "URLDownloadToFileA",
            "WSAStartup",
        ];
        let found_net: Vec<String> = net_apis
            .iter()
            .filter(|api| Self::contains_ascii(data, api.as_bytes()))
            .map(|s| s.to_string())
            .collect();
        if found_net.len() >= 2 {
            caps.push(MitreCapability {
                category: "Network / C2".to_string(),
                tactic: "Command and Control".to_string(),
                technique: "T1071 - Application Layer Protocol".to_string(),
                matched_apis: found_net,
                severity: "Medium".to_string(),
            });
        }

        caps
    }

    fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|window| window == needle)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_pe_triager_non_pe_text_file() {
        let text_data = b"This is just a regular plain text log file without any MZ header.";
        let rep = PeTriager::triage_bytes(text_data, "sample.txt").unwrap();
        assert!(!rep.is_pe);
        assert_eq!(rep.threat_score, 0);
        assert_eq!(rep.verdict, "BENIGN / NON-PE");
    }

    #[test]
    fn test_pe_triager_capability_matching() {
        let mut synthetic_payload = Vec::new();
        synthetic_payload.extend_from_slice(b"MZ\x90\x00"); // MZ header hint
        synthetic_payload.resize(256, 0x00);
        // Inject capabilities
        synthetic_payload.extend_from_slice(b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00");
        synthetic_payload.extend_from_slice(b"MiniDumpWriteDump\x00");
        synthetic_payload.extend_from_slice(b"vssadmin delete shadows\x00");

        let rep = PeTriager::triage_bytes(&synthetic_payload, "malware_test.exe").unwrap();
        assert!(rep.threat_score >= 50);

        let cap_categories: Vec<String> = rep.capabilities.iter().map(|c| c.category.clone()).collect();
        assert!(cap_categories.contains(&"Process Injection".to_string()));
        assert!(cap_categories.contains(&"Credential Access".to_string()));
        assert!(cap_categories.contains(&"Ransomware / Destruction".to_string()));
    }

    #[test]
    fn test_pe_triager_entropy_calculation() {
        // All zeroes -> 0.0 entropy
        let zeros = vec![0u8; 1000];
        assert_eq!(PeTriager::calculate_entropy(&zeros), 0.0);

        // High entropy pseudo-random sequence
        let pseudo_random: Vec<u8> = (0..1024).map(|i| ((i * 137 + 13) % 256) as u8).collect();
        let entropy = PeTriager::calculate_entropy(&pseudo_random);
        assert!(entropy > 7.5);
    }
}
