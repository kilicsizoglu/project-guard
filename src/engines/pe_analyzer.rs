use object::{pe, File, Object, ObjectSection, SectionFlags};

#[derive(Debug, Clone)]
pub struct PeAnalysisResult {
    pub is_pe: bool,
    pub is_64bit: bool,
    pub section_count: usize,
    pub suspicious_sections: Vec<String>,
    pub has_wx_section: bool, // Hem yazilabilir hem calistirilabilir (W^X violation)
    pub detected_packer: Option<String>,
    pub suspicious_api_indicators: Vec<String>,
}

pub struct PeAnalyzer;

impl PeAnalyzer {
    pub fn analyze(data: &[u8]) -> Option<PeAnalysisResult> {
        // MZ ve PE imza kontrolü
        if data.len() < 128 || !data.starts_with(b"MZ") {
            return None;
        }

        let parsed = File::parse(data).ok()?;
        let is_64bit = parsed.is_64();

        let mut suspicious_sections = Vec::new();
        let mut has_wx_section = false;
        let mut detected_packer = None;

        let known_packers = [
            ("UPX", vec!["upx0", "upx1", "upx2"]),
            ("ASPack", vec![".aspack", "adata"]),
            ("VMProtect", vec![".vmp0", ".vmp1", ".vmp2"]),
            ("Themida", vec![".themida"]),
            ("PECompact", vec!["pec1", "pec2"]),
        ];

        let mut section_names = Vec::new();

        for section in parsed.sections() {
            let name = section.name().unwrap_or("").to_lowercase();
            section_names.push(name.clone());

            // Packer tespiti
            for (packer_name, sigs) in &known_packers {
                for sig in sigs {
                    if name.contains(sig) {
                        detected_packer = Some(packer_name.to_string());
                        suspicious_sections.push(format!("Packer ({}) bolumu: {}", packer_name, name));
                    }
                }
            }

            // Section Flags: Hem Writable hem Executable mı?
            if let SectionFlags::Coff { characteristics } = section.flags() {
                let is_exec = characteristics.contains(pe::IMAGE_SCN_MEM_EXECUTE);
                let is_write = characteristics.contains(pe::IMAGE_SCN_MEM_WRITE);
                if is_exec && is_write && !name.contains(".data") {
                    has_wx_section = true;
                    suspicious_sections.push(format!("W^X Guvenlik Ihlali (Hem Yazilabilir Hem Calistirilabilir): {}", name));
                }
            }
        }

        // İçe aktarılan veya ham verideki kritik API göstergeleri
        let suspicious_api_indicators = Self::scan_suspicious_apis(data);

        Some(PeAnalysisResult {
            is_pe: true,
            is_64bit,
            section_count: section_names.len(),
            suspicious_sections,
            has_wx_section,
            detected_packer,
            suspicious_api_indicators,
        })
    }

    fn scan_suspicious_apis(data: &[u8]) -> Vec<String> {
        let mut indicators = Vec::new();

        // 1. Process Injection Zinciri
        let injection_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "QueueUserAPC",
        ];
        let mut injection_found = 0;
        for api in injection_apis {
            if Self::contains_ascii(data, api.as_bytes()) {
                injection_found += 1;
            }
        }
        if injection_found >= 2 {
            indicators.push(format!("Process Injection / Hollowing API kumesi tespit edildi ({}/5 API)", injection_found));
        }

        // 2. Keylogger Göstergeleri
        let keylogger_apis = ["GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW", "GetKeyboardState"];
        let mut kl_found = 0;
        for api in keylogger_apis {
            if Self::contains_ascii(data, api.as_bytes()) {
                kl_found += 1;
            }
        }
        if kl_found >= 2 {
            indicators.push(format!("Tus Kaydedici (Keylogger) API kumesi tespit edildi ({}/4 API)", kl_found));
        }

        // 3. Evasion & Anti-Debugging
        let evasion_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"];
        let mut ev_found = 0;
        for api in evasion_apis {
            if Self::contains_ascii(data, api.as_bytes()) {
                ev_found += 1;
            }
        }
        if ev_found >= 2 {
            indicators.push("Anti-Analiz ve Hata Ayiklayici Atlama (Anti-Debug) API'leri tespit edildi".to_string());
        }

        indicators
    }

    fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|window| window == needle)
    }
}
