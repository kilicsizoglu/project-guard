use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisCheckItem {
    pub id: String,
    pub title: String,
    pub cis_control: String, // "CIS v8.1 Safeguard 4.1"
    pub category: String,
    pub passed: bool,
    pub current_value: String,
    pub recommended_value: String,
    pub description: String,
    pub remediation: String,
}

impl CisCheckItem {
    pub fn new(
        id: &str,
        title: &str,
        cis_control: &str,
        category: &str,
        passed: bool,
        current_value: String,
        recommended_value: &str,
        description: &str,
        remediation: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            cis_control: cis_control.to_string(),
            category: category.to_string(),
            passed,
            current_value,
            recommended_value: recommended_value.to_string(),
            description: description.to_string(),
            remediation: remediation.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisAuditReport {
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub compliance_score: f32, // 0.0 - 100.0
    pub grade: String,         // "A+", "A", "B", "C", "F"
    pub checks: Vec<CisCheckItem>,
}

pub struct CisAuditEngine;

impl CisAuditEngine {
    /// Windows CIS Controls v8.1 ve CIS Benchmark standartlarına göre tam güvenlik denetimi yürütür
    pub fn run_audit() -> CisAuditReport {
        let mut checks = Vec::new();

        // 1. CIS Safeguard 4.1 & 5.4 - UAC (User Account Control)
        checks.push(Self::check_uac_enabled());
        checks.push(Self::check_uac_admin_consent());

        // 2. CIS Safeguard 10.5 - LSA Koruması (RunAsPPL)
        checks.push(Self::check_lsa_protection());

        // 3. CIS Safeguard 8.2 - PowerShell ScriptBlock Logging (EID 4104)
        checks.push(Self::check_powershell_scriptblock_logging());

        // 4. CIS Safeguard 10.1 - Windows Defender / Tamper Protection
        checks.push(Self::check_defender_tamper_protection());

        // 5. Ağ ve Protokol Güvenliği - SMBv1 Devre Dışı Bırakılması
        checks.push(Self::check_smbv1_disabled());

        // 6. Ağ ve Protokol Güvenliği - LLMNR Zehirleme Koruması
        checks.push(Self::check_llmnr_disabled());

        // 7. CIS Safeguard 4.1 - RDP Ağ Düzeyinde Kimlik Doğrulama (NLA)
        checks.push(Self::check_rdp_nla_enforced());

        // 8. CIS Safeguard 10.5 & CISA BYOVD - Microsoft Savunmasız Sürücü Engelleme Listesi
        checks.push(Self::check_vulnerable_driver_blocklist());

        // 9. CIS Safeguard 10.1 & NCSC UK - Denetimli Klasör Erişimi (Ransomware Kalkanı)
        checks.push(Self::check_controlled_folder_access());

        // 10. CIS Safeguard 5.4 & MITRE T1003 - LSASS WDigest Düz Metin Şifre Önbellek Engellemesi
        checks.push(Self::check_wdigest_credential_caching());

        // 11. CIS Safeguard 10.2 - Windows SmartScreen Web ve İtibar Doğrulaması
        checks.push(Self::check_smartscreen_enabled());

        let total = checks.len();
        let passed = checks.iter().filter(|c| c.passed).count();
        let failed = total.saturating_sub(passed);
        let score = if total > 0 {
            (passed as f32 / total as f32) * 100.0
        } else {
            0.0
        };

        let grade = if score >= 90.0 {
            "A+ (Mukemmel)"
        } else if score >= 80.0 {
            "A (Iyi)"
        } else if score >= 65.0 {
            "B (Orta Duzey)"
        } else if score >= 50.0 {
            "C (Riskli)"
        } else {
            "F (Kritik Zafiyet)"
        };

        CisAuditReport {
            total_checks: total,
            passed_checks: passed,
            failed_checks: failed,
            compliance_score: score,
            grade: grade.to_string(),
            checks,
        }
    }

    /// Kayıt defteri değerini reg.exe üzerinden güvenli ve salt okunur sorgular
    #[cfg(windows)]
    fn query_registry_dword(key: &str, value_name: &str) -> Option<u32> {
        let output = crate::engines::create_hidden_command("reg")
            .args(["query", key, "/v", value_name])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains(value_name) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let hex_val = parts[2].trim_start_matches("0x");
                    if let Ok(val) = u32::from_str_radix(hex_val, 16) {
                        return Some(val);
                    }
                }
            }
        }
        None
    }

    #[cfg(not(windows))]
    fn query_registry_dword(_key: &str, _value_name: &str) -> Option<u32> {
        None
    }

    fn check_uac_enabled() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        let val = Self::query_registry_dword(key, "EnableLUA");
        let passed = val == Some(1);

        CisCheckItem::new(
            "CIS-4.1.1",
            "UAC (User Account Control) Etkinligi",
            "CIS v8.1 Safeguard 5.4",
            "Erisim Kontrolu & Yetkilendirme",
            passed,
            match val {
                Some(1) => "Etkin (1)".to_string(),
                Some(0) => "Devre Disi (0) [TEHLIKE]".to_string(),
                _ => "Bilinmiyor / Bulunamadi".to_string(),
            },
            "1 (Etkin)",
            "UAC, yetkisiz yazilimlarin yonetici haklariyla arka planda calismasini engeller.",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
        )
    }

    fn check_uac_admin_consent() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        let val = Self::query_registry_dword(key, "ConsentPromptBehaviorAdmin");
        // 2 = Prompt for credentials on secure desktop, 5 = Prompt for consent on secure desktop
        let passed = val == Some(2) || val == Some(5);

        CisCheckItem::new(
            "CIS-4.1.2",
            "UAC Guvenli Masaustu Onay Istemi",
            "CIS v8.1 Safeguard 5.4",
            "Erisim Kontrolu & Yetkilendirme",
            passed,
            match val {
                Some(v) => format!("Mod: {}", v),
                None => "Varsayilan / Yapilandirilmamis".to_string(),
            },
            "2 veya 5 (Guvenli Masaustunde Onay)",
            "Yonetici onay istemlerinin sahte pencereler tarafindan manipule edilmesini onler.",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f",
        )
    }

    fn check_lsa_protection() -> CisCheckItem {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
        let val = Self::query_registry_dword(key, "RunAsPPL");
        // 1 or 2 means LSA protection / Credential Guard is active
        let passed = val == Some(1) || val == Some(2);

        CisCheckItem::new(
            "CIS-10.5.1",
            "LSA Korumasi (LSASS RunAsPPL)",
            "CIS v8.1 Safeguard 10.5",
            "Kimlik Guvenligi (LSASS)",
            passed,
            match val {
                Some(1) | Some(2) => "Etkin (PPL Korumali)".to_string(),
                _ => "Devre Disi / Korunmasiz".to_string(),
            },
            "1 veya 2 (RunAsPPL Etkin)",
            "Mimikatz ve bellek dokumu araclari ile LSASS surecinden sifre/hash calinmasini donanimsal olarak engeller.",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f",
        )
    }

    fn check_powershell_scriptblock_logging() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
        let val = Self::query_registry_dword(key, "EnableScriptBlockLogging");
        let passed = val == Some(1);

        CisCheckItem::new(
            "CIS-8.2.1",
            "PowerShell Script Block Logging (EID 4104)",
            "CIS v8.1 Safeguard 8.2",
            "Denetim & Telemetri",
            passed,
            match val {
                Some(1) => "Etkin (1)".to_string(),
                _ => "Devre Disi (0)".to_string(),
            },
            "1 (Etkin)",
            "PowerShell uzerinden calistirilan tum betik bloklarini (gizlenmis ve sifrelenmis olsa dahi) cozulmus halde olay gunlugune kaydeder.",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
        )
    }

    fn check_defender_tamper_protection() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features";
        let val = Self::query_registry_dword(key, "TamperProtection");
        // 5 = Enabled
        let passed = val == Some(5);

        CisCheckItem::new(
            "CIS-10.1.1",
            "Windows Defender Kurcalama Korumasi (Tamper Protection)",
            "CIS v8.1 Safeguard 10.1",
            "Zararli Yazilim Savunmasi",
            passed,
            match val {
                Some(5) => "Etkin (5)".to_string(),
                Some(0) => "Devre Disi (0) [KRITIK]".to_string(),
                _ => "Etkin veya Varsayilan".to_string(),
            },
            "5 (Tamper Protection Aktif)",
            "Zararli yazilimlarin veya fidye yazilimlarinin guvenlik ayarlarini kayit defterinden degistirmesini engeller.",
            "Windows Guvenligi -> Virus ve tehdit korumasi ayarlarindan 'Kurcalamaya Karsi Koruma' secenegini acin.",
        )
    }

    fn check_smbv1_disabled() -> CisCheckItem {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        let val = Self::query_registry_dword(key, "SMB1");
        // 0 = disabled, or None (in modern Windows SMBv1 is removed by default)
        let passed = val != Some(1);

        CisCheckItem::new(
            "CIS-9.2.1",
            "Guvenli Olmayan SMBv1 Protokolunun Kapatilmasi",
            "CIS v8.1 Safeguard 4.8",
            "Ag Protokol Guvenligi",
            passed,
            match val {
                Some(1) => "Etkin (1) [KRITIK ETERNALBLUE RISKI]".to_string(),
                _ => "Kapali / Kaldirilmis (Guvenli)".to_string(),
            },
            "0 (Devre Disi)",
            "WannaCry ve NotPetya gibi fidyelerin kullandigi antik SMBv1 zafiyetlerinin (EternalBlue) onlenmesini saglar.",
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
        )
    }

    fn check_llmnr_disabled() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        let val = Self::query_registry_dword(key, "EnableMulticast");
        let passed = val == Some(0);

        CisCheckItem::new(
            "CIS-9.2.2",
            "LLMNR Cok Noktaya Yayin Protokolu Zehirleme Korumasi",
            "CIS v8.1 Safeguard 4.8",
            "Ag Protokol Guvenligi",
            passed,
            match val {
                Some(0) => "Devre Disi (0) [Guvenli]".to_string(),
                _ => "Etkin / Varsayilan [Responder Zehirleme Riski]".to_string(),
            },
            "0 (Devre Disi)",
            "Agda Responder ve yanal yayilma saldirganlarinin NTLMv2 karma ozetlerini (hash) yakalamasini engeller.",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f",
        )
    }

    fn check_rdp_nla_enforced() -> CisCheckItem {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
        let val = Self::query_registry_dword(key, "UserAuthentication");
        let passed = val == Some(1);

        CisCheckItem::new(
            "CIS-4.1.3",
            "RDP Ag Duzeyinde Kimlik Dogrulama (NLA)",
            "CIS v8.1 Safeguard 4.1",
            "Uzak Erisim & Kimlik Dogrulama",
            passed,
            match val {
                Some(1) => "Etkin (NLA Zorunlu)".to_string(),
                Some(0) => "Devre Disi (0) [BlueKeep ve Kaba Kuvvet Riski]".to_string(),
                _ => "Varsayilan / NLA Etkin".to_string(),
            },
            "1 (NLA Zorunlu)",
            "Uzak Masaustu baglantilarinda oturum acilmadan once kimlik dogrulamasi yapilmasini zorunlu kilar.",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f",
        )
    }

    fn check_vulnerable_driver_blocklist() -> CisCheckItem {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config";
        let val = Self::query_registry_dword(key, "VulnerableDriverBlocklistEnable");
        // Windows 11'de 1 veya mevcut olmaması (varsayılan açık) durumunda koruma aktiftir
        let passed = val != Some(0);

        CisCheckItem::new(
            "CIS-10.5.2",
            "Microsoft Savunmasiz Surucu Engelleme Listesi (BYOVD Savunmasi)",
            "CIS v8.1 Safeguard 10.5",
            "Sistem & Cekirdek Guvenligi",
            passed,
            match val {
                Some(1) => "Etkin (1) [Cekirdek Seviyesi BYOVD Korumasi Aktif]".to_string(),
                Some(0) => "Devre Disi (0) [Kritik AuKill / Terminator Saldiri Riski]".to_string(),
                _ => "Varsayilan / Sistem Tarafından Yonetiliyor (Guvenli)".to_string(),
            },
            "1 (Etkin)",
            "Siber saldirganlarin antivirus ve EDR sureclerini kapatmak icin zafiyetli imzali suruculeri yuklemesini onler.",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f",
        )
    }

    fn check_controlled_folder_access() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
        let val = Self::query_registry_dword(key, "EnableControlledFolderAccess");
        let passed = val == Some(1);

        CisCheckItem::new(
            "CIS-10.1.3",
            "Windows Defender Denetimli Klasor Erisimi (CFA - Fidye Kalkanı)",
            "CIS v8.1 Safeguard 10.1",
            "Uç Nokta Veri Koruma",
            passed,
            match val {
                Some(1) => "Etkin (1) [Fidye Sifreleme Kalkanı Aktif]".to_string(),
                _ => "Kapali / Yapilandirilmamis [Fidye Yazilimi Sifreleme Riski]".to_string(),
            },
            "1 (Etkin)",
            "Yetkisiz veya supheli uygulamalarin Belgeler, Resimler ve Masaustu klasorlerindeki dosyalari degistirmesini engeller.",
            "Set-MpPreference -EnableControlledFolderAccess Enabled",
        )
    }

    fn check_wdigest_credential_caching() -> CisCheckItem {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
        let val = Self::query_registry_dword(key, "UseLogonCredential");
        // 0 = düz metin parola önbellekleme kapalı (güvenli)
        let passed = val != Some(1);

        CisCheckItem::new(
            "CIS-5.4.1",
            "LSASS WDigest Duz Metin Sifre Onbelleginin Engellenmesi",
            "CIS v8.1 Safeguard 5.4",
            "Kimlik & Bellek Guvenligi",
            passed,
            match val {
                Some(1) => "Etkin (1) [KRITIK: LSASS Bellekte Duz Metin Sifre Tutuyor]".to_string(),
                _ => "Devre Disi (0) / Guvenli (Mimikatz Korumali)".to_string(),
            },
            "0 (Devre Disi)",
            "Mimikatz veya LSASS bellek dokumlerinde kullanici acik metin parolalarinin ele gecirilmesini onler.",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f",
        )
    }

    fn check_smartscreen_enabled() -> CisCheckItem {
        let key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System";
        let val = Self::query_registry_dword(key, "EnableSmartScreen");
        let passed = val != Some(0);

        CisCheckItem::new(
            "CIS-10.2.1",
            "Windows SmartScreen Web ve Uygulama Itibar Dogrulamasi",
            "CIS v8.1 Safeguard 10.2",
            "Uygulama Guvenligi",
            passed,
            match val {
                Some(1) | Some(2) => "Etkin (SmartScreen Aktif)".to_string(),
                Some(0) => "Devre Disi (0) [Zararli Indirme ve Oltalama Riski]".to_string(),
                _ => "Varsayilan / Sistem Koruma Seviyesinde".to_string(),
            },
            "1 (Etkin)",
            "Kullanicilarin internetten indirdigi bilinmeyen veya itibar puani dusuk zararli yazilimlari calistirmasini engeller.",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v EnableSmartScreen /t REG_DWORD /d 1 /f",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cis_audit_score_calculation() {
        let report = CisAuditEngine::run_audit();
        assert_eq!(report.total_checks, 12);
        assert_eq!(report.passed_checks + report.failed_checks, 12);
        assert!(report.compliance_score >= 0.0 && report.compliance_score <= 100.0);
        assert!(!report.grade.is_empty());
    }
}
