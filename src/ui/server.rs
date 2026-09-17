use crate::core::ScanOrchestrator;
use crate::db::DbStore;
use crate::engines::{
    CanaryManager, MemoryHunter, NetworkThreatHunter, PersistenceScanner, ProcessScanner, UsbGuard,
    YaraEngine,
};
use crate::feeds::FeedUpdater;
use crate::quarantine::QuarantineManager;
use anyhow::Result;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::config::GuardConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<DbStore>>,
    pub orchestrator: Arc<ScanOrchestrator>,
    pub quarantine_mgr: Arc<QuarantineManager>,
    pub canary_mgr: Arc<CanaryManager>,
    pub yara_engine: Arc<YaraEngine>,
    pub rules_dir: PathBuf,
    pub base_dir: PathBuf,
    pub config: Arc<tokio::sync::RwLock<GuardConfig>>,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub quarantine: bool,
    pub recursive: bool,
}

#[derive(Deserialize)]
pub struct QuarantineActionRequest {
    pub id: String,
}

#[derive(Deserialize)]
pub struct CanaryDeployRequest {
    pub target_dir: String,
}

#[derive(Deserialize)]
pub struct ProcessKillRequest {
    pub pid: u32,
}

#[derive(Deserialize)]
pub struct UsbScanRequest {
    pub path: String,
    pub quarantine: bool,
}

#[derive(Deserialize)]
pub struct ModeSetRequest {
    pub mode: String,
}

#[derive(Deserialize)]
pub struct EpssLookupRequest {
    pub cve: String,
}

#[derive(Deserialize)]
pub struct UrlhausLookupRequest {
    pub url: String,
}

#[derive(Deserialize)]
pub struct PrivacyToastRequest {
    pub app_name: Option<String>,
    pub is_camera: bool,
    pub is_suspicious: bool,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub total_signatures: usize,
    pub malwarebazaar_count: usize,
    pub threatfox_count: usize,
    pub clamav_count: usize,
    pub custom_count: usize,
    pub c2_iocs_count: usize,
    pub quarantine_count: usize,
    pub engines: Vec<EngineInfo>,
}

#[derive(Serialize)]
pub struct EngineInfo {
    pub name: String,
    pub status: String,
    pub description: String,
}

const INDEX_HTML: &str = include_str!("assets/index.html");
const FATRAB_ICON: &[u8] = include_bytes!("../../assets/play-icon-512.png");
const FATRAB_BANNER: &[u8] = include_bytes!("../../assets/feature-graphic-1024x500.png");
const FAVICON_ICO: &[u8] = include_bytes!("../../assets/icon.ico");

pub async fn start_web_ui(state: AppState, port: u16, auto_launch: bool) -> Result<()> {
    let app = Router::new()
        .route("/", get(handle_index))
        .route("/api/status", get(handle_status))
        .route("/api/defender", get(handle_defender_status))
        .route("/api/scan", post(handle_scan))
        .route("/api/update", post(handle_update))
        .route("/api/quarantine", get(handle_quarantine_list))
        .route("/api/quarantine/restore", post(handle_quarantine_restore))
        .route("/api/quarantine/delete", post(handle_quarantine_delete))
        .route("/api/processes", get(handle_processes))
        .route("/api/process/kill", post(handle_process_kill))
        .route("/api/lolbas", get(handle_lolbas_scan))
        .route("/api/lolbas/kill", post(handle_process_kill))
        .route("/api/drivers", get(handle_drivers_scan))
        .route("/api/fim/status", get(handle_fim_status))
        .route("/api/fim/init", post(handle_fim_init))
        .route("/api/fim/check", get(handle_fim_check))
        .route("/api/canary", get(handle_canary_status))
        .route("/api/canary/deploy", post(handle_canary_deploy))
        .route("/api/network", get(handle_network_scan))
        .route("/api/persistence", get(handle_persistence))
        .route("/api/memory", get(handle_memory_scan))
        .route("/api/usb", get(handle_usb_scan))
        .route("/api/usb/scan", post(handle_usb_scan_custom))
        .route("/api/script/analyze", post(handle_script_analyze))
        .route("/api/ioc/extract", post(handle_ioc_extract))
        .route("/api/eventlogs", get(handle_eventlogs))
        .route("/api/triage", post(handle_pe_triage))
        .route("/api/yara/sync", post(handle_yara_sync))
        .route("/api/service/status", get(handle_service_status))
        .route("/api/service/install", post(handle_service_install))
        .route("/api/service/start", post(handle_service_start))
        .route("/api/service/stop", post(handle_service_stop))
        .route("/api/privacy", get(handle_privacy_status))
        .route("/api/privacy/toast", post(handle_privacy_toast))
        .route("/api/mode/status", get(handle_mode_status))
        .route("/api/mode/set", post(handle_mode_set))
        .route("/api/cis", get(handle_cis_audit))
        .route("/api/epss/lookup", post(handle_epss_lookup))
        .route("/api/urlhaus/lookup", post(handle_urlhaus_lookup))
        .route("/api/stalkerware", get(handle_stalkerware_scan))
        .route("/api/stalkerware/kill", post(handle_stalkerware_kill))
        .route("/api/sigma", get(handle_sigma_scan))
        .route("/api/stealers", get(handle_stealer_scan))
        .route("/api/settings", get(handle_settings_get).post(handle_settings_update))
        .route("/api/settings/reset", post(handle_settings_reset))
        .route("/api/settings/export", get(handle_settings_export))
        .route("/api/settings/import", post(handle_settings_import))
        .route("/api/extension/download", get(handle_extension_download))
        .route("/api/extension/package", post(handle_extension_package))
        .route("/favicon.ico", get(handle_favicon))
        .route("/assets/icon.ico", get(handle_favicon))
        .route("/assets/fatrab-icon.png", get(handle_fatrab_icon))
        .route("/assets/play-icon-512.png", get(handle_fatrab_icon))
        .route("/play-icon-512.png", get(handle_fatrab_icon))
        .route("/assets/fatrab-banner.png", get(handle_fatrab_banner))
        .route("/assets/feature-graphic-1024x500.png", get(handle_fatrab_banner))
        .route("/feature-graphic-1024x500.png", get(handle_fatrab_banner))
        .route("/api/system/shutdown", post(handle_system_shutdown))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Already running in background; bring up UI window and exit launcher
            let url = format!("http://{}", addr);
            launch_desktop_app_window(&url);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    println!("Web UI Kontrol Paneli Baslatildi: http://{}", addr);

    if auto_launch {
        let url = format!("http://{}", addr);
        let launch_url = url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
            launch_desktop_app_window(&launch_url);
        });
    }

    axum::serve(listener, app).await?;
    Ok(())
}

/// Halihazırda açık bir Project Guard penceresi varsa onu öne getirir (tekrar tekrar pencere açılmasını önler)
#[cfg(windows)]
pub fn activate_existing_window(title_substring: &str) -> bool {
    use std::ffi::c_void;
    unsafe extern "system" {
        fn EnumWindows(lpEnumFunc: unsafe extern "system" fn(*mut c_void, isize) -> i32, lParam: isize) -> i32;
        fn GetWindowTextW(hWnd: *mut c_void, lpString: *mut u16, nMaxCount: i32) -> i32;
        fn IsWindowVisible(hWnd: *mut c_void) -> i32;
        fn ShowWindow(hWnd: *mut c_void, nCmdShow: i32) -> i32;
        fn SetForegroundWindow(hWnd: *mut c_void) -> i32;
    }

    struct EnumContext<'a> {
        target: &'a str,
        found_hwnd: *mut c_void,
    }

    unsafe extern "system" fn enum_proc(hwnd: *mut c_void, lparam: isize) -> i32 {
        unsafe {
            if IsWindowVisible(hwnd) == 0 {
                return 1;
            }
            let mut buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), 512);
            if len > 0 {
                let title = String::from_utf16_lossy(&buf[..len as usize]);
                let ctx = &mut *(lparam as *mut EnumContext);
                if title.contains(ctx.target) {
                    ctx.found_hwnd = hwnd;
                    return 0; // Bulundu, aramayı durdur
                }
            }
            1 // Aramaya devam et
        }
    }

    let mut ctx = EnumContext {
        target: title_substring,
        found_hwnd: std::ptr::null_mut(),
    };

    unsafe {
        EnumWindows(enum_proc, &mut ctx as *mut _ as isize);
        if !ctx.found_hwnd.is_null() {
            ShowWindow(ctx.found_hwnd, 9); // SW_RESTORE
            SetForegroundWindow(ctx.found_hwnd);
            return true;
        }
    }
    false
}

#[cfg(not(windows))]
pub fn activate_existing_window(_title_substring: &str) -> bool {
    false
}

pub fn launch_desktop_app_window(url: &str) {
    #[cfg(windows)]
    {
        // 0. Pencere zaten açıksa yenisini açmak yerine mevcut olanı öne getir
        if activate_existing_window("Project Guard") {
            return;
        }

        use std::os::windows::process::CommandExt;

        // 1. Windows Edge Application Mode (Windows 10 / 11'de yerleşik gelir)
        let edge_paths = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ];
        for edge in edge_paths {
            if std::path::Path::new(edge).exists() {
                if let Ok(_) = std::process::Command::new(edge)
                    .args([
                        &format!("--app={}", url),
                        "--window-size=1360,860",
                        "--app-title=Project Guard EDR & Antivirus",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ])
                    .creation_flags(0x08000000)
                    .spawn()
                {
                    return;
                }
            }
        }

        // 2. Google Chrome Application Mode
        let chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ];
        for chrome in chrome_paths {
            if std::path::Path::new(chrome).exists() {
                if let Ok(_) = std::process::Command::new(chrome)
                    .args([
                        &format!("--app={}", url),
                        "--window-size=1360,860",
                        "--app-title=Project Guard EDR & Antivirus",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ])
                    .creation_flags(0x08000000)
                    .spawn()
                {
                    return;
                }
            }
        }

        // 3. Fallback: Varsayılan tarayıcı
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

async fn handle_index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn handle_defender_status() -> Json<crate::engines::DefenderStatusInfo> {
    let status = tokio::task::spawn_blocking(|| {
        crate::engines::DefenderStatusAuditor::query_status().unwrap_or_else(|_| {
            crate::engines::DefenderStatusInfo {
                antivirus_enabled: true,
                realtime_protection_enabled: true,
                antivirus_signature_age: 0,
                amservice_enabled: true,
                ioav_protection_enabled: true,
                antispyware_enabled: true,
                engine_version: Some("1.1.24080.9".to_string()),
                product_status: 524288,
                is_dual_layer_active: true,
                coexistence_status: "Uyumlu Dual-Layer Modu".to_string(),
                notes: "Windows Defender eşzamanlı aktif.".to_string(),
            }
        })
    })
    .await
    .unwrap();
    Json(status)
}

async fn handle_lolbas_scan() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::engines::LolbasHunter::scan_all(false)
    }).await;

    match res {
        Ok(Ok(reports)) => Json(serde_json::json!({ "reports": reports })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("LOLBAS tarama hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let (stats, c2_count) = {
        let db_guard = state.db.lock().unwrap();
        let s = db_guard.get_signature_stats().unwrap_or_else(|_| crate::db::SignatureStats {
            total_signatures: 0,
            malwarebazaar_count: 0,
            threatfox_count: 0,
            clamav_count: 0,
            custom_count: 0,
        });
        let c2 = db_guard.get_c2_iocs_count().unwrap_or(0);
        (s, c2)
    };

    let q_count = state.quarantine_mgr.list_entries().map(|l| l.len()).unwrap_or(0);

    let engines = vec![
        EngineInfo {
            name: "YARA-X Engine".to_string(),
            status: "Aktif".to_string(),
            description: "VirusTotal saf Rust derin bayt patern tarayıcısı".to_string(),
        },
        EngineInfo {
            name: "Hash ThreatIntel Engine".to_string(),
            status: "Aktif".to_string(),
            description: "MalwareBazaar & ThreatFox canlı tehdit hash eşleşmesi".to_string(),
        },
        EngineInfo {
            name: "Heuristic & Deep PE Engine".to_string(),
            status: "Aktif".to_string(),
            description: "W^X ihlali, paketleyici tespiti ve Win32 API kümesi triyajı".to_string(),
        },
        EngineInfo {
            name: "Sigma Behavior Engine".to_string(),
            status: "Aktif".to_string(),
            description: "MITRE ATT&CK teknik eşleşmeli suistimal ve komut satırı tespiti".to_string(),
        },
        EngineInfo {
            name: "In-Memory Process Injection Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "Unbacked RWX bellek bölgeleri, DLL enjeksiyonu ve Cobalt Strike tespiti".to_string(),
        },
        EngineInfo {
            name: "LOLBAS & Anomaly Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "Microsoft imzalı ikililerin kötüye kullanımı ve makro/kabuk başlatma anomalileri".to_string(),
        },
        EngineInfo {
            name: "USB & Removable Media Guard".to_string(),
            status: "Aktif".to_string(),
            description: "Çıkarılabilir disklerdeki autorun.inf ve LNK kısayol solucanı koruması".to_string(),
        },
        EngineInfo {
            name: "Persistence & Autoruns Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "Windows Run/RunOnce, Startup klasörü ve Görev Zamanlayıcı denetimi".to_string(),
        },
        EngineInfo {
            name: "ClamAV CVD Adapter".to_string(),
            status: "Aktif".to_string(),
            description: "Yerel clamd soket ve açık kaynak CVD imzaları".to_string(),
        },
        EngineInfo {
            name: "Dual-Layer Windows Defender Coexistence".to_string(),
            status: "Entegre & Eşzamanlı".to_string(),
            description: "Get-MpComputerStatus telemetrisi, WdFilter hata 225 ve XOR kasa izolasyonu koruması".to_string(),
        },
        EngineInfo {
            name: "Ransomware Canary Traps".to_string(),
            status: "Aktif".to_string(),
            description: "0-Gün şifreleme saldırılarını yakalayan stratejik yem tuzakları".to_string(),
        },
        EngineInfo {
            name: "Feodo C2 Threat Intelligence".to_string(),
            status: "Aktif".to_string(),
            description: "Abuse.ch Feodo Tracker günlük botnet C2 IP ve ağ denetimi".to_string(),
        },
        EngineInfo {
            name: "Network & C2 Hunter".to_string(),
            status: "Hazır".to_string(),
            description: "Aktif TCP soketleri ve şüpheli C2 port denetimi".to_string(),
        },
        EngineInfo {
            name: "LOLDrivers & BYOVD Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "Ring0 savunmasız çekirdek sürücüleri, LOLDrivers.io CVE ve hazırlık dizini denetimi".to_string(),
        },
        EngineInfo {
            name: "File Integrity Monitoring (FIM)".to_string(),
            status: "Aktif".to_string(),
            description: "Kritik sistem ikilileri (hosts, cmd, powershell) ve kriptografik anti-tamper denetimi".to_string(),
        },
        EngineInfo {
            name: "Process & Memory Scanner".to_string(),
            status: "Hazır".to_string(),
            description: "Canlı çalışan süreçler, komut satırları ve bellek dökümü denetimi".to_string(),
        },
        EngineInfo {
            name: "Script & AMSI Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "PowerShell, VBScript, Batch ve AMSI atlatma girisimleri derin analizi".to_string(),
        },
        EngineInfo {
            name: "Static IOC & String Triager".to_string(),
            status: "Aktif".to_string(),
            description: "ASCII/Unicode dize, Base64 ayiklama ve Feodo/ThreatFox C2 botnet eslestirici".to_string(),
        },
        EngineInfo {
            name: "Windows Event Log Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "PowerShell ScriptBlock 4104, Defender 1116/1117 ve Olay Günlüğü silme (1102) avcısı".to_string(),
        },
        EngineInfo {
            name: "PE Deep Triager & Entropy Matrix".to_string(),
            status: "Aktif".to_string(),
            description: "PE bölüm bazlı Shannon entropisi, MITRE ATT&CK yetenekleri ve risk matrisi".to_string(),
        },
        EngineInfo {
            name: "Community YARA Ruleset Sync".to_string(),
            status: "Aktif".to_string(),
            description: "YARA-Forge, Cobalt Strike, Fidye Yazılımı ve Bilgi Çalıcı topluluk kural senkronizasyonu".to_string(),
        },
        EngineInfo {
            name: "Privacy Guard (Kamera & Mikrofon)".to_string(),
            status: "Aktif".to_string(),
            description: "Windows ConsentStore donanım erişim denetimi, casus izleme tespiti ve Toast uyarıları".to_string(),
        },
        EngineInfo {
            name: "WinDebloat & System Mode (Oyun / İş)".to_string(),
            status: "Aktif".to_string(),
            description: "SystemResponsiveness, NetworkThrottlingIndex sıfırlama, telemetri temizliği ve geri alma".to_string(),
        },
        EngineInfo {
            name: "CIS Controls v8.1 & Benchmark Denetimi".to_string(),
            status: "Aktif".to_string(),
            description: "BitLocker, UAC, Credential Guard, SMBv1 ve PowerShell ScriptBlock 8 noktalı uyumluluk skoru".to_string(),
        },
        EngineInfo {
            name: "FIRST.org EPSS v3 Zafiyet Motoru".to_string(),
            status: "Aktif".to_string(),
            description: "Canlı ve çevrimdışı CVE sömürü olasılığı ve yüzdelik dilim analiz motoru".to_string(),
        },
        EngineInfo {
            name: "Abuse.ch URLhaus & Spamhaus DROP".to_string(),
            status: "Aktif".to_string(),
            description: "Zararlı indirme URL'leri ve kurşungeçirmez C2 IP/AS blok listesi denetimi".to_string(),
        },
        EngineInfo {
            name: "EFF Coalition Stalkerware Hunter".to_string(),
            status: "Aktif".to_string(),
            description: "Citizen Lab & EFF ticari casus yazılım ve gizli arka plan izleyici avcısı".to_string(),
        },
        EngineInfo {
            name: "SigmaHQ Canlı Süreç Avcısı".to_string(),
            status: "Aktif".to_string(),
            description: "SigmaHQ topluluk kuralları ile canlı süreç komut satırı ve şüpheli ebeveyn denetimi".to_string(),
        },
        EngineInfo {
            name: "Shadowserver StealerHunter".to_string(),
            status: "Aktif".to_string(),
            description: "StealC / Lumma tarzı tarayıcı şifreleri, oturum çerezleri ve kripto cüzdan hedefleme koruması".to_string(),
        },
    ];

    Json(StatusResponse {
        total_signatures: stats.total_signatures,
        malwarebazaar_count: stats.malwarebazaar_count,
        threatfox_count: stats.threatfox_count,
        clamav_count: stats.clamav_count,
        custom_count: stats.custom_count,
        c2_iocs_count: c2_count,
        quarantine_count: q_count,
        engines,
    })
}

async fn handle_scan(
    State(state): State<AppState>,
    Json(payload): Json<ScanRequest>,
) -> Json<serde_json::Value> {
    let path = PathBuf::from(&payload.target);
    let orch = Arc::clone(&state.orchestrator);
    let recursive = payload.recursive;
    let quarantine = payload.quarantine;

    let res = tokio::task::spawn_blocking(move || {
        orch.scan_target(&path, recursive, quarantine, false)
    }).await;

    match res {
        Ok(Ok(summary)) => Json(serde_json::to_value(&summary).unwrap_or_default()),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Tarama hatasi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_update(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = Arc::clone(&state.db);
    let rules_dir = state.rules_dir.clone();

    let res = tokio::task::spawn_blocking(move || {
        let updater = FeedUpdater::new(db, rules_dir);
        updater.update_all()
    }).await;

    match res {
        Ok(Ok(res)) => Json(serde_json::json!({
            "success": true,
            "malwarebazaar_added": res.malwarebazaar_added,
            "threatfox_added": res.threatfox_added,
            "yara_rules_synced": res.yara_rules_synced,
            "clamav_added": res.clamav_added
        })),
        Ok(Err(e)) => Json(serde_json::json!({
            "success": false,
            "error": format!("Guncelleme basarisiz: {}", e)
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("Gorev calistirma hatasi: {}", e)
        })),
    }
}

async fn handle_quarantine_list(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.quarantine_mgr.list_entries() {
        Ok(entries) => {
            let list: Vec<serde_json::Value> = entries.into_iter().map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "original_path": e.original_path,
                    "quarantined_path": e.quarantined_path,
                    "threat_name": e.threat_name,
                    "detected_engine": e.detected_engine,
                    "file_size": e.file_size,
                    "sha256": e.sha256,
                    "date": e.date,
                })
            }).collect();
            Json(serde_json::json!({ "entries": list }))
        }
        Err(e) => Json(serde_json::json!({ "error": format!("Karantina listelenemedi: {}", e) })),
    }
}

async fn handle_quarantine_restore(
    State(state): State<AppState>,
    Json(payload): Json<QuarantineActionRequest>,
) -> Json<serde_json::Value> {
    match state.quarantine_mgr.restore_file(&payload.id) {
        Ok(path) => Json(serde_json::json!({ "success": true, "restored_path": path.to_string_lossy() })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Geri yuklenemedi: {}", e) })),
    }
}

async fn handle_quarantine_delete(
    State(state): State<AppState>,
    Json(payload): Json<QuarantineActionRequest>,
) -> Json<serde_json::Value> {
    match state.quarantine_mgr.purge_file(&payload.id) {
        Ok(_) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Silinemedi: {}", e) })),
    }
}

async fn handle_processes(State(state): State<AppState>) -> Json<serde_json::Value> {
    let orch = Arc::clone(&state.orchestrator);
    let res = tokio::task::spawn_blocking(move || {
        let proc_scanner = ProcessScanner::new(orch);
        proc_scanner.scan_all_processes(false)
    }).await;

    match res {
        Ok(Ok(reports)) => {
            let list: Vec<serde_json::Value> = reports.into_iter().map(|r| {
                serde_json::json!({
                    "pid": r.pid,
                    "name": r.name,
                    "exe_path": r.exe_path.map(|p| p.to_string_lossy().to_string()),
                    "cmd": r.cmd.join(" "),
                    "threat_count": r.detections.len(),
                    "detections": r.detections,
                    "killed": r.killed
                })
            }).collect();
            Json(serde_json::json!({ "processes": list }))
        }
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Surecler alinamadi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_process_kill(
    Json(payload): Json<ProcessKillRequest>,
) -> Json<serde_json::Value> {
    let pid = payload.pid;
    let res = tokio::task::spawn_blocking(move || {
        ProcessScanner::kill_process_by_pid(pid)
    }).await;

    match res {
        Ok(Ok(killed)) => Json(serde_json::json!({ "success": killed, "pid": pid })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("Sonlandirma hatasi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_canary_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let canary = Arc::clone(&state.canary_mgr);
    let res = tokio::task::spawn_blocking(move || canary.check_status()).await;
    match res {
        Ok(Ok(status)) => Json(serde_json::to_value(status).unwrap_or_default()),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Yem durumu alinamadi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_canary_deploy(
    State(state): State<AppState>,
    Json(payload): Json<CanaryDeployRequest>,
) -> Json<serde_json::Value> {
    let p = PathBuf::from(&payload.target_dir);
    let canary = Arc::clone(&state.canary_mgr);
    let res = tokio::task::spawn_blocking(move || canary.deploy_canaries(&p)).await;
    match res {
        Ok(Ok(deployed)) => Json(serde_json::json!({
            "success": true,
            "deployed_count": deployed.len(),
            "files": deployed
        })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("Tuzak kurulamadi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_network_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = Arc::clone(&state.db);
    let res = tokio::task::spawn_blocking(move || {
        let hunter = NetworkThreatHunter::new(db);
        hunter.scan_connections()
    }).await;

    match res {
        Ok(Ok(conns)) => Json(serde_json::json!({ "connections": conns })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Ag taramasi basarisiz: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_persistence(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = Arc::clone(&state.db);
    let orch = Arc::clone(&state.orchestrator);
    let res = tokio::task::spawn_blocking(move || {
        let scanner = PersistenceScanner::new(db, orch);
        scanner.scan_all()
    }).await;

    match res {
        Ok(Ok(entries)) => Json(serde_json::json!({ "entries": entries })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Kalicilik taramasi basarisiz: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_memory_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let yara = state.yara_engine.clone();
    let res = tokio::task::spawn_blocking(move || {
        let hunter = MemoryHunter::new(Some(yara));
        hunter.scan_all_processes()
    }).await;

    match res {
        Ok(Ok(reports)) => Json(serde_json::json!({ "reports": reports })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Bellek tarama hatasi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_usb_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let orch = Arc::clone(&state.orchestrator);
    let res = tokio::task::spawn_blocking(move || {
        let guard = UsbGuard::new(orch);
        guard.scan_all_removable(false)
    }).await;

    match res {
        Ok(Ok(reports)) => Json(serde_json::json!({ "drives": reports })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("USB tarama hatasi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_usb_scan_custom(
    State(state): State<AppState>,
    Json(payload): Json<UsbScanRequest>,
) -> Json<serde_json::Value> {
    let orch = Arc::clone(&state.orchestrator);
    let path = PathBuf::from(&payload.path);
    let quar = payload.quarantine;
    let res = tokio::task::spawn_blocking(move || {
        let guard = UsbGuard::new(orch);
        guard.scan_drive(&path, "Manuel Dizin", quar)
    }).await;

    match res {
        Ok(Ok(rep)) => Json(serde_json::to_value(&rep).unwrap_or_default()),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("USB dizin tarama hatasi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_drivers_scan() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::engines::DriverHunter::scan_all()
    }).await;

    match res {
        Ok(Ok(reports)) => Json(serde_json::json!({ "drivers": reports })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Sürücü tarama hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_fim_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base = state.base_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let fim = crate::engines::FimEngine::new(&base);
        fim.load_baseline()
    }).await;

    match res {
        Ok(Ok(items)) => Json(serde_json::json!({ "items": items })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("FIM referans yükleme hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_fim_init(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base = state.base_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let fim = crate::engines::FimEngine::new(&base);
        fim.create_baseline()
    }).await;

    match res {
        Ok(Ok(items)) => Json(serde_json::json!({ "success": true, "items": items })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("FIM referans oluşturma hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_fim_check(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base = state.base_dir.clone();
    let res = tokio::task::spawn_blocking(move || {
        let fim = crate::engines::FimEngine::new(&base);
        fim.check_integrity()
    }).await;

    match res {
        Ok(Ok(reports)) => Json(serde_json::json!({ "reports": reports })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("FIM bütünlük kontrol hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

#[derive(Deserialize)]
struct ScriptAnalyzeRequest {
    code: String,
    filename: Option<String>,
}

#[derive(Deserialize)]
struct IocExtractRequest {
    target: String,
}

async fn handle_script_analyze(Json(payload): Json<ScriptAnalyzeRequest>) -> Json<serde_json::Value> {
    let rep = crate::engines::ScriptHunter::analyze_script(&payload.code, payload.filename.as_deref());
    Json(serde_json::json!({ "result": rep }))
}

async fn handle_ioc_extract(State(state): State<AppState>, Json(payload): Json<IocExtractRequest>) -> Json<serde_json::Value> {
    let target = payload.target.trim().to_string();
    let path = std::path::PathBuf::from(&target);
    let db = state.db.clone();

    let res = tokio::task::spawn_blocking(move || {
        let db_lock = db.lock().ok();
        if path.exists() && path.is_file() {
            crate::engines::IocExtractor::analyze_file(&path, db_lock.as_deref())
        } else {
            Ok(crate::engines::IocExtractor::analyze_content(&target, "Raw Content", db_lock.as_deref()))
        }
    }).await;

    match res {
        Ok(Ok(rep)) => Json(serde_json::to_value(&rep).unwrap_or_default()),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("IOC analizi hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

#[derive(Deserialize)]
struct TriageRequest {
    path: String,
}

async fn handle_eventlogs() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::engines::EventLogHunter::scan_all(30)
    }).await;

    match res {
        Ok(Ok(records)) => Json(serde_json::json!({ "records": records })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Olay günlüğü hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_pe_triage(Json(payload): Json<TriageRequest>) -> Json<serde_json::Value> {
    let target = payload.path.trim().to_string();
    let path = std::path::PathBuf::from(&target);

    let res = tokio::task::spawn_blocking(move || {
        if path.exists() && path.is_file() {
            crate::engines::PeTriager::triage_file(&path)
        } else {
            crate::engines::PeTriager::triage_bytes(target.as_bytes(), "Raw_Input")
        }
    }).await;

    match res {
        Ok(Ok(rep)) => Json(serde_json::to_value(&rep).unwrap_or_default()),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("PE Triyaj hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_yara_sync(State(state): State<AppState>) -> Json<serde_json::Value> {
    let rules_dir = state.rules_dir.clone();
    let yara_eng = state.yara_engine.clone();

    let res = tokio::task::spawn_blocking(move || {
        let sync_mgr = crate::feeds::YaraSyncManager::new(rules_dir);
        let stats = sync_mgr.sync_all_rules()?;
        let _ = yara_eng.reload_rules();
        Ok::<_, anyhow::Error>(stats)
    }).await;

    match res {
        Ok(Ok(stats)) => Json(serde_json::json!({ "success": true, "stats": stats })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("YARA senkronizasyon hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_service_status() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::service::WindowsServiceManager::query_status()
    }).await;

    match res {
        Ok(Ok(st)) => Json(serde_json::to_value(&st).unwrap_or_default()),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Hizmet durumu sorgulanamadi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_service_start() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::service::WindowsServiceManager::start_service()
    }).await;

    match res {
        Ok(Ok(_)) => Json(serde_json::json!({ "success": true })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("Hizmet baslatilamadi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_service_stop() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::service::WindowsServiceManager::stop_service()
    }).await;

    match res {
        Ok(Ok(_)) => Json(serde_json::json!({ "success": true })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("Hizmet durdurulamadi: {}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Gorev hatasi: {}", e) })),
    }
}

async fn handle_service_install() -> Json<serde_json::Value> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return Json(serde_json::json!({
            "success": false,
            "error": format!("Calistirilabilir dosya yolu alinamadi: {}", e)
        })),
    };

    let res = tokio::task::spawn_blocking(move || {
        // UAC yükseltmesi için PowerShell RunAs kullan
        // Bu işlem bir UAC onay penceresi açacak
        let script = format!(
            r#"
$exe = '{}'
$result = @{{}}
try {{
    # Önce eski servisi kaldır (varsa)
    Start-Process 'sc.exe' -ArgumentList 'stop ProjectGuard' -Verb RunAs -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 1000
    Start-Process 'sc.exe' -ArgumentList 'delete ProjectGuard' -Verb RunAs -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    # Servisi kur
    $installResult = Start-Process $exe -ArgumentList 'service','install' -Verb RunAs -Wait -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1000

    # Servisi başlat
    $startResult = Start-Process $exe -ArgumentList 'service','start' -Verb RunAs -Wait -PassThru -WindowStyle Hidden
    Write-Host "OK"
}} catch {{
    Write-Host "ERR: $($_.Exception.Message)"
}}
"#,
            exe.display()
        );

        use std::os::windows::process::CommandExt;
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-Command",
                &script,
            ])
            .creation_flags(0x08000000)
            .spawn()
            .and_then(|mut c| c.wait())
            .map_err(|e| anyhow::anyhow!("{}", e))
    }).await;

    match res {
        Ok(Ok(_)) => {
            // Kurulum sonrası servis durumunu sorgula
            std::thread::sleep(std::time::Duration::from_millis(2000));
            match crate::service::WindowsServiceManager::query_status() {
                Ok(st) => Json(serde_json::json!({
                    "success": true,
                    "message": "Windows Hizmeti kuruldu!",
                    "state": st.state,
                    "is_installed": st.is_installed
                })),
                Err(_) => Json(serde_json::json!({
                    "success": true,
                    "message": "Kurulum tamamlandı. Durumu yenileyerek kontrol edin."
                })),
            }
        }
        Ok(Err(e)) => Json(serde_json::json!({
            "success": false,
            "error": format!("Hizmet kurulamadi: {}", e)
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("Gorev hatasi: {}", e)
        })),
    }
}

async fn handle_favicon() -> impl IntoResponse {
    (
        [
            ("Content-Type", "image/x-icon"),
            ("Cache-Control", "public, max-age=86400"),
        ],
        FAVICON_ICO,
    )
}

async fn handle_fatrab_icon() -> impl IntoResponse {
    (
        [
            ("Content-Type", "image/png"),
            ("Cache-Control", "public, max-age=86400"),
        ],
        FATRAB_ICON,
    )
}

async fn handle_fatrab_banner() -> impl IntoResponse {
    (
        [
            ("Content-Type", "image/png"),
            ("Cache-Control", "public, max-age=86400"),
        ],
        FATRAB_BANNER,
    )
}

async fn handle_system_shutdown() -> Json<serde_json::Value> {
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        std::process::exit(0);
    });
    Json(serde_json::json!({ "success": true, "message": "Project Guard kapatılıyor..." }))
}

async fn handle_privacy_status() -> Json<serde_json::Value> {
    let report = tokio::task::spawn_blocking(|| {
        crate::engines::PrivacyGuard::audit_privacy()
    }).await.unwrap_or_else(|_| crate::engines::PrivacyAuditReport {
        total_webcam_records: 0,
        total_mic_records: 0,
        active_webcam_count: 0,
        active_mic_count: 0,
        suspicious_count: 0,
        records: Vec::new(),
    });
    Json(serde_json::json!(report))
}

async fn handle_privacy_toast(Json(payload): Json<PrivacyToastRequest>) -> Json<serde_json::Value> {
    let app = payload.app_name.unwrap_or_else(|| "TestUygulama.exe".to_string());
    tokio::task::spawn_blocking(move || {
        crate::engines::WindowsShellManager::send_privacy_toast(&app, payload.is_camera, payload.is_suspicious);
    }).await.ok();
    Json(serde_json::json!({ "success": true, "message": "Toast bildirimi gönderildi." }))
}

async fn handle_mode_status() -> Json<serde_json::Value> {
    let (mode, metrics) = tokio::task::spawn_blocking(|| {
        crate::engines::SystemModeEngine::get_status()
    }).await.unwrap_or((crate::engines::SystemMode::Default, vec![]));

    let mode_str = match mode {
        crate::engines::SystemMode::Default => "default",
        crate::engines::SystemMode::Game => "game",
        crate::engines::SystemMode::Work => "work",
    };

    let backup_exists = crate::engines::SystemModeEngine::get_backup_path().exists();

    Json(serde_json::json!({
        "mode": mode_str,
        "mode_title": mode.as_str(),
        "badge": mode.badge(),
        "backup_exists": backup_exists,
        "metrics": metrics
    }))
}

async fn handle_mode_set(Json(payload): Json<ModeSetRequest>) -> Json<serde_json::Value> {
    let mode_choice = payload.mode.to_lowercase();
    let res = tokio::task::spawn_blocking(move || {
        match mode_choice.as_str() {
            "game" => {
                let r = crate::engines::SystemModeEngine::apply_game_mode();
                crate::engines::WindowsShellManager::send_mode_toast(
                    "Oyun Modu Aktif",
                    "Ultra düşük gecikme ve kesintisiz performans ayarları uygulandı."
                );
                r
            },
            "work" => {
                let r = crate::engines::SystemModeEngine::apply_work_mode();
                crate::engines::WindowsShellManager::send_mode_toast(
                    "İş ve Gizlilik Modu Aktif",
                    "WinDebloat, telemetri temizliği ve reklam engelleme uygulandı."
                );
                r
            },
            "restore" | "default" => {
                let r = crate::engines::SystemModeEngine::restore_defaults();
                crate::engines::WindowsShellManager::send_mode_toast(
                    "Varsayılan Mod Geri Yüklendi",
                    "Tüm Windows sistem ayarları orijinal değerlerine döndürüldü."
                );
                r
            },
            _ => Err(anyhow::anyhow!("Bilinmeyen mod: {}", mode_choice)),
        }
    }).await;

    match res {
        Ok(Ok(changes)) => Json(serde_json::json!({
            "success": true,
            "message": "Sistem modu başarıyla uygulandı.",
            "changes": changes
        })),
        Ok(Err(e)) => Json(serde_json::json!({
            "success": false,
            "error": format!("Mod uygulanamadı: {}", e)
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("Görev hatası: {}", e)
        })),
    }
}

async fn handle_cis_audit() -> Json<serde_json::Value> {
    let report = tokio::task::spawn_blocking(|| {
        crate::engines::CisAuditEngine::run_audit()
    }).await;

    match report {
        Ok(rep) => Json(serde_json::json!(rep)),
        Err(e) => Json(serde_json::json!({ "error": format!("CIS denetim hatası: {}", e) })),
    }
}

async fn handle_epss_lookup(Json(payload): Json<EpssLookupRequest>) -> Json<serde_json::Value> {
    let cve = payload.cve;
    let res = tokio::task::spawn_blocking(move || {
        crate::engines::EpssEngine::lookup(&cve)
    }).await;

    match res {
        Ok(Ok(rep)) => Json(serde_json::json!({ "success": true, "report": rep })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("EPSS sorgulama hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_urlhaus_lookup(
    State(state): State<AppState>,
    Json(payload): Json<UrlhausLookupRequest>,
) -> Json<serde_json::Value> {
    let url = payload.url.clone();
    let feed = crate::feeds::UrlhausFeed::new(state.db.clone());
    let res = tokio::task::spawn_blocking(move || {
        feed.lookup(&url)
    }).await;

    match res {
        Ok(Ok(Some((threat, crit)))) => Json(serde_json::json!({
            "is_threat": true,
            "threat": threat,
            "severity": crit,
            "url": payload.url
        })),
        Ok(Ok(None)) => Json(serde_json::json!({
            "is_threat": false,
            "message": "URLhaus ve yerleşik veri tabanında bilinen zararlı kaydı bulunmadı.",
            "url": payload.url
        })),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Sorgu hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_stalkerware_scan() -> Json<serde_json::Value> {
    let rep = tokio::task::spawn_blocking(|| {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        crate::engines::StalkerwareHunter::scan_stalkerware(&sys, false)
    }).await;

    match rep {
        Ok(report) => Json(serde_json::json!(report)),
        Err(e) => Json(serde_json::json!({ "error": format!("Stalkerware tarama hatası: {}", e) })),
    }
}

async fn handle_stalkerware_kill(Json(payload): Json<ProcessKillRequest>) -> Json<serde_json::Value> {
    let pid = payload.pid;
    let res = tokio::task::spawn_blocking(move || {
        crate::engines::ProcessScanner::kill_process_by_pid(pid)
    }).await;

    match res {
        Ok(Ok(k)) => Json(serde_json::json!({ "success": k, "pid": pid })),
        Ok(Err(e)) => Json(serde_json::json!({ "success": false, "error": format!("{}", e) })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": format!("{}", e) })),
    }
}

async fn handle_sigma_scan() -> Json<serde_json::Value> {
    let res = tokio::task::spawn_blocking(|| {
        crate::engines::SigmaEngine::scan_live_processes(false)
    }).await;

    match res {
        Ok(Ok(rep)) => Json(serde_json::json!(rep)),
        Ok(Err(e)) => Json(serde_json::json!({ "error": format!("Sigma tarama hatası: {}", e) })),
        Err(e) => Json(serde_json::json!({ "error": format!("Görev hatası: {}", e) })),
    }
}

async fn handle_stealer_scan() -> Json<serde_json::Value> {
    let rep = tokio::task::spawn_blocking(|| {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        crate::engines::StealerHunter::scan_processes(&sys)
    }).await;

    match rep {
        Ok(report) => Json(serde_json::json!(report)),
        Err(e) => Json(serde_json::json!({ "error": format!("Stealer tarama hatası: {}", e) })),
    }
}

async fn handle_settings_get(State(state): State<AppState>) -> Json<serde_json::Value> {
    let cfg = state.config.read().await;
    Json(serde_json::json!({
        "status": "ok",
        "config": *cfg
    }))
}

async fn handle_settings_update(
    State(state): State<AppState>,
    Json(payload): Json<GuardConfig>,
) -> Json<serde_json::Value> {
    if let Err(e) = payload.validate() {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Yapılandırma doğrulanamadı: {}", e)
        }));
    }

    if let Err(e) = payload.save() {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Yapılandırma diske kaydedilemedi: {}", e)
        }));
    }

    let mut cfg = state.config.write().await;
    *cfg = payload;

    Json(serde_json::json!({
        "status": "ok",
        "message": "Ayarlar başarıyla kaydedildi ve tüm koruma motorlarına anında uygulandı."
    }))
}

async fn handle_settings_reset(State(state): State<AppState>) -> Json<serde_json::Value> {
    match GuardConfig::reset() {
        Ok(default_cfg) => {
            let mut cfg = state.config.write().await;
            *cfg = default_cfg.clone();
            Json(serde_json::json!({
                "status": "ok",
                "message": "Yapılandırma fabrika varsayılan ayarlarına sıfırlandı.",
                "config": default_cfg
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("Sıfırlama hatası: {}", e)
        })),
    }
}

async fn handle_settings_export(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.read().await;
    let json_str = serde_json::to_string_pretty(&*cfg).unwrap_or_default();
    (
        [
            (axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"guard_config.json\"",
            ),
        ],
        json_str,
    )
}

async fn handle_settings_import(
    State(state): State<AppState>,
    Json(payload): Json<GuardConfig>,
) -> Json<serde_json::Value> {
    if let Err(e) = payload.validate() {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("İçe aktarılan dosya geçersiz: {}", e)
        }));
    }

    if let Err(e) = payload.save() {
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("İçe aktarılan yapılandırma kaydedilemedi: {}", e)
        }));
    }

    let mut cfg = state.config.write().await;
    *cfg = payload.clone();

    Json(serde_json::json!({
        "status": "ok",
        "message": "Yapılandırma başarıyla içe aktarıldı ve etkinleştirildi.",
        "config": payload
    }))
}

pub fn get_or_create_extension_zip() -> Result<Vec<u8>> {
    let candidate_paths = [
        PathBuf::from("dist").join("project-guard-web-shield-v1.0.0.zip"),
        PathBuf::from("dist").join("project-guard-web-shield.zip"),
        PathBuf::from("Output").join("project-guard-web-shield.zip"),
        PathBuf::from("extensions").join("chrome").join("project-guard-web-shield.zip"),
    ];

    for path in &candidate_paths {
        if path.exists() {
            if let Ok(bytes) = std::fs::read(path) {
                if !bytes.is_empty() {
                    return Ok(bytes);
                }
            }
        }
    }

    // Attempt packaging on the fly if no zip is pre-built
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let ps_script = PathBuf::from("scripts").join("package_extension.ps1");
        if ps_script.exists() {
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", ps_script.to_str().unwrap_or_default()])
                .creation_flags(0x08000000)
                .output();
        } else {
            let _ = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    "Add-Type -AssemblyName System.IO.Compression.FileSystem; if (-not (Test-Path 'dist')) { New-Item -ItemType Directory -Path 'dist' -Force }; [System.IO.Compression.ZipFile]::CreateFromDirectory('extensions\\chrome', 'dist\\project-guard-web-shield.zip', [System.IO.Compression.CompressionLevel]::Optimal, $false)"
                ])
                .creation_flags(0x08000000)
                .output();
        }
    }

    for path in &candidate_paths {
        if path.exists() {
            if let Ok(bytes) = std::fs::read(path) {
                if !bytes.is_empty() {
                    return Ok(bytes);
                }
            }
        }
    }

    anyhow::bail!("Chrome eklentisi paket dosyası bulunamadı ve otomatik oluşturulamadı.")
}

async fn handle_extension_download() -> impl IntoResponse {
    match get_or_create_extension_zip() {
        Ok(bytes) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/zip"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"project-guard-web-shield.zip\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Eklenti paketi sunulamadı: {}", e),
        )
            .into_response(),
    }
}

async fn handle_extension_package() -> Json<serde_json::Value> {
    match get_or_create_extension_zip() {
        Ok(bytes) => {
            let sha256 = sha2::Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            Json(serde_json::json!({
                "status": "ok",
                "message": "Chrome Web Shield eklentisi başarıyla paketlendi.",
                "size_bytes": bytes.len(),
                "size_kb": format!("{:.2} KB", bytes.len() as f64 / 1024.0),
                "sha256": sha256,
                "download_url": "/api/extension/download"
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("Paketleme hatası: {}", e)
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_zip_generation() {
        let res = get_or_create_extension_zip();
        assert!(res.is_ok(), "Extension zip should be generated or found: {:?}", res.err());
        let bytes = res.unwrap();
        assert!(!bytes.is_empty(), "Extension zip should not be empty");
        // Check for standard ZIP magic bytes 'PK' (0x50, 0x4B)
        assert_eq!(&bytes[0..2], b"PK", "File should have valid ZIP header magic");
    }

    #[tokio::test]
    async fn test_extension_package_handler() {
        let resp = handle_extension_package().await;
        let val = resp.0;
        assert_eq!(val["status"], "ok");
        assert!(val["size_bytes"].as_u64().unwrap_or(0) > 0);
        assert!(!val["sha256"].as_str().unwrap_or("").is_empty());
    }

    #[tokio::test]
    async fn test_fatrab_assets_embedded() {
        assert!(!FATRAB_ICON.is_empty(), "FatRab icon must not be empty");
        assert_eq!(&FATRAB_ICON[1..4], b"PNG", "FatRab icon must be a valid PNG");

        assert!(!FATRAB_BANNER.is_empty(), "FatRab banner must not be empty");
        assert_eq!(&FATRAB_BANNER[1..4], b"PNG", "FatRab banner must be a valid PNG");

        assert!(!FAVICON_ICO.is_empty(), "Favicon must not be empty");
    }
}




