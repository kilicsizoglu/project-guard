// Project Guard - Windows Native System Tray (Taskbar Notification Area)
// Pure Rust implementation using Windows Shell & User32 APIs (Zero extra C/C++ dependencies).

#[cfg(windows)]
#[allow(unsafe_op_in_unsafe_fn, dead_code, unused_imports)]
pub mod win_tray {
    use std::ffi::c_void;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::config::GuardConfig;
    use crate::ui::server::launch_desktop_app_window;

    // --- Win32 Structures ---
    #[allow(non_snake_case)]
    #[repr(C)]
    pub struct WNDCLASSEXW {
        pub cbSize: u32,
        pub style: u32,
        pub lpfnWndProc: unsafe extern "system" fn(*mut c_void, u32, usize, isize) -> isize,
        pub cbClsExtra: i32,
        pub cbWndExtra: i32,
        pub hInstance: *mut c_void,
        pub hIcon: *mut c_void,
        pub hCursor: *mut c_void,
        pub hbrBackground: *mut c_void,
        pub lpszMenuName: *const u16,
        pub lpszClassName: *const u16,
        pub hIconSm: *mut c_void,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct POINT {
        pub x: i32,
        pub y: i32,
    }

    #[allow(non_snake_case)]
    #[repr(C)]
    pub struct MSG {
        pub hwnd: *mut c_void,
        pub message: u32,
        pub wParam: usize,
        pub lParam: isize,
        pub time: u32,
        pub pt: POINT,
    }

    #[allow(non_snake_case)]
    #[repr(C)]
    pub struct NOTIFYICONDATAW {
        pub cbSize: u32,
        pub hWnd: *mut c_void,
        pub uID: u32,
        pub uFlags: u32,
        pub uCallbackMessage: u32,
        pub hIcon: *mut c_void,
        pub szTip: [u16; 128],
        pub dwState: u32,
        pub dwStateMask: u32,
        pub szInfo: [u16; 256],
        pub uTimeoutOrVersion: u32,
        pub szInfoTitle: [u16; 64],
        pub dwInfoFlags: u32,
        pub guidItem: [u8; 16],
        pub hBalloonIcon: *mut c_void,
    }

    unsafe extern "system" {
        fn GetTickCount64() -> u64;
    }

    static LAST_LBUTTON_TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    // --- Win32 Constants ---
    pub const WM_CREATE: u32 = 0x0001;
    pub const WM_DESTROY: u32 = 0x0002;
    pub const WM_CLOSE: u32 = 0x0010;
    pub const WM_COMMAND: u32 = 0x0111;
    pub const WM_USER: u32 = 0x0400;
    pub const WM_APP: u32 = 0x8000;
    pub const WM_TRAYICON: u32 = WM_APP + 101;

    pub const WM_LBUTTONUP: usize = 0x0202;
    pub const WM_LBUTTONDBLCLK: usize = 0x0203;
    pub const WM_RBUTTONUP: usize = 0x0205;
    pub const WM_CONTEXTMENU: usize = 0x007B;

    pub const NIM_ADD: u32 = 0x00000000;
    pub const NIM_MODIFY: u32 = 0x00000001;
    pub const NIM_DELETE: u32 = 0x00000002;

    pub const NIF_MESSAGE: u32 = 0x00000001;
    pub const NIF_ICON: u32 = 0x00000002;
    pub const NIF_TIP: u32 = 0x00000004;
    pub const NIF_INFO: u32 = 0x00000010;

    pub const NIIF_NONE: u32 = 0x00000000;
    pub const NIIF_INFO: u32 = 0x00000001;
    pub const NIIF_WARNING: u32 = 0x00000002;
    pub const NIIF_ERROR: u32 = 0x00000003;

    pub const MF_STRING: u32 = 0x00000000;
    pub const MF_GRAYED: u32 = 0x00000001;
    pub const MF_DISABLED: u32 = 0x00000002;
    pub const MF_CHECKED: u32 = 0x00000008;
    pub const MF_UNCHECKED: u32 = 0x00000000;
    pub const MF_SEPARATOR: u32 = 0x00000800;

    pub const TPM_RETURNCMD: u32 = 0x0100;
    pub const TPM_RIGHTBUTTON: u32 = 0x0002;
    pub const TPM_NONOTIFY: u32 = 0x0080;

    // --- Menu Command Identifiers ---
    pub const ID_TRAY_TITLE: usize = 1000;
    pub const ID_TRAY_OPEN_DASHBOARD: usize = 1001;
    pub const ID_TRAY_QUICK_SCAN: usize = 1002;
    pub const ID_TRAY_TOGGLE_RTP: usize = 1003;
    pub const ID_TRAY_TOGGLE_GAMEMODE: usize = 1004;
    pub const ID_TRAY_TOGGLE_WORKMODE: usize = 1005;
    pub const ID_TRAY_OPEN_SETTINGS: usize = 1006;
    pub const ID_TRAY_CHROME_EXT: usize = 1007;
    pub const ID_TRAY_UPDATE_FEEDS: usize = 1008;
    pub const ID_TRAY_EXIT: usize = 1099;

    // --- Win32 FFI Declarations ---
    unsafe extern "system" {
        fn GetModuleHandleW(lpModuleName: *const u16) -> *mut c_void;
        fn RegisterClassExW(lpWndClass: *const WNDCLASSEXW) -> u16;
        fn CreateWindowExW(
            dwExStyle: u32,
            lpClassName: *const u16,
            lpWindowName: *const u16,
            dwStyle: u32,
            X: i32,
            Y: i32,
            nWidth: i32,
            nHeight: i32,
            hWndParent: *mut c_void,
            hMenu: *mut c_void,
            hInstance: *mut c_void,
            lpParam: *mut c_void,
        ) -> *mut c_void;
        fn DestroyWindow(hWnd: *mut c_void) -> i32;
        fn DefWindowProcW(hWnd: *mut c_void, Msg: u32, wParam: usize, lParam: isize) -> isize;
        fn LoadIconW(hInstance: *mut c_void, lpIconName: *const u16) -> *mut c_void;
        fn Shell_NotifyIconW(dwMessage: u32, lpData: *mut NOTIFYICONDATAW) -> i32;
        fn CreatePopupMenu() -> *mut c_void;
        fn AppendMenuW(hMenu: *mut c_void, uFlags: u32, uIDNewItem: usize, lpNewItem: *const u16) -> i32;
        fn TrackPopupMenuEx(
            hMenu: *mut c_void,
            uFlags: u32,
            x: i32,
            y: i32,
            hWnd: *mut c_void,
            lptpm: *mut c_void,
        ) -> i32;
        fn DestroyMenu(hMenu: *mut c_void) -> i32;
        fn GetCursorPos(lpPoint: *mut POINT) -> i32;
        fn SetForegroundWindow(hWnd: *mut c_void) -> i32;
        fn PostMessageW(hWnd: *mut c_void, Msg: u32, wParam: usize, lParam: isize) -> i32;
        fn GetMessageW(lpMsg: *mut MSG, hWnd: *mut c_void, wMsgFilterMin: u32, wMsgFilterMax: u32) -> i32;
        fn TranslateMessage(lpMsg: *const MSG) -> i32;
        fn DispatchMessageW(lpMsg: *const MSG) -> isize;
        fn PostQuitMessage(nExitCode: i32);
    }

    // Thread-safe global references for the static Win32 Window Procedure
    static GLOBAL_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(7890);
    static GLOBAL_CONFIG: std::sync::OnceLock<Arc<RwLock<GuardConfig>>> = std::sync::OnceLock::new();
    static GLOBAL_HWND: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
    static RUNNING: AtomicBool = AtomicBool::new(true);

    fn to_wstring(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn copy_to_fixed_wstr<const N: usize>(src: &str, dest: &mut [u16; N]) {
        let wide = to_wstring(src);
        let len = wide.len().min(N - 1);
        dest[..len].copy_from_slice(&wide[..len]);
        dest[len] = 0;
    }

    /// Windows Window Procedure for hidden message window
    unsafe extern "system" fn tray_wnd_proc(
        hwnd: *mut c_void,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
        match msg {
            WM_TRAYICON => {
                let event = lparam as usize;
                if event == WM_LBUTTONUP || event == WM_LBUTTONDBLCLK {
                    // Debounce: Double-click veya peş peşe tıklamalarda birden fazla pencere açılmasını engelle (450ms)
                    let now = unsafe { GetTickCount64() };
                    let prev = LAST_LBUTTON_TICK.swap(now, Ordering::Relaxed);
                    if now.saturating_sub(prev) > 450 {
                        let port = GLOBAL_PORT.load(Ordering::Relaxed);
                        let url = format!("http://localhost:{}", port);
                        launch_desktop_app_window(&url);
                    }
                } else if event == WM_RBUTTONUP || event == WM_CONTEXTMENU {
                    // Right click: Display context menu
                    unsafe {
                        show_tray_menu(hwnd);
                    }
                }
                0
            }
            WM_DESTROY => {
                RUNNING.store(false, Ordering::SeqCst);
                unsafe {
                    PostQuitMessage(0);
                }
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    /// Populates and renders the system tray context menu with live configuration flags
    unsafe fn show_tray_menu(hwnd: *mut c_void) {
        let mut pt = POINT::default();
        if GetCursorPos(&mut pt) == 0 {
            return;
        }

        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            return;
        }

        // Query current config state and live system mode synchronously
        let rtp_active = if let Some(cfg_lock) = GLOBAL_CONFIG.get() {
            if let Ok(cfg) = cfg_lock.try_read() {
                cfg.rtp.enabled
            } else {
                true
            }
        } else {
            true
        };

        let (current_mode, _) = crate::engines::SystemModeEngine::get_status();
        let game_active = current_mode == crate::engines::SystemMode::Game;
        let work_active = current_mode == crate::engines::SystemMode::Work;

        // Header (Disabled Title)
        let title_w = to_wstring("🛡️ Project Guard EDR v1.1.0");
        AppendMenuW(hmenu, MF_STRING | MF_DISABLED | MF_GRAYED, ID_TRAY_TITLE, title_w.as_ptr());
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // Open Dashboard
        let dash_w = to_wstring("🌐 SOC Kontrol Panelini Aç");
        AppendMenuW(hmenu, MF_STRING, ID_TRAY_OPEN_DASHBOARD, dash_w.as_ptr());

        // Quick Scan
        let scan_w = to_wstring("⚡ Hızlı Sistem Taraması Başlat");
        AppendMenuW(hmenu, MF_STRING, ID_TRAY_QUICK_SCAN, scan_w.as_ptr());

        // RTP Toggle
        let rtp_text = if rtp_active {
            "🛡️ Gerçek Zamanlı Koruma (RTP) [AKTİF]"
        } else {
            "🛡️ Gerçek Zamanlı Koruma (RTP) [DURAKLATILDI]"
        };
        let rtp_w = to_wstring(rtp_text);
        let rtp_flag = if rtp_active { MF_CHECKED } else { MF_UNCHECKED };
        AppendMenuW(hmenu, MF_STRING | rtp_flag, ID_TRAY_TOGGLE_RTP, rtp_w.as_ptr());

        // Game Mode Toggle
        let game_text = if game_active {
            "🎮 Windows Oyun Modu [AÇIK]"
        } else {
            "🎮 Windows Oyun Modu [KAPALI]"
        };
        let game_w = to_wstring(game_text);
        let game_flag = if game_active { MF_CHECKED } else { MF_UNCHECKED };
        AppendMenuW(hmenu, MF_STRING | game_flag, ID_TRAY_TOGGLE_GAMEMODE, game_w.as_ptr());

        // Work Mode Toggle
        let work_text = if work_active {
            "💼 Windows İş & Gizlilik Modu [AÇIK]"
        } else {
            "💼 Windows İş & Gizlilik Modu [KAPALI]"
        };
        let work_w = to_wstring(work_text);
        let work_flag = if work_active { MF_CHECKED } else { MF_UNCHECKED };
        AppendMenuW(hmenu, MF_STRING | work_flag, ID_TRAY_TOGGLE_WORKMODE, work_w.as_ptr());

        // Settings
        let sett_w = to_wstring("⚙️ Sistem & Koruma Ayarları");
        AppendMenuW(hmenu, MF_STRING, ID_TRAY_OPEN_SETTINGS, sett_w.as_ptr());

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // Chrome Web Shield Extension
        let ext_w = to_wstring("📦 Chrome Web Kalkanı Eklentisini İndir (.zip)");
        AppendMenuW(hmenu, MF_STRING, ID_TRAY_CHROME_EXT, ext_w.as_ptr());

        // Update Feeds
        let update_w = to_wstring("🔄 Tehdit İstihbaratını ve İmzaları Güncelle");
        AppendMenuW(hmenu, MF_STRING, ID_TRAY_UPDATE_FEEDS, update_w.as_ptr());

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // Exit
        let exit_w = to_wstring("❌ Project Guard'ı Kapat (Çıkış)");
        AppendMenuW(hmenu, MF_STRING, ID_TRAY_EXIT, exit_w.as_ptr());

        // Crucial Win32 sequence to ensure menu dismisses on outside clicks
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenuEx(
            hmenu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
            pt.x,
            pt.y,
            hwnd,
            std::ptr::null_mut(),
        );
        PostMessageW(hwnd, 0, 0, 0);
        DestroyMenu(hmenu);

        if cmd > 0 {
            handle_tray_command(hwnd, cmd as usize);
        }
    }

    /// Handles actions triggered from the system tray context menu
    fn handle_tray_command(hwnd: *mut c_void, cmd: usize) {
        let port = GLOBAL_PORT.load(Ordering::Relaxed);
        match cmd {
            ID_TRAY_OPEN_DASHBOARD => {
                let url = format!("http://localhost:{}", port);
                launch_desktop_app_window(&url);
            }
            ID_TRAY_QUICK_SCAN => {
                let url = format!("http://localhost:{}/#tab-scan", port);
                launch_desktop_app_window(&url);
                send_balloon_notification(
                    hwnd,
                    "⚡ Project Guard Tarama",
                    "Hızlı tarama paneli açıldı. Kritik sistem yolları ve süreçler taranıyor.",
                    NIIF_INFO,
                );
            }
            ID_TRAY_TOGGLE_RTP => {
                if let Some(cfg_lock) = GLOBAL_CONFIG.get() {
                    let cfg_clone = Arc::clone(cfg_lock);
                    tokio::spawn(async move {
                        let mut cfg = cfg_clone.write().await;
                        cfg.rtp.enabled = !cfg.rtp.enabled;
                        let _ = cfg.save();
                    });
                }
                send_balloon_notification(
                    hwnd,
                    "🛡️ Gerçek Zamanlı Koruma",
                    "RTP kalkanı çalışma durumu güncellendi.",
                    NIIF_INFO,
                );
            }
            ID_TRAY_TOGGLE_GAMEMODE => {
                let port_val = port;
                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let _ = client
                        .post(&format!("http://localhost:{}/api/mode/set", port_val))
                        .json(&serde_json::json!({ "mode": "gaming" }))
                        .send()
                        .await;
                });
                send_balloon_notification(
                    hwnd,
                    "🎮 Windows Oyun Modu",
                    "Oyun modu optimizasyonları ve düşük gecikme modu uygulandı.",
                    NIIF_INFO,
                );
            }
            ID_TRAY_TOGGLE_WORKMODE => {
                let port_val = port;
                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let _ = client
                        .post(&format!("http://localhost:{}/api/mode/set", port_val))
                        .json(&serde_json::json!({ "mode": "work" }))
                        .send()
                        .await;
                });
                send_balloon_notification(
                    hwnd,
                    "💼 Windows İş & Gizlilik Modu",
                    "Kamera/mikrofon koruması ve telemetri izolasyonu etkinleştirildi.",
                    NIIF_INFO,
                );
            }
            ID_TRAY_OPEN_SETTINGS => {
                let url = format!("http://localhost:{}/#tab-settings", port);
                launch_desktop_app_window(&url);
            }
            ID_TRAY_CHROME_EXT => {
                let url = format!("http://localhost:{}/api/extension/download", port);
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "start", &url])
                    .creation_flags(0x08000000)
                    .spawn();
                send_balloon_notification(
                    hwnd,
                    "📦 Chrome Web Kalkanı",
                    "Eklenti paketi (.zip) hazırlanıyor ve indiriliyor.",
                    NIIF_INFO,
                );
            }
            ID_TRAY_UPDATE_FEEDS => {
                let port_val = port;
                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let _ = client
                        .post(&format!("http://localhost:{}/api/update", port_val))
                        .send()
                        .await;
                });
                send_balloon_notification(
                    hwnd,
                    "🔄 Tehdit İstihbaratı",
                    "MalwareBazaar, ThreatFox, USOM ve YARA kural güncellemesi arka planda başlatıldı.",
                    NIIF_INFO,
                );
            }
            ID_TRAY_EXIT => {
                // Remove tray icon from taskbar and shut down cleanly
                unsafe {
                    let mut nid = NOTIFYICONDATAW {
                        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                        hWnd: hwnd,
                        uID: 1001,
                        uFlags: 0,
                        uCallbackMessage: 0,
                        hIcon: std::ptr::null_mut(),
                        szTip: [0; 128],
                        dwState: 0,
                        dwStateMask: 0,
                        szInfo: [0; 256],
                        uTimeoutOrVersion: 0,
                        szInfoTitle: [0; 64],
                        dwInfoFlags: 0,
                        guidItem: [0; 16],
                        hBalloonIcon: std::ptr::null_mut(),
                    };
                    Shell_NotifyIconW(NIM_DELETE, &mut nid);
                    DestroyWindow(hwnd);
                }
                std::process::exit(0);
            }
            _ => {}
        }
    }

    /// Displays an interactive balloon notification from the tray icon
    pub fn send_balloon_notification(
        hwnd: *mut c_void,
        title: &str,
        message: &str,
        flags: u32,
    ) {
        unsafe {
            let mut nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1001,
                uFlags: NIF_INFO,
                uCallbackMessage: WM_TRAYICON,
                hIcon: std::ptr::null_mut(),
                szTip: [0; 128],
                dwState: 0,
                dwStateMask: 0,
                szInfo: [0; 256],
                uTimeoutOrVersion: 0,
                szInfoTitle: [0; 64],
                dwInfoFlags: flags,
                guidItem: [0; 16],
                hBalloonIcon: std::ptr::null_mut(),
            };
            copy_to_fixed_wstr(title, &mut nid.szInfoTitle);
            copy_to_fixed_wstr(message, &mut nid.szInfo);
            Shell_NotifyIconW(NIM_MODIFY, &mut nid);
        }
    }

    /// Runs the Windows System Tray message pump on the main thread (blocking until exit)
    pub fn run_system_tray(port: u16, config: Arc<RwLock<GuardConfig>>) {
        GLOBAL_PORT.store(port, Ordering::Relaxed);
        let _ = GLOBAL_CONFIG.set(config);

        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = to_wstring("ProjectGuardTrayClass");
            let window_name = to_wstring("ProjectGuardTrayWindow");

            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: tray_wnd_proc,
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinstance,
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm: std::ptr::null_mut(),
            };

            RegisterClassExW(&wnd_class);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                window_name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null_mut(),
            );

            if hwnd.is_null() {
                eprintln!("[!] Sistem tepsisi penceresi oluşturulamadı.");
                return;
            }
            GLOBAL_HWND.store(hwnd as isize, Ordering::Relaxed);

            // Load embedded icon (Resource #1 from build.rs winres) or standard shield
            let mut h_icon = LoadIconW(hinstance, 1 as *const u16);
            if h_icon.is_null() {
                // Fallback to standard application icon
                h_icon = LoadIconW(std::ptr::null_mut(), 32512 as *const u16);
            }

            // Create NotifyIconData
            let mut nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: 1001,
                uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO,
                uCallbackMessage: WM_TRAYICON,
                hIcon: h_icon,
                szTip: [0; 128],
                dwState: 0,
                dwStateMask: 0,
                szInfo: [0; 256],
                uTimeoutOrVersion: 0,
                szInfoTitle: [0; 64],
                dwInfoFlags: NIIF_INFO,
                guidItem: [0; 16],
                hBalloonIcon: std::ptr::null_mut(),
            };

            copy_to_fixed_wstr("Project Guard EDR (Koruma Aktif)", &mut nid.szTip);
            copy_to_fixed_wstr("🛡️ Project Guard EDR Kalkanı Devrede", &mut nid.szInfoTitle);
            let balloon_msg = format!("Gerçek zamanlı savunma ve EDR aktif. SOC kontrol paneli: http://localhost:{}", port);
            copy_to_fixed_wstr(&balloon_msg, &mut nid.szInfo);

            Shell_NotifyIconW(NIM_ADD, &mut nid);

            // Run standard Win32 Message Loop
            let mut msg = MSG {
                hwnd: std::ptr::null_mut(),
                message: 0,
                wParam: 0,
                lParam: 0,
                time: 0,
                pt: POINT::default(),
            };

            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Clean up icon on shutdown
            Shell_NotifyIconW(NIM_DELETE, &mut nid);
        }
    }
}

#[cfg(not(windows))]
pub mod win_tray {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::config::GuardConfig;

    pub fn run_system_tray(_port: u16, _config: Arc<RwLock<GuardConfig>>) {
        println!("Sistem tepsisi yalnızca Windows işletim sisteminde desteklenmektedir.");
    }
}

pub use win_tray::run_system_tray;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn test_tray_identifiers_and_constants() {
        assert_eq!(win_tray::WM_TRAYICON, win_tray::WM_APP + 101);
        assert_eq!(win_tray::ID_TRAY_TITLE, 1000);
        assert_eq!(win_tray::ID_TRAY_OPEN_DASHBOARD, 1001);
        assert_eq!(win_tray::ID_TRAY_QUICK_SCAN, 1002);
        assert_eq!(win_tray::ID_TRAY_TOGGLE_RTP, 1003);
        assert_eq!(win_tray::ID_TRAY_TOGGLE_GAMEMODE, 1004);
        assert_eq!(win_tray::ID_TRAY_TOGGLE_WORKMODE, 1005);
        assert_eq!(win_tray::ID_TRAY_OPEN_SETTINGS, 1006);
        assert_eq!(win_tray::ID_TRAY_CHROME_EXT, 1007);
        assert_eq!(win_tray::ID_TRAY_UPDATE_FEEDS, 1008);
        assert_eq!(win_tray::ID_TRAY_EXIT, 1099);
    }
}

