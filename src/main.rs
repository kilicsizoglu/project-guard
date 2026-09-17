#![windows_subsystem = "windows"]

mod config;
mod core;
mod db;
mod engines;
mod feeds;
mod monitor;
mod quarantine;
mod service;
mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use core::{HtmlReportGenerator, ScanOrchestrator, ScanSummary};
use db::DbStore;
use engines::{ClamAvEngine, HashEngine, HeuristicEngine, ProcessScanner, ScanEngine, YaraEngine};
use feeds::FeedUpdater;
use monitor::RealTimeMonitor;
use quarantine::QuarantineManager;
use sha2::Digest;

#[cfg(windows)]
pub fn hide_console() {
    unsafe {
        unsafe extern "system" {
            fn GetConsoleWindow() -> *mut std::ffi::c_void;
            fn ShowWindow(hWnd: *mut std::ffi::c_void, nCmdShow: i32) -> i32;
            fn FreeConsole() -> i32;
        }
        let hwnd = GetConsoleWindow();
        if !hwnd.is_null() {
            ShowWindow(hwnd, 0); // 0 = SW_HIDE
            FreeConsole();
        }
    }
}

#[cfg(not(windows))]
pub fn hide_console() {}

#[cfg(windows)]
pub fn attach_console_for_cli() {
    unsafe {
        unsafe extern "system" {
            fn AttachConsole(dwProcessId: u32) -> i32;
            fn SetStdHandle(nStdHandle: u32, hHandle: *mut std::ffi::c_void) -> i32;
            fn CreateFileW(
                lpFileName: *const u16,
                dwDesiredAccess: u32,
                dwShareMode: u32,
                lpSecurityAttributes: *mut std::ffi::c_void,
                dwCreationDisposition: u32,
                dwFlagsAndAttributes: u32,
                hTemplateFile: *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
        }
        if AttachConsole(0xFFFFFFFF) != 0 {
            let conout: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
            let handle = CreateFileW(
                conout.as_ptr(),
                0x40000000 | 0x80000000,
                1 | 2,
                std::ptr::null_mut(),
                3,
                0,
                std::ptr::null_mut(),
            );
            if !handle.is_null() && handle != (-1isize as *mut std::ffi::c_void) {
                SetStdHandle(0xFFFFFFF5, handle); // STD_OUTPUT_HANDLE
                SetStdHandle(0xFFFFFFF4, handle); // STD_ERROR_HANDLE
            }
        }
    }
}

#[cfg(not(windows))]
pub fn attach_console_for_cli() {}

#[derive(Parser)]
#[command(
    name = "guard",
    author = "Project Guard Team",
    version = "1.1.0",
    about = "Acik kaynak motorlardan ve tehdit istihbaratindan beslenen moduler antivirus ve tehdit avlama sistemi"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Bir dosya veya dizini coklu motorlarla tarar
    Scan {
        /// Taranacak dosya veya dizin yolu
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Zararli tespit edildiginde otomatik karantinaya al
        #[arg(short, long)]
        quarantine: bool,

        /// Alt dizinleri yinelemeli olarak tara
        #[arg(short, long, default_value_t = true)]
        recursive: bool,

        /// Sonuclari JSON formatinda cikar
        #[arg(long)]
        json: bool,

        /// Sonuclari modern HTML gorsel rapor formatinda kaydet (Ornek: --html scan_report.html)
        #[arg(long)]
        html: Option<PathBuf>,
    },

    /// Sistemde aktif calisan tum surecleri, komut satirlarini ve bellek yuklerini tarar
    ScanProcesses {
        /// Tehdit tespit edilen zararlı surecleri aninda sonlandir (KILL)
        #[arg(short, long)]
        kill: bool,
    },

    /// Acik kaynak tehdit istihbarati akislarindan (MalwareBazaar, ThreatFox, YARA, ClamAV) imzalari gunceller
    Update,

    /// Bir dizini gercek zamanli olarak izler ve yeni/degisen dosyalari aninda tarar (RTP)
    Monitor {
        /// Izlenecek dizin
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Tehdit bulundugunda otomatik karantinaya al
        #[arg(short, long)]
        quarantine: bool,
    },

    /// Karantina kasasini yonetir (listeleme, geri yukleme, silme)
    Quarantine {
        #[command(subcommand)]
        action: QuarantineCommands,
    },

    /// Sistem durumunu, imza sayilarini ve aktif motorlari gosterir
    Status,

    /// Tarama motorlarinin islem hacmini ve hizini test eder (Benchmark)
    Benchmark,

    /// Guvenli EICAR standart test dosyasini olusturarak motorlari test eder
    TestEicar {
        /// Test dosyasinin olusturulacagi hedef dizin
        #[arg(default_value = "./test_malware_sample")]
        target_dir: PathBuf,
    },

    /// Sifir-Gun fidye yazilimlarina karsi stratejik yem (Canary / Honeypot) tuzaklari yerlestirir
    CanaryDeploy {
        /// Yem dosyalarinin yerlestirilecegi hedef dizin
        #[arg(default_value = ".")]
        target_dir: PathBuf,
    },

    /// Yem tuzak dosyalarini gercek zamanli izler ve herhangi bir sifreleme girisiminde alarm uretir
    CanaryWatch {
        /// Izlenecek dizin
        #[arg(default_value = ".")]
        watch_dir: PathBuf,
    },

    /// Sistemdeki aktif TCP baglantilarini tarar ve bilinen C2 arka kapi portlarini denetler
    ScanNetwork,

    /// Windows baslangic ve kalicilik noktalarini (Kayit Defteri Run, Baslangic Klasoru, Gorev Zamanlayici) denetler
    ScanPersistence,

    /// Canli sureclerin bellek bolgelerini (RWX, Unbacked Private Executable) ve bellek ici enjeksiyonlari tarar
    ScanMemory {
        /// Taranacak belirli bir surecin PID numarasi (Belirtilmezse tum surecler taranir)
        #[arg(short, long)]
        pid: Option<u32>,
    },

    /// Cikarilabilir USB bellekleri ve harici suruculeri otomatik algilar, autorun ve kisayol solucanlarini denetler
    ScanUsb {
        /// Taranacak belirli bir surucu yolu (Orn: E:\ veya F:\). Belirtilmezse takili tum USB suruculeri taranir
        #[arg(short, long)]
        drive: Option<PathBuf>,

        /// Tespit edilen zararlilari otomatik karantinaya al
        #[arg(short, long)]
        quarantine: bool,
    },

    /// Belirtilen PID'ye sahip zararli bir sureci aninda zorla sonlandirir (Kill Switch)
    KillProcess {
        /// Sonlandirilacak surecin PID'si
        pid: u32,
    },

    /// Microsoft imzali meşru ikililerin kotuye kullanimini (LOLBAS) ve ebeveyn-cocuk anomalisini tarar
    ScanLolbas {
        /// Tehdit tespit edilen surecleri aninda sonlandir (KILL)
        #[arg(short, long)]
        kill: bool,
    },

    /// Windows Defender saglik durumunu ve cift katmanli uyumluluk telemetrisini denetler
    DefenderStatus,

    /// Savunmasiz ve kotuye kullanilan cekirdek suruculerini (LOLDrivers / BYOVD) ve hazirlik alanlarini tarar
    ScanDrivers,

    /// Kritik sistem dosyalari icin guvenli kriptografik SHA-256 referans (baseline) olusturur
    FimInit,

    /// Kritik sistem dosyalarini referans ile karsilastirip yetkisiz degisiklik ve tampering kontrolu yapar
    FimCheck,

    /// PowerShell, VBScript, Batch betiklerini ve AMSI atlatma girisimlerini analiz eder
    ScanScript {
        /// Taranacak betik dosyasi veya metin icerigi
        target: String,
    },

    /// Ikili (PE/DLL) veya metin dosyalarindan gizli dize, public IP, URL ve C2 botnet eslesmelerini ayiklar
    ExtractIocs {
        /// Analiz edilecek dosya yolu
        target: String,
    },

    /// Windows Olay Günlüklerini (PowerShell 4104 ScriptBlock, Defender 1116/1117, Güvenlik 1102) denetler
    ScanEventlog {
        /// İncelenecek maksimum olay sayısı (Varsayılan: 25)
        #[arg(short, long, default_value_t = 25)]
        limit: usize,
    },

    /// Taşınabilir Çalıştırılabilir (PE/DLL) dosyasında derin statik triyaj, bölüm entropisi ve ATT&CK yetenek matrisi çıkarır
    Triage {
        /// Analiz edilecek PE dosya yolu
        target: String,
    },

    /// Açık kaynak topluluk YARA kurallarını (YARA-Forge, Cobalt Strike, Fidye Yazılımı) senkronize eder ve derler
    SyncYara,

    /// Modern Web tabanli Siber Guvenlik Kontrol Panelini (UI Dashboard) baslatir
    Ui {
        /// Calisacagi yerel port (Varsayilan: 7890)
        #[arg(short, long, default_value_t = 7890)]
        port: u16,
    },

    /// Windows Masaustu Uygulamasi Penceresi (Standalone Desktop Window) olarak baslatir
    Gui {
        /// Calisacagi yerel port (Varsayilan: 7890)
        #[arg(short, long, default_value_t = 7890)]
        port: u16,
    },

    /// Windows Hizmet (Service) yonetimi: 7/24 arka plan EDR ve canli koruma
    Service {
        #[command(subcommand)]
        action: ServiceCommands,
    },

    /// CISA Bilinen ve Aktif İstismar Edilen Zafiyetler Kataloğu (CISA KEV) denetimini yürütür
    CisaKev,

    /// Windows Dosya Gezgini (Explorer) sağ tık menüsüne 'Project Guard ile Tara' seçeneğini kaydeder
    RegisterShell {
        /// Özel ikili dosya yolu (Varsayılan: çalışan project-guard.exe)
        #[arg(short, long)]
        exe_path: Option<PathBuf>,
    },

    /// Windows Dosya Gezgini (Explorer) sağ tık menüsünü kaldırır
    UnregisterShell,

    /// USOM (Siber Güvenlik Başkanlığı) güncel zararlı bağlantı ve C2 istihbaratını senkronize eder
    UpdateUsom,

    /// Shadowserver StealC infostealer tehditlerine karşı süreçleri ve hassas kimlik depolarını tarar
    ScanStealers {
        /// Tespit edilen zararlı süreçleri anında zorla sonlandır (KILL)
        #[arg(short, long)]
        kill: bool,
    },

    /// Center for Internet Security (CIS) Controls v8.1 ve Windows Hardening denetimini yürütür
    CisAudit,

    /// OpenSSF ve OWASP A03 yazılım tedarik zinciri (Supply Chain) ve bağımlılık taraması yapar
    ScanSupplyChain {
        /// Taranacak proje veya kaynak kod dizini
        #[arg(default_value = ".")]
        target: PathBuf,
    },

    /// FIRST.org EPSS (Exploit Prediction Scoring System) ile zafiyet istismar olasılığını sorgular
    EpssLookup {
        /// Sorgulanacak CVE numarası (Örn: CVE-2024-21338 veya 2024-38063)
        cve: String,
    },

    /// SANS ISC DShield bal küpü tehdit istihbaratından en çok saldıran IP'leri senkronize eder
    UpdateSans {
        /// Çekilecek maksimum IP sayısı (Varsayılan: 25)
        #[arg(short, long, default_value_t = 25)]
        limit: usize,
    },

    /// SigmaHQ açık kaynak kural standartlarıyla süreç ve komut satırı davranış anomalilerini tarar
    ScanSigma {
        /// Kritik tespit edilen süreçleri anında zorla sonlandır (KILL)
        #[arg(short, long)]
        kill: bool,
    },

    /// The Spamhaus Project DROP ve eDROP kurşun geçirmez botnet ağlarını senkronize eder
    UpdateSpamhaus,

    /// Abuse.ch URLhaus veritabanından en güncel aktif zararlı URL ve indirme beşikleri senkronize eder
    UpdateUrlhaus {
        /// Çekilecek maksimum kayıt sayısı (Varsayılan: 500)
        #[arg(short, long, default_value_t = 500)]
        limit: usize,
    },

    /// Abuse.ch URLhaus ve yerel tehdit veritabanında bir bağlantının (URL) itibarını sorgular
    LookupUrl {
        /// Sorgulanacak web adresi / URL
        url: String,
    },

    /// EFF ve Citizen Lab yönergeleriyle gizli casus yazılımları, takip ajanlarını ve dinleyicileri tarar
    ScanStalkerware {
        /// Tespit edilen casus yazılım süreçlerini anında zorla sonlandır (KILL)
        #[arg(short, long)]
        kill: bool,
    },

    /// Kamera ve mikrofon donanımını kullanan uygulamaları ve anlık erişim durumunu listeler
    PrivacyStatus,

    /// Kamera ve mikrofon erişimlerini canlı izler; donanım açıldığında Windows Toast bildirimi fırlatır
    PrivacyWatch {
        /// Denetim aralığı (saniye, varsayılan: 2)
        #[arg(short, long, default_value_t = 2)]
        interval: u64,
    },

    /// Windows Oyun ve İş/Gizlilik Modu yönetimi (WinDebloat ve Performans Optimizasyonu)
    Mode {
        #[command(subcommand)]
        action: Option<ModeCommands>,
    },

    /// Windows Bildirim Merkezine (Action Center) yerel Toast bildirimi gönderir
    Notify {
        /// Bildirim başlığı
        #[arg(short, long)]
        title: String,
        /// Bildirim mesaj metni
        #[arg(short, long)]
        message: String,
    },

    /// Merkezi ayarlar ve yapılandırma yönetimi (göster, değiştir, sıfırla, içe/dışa aktar)
    Config {
        #[command(subcommand)]
        action: Option<ConfigCommands>,
    },

    /// Windows Sistem Tepsisinde (System Tray / Görev Çubuğu Bildirim Alanı) çalıştırır
    Tray {
        /// Calisacagi yerel port (Varsayilan: 7890)
        #[arg(short, long, default_value_t = 7890)]
        port: u16,
    },

    /// Chrome Web Shield (Web Kalkanı) tarayıcı eklentisini doğrular ve .zip olarak paketler
    PackageExtension,
}

#[derive(Subcommand, Debug, Clone)]
enum ConfigCommands {
    /// Mevcut tüm yapılandırma parametrelerini gösterir
    Show,
    /// Belirtilen ayar anahtarının değerini okur (Örn: rtp.max_file_size_mb)
    Get { key: String },
    /// Belirtilen ayarın değerini günceller ve kaydeder (Örn: rtp.max_file_size_mb 500)
    Set { key: String, value: String },
    /// Ayarları fabrika varsayılanlarına sıfırlar
    Reset,
    /// Yapılandırmayı JSON dosyası olarak dışa aktarır
    Export { path: Option<PathBuf> },
    /// JSON dosyasından yapılandırmayı yükler ve uygular
    Import { path: PathBuf },
}

#[derive(Subcommand, Debug, Clone)]
enum ModeCommands {
    /// Mevcut çalışma modunu ve optimizasyon parametrelerini sorgular
    Status,
    /// Oyun Modunu devreye sokar (Ultra düşük gecikme, NetworkThrottling iptali, GPU önceliği)
    Game,
    /// İş ve Gizlilik Modunu devreye sokar (WinDebloat telemetri temizliği, Bing kapatma, reklam ID iptali)
    Work,
    /// Tüm ayarları orijinal Windows varsayılanlarına geri yükler (Rollback)
    Restore,
}

#[derive(Subcommand)]
enum ServiceCommands {
    /// Project Guard Windows Hizmetini sisteme kaydeder (Install)
    Install,
    /// Project Guard Windows Hizmetini sistemden kaldirir (Uninstall)
    Uninstall,
    /// Project Guard Windows Hizmetini baslatir (Start)
    Start,
    /// Project Guard Windows Hizmetini durdurur (Stop)
    Stop,
    /// Project Guard Windows Hizmet durumunu sorgular (Status)
    Status,
    /// Hizmet arka plan calisma dongusu (SCM dahili cagirisi)
    Run,
}

#[derive(Subcommand)]
enum QuarantineCommands {
    /// Karantinadaki dosyalari listeler
    List,
    /// Karantinadaki dosyayi orijinal yerine geri yukler
    Restore {
        /// Karantina ID'si
        id: String,
    },
    /// Karantinadaki dosyayi kalici olarak siler
    Delete {
        /// Karantina ID'si
        id: String,
    },
}

fn get_project_dirs() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let base_dir = dirs_base();
    let db_path = base_dir.join("guard.db");
    let quarantine_dir = base_dir.join("quarantine");
    let rules_dir = base_dir.join("rules");

    fs::create_dir_all(&base_dir)?;
    fs::create_dir_all(&quarantine_dir)?;
    fs::create_dir_all(&rules_dir)?;

    Ok((db_path, quarantine_dir, rules_dir))
}

fn dirs_base() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\ProjectGuard")
}

fn build_orchestrator(
    db: Arc<Mutex<DbStore>>,
    quarantine_dir: PathBuf,
    rules_dir: PathBuf,
) -> Result<(ScanOrchestrator, Arc<QuarantineManager>, Arc<HashEngine>, Arc<YaraEngine>)> {
    let q_mgr = Arc::new(QuarantineManager::new(quarantine_dir, Arc::clone(&db))?);

    let hash_engine = Arc::new(HashEngine::new(Arc::clone(&db))?);
    let yara_engine = Arc::new(YaraEngine::new(rules_dir)?);
    let heuristic_engine = Arc::new(HeuristicEngine::new());
    let clamav_engine = Arc::new(ClamAvEngine::new(Some(3310), Arc::clone(&db)));
    let defender_engine = Arc::new(engines::WindowsDefenderEngine::new());
    let script_engine = Arc::new(engines::ScriptHunter::new());

    let engines: Vec<Arc<dyn ScanEngine>> = vec![
        Arc::clone(&hash_engine) as Arc<dyn ScanEngine>,
        Arc::clone(&yara_engine) as Arc<dyn ScanEngine>,
        heuristic_engine as Arc<dyn ScanEngine>,
        clamav_engine as Arc<dyn ScanEngine>,
        defender_engine as Arc<dyn ScanEngine>,
        script_engine as Arc<dyn ScanEngine>,
    ];

    let orchestrator = ScanOrchestrator::new(engines, Some(Arc::clone(&q_mgr)));
    Ok((orchestrator, q_mgr, hash_engine, yara_engine))
}

fn print_banner() {
    println!(
        "{}",
        r#"
  ____            _           _      ____                  _ 
 |  _ \ _ __ ___ (_) ___  ___| |_   / ___|_   _  __ _ _ __| |
 | |_) | '__/ _ \| |/ _ \/ __| __| | |  _| | | |/ _` | '__| |
 |  __/| | | (_) | |  __/ (__| |_  | |_| | |_| | (_| | |  |_|
 |_|   |_|  \___// |\___|\___|\__|  \____|\__,_|\__,_|_|  (_)
               |__/                                           
    -- Acik Kaynak Coklu Motor Antivirus Sistemi v1.1.0 --
"#
        .cyan()
        .bold()
    );
}

fn main() {
    if let Err(e) = run_main() {
        let temp_log = std::env::temp_dir().join("project_guard_crash.log");
        let _ = std::fs::write(&temp_log, format!("Project Guard başlatılırken kritik bir hata oluştu:\n{:#?}\n\nBu dosya otomatik oluşturulmuştur.", e));
        
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // Basit bir uyarı göstermek için PowerShell'i kullan (Harici kütüphane gerektirmeyen fallback)
            let msg = format!("Project Guard başlatılamadı. Hata detayı: {}", temp_log.display());
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &format!("[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.MessageBox]::Show('{}', 'Project Guard Hata', 0, 16)", msg)])
                .creation_flags(0x08000000)
                .spawn();
        }

        std::process::exit(1);
    }
}

fn run_main() -> Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Commands::Gui { port: 7890 });

    match &command {
        Commands::Gui { .. } | Commands::Tray { .. } => {
            hide_console();
        }
        _ => {
            attach_console_for_cli();
        }
    }

    let (db_path, quarantine_dir, rules_dir) = get_project_dirs()?;
    let db = Arc::new(Mutex::new(DbStore::new(&db_path)?));

    match command {
        Commands::Scan {
            target,
            quarantine,
            recursive,
            json,
            html,
        } => {
            if !json {
                print_banner();
                println!("Hedef Taramasi Baslatiliyor: {:?}", target);
                println!("Otomatik Karantina: {}", if quarantine { "EVET".yellow().bold() } else { "HAYIR".white() });
                println!("------------------------------------------------------------");
            }

            let (orchestrator, _, _, _) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir)?;
            let summary = orchestrator.scan_target(&target, recursive, quarantine, !json)?;

            if let Some(ref html_path) = html {
                HtmlReportGenerator::generate(&summary, html_path)?;
                if !json {
                    println!("{}", format!("[+] HTML Guvenlik Raporu olusturuldu: {:?}", html_path).green().bold());
                }
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print_scan_summary(&summary);
            }

            // Veritabanına tarama geçmişini kaydet
            let db_guard = db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            let _ = db_guard.log_scan(
                &summary.target_path,
                summary.scanned_files,
                summary.infected_files,
                summary.elapsed_ms,
            );
        }

        Commands::ScanProcesses { kill } => {
            print_banner();
            println!("{}", "Aktif Surecler ve Bellek Taramasi Baslatiliyor...".bold());
            println!("Tehlikeli Surecleri Sonlandir (KILL): {}", if kill { "EVET".red().bold() } else { "HAYIR (Yalnizca Rapor)".white() });
            println!("------------------------------------------------------------");

            let (orchestrator, _, _, _) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir)?;
            let proc_scanner = ProcessScanner::new(Arc::new(orchestrator));
            let reports = proc_scanner.scan_all_processes(kill)?;

            println!("\n{}", "==================== SUREC TARAMA RAPORU ====================".cyan().bold());
            if reports.is_empty() {
                println!("{}", "[OK] Aktif calisan hicbir surecte tehdit tespit edilmedi. Sistem temiz.".green().bold());
            } else {
                println!("{}", format!("[!] TESPIT EDILEN ZARARLI/SUPHELI SURECLER (Toplam: {}):", reports.len()).red().bold());
                for rep in reports {
                    println!("\n-> PID: {} | Isim: {}", rep.pid.to_string().cyan().bold(), rep.name.yellow().bold());
                    if let Some(exe) = rep.exe_path {
                        println!("   Dosya: {:?}", exe);
                    }
                    if !rep.cmd.is_empty() {
                        println!("   Komut: {}", rep.cmd.join(" ").white());
                    }
                    for det in rep.detections {
                        println!("   Tehdit: {} ({}) [{}]", det.threat_name.red().bold(), det.severity.to_string().magenta(), det.engine_name.cyan());
                        println!("   Detay : {}", det.details);
                    }
                    if rep.killed {
                        println!("{}", "   [+] Aksiyon: Surec basariyla sonlandirildi (Terminated).".green().bold());
                    }
                }
            }
            println!("=============================================================");
        }

        Commands::Update => {
            print_banner();
            println!("{}", "Acik kaynak tehdit beslemeleri ve kural depolari guncelleniyor...".bold());
            println!("------------------------------------------------------------");

            let updater = FeedUpdater::new(Arc::clone(&db), rules_dir.clone());
            let result = updater.update_all()?;

            println!("\n{}", "Guncelleme Islemi Basariyla Tamamlandi:".green().bold());
            println!("  * MalwareBazaar'dan eklenen hash: {}", result.malwarebazaar_added);
            println!("  * ThreatFox'tan eklenen IOC:     {}", result.threatfox_added);
            println!("  * YARA-X kural dosyalari:         {}", result.yara_rules_synced);
            println!("  * ClamAV imza eslesmeleri:        {}", result.clamav_added);

            // Veritabanı durumunu göster
            let db_guard = db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
            let stats = db_guard.get_signature_stats()?;
            println!(
                "\nToplam Aktif Zararli Imza Sayisi: {}",
                stats.total_signatures.to_string().cyan().bold()
            );
        }

        Commands::Monitor { path, quarantine } => {
            print_banner();
            let (orchestrator, _, _, _) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir)?;
            let monitor = RealTimeMonitor::new(Arc::new(orchestrator));
            monitor.start_monitoring(&path, quarantine)?;
        }

        Commands::Quarantine { action } => {
            print_banner();
            let q_mgr = QuarantineManager::new(quarantine_dir, Arc::clone(&db))?;

            match action {
                QuarantineCommands::List => {
                    let entries = q_mgr.list_entries()?;
                    println!("{}", "Karantina Kasasindaki Dosyalar:".bold());
                    println!("-----------------------------------------------------------------------------------------");
                    if entries.is_empty() {
                        println!("{}", "Karantina kasasi temiz. Hicbir dosya bulunmuyor.".green());
                    } else {
                        for e in entries {
                            println!(
                                "[ID: {}] {} ({})",
                                e.id.cyan().bold(),
                                e.threat_name.red().bold(),
                                e.detected_engine.yellow()
                            );
                            println!("  Orijinal Yol: {}", e.original_path);
                            println!("  Kasa Konumu : {}", e.quarantined_path);
                            println!("  Boyut: {} bayt | Tarih: {}", e.file_size, e.date);
                            println!("  SHA256: {}", e.sha256);
                            println!("-----------------------------------------------------------------------------------------");
                        }
                    }
                }
                QuarantineCommands::Restore { id } => {
                    match q_mgr.restore_file(&id) {
                        Ok(orig) => {
                            println!(
                                "{}",
                                format!("[+] Dosya basariyla geri yuklendi: {:?}", orig)
                                    .green()
                                    .bold()
                            );
                        }
                        Err(e) => {
                            eprintln!("{}", format!("[-] Geri yukleme hatasi: {}", e).red());
                        }
                    }
                }
                QuarantineCommands::Delete { id } => {
                    match q_mgr.purge_file(&id) {
                        Ok(_) => {
                            println!(
                                "{}",
                                format!("[+] Karantinadaki dosya kalici olarak silindi: {}", id)
                                    .green()
                            );
                        }
                        Err(e) => {
                            eprintln!("{}", format!("[-] Silme hatasi: {}", e).red());
                        }
                    }
                }
            }
        }

        Commands::Status => {
            print_banner();
            println!("{}", "PROJECT GUARD SISTEM VE IMZA DURUMU".bold());
            println!("------------------------------------------------------------");

            let (stats, c2_count) = {
                let db_guard = db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
                let s = db_guard.get_signature_stats()?;
                let c2 = db_guard.get_c2_iocs_count().unwrap_or(0);
                (s, c2)
            };

            println!("Aktif Tarama Motorlari:");
            println!("  [x] YARA-X Engine (VirusTotal Saf Rust Kural Motoru)");
            println!("  [x] Hash-ThreatIntel Engine (MalwareBazaar & ThreatFox)");
            println!("  [x] Heuristic & Deep PE Analyzer (W^X Ihlali, API Kumesi, Entropi)");
            println!("  [x] Sigma Behavior Engine (MITRE ATT&CK Taktik ve Teknikleri)");
            println!("  [x] In-Memory Injection Hunter (Unbacked RWX ve Dosyasiz Kod)");
            println!("  [x] LOLBAS & Anomaly Hunter (Living Off The Land & Parent-Child)");
            println!("  [x] USB & Removable Media Guard (Autorun & LNK Kisayol Solucanlari)");
            println!("  [x] Persistence & Autoruns Hunter (Registry Run, Startup, SchTasks)");
            println!("  [x] ClamAV Adapter Engine (Yerel Clamd & CVD Imzalari)");
            println!("  [x] Dual-Layer Windows Defender Integration (MpCmdRun CLI & WdFilter Coexistence)");
            println!("  [x] Ransomware Canary Traps (Stratejik Yem Dosyalari)");
            println!("  [x] Feodo C2 Hunter (Aktif TCP Baglanti ve Botnet IP Eslesmesi)");

            println!("\nTehdit Imza ve İstihbarat Veritabani:");
            println!("  * Toplam Kayitli Imza   : {}", stats.total_signatures.to_string().cyan().bold());
            println!("  * MalwareBazaar Imzalari: {}", stats.malwarebazaar_count);
            println!("  * ThreatFox IOC Imzalari: {}", stats.threatfox_count);
            println!("  * ClamAV Acik Imzalari  : {}", stats.clamav_count);
            println!("  * Feodo Botnet C2 IP'ler: {}", c2_count.to_string().yellow().bold());
            println!("  * Ozel / Built-in Imza  : {}", stats.custom_count);

            if let Ok(def) = engines::DefenderStatusAuditor::query_status() {
                println!("\nWindows Defender Eşzamanlı Koruma:");
                println!("  * Real-Time Protection  : {}", if def.realtime_protection_enabled { "Aktif [OK]".green().bold() } else { "Devre Disi".red() });
                println!("  * Calisma Modu          : {}", def.coexistence_status.cyan().bold());
            }

            let q_mgr = QuarantineManager::new(quarantine_dir, Arc::clone(&db))?;
            let q_entries = q_mgr.list_entries()?;
            println!(
                "\nKarantina Kasasindaki Tehditler: {}",
                if q_entries.is_empty() {
                    "0 (Temiz)".green()
                } else {
                    format!("{} dosya", q_entries.len()).red().bold()
                }
            );
        }

        Commands::Benchmark => {
            print_banner();
            println!("{}", "PERFORMANS VE DONANIM HIZ TESTI (BENCHMARK)".bold());
            println!("------------------------------------------------------------");

            let test_data_size = 10 * 1024 * 1024; // 10 MB
            println!("1. 10 MB Sentetik Veri Hashing & Entropi Testi Calistiriliyor...");
            let dummy_data: Vec<u8> = (0..test_data_size).map(|i| (i % 256) as u8).collect();

            let start = Instant::now();
            let entropy = HeuristicEngine::calculate_entropy(&dummy_data);
            let elapsed_entropy = start.elapsed();
            println!("   -> Entropi Hesaplama: {:.2} (Sure: {:?})", entropy, elapsed_entropy);

            let start_hash = Instant::now();
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&dummy_data);
            let _ = hasher.finalize();
            let elapsed_hash = start_hash.elapsed();
            let throughput_mb = 10.0 / elapsed_hash.as_secs_f64();
            println!("   -> SHA256 Hashing Hizi: {:.2} MB/saniye (Sure: {:?})", throughput_mb, elapsed_hash);

            println!("\n2. YARA-X Kural Motoru Arama Testi Calistiriliyor...");
            let mut compiler = yara_x::Compiler::new();
            compiler.add_source(r#"
                rule Benchmark_Rule {
                    strings:
                        $s1 = "ThisIsABenchmarkStringInStream"
                    condition:
                        $s1
                }
            "#)?;
            let rules_test = compiler.build();
            let mut scanner = yara_x::Scanner::new(&rules_test);
            let start_yara = Instant::now();
            let _ = scanner.scan(&dummy_data)?;
            let elapsed_yara = start_yara.elapsed();
            let yara_throughput = 10.0 / elapsed_yara.as_secs_f64();
            println!("   -> YARA-X Bayt Tarama Hizi: {:.2} MB/saniye (Sure: {:?})", yara_throughput, elapsed_yara);

            println!("\n{}", "[+] Benchmark basariyla tamamlandi. Sistem yuksek performansla calisiyor.".green().bold());
        }

        Commands::TestEicar { target_dir } => {
            print_banner();
            fs::create_dir_all(&target_dir)?;

            let eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            let test_file_path = target_dir.join("eicar_test_virus.com");

            fs::write(&test_file_path, eicar_content)?;

            println!(
                "{}",
                "[+] Guvenli EICAR standart antivirus test dosyasi olusturuldu:"
                    .green()
                    .bold()
            );
            println!("  Yol: {:?}", test_file_path);
            println!(
                "\nSimdi bu dosyayi taramak icin su komutu calistirabilirsiniz:\n  cargo run -- scan {:?}\n",
                target_dir
            );
        }

        Commands::CanaryDeploy { target_dir } => {
            print_banner();
            let base_dir = dirs_base();
            let canary_mgr = engines::CanaryManager::new(&base_dir);
            match canary_mgr.deploy_canaries(&target_dir) {
                Ok(files) => {
                    println!("{}", format!("[+] {} adet tuzak (Canary & CISA Honeytoken) yem dosyasi basariyla yerlestirildi:", files.len()).green().bold());
                    for f in files {
                        println!("  -> [{}] {} (SHA256: {})", f.decoy_type.magenta(), f.filename.yellow(), f.initial_sha256);
                    }
                    println!("\nBu dizini canli izlemek icin su komutu calistirabilirsiniz:\n  guard canary-watch {:?}", target_dir);
                }
                Err(e) => eprintln!("{}", format!("[-] Tuzak yerlestirilemedi: {}", e).red()),
            }
        }

        Commands::CanaryWatch { watch_dir } => {
            print_banner();
            let base_dir = dirs_base();
            let canary_mgr = engines::CanaryManager::new(&base_dir);
            canary_mgr.watch_canaries(&watch_dir)?;
        }

        Commands::ScanNetwork => {
            print_banner();
            println!("{}", "Aktif Ag Baglantilari ve C2 Port Denetimi Baslatiliyor...".bold());
            println!("------------------------------------------------------------");
            let hunter = engines::NetworkThreatHunter::new(Arc::clone(&db));
            let conns = hunter.scan_connections()?;
            println!("Tespit Edilen Aktif TCP Baglanti Sayisi: {}\n", conns.len());

            for c in conns {
                if c.is_suspicious {
                    println!("{}", format!("[!] SUPHELI C2 BAGLANTISI: {} -> {} (PID: {}, Surec: {})", c.local_addr, c.foreign_addr, c.pid, c.process_name).red().bold());
                    if let Some(det) = c.threat_details {
                        println!("    Ayrinti: {}", det.yellow());
                    }
                } else {
                    println!("-> [OK] {} -> {} | Durum: {} | Surec: {} (PID: {})", c.local_addr, c.foreign_addr.cyan(), c.state, c.process_name, c.pid);
                }
            }
            println!("\n{}", "==================== AG DENETIMI TAMAMLANDI ====================".cyan().bold());
        }

        Commands::ScanPersistence => {
            print_banner();
            println!("{}", "Windows Kalicilik ve Baslangic Noktalari Denetleniyor (Autoruns)...".cyan().bold());
            println!("----------------------------------------------------------------------");
            let (orchestrator, _, _, _) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir)?;
            let scanner = engines::PersistenceScanner::new(Arc::clone(&db), Arc::new(orchestrator));
            let entries = scanner.scan_all()?;

            let mut suspicious_count = 0;
            for entry in &entries {
                if entry.is_suspicious {
                    suspicious_count += 1;
                    println!("{}", format!("[!] TEHLİKELİ/ŞÜPHELİ BAŞLANGIÇ: [{}] {}", entry.location, entry.name).red().bold());
                    println!("    Komut  : {}", entry.command.yellow());
                    if let Some(ref target) = entry.target_path {
                        println!("    Hedef  : {}", target.cyan());
                    }
                    if let Some(ref det) = entry.threat_details {
                        println!("    Ayrinti: {}", det.bright_red());
                    }
                    println!();
                } else {
                    println!("-> [{}] {} | Komut: {}", entry.location.cyan(), entry.name.green(), entry.command);
                }
            }

            println!("\n{}", "==================== KALICILIK RAPORU ====================".cyan().bold());
            println!("Toplam Denetlenen Baslangic Noktasi: {}", entries.len());
            println!("Tespit Edilen Supheli/Zararli Giris : {}", if suspicious_count > 0 {
                suspicious_count.to_string().red().bold()
            } else {
                "0 (Temiz)".green().bold()
            });
            println!("==========================================================");
        }

        Commands::ScanMemory { pid } => {
            print_banner();
            println!("{}", "Canli Bellek ve Enjeksiyon Avcisi Baslatiliyor (In-Memory Hunter)...".cyan().bold());
            println!("------------------------------------------------------------------");
            let (_, _, _, yara_eng) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir)?;
            let hunter = engines::MemoryHunter::new(Some(yara_eng));

            let reports = if let Some(target_pid) = pid {
                hunter.scan_process_memory(target_pid, &format!("PID: {}", target_pid))
            } else {
                hunter.scan_all_processes()?
            };

            let mut suspicious_count = 0;
            for rep in &reports {
                suspicious_count += 1;
                println!("{}", format!("[!] TESPIT EDILEN BELLEK ENJEKSIYONU: {} (PID: {})", rep.process_name, rep.pid).red().bold());
                println!("    Adres      : {}", rep.region_address.yellow());
                println!("    Boyut      : {} KB", rep.region_size / 1024);
                println!("    Korumasi   : {}", rep.protection.magenta());
                println!("    Tehdit Tipi: {}", rep.threat_type.bright_red().bold());
                println!("    Ayrinti    : {}", rep.details);
                for y in &rep.yara_matches {
                    println!("    -> YARA Eslesti: {}", y.yellow());
                }
                println!();
            }

            println!("{}", "==================== BELLEK RAPORU ====================".cyan().bold());
            println!("Tespit Edilen Supheli/Enjekte Bellek Bolgesi: {}", if suspicious_count > 0 {
                suspicious_count.to_string().red().bold()
            } else {
                "0 (Temiz - Bellek Enjeksiyonu Yok)".green().bold()
            });
            println!("=======================================================");
        }

        Commands::ScanUsb { drive, quarantine } => {
            print_banner();
            println!("{}", "Cikarilabilir USB ve Surucu Guvenlik Denetimi Baslatiliyor...".cyan().bold());
            println!("------------------------------------------------------------");
            let (orchestrator, _, _, _) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir)?;
            let guard = engines::UsbGuard::new(Arc::new(orchestrator));

            let reports = if let Some(ref d) = drive {
                vec![guard.scan_drive(d, "Secilen Surucu", quarantine)?]
            } else {
                guard.scan_all_removable(quarantine)?
            };

            if reports.is_empty() {
                println!("{}", "[i] Sistemde takili cikarilabilir (USB) surucu bulunamadi.".yellow());
                println!("    Belirli bir dizini taramak icin: guard scan-usb --drive <surucu_yolu>");
            } else {
                for r in &reports {
                    println!("\nSurucu: {} ({}) | Taranan Dosya: {}", r.drive_path.cyan().bold(), r.drive_type, r.scanned_files);
                    if r.infected_count > 0 {
                        println!("{}", format!("  [!] {} ZARARLI TESPIT EDILDI:", r.infected_count).red().bold());
                        for t in &r.threats {
                            println!("    -> {} ({}) - {}", t.filename.yellow(), t.threat_type.red(), t.details);
                            if t.quarantined {
                                println!("       [+] Otomatik karantinaya alindi.");
                            }
                        }
                    } else {
                        println!("{}", "  [OK] Surucu temiz. Solucan veya zararli bulunmadi.".green());
                    }
                }
            }
        }

        Commands::KillProcess { pid } => {
            print_banner();
            println!("PID: {} Surecini Sonlandirma Istegi...", pid);
            match engines::ProcessScanner::kill_process_by_pid(pid) {
                Ok(true) => println!("{}", format!("[+] Basarili: PID {} sureci sistemden zorla sonlandirildi (Terminated).", pid).green().bold()),
                Ok(false) => eprintln!("{}", format!("[-] Hata: PID {} sureci bulunamadi veya sonlandirilamadi.", pid).red()),
                Err(e) => eprintln!("{}", format!("[-] Hata: {}", e).red()),
            }
        }

        Commands::ScanLolbas { kill } => {
            print_banner();
            println!("{}", "LOLBAS & Ebeveyn-Cocuk Surec Anomalisi Taramasi Baslatiliyor...".cyan().bold());
            let reports = engines::LolbasHunter::scan_all(kill)?;

            if reports.is_empty() {
                println!("{}", "\n[OK] Sistemde suistimal edilen LOLBAS ikilisi veya anormal ebeveyn-cocuk surec tespit edilmedi.".green().bold());
            } else {
                println!("\n{}", format!("[!] {} SUPHELI / ZARARLI LOLBAS SUREC AKTIVITESI TESPIT EDILDI:", reports.len()).red().bold());
                for r in &reports {
                    let sev_colored = match r.severity.as_str() {
                        "Critical" => r.severity.red().bold(),
                        "High" => r.severity.yellow().bold(),
                        _ => r.severity.cyan(),
                    };
                    println!("\n  -> Surec: {} (PID: {}) | Ebeveyn: {} (PPID: {:?})", r.name.yellow().bold(), r.pid, r.parent_name.cyan(), r.parent_pid);
                    println!("     Kategori : {} | MITRE: {}", r.category.magenta().bold(), r.mitre_id.red());
                    println!("     Seviye   : {}", sev_colored);
                    println!("     Aciklama : {}", r.description);
                    println!("     Komut    : {}", r.cmd);
                    if r.killed {
                        println!("{}", "     [+] DURUM: Surec aninda sistemden sonlandirildi (Terminated).".green().bold());
                    }
                }
            }
        }

        Commands::DefenderStatus => {
            print_banner();
            println!("{}", "WINDOWS DEFENDER VE CIFT KATMANLI KORUMA DENETIMI:".cyan().bold());
            match engines::DefenderStatusAuditor::query_status() {
                Ok(status) => {
                    println!("  Antivirus Etkin               : {}", if status.antivirus_enabled { "Aktif [OK]".green().bold() } else { "Devre Disi".red() });
                    println!("  Gercek Zamanli Koruma (RTP)   : {}", if status.realtime_protection_enabled { "Aktif [OK]".green().bold() } else { "Devre Disi".red() });
                    println!("  Casus Yazilim Korumasi        : {}", if status.antispyware_enabled { "Aktif [OK]".green().bold() } else { "Devre Disi".red() });
                    println!("  Imza Guncelligi               : {} gun once guncellendi", status.antivirus_signature_age);
                    println!("  Cift Katmanli Koruma Modu     : {}", status.coexistence_status.cyan().bold());
                    println!("  Notlar & Entegrasyon          : {}", status.notes.yellow());
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] Windows Defender durumu sorgulanamadi: {}", e).red());
                }
            }
        }

        Commands::ScanDrivers => {
            print_banner();
            println!("{}", "LOLDrivers / BYOVD SAVUNMASIZ CEKIRDEK SURUCU AVLANMASI:".cyan().bold());
            match engines::DriverHunter::scan_all() {
                Ok(threats) => {
                    if threats.is_empty() {
                        println!("{}", "[+] Temiz: Sistemde yuklu veya bekleyen savunmasiz/zararli surucu (BYOVD) tespit edilmedi.".green().bold());
                    } else {
                        println!("{}", format!("[!] DIKKAT: {} adet supheli/savunmasiz surucu tehdidi tespit edildi!", threats.len()).red().bold());
                        for (idx, t) in threats.iter().enumerate() {
                            println!("  [{}] Surucu        : {}", idx + 1, t.driver_name.red().bold());
                            println!("      Yol            : {}", t.driver_path);
                            println!("      Risk Seviyesi  : {}", t.severity.red());
                            println!("      CVE / Kural    : {}", t.cve.as_deref().unwrap_or("N/A").yellow());
                            println!("      SHA-256        : {}", t.sha256);
                            println!("      Aciklama       : {}", t.description);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] Surucu taramasi basarisiz: {}", e).red());
                }
            }
        }

        Commands::FimInit => {
            print_banner();
            println!("{}", "DOSYA VE SISTEM BUTUNLUGU IZLEME (FIM) REFERANS KAYDI:".cyan().bold());
            let base_dir = dirs_base();
            let fim = engines::FimEngine::new(&base_dir);
            match fim.create_baseline() {
                Ok(items) => {
                    println!("{}", format!("[+] Basarili: {} adet kritik sistem dosyasi icin kriptografik SHA-256 referansi olusturuldu.", items.len()).green().bold());
                    for item in &items {
                        println!("  -> [{}] {} (SHA-256: {}...)", item.description.cyan(), item.path, &item.sha256[..16.min(item.sha256.len())]);
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] FIM referansi olusturulamadi: {}", e).red());
                }
            }
        }

        Commands::FimCheck => {
            print_banner();
            println!("{}", "DOSYA VE SISTEM BUTUNLUGU (FIM) KONTROLU VE TAMPERING DENETIMI:".cyan().bold());
            let base_dir = dirs_base();
            let fim = engines::FimEngine::new(&base_dir);
            match fim.check_integrity() {
                Ok(reports) => {
                    let mut tampered = 0;
                    for r in &reports {
                        if r.status.contains("Tampered") || r.status.contains("Değiştir") {
                            tampered += 1;
                            println!("  {} {} (Aciklama: {})", "[!] DEGISTIRILMIS (TAMPERED):".red().bold(), r.path, r.description);
                            println!("      Eski SHA-256: {}", r.baseline_hash.as_deref().unwrap_or("N/A"));
                            println!("      Yeni SHA-256: {}", r.current_hash.as_deref().unwrap_or("N/A").red());
                        } else if r.status.contains("Deleted") || r.status.contains("Silin") || r.status.contains("Eksik") {
                            tampered += 1;
                            println!("  {} {}", "[X] DOSYA SILINMIS VEYA BULUNAMIYOR:".yellow().bold(), r.path);
                        } else {
                            println!("  {} {} ({})", "[+] BUTUNLUK SAGLAM:".green(), r.path, r.description);
                        }
                    }
                    if tampered == 0 {
                        println!("{}", "\n[+] Harika! Tum kritik sistem dosyalari ve kurallari degistirilmemis, butunluk saglam.".green().bold());
                    } else {
                        println!("{}", format!("\n[!] DIKKAT: {} adet dosyada guvenlik butunlugu ihlali/degisiklik saptandi!", tampered).red().bold());
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] FIM kontrolu basarisiz: {}", e).red());
                }
            }
        }

        Commands::ScanScript { target } => {
            print_banner();
            println!("{}", "ZARARLI KOMUT DOSYASI VE AMSI AVLANMASI (SCRIPT & AMSI HUNTER):".cyan().bold());
            let path = Path::new(&target);
            let (content, name_hint) = if path.exists() && path.is_file() {
                match std::fs::read_to_string(path) {
                    Ok(txt) => (txt, Some(path.file_name().unwrap().to_string_lossy().to_string())),
                    Err(_) => {
                        let bytes = std::fs::read(path).unwrap_or_default();
                        (String::from_utf8_lossy(&bytes).to_string(), Some(path.file_name().unwrap().to_string_lossy().to_string()))
                    }
                }
            } else {
                (target.clone(), None)
            };

            match engines::ScriptHunter::analyze_script(&content, name_hint.as_deref()) {
                Some(rep) => {
                    println!("  {} {}", "TEHDİT BULUNDU:".red().bold(), rep.threat_name.red().bold());
                    println!("  Tip             : {}", rep.file_type.yellow());
                    println!("  Risk Seviyesi   : {}", rep.severity.red().bold());
                    println!("  MITRE Tekniği   : {}", rep.mitre_technique.cyan().bold());
                    println!("  Açıklama        : {}", rep.description);
                    println!("\n  Gözlemlenen Göstergeler:");
                    for ind in &rep.matched_indicators {
                        println!("    -> {}", ind.yellow());
                    }
                    if let Some(deob) = rep.deobfuscated_payload {
                        println!("\n  {} (De-obfuscated):", "ÇÖZÜLMÜŞ GİZLİ PAYLOAD".green().bold());
                        println!("    {}", deob.trim());
                    }
                }
                None => {
                    println!("{}", "[+] Temiz: Belirtilen betikte AMSI bypass veya zararlı indirme beşiği tespit edilmedi.".green().bold());
                }
            }
        }

        Commands::ExtractIocs { target } => {
            print_banner();
            println!("{}", "STATIK IOC VE DIZE TRIYAJI (STRING & IOC EXTRACTOR):".cyan().bold());
            let path = Path::new(&target);
            if !path.exists() {
                eprintln!("{}", format!("[-] Dosya bulunamadi: {}", target).red());
            } else {
                let db_lock = db.lock().map_err(|e| anyhow::anyhow!("DB kilitlenemedi: {}", e))?;
                match engines::IocExtractor::analyze_file(path, Some(&*db_lock)) {
                    Ok(rep) => {
                        println!("  Hedef Dosya          : {}", rep.target_name.cyan().bold());
                        println!("  Ayıklanan Dize Sayısı: {}", rep.total_strings_extracted);
                        println!("  Genel (Public) IP'ler: {}", rep.public_ips.len());
                        println!("  URL Sayısı           : {}", rep.urls.len());
                        println!("  Alan Adı (Domain)    : {}", rep.domains.len());
                        println!("  Kripto Cüzdanları    : {}", rep.crypto_wallets.len());

                        if !rep.confirmed_c2_ips.is_empty() {
                            println!("\n  {}", "KRITIK C2 BOTNET ESLESMELERI (Feodo Tracker / ThreatFox):".red().bold());
                            for c2 in &rep.confirmed_c2_ips {
                                println!("    [!] {} -> {}", c2.indicator.red().bold(), c2.threat_tag.as_deref().unwrap_or(""));
                            }
                        }

                        if !rep.public_ips.is_empty() {
                            println!("\n  Bulunan Genel IP'ler:");
                            for ip in rep.public_ips.iter().take(10) {
                                println!("    -> {}", ip.yellow());
                            }
                            if rep.public_ips.len() > 10 {
                                println!("    ... (ve {} adet daha)", rep.public_ips.len() - 10);
                            }
                        }

                        if !rep.urls.is_empty() {
                            println!("\n  Bulunan URL'ler:");
                            for u in rep.urls.iter().take(8) {
                                println!("    -> {}", u.cyan());
                            }
                        }

                        if !rep.crypto_wallets.is_empty() {
                            println!("\n  Tespit Edilen Kripto Cüzdanları:");
                            for w in &rep.crypto_wallets {
                                println!("    -> [{}] {}", w.ioc_type.yellow(), w.indicator);
                            }
                        }

                        if !rep.base64_payloads.is_empty() {
                            println!("\n  Açılan Base64 Yükleri:");
                            for b in rep.base64_payloads.iter().take(3) {
                                println!("    -> {}", b.green());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", format!("[-] IOC çıkarma hatası: {}", e).red());
                    }
                }
            }
        }

        Commands::ScanEventlog { limit } => {
            print_banner();
            println!("{}", "WINDOWS OLAY GUNLUKLERI VE TEHDIT AVCILIGI (EVENT LOG HUNTER):".cyan().bold());
            println!("İncelenen Kaynaklar: PowerShell (4104), Defender (1116/1117), Güvenlik Denetimi (1102)\n");

            match engines::EventLogHunter::scan_all(limit) {
                Ok(records) => {
                    if records.is_empty() {
                        println!("{}", "[+] Olay günlüklerinde şüpheli tehdit veya script aktivitesi saptanmadı (Kayıtlar temiz).".green().bold());
                    } else {
                        println!("Toplam İncelenen Olay Sayısı: {}", records.len());
                        let mut susp_count = 0;
                        for r in &records {
                            if r.is_suspicious {
                                susp_count += 1;
                                println!("\n  {} [{}] Olay ID: {} | Tarih: {}", "[!] ŞÜPHELİ / ZARARLI OLAY:".red().bold(), r.severity.magenta().bold(), r.event_id.to_string().yellow().bold(), r.time_created.cyan());
                                println!("      Kaynak: {} ({})", r.log_name, r.source);
                                println!("      Detay : {}", r.details.bright_red());
                                if let Some(ref mitre) = r.mitre_technique {
                                    println!("      MITRE : {}", mitre.yellow());
                                }
                                if let Some(ref st) = r.script_threat {
                                    println!("      -> Zararlı Betik Göstergeleri: {}", st.matched_indicators.join(", ").yellow());
                                    if let Some(ref deob) = st.deobfuscated_payload {
                                        println!("      -> Açılan Gizli Kod: {}", deob.trim().bright_white());
                                    }
                                }
                            } else {
                                println!("  -> [Olay ID: {}] {} | Tarih: {} | {}", r.event_id.to_string().cyan(), r.source.green(), r.time_created, r.message_preview);
                            }
                        }
                        if susp_count > 0 {
                            println!("\n{}", format!("[!] DIKKAT: {} adet şüpheli/zararlı olay kaydı tespit edildi!", susp_count).red().bold());
                        } else {
                            println!("\n{}", "[+] İncelenen olay günlüklerinde aktif saldırı izi bulunamadı.".green().bold());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] Olay günlüğü tarama hatası: {}", e).red());
                }
            }
        }

        Commands::Triage { target } => {
            print_banner();
            println!("{}", "DERİN PE STATİK TRİYAJ VE ENTROPİ MATRİSİ (PE DEEP TRIAGER):".cyan().bold());
            let path = Path::new(&target);
            let rep = if path.exists() && path.is_file() {
                engines::PeTriager::triage_file(path)
            } else {
                engines::PeTriager::triage_bytes(target.as_bytes(), "Raw_Payload")
            };

            match rep {
                Ok(t) => {
                    let score_color = if t.threat_score >= 70 {
                        t.threat_score.to_string().red().bold()
                    } else if t.threat_score >= 40 {
                        t.threat_score.to_string().yellow().bold()
                    } else {
                        t.threat_score.to_string().green().bold()
                    };

                    println!("  Hedef Dosya    : {}", t.file_name.cyan().bold());
                    println!("  PE Mimarisi    : {}", if t.is_pe { if t.is_64bit { "64-bit (x64)" } else { "32-bit (x86)" } } else { "NON-PE" });
                    println!("  Giriş Noktası  : {:#x}", t.entry_point);
                    println!("  Genel Entropi  : {:.2} / 8.00", t.overall_entropy);
                    println!("  Tehdit Skoru   : {} / 100", score_color);
                    println!("  Otomatik Karar : {}\n", if t.threat_score >= 70 { t.verdict.red().bold() } else if t.threat_score >= 40 { t.verdict.yellow().bold() } else { t.verdict.green().bold() });

                    if !t.sections.is_empty() {
                        println!("{}", "  BÖLÜM ENTROPİ DAĞILIMI:".cyan().bold());
                        println!("  {:<12} {:<12} {:<10} {:<6} {:<6} {}", "Bölüm", "Boyut", "Entropi", "Exec", "Write", "Durum");
                        println!("  ----------------------------------------------------------------------");
                        for s in &t.sections {
                            let ent_str = format!("{:.2}", s.entropy);
                            let ent_colored = if s.entropy > 7.1 { ent_str.red().bold() } else { ent_str.white() };
                            println!("  {:<12} {:<12} {:<10} {:<6} {:<6} {}", s.name, format!("{} B", s.raw_size), ent_colored, if s.is_executable { "E".green() } else { "-".white() }, if s.is_writable { "W".yellow() } else { "-".white() }, s.status);
                        }
                    }

                    if !t.capabilities.is_empty() {
                        println!("\n{}", "  TESPİT EDİLEN MITRE ATT&CK / CAPA YETENEKLERİ:".red().bold());
                        for c in &t.capabilities {
                            println!("  [{}] {}: {}", c.category.magenta().bold(), c.technique.yellow().bold(), c.matched_apis.join(", ").white());
                        }
                    }

                    if !t.summary_notes.is_empty() {
                        println!("\n{}", "  GÜVENLİK ANALİSTİ NOTLARI:".cyan());
                        for n in &t.summary_notes {
                            println!("    * {}", n);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] PE Triyaj hatası: {}", e).red());
                }
            }
        }

        Commands::SyncYara => {
            print_banner();
            println!("{}", "AÇIK KAYNAK TOPLULUK YARA KURALLARI SENKRONİZASYONU (YARA FORGE / SIG-BASE):".cyan().bold());
            let sync_mgr = feeds::YaraSyncManager::new(rules_dir.clone());
            match sync_mgr.sync_all_rules() {
                Ok(stats) => {
                    println!("{}", stats.message.green().bold());
                    println!("  * Doğrulanan ve Kaydedilen Kural Setleri: {}", stats.successfully_added.to_string().cyan().bold());
                    println!("  * Sözdizimi Hatası Nedeniyle Atlanan   : {}", stats.failed_validation.to_string().yellow());
                    println!("  * Disk Üzerindeki Toplam Kural Dosyası : {}", stats.total_rules_files.to_string().green().bold());
                    println!("\nAktif Kural Dosyaları (.project_guard/rules):");
                    for f in stats.current_on_disk_files {
                        println!("    -> {}", f.cyan());
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] YARA senkronizasyon hatası: {}", e).red());
                }
            }
        }

        Commands::Ui { port } => {
            attach_console_for_cli();
            print_banner();
            println!("{}", "PROJECT GUARD WEB SOC KONTROL MERKEZI BASLATILIYOR...".green().bold());
            println!("Yerel Baglanti: http://127.0.0.1:{}", port);
            let (orchestrator, q_mgr, _, yara_eng) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir.clone())?;
            let base_dir = dirs_base();
            let config = Arc::new(tokio::sync::RwLock::new(config::GuardConfig::load()));
            let state = ui::AppState {
                db: Arc::clone(&db),
                orchestrator: Arc::new(orchestrator),
                quarantine_mgr: q_mgr,
                canary_mgr: Arc::new(engines::CanaryManager::new(&base_dir)),
                yara_engine: yara_eng,
                rules_dir,
                base_dir,
                config,
            };

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(ui::start_web_ui(state, port, true))?;
        }

        Commands::Gui { port } | Commands::Tray { port } => {
            let is_tray_only = matches!(command, Commands::Tray { .. });
            hide_console();
            let (orchestrator, q_mgr, _, yara_eng) = build_orchestrator(Arc::clone(&db), quarantine_dir, rules_dir.clone())?;
            let base_dir = dirs_base();
            let config = Arc::new(tokio::sync::RwLock::new(config::GuardConfig::load()));
            let state = ui::AppState {
                db: Arc::clone(&db),
                orchestrator: Arc::new(orchestrator),
                quarantine_mgr: q_mgr,
                canary_mgr: Arc::new(engines::CanaryManager::new(&base_dir)),
                yara_engine: yara_eng,
                rules_dir,
                base_dir,
                config: Arc::clone(&config),
            };

            let rt = tokio::runtime::Runtime::new()?;
            let server_state = state.clone();
            let tray_config = Arc::clone(&config);

            // Arka planda Axum Web UI sunucusunu Tokio runtime içinde başlat (Tray modunda sessiz çalışır, pencere açmaz)
            rt.spawn(async move {
                if let Err(e) = ui::start_web_ui(server_state, port, !is_tray_only).await {
                    eprintln!("Web UI sunucu hatası: {}", e);
                }
            });

            // Ana iş parçacığında yerel Windows Sistem Tepsisini (System Tray) çalıştır
            #[cfg(windows)]
            {
                ui::run_system_tray(port, tray_config);
            }
            #[cfg(not(windows))]
            {
                rt.block_on(async {
                    tokio::signal::ctrl_c().await.ok();
                });
            }
        }

        Commands::Service { action } => {
            print_banner();
            match action {
                ServiceCommands::Install => {
                    service::WindowsServiceManager::install_service(None)?;
                }
                ServiceCommands::Uninstall => {
                    service::WindowsServiceManager::uninstall_service()?;
                }
                ServiceCommands::Start => {
                    service::WindowsServiceManager::start_service()?;
                }
                ServiceCommands::Stop => {
                    service::WindowsServiceManager::stop_service()?;
                }
                ServiceCommands::Status => {
                    let st = service::WindowsServiceManager::query_status()?;
                    println!("{}", "WINDOWS HIZMET DURUMU (SCM):".cyan().bold());
                    println!("  Hizmet Adi    : {}", service::SERVICE_NAME.yellow().bold());
                    println!("  Gorunen Isim  : {}", st.display_name);
                    println!("  Yuklu mu?     : {}", if st.is_installed { "EVET [OK]".green().bold() } else { "HAYIR (Yuklu Degil)".red() });
                    println!("  Calisma Durumu: {}", match st.state.as_str() {
                        "RUNNING" => "CALISIYOR (RUNNING) [OK]".green().bold(),
                        "STOPPED" => "DURDURULDU (STOPPED)".yellow().bold(),
                        _ => st.state.white(),
                    });
                }
                ServiceCommands::Run => {
                    service::run_windows_service()?;
                }
            }
        }

        Commands::CisaKev => {
            print_banner();
            println!("{}", "CISA BILINEN VE AKTIF ISTISMAR EDILEN ZAFIYETLER (CISA KEV CATALOG AUDIT):".cyan().bold());
            println!("Referans Direktif: CISA Binding Operational Directive (BOD 22-01 / 26-04)\n");

            match engines::CisaKevEngine::audit_system() {
                Ok(rep) => {
                    println!("Toplam KEV Kural Sayisi       : {}", rep.total_kev_rules.to_string().cyan().bold());
                    println!("Kritik Zafiyet Sayisi         : {}", rep.critical_vulnerabilities.to_string().red().bold());
                    println!("Fidye Yazilimi Iliskili Sayisi: {}\n", rep.ransomware_associated_count.to_string().yellow().bold());

                    println!("{}", "AKTIF TAKIP EDILEN KRITIK UC NOKTA VE WINDOWS ZAFIYETLERI:".cyan().bold());
                    println!("{:<16} {:<10} {:<34} {:<12} {}", "CVE ID", "Onem", "Urun", "Tarih", "Aciklama");
                    println!("---------------------------------------------------------------------------------------------------------");
                    for k in &rep.entries {
                        let sev_colored = if k.severity == "Critical" { k.severity.red().bold() } else { k.severity.yellow() };
                        let r_flag = if k.known_ransomware_campaign_use { "[RANSOMWARE]".red().bold() } else { "".normal() };
                        println!("{:<16} {:<10} {:<34} {:<12} {} {}", k.cve_id.yellow().bold(), sev_colored, k.product, k.date_added, k.vulnerability_name, r_flag);
                        println!("   -> Gerekli Eylem: {}", k.required_action.cyan());
                    }

                    if !rep.endpoint_warnings.is_empty() {
                        println!("\n{}", "UC NOKTA SAVUNMA VE GUVENLIK UYARILARI:".magenta().bold());
                        for w in &rep.endpoint_warnings {
                            println!("   [!] {}", w.yellow());
                        }
                    }
                    println!("\n{}", "[+] CISA KEV zafiyet ve uyumluluk denetimi tamamlandi.".green().bold());
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] CISA KEV denetim hatasi: {}", e).red());
                }
            }
        }

        Commands::RegisterShell { exe_path } => {
            print_banner();
            engines::WindowsShellManager::register_context_menu(exe_path.as_deref())?;
        }

        Commands::UnregisterShell => {
            print_banner();
            engines::WindowsShellManager::unregister_context_menu()?;
        }

        Commands::UpdateUsom => {
            print_banner();
            println!("{}", "USOM (SGB-TR) YERLI TEHDIT ISTIHBARATI SENKRONIZASYONU:".cyan().bold());
            let usom_feed = feeds::UsomFeed::new(Arc::clone(&db));
            match usom_feed.sync_usom(1000) {
                Ok(stats) => {
                    println!("{}", "[+] USOM verileri basariyla senkronize edildi:".green().bold());
                    println!("    * Kaynak             : {}", stats.source.yellow().bold());
                    println!("    * Toplam Islenen     : {}", stats.total_processed);
                    println!("    * Veritabanina Eklenen: {}", stats.total_added.to_string().green().bold());
                    println!("    * Zararli Domainler  : {}", stats.domain_count);
                    println!("    * Zararli IP/C2      : {}", stats.ip_count);
                    println!("    * Zararli URL'ler    : {}", stats.url_count);
                }
                Err(e) => {
                    eprintln!("{}", format!("[-] USOM senkronizasyonu basarisiz: {}", e).red());
                }
            }
        }

        Commands::ScanStealers { kill } => {
            print_banner();
            println!("{}", "SHADOWSERVER STEALC & INFOSTEALER KIMLIK KORUMA TARAMASI:".cyan().bold());
            println!("Hedef Depolar: Chrome/Edge Login Data, Cookies, Metamask/Phantom Cüzdanları, Telegram tdata\n");

            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            let report = engines::StealerHunter::scan_processes(&sys);

            println!("Taranan Aktif Surec Sayisi   : {}", report.total_processes_scanned);
            println!("Korunan Hassas Kasa Sayisi   : {}\n", report.vaults_protected_count);

            if report.threats.is_empty() {
                println!("{}", "[+] Harika: Tarayici kimlik depolarina veya cuzdanlara yonelik supheli bir infostealer sureci tespit edilmedi.".green().bold());
            } else {
                println!("{}", format!("[!] TEHLIKE: {} adet Infostealer / Kimlik Hirsizligi faaliyeti saptandi!", report.threats.len()).red().bold());
                for t in &report.threats {
                    println!("\n  -> PID: {} | Surec: {}", t.pid.to_string().cyan().bold(), t.process_name.red().bold());
                    println!("     Hedef Kasa: {} ({})", t.target_asset.yellow().bold(), t.category.magenta());
                    println!("     MITRE     : {}", t.mitre_technique.yellow());
                    println!("     Aciklama  : {}", t.description);
                    println!("     Komut     : {}", t.command_line.white());
                    println!("     Tavsiye   : {}", t.recommendation.cyan());

                    if kill {
                        let _ = engines::ProcessScanner::kill_process_by_pid(t.pid);
                        println!("{}", "     [+] DURUM: Zararli surec aninda sonlandirildi (Terminated).".green().bold());
                    }
                }
            }
        }

        Commands::CisAudit => {
            print_banner();
            println!("{}", "CENTER FOR INTERNET SECURITY (CIS) CONTROLS V8.1 & HARDENING DENETIMI:".cyan().bold());
            let report = engines::CisAuditEngine::run_audit();

            println!("Toplam Denetlenen Kontrol : {}", report.total_checks);
            println!("Gecen Guvenlik Ayarlari   : {}", report.passed_checks.to_string().green().bold());
            println!("Eksik / Riskli Maddeler   : {}", report.failed_checks.to_string().red().bold());
            println!("CIS Uyum Skoru            : %{:.1} [{}]", report.compliance_score, report.grade.cyan().bold());
            println!("--------------------------------------------------------------------------------");

            for check in &report.checks {
                let status_badge = if check.passed { "[GECTI / OK]".green().bold() } else { "[RISK / EKSIK]".red().bold() };
                println!("\n{} {} ({})", status_badge, check.title.yellow().bold(), check.cis_control.cyan());
                println!("   Kategori      : {}", check.category);
                println!("   Mevcut Deger  : {}", check.current_value);
                println!("   Onerilen Deger: {}", check.recommended_value);
                println!("   Aciklama      : {}", check.description);
                if !check.passed {
                    println!("   Iyilestirme   : {}", check.remediation.bright_magenta());
                }
            }
        }

        Commands::ScanSupplyChain { target } => {
            print_banner();
            println!("{}", "OPENSSF & OWASP A03 YAZILIM TEDARIK ZINCIRI VE BAGIMLILIK TARAMASI:".cyan().bold());
            println!("Hedef Dizin: {:?}\n", target);

            let report = engines::SupplyChainScanner::scan_directory(&target);
            println!("Taranan Bagimlilik Dosyasi : {}", report.total_files_scanned);
            println!("Riskli / Zararli Paket     : {}", if report.vulnerable_packages_count > 0 {
                report.vulnerable_packages_count.to_string().red().bold()
            } else {
                "0 (Temiz)".green().bold()
            });

            if report.threats.is_empty() {
                println!("\n{}", "[+] Harika: Projede zararlı lifecycle scripti veya bilinen kötücül bağımlılık bulunamadı.".green().bold());
            } else {
                println!("\n{}", format!("[!] KRITIK: {} adet tedarik zinciri tehdidi tespit edildi:", report.threats.len()).red().bold());
                for t in &report.threats {
                    println!("\n  -> Dosya    : {}", t.file_path.yellow().bold());
                    println!("     Ekosistem: {} | Seviye: {}", t.package_ecosystem.cyan(), t.severity.red().bold());
                    println!("     Tur      : {}", t.threat_type.magenta().bold());
                    println!("     Gosterge : {}", t.indicator);
                    println!("     Kod Kesiti: {}", t.snippet.white());
                    println!("     MITRE    : {}", t.mitre_technique);
                    println!("     Oneri    : {}", t.recommendation.bright_red());
                }
            }
        }

        Commands::EpssLookup { cve } => {
            print_banner();
            let report = engines::EpssEngine::lookup(&cve)?;
            engines::EpssEngine::print_report(&report);
        }

        Commands::UpdateSans { limit } => {
            print_banner();
            println!("{}", "SANS ISC DShield bal küpü verileri ve saldırgan IP'leri senkronize ediliyor...".bold());
            println!("------------------------------------------------------------");

            let sans_feed = feeds::SansFeed::new(Arc::clone(&db));
            let stats = sans_feed.sync_dshield(limit)?;
            feeds::SansFeed::print_sync_report(&stats);
        }

        Commands::ScanSigma { kill } => {
            print_banner();
            println!("{}", "SigmaHQ açık kaynak tespit kuralları ile çalışan süreçler denetleniyor...".bold());
            println!("------------------------------------------------------------");

            let report = engines::SigmaEngine::scan_live_processes(kill)?;
            engines::SigmaEngine::print_report(&report);
        }

        Commands::UpdateSpamhaus => {
            print_banner();
            println!("{}", "The Spamhaus Project DROP/eDROP kurşun geçirmez botnet ağları senkronize ediliyor...".bold());
            println!("------------------------------------------------------------");

            let spamhaus_feed = feeds::SpamhausFeed::new(Arc::clone(&db));
            let stats = spamhaus_feed.sync_drop(500)?;
            feeds::SpamhausFeed::print_sync_report(&stats);
        }

        Commands::UpdateUrlhaus { limit } => {
            print_banner();
            println!("{}", "Abuse.ch URLhaus veritabanından aktif zararlı indirme bağlantıları senkronize ediliyor...".bold());
            println!("------------------------------------------------------------");

            let urlhaus_feed = feeds::UrlhausFeed::new(Arc::clone(&db));
            let stats = urlhaus_feed.sync_urlhaus(limit)?;
            feeds::UrlhausFeed::print_sync_report(&stats);
        }

        Commands::LookupUrl { url } => {
            print_banner();
            println!("{}", "Abuse.ch URLhaus & Tehdit Veritabanı URL İtibar Sorgusu:".cyan().bold());
            println!("Hedef Bağlantı: {}\n", url.yellow());

            let urlhaus_feed = feeds::UrlhausFeed::new(Arc::clone(&db));
            match urlhaus_feed.lookup(&url)? {
                Some((threat, severity)) => {
                    println!("{}", "[!] ZARARLI BAĞLANTI TESPİT EDİLDİ (MALICIOUS URL):".red().bold());
                    println!("    * Tehdit Ailesi: {}", threat.bright_red().bold());
                    println!("    * Önem Seviyesi: {}", severity.magenta().bold());
                    println!("    * Kaynak       : Abuse.ch URLhaus & Project Guard C2/Malware Feed");
                    println!("    * Tavsiye      : Bu bağlantıya yönelik web istekleri engellenmeli ve indirilmişse dosya karantinaya alınmalıdır.");
                }
                None => {
                    println!("{}", "[+] GÜVENLİ / TEMİZ: Bu bağlantı URLhaus veya yerel zararlı listelerinde bulunamadı.".green().bold());
                }
            }
        }

        Commands::ScanStalkerware { kill } => {
            print_banner();
            println!("{}", "EFF Coalition Against Stalkerware & Citizen Lab yönergeleriyle süreçler denetleniyor...".bold());
            println!("------------------------------------------------------------");

            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            let report = engines::StalkerwareHunter::scan_stalkerware(&sys, kill);
            engines::StalkerwareHunter::print_report(&report);
        }

        Commands::PrivacyStatus => {
            print_banner();
            let report = engines::PrivacyGuard::audit_privacy();
            engines::PrivacyGuard::print_report(&report);
        }

        Commands::PrivacyWatch { interval } => {
            print_banner();
            println!("{}", "DONANIM GİZLİLİK KORUMASI CANLI İZLEME MODU (PRIVACY WATCH):".cyan().bold());
            println!("Kamera veya mikrofon açıldığında anlık masaüstü Toast bildirimi gönderilecektir.");
            println!("Durdurmak için Ctrl+C tuşlarına basın. (Denetim Aralığı: {} saniye)\n", interval);

            let mut seen_active: std::collections::HashSet<String> = std::collections::HashSet::new();

            loop {
                let report = engines::PrivacyGuard::audit_privacy();
                for rec in &report.records {
                    if rec.is_active {
                        let key = format!("{}:{}", rec.device_type.as_str(), rec.process_name);
                        if !seen_active.contains(&key) {
                            seen_active.insert(key.clone());
                            println!(
                                "{} [{}] {} {} tarafından aktif olarak kullanılıyor!",
                                "🚨".red(),
                                chrono::Local::now().format("%H:%M:%S").to_string().yellow(),
                                rec.device_type.as_str().bold().cyan(),
                                rec.process_name.bold().red()
                            );
                            let is_cam = rec.device_type == engines::DeviceType::Webcam;
                            engines::WindowsShellManager::send_privacy_toast(&rec.process_name, is_cam, rec.is_suspicious);
                        }
                    } else {
                        let key = format!("{}:{}", rec.device_type.as_str(), rec.process_name);
                        if seen_active.contains(&key) {
                            seen_active.remove(&key);
                            println!(
                                "{} [{}] {} erişimi sonlandı: {}",
                                "ℹ️".green(),
                                chrono::Local::now().format("%H:%M:%S").to_string().cyan(),
                                rec.device_type.as_str(),
                                rec.process_name
                            );
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
            }
        }

        Commands::Mode { action } => {
            print_banner();
            let mode_action = action.unwrap_or(ModeCommands::Status);
            match mode_action {
                ModeCommands::Status => {
                    engines::SystemModeEngine::print_status();
                }
                ModeCommands::Game => {
                    println!("{}", "OYUN MODU (ULTRA DÜŞÜK GECİKME & MAKSİMUM FPS) ETKİNLEŞTİRİLİYOR:".cyan().bold());
                    match engines::SystemModeEngine::apply_game_mode() {
                        Ok(actions) => {
                            for act in actions {
                                println!("  {} {}", "✔".green().bold(), act.white());
                            }
                            println!("\n{}", "[+] Harika: Oyun modu basariyla devreye alindi. Iyi eglenceler!".green().bold());
                            engines::WindowsShellManager::send_mode_toast("Oyun Modu Aktif", "Arka plan gecikmeleri sıfırlandı ve ağ/GPU önceliği atandı.");
                        }
                        Err(e) => {
                            eprintln!("{}", format!("[-] Oyun modu etkinlestirme hatasi: {}", e).red());
                        }
                    }
                }
                ModeCommands::Work => {
                    println!("{}", "İŞ VE GİZLİLİK MODU (WINDEBLOAT & ODAKLANMA) ETKİNLEŞTİRİLİYOR:".cyan().bold());
                    match engines::SystemModeEngine::apply_work_mode() {
                        Ok(actions) => {
                            for act in actions {
                                println!("  {} {}", "✔".green().bold(), act.white());
                            }
                            println!("\n{}", "[+] Harika: Is ve gizlilik modu devrede. Telemetri engellendi ve odaklanma saglandi.".green().bold());
                            engines::WindowsShellManager::send_mode_toast("İş & Gizlilik Modu Aktif", "WinDebloat telemetri temizliği yapıldı ve EDR koruması yükseltildi.");
                        }
                        Err(e) => {
                            eprintln!("{}", format!("[-] Is modu etkinlestirme hatasi: {}", e).red());
                        }
                    }
                }
                ModeCommands::Restore => {
                    println!("{}", "SİSTEM AYARLARI ORİJİNAL WINDOWS VARSAYILANLARINA GERİ YÜKLENİYOR:".cyan().bold());
                    match engines::SystemModeEngine::restore_defaults() {
                        Ok(actions) => {
                            for act in actions {
                                println!("  {} {}", "✔".green().bold(), act.white());
                            }
                            println!("\n{}", "[+] Orijinal sistem ayarlari ve servisleri basariyla geri yuklendi.".green().bold());
                            engines::WindowsShellManager::send_mode_toast("Sistem Sıfırlandı", "Tüm kayıt defteri ayarları orijinal fabrika ayarlarına döndürüldü.");
                        }
                        Err(e) => {
                            eprintln!("{}", format!("[-] Geri yukleme hatasi: {}", e).red());
                        }
                    }
                }
            }
        }

        Commands::Notify { title, message } => {
            print_banner();
            println!("{}", "Windows Bildirim Merkezine Toast Bildirimi Gönderiliyor...".cyan());
            println!("  • Başlık: {}", title.yellow().bold());
            println!("  • Mesaj : {}", message.white());
            engines::WindowsShellManager::send_native_toast(&title, &message);
            println!("{}", "[+] Bildirim basariyla gonderildi.".green().bold());
        }

        Commands::Config { action } => {
            attach_console_for_cli();
            print_banner();
            let mut cfg = config::GuardConfig::load();
            let act = action.unwrap_or(ConfigCommands::Show);
            match act {
                ConfigCommands::Show => {
                    println!("{}", "PROJECT GUARD MERKEZI YAPILANDIRMA".cyan().bold());
                    println!("Dosya Yolu: {:?}\n", config::GuardConfig::config_file_path());
                    let json = serde_json::to_string_pretty(&cfg)?;
                    println!("{}", json);
                }
                ConfigCommands::Get { key } => {
                    match cfg.get_value_by_key(&key) {
                        Some(val) => println!("{}: {}", key.cyan().bold(), val.green()),
                        None => eprintln!("{}", format!("[-] Ayar anahtarı bulunamadı: {}", key).red()),
                    }
                }
                ConfigCommands::Set { key, value } => {
                    match cfg.set_value_by_key(&key, &value) {
                        Ok(()) => println!("{}", format!("[+] Ayar başarıyla güncellendi: {} = {}", key, value).green().bold()),
                        Err(e) => eprintln!("{}", format!("[-] Ayar güncellenemedi: {}", e).red()),
                    }
                }
                ConfigCommands::Reset => {
                    match config::GuardConfig::reset() {
                        Ok(_) => println!("{}", "[+] Tüm ayarlar başarıyla fabrika varsayılanlarına sıfırlandı.".green().bold()),
                        Err(e) => eprintln!("{}", format!("[-] Ayarlar sıfırlanamadı: {}", e).red()),
                    }
                }
                ConfigCommands::Export { path } => {
                    let out_path = path.unwrap_or_else(|| PathBuf::from("guard_config_backup.json"));
                    let json = serde_json::to_string_pretty(&cfg)?;
                    fs::write(&out_path, json)?;
                    println!("{}", format!("[+] Yapılandırma başarıyla dışa aktarıldı: {:?}", out_path).green().bold());
                }
                ConfigCommands::Import { path } => {
                    let content = fs::read_to_string(&path)?;
                    let imported: config::GuardConfig = serde_json::from_str(&content)?;
                    imported.save()?;
                    println!("{}", format!("[+] Yapılandırma başarıyla içe aktarıldı ve uygulandı: {:?}", path).green().bold());
                }
            }
        }

        Commands::PackageExtension => {
            print_banner();
            println!("{}", "PROJECT GUARD CHROME WEB SHIELD EKLENTİSİ PAKETLENİYOR:".cyan().bold());
            match ui::server::get_or_create_extension_zip() {
                Ok(bytes) => {
                    let sha = sha2::Sha256::digest(&bytes)
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                    println!("  -> Paket Durumu  : {}", "BAŞARILI [OK]".green().bold());
                    println!("  -> Dosya Boyutu  : {:.2} KB ({} bayt)", bytes.len() as f64 / 1024.0, bytes.len());
                    println!("  -> SHA-256       : {}", sha.yellow().bold());
                    println!("  -> Çıktı Konumu  : {}", "dist/project-guard-web-shield.zip".cyan().bold());
                    println!("\n{}", "Chrome Tarayıcısına Yükleme Adımları:".magenta().bold());
                    println!("  1. 'chrome://extensions/' sayfasını açın.");
                    println!("  2. Sağ üstten 'Geliştirici modu'nu aktif edin.");
                    println!("  3. 'Paketlenmemiş öğe yükle' ile 'extensions\\chrome' klasörünü seçin.");
                    println!("  4. Veya .zip arşivini bir dizine çıkarıp yükleyin.");
                }
                Err(e) => {
                    println!("{}", format!("[!] Paketleme hatası: {}", e).red().bold());
                }
            }
        }
    }

    Ok(())
}



fn print_scan_summary(summary: &ScanSummary) {
    println!("\n{}", "==================== TARAMA RAPORU ====================".cyan().bold());
    println!("Hedef              : {}", summary.target_path);
    println!("Taranan Dosya      : {}", summary.scanned_files);
    println!("Tespit Edilen Tehdit: {}", if summary.infected_files > 0 {
        summary.infected_files.to_string().red().bold()
    } else {
        "0 (Temiz)".green().bold()
    });
    println!("Toplam Veri Boyutu : {:.2} MB", summary.total_bytes as f64 / (1024.0 * 1024.0));
    println!("Gecen Sure         : {} ms", summary.elapsed_ms);
    println!("=======================================================");

    if summary.infected_files > 0 {
        println!("\n{}", "TESPIT EDILEN ZARARLILAR:".red().bold());
        for report in &summary.reports {
            if report.is_infected {
                println!(
                    "\n[!] Dosya: {}",
                    report.file_path.display().to_string().yellow().bold()
                );
                println!("    Boyut : {} bayt | SHA256: {}", report.file_size, report.sha256);
                for det in &report.detections {
                    println!(
                        "    -> [{}] {} ({}) - {}",
                        det.engine_name.cyan(),
                        det.threat_name.red().bold(),
                        det.severity.to_string().magenta(),
                        det.details
                    );
                }
                if report.quarantined {
                    println!("{}", "    [+] Durum: Karantinaya alindi ve zararsizlastirildi.".green());
                }
            }
        }
        println!();
    } else {
        println!("\n{}", "[OK] Hicbir tehdit tespit edilmedi. Sistem temiz.".green().bold());
    }
}
