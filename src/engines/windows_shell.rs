use anyhow::Result;
use colored::Colorize;
use std::env;
use std::path::{Path, PathBuf};
use crate::engines::create_hidden_command;

pub struct WindowsShellManager;

impl WindowsShellManager {
    /// Mevcut çalışan project-guard.exe dosyasının mutlak yolunu bulur
    pub fn get_current_exe_path() -> Result<PathBuf> {
        let exe = env::current_exe()?;
        Ok(exe)
    }

    /// Windows Explorer sağ tık (Context Menu) entegrasyonunu Kayıt Defterine ekler
    pub fn register_context_menu(custom_exe_path: Option<&Path>) -> Result<()> {
        let exe_path = match custom_exe_path {
            Some(p) => p.to_path_buf(),
            None => Self::get_current_exe_path()?,
        };
        let exe_str = exe_path.to_string_lossy().to_string();

        println!("{}", "[*] Windows Dosya Gezgini (Explorer) Sag Tik Menusu Kaydediliyor...".cyan().bold());

        // 1. Tüm Dosyalar İçin (*\shell\ProjectGuardScan)
        let file_key = r"HKCU\Software\Classes\*\shell\ProjectGuardScan";
        let file_cmd_key = r"HKCU\Software\Classes\*\shell\ProjectGuardScan\command";

        let _ = create_hidden_command("reg.exe")
            .args(["add", file_key, "/ve", "/d", "Project Guard ile Guvenlik Taramasi Yap", "/f"])
            .output();

        let _ = create_hidden_command("reg.exe")
            .args(["add", file_key, "/v", "Icon", "/d", &exe_str, "/f"])
            .output();

        let file_exec = format!("\"{}\" scan \"%1\"", exe_str);
        let _ = create_hidden_command("reg.exe")
            .args(["add", file_cmd_key, "/ve", "/d", &file_exec, "/f"])
            .output();

        // 2. Klasörler İçin (Directory\shell\ProjectGuardScan)
        let dir_key = r"HKCU\Software\Classes\Directory\shell\ProjectGuardScan";
        let dir_cmd_key = r"HKCU\Software\Classes\Directory\shell\ProjectGuardScan\command";

        let _ = create_hidden_command("reg.exe")
            .args(["add", dir_key, "/ve", "/d", "Project Guard ile Klasoru Tara", "/f"])
            .output();

        let _ = create_hidden_command("reg.exe")
            .args(["add", dir_key, "/v", "Icon", "/d", &exe_str, "/f"])
            .output();

        let dir_exec = format!("\"{}\" scan \"%1\" --recursive", exe_str);
        let _ = create_hidden_command("reg.exe")
            .args(["add", dir_cmd_key, "/ve", "/d", &dir_exec, "/f"])
            .output();

        println!("{}", "[+] Windows Explorer Sag Tik Menusu Basariyla Olusturuldu:".green().bold());
        println!("  -> Dosyalar icin: 'Project Guard ile Guvenlik Taramasi Yap'");
        println!("  -> Klasorler icin: 'Project Guard ile Klasoru Tara'");
        println!("  -> Bagli Program: {}", exe_str.yellow());

        Ok(())
    }

    /// Windows Explorer sağ tık bağlam menüsünü kaldırır
    pub fn unregister_context_menu() -> Result<()> {
        println!("{}", "[*] Windows Explorer Sag Tik Menusu Kaldiriliyor...".yellow());

        let file_key = r"HKCU\Software\Classes\*\shell\ProjectGuardScan";
        let dir_key = r"HKCU\Software\Classes\Directory\shell\ProjectGuardScan";

        let _ = create_hidden_command("reg.exe")
            .args(["delete", file_key, "/f"])
            .output();

        let _ = create_hidden_command("reg.exe")
            .args(["delete", dir_key, "/f"])
            .output();

        println!("{}", "[+] Sag tik menusu basariyla kaldirildi.".green().bold());
        Ok(())
    }

    /// Windows 10/11 Bildirim Merkezine (Action Center) yerel Toast bildirimi gönderir
    pub fn send_native_toast(title: &str, message: &str) {
        #[cfg(target_os = "windows")]
        {
            let script = format!(
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
                 $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
                 $textNodes = $template.GetElementsByTagName('text'); \
                 $textNodes.Item(0).AppendChild($template.CreateTextNode('{}')) > $null; \
                 $textNodes.Item(1).AppendChild($template.CreateTextNode('{}')) > $null; \
                 $toast = [Windows.UI.Notifications.ToastNotification]::new($template); \
                 [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Project Guard EDR').Show($toast);",
                title.replace('\'', "''"),
                message.replace('\'', "''")
            );

            // Asenkron olarak arka planda çalıştır (tarama veya EDR iş parçacığını kilitlemez)
            let _ = create_hidden_command("powershell.exe")
                .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
                .spawn();
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (title, message);
        }
    }

    /// Kamera veya mikrofon donanımı açıldığında anlık Toast bildirimi gönderir
    pub fn send_privacy_toast(app_name: &str, is_camera: bool, is_suspicious: bool) {
        let title = if is_suspicious {
            if is_camera {
                "🚨 DİKKAT: YETKİSİZ KAMERA ERİŞİMİ!"
            } else {
                "🚨 DİKKAT: YETKİSİZ MİKROFON ERİŞİMİ!"
            }
        } else {
            if is_camera {
                "📷 Kamera Açıldı"
            } else {
                "🎙️ Mikrofon Açıldı"
            }
        };

        let message = if is_suspicious {
            format!("'{}' uygulaması haberiniz olmadan donanıma erişiyor! Engellemek için 'guard scan-stalkerware --kill' çalıştırın.", app_name)
        } else {
            format!("'{}' uygulaması şu anda donanımı aktif olarak kullanıyor.", app_name)
        };

        Self::send_native_toast(title, &message);
    }

    /// Oyun veya İş modu devreye girdiğinde Toast bildirimi gönderir
    pub fn send_mode_toast(mode_name: &str, description: &str) {
        let title = format!("⚡ Project Guard | {}", mode_name);
        Self::send_native_toast(&title, description);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_exe_path_resolution() {
        let p = WindowsShellManager::get_current_exe_path();
        assert!(p.is_ok());
    }

    #[test]
    fn test_context_menu_registration_cycle() {
        let dummy_exe = PathBuf::from(r"C:\Program Files\ProjectGuard\project-guard.exe");
        let reg_res = WindowsShellManager::register_context_menu(Some(&dummy_exe));
        assert!(reg_res.is_ok());

        let unreg_res = WindowsShellManager::unregister_context_menu();
        assert!(unreg_res.is_ok());
    }
}
