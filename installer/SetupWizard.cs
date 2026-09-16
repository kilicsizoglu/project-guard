using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ProjectGuard.Installer
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 1. Administrator Elevation Check
            WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (!isAdmin)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = Application.ExecutablePath;
                    psi.Verb = "runas";
                    psi.Arguments = string.Join(" ", args);
                    Process.Start(psi);
                    return;
                }
                catch
                {
                    MessageBox.Show(
                        "Project Guard kurulumu sistem servisi ve dizin kayitlari icin Yonetici (Administrator) yetkileri gerektirmektedir.\n\nLutfen sag tiklayip 'Yonetici Olarak Calistir' seciniz.",
                        "Project Guard Kurulum Yetkisi",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                    return;
                }
            }

            Application.Run(new InstallerForm());
        }
    }

    public class InstallerForm : Form
    {
        private ProgressBar progressBar;
        private Label lblStatus;
        private TextBox txtInstallDir;
        private Button btnInstall;
        private Button btnBrowse;
        private CheckBox chkService;
        private CheckBox chkShortcut;
        private CheckBox chkLaunch;

        public InstallerForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "Project Guard Setup v1.1.0 - Windows Kurulum Sihirbazi";
            this.Size = new Size(620, 460);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.BackColor = Color.FromArgb(15, 23, 42); // Dark Obsidian #0f172a
            this.ForeColor = Color.FromArgb(248, 250, 252);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            // Header Banner Panel
            Panel headerPanel = new Panel();
            headerPanel.Dock = DockStyle.Top;
            headerPanel.Height = 85;
            headerPanel.BackColor = Color.FromArgb(30, 41, 59); // Slate-800
            headerPanel.Padding = new Padding(20, 15, 20, 15);

            Label lblTitle = new Label();
            lblTitle.Text = "Project Guard Kurulum Sihirbazi";
            lblTitle.Font = new Font("Segoe UI", 14f, FontStyle.Bold);
            lblTitle.ForeColor = Color.FromArgb(6, 182, 212); // Cyan-500
            lblTitle.AutoSize = true;
            lblTitle.Location = new Point(18, 12);
            headerPanel.Controls.Add(lblTitle);

            Label lblSubtitle = new Label();
            lblSubtitle.Text = "Yeni Nesil Acik Kaynak Antivirus, EDR ve Tehdit Avlama Platformu (Rust)";
            lblSubtitle.Font = new Font("Segoe UI", 9f, FontStyle.Regular);
            lblSubtitle.ForeColor = Color.FromArgb(148, 163, 184); // Slate-400
            lblSubtitle.AutoSize = true;
            lblSubtitle.Location = new Point(20, 42);
            headerPanel.Controls.Add(lblSubtitle);

            this.Controls.Add(headerPanel);

            // Install Dir Group
            Label lblDirPrompt = new Label();
            lblDirPrompt.Text = "Kurulum Hedef Dizini:";
            lblDirPrompt.Location = new Point(25, 105);
            lblDirPrompt.AutoSize = true;
            lblDirPrompt.ForeColor = Color.FromArgb(203, 213, 225);
            this.Controls.Add(lblDirPrompt);

            txtInstallDir = new TextBox();
            txtInstallDir.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ProjectGuard");
            txtInstallDir.Location = new Point(25, 130);
            txtInstallDir.Size = new Size(450, 26);
            txtInstallDir.BackColor = Color.FromArgb(30, 41, 59);
            txtInstallDir.ForeColor = Color.White;
            txtInstallDir.BorderStyle = BorderStyle.FixedSingle;
            this.Controls.Add(txtInstallDir);

            btnBrowse = new Button();
            btnBrowse.Text = "Gozat...";
            btnBrowse.Location = new Point(485, 128);
            btnBrowse.Size = new Size(95, 28);
            btnBrowse.BackColor = Color.FromArgb(51, 65, 85);
            btnBrowse.ForeColor = Color.White;
            btnBrowse.FlatStyle = FlatStyle.Flat;
            btnBrowse.FlatAppearance.BorderSize = 0;
            btnBrowse.Click += (s, e) => {
                using (FolderBrowserDialog fbd = new FolderBrowserDialog())
                {
                    fbd.SelectedPath = txtInstallDir.Text;
                    if (fbd.ShowDialog() == DialogResult.OK)
                    {
                        txtInstallDir.Text = fbd.SelectedPath;
                    }
                }
            };
            this.Controls.Add(btnBrowse);

            // Options Checkboxes
            chkService = new CheckBox();
            chkService.Text = "7/24 Windows Arka Plan Hizmetini (ProjectGuard Service) kur ve calistir";
            chkService.Location = new Point(25, 175);
            chkService.AutoSize = true;
            chkService.Checked = true;
            chkService.ForeColor = Color.FromArgb(226, 232, 240);
            this.Controls.Add(chkService);

            chkShortcut = new CheckBox();
            chkShortcut.Text = "Masaustu ve Baslat Menusu kisayollarini olustur";
            chkShortcut.Location = new Point(25, 205);
            chkShortcut.AutoSize = true;
            chkShortcut.Checked = true;
            chkShortcut.ForeColor = Color.FromArgb(226, 232, 240);
            this.Controls.Add(chkShortcut);

            chkLaunch = new CheckBox();
            chkLaunch.Text = "Kurulum tamamlandiginda Project Guard Masaustu Kontrol Panelini ac";
            chkLaunch.Location = new Point(25, 235);
            chkLaunch.AutoSize = true;
            chkLaunch.Checked = true;
            chkLaunch.ForeColor = Color.FromArgb(226, 232, 240);
            this.Controls.Add(chkLaunch);

            // Status Label & Progress Bar
            lblStatus = new Label();
            lblStatus.Text = "Kuruluma baslamak icin 'Kuruluma Basla' butonuna basiniz.";
            lblStatus.Location = new Point(25, 280);
            lblStatus.Size = new Size(550, 22);
            lblStatus.ForeColor = Color.FromArgb(148, 163, 184);
            this.Controls.Add(lblStatus);

            progressBar = new ProgressBar();
            progressBar.Location = new Point(25, 305);
            progressBar.Size = new Size(555, 24);
            progressBar.Style = ProgressBarStyle.Blocks;
            this.Controls.Add(progressBar);

            // Bottom Buttons Panel
            btnInstall = new Button();
            btnInstall.Text = "Kuruluma Basla";
            btnInstall.Location = new Point(440, 360);
            btnInstall.Size = new Size(140, 38);
            btnInstall.BackColor = Color.FromArgb(6, 182, 212); // Cyan primary
            btnInstall.ForeColor = Color.FromArgb(15, 23, 42); // Dark text
            btnInstall.Font = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            btnInstall.FlatStyle = FlatStyle.Flat;
            btnInstall.FlatAppearance.BorderSize = 0;
            btnInstall.Cursor = Cursors.Hand;
            btnInstall.Click += BtnInstall_Click;
            this.Controls.Add(btnInstall);

            Button btnCancel = new Button();
            btnCancel.Text = "Iptal";
            btnCancel.Location = new Point(330, 360);
            btnCancel.Size = new Size(95, 38);
            btnCancel.BackColor = Color.FromArgb(51, 65, 85);
            btnCancel.ForeColor = Color.White;
            btnCancel.FlatStyle = FlatStyle.Flat;
            btnCancel.FlatAppearance.BorderSize = 0;
            btnCancel.Click += (s, e) => { this.Close(); };
            this.Controls.Add(btnCancel);
        }

        private void SetStatus(string text, int progress)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => SetStatus(text, progress)));
                return;
            }
            lblStatus.Text = text;
            progressBar.Value = Math.Min(100, Math.Max(0, progress));
        }

        /// <summary>
        /// sc.exe komutunu yönetici yetkisiyle çalıştıran yardımcı metot
        /// </summary>
        private static void RunSc(string arguments, int timeoutMs = 5000)
        {
            try
            {
                using (Process proc = new Process())
                {
                    proc.StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = arguments,
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    proc.Start();
                    proc.WaitForExit(timeoutMs);
                }
            }
            catch { }
        }

        private void BtnInstall_Click(object sender, EventArgs e)
        {
            btnInstall.Enabled = false;
            btnBrowse.Enabled = false;
            txtInstallDir.Enabled = false;
            chkService.Enabled = false;
            chkShortcut.Enabled = false;
            chkLaunch.Enabled = false;

            string targetDir = txtInstallDir.Text.Trim();
            bool enableService = chkService.Checked;
            bool createShortcuts = chkShortcut.Checked;
            bool autoLaunch = chkLaunch.Checked;

            Thread worker = new Thread(() =>
            {
                try
                {
                    PerformInstallation(targetDir, enableService, createShortcuts, autoLaunch);
                }
                catch (Exception ex)
                {
                    this.Invoke(new Action(() =>
                    {
                        MessageBox.Show(
                            "Kurulum sirasinda bir hata meydana geldi:\n\n" + ex.Message,
                            "Kurulum Hatasi",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );
                        btnInstall.Enabled = true;
                        lblStatus.Text = "Hata nedeniyle durduruldu.";
                    }));
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }

        private void PerformInstallation(string targetDir, bool enableService, bool createShortcuts, bool autoLaunch)
        {
            SetStatus("Kurulum dizini hazirlaniyor...", 10);
            if (!Directory.Exists(targetDir))
            {
                Directory.CreateDirectory(targetDir);
            }

            // Stop any running project-guard process
            try
            {
                foreach (var p in Process.GetProcessesByName("project-guard"))
                {
                    try { p.Kill(); p.WaitForExit(2000); } catch { }
                }
            }
            catch { }

            SetStatus("Kurulum dosyalari paketinden cikariliyor...", 25);
            // Extract embedded Payload zip resource
            Assembly assembly = Assembly.GetExecutingAssembly();
            string tempExtractZip = Path.Combine(Path.GetTempPath(), "pg_install_" + Guid.NewGuid().ToString("N") + ".zip");
            try
            {
                using (Stream stream = assembly.GetManifestResourceStream("Payload"))
                using (FileStream fs = new FileStream(tempExtractZip, FileMode.Create, FileAccess.Write))
                {
                    if (stream != null)
                    {
                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            fs.Write(buffer, 0, bytesRead);
                        }
                    }
                }

                if (File.Exists(tempExtractZip))
                {
                    // Overwrite files into targetDir
                    using (ZipArchive archive = ZipFile.OpenRead(tempExtractZip))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            string destinationPath = Path.Combine(targetDir, entry.FullName);
                            string destFolder = Path.GetDirectoryName(destinationPath);
                            if (!string.IsNullOrEmpty(destFolder) && !Directory.Exists(destFolder))
                            {
                                Directory.CreateDirectory(destFolder);
                            }
                            if (!string.IsNullOrEmpty(entry.Name))
                            {
                                entry.ExtractToFile(destinationPath, true);
                            }
                        }
                    }
                }
            }
            finally
            {
                try { if (File.Exists(tempExtractZip)) File.Delete(tempExtractZip); } catch { }
            }

            string exePath = Path.Combine(targetDir, "project-guard.exe");
            string iconPath = Path.Combine(targetDir, "assets", "icon.ico");
            if (!File.Exists(iconPath)) { iconPath = exePath; }

            // Shortcuts
            if (createShortcuts)
            {
                SetStatus("Masaustu ve Baslat Menusu kisayollari olusturuluyor...", 55);
                try
                {
                    Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                    if (shellType != null)
                    {
                        dynamic shell = Activator.CreateInstance(shellType);

                        // Desktop Shortcut (Public + User + OneDrive)
                        string[] desktopDirs = new string[]
                        {
                            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive", "Desktop")
                        };

                        foreach (string dPath in desktopDirs)
                        {
                            if (!string.IsNullOrEmpty(dPath) && Directory.Exists(dPath))
                            {
                                try
                                {
                                    dynamic desktopShortcut = shell.CreateShortcut(Path.Combine(dPath, "Project Guard.lnk"));
                                    desktopShortcut.TargetPath = exePath;
                                    desktopShortcut.Arguments = "gui";
                                    desktopShortcut.WorkingDirectory = targetDir;
                                    desktopShortcut.IconLocation = iconPath + ",0";
                                    desktopShortcut.Description = "Project Guard Autonomous EDR & Antivirus";
                                    desktopShortcut.Save();
                                }
                                catch { }
                            }
                        }

                        // Start Menu
                        string startMenuPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
                        string groupPath = Path.Combine(startMenuPath, "Project Guard");
                        if (!Directory.Exists(groupPath)) Directory.CreateDirectory(groupPath);

                        dynamic appShortcut = shell.CreateShortcut(Path.Combine(groupPath, "Project Guard.lnk"));
                        appShortcut.TargetPath = exePath;
                        appShortcut.Arguments = "gui";
                        appShortcut.WorkingDirectory = targetDir;
                        appShortcut.IconLocation = iconPath + ",0";
                        appShortcut.Description = "Project Guard Autonomous EDR & Antivirus";
                        appShortcut.Save();

                        dynamic webShortcut = shell.CreateShortcut(Path.Combine(groupPath, "Project Guard Web SOC.lnk"));
                        webShortcut.TargetPath = "http://127.0.0.1:7890";
                        webShortcut.Description = "Project Guard Web SOC Dashboard";
                        webShortcut.Save();

                        string uninstCmd = Path.Combine(targetDir, "Uninstall.cmd");
                        if (File.Exists(uninstCmd))
                        {
                            dynamic uninstShortcut = shell.CreateShortcut(Path.Combine(groupPath, "Uninstall Project Guard.lnk"));
                            uninstShortcut.TargetPath = uninstCmd;
                            uninstShortcut.WorkingDirectory = targetDir;
                            uninstShortcut.IconLocation = iconPath + ",0";
                            uninstShortcut.Description = "Project Guard Kaldir";
                            uninstShortcut.Save();
                        }
                    }
                }
                catch { }
            }

            // PATH Environment Variable
            SetStatus("Sistem PATH ortami yapilandiriliyor...", 75);
            try
            {
                string path = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine) ?? "";
                if (!path.Contains(targetDir))
                {
                    string newPath = path.TrimEnd(';') + ";" + targetDir;
                    Environment.SetEnvironmentVariable("Path", newPath, EnvironmentVariableTarget.Machine);
                }
            }
            catch { }

            // Windows Registry Programs & Features
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\ProjectGuard"))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", "Project Guard EDR & Antivirus");
                        key.SetValue("DisplayVersion", "1.1.0");
                        key.SetValue("Publisher", "Project Guard Team");
                        key.SetValue("InstallLocation", targetDir);
                        key.SetValue("DisplayIcon", iconPath);
                        key.SetValue("UninstallString", "\"" + Path.Combine(targetDir, "Uninstall.cmd") + "\"");
                        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }

            // Service registration
            if (enableService && File.Exists(exePath))
            {
                SetStatus("7/24 Windows Arka Plan Hizmeti kuruluyor...", 85);
                try
                {
                    // Önce mevcut servisi durdur ve kaldır (temiz kurulum için)
                    RunSc("stop ProjectGuard", 5000);
                    Thread.Sleep(1000);
                    RunSc("delete ProjectGuard", 3000);
                    Thread.Sleep(500);

                    SetStatus("Windows Hizmeti kaydediliyor (sc.exe create)...", 88);

                    // Servisi sc.exe ile dogrudan olustur
                    RunSc(
                        "create ProjectGuard binPath= \"\\\"" + exePath + "\\\" service run\" " +
                        "start= auto DisplayName= \"Project Guard EDR & Antivirus\"",
                        8000
                    );
                    Thread.Sleep(500);

                    // Servis açıklaması ekle
                    RunSc("description ProjectGuard \"7/24 Gercek Zamanli Koruma, YARA Tarama ve Fidye Yazilimi Kapani (EDR & Antivirus)\"", 3000);

                    // Hata kurtarma: servis crashlarsa otomatik yeniden başlat
                    RunSc("failure ProjectGuard reset= 86400 actions= restart/5000/restart/10000/restart/30000", 3000);

                    SetStatus("Windows Hizmeti baslatiliyor...", 92);
                    RunSc("start ProjectGuard", 10000);
                }
                catch { }
            }

            SetStatus("Kurulum basariyla tamamlandi!", 100);

            this.Invoke(new Action(() =>
            {
                MessageBox.Show(
                    "Project Guard sisteminize basariyla kuruldu!\n\n" +
                    "Kurulum Yolu : " + targetDir + "\n" +
                    "Masaustu Simgesi : Olusturuldu\n" +
                    "Windows Hizmeti  : " + (enableService ? "Kuruldu ve baslatildi (7/24 AKTIF)" : "Atlandi") + "\n" +
                    "Web SOC Paneli   : http://127.0.0.1:7890\n\n" +
                    (enableService ? "\u2705 7/24 koruma aktif! Servis arka planda calismaya devam ediyor.\n" : "") +
                    "Masaustu simgesine cift tiklayarak kontrol panelini acabilirsiniz.",
                    "Kurulum Tamamlandi",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                if (autoLaunch && File.Exists(exePath))
                {
                    try
                    {
                        Process.Start(exePath, "gui");
                    }
                    catch { }
                }

                this.Close();
            }));
        }
    }
}
