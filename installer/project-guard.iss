; =====================================================================
; Project Guard - Inno Setup 6 Script
; Kurumsal Windows Kurulum Paketi (Installer Builder)
; =====================================================================

#define MyAppName "Project Guard"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "Project Guard Team"
#define MyAppURL "https://github.com/kilic/project-guard"
#define MyAppExeName "project-guard.exe"

[Setup]
; Temel Kurulum Bilgileri
AppId={{D814B29A-C10E-4E7B-8B37-332D65A2C9F8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\ProjectGuard
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE
OutputDir=dist
OutputBaseFilename=ProjectGuard-Setup-v{#MyAppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\assets\icon.ico
UninstallDisplayName={#MyAppName} EDR & Antivirus
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "startservice"; Description: "Project Guard 7/24 Windows Arka Plan Hizmetini Kaydet ve Baslat"; GroupDescription: "Hizmet Yapilandirmasi:"; Flags: checkedonce

[Files]
; Ana Uygulama Ikilisi (Release veya Debug)
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion; Check: FileExists(ExpandConstant('{src}\..\target\release\{#MyAppExeName}'))
Source: "..\target\debug\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion; Check: not FileExists(ExpandConstant('{src}\..\target\release\{#MyAppExeName}'))

; Medya ve Varlıklar
Source: "..\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

; Yonetim ve Kurulum Komut Dosyalari
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\Uninstall.cmd"; DestDir: "{app}"; Flags: ignoreversion

; Dokumantasyon
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\QUICKSTART.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\ARCHITECTURE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Masaustu Kisayolu (GUI modunda)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "gui"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

; Baslat Menusu Kisayollari
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "gui"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\{#MyAppName} Web SOC Paneli"; Filename: "http://127.0.0.1:7890"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\{#MyAppName} Hizmet Durumu"; Filename: "{app}\{#MyAppExeName}"; Parameters: "service status"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"; IconFilename: "{app}\assets\icon.ico"

[Registry]
; PATH Ortam Degiskenine Ekleme
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; Windows Hizmetini Kaydet ve Baslat (secildiyse)
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install"; StatusMsg: "Project Guard Windows Hizmeti kuruluyor..."; Tasks: startservice; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service start"; StatusMsg: "Project Guard Hizmeti baslatiliyor..."; Tasks: startservice; Flags: runhidden

; Kurulum Sonunda Masaustu Uygulamasini Baslatma
Filename: "{app}\{#MyAppExeName}"; Parameters: "gui"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kaldirma Esnasinda Hizmeti Durdur ve Sil
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden

[Code]
// PATH kontrol fonksiyonu
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
