[Setup]
AppName=Project Guard EDR & Antivirus
AppVersion=1.1.0
AppPublisher=Project Guard Team
DefaultDirName={autopf}\ProjectGuard
DisableProgramGroupPage=yes
OutputBaseFilename=ProjectGuard_Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
OutputDir=Output

[Files]
Source: "target\release\project-guard.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\Project Guard"; Filename: "{app}\project-guard.exe"; Parameters: "gui"

[Run]
; Add Defender Exclusions for App and ProgramData
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -WindowStyle Hidden -Command ""Add-MpPreference -ExclusionPath '{app}'; Add-MpPreference -ExclusionPath 'C:\ProgramData\ProjectGuard'"""; Flags: runhidden waituntilterminated

; Install the Windows Service
Filename: "{app}\project-guard.exe"; Parameters: "service install"; Flags: runhidden waituntilterminated

; Start the Windows Service
Filename: "{app}\project-guard.exe"; Parameters: "service start"; Flags: runhidden waituntilterminated

[UninstallRun]
; Stop the Windows Service
Filename: "{app}\project-guard.exe"; Parameters: "service stop"; Flags: runhidden waituntilterminated

; Uninstall the Windows Service
Filename: "{app}\project-guard.exe"; Parameters: "service uninstall"; Flags: runhidden waituntilterminated
