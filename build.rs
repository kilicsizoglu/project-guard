fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "Project Guard - Next-Gen Open EDR & Antivirus");
        res.set("FileDescription", "Project Guard Autonomous Security Agent & EDR");
        res.set("LegalCopyright", "Copyright (C) 2026 Project Guard Open Source");
        res.set("OriginalFilename", "project-guard.exe");
        res.set("InternalName", "project-guard");
        res.set("CompanyName", "Project Guard Team");
        res.set("FileVersion", "1.1.0.0");
        res.set("ProductVersion", "1.1.0.0");
        res.set("Comments", "Next-Gen Open-Source Antivirus, EDR & Threat Hunting Platform with Windows Defender Coexistence");
        res.set_version_info(winres::VersionInfo::FILEVERSION, 0x0001000100000000);
        res.set_version_info(winres::VersionInfo::PRODUCTVERSION, 0x0001000100000000);
        if let Err(e) = res.compile() {
            eprintln!("Warning: Failed to compile windows resource: {}", e);
        }
    }
}
