use std::ffi::c_void;
use std::path::PathBuf;

// Windows API sabitleri
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_TERMINATE: u32 = 0x0001;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_IMAGE: u32 = 0x1000000;

pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;

/// Windows konsol penceresinin açılmasını engelleyen Win32 bayrağı
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Windows üzerinde konsol penceresi (siyah terminal) fırlamasını önleyen güvenli komut oluşturucu
pub fn create_hidden_command<S: AsRef<std::ffi::OsStr>>(program: S) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    #[cfg(target_pointer_width = "64")]
    pub partition_id: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub memory_type: u32,
}

impl Default for MemoryBasicInformation {
    fn default() -> Self {
        Self {
            base_address: std::ptr::null_mut(),
            allocation_base: std::ptr::null_mut(),
            allocation_protect: 0,
            #[cfg(target_pointer_width = "64")]
            partition_id: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            memory_type: 0,
        }
    }
}

unsafe extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn VirtualQueryEx(
        hProcess: *mut c_void,
        lpAddress: *const c_void,
        lpBuffer: *mut MemoryBasicInformation,
        dwLength: usize,
    ) -> usize;
    fn ReadProcessMemory(
        hProcess: *mut c_void,
        lpBaseAddress: *const c_void,
        lpBuffer: *mut u8,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;
    fn TerminateProcess(hProcess: *mut c_void, uExitCode: u32) -> i32;
    fn GetLogicalDrives() -> u32;
    fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
}

pub struct ProcessHandle(*mut c_void);

impl ProcessHandle {
    pub fn open(pid: u32, desired_access: u32) -> Option<Self> {
        let handle = unsafe { OpenProcess(desired_access, 0, pid) };
        if handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn as_raw(&self) -> *mut c_void {
        self.0
    }

    pub fn terminate(&self, exit_code: u32) -> bool {
        let res = unsafe { TerminateProcess(self.0, exit_code) };
        res != 0
    }

    pub fn query_memory_region(&self, address: *const c_void) -> Option<MemoryBasicInformation> {
        let mut mbi = MemoryBasicInformation::default();
        let size = std::mem::size_of::<MemoryBasicInformation>();
        let res = unsafe { VirtualQueryEx(self.0, address, &mut mbi, size) };
        if res == 0 {
            None
        } else {
            Some(mbi)
        }
    }

    pub fn read_memory(&self, address: *const c_void, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.0,
                address,
                buffer.as_mut_ptr(),
                size,
                &mut bytes_read,
            )
        };
        if res != 0 && bytes_read > 0 {
            buffer.truncate(bytes_read);
            Some(buffer)
        } else {
            None
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Sistemde takılı çıkarılabilir (USB / Flash Bellek) sürücü harflerini döndürür
pub fn get_removable_drives() -> Vec<PathBuf> {
    let mut drives = Vec::new();
    let bitmask = unsafe { GetLogicalDrives() };

    for i in 0..26 {
        if (bitmask & (1 << i)) != 0 {
            let drive_letter = (b'A' + i) as char;
            let root_str = format!("{}:\\\0", drive_letter);
            let wide_chars: Vec<u16> = root_str.encode_utf16().collect();
            let drive_type = unsafe { GetDriveTypeW(wide_chars.as_ptr()) };

            if drive_type == DRIVE_REMOVABLE {
                drives.push(PathBuf::from(format!("{}:\\", drive_letter)));
            }
        }
    }

    drives
}

/// Tüm takılı sabit ve çıkarılabilir sürücü harflerini döndürür
pub fn get_all_drives() -> Vec<(PathBuf, &'static str)> {
    let mut drives = Vec::new();
    let bitmask = unsafe { GetLogicalDrives() };

    for i in 0..26 {
        if (bitmask & (1 << i)) != 0 {
            let drive_letter = (b'A' + i) as char;
            let root_str = format!("{}:\\\0", drive_letter);
            let wide_chars: Vec<u16> = root_str.encode_utf16().collect();
            let drive_type = unsafe { GetDriveTypeW(wide_chars.as_ptr()) };

            let type_str = match drive_type {
                DRIVE_REMOVABLE => "Cikarilabilir (USB)",
                DRIVE_FIXED => "Sabit Disk",
                _ => "Diger",
            };

            drives.push((PathBuf::from(format!("{}:\\", drive_letter)), type_str));
        }
    }

    drives
}
