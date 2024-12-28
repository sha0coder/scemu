use crate::emu;
use crate::console;
use crate::constants;
use crate::peb64;
use crate::structures;
use crate::winapi32::helper;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::context64;
use lazy_static::lazy_static;
use std::sync::Mutex;

macro_rules! log_red {
    ($emu:expr, $($arg:tt)*) => {
        log::info!(
            "{}{}{}",
            $emu.colors.light_red,
            format!($($arg)*),
            $emu.colors.nc
        );
    };
}

// a in RCX, b in RDX, c in R8, d in R9, then e pushed on stack

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = guess_api_name(emu, addr);
    match api.as_str() {
        "FindActCtxSectionStringW" => FindActCtxSectionStringW(emu),
        "LoadLibraryA" => LoadLibraryA(emu),
        "LoadLibraryW" => LoadLibraryW(emu),
        "LoadLibraryExA" => LoadLibraryExA(emu),
        "LoadLibraryExW" => LoadLibraryExW(emu),
        "GetProcAddress" => GetProcAddress(emu),
        "WinExec" => WinExec(emu),
        "GetVersion" => GetVersion(emu),
        "GetVersionExA" => GetVersionExA(emu),
        "GetVersionExW" => GetVersionExW(emu),
        "CreateProcessA" => CreateProcessA(emu),
        "CreateProcessW" => CreateProcessW(emu),
        "CreateToolhelp32Snapshot" => CreateToolhelp32Snapshot(emu),
        "Process32First" => Process32First(emu),
        "Process32Next" => Process32Next(emu),
        "LStrCmpI" => LStrCmpI(emu),
        "lstrcmpiW" => LStrCmpIW(emu),
        "LStrCmpIW" => LStrCmpIW(emu),
        "AreFileApiIsAnsi" => AreFileApiIsAnsi(emu),
        "BeginUpdateResourceA" => BeginUpdateResourceA(emu),
        "OpenProcess" => OpenProcess(emu),
        "VirtualAlloc" => VirtualAlloc(emu),
        "VirtualAllocEx" => VirtualAllocEx(emu),
        "Thread32First" => Thread32First(emu),
        "Thread32Next" => Thread32Next(emu),
        "OpenThread" => OpenThread(emu),
        "GetSystemTimeAsFileTime" => GetSystemTimeAsFileTime(emu),
        "GetCurrentThreadId" => GetCurrentThreadId(emu),
        "GetCurrentProcessId" => GetCurrentProcessId(emu),
        "QueryPerformanceCounter" => QueryPerformanceCounter(emu),
        "GetProcessHeap" => GetProcessHeap(emu),
        "HeapCreate" => HeapCreate(emu),
        "HeapAlloc" => HeapAlloc(emu),
        "CreateEventA" => CreateEventA(emu),
        "CreateThread" => CreateThread(emu),
        "Sleep" => Sleep(emu),
        "LocalAlloc" => LocalAlloc(emu),
        "WriteProcessMemory" => WriteProcessMemory(emu),
        "CreateRemoteThread" => CreateRemoteThread(emu),
        "CreateNamedPipeA" => CreateNamedPipeA(emu),
        "CreateNamedPipeW" => CreateNamedPipeW(emu),
        "ConnectNamedPipe" => ConnectNamedPipe(emu),
        "DisconnectNamedPipe" => DisconnectNamedPipe(emu),
        "ReadFile" => ReadFile(emu),
        "WriteFile" => WriteFile(emu),
        "CloseHandle" => CloseHandle(emu),
        "ExitProcess" => ExitProcess(emu),
        "TerminateProcess" => TerminateProcess(emu),
        "WaitForSingleObject" => WaitForSingleObject(emu),
        "GetThreadContext" => GetThreadContext(emu),
        "ReadProcessMemory" => ReadProcessMemory(emu),
        "GetCurrentDirectoryA" => GetCurrentDirectoryA(emu),
        "GetCurrentDirectoryW" => GetCurrentDirectoryW(emu),
        "VirtualProtect" => VirtualProtect(emu),
        "VirtualProtectEx" => VirtualProtectEx(emu),
        "ResumeThread" => ResumeThread(emu),
        "GetFullPathNameA" => GetFullPathNameA(emu),
        "GetFullPathNameW" => GetFullPathNameW(emu),
        "SystemTimeToTzSpecificLocalTime" => SystemTimeToTzSpecificLocalTime(emu),
        "GetLogicalDrives" => GetLogicalDrives(emu),
        "ExpandEnvironmentStringsA" => ExpandEnvironmentStringsA(emu),
        "ExpandEnvironmentStringsW" => ExpandEnvironmentStringsW(emu),
        "GetFileAttributesA" => GetFileAttributesA(emu),
        "GetFileAttributesW" => GetFileAttributesW(emu),
        "FileTimeToSystemTime" => FileTimeToSystemTime(emu),
        "FindFirstFileA" => FindFirstFileA(emu),
        "FindFirstFileW" => FindFirstFileW(emu),
        "FindNextFileA" => FindNextFileA(emu),
        "FindNextFileW" => FindNextFileW(emu),
        "CopyFileA" => CopyFileA(emu),
        "CopyFileW" => CopyFileW(emu),
        "FindClose" => FindClose(emu),
        "MoveFileA" => MoveFileA(emu),
        "MoveFileW" => MoveFileW(emu),
        "MapViewOfFile" => MapViewOfFile(emu),
        "GetTickCount" => GetTickCount(emu),
        "InitializeCriticalSectionAndSpinCount" => InitializeCriticalSectionAndSpinCount(emu),
        "GetProcessAffinityMask" => GetProcessAffinityMask(emu),
        "IsDebuggerPresent" => IsDebuggerPresent(emu),
        "SetUnhandledExceptionFilter" => SetUnhandledExceptionFilter(emu),
        "UnhandledExceptionFilter" => UnhandledExceptionFilter(emu),
        "GetCurrentProcess" => GetCurrentProcess(emu),
        "VirtualAllocExNuma" => VirtualAllocExNuma(emu),
        "GetUserDefaultLangId" => GetUserDefaultLangId(emu),
        "GetComputerNameA" => GetComputerNameA(emu),
        "GetComputerNameW" => GetComputerNameW(emu),
        "CreateMutexA" => CreateMutexA(emu),
        "CreateMutexW" => CreateMutexW(emu),
        "GetLastError" => GetLastError(emu),
        "CreateFileMappingA" => CreateFileMappingA(emu),
        "CreateFileMappingW" => CreateFileMappingW(emu),
        "GetSystemTime" => GetSystemTime(emu),
        "lstrcatA" => lstrcatA(emu),
        "lstrcatW" => lstrcatW(emu),
        "SetErrorMode" => SetErrorMode(emu),
        "GetSystemDirectoryA" => GetSystemDirectoryA(emu),
        "GetSystemDirectoryW" => GetSystemDirectoryW(emu),
        "GetStartupInfoA" => GetStartupInfoA(emu),
        "GetStartupInfoW" => GetStartupInfoW(emu),
        "IsProcessorFeaturePresent" => IsProcessorFeaturePresent(emu),
        "InitializeCriticalSection" => InitializeCriticalSection(emu),
        "InitializeCriticalSectionEx" => InitializeCriticalSectionEx(emu),
        "FlsAlloc" => FlsAlloc(emu),
        "FlsGetValue" => FlsGetValue(emu),
        "FlsSetValue" => FlsSetValue(emu),
        "SetLastError" => SetLastError(emu),
        "lstrlenA" => lstrlenA(emu),
        "lstrlenW" => lstrlenW(emu),
        "MultiByteToWideChar" => MultiByteToWideChar(emu),
        "GetSystemInfo" => GetSystemInfo(emu),
        "HeapFree" => HeapFree(emu),
        "EncodePointer" => EncodePointer(emu),
        "DecodePointer" => DecodePointer(emu),
        "lstrcpyn" => lstrcpyn(emu),
        "GetModuleFileNameA" => GetModuleFileNameA(emu),
        "GetLocalTime" => GetLocalTime(emu),
        "SystemTimeToFileTime" => SystemTimeToFileTime(emu),
        "GetNativeSystemInfo" => GetNativeSystemInfo(emu),
        "lstrcpyW" => lstrcpyW(emu),
        "lstrcpy" => lstrcpy(emu),
        "GetModuleHandleA" => GetModuleHandleA(emu),
        "GetModuleHandleW" => GetModuleHandleW(emu),
        "TlsAlloc" => TlsAlloc(emu),
        "TlsSetValue" => TlsSetValue(emu),
        "TlsGetValue" => TlsGetValue(emu),
        "TlsFree" => TlsFree(emu),
        "GetACP" => GetACP(emu),
        "GetStdHandle" => GetStdHandle(emu),
        "GetConsoleCP" => GetConsoleCP(emu),
        "GetConsoleOutputCP" => GetConsoleOutputCP(emu),
        "GetCommandLineA" => GetCommandLineA(emu),
        "GetCommandLineW" => GetCommandLineW(emu),
        "GetCPInfo" => GetCPInfo(emu),
        "GetUserDefaultLCID" => GetUserDefaultLCID(emu),
        "SetThreadLocale" => SetThreadLocale(emu),
        "GetThreadLocale" => GetThreadLocale(emu),
        "GetLocaleInfoW" => GetLocaleInfoW(emu),
        "WideCharToMultiByte" => WideCharToMultiByte(emu),
        "GetLocaleInfoA" => GetLocaleInfoA(emu),
        "GetWindowsDirectoryA" => GetWindowsDirectoryA(emu),
        "ResetEvent" => ResetEvent(emu),
        "VirtualFree" => VirtualFree(emu),
        "GetModuleFileNameW" => GetModuleFileNameW(emu),
        "EnterCriticalSection" => EnterCriticalSection(emu),
        "LeaveCriticalSection" => LeaveCriticalSection(emu),

        _ => {
            if emu.cfg.skip_unimplemented == false {
                unimplemented!("calling unimplemented kernel32 API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented kernel32 API 0x{:x} {}", addr, api);
            return api;
        }
    }

    String::new()
}

lazy_static! {
    static ref COUNT_READ: Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE: Mutex<u32> = Mutex::new(0);
    static ref LAST_ERROR: Mutex<u64> = Mutex::new(0);
}

pub fn dump_module_iat(emu: &mut emu::Emu, module: &str) {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.mod_name.to_lowercase().contains(module) && flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                log::info!(
                    "0x{:x} {}!{}",
                    ordinal.func_va,
                    &flink.mod_name,
                    &ordinal.func_name
                );
            }
        }
        flink.next(emu);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }
}

pub fn resolve_api_addr_to_name(emu: &mut emu::Emu, addr: u64) -> String {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                if ordinal.func_va == addr {
                    let s = ordinal.func_name.to_string();
                    return s;
                }
            }
        }
        flink.next(emu);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    "".to_string()
}

pub fn resolve_api_name(emu: &mut emu::Emu, name: &str) -> u64 {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                if ordinal.func_name.to_lowercase() == name.to_lowercase() {
                    //if ordinal.func_name.contains(name) {
                    return ordinal.func_va;
                }
            }
        }
        flink.next(emu);

        //log::info!("flink: 0x{:x} first_ptr: 0x{:x}", flink.get_ptr(), first_ptr);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    0 //TODO: use Option<>
}

pub fn search_api_name(emu: &mut emu::Emu, name: &str) -> (u64, String, String) {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                if ordinal.func_name.contains(name) {
                    return (
                        ordinal.func_va,
                        flink.mod_name.clone(),
                        ordinal.func_name.clone(),
                    );
                }
            }
        }
        flink.next(emu);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    (0, String::new(), String::new()) //TODO: use Option<>
}

pub fn guess_api_name(emu: &mut emu::Emu, addr: u64) -> String {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        //let mod_name = flink.mod_name.clone();

        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);

                if ordinal.func_va == addr {
                    return ordinal.func_name.clone();
                }
            }
        }

        flink.next(emu);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    "function not found".to_string()
}

pub fn load_library(emu: &mut emu::Emu, libname: &str) -> u64 {
    // log::info!("kern32!load_library: {}", libname);

    let mut dll = libname.to_string().to_lowercase();

    if dll.is_empty() {
        emu.regs.rax = 0;
        return 0;
    }

    if !dll.ends_with(".dll") {
        dll.push_str(".dll");
    }

    let mut dll_path = emu.cfg.maps_folder.clone();
    dll_path.push('/');
    dll_path.push_str(&dll);

    match peb64::get_module_base(&dll, emu) {
        Some(base) => {
            // already linked
            /*
            if emu.cfg.verbose > 0 {
                log::info!("dll {} already linked.", dll);
            }*/
            base
        }
        None => {
            // do link
            if std::path::Path::new(&dll_path).exists() {
                let (base, pe_off) = emu.load_pe64(&dll_path, false, 0);
                peb64::dynamic_link_module(base, pe_off, &dll, emu);
                return base;
            } else {
                if emu.cfg.verbose > 0 {
                    log::info!("dll {} not found.", dll_path);
                }
                0
            }
        }
    }
}

pub fn get_library_handle(emu: &mut emu::Emu, libname: &str) -> u64 {
    // log::info!("kern32!load_library: {}", libname);

    let mut dll = libname.to_string().to_lowercase();

    if dll.is_empty() {
        emu.regs.rax = 0;
        return 0;
    }

    if !dll.ends_with(".dll") {
        dll.push_str(".dll");
    }

    let mut dll_path = emu.cfg.maps_folder.clone();
    dll_path.push('/');
    dll_path.push_str(&dll);

    match peb64::get_module_base(&dll, emu) {
        Some(base) => {
            return base;
        }
        None => {
            // if is not linked, dont link, this is not a load_library
            return 0;
        }
    }
}

fn LoadLibraryA(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    log::info!(
        "{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        dll,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn LoadLibraryW(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_wide_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    log::info!(
        "{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        dll,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn LoadLibraryExA(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    log::info!(
        "{}** {} kernel32!LoadLibraryExA  '{}' =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        dll,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn LoadLibraryExW(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_wide_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    log::info!(
        "{}** {} kernel32!LoadLibraryExW '{}' =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        dll,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn GetProcAddress(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let func_ptr = emu.regs.rdx;

    let func = emu.maps.read_string(func_ptr).to_lowercase();

    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }
                let ordinal = flink.get_function_ordinal(emu, i);

                // log::info!("func name {}!{}", flink.mod_name, ordinal.func_name);

                if ordinal.func_name.to_lowercase() == func {
                    emu.regs.rax = ordinal.func_va;
                    log::info!(
                        "{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}",
                        emu.colors.light_red,
                        emu.pos,
                        flink.mod_name,
                        ordinal.func_name,
                        emu.regs.rax,
                        emu.colors.nc
                    );
                    return;
                }
            }
        }

        flink.next(emu);
        if flink.get_ptr() == first_flink {
            break;
        }
    }
    emu.regs.rax = 0;
    log::warn!("kernel32!GetProcAddress error searching {}", func);
}

fn WinExec(emu: &mut emu::Emu) {
    let cmdline_ptr = emu.regs.rcx;
    let cmdline = emu.maps.read_string(cmdline_ptr);

    log::info!(
        "{}** {} kernel32!WinExec  '{}'  {}",
        emu.colors.light_red,
        emu.pos,
        cmdline,
        emu.colors.nc
    );

    emu.regs.rax = 32;
}

fn GetVersion(emu: &mut emu::Emu) {
    emu.regs.rax = constants::VERSION;
    log::info!(
        "{}** {} kernel32!GetVersion   =0x{:x}  {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn GetVersionExW(emu: &mut emu::Emu) {
    let version_info_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetVersionExW 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        version_info_ptr,
        emu.colors.nc
    );

    let os_version_info = structures::OsVersionInfo::new();
    os_version_info.save(version_info_ptr, &mut emu.maps);

    emu.regs.rax = 1;
}

fn GetVersionExA(emu: &mut emu::Emu) {
    let version_info_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetVersionExA 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        version_info_ptr,
        emu.colors.nc
    );

    let os_version_info = structures::OsVersionInfo::new();
    os_version_info.save(version_info_ptr, &mut emu.maps);

    emu.regs.rax = 1;
}

fn CreateToolhelp32Snapshot(emu: &mut emu::Emu) {
    let flags = emu.regs.rcx;
    let pid = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!CreateToolhelp32Snapshot flags: {:x} pid: {} {}",
        emu.colors.light_red,
        emu.pos,
        flags,
        pid,
        emu.colors.nc
    );

    let uri = format!("CreateToolhelp32Snapshot://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn Process32First(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let lppe = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!Process32First hndl: {:x} lppe: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        lppe,
        emu.colors.nc
    );

    if !helper::handler_exist(handle) {
        emu.regs.rax = 0;
        return;
    }

    emu.maps.write_string(lppe + 44, "smss.exe\x00");

    /*

                typedef struct tagPROCESSENTRY32 {
                DWORD     dwSize;                +0
                DWORD     cntUsage;              +4
                DWORD     th32ProcessID;         +8
                ULONG_PTR th32DefaultHeapID;    +12
                DWORD     th32ModuleID;         +16
                DWORD     cntThreads;           +20
                DWORD     th32ParentProcessID;  +24
                LONG      pcPriClassBase;       +28
                DWORD     dwFlags;              +32
                CHAR      szExeFile[MAX_PATH];  +36
                } PROCESSENTRY32;
    */

    emu.regs.rax = 1;
}

fn Process32Next(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let lppe = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!Process32Next hndl: {:x} lppe: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        lppe,
        emu.colors.nc
    );

    emu.maps.write_string(lppe + 44, "explorer.exe\x00");

    if !helper::handler_exist(handle) {
        emu.regs.rax = 0;
        return;
    }

    emu.regs.rax = 0; // trigger exit loop
}

fn LStrCmpI(emu: &mut emu::Emu) {
    let sptr1 = emu.regs.rcx;
    let sptr2 = emu.regs.rdx;

    let s1 = emu.maps.read_string(sptr1);
    let s2 = emu.maps.read_string(sptr2);

    if s1 == s2 {
        log::info!(
            "{}** {} kernel32!lstrcmpi `{}` == `{}` {}",
            emu.colors.light_red,
            emu.pos,
            s1,
            s2,
            emu.colors.nc
        );
        emu.regs.rax = 0;
    } else {
        log::info!(
            "{}** {} kernel32!lstrcmpi `{}` != `{}` {}",
            emu.colors.light_red,
            emu.pos,
            s1,
            s2,
            emu.colors.nc
        );
        emu.regs.rax = 1;
    }
}

fn LStrCmpIW(emu: &mut emu::Emu) {
    let sptr1 = emu.regs.rcx;
    let sptr2 = emu.regs.rdx;

    let s1 = emu.maps.read_wide_string(sptr1);
    let s2 = emu.maps.read_wide_string(sptr2);

    if s1 == s2 {
        log::info!(
            "{}** {} kernel32!lstrcmpiW `{}` == `{}` {}",
            emu.colors.light_red,
            emu.pos,
            s1,
            s2,
            emu.colors.nc
        );
        emu.regs.rax = 0;
    } else {
        log::info!(
            "{}** {} kernel32!lstrcmpiW `{}` != `{}` {}",
            emu.colors.light_red,
            emu.pos,
            s1,
            s2,
            emu.colors.nc
        );
        emu.regs.rax = 1;
    }
}

fn AreFileApiIsAnsi(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!AreFileApiIsAnsi {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn BeginUpdateResourceA(emu: &mut emu::Emu) {
    let pFileName = emu.regs.rcx;
    let bDeleteExistingResources = emu.regs.rdx;

    let filename = emu.maps.read_string(pFileName);

    log::info!(
        "{}** {} kernel32!BeginUpdateResourceA `{}` {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        bDeleteExistingResources,
        emu.colors.nc
    );

    emu.regs.rax = helper::handler_create(&filename);
}

fn OpenProcess(emu: &mut emu::Emu) {
    let access = emu.regs.rcx;
    let inherit = emu.regs.rdx;
    let pid = emu.regs.r8;

    log::info!(
        "{}** {} kernel32!OpenProcess pid: {} {}",
        emu.colors.light_red,
        emu.pos,
        pid,
        emu.colors.nc
    );

    let uri = format!("pid://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn VirtualAlloc(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let typ = emu.regs.r8;
    let prot = emu.regs.r9;

    if size == 0 {
        log::info!(
            "{}** {} kernel32!VirtualAlloc addr: 0x{:x} sz: {} = 0 {}",
            emu.colors.light_red,
            emu.pos,
            addr,
            size,
            emu.colors.nc
        );
        emu.regs.rax = 0
    } else {
        let base = emu
            .maps
            .alloc(size)
            .unwrap_or_else(|| panic!("kernel32!VirtualAlloc out of memory size:{}", size));

        log::info!(
            "{}** {} kernel32!VirtualAlloc addr: 0x{:x} sz: {} = 0x{:x} {}",
            emu.colors.light_red,
            emu.pos,
            addr,
            size,
            base,
            emu.colors.nc
        );

        emu.maps
            .create_map(format!("alloc_{:x}", base).as_str(), base, size)
            .expect("kernel32!VirtualAlloc out of memory");

        emu.regs.rax = base;
    }
}

fn VirtualAllocEx(emu: &mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let size = emu.regs.r8;
    let alloc_type = emu.regs.r9;
    let protect = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!VirtualAllocEx cannot read_qword protect");

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAllocEx out of memory");

    log::info!(
        "{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} sz: {} = 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        proc_hndl,
        addr,
        size,
        base,
        emu.colors.nc
    );

    emu.maps
        .create_map(format!("alloc_{:x}", base).as_str(), base, size)
        .expect("kernel32!VirtualAllocEx out of memory");

    emu.regs.rax = base;
}

fn WriteProcessMemory(emu: &mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let buff = emu.regs.r8;
    let size = emu.regs.r9;
    let written_ptr = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!WriteProcessMemory cannot read written_ptr");

    log::info!(
        "{}** {} kernel32!WriteProcessMemory hproc: 0x{:x} from: 0x{:x } to: 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        proc_hndl,
        buff,
        addr,
        size,
        emu.colors.nc
    );

    if emu.maps.memcpy(buff, addr, size as usize) {
        emu.regs.rax = 1;
        log::info!(
            "{}\twritten succesfully{}",
            emu.colors.light_red,
            emu.colors.nc
        );
        if written_ptr != 0 && !emu.maps.write_qword(written_ptr, size) {
            log::info!("kernel32!WriteProcessMemory cannot write on written_ptr");
        }
    } else {
        emu.regs.rax = 0;
        log::info!(
            "{}\tcouldnt write all the bytes{}",
            emu.colors.light_red,
            emu.colors.nc
        );
        if written_ptr != 0 && !emu.maps.write_qword(written_ptr, 0) {
            log::info!("kernel32!WriteProcessMemory cannot write on written_ptr");
        }
    }
}

fn Thread32First(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let entry = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!Thread32First {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
    //emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn Thread32Next(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let entry = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!Thread32Next {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn OpenThread(emu: &mut emu::Emu) {
    let access = emu.regs.rcx;
    let inherit = emu.regs.rdx;
    let tid = emu.regs.r8;

    log::info!(
        "{}** {} kernel32!OpenThread tid: {} {}",
        emu.colors.light_red,
        emu.pos,
        tid,
        emu.colors.nc
    );

    let uri = format!("tid://{}", tid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetSystemTimeAsFileTime(emu: &mut emu::Emu) {
    let sys_time_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetSystemTimeAsFileTime {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetCurrentThreadId(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCurrentThreadId {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 0x111; //TODO: track pids and tids
}

fn GetCurrentProcessId(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCurrentProcessId {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 0x123;
}

fn QueryPerformanceCounter(emu: &mut emu::Emu) {
    let counter_ptr = emu.regs.rcx;

    emu.maps.write_dword(counter_ptr, 0x1);

    log::info!(
        "{}** {} kernel32!QueryPerformanceCounter {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetProcessHeap(emu: &mut emu::Emu) {
    emu.regs.rax = helper::handler_create("heap");

    log::info!(
        "{}** {} kernel32!GetProcessHeap ={} {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn HeapAlloc(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let size = emu.regs.r8;

    emu.regs.rax = emu.maps.alloc(size).unwrap_or_default();

    emu.maps
        .create_map(
            format!("alloc_{:x}", emu.regs.rax).as_str(),
            emu.regs.rax,
            size,
        )
        .expect("kernel32!HeapAlloc out of memory");

    log::info!(
        "{}** {} kernel32!HeapAlloc flags: 0x{:x} size: {} =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        flags,
        size,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn CreateEventA(emu: &mut emu::Emu) {
    let attributes = emu.regs.rcx;
    let bManualReset = emu.regs.rdx;
    let bInitialState = emu.regs.r8;
    let name_ptr = emu.regs.r9;

    let mut name = String::new();
    if name_ptr > 0 {
        name = emu.maps.read_string(name_ptr);
    }

    log::info!(
        "{}** {} kernel32!CreateEventA attr: 0x{:x} manual_reset: {} init_state: {} name: {} {}",
        emu.colors.light_red,
        emu.pos,
        attributes,
        bManualReset,
        bInitialState,
        name,
        emu.colors.nc
    );

    let uri = format!("event://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateThread(emu: &mut emu::Emu) {
    let sec_attr = emu.regs.rcx;
    let stack_sz = emu.regs.rdx;
    let code = emu.regs.r8;
    let param = emu.regs.r9;
    let flags = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!CreateThread cannot read flags");
    let tid_ptr = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateThread cannot read tid_ptr");

    if tid_ptr > 0 {
        emu.maps.write_dword(tid_ptr, 0x123);
    }

    log::info!(
        "{}** {} kernel32!CreateThread code: 0x{:x} param: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        code,
        param,
        emu.colors.nc
    );

    if flags == constants::CREATE_SUSPENDED {
        log::info!("\tcreated suspended!");
    }

    let con = console::Console::new();
    con.print("Continue emulating the created thread (y/n)? ");
    let line = con.cmd();

    if line == "y" || line == "yes" {
        if emu.maps.is_mapped(code) {
            emu.regs.rip = code;
            emu.regs.rax = 0;
            emu.regs.rcx = param;
            emu.main_thread_cont = emu.gateway_return;
            emu.stack_push64(param);
            emu.stack_push64(constants::RETURN_THREAD.into());

            // alloc a stack vs reusing stack.
            return;
        } else {
            log::info!("cannot emulate the thread, the function pointer is not mapped.");
        }
    }

    emu.regs.rax = helper::handler_create("tid://0x123");
}

fn Sleep(emu: &mut emu::Emu) {
    let millis = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!Sleep millis: {} {}",
        emu.colors.light_red,
        emu.pos,
        millis,
        emu.colors.nc
    );
    emu.tick += millis as usize;
}

fn LocalAlloc(emu: &mut emu::Emu) {
    let flags = emu.regs.rcx;
    let bytes = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!LocalAlloc flags: {:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        flags,
        bytes,
        emu.colors.nc
    );

    let base = emu
        .maps
        .alloc(bytes)
        .expect("kernel32!LocalAlloc out of memory");
    emu.maps
        .create_map(format!("alloc_{:x}", base).as_str(), base, bytes)
        .expect("kernel32!LocalAlloc out of memory");

    emu.regs.rax = base;
}

fn CreateProcessA(emu: &mut emu::Emu) {
    let appname_ptr = emu.regs.rcx;
    let cmdline_ptr = emu.regs.rdx;
    let appname = emu.maps.read_string(appname_ptr);
    let cmdline = emu.maps.read_string(cmdline_ptr);

    log::info!(
        "{}** {} kernel32!CreateProcessA  {} {} {}",
        emu.colors.light_red,
        emu.pos,
        appname,
        cmdline,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CreateProcessW(emu: &mut emu::Emu) {
    let appname_ptr = emu.regs.rcx;
    let cmdline_ptr = emu.regs.rdx;
    let appname = emu.maps.read_wide_string(appname_ptr);
    let cmdline = emu.maps.read_wide_string(cmdline_ptr);

    log::info!(
        "{}** {} kernel32!CreateProcessW  {} {} {}",
        emu.colors.light_red,
        emu.pos,
        appname,
        cmdline,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CreateRemoteThread(emu: &mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let sec = emu.regs.rdx;
    let stack_size = emu.regs.r8;
    let addr = emu.regs.r9;
    let param = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("krenel32!CreateRemoteThread cannot read the param");
    let flags = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateRemoteThread cannot read the flags");
    let out_tid = emu
        .maps
        .read_qword(emu.regs.rsp + 16)
        .expect("kernel32!CreateRemoteThread cannot read the tid");

    log::info!(
        "{}** {} kernel32!CreateRemoteThread hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        proc_hndl,
        addr,
        emu.colors.nc
    );

    emu.maps.write_dword(out_tid, 0x123);
    emu.regs.rax = helper::handler_create("tid://0x123");
}

fn CreateNamedPipeA(emu: &mut emu::Emu) {
    let name_ptr = emu.regs.rcx;
    let open_mode = emu.regs.rcx;
    let pipe_mode = emu.regs.r8;
    let instances = emu.regs.r9;
    let out_buff_sz = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu
        .maps
        .read_qword(emu.regs.rsp + 16)
        .expect("kernel32!CreateNamedPipeA cannot read the timeout");
    let security = emu
        .maps
        .read_qword(emu.regs.rsp + 24)
        .expect("kernel32!CreateNamedPipeA cannot read the security");

    let name = emu.maps.read_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        in_buff_sz,
        out_buff_sz,
        emu.colors.nc
    );

    emu.regs.rax = helper::handler_create(&name);
}

fn CreateNamedPipeW(emu: &mut emu::Emu) {
    let name_ptr = emu.regs.rcx;
    let open_mode = emu.regs.rcx;
    let pipe_mode = emu.regs.r8;
    let instances = emu.regs.r9;
    let out_buff_sz = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu
        .maps
        .read_qword(emu.regs.rsp + 16)
        .expect("kernel32!CreateNamedPipeA cannot read the timeout");
    let security = emu
        .maps
        .read_qword(emu.regs.rsp + 24)
        .expect("kernel32!CreateNamedPipeA cannot read the security");

    let name = emu.maps.read_wide_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        in_buff_sz,
        out_buff_sz,
        emu.colors.nc
    );

    emu.regs.rax = helper::handler_create(&name);
}

fn ConnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let overlapped = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!ConnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        emu.colors.nc
    );

    if !helper::handler_exist(handle) {
        log::info!("\tinvalid handle.");
    }

    emu.regs.rax = 1;
}

fn DisconnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn ReadFile(emu: &mut emu::Emu) {
    let file_hndl = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let size = emu.regs.r8;
    let bytes_read = emu.regs.r9;
    let overlapped = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!ReadFile cannot read the overlapped");

    let mut count = COUNT_READ.lock().unwrap();
    *count += 1;

    if size == 4 && *count == 1 {
        // probably reading the size
        emu.maps.write_dword(buff, 0x10);
    }

    if *count < 3 {
        // keep reading bytes
        emu.maps.write_qword(bytes_read, size);
        emu.maps.memset(buff, 0x90, size as usize);
        emu.regs.rax = 1;
    } else {
        // try to force finishing reading and continue the malware logic
        emu.maps.write_qword(bytes_read, 0);
        emu.regs.rax = 0;
    }

    //TODO: write some random bytes to the buffer
    //emu.maps.write_spaced_bytes(buff, "00 00 00 01".to_string());

    log::info!(
        "{}** {} kernel32!ReadFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        file_hndl,
        buff,
        size,
        emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        log::info!("\tinvalid handle.")
    }
}

fn WriteFile(emu: &mut emu::Emu) {
    let file_hndl = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let size = emu.regs.r8;
    let bytes_written = emu.regs.r9;
    let overlapped = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!WriteFile cannot read the overlapped");

    let mut count = COUNT_WRITE.lock().unwrap();
    *count += 1;

    emu.maps.write_qword(bytes_written, size);

    log::info!(
        "{}** {} kernel32!WriteFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        file_hndl,
        buff,
        size,
        emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        log::info!("\tinvalid handle.")
    }

    emu.regs.rax = 1;
}

fn CloseHandle(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!CloseHandle 0x{:X} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        emu.colors.nc
    );

    if !helper::handler_close(handle) {
        log::info!("\tinvalid handle.")
    }
    emu.regs.rax = 1;
}

fn ExitProcess(emu: &mut emu::Emu) {
    let code = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!ExitProcess code: {} {}",
        emu.colors.light_red,
        emu.pos,
        code,
        emu.colors.nc
    );
    std::process::exit(1);
}

fn TerminateProcess(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let code = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!TerminateProcess hndl: {} code: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        code,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn WaitForSingleObject(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let millis = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        millis,
        emu.colors.nc
    );

    emu.regs.rax = constants::WAIT_TIMEOUT;
}

fn GetThreadContext(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let ctx_ptr = emu.regs.rdx;

    let ctx = context64::Context64::new(&emu.regs);
    ctx.save(ctx_ptr, &mut emu.maps);

    log::info!(
        "{}** {} kernel32!GetThreadContext  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn ReadProcessMemory(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let buff = emu.regs.r8;
    let size = emu.regs.r9;
    let bytes = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!ReadProcessMemory cannot read bytes");

    log::info!(
        "{}** {} kernel32!ReadProcessMemory hndl: {} from: 0x{:x} to: 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        addr,
        buff,
        size,
        emu.colors.nc
    );

    emu.maps.write_qword(bytes, size);
    emu.maps.memset(buff, 0x90, size as usize);

    emu.regs.rax = 1;
}

fn GetCurrentDirectoryA(emu: &mut emu::Emu) {
    let buff_len = emu.regs.rcx;
    let buff_ptr = emu.regs.rdx;

    emu.maps.write_string(buff_ptr, "c:\\\x00");
    log::info!(
        "{}** {} kernel32!GetCurrentDirectoryA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 3;
}

fn GetCurrentDirectoryW(emu: &mut emu::Emu) {
    let buff_len = emu.regs.rcx;
    let buff_ptr = emu.regs.rdx;

    emu.maps
        .write_string(buff_ptr, "c\x00:\x00\\\x00\x00\x00\x00\x00");
    log::info!(
        "{}** {} kernel32!GetCurrentDirectoryW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 6;
}

fn VirtualProtect(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let new_prot = emu.regs.r8;
    let old_prot_ptr = emu.regs.r9;

    emu.maps.write_qword(old_prot_ptr, new_prot);

    log::info!(
        "{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        size,
        new_prot,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn VirtualProtectEx(emu: &mut emu::Emu) {
    let hproc = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let size = emu.regs.r8;
    let new_prot = emu.regs.r9;
    let oldld_prot_ptr = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!VirtualProtectEx cannot read old_prot");

    log::info!(
        "{}** {} kernel32!VirtualProtectEx hproc: {} addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red,
        emu.pos,
        hproc,
        addr,
        size,
        new_prot,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn ResumeThread(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!ResumeThread hndl: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        emu.colors.nc
    );

    emu.regs.rax = 1; // previous suspend count
}

fn GetFullPathNameA(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let buff = emu.regs.r8;
    let path = emu.regs.r9;

    let filename = emu.maps.read_string(file_ptr);
    log::info!(
        "{}** {} kernel32!GetFullPathNameA file: {}  {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );
    // TODO: save the path to buff.
    emu.regs.rax = 10;
}

fn GetFullPathNameW(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let buff = emu.regs.r8;
    let path = emu.regs.r9;

    let filename = emu.maps.read_wide_string(file_ptr);
    log::info!(
        "{}** {} kernel32!GetFullPathNameW file: {}  {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );
    // TODO: save the path to buff.
    emu.regs.rax = 10;
}

fn SystemTimeToTzSpecificLocalTime(emu: &mut emu::Emu) {
    let tz_ptr = emu.regs.rcx;
    let ut_ptr = emu.regs.rcx;
    let lt_ptr = emu.regs.r8;

    log::info!(
        "{}** {} kernel32!SystemTimeToTzSpecificLocalTime {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetLogicalDrives(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetLogicalDrives {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0xc;
}

fn ExpandEnvironmentStringsA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let size = emu.regs.r8;

    let src = emu.maps.read_string(src_ptr);

    log::info!(
        "{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        emu.colors.nc
    );
    // TODO: expand typical environment varsl.
    emu.regs.rax = 1;
}

fn ExpandEnvironmentStringsW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let size = emu.regs.r8;

    let src = emu.maps.read_wide_string(src_ptr);

    log::info!(
        "{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        emu.colors.nc
    );
    // TODO: expand typical environment varsl.
    emu.regs.rax = 1;
}

fn GetFileAttributesA(emu: &mut emu::Emu) {
    let filename_ptr = emu.regs.rcx;
    let filename = emu.maps.read_string(filename_ptr);

    log::info!(
        "{}** {} kernel32!GetFileAttributesA file: {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );
    emu.regs.rax = 0x123;
}

fn GetFileAttributesW(emu: &mut emu::Emu) {
    let filename_ptr = emu.regs.rcx;
    let filename = emu.maps.read_wide_string(filename_ptr);

    log::info!(
        "{}** {} kernel32!GetFileAttributesW file: {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );
    emu.regs.rax = 0x123;
}

fn FileTimeToSystemTime(emu: &mut emu::Emu) {
    let file_time = emu.regs.rcx;
    let sys_time_ptr = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!FileTimeToSystemTime {} ",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn FindFirstFileA(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    let file = emu.maps.read_string(file_ptr);
    log::info!(
        "{}** {} kernel32!FindFirstFileA file: {} {}",
        emu.colors.light_red,
        emu.pos,
        file,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn FindFirstFileW(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    let file = emu.maps.read_wide_string(file_ptr);
    log::info!(
        "{}** {} kernel32!FindFirstFileW file: {} {}",
        emu.colors.light_red,
        emu.pos,
        file,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn FindNextFileA(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!FindNextFileA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn FindNextFileW(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!FindNextFileW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn CopyFileA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let do_fail = emu.regs.r8;

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    log::info!(
        "{}** {} kernel32!CopyFileA `{}` to `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        dst,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CopyFileW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let do_fail = emu.regs.r8;

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    log::info!(
        "{}** {} kernel32!CopyFileW `{}` to `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        dst,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FindClose(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!FindClose {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    helper::handler_close(hndl);
    emu.regs.rax = 1;
}

fn MoveFileA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    log::info!(
        "{}** {} kernel32!MoveFileA `{}` to `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        dst,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn MoveFileW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    log::info!(
        "{}** {} kernel32!MoveFileW `{}` to `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        dst,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn MapViewOfFile(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let access = emu.regs.rdx;
    let off_high = emu.regs.r8;
    let off_low = emu.regs.r9;
    let mut size = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!MapViewOfFile cannot read the size");

    let off: u64 = (off_high << 32) + off_low;

    if size > 1024 * 4 {
        size = 1024
    }

    let addr = emu
        .maps
        .alloc(size)
        .expect("kernel32!MapViewOfFile cannot allocate");
    let mem = emu
        .maps
        .create_map("file_map", addr, size)
        .expect("kernel32!MapViewOfFile cannot create map");
    let loaded = mem.load_chunk(&emu.filename, off, size as usize);

    log::info!(
        "{}** {} kernel32!MapViewOfFile hndl: {} off: {} sz: {} ={} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        off,
        size,
        addr,
        emu.colors.nc
    );

    if off > 0 {
        log::info!("the non-zero offset is not implemented for now");
    }

    emu.regs.rax = addr;
}

fn GetTickCount(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetTickCount {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    // TODO: increment the tick?
    emu.regs.rax = emu.tick as u64;
}

fn InitializeCriticalSectionAndSpinCount(emu: &mut emu::Emu) {
    let crit_sect = emu.regs.rcx;
    let spin_count = emu.regs.rdx;

    log::info!("{}** {} kernel32!InitializeCriticalSectionAndSpinCount crit_sect: 0x{:x} spin_count: {} {}", emu.colors.light_red,
        emu.pos, crit_sect, spin_count, emu.colors.nc);

    emu.regs.rax = 1;
}

fn GetProcessAffinityMask(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let proc_affinity_mask_ptr = emu.regs.rdx;
    let sys_affinity_mask_ptr = emu.regs.r8;

    emu.maps.write_dword(proc_affinity_mask_ptr, 0x1337);
    emu.maps.write_dword(sys_affinity_mask_ptr, 0x1337);

    log::info!(
        "{}** {} kernel32!GetProcessAffinityMask {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn IsDebuggerPresent(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!IsDebuggerPresent {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0; // of course :p
}

fn SetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let callback = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!SetUnhandledExceptionFilter  callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        callback,
        emu.colors.nc
    );

    emu.regs.rax = emu.seh;
    emu.seh = callback;
}

fn UnhandledExceptionFilter(emu: &mut emu::Emu) {
    let exception_info = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!UnhandledExceptionFilter  exception_info: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        exception_info,
        emu.colors.nc
    );

    emu.regs.rax = constants::EXCEPTION_EXECUTE_HANDLER; // a debugger would had answered EXCEPTION_CONTINUE_SEARCH
}

fn GetCurrentProcess(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCurrentProcess {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = helper::handler_create("current process");
}

fn VirtualAllocExNuma(emu: &mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let size = emu.regs.r8;
    let alloc_type = emu.regs.r9;
    let protect = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!VirtualAllocExNuma cannot read the protect");
    let nnd = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!VirtualAllocExNuma cannot read the nndPreferred");

    log::info!(
        "{}** {} kernel32!VirtualAllocExNuma hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        proc_hndl,
        addr,
        emu.colors.nc
    );

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAllocExNuma out of memory");
    emu.maps
        .create_map(format!("alloc_{:x}", base).as_str(), base, size)
        .expect("kernel32!VirtualAllocExNuma cannot create map");

    emu.regs.rax = base;
}

fn GetUserDefaultLangId(emu: &mut emu::Emu) {
    emu.regs.rax = 0x000000000000ffff;
    log::info!(
        "{}** {} kernel32!GetUserDefaultLangID =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax as u16,
        emu.colors.nc
    );
}

fn GetComputerNameA(emu: &mut emu::Emu) {
    let buff_ptr = emu.regs.rcx;
    let size_ptr = emu.regs.rdx;

    emu.maps.write_dword(size_ptr, 6);
    emu.maps.write_string(buff_ptr, "medusa");

    log::info!(
        "{}** {} kernel32!GetComputerNameA 'medusa' {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetComputerNameW(emu: &mut emu::Emu) {
    let buff_ptr = emu.regs.rcx;
    let size_ptr = emu.regs.rdx;

    emu.maps.write_dword(size_ptr, 12);
    emu.maps.write_wide_string(buff_ptr, "medusa");

    log::info!(
        "{}** {} kernel32!GetComputerNameW 'medusa' {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CreateMutexA(emu: &mut emu::Emu) {
    let attr = emu.regs.rcx;
    let owner = emu.regs.rdx;
    let name_ptr = emu.regs.r8;

    let name = emu.maps.read_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateMutexA '{}' {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc
    );

    let uri = format!("mutex://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateMutexW(emu: &mut emu::Emu) {
    let attr = emu.regs.rcx;
    let owner = emu.regs.rdx;
    let name_ptr = emu.regs.r8;

    let name = emu.maps.read_wide_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateMutexA '{}' {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc
    );

    let uri = format!("mutex://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetLastError(emu: &mut emu::Emu) {
    let err = LAST_ERROR.lock().unwrap();
    emu.regs.rax = *err;
    log::info!(
        "{}** {} kernel32!GetLastError ={} {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn CreateFileMappingA(emu: &mut emu::Emu) {
    let hFile = emu.regs.rcx;
    let attr = emu.regs.rdx;
    let protect = emu.regs.r8;
    let max_sz_high = emu.regs.r9;
    let max_sz_low = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!CreateFileMappingW cannot read max size low");
    let name_ptr = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateFileMappingW cannot read name pointer");

    let mut name: String = String::new();
    if name_ptr > 0 {
        name = emu.maps.read_string(name_ptr);
    }

    emu.regs.rax = helper::handler_create(&name);
    log::info!(
        "{}** {} kernel32!CreateFileMappingA '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.regs.get_eax(),
        emu.colors.nc
    );
}

fn CreateFileMappingW(emu: &mut emu::Emu) {
    let hFile = emu.regs.rcx;
    let attr = emu.regs.rdx;
    let protect = emu.regs.r8;
    let max_sz_high = emu.regs.r9;
    let max_sz_low = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!CreateFileMappingW cannot read max size low");
    let name_ptr = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateFileMappingW cannot read name pointer");

    let mut name: String = String::new();
    if name_ptr > 0 {
        name = emu.maps.read_wide_string(name_ptr);
    }

    emu.regs.rax = helper::handler_create(&name);
    log::info!(
        "{}** {} kernel32!CreateFileMappingW '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.regs.get_eax(),
        emu.colors.nc
    );
}

fn GetSystemTime(emu: &mut emu::Emu) {
    let out_time = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetSystemTime ptr: 0x{:x}' {}",
        emu.colors.light_red,
        emu.pos,
        out_time,
        emu.colors.nc
    );

    let systime = structures::SystemTime::now();
    systime.save(out_time, &mut emu.maps);
}

fn lstrcatA(emu: &mut emu::Emu) {
    let str1_ptr = emu.regs.rcx;
    let str2_ptr = emu.regs.rdx;

    let mut str1 = emu.maps.read_string(str1_ptr);
    let str2 = emu.maps.read_string(str2_ptr);

    log::info!(
        "{}** {} kernel32!lstrcatA '{}'+'{}' {}",
        emu.colors.light_red,
        emu.pos,
        str1,
        str2,
        emu.colors.nc
    );

    str1.push_str(&str2);
    emu.maps.write_string(str1_ptr, &str1);

    emu.regs.rax = 1;
}

fn lstrcatW(emu: &mut emu::Emu) {
    let str1_ptr = emu.regs.rcx;
    let str2_ptr = emu.regs.rdx;

    let mut str1 = emu.maps.read_wide_string(str1_ptr);
    let str2 = emu.maps.read_wide_string(str2_ptr);

    log::info!(
        "{}** {} kernel32!lstrcatW '{}'+'{}' {}",
        emu.colors.light_red,
        emu.pos,
        str1,
        str2,
        emu.colors.nc
    );

    str1.push_str(&str2);
    emu.maps.write_wide_string(str1_ptr, &str1);

    emu.regs.rax = 1;
}

fn SetErrorMode(emu: &mut emu::Emu) {
    let mode = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!SetErrorMode 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        mode,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn GetSystemDirectoryA(emu: &mut emu::Emu) {
    let out_buff_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;

    emu.maps.write_string(out_buff_ptr, "C:\\Windows\\");

    log::info!(
        "{}** {} kernel32!GetSystemDirectoryW  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 11;
}

fn GetSystemDirectoryW(emu: &mut emu::Emu) {
    let out_buff_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;

    emu.maps.write_wide_string(out_buff_ptr, "C:\\Windows\\");

    log::info!(
        "{}** {} kernel32!GetSystemDirectoryW  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 11 * 2;
}

fn GetStartupInfoA(emu: &mut emu::Emu) {
    let startup_info_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetStartupInfoA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    if startup_info_ptr > 0 {
        let startupinfo = structures::StartupInfo64::new();
        startupinfo.save(startup_info_ptr, &mut emu.maps);
    }
}

fn GetStartupInfoW(emu: &mut emu::Emu) {
    let startup_info_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetStartupInfoW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    if startup_info_ptr > 0 {
        let startupinfo = structures::StartupInfo64::new();
        startupinfo.save(startup_info_ptr, &mut emu.maps);
    }
}

fn FlsGetValue(emu: &mut emu::Emu) {
    let idx = emu.regs.rcx;
    if idx as usize > emu.fls.len() {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = emu.fls[idx as usize] as u64;
    }

    log::info!(
        "{}** {} kernel32!FlsGetValue idx: {} =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        emu.regs.get_eax() as u32,
        emu.colors.nc
    );
}

fn IsProcessorFeaturePresent(emu: &mut emu::Emu) {
    let feature = emu.regs.rcx as u32;

    let msg = match feature {
        constants::PF_ARM_64BIT_LOADSTORE_ATOMIC => "PF_ARM_64BIT_LOADSTORE_ATOMIC",
        constants::PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE => "PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE",
        constants::PF_ARM_EXTERNAL_CACHE_AVAILABLE => "PF_ARM_EXTERNAL_CACHE_AVAILABLE",
        constants::PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE => "PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE",
        constants::PF_ARM_VFP_32_REGISTERS_AVAILABLE => "PF_ARM_VFP_32_REGISTERS_AVAILABLE",
        constants::PF_3DNOW_INSTRUCTIONS_AVAILABLE => "PF_3DNOW_INSTRUCTIONS_AVAILABLE",
        constants::PF_CHANNELS_ENABLED => "PF_CHANNELS_ENABLED",
        constants::PF_COMPARE_EXCHANGE_DOUBLE => "PF_COMPARE_EXCHANGE_DOUBLE",
        constants::PF_COMPARE_EXCHANGE128 => "PF_COMPARE_EXCHANGE128",
        constants::PF_COMPARE64_EXCHANGE128 => "PF_COMPARE64_EXCHANGE128",
        constants::PF_FASTFAIL_AVAILABLE => "PF_FASTFAIL_AVAILABLE",
        constants::PF_FLOATING_POINT_EMULATED => "PF_FLOATING_POINT_EMULATED",
        constants::PF_FLOATING_POINT_PRECISION_ERRATA => "PF_FLOATING_POINT_PRECISION_ERRATA",
        constants::PF_MMX_INSTRUCTIONS_AVAILABLE => "PF_MMX_INSTRUCTIONS_AVAILABLE",
        constants::PF_NX_ENABLED => "PF_NX_ENABLED",
        constants::PF_PAE_ENABLED => "PF_PAE_ENABLED",
        constants::PF_RDTSC_INSTRUCTION_AVAILABLE => "PF_RDTSC_INSTRUCTION_AVAILABLE",
        constants::PF_RDWRFSGSBASE_AVAILABLE => "PF_RDWRFSGSBASE_AVAILABLE",
        constants::PF_SECOND_LEVEL_ADDRESS_TRANSLATION => "PF_SECOND_LEVEL_ADDRESS_TRANSLATION",
        constants::PF_SSE3_INSTRUCTIONS_AVAILABLE => "PF_SSE3_INSTRUCTIONS_AVAILABLE",
        constants::PF_SSSE3_INSTRUCTIONS_AVAILABLE => "PF_SSSE3_INSTRUCTIONS_AVAILABLE",
        constants::PF_SSE4_1_INSTRUCTIONS_AVAILABLE => "PF_SSE4_1_INSTRUCTIONS_AVAILABLE",
        constants::PF_SSE4_2_INSTRUCTIONS_AVAILABLE => "PF_SSE4_2_INSTRUCTIONS_AVAILABLE",
        constants::PF_AVX_INSTRUCTIONS_AVAILABLE => "PF_AVX_INSTRUCTIONS_AVAILABLE",
        constants::PF_AVX2_INSTRUCTIONS_AVAILABLE => "PF_AVX2_INSTRUCTIONS_AVAILABLE",
        constants::PF_AVX512F_INSTRUCTIONS_AVAILABLE => "PF_AVX512F_INSTRUCTIONS_AVAILABLE",
        constants::PF_VIRT_FIRMWARE_ENABLED => "PF_VIRT_FIRMWARE_ENABLED",
        constants::PF_XMMI_INSTRUCTIONS_AVAILABLE => "PF_XMMI_INSTRUCTIONS_AVAILABLE",
        constants::PF_XMMI64_INSTRUCTIONS_AVAILABLE => "PF_XMMI64_INSTRUCTIONS_AVAILABLE",
        constants::PF_XSAVE_ENABLED => "PF_XSAVE_ENABLED",
        constants::PF_ARM_V8_INSTRUCTIONS_AVAILABLE => "PF_ARM_V8_INSTRUCTIONS_AVAILABLE",
        constants::PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE => {
            "PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE"
        }
        constants::PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE => {
            "PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE"
        }
        constants::PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE => {
            "PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE"
        }
        _ => "unknown feature",
    };

    log::info!(
        "{}** {} kernel32!IsProcessorFeaturePresent feature: {} {} {}",
        emu.colors.light_red,
        emu.pos,
        feature,
        msg,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn InitializeCriticalSection(emu: &mut emu::Emu) {
    let ptr_crit_sect = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!InitializeCriticalSection ptr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        ptr_crit_sect,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn InitializeCriticalSectionEx(emu: &mut emu::Emu) {
    let ptr_crit_sect = emu.regs.rcx;
    let spin_count = emu.regs.rdx;
    let flags = emu.regs.r9;

    log::info!(
        "{}** {} kernel32!InitializeCriticalSectionEx ptr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        ptr_crit_sect,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FlsAlloc(emu: &mut emu::Emu) {
    let callback = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!FlsAlloc callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        callback,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FlsSetValue(emu: &mut emu::Emu) {
    let idx = emu.regs.rcx;
    let val = emu.regs.rdx as u32;

    log::info!(
        "{}** {} kernel32!FlsSetValue idx: {} val: {} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        val,
        emu.colors.nc
    );

    if emu.fls.len() > idx as usize {
        emu.fls[idx as usize] = val;
    } else {
        for _ in 0..=idx {
            emu.fls.push(0);
        }
        emu.fls[idx as usize] = val;
    }

    emu.regs.rax = 1;
}

fn SetLastError(emu: &mut emu::Emu) {
    let err_code = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!SetLastError err: {} {}",
        emu.colors.light_red,
        emu.pos,
        err_code,
        emu.colors.nc
    );
    let mut err = LAST_ERROR.lock().unwrap();
    *err = err_code;
}

fn lstrlenA(emu: &mut emu::Emu) {
    let s_ptr = emu.regs.rcx;

    let s = emu.maps.read_string(s_ptr);
    let len = s.len() as u64;

    log::info!(
        "{}** {} kernel32!lstrlen '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        len,
        emu.colors.nc
    );

    emu.regs.rax = len;
}

fn lstrlenW(emu: &mut emu::Emu) {
    let s_ptr = emu.regs.rcx;

    let s = emu.maps.read_wide_string(s_ptr);
    let len = s.len() as u64;

    log::info!(
        "{}** {} kernel32!lstrlen '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        len,
        emu.colors.nc
    );

    emu.regs.rax = len * 2;
}

fn MultiByteToWideChar(emu: &mut emu::Emu) {
    let codepage = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let utf8_ptr = emu.regs.r8;
    let cb_multi_byte = emu.regs.r9;
    let wide_ptr = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!MultiByteToWideChar cannot read wide_ptr");
    let cc_wide_char = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!MultiByteToWideChar cannot read cchWideChar");

    let utf8 = emu.maps.read_string(utf8_ptr);
    let mut wide = String::new();
    for c in utf8.chars() {
        wide.push_str(&format!("{}", c));
        wide.push('\x00');
    }

    log::info!(
        "{}** {} kernel32!MultiByteToWideChar '{}' {}",
        emu.colors.light_red,
        emu.pos,
        utf8,
        emu.colors.nc
    );

    emu.maps.write_string(wide_ptr, &wide);
    emu.regs.rax = wide.len() as u64;
}

fn GetSystemInfo(emu: &mut emu::Emu) {
    let out_sysinfo = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!GetSystemInfo sysinfo: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        out_sysinfo,
        emu.colors.nc
    );

    let mut sysinfo = structures::SystemInfo64::new();
    sysinfo.save(out_sysinfo, &mut emu.maps);
}

fn HeapFree(emu: &mut emu::Emu) {
    let heap = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let mem = emu.regs.r8;

    log::info!(
        "{}** {} kernel32!HeapFree mem: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        mem,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn EncodePointer(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!EncodePointer ptr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        ptr,
        emu.colors.nc
    );

    emu.regs.rax = ptr;
}

fn DecodePointer(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!DecodePointer ptr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        ptr,
        emu.colors.nc
    );

    emu.regs.rax = ptr;
}

fn HeapCreate(emu: &mut emu::Emu) {
    let opts = emu.regs.rcx;
    let initSZ = emu.regs.rdx;
    let maxSZ = emu.regs.r8;

    log::info!(
        "{}** {} kernel32!HeapCreate maxSZ:{} {}",
        emu.colors.light_red,
        emu.pos,
        maxSZ,
        emu.colors.nc
    );

    let uri = format!("HeapCreate://{}", maxSZ);
    emu.regs.rax = helper::handler_create(&uri);
}

fn lstrcpyn(emu: &mut emu::Emu) {
    let out_str1 = emu.regs.rcx;
    let in_str2 = emu.regs.rdx;
    let len = emu.regs.r8 as usize;

    let mut s = emu.maps.read_string(in_str2);
    if s.len() - 1 > len {
        s = s.chars().take(len).collect();
    }
    emu.maps.memset(out_str1, 0, len);
    emu.maps.write_string(out_str1, &s);

    log::info!(
        "{}** {} kernel32!lstrcpyn {} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        emu.colors.nc
    );

    emu.regs.rax = out_str1;
}

fn GetModuleFileNameA(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let out_filename = emu.regs.rdx;
    let sz = emu.regs.r8;

    if sz >= 11 {
        emu.maps.write_string(out_filename, "jowei3r.exe");
        emu.regs.rax = 11;
    } else {
        emu.regs.rax = 0;
    }

    log::info!(
        "{}** {} kernel32!GetModuleFileNameA hndl:{:x} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        emu.colors.nc
    );
}

fn GetLocalTime(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("error getting the localtime");

    let seconds = duration.as_secs();
    let seconds_since_midnight = seconds % 86400;
    let hours = seconds_since_midnight / 3600;
    let minutes = (seconds_since_midnight % 3600) / 60;
    let seconds = seconds_since_midnight % 60;

    let mut buffer = [0u8; 8];
    buffer[0] = hours as u8;
    buffer[1] = minutes as u8;
    buffer[2] = seconds as u8;

    emu.maps.write_bytes_slice(ptr, &buffer);

    log::info!(
        "{}** {} kernel32!GetLocalTime  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
}

fn SystemTimeToFileTime(emu: &mut emu::Emu) {
    let in_ptr = emu.regs.rcx;
    let out_ptr = emu.regs.rdx;

    let now = structures::SystemTime::now();
    now.save(out_ptr, &mut emu.maps);

    log::info!(
        "{}** {} kernel32!SystemTimeToFileTime  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
}

fn GetNativeSystemInfo(emu: &mut emu::Emu) {
    let ptr_sysinfo = emu.regs.rcx;

    let mut sysinfo = structures::SystemInfo32::new();
    sysinfo.save(ptr_sysinfo, &mut emu.maps);

    log::info!(
        "{}** {} kernel32!GetNativeSysteminfo 0x{:x}  {}",
        emu.colors.light_red,
        emu.pos,
        ptr_sysinfo,
        emu.colors.nc
    );
}

fn lstrcpyW(emu: &mut emu::Emu) {
    let dst = emu.regs.rcx;
    let src = emu.regs.rdx;

    let s = emu.maps.read_wide_string(src);
    emu.maps.write_wide_string(dst, &s);
    emu.maps.write_byte(dst + (s.len() as u64 * 2), 0);

    log::info!(
        "{}** {} kernel32!lstrcpyW 0x{:x} 0x{:x} {}  {}",
        emu.colors.light_red,
        emu.pos,
        dst,
        src,
        &s,
        emu.colors.nc
    );

    if s.is_empty() {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = dst;
    }
}

fn lstrcpy(emu: &mut emu::Emu) {
    let dst = emu.regs.rcx;
    let src = emu.regs.rdx;

    let s = emu.maps.read_string(src);
    emu.maps.write_string(dst, &s);
    emu.maps.write_byte(dst + (s.len() as u64), 0);

    log::info!(
        "{}** {} kernel32!lstrcpy 0x{:x} 0x{:x} {}  {}",
        emu.colors.light_red,
        emu.pos,
        dst,
        src,
        &s,
        emu.colors.nc
    );

    if s.is_empty() {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = dst;
    }
}

pub fn FindActCtxSectionStringW(emu: &mut emu::Emu) {
    let actctx = emu.regs.rcx;
    let section_name = emu.maps.read_wide_string(emu.regs.rdx);
    let string_name = emu.maps.read_wide_string(emu.regs.r8);
    let string_value = emu.maps.read_wide_string(emu.regs.r9);

    log::info!(
        "{}** {} kernel32!FindActCtxSectionStringW section_name: {} string_name: {} string_value: {} {}",
        emu.colors.light_red, emu.pos, section_name, string_name, string_value, emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn GetModuleHandleA(emu: &mut emu::Emu) {
    let module_name_ptr = emu.regs.rcx;
    let module_name: String;

    if module_name_ptr == 0 {
        module_name = "self".to_string();
        emu.regs.rax = match emu.maps.get_base() {
            Some(base) => base,
            None => helper::handler_create(&module_name),
        }

    } else {
        module_name = emu.maps.read_string(module_name_ptr).to_lowercase();
        let mod_mem = match emu.maps.get_mem2(&module_name) {
            Some(m) => m,
            None => {
                emu.regs.rax = 0;
                return;
            }
        };

        emu.regs.rax = mod_mem.get_base();
    }

    log::info!(
        "{}** {} kernel32!GetModuleHandleA `{}`  {}",
        emu.colors.light_red,
        emu.pos,
        module_name,
        emu.colors.nc
    );

}

fn GetModuleHandleW(emu: &mut emu::Emu) {
    let module_name_ptr = emu.regs.rcx;
    let module_name: String;

    if module_name_ptr == 0 {
        module_name = "self".to_string();
        emu.regs.rax = match emu.maps.get_base() {
            Some(base) => base,
            None => helper::handler_create(&module_name),
        }

    } else {
        module_name = emu.maps.read_wide_string(module_name_ptr).to_lowercase();
        let mod_mem = match emu.maps.get_mem2(&module_name) {
            Some(m) => m,
            None => {
                emu.regs.rax = 0;
                return;
            }
        };

        emu.regs.rax = mod_mem.get_base();
    }

    log::info!(
        "{}** {} kernel32!GetModuleHandleW `{}`  {}",
        emu.colors.light_red,
        emu.pos,
        module_name,
        emu.colors.nc
    );
}

/*
DWORD TlsAlloc();
*/
fn TlsAlloc(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!TlsAlloc {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.tls64.push(0);
    emu.regs.rax = (emu.tls64.len() - 1) as u64;  // Return index of newly allocated slot
}

/* 
BOOL TlsFree(
  [in] DWORD dwTlsIndex
);
*/
fn TlsFree(emu: &mut emu::Emu) {
    let idx = emu.regs.rcx as usize;  // First parameter passed in RCX in x64

    log::info!(
        "{}** {} kernel32!TlsFree idx: {} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        emu.colors.nc
    );

    if idx < emu.tls64.len() {
        emu.tls64[idx] = 0;  // Clear the slot
        emu.regs.rax = 1;    // Return TRUE
    } else {
        emu.regs.rax = 0;    // Return FALSE if invalid index
    }
}

/*
BOOL TlsSetValue(
  [in]           DWORD  dwTlsIndex,
  [in, optional] LPVOID lpTlsValue
);
*/
fn TlsSetValue(emu: &mut emu::Emu) {
    let idx = emu.regs.rcx as usize;     // First parameter in RCX
    let val = emu.regs.rdx;              // Second parameter in RDX

    log::info!(
        "{}** {} kernel32!TlsSetValue idx: {} val: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        val,
        emu.colors.nc
    );

    if idx < emu.tls64.len() {
        emu.tls64[idx] = val;
    } else {
        // Expand TLS array if needed
        while emu.tls64.len() <= idx {
            emu.tls64.push(0);
        }
        emu.tls64[idx] = val;
    }

    emu.regs.rax = 1;  // Return TRUE
}

/*
DWORD TlsGetValue(
  [in] DWORD dwTlsIndex
);
*/
fn TlsGetValue(emu: &mut emu::Emu) {
    let idx = emu.regs.rcx as usize;  // Parameter passed in RCX in x64

    let val = if idx < emu.tls64.len() {
        emu.tls64[idx]
    } else {
        0
    };

    emu.regs.rax = val;

    log_red!(emu, "** {} kernel32!TlsGetValue idx: {} =0x{:x}", 
        emu.pos,
        idx,
        val
    );
}

/*
UINT GetACP();
*/
// TODO: there is GetAcp and GetACP?
fn GetACP(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetACP {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x00000409;
}

/*
HANDLE GetStdHandle(
  [in] DWORD nStdHandle
);
*/
fn GetStdHandle(emu: &mut emu::Emu) {
    let nstd = emu.regs.rcx as usize;  // Parameter passed in RCX in x64    
    log_red!(emu, "** {} kernel32!GetStdHandle nstd: {}", 
        emu.pos,
        nstd
    );
    emu.regs.rax = nstd as u64;
}

fn GetConsoleCP(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetConsoleCP {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x00000409;
}

fn GetConsoleOutputCP(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetConsoleOutputCP {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x00000409;
}

fn GetCommandLineA(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCommandLineA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let addr = emu.maps.alloc(1024).expect("out of memory");
    let name = format!("alloc_{:x}", addr);
    emu.maps.create_map(&name, addr, 1024);
    emu.maps.write_string(addr, "test.exe");
    emu.regs.rax = addr;
}

fn GetCommandLineW(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCommandLineW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let addr = emu.maps.alloc(1024).expect("out of memory");
    let name = format!("alloc_{:x}", addr);
    emu.maps.create_map(&name, addr, 1024);
    emu.maps.write_wide_string(addr, "test.exe");
    emu.regs.rax = addr;
}

/*
BOOL GetCPInfo(
  [in]  UINT     CodePage,
  [out] LPCPINFO lpCPInfo
);
*/
fn GetCPInfo(emu: &mut emu::Emu) {
    let code_page = emu.regs.rcx as usize;
    let lp_cp_info = emu.regs.rdx;

    log::info!(
        "{}** {} kernel32!GetCPInfo code_page: {} lp_cp_info: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        code_page,
        lp_cp_info,
        emu.colors.nc
    );

    // Create and initialize a CpInfo structure
    let cp_info = match code_page {
        // CP_ACP (0) - ANSI code page
        0 => structures::CpInfo {
            max_char_size: 2,
            default_char: [0x3F, 0], // '?'
            lead_byte: [0; 12],
        },
        // CP_OEMCP (1) - OEM code page
        1 => structures::CpInfo {
            max_char_size: 1,
            default_char: [0x3F, 0], // '?'
            lead_byte: [0; 12],
        },
        // For other code pages, use default values
        _ => structures::CpInfo::new(),
    };

    // Save the CpInfo structure to the provided memory location
    cp_info.save(lp_cp_info, &mut emu.maps);

    // Return TRUE to indicate success
    emu.regs.rax = 1;
}

/*
DWORD GetUserDefaultLCID();
*/
fn GetUserDefaultLCID(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetUserDefaultLCID {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x00000400;
}

/*
BOOL SetThreadLocale(
  [in] LCID Locale
);
*/
fn SetThreadLocale(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!SetThreadLocale {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    // TODO: do something
    emu.regs.rax = 1;
}

/*
DWORD GetThreadLocale();
*/
fn GetThreadLocale(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetThreadLocale {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x409;
}

/*
int GetLocaleInfoW(
  [in]            LCID   Locale,
  [in]            LCTYPE LCType,
  [out, optional] LPWSTR lpLCData,
  [in]            int    cchData
);
*/
fn GetLocaleInfoW(emu: &mut emu::Emu) {
    let locale = emu.regs.rcx as usize;         
    let lctype = emu.regs.rdx as usize;
    let lp_lc_data = emu.regs.r8 as usize;
    let cch_data = emu.regs.r9 as usize;
    log_red!(emu, "** {} kernel32!GetLocaleInfoW locale: {} lctype: {} lp_lc_data: 0x{:x} cch_data: {}", 
        emu.pos,
        locale,
        lctype,
        lp_lc_data,
        cch_data
    );
    // TODO: set lp_lc_data
    emu.regs.rax = 1;
}

/*
int WideCharToMultiByte(
  [in]            UINT                               CodePage, rcx
  [in]            DWORD                              dwFlags, rdx
  [in]            _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, r8
  [in]            int                                cchWideChar, r9

  [out, optional] LPSTR                              lpMultiByteStr, rsp
  [in]            int                                cbMultiByte, rsp+8
  [in, optional]  LPCCH                              lpDefaultChar, rsp+16
  [out, optional] LPBOOL                             lpUsedDefaultChar, rsp+24
);
*/
fn WideCharToMultiByte(emu: &mut emu::Emu) {
    let code_page = emu.regs.rcx as usize;
    let dw_flags = emu.regs.rdx as usize;
    let lp_wide_char_str = emu.regs.r8 as usize;
    let cch_wide_char = emu.regs.r9 as usize;
    let lp_multi_byte_str = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let cb_multi_byte = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let lp_default_char = emu
        .maps
        .read_qword(emu.regs.rsp + 16)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let lp_used_default_char = emu
        .maps
        .read_qword(emu.regs.rsp + 24)
        .expect("kernel32!WideCharToMultiByte error reading param");
    log_red!(emu, "** {} kernel32!WideCharToMultiByte code_page: {} dw_flags: {} lp_wide_char_str: 0x{:x} cch_wide_char: {} lp_multi_byte_str: 0x{:x} cb_multi_byte: {} lp_default_char: 0x{:x} lp_used_default_char: 0x{:x}", 
        emu.pos,
        code_page,
        dw_flags,
        lp_wide_char_str,
        cch_wide_char,
        lp_multi_byte_str,
        cb_multi_byte,
        lp_default_char,
        lp_used_default_char
    );
    let s = emu.maps.read_wide_string(lp_wide_char_str as u64);
    if lp_multi_byte_str > 0 {
        emu.maps.write_string(lp_multi_byte_str, &s);
    }
    for _ in 0..4 {
        emu.stack_pop64(false);
    }
    emu.regs.rax = s.len() as u64 + 2;
}

/*
int GetLocaleInfoA(
  [in]            LCID   Locale,
  [in]            LCTYPE LCType,
  [out, optional] LPSTR  lpLCData,
  [in]            int    cchData
);
*/
fn GetLocaleInfoA(emu: &mut emu::Emu) {
    let locale = emu.regs.rcx as usize;     
    let lctype = emu.regs.rdx as usize;
    let lp_lc_data = emu.regs.r8 as usize;
    let cch_data = emu.regs.r9 as usize;
    log_red!(emu, "** {} kernel32!GetLocaleInfoA locale: {} lctype: {} lp_lc_data: 0x{:x} cch_data: {}", 
        emu.pos,
        locale,
        lctype,
        lp_lc_data,
        cch_data
    );
    // TODO: set lp_lc_data
    emu.regs.rax = 1;
}

/*
UINT GetWindowsDirectoryA(
  [out] LPSTR lpBuffer,
  [in]  UINT  uSize
);
*/
fn GetWindowsDirectoryA(emu: &mut emu::Emu) {
    let lp_buffer = emu.regs.rcx as usize;
    let u_size = emu.regs.rdx as usize;
    log_red!(emu, "** {} kernel32!GetWindowsDirectoryA lp_buffer: 0x{:x} u_size: {}", 
        emu.pos,
        lp_buffer,
        u_size
    );
    let output = "C:\\Windows\\";
    emu.maps.write_string(lp_buffer as u64, output);
    emu.regs.rax = output.len() as u64;
}

/*
BOOL ResetEvent(
  [in] HANDLE hEvent
);
*/
fn ResetEvent(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!ResetEvent {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    // TODO: do something
    emu.regs.rax = 1;
}

/*
BOOL VirtualFree(
  [in] LPVOID lpAddress,
  [in] SIZE_T dwSize,
  [in] DWORD  dwFreeType
);
*/
fn VirtualFree(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!VirtualFree {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    // TODO: do something
    emu.regs.rax = 1;
}

/*
DWORD GetModuleFileNameW(
  [in, optional] HMODULE hModule,
  [out]          LPWSTR  lpFilename,
  [in]           DWORD   nSize
);
*/
fn GetModuleFileNameW(emu: &mut emu::Emu) {
    let module = emu.regs.rcx as usize;
    let lp_filename = emu.regs.rdx as usize;
    let n_size = emu.regs.r8 as usize;
    log_red!(emu, "** {} kernel32!GetModuleFileNameW module: 0x{:x} lp_filename: 0x{:x} n_size: {}", 
        emu.pos,
        module,
        lp_filename,
        n_size
    );
    let output = "haspmeul.dll";
    emu.maps.write_wide_string(lp_filename as u64, output);
    emu.regs.rax = output.len() as u64;
}

fn EnterCriticalSection(emu: &mut emu::Emu) {
    let crit_sect = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!EnterCriticalSection 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        crit_sect,
        emu.colors.nc
    );

    emu.regs.rax = crit_sect;
}

fn LeaveCriticalSection(emu: &mut emu::Emu) {
    let crit_sect = emu.regs.rcx;

    log::info!(
        "{}** {} kernel32!LeaveCriticalSection 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        crit_sect,
        emu.colors.nc
    );

    emu.regs.rax = crit_sect;
}
