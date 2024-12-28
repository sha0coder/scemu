use crate::emu;
use crate::emu::console;
use crate::emu::constants;
use crate::emu::context32;
use crate::emu::peb32;
use crate::emu::structures;
use crate::emu::winapi32::helper;

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

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = guess_api_name(emu, addr);
    match api.as_str() {
        "LoadLibraryA" => LoadLibraryA(emu),
        "LoadLibraryExA" => LoadLibraryExA(emu),
        "LoadLibraryExW" => LoadLibraryExW(emu),
        "GetProcAddress" => GetProcAddress(emu),
        "LoadLibraryW" => LoadLibraryW(emu),
        "WinExec" => WinExec(emu),
        "GetVersion" => GetVersion(emu),
        "CreateProcessA" => CreateProcessA(emu),
        "WaitForSingleObject" => WaitForSingleObject(emu),
        "VirtualAlloc" => VirtualAlloc(emu),
        "VirtualAllocEx" => VirtualAllocEx(emu),
        "WriteProcessMemory" => WriteProcessMemory(emu),
        "CreateRemoteThread" => CreateRemoteThread(emu),
        "CreateNamedPipeA" => CreateNamedPipeA(emu),
        "ConnectNamedPipe" => ConnectNamedPipe(emu),
        "DisconnectNamedPipe" => DisconnectNamedPipe(emu),
        "ReadFile" => ReadFile(emu),
        "WriteFile" => WriteFile(emu),
        "CreateFileW" => CreateFileW(emu),
        "CloseHandle" => CloseHandle(emu),
        "ExitProcess" => ExitProcess(emu),
        "TerminateProcess" => TerminateProcess(emu),
        "GetThreadContext" => GetThreadContext(emu),
        "ReadProcessMemory" => ReadProcessMemory(emu),
        "GetCurrentDirectoryW" => GetCurrentDirectoryW(emu),
        "GetCurrentDirectoryA" => GetCurrentDirectoryA(emu),
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
        "FindNextFileA" => FindNextFileA(emu),
        "FindFirstFileW" => FindFirstFileW(emu),
        "FindNextFileW" => FindNextFileW(emu),
        "CopyFileA" => CopyFileA(emu),
        "CopyFileW" => CopyFileW(emu),
        "FindClose" => FindClose(emu),
        "MoveFileA" => MoveFileA(emu),
        "MoveFileW" => MoveFileW(emu),
        "OpenProcess" => OpenProcess(emu),
        "GetCurrentProcessId" => GetCurrentProcessId(emu),
        "Thread32First" => Thread32First(emu),
        "Thread32Next" => Thread32Next(emu),
        "OpenThread" => OpenThread(emu),
        "CreateToolhelp32Snapshot" => CreateToolhelp32Snapshot(emu),
        "CreateThread" => CreateThread(emu),
        "SetThreadContext" => SetThreadContext(emu),
        "MapViewOfFile" => MapViewOfFile(emu),
        "GetSystemTimeAsFileTime" => GetSystemTimeAsFileTime(emu),
        "GetCurrentThreadId" => GetCurrentThreadId(emu),
        "GetTickCount" => GetTickCount(emu),
        "QueryPerformanceCounter" => QueryPerformanceCounter(emu),
        "HeapCreate" => HeapCreate(emu),
        "HeapDestroy" => HeapDestroy(emu),
        "GetModuleHandleA" => GetModuleHandleA(emu),
        "GetModuleHandleW" => GetModuleHandleW(emu),
        "TlsAlloc" => TlsAlloc(emu),
        "TlsSetValue" => TlsSetValue(emu),
        "TlsGetValue" => TlsGetValue(emu),
        "TlsFree" => TlsFree(emu),
        "EncodePointer" => EncodePointer(emu),
        "DecodePointer" => DecodePointer(emu),
        "Sleep" => Sleep(emu),
        "InitializeCriticalSectionAndSpinCount" => InitializeCriticalSectionAndSpinCount(emu),
        "HeapAlloc" => HeapAlloc(emu),
        "GetProcessAffinityMask" => GetProcessAffinityMask(emu),
        "IsDebuggerPresent" => IsDebuggerPresent(emu),
        "SetUnhandledExceptionFilter" => SetUnhandledExceptionFilter(emu),
        "UnhandledExceptionFilter" => UnhandledExceptionFilter(emu),
        "GetCurrentProcess" => GetCurrentProcess(emu),
        "LocalAlloc" => LocalAlloc(emu),
        "VirtualAllocExNuma" => VirtualAllocExNuma(emu),
        "GetUserDefaultLangID" => GetUserDefaultLangID(emu),
        "GetProcessHeap" => GetProcessHeap(emu),
        "GetComputerNameA" => GetComputerNameA(emu),
        "CreateMutexA" => CreateMutexA(emu),
        "GetLastError" => GetLastError(emu),
        "CreateFileMappingA" => CreateFileMappingA(emu),
        "CreateFileMappingW" => CreateFileMappingW(emu),
        "GetSystemTime" => GetSystemTime(emu),
        "lstrcat" => lstrcat(emu),
        "SetErrorMode" => SetErrorMode(emu),
        "GetVersionExW" => GetVersionExW(emu),
        "GetSystemDirectoryA" => GetSystemDirectoryA(emu),
        "GetSystemDirectoryW" => GetSystemDirectoryW(emu),
        "GetStartupInfoA" => GetStartupInfoA(emu),
        "GetStartupInfoW" => GetStartupInfoW(emu),
        "FlsGetValue" => FlsGetValue(emu),
        "IsProcessorFeaturePresent" => IsProcessorFeaturePresent(emu),
        "InitializeCriticalSection" => InitializeCriticalSection(emu),
        "InitializeCriticalSectionEx" => InitializeCriticalSectionEx(emu),
        "FlsAlloc" => FlsAlloc(emu),
        "FlsSetValue" => FlsSetValue(emu),
        "SetLastError" => SetLastError(emu),
        "lstrlen" => lstrlen(emu),
        "MultiByteToWideChar" => MultiByteToWideChar(emu),
        "GetSystemInfo" => GetSystemInfo(emu),
        "HeapFree" => HeapFree(emu),
        "SetThreadLocale" => SetThreadLocale(emu),
        "GetCommandLineA" => GetCommandLineA(emu),
        "GetCommandLineW" => GetCommandLineW(emu),
        "GetAcp" => GetAcp(emu),
        "GetModuleFileNameW" => GetModuleFileNameW(emu),
        "RegOpenKeyExW" => RegOpenKeyExW(emu),
        "GetUserDefaultUILanguage" => GetUserDefaultUILanguage(emu),
        "EnterCriticalSection" => EnterCriticalSection(emu),
        "LeaveCriticalSection" => LeaveCriticalSection(emu),
        "IsValidLocale" => IsValidLocale(emu),
        "GetThreadUILanguage" => GetThreadUILanguage(emu),
        "GetThreadPreferredUILanguages" => GetThreadPreferredUILanguages(emu),
        "lstrcmp" => lstrcmpA(emu),
        "lstrcmpA" => lstrcmpA(emu),
        "lstrcmpW" => lstrcmpW(emu),
        "GetNativeSystemInfo" => GetNativeSystemInfo(emu),
        "GetTempPathW" => GetTempPathW(emu),
        "FileTimeToLocalFileTime" => FileTimeToLocalFileTime(emu),
        "FileTimeToDosDateTime" => FileTimeToDosDateTime(emu),
        "CreateMutexW" => CreateMutexW(emu),
        "VirtualQuery" => VirtualQuery(emu),
        "VirtualFree" => VirtualFree(emu),
        "RaiseException" => RaiseException(emu),
        "VerifyVersionInfoW" => VerifyVersionInfoW(emu),
        "GetTimeZoneInformation" => GetTimeZoneInformation(emu),
        "VirtualQueryEx" => VirtualQueryEx(emu),
        "InterlockedIncrement" => InterlockedIncrement(emu),
        "GetEnvironmentStrings" => GetEnvironmentStrings(emu),
        "GetEnvironmentStringsW" => GetEnvironmentStringsW(emu),
        "GetStdHandle" => GetStdHandle(emu),
        "GetFileType" => GetFileType(emu),
        "SetHandleCount" => SetHandleCount(emu),
        "IsValidCodePage" => IsValidCodePage(emu),
        "GetCPInfo" => GetCPInfo(emu),
        "GetStringTypeW" => GetStringTypeW(emu),
        "LCMapStringW" => LCMapStringW(emu),
        "WideCharToMultiByte" => WideCharToMultiByte(emu),
        "CryptCreateHash" => CryptCreateHash(emu),
        "HeapSetInformation" => HeapSetInformation(emu),
        "OpenProcessToken" => OpenProcessToken(emu),
        "CreateEventA" => CreateEventA(emu),
        "AddVectoredExceptionHandler" => AddVectoredExceptionHandler(emu),
        "GetLongPathNameW" => GetLongPathNameW(emu),
        "FreeLibrary" => FreeLibrary(emu),
        "AreFileApisANSI" => AreFileApisANSI(emu),
        "GetModuleFileNameA" => GetModuleFileNameA(emu),
        "lstrcpy" => lstrcpy(emu),
        "GetACP" => GetACP(emu),
        "GetOEMCP" => GetOEMCP(emu),
        "GetWindowsDirectoryA" => GetWindowsDirectoryA(emu),
        "GetWindowsDirectoryW" => GetWindowsDirectoryW(emu),
        "GetSystemWindowsDirectoryA" => GetSystemWindowsDirectoryA(emu),
        "GetSystemWindowsDirectoryW" => GetSystemWindowsDirectoryW(emu),
        "RegCreateKeyExA" => RegCreateKeyExA(emu),
        "RegCreateKeyExW" => RegCreateKeyExW(emu),
        "RegSetValueExA" => RegSetValueExA(emu),
        "RegSetValueExW" => RegSetValueExW(emu),
        "RegCloseKey" => RegCloseKey(emu),
        "RegOpenKeyA" => RegOpenKeyA(emu),
        "RegOpenKeyW" => RegOpenKeyW(emu),
        _ => {
            unimplemented!("calling unimplemented kernel32 API 0x{:x} {}", addr, api);
        }
    }

    String::new()
}

lazy_static! {
    static ref COUNT_READ: Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE: Mutex<u32> = Mutex::new(0);
    pub static ref TICK: Mutex<u32> = Mutex::new(0);
    static ref LAST_ERROR: Mutex<u32> = Mutex::new(0);
}

/// kernel32 API ////

pub fn dump_module_iat(emu: &mut emu::Emu, module: &str) {
    let mut flink = peb32::Flink::new(emu);
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
    let mut flink = peb32::Flink::new(emu);
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
                    let apiname = ordinal.func_name.to_string();
                    return apiname;
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
    let mut flink = peb32::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                if ordinal.func_name == name {
                    //if ordinal.func_name.contains(name) {
                    return ordinal.func_va;
                }
            }
        }
        flink.next(emu);

        //log::info!("flink: 0x{:x} first_ptr: 0x{:x} num_of_funcs: {}", flink.get_ptr(), first_ptr, flink.num_of_funcs);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    0 //TODO: use Option<>
}

pub fn search_api_name(emu: &mut emu::Emu, name: &str) -> (u64, String, String) {
    let mut flink = peb32::Flink::new(emu);
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

pub fn guess_api_name(emu: &mut emu::Emu, addr: u32) -> String {
    let mut flink = peb32::Flink::new(emu);
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

                if ordinal.func_va == addr.into() {
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

fn GetProcAddress(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetProcAddress cannot read the handle") as u64;
    let func_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetProcAddress cannot read the func name") as u64;
    let func = emu.maps.read_string(func_ptr).to_lowercase();

    //log::info!("looking for '{}'", func);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    //peb32::show_linked_modules(emu);

    let mut flink = peb32::Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }
                let ordinal = flink.get_function_ordinal(emu, i);

                //log::info!("func name {}!{}", flink.mod_name, ordinal.func_name);

                if ordinal.func_name.to_lowercase() == func {
                    emu.regs.rax = ordinal.func_va;
                    log::info!(
                        "{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}",
                        emu.colors.light_red,
                        emu.pos,
                        flink.mod_name,
                        ordinal.func_name,
                        emu.regs.get_eax() as u32,
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
    if emu.cfg.verbose >= 1 {
        log::info!("kernel32!GetProcAddress error searching {}", func);
    }
}

pub fn load_library(emu: &mut emu::Emu, libname: &str) -> u64 {
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

    match peb32::get_module_base(&dll, emu) {
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
            if std::path::Path::new(dll_path.as_str()).exists() {
                let (base, pe_off) = emu.load_pe32(&dll_path, false, 0);
                peb32::dynamic_link_module(base as u64, pe_off, &dll, emu);
                base as u64
            } else {
                if emu.cfg.verbose > 0 {
                    log::info!("dll {} not found.", dll_path);
                }
                0
            }
        }
    }
}

fn LoadLibraryA(emu: &mut emu::Emu) {
    let dllptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("bad LoadLibraryA parameter") as u64;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    log::info!(
        "{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        &dll,
        emu.regs.get_eax() as u32,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    //TODO: instead returning the base, return a handle that have linked the dll name
}

fn LoadLibraryExA(emu: &mut emu::Emu) {
    let libname_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32_LoadLibraryExA: error reading libname ptr param") as u64;
    let libname = emu.maps.read_string(libname_ptr);

    log::info!(
        "{}** {} kernel32!LoadLibraryExA '{}' {}",
        emu.colors.light_red,
        emu.pos,
        libname,
        emu.colors.nc
    );

    emu.regs.rax = load_library(emu, &libname);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn LoadLibraryExW(emu: &mut emu::Emu) {
    let libname_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!LoadLibraryExW: error reading libname ptr param") as u64;
    let hfile = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!LoadLibraryExW: error reading hFile") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!LoadLibraryExW: error reading flags") as u64;

    let libname = emu.maps.read_wide_string(libname_ptr);

    log::info!(
        "{}** {} LoadLibraryExW '{}' {}",
        emu.colors.light_red,
        emu.pos,
        libname,
        emu.colors.nc
    );

    emu.regs.rax = load_library(emu, &libname);

    /*
    if emu.regs.rax == 0 {
        emu.regs.rax = 1;
    }*/

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn LoadLibraryW(emu: &mut emu::Emu) {
    let dllptr = match emu.maps.read_dword(emu.regs.get_esp()) {
        Some(v) => v as u64,
        None => panic!("bad LoadLibraryW parameter"),
    };
    let dll = emu.maps.read_wide_string(dllptr);
    log::info!(
        "{}** {} LoadLibraryW  '{}'  {}",
        emu.colors.light_red,
        emu.pos,
        dll,
        emu.colors.nc
    );

    //if dll == "ntdll.dll" {
    //  emu.regs.rax = emu.maps.get_mem("ntdll").get_base();
    //}

    emu.regs.rax = load_library(emu, &dll);

    emu.stack_pop32(false);
}

fn WinExec(emu: &mut emu::Emu) {
    let cmdline_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("cannot read the cmdline parameter of WinExec") as u64;
    let cmdline = emu.maps.read_string(cmdline_ptr);

    //emu.spawn_console();

    log::info!(
        "{}** {} WinExec  '{}'  {}",
        emu.colors.light_red,
        emu.pos,
        cmdline,
        emu.colors.nc
    );

    emu.regs.rax = 0;
    emu.stack_pop32(false);
}

fn GetVersion(emu: &mut emu::Emu) {
    emu.regs.rax = emu::constants::VERSION;
    log::info!(
        "{}** {} kernel32!GetVersion   =0x{:x}  {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.get_eax() as u32,
        emu.colors.nc
    );
}

fn CreateProcessA(emu: &mut emu::Emu) {
    /*
    [in, optional]      LPCSTR                lpApplicationName,
    [in, out, optional] LPSTR                 lpCommandLine,
    */

    let appname_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateProcessA: cannot read stack") as u64;
    let cmdline_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateProcessA: cannot read stack2") as u64;
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

    for _ in 0..10 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn WaitForSingleObject(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!WaitForSingleObject error reading handle") as u64;
    let millis = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!WaitForSingleObject error reading millis");

    log::info!(
        "{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        millis,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = emu::constants::WAIT_TIMEOUT;
}

fn VirtualAlloc(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualAlloc error reading addr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualAlloc error reading size ptr") as u64;
    let atype = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualAlloc error reading type");
    let protect = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!VirtualAlloc error reading protect");

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAlloc out of memory");
    emu.maps
        .create_map(format!("alloc_{:x}", base).as_str(), base, size)
        .expect("kernel32!VirtualAlloc out of memory");

    log::info!(
        "{}** {} kernel32!VirtualAlloc sz: {} addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        size,
        base,
        emu.colors.nc
    );

    emu.regs.rax = base;

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn VirtualAllocEx(emu: &mut emu::Emu) {
    let proc_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualAllocEx cannot read the proc handle") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualAllocEx cannot read the address") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualAllocEx cannot read the size") as u64;
    let alloc_type = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!VirtualAllocEx cannot read the type");
    let protect = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!VirtualAllocEx cannot read the protect");

    log::info!(
        "{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        proc_hndl,
        addr,
        emu.colors.nc
    );

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAllocEx out of memory");
    emu.maps
        .create_map(format!("alloc_{:x}", base).as_str(), base, size)
        .expect("kernel32!VirtualAllocEx out of memory");

    emu.regs.rax = base;

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
}

fn WriteProcessMemory(emu: &mut emu::Emu) {
    let proc_hndl =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!WriteProcessMemory cannot read the proc handle") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!WriteProcessMemory cannot read the address") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!WriteProcessMemory cannot read the buffer") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!WriteProcessMemory cannot read the size") as u64;
    let written_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!WriteProcessMemory cannot read the ptr of num of written bytes");

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
    } else {
        emu.regs.rax = 0;
        log::info!(
            "{}\tcouldnt write the bytes{}",
            emu.colors.light_red,
            emu.colors.nc
        );
    }

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
}

fn CreateRemoteThread(emu: &mut emu::Emu) {
    let proc_hndl =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!CreateRemoteThread cannot read the proc handle") as u64;
    let sec = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateRemoteThread cannot read the proc security thread attributs")
        as u64;
    let stack_size =
        emu.maps
            .read_dword(emu.regs.get_esp() + 8)
            .expect("kernel32!CreateRemoteThread cannot read the stack size") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!CreateRemoteThread cannot read the addr") as u64;
    let param = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!CreateRemoteThread cannot read the param");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!CreateRemoteThread cannot read the flags");
    let out_tid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("kernel32!CreateRemoteThread cannot read the tid") as u64;

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

    for _ in 0..7 {
        emu.stack_pop32(false);
    }
}

fn CreateNamedPipeA(emu: &mut emu::Emu) {
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateNamedPipeA cannot read the name_ptr") as u64;
    let open_mode = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateNamedPipeA cannot read the open_mode");
    let pipe_mode = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!CreateNamedPipeA cannot read the pipe_mode");
    let instances = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!CreateNamedPipeA cannot read the instances");
    let out_buff_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("kernel32!CreateNamedPipeA cannot read the timeout");
    let security = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
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

    for _ in 0..8 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = helper::handler_create(&name);
}

fn ConnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ConnectNamedPipe cannot read the handle") as u64;
    let overlapped = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!ConnectNamedPipe cannot read the overlapped");

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

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn DisconnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!DisconnectNamedPipe cannot read the handle");

    log::info!(
        "{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn ReadFile(emu: &mut emu::Emu) {
    let file_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ReadFile cannot read the file_hndl") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!ReadFile cannot read the buff") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!ReadFile cannot read the size");
    let bytes_read = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!ReadFile cannot read the bytes_read") as u64;
    let overlapped = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!ReadFile cannot read the overlapped");

    let mut count = COUNT_READ.lock().unwrap();
    *count += 1;

    if size == 4 && *count == 1 {
        // probably reading the size
        emu.maps.write_dword(buff, 0x10);
    }

    if *count < 3 {
        // keep reading bytes
        emu.maps.write_dword(bytes_read, size);
        emu.maps.memset(buff, 0x90, size as usize);
        emu.regs.rax = 1;
    } else {
        // try to force finishing reading and continue the malware logic
        emu.maps.write_dword(bytes_read, 0);
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

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
}

fn WriteFile(emu: &mut emu::Emu) {
    let file_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!WriteFile cannot read the file_hndl") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!WriteFile cannot read the buff") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!WriteFile cannot read the size");
    let bytes_written = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!WriteFile cannot read the bytes_written") as u64;
    let overlapped = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!WriteFile cannot read the overlapped");

    let mut count = COUNT_WRITE.lock().unwrap();
    *count += 1;

    emu.maps.write_dword(bytes_written, size);

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

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CloseHandle(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CloseHandle cannot read the handle") as u64;

    log::info!(
        "{}** {} kernel32!CloseHandle 0x{:X} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        emu.colors.nc
    );

    if !helper::handler_close(hndl) {
        log::info!("\tinvalid handle.")
    }
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn ExitProcess(emu: &mut emu::Emu) {
    let code = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ExitProcess cannot read the exit code");

    log::info!(
        "{}** {} kernel32!ExitProcess code: {} {}",
        emu.colors.light_red,
        emu.pos,
        code,
        emu.colors.nc
    );
    emu.stack_pop32(false);

    std::process::exit(1);
}

fn TerminateProcess(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!TerminateProcess cannot read the handle");
    let code = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!TerminateProcess cannot read the exit code");

    log::info!(
        "{}** {} kernel32!TerminateProcess hndl: {} code: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        code,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn GetThreadContext(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetThreadContext cannot read the handle");
    let ctx_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetThreadContext cannot read the ctx");

    let ctx = context32::Context32::new(&emu.regs);
    ctx.save(ctx_ptr, &mut emu.maps);

    log::info!(
        "{}** {} kernel32!GetThreadContext  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn SetThreadContext(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!SetThreadContext cannot read the handle");
    let ctx_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!SetThreadContext cannot read the ctx_ptr");

    log::info!(
        "{}** {} kernel32!SetThreadContext  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let con = console::Console::new();
    con.print("apply the context (y/n)?");
    let opt = con.cmd();

    if opt == "y" || opt == "yes" {
        let mut ctx = context32::Context32::new(&emu.regs);
        ctx.load(ctx_ptr, &mut emu.maps);
        ctx.sync(&mut emu.regs);
    }

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn ReadProcessMemory(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ReadProcessMemory cannot read the handle");
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!ReadProcessMemory cannot read the base address");
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!ReadProcessMemory cannot read buff") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!ReadProcessMemory cannot read size");
    let bytes = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!ReadProcessMemory cannot read bytes") as u64;

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

    emu.maps.write_dword(bytes, size);
    emu.maps.memset(buff, 0x90, size as usize);

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn GetCurrentDirectoryW(emu: &mut emu::Emu) {
    let buff_len = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetCurrentDirectoryW cannot read buff_len");
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetCurrentDirectoryW cannot read buff_ptr") as u64;

    emu.maps
        .write_string(buff_ptr, "c\x00:\x00\\\x00\x00\x00\x00\x00");

    log::info!(
        "{}** {} kernel32!GetCurrentDirectoryW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 6;
}

fn GetCurrentDirectoryA(emu: &mut emu::Emu) {
    let buff_len = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetCurrentDirectoryW cannot read buff_len");
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetCurrentDirectoryW cannot read buff_ptr") as u64;

    emu.maps.write_string(buff_ptr, "c:\\\x00");

    log::info!(
        "{}** {} kernel32!GetCurrentDirectoryA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 3;
}

fn VirtualProtect(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualProtect cannot read addr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualProtect cannot read size");
    let new_prot = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualProtect cannot read new_prot");
    let old_prot_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!VirtualProtect cannot read old_prot") as u64;

    emu.maps.write_dword(old_prot_ptr, new_prot);

    log::info!(
        "{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        size,
        new_prot,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn VirtualProtectEx(emu: &mut emu::Emu) {
    let hproc = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualProtectEx cannot read hproc") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualProtectEx cannot read addr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualProtectEx cannot read size");
    let new_prot = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!VirtualProtectEx cannot read new_prot");
    let old_prot_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!VirtualProtectEx cannot read old_prot") as u64;

    emu.maps.write_dword(old_prot_ptr, new_prot);

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

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn ResumeThread(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ResumeThread cannot read the handle");

    log::info!(
        "{}** {} kernel32!ResumeThread hndl: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 1; // previous suspend count
}

fn GetFullPathNameA(emu: &mut emu::Emu) {
    let file_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetFullPathNameA cannot read file_ptr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetFullPathNameA cannot read size");
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetFullPathNameA cannot read buff");
    let path = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!GetFullPathNameA cannot read path");

    let filename = emu.maps.read_string(file_ptr);

    log::info!(
        "{}** {} kernel32!GetFullPathNameA file: {}  {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 10;
}

fn GetFullPathNameW(emu: &mut emu::Emu) {
    let file_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetFullPathNameW cannot read file_ptr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetFullPathNameW cannot read size");
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetFullPathNameW cannot read buff");
    let path = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!GetFullPathNameW cannot read path");

    let filename = emu.maps.read_wide_string(file_ptr);

    log::info!(
        "{}** {} kernel32!GetFullPathNameW file: {}  {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 10;
}

fn SystemTimeToTzSpecificLocalTime(emu: &mut emu::Emu) {
    let tz_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read tz_ptr");
    let ut_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read ut_ptr");
    let lt_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read lt_ptr");

    log::info!(
        "{}** {} kernel32!SystemTimeToTzSpecificLocalTime {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

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
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ExpandEnvironmentStringsA cannot read src") as u64;
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!ExpandEnvironmentStringsA cannot read dst") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!ExpandEnvironmentStringsA cannot read size");

    let src = emu.maps.read_string(src_ptr);

    log::info!(
        "{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;

    //TODO: implement expand
}

fn ExpandEnvironmentStringsW(emu: &mut emu::Emu) {
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ExpandEnvironmentStringsW cannot read src") as u64;
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!ExpandEnvironmentStringsW cannot read dst") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!ExpandEnvironmentStringsW cannot read size");

    let src = emu.maps.read_wide_string(src_ptr);

    log::info!(
        "{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        emu.colors.nc
    );

    //TODO: implement expand

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn GetFileAttributesA(emu: &mut emu::Emu) {
    let filename_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetFileAttributesA cannot read filename_ptr") as u64;
    let filename = emu.maps.read_string(filename_ptr);

    log::info!(
        "{}** {} kernel32!GetFileAttributesA file: {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );

    emu.regs.rax = 0x123; // file attributes

    emu.stack_pop32(false);
}

fn GetFileAttributesW(emu: &mut emu::Emu) {
    let filename_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetFileAttributesW cannot read filename_ptr") as u64;
    let filename = emu.maps.read_wide_string(filename_ptr);

    log::info!(
        "{}** {} kernel32!GetFileAttributesW file: {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 0x123; // file attributes
}

fn FileTimeToSystemTime(emu: &mut emu::Emu) {
    let file_time = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FileTimeToSystemTime cannot read file_time");
    let sys_time_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FileTimeToSystemTime cannot read sys_time_ptr");

    log::info!(
        "{}** {} kernel32!FileTimeToSystemTime {} ",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn FindFirstFileA(emu: &mut emu::Emu) {
    let file_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FindFirstFileA cannot read file_ptr") as u64;
    let find_data = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FindFirstFileA cannot read find_data");

    let file = emu.maps.read_string(file_ptr);

    log::info!(
        "{}** {} kernel32!FindFirstFileA file: {} {}",
        emu.colors.light_red,
        emu.pos,
        file,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn FindFirstFileW(emu: &mut emu::Emu) {
    let file_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FindFirstFileW cannot read file_ptr") as u64;
    let find_data = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FindFirstFileW cannot read find_data");

    let file = emu.maps.read_wide_string(file_ptr);

    log::info!(
        "{}** {} kernel32!FindFirstFileW file: {} {}",
        emu.colors.light_red,
        emu.pos,
        file,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create(&file);
}

fn FindNextFileA(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FindNextFileA cannot read the handle");
    let find_data = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FindNextFileA cannot read the find_data");

    log::info!(
        "{}** {} kernel32!FindNextFileA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn FindNextFileW(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FindNextFileW cannot read the handle");
    let find_data = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FindNextFileW cannot read the find_data");

    log::info!(
        "{}** {} kernel32!FindNextFileW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn CopyFileA(emu: &mut emu::Emu) {
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CopyFileA cannot read src_ptr") as u64;
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CopyFileA cannot read dst_ptr") as u64;
    let do_fail = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!CopyFileA cannot read do_fail");

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

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn CopyFileW(emu: &mut emu::Emu) {
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CopyFileW cannot read src_ptr") as u64;
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CopyFileW cannot read dst_ptr") as u64;
    let do_fail = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!CopyFileW cannot read do_fail");

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

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn FindClose(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FindClose cannot read the handle") as u64;

    log::info!(
        "{}** {} kernel32!FindClose {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    helper::handler_close(hndl);
    emu.regs.rax = 1;
}

fn MoveFileA(emu: &mut emu::Emu) {
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!MoveFileA cannot read src_ptr") as u64;
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!MoveFileA cannot read dst_ptr") as u64;

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

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn MoveFileW(emu: &mut emu::Emu) {
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!MoveFileW cannot read src_ptr") as u64;
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!MoveFileW cannot read dst_ptr") as u64;

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

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn OpenProcess(emu: &mut emu::Emu) {
    let access = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!OpenProcess cannot read access");
    let inherit = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!OpenProcess cannot read inherit");
    let pid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!OpenProcess cannot read pid");

    log::info!(
        "{}** {} kernel32!OpenProcess pid: {} {}",
        emu.colors.light_red,
        emu.pos,
        pid,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    let uri = format!("pid://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
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

fn Thread32First(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!Thread32First cannot read the handle");
    let entry = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!Thread32First cannot read the entry32");

    log::info!(
        "{}** {} kernel32!Thread32First {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn Thread32Next(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!Thread32Next cannot read the handle");
    let entry = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!Thread32Next cannot read the entry32");

    log::info!(
        "{}** {} kernel32!Thread32Next {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn OpenThread(emu: &mut emu::Emu) {
    let access = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!OpenThread cannot read acess");
    let inherit = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!OpenThread cannot read inherit");
    let tid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!OpenThread cannot read tid");

    log::info!(
        "{}** {} kernel32!OpenThread tid: {} {}",
        emu.colors.light_red,
        emu.pos,
        tid,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    let uri = format!("tid://{}", tid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateToolhelp32Snapshot(emu: &mut emu::Emu) {
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateToolhelp32Snapshot cannot read flags");
    let pid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateToolhelp32Snapshot cannot read pid");

    log::info!(
        "{}** {} kernel32!CreateToolhelp32Snapshot pid: {} {}",
        emu.colors.light_red,
        emu.pos,
        pid,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    let uri = format!("pid://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateThread(emu: &mut emu::Emu) {
    let sec_attr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateThread cannot read sec_attr");
    let stack_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateThread cannot read stack_sz");
    let code = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!CreateThread cannot read fptr") as u64;
    let param = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!CreateThread cannot read param");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!CreateThread cannot read flags") as u64;
    let tid_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!CreateThread cannot read tid_ptr") as u64;

    if tid_ptr > 0 {
        emu.maps.write_dword(tid_ptr, 0x123);
    }

    log::info!(
        "{}** {} kernel32!CreateThread code: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        code,
        emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }

    if flags == constants::CREATE_SUSPENDED {
        log::info!("\tcreated suspended!");
    }

    let con = console::Console::new();
    con.print("Continue emulating the created thread (y/n)? ");
    let line = con.cmd();

    if line == "y" || line == "yes" {
        if emu.maps.is_mapped(code) {
            emu.regs.set_eip(code);
            emu.regs.rax = 0;
            emu.regs.set_ecx(param as u64);
            emu.main_thread_cont = emu.gateway_return;
            emu.stack_push32(param);
            emu.stack_push32(constants::RETURN_THREAD);

            // alloc a stack vs reusing stack.
            return;
        } else {
            log::info!("cannot emulate the thread, the function pointer is not mapped.");
        }
    }

    emu.regs.rax = helper::handler_create("tid://0x123");
}

fn MapViewOfFile(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!MapViewOfFile cannot read the handle");
    let access = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!MapViewOfFile cannot read the acess");
    let off_high = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!MapViewOfFile cannot read the off_hight") as u64;
    let off_low = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!MapViewOfFile cannot read the off_low") as u64;
    let mut size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!MapViewOfFile cannot read the size") as u64;

    let off: u64 = (off_high << 32) + off_low;

    /*if size > 1024 * 4 {
        size = 1024
    }*/
    if size < 1024 {
        size = 1024;
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

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = addr;
}

fn GetSystemTimeAsFileTime(emu: &mut emu::Emu) {
    let sys_time_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetSystemTimeAsFileTime cannot read sys_time_ptr");

    log::info!(
        "{}** {} kernel32!GetSystemTimeAsFileTime {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);

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

fn GetTickCount(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetTickCount {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let tick = TICK.lock().unwrap();
    emu.regs.rax = *tick as u64;
}

fn QueryPerformanceCounter(emu: &mut emu::Emu) {
    let counter_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!QueryPerformanceCounter cannot read counter_ptr") as u64;

    emu.maps.write_dword(counter_ptr, 0x1);

    log::info!(
        "{}** {} kernel32!QueryPerformanceCounter {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn HeapDestroy(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!HeapDestroy cannot read handle") as u64;

    log::info!(
        "{}** {} kernel32!HeapDestroy {:x}  {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        emu.colors.nc
    );

    helper::handler_close(hndl);

    emu.regs.rax = hndl;
    emu.stack_pop32(false);
}

fn HeapCreate(emu: &mut emu::Emu) {
    let opts = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!HeapCreate cannot read opts");
    let init_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!HeapCreate cannot read init_sz");
    let max_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!HeapCreate cannot read max_sz");

    log::info!(
        "{}** {} kernel32!HeapCreate initSz: {} maxSz: {}  {}",
        emu.colors.light_red,
        emu.pos,
        init_sz,
        max_sz,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create("heap://");
}

fn GetModuleHandleA(emu: &mut emu::Emu) {
    let mod_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetModuleHandleA cannot read mod_name_ptr") as u64;

    let mod_name: String;

    if mod_name_ptr == 0 {
        mod_name = "self".to_string();
        emu.regs.rax = match emu.maps.get_base() {
            Some(base) => base,
            None => helper::handler_create(&mod_name),
        }
    } else {
        mod_name = emu.maps.read_string(mod_name_ptr).to_lowercase();
        let mod_mem = match emu.maps.get_mem2(&mod_name) {
            Some(m) => m,
            None => {
                emu.regs.rax = 0;
                return;
            }
        };

        emu.regs.rax = mod_mem.get_base();
    }

    log::info!(
        "{}** {} kernel32!GetModuleHandleA '{}' {}",
        emu.colors.light_red,
        emu.pos,
        mod_name,
        emu.colors.nc
    );

    emu.stack_pop32(false);
}

fn GetModuleHandleW(emu: &mut emu::Emu) {
    let mod_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetModuleHandleW cannot read mod_name_ptr") as u64;

    let mod_name: String;

    if mod_name_ptr == 0 {
        mod_name = "self".to_string();
        emu.regs.rax = match emu.maps.get_base() {
            Some(base) => base,
            None => helper::handler_create(&mod_name),
        }
    } else {
        mod_name = emu.maps.read_wide_string(mod_name_ptr).to_lowercase();
        let mod_mem = match emu.maps.get_mem2(&mod_name) {
            Some(m) => m,
            None => {
                emu.regs.rax = 0;
                return;
            }
        };
        emu.regs.rax = mod_mem.get_base();
    }

    log::info!(
        "{}** {} kernel32!GetModuleHandleW '{}' {}",
        emu.colors.light_red,
        emu.pos,
        mod_name,
        emu.colors.nc
    );

    emu.stack_pop32(false);
}

fn TlsAlloc(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!TlsAlloc {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.tls32.push(0);
    emu.regs.set_eax(emu.tls32.len() as u64);
}

fn TlsFree(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!TlsFree cannot read idx");

    log::info!(
        "{}** {} kernel32!TlsFree idx: {} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

fn TlsSetValue(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!TlsSetValue cannot read idx");
    let val = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!TlsSetValue cannot read val_ptr");

    log::info!(
        "{}** {} kernel32!TlsSetValue idx: {} val: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        val,
        emu.colors.nc
    );

    if emu.tls32.len() > idx as usize {
        emu.tls32[idx as usize] = val;
    } else {
        for _ in 0..=idx {
            emu.tls32.push(0);
        }
        emu.tls32[idx as usize] = val;
    }

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

fn TlsGetValue(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!TlsGetValue cannot read idx");

    emu.stack_pop32(false);

    if idx as usize > emu.tls32.len() {
        emu.regs.set_eax(0);
    } else {
        emu.regs.set_eax(emu.tls32[idx as usize] as u64);
    }

    log_red!(emu, "** {} kernel32!TlsGetValue idx: {} =0x{:x}", 
        emu.pos,
        idx,
        emu.regs.get_eax() as u32
    );
}

fn EncodePointer(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!EncodePointer cannot read the pointer") as u64;

    log::info!(
        "{}** {} kernel32!EncodePointer ptr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        ptr,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = ptr;
}

fn DecodePointer(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!DecodePointer cannot read the pointer") as u64;

    log::info!(
        "{}** {} kernel32!DecodePointer ptr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        ptr,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = ptr;
}

fn Sleep(emu: &mut emu::Emu) {
    let millis = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!Sleep cannot read millis");

    log::info!(
        "{}** {} kernel32!Sleep millis: {} {}",
        emu.colors.light_red,
        emu.pos,
        millis,
        emu.colors.nc
    );
    let mut tick = TICK.lock().unwrap();
    *tick += millis;

    emu.stack_pop32(false);
}

fn InitializeCriticalSectionAndSpinCount(emu: &mut emu::Emu) {
    let crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!InitializeCriticalSectionAndSpinCount cannot read crit_sect");
    let spin_count = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!InitializeCriticalSectionAndSpinCount cannot read spin_count");

    log::info!("{}** {} kernel32!InitializeCriticalSectionAndSpinCount crit_sect: 0x{:x} spin_count: {} {}", emu.colors.light_red, emu.pos, crit_sect, spin_count, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn HeapAlloc(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!HeapAlloc cannot read the handle");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!HeapAlloc cannot read the flags");
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!HeapAlloc cannot read the size") as u64;

    emu.regs.rax = emu.maps.alloc(size).unwrap_or_default();

    emu.maps
        .create_map(
            format!("alloc_{:x}", emu.regs.get_eax() as u32).as_str(),
            emu.regs.get_eax(),
            size,
        )
        .expect("kernel32!HeapAlloc out of memory");

    log::info!(
        "{}** {} kernel32!HeapAlloc flags: 0x{:x} size: {} =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        flags,
        size,
        emu.regs.get_eax() as u32,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn GetProcessAffinityMask(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetProcessAffinityMask cannot read the handle") as u64;
    let proc_affinity_mask_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetProcessAffinityMask cannot read the  proc_affinity_mask_ptr")
        as u64;
    let sys_affinity_mask_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetProcessAffinityMask cannot read the sys_affinity_mask_ptr")
        as u64;

    emu.maps.write_dword(proc_affinity_mask_ptr, 0x1337);
    emu.maps.write_dword(sys_affinity_mask_ptr, 0x1337);

    log::info!(
        "{}** {} kernel32!GetProcessAffinityMask {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
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
    let callback =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!SetUnhandledExceptionFilter cannot read the callback") as u64;

    log::info!(
        "{}** {} kernel32!SetUnhandledExceptionFilter  callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        callback,
        emu.colors.nc
    );

    emu.regs.rax = emu.seh;
    emu.seh = callback;

    emu.stack_pop32(false);
}

fn UnhandledExceptionFilter(emu: &mut emu::Emu) {
    let exception_info = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!UnhandledExceptionFilter cannot read exception_info");

    log::info!(
        "{}** {} kernel32!UnhandledExceptionFilter  exception_info: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        exception_info,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = constants::EXCEPTION_EXECUTE_HANDLER;
    // a debugger would had answered EXCEPTION_CONTINUE_SEARCH
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

fn LocalAlloc(emu: &mut emu::Emu) {
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!LocalAlloc cannot read flags");
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!LocalAlloc cannot read size") as u64;

    emu.regs.rax = emu.maps.alloc(size).unwrap_or_default();

    emu.maps
        .create_map(
            format!("alloc_{:x}", emu.regs.get_eax() as u32).as_str(),
            emu.regs.get_eax(),
            size,
        )
        .expect("kernel32!LocalAlloc out of memory");

    log::info!(
        "{}** {} kernel32!LocalAlloc flags: 0x{:x} size: {} =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        flags,
        size,
        emu.regs.get_eax() as u32,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn VirtualAllocExNuma(emu: &mut emu::Emu) {
    let proc_hndl =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!VirtualAllocExNuma cannot read the proc handle") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualAllocExNuma cannot read the address") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualAllocExNuma cannot read the size") as u64;
    let alloc_type = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!VirtualAllocExNuma cannot read the type");
    let protect = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!VirtualAllocExNuma cannot read the protect");
    let nnd = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
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
        .expect("kernel32!VirtualAllocExNuma out of memory");

    emu.regs.rax = base;

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn GetUserDefaultLangID(emu: &mut emu::Emu) {
    emu.regs.rax = 0x000000000000ffff;
    log::info!(
        "{}** {} kernel32!GetUserDefaultLangID =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax as u16,
        emu.colors.nc
    );
}

fn GetProcessHeap(emu: &mut emu::Emu) {
    emu.regs.rax = helper::handler_create("process heap");
    log::info!(
        "{}** {} kernel32!GetProcessHeap =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax as u32,
        emu.colors.nc
    );
}

fn GetComputerNameA(emu: &mut emu::Emu) {
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetComputerNameA cannot read buff param") as u64;
    let size_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetComputerNameA cannot read size param") as u64;

    if buff_ptr > 0 {
        emu.maps.write_string(buff_ptr, "medusa");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }

    if size_ptr > 0 {
        emu.maps.write_dword(size_ptr, 6);
        emu.regs.rax = 1;
    }

    log::info!(
        "{}** {} kernel32!GetComputerName 'medusa' {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn CreateMutexA(emu: &mut emu::Emu) {
    let attr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateMutexA cannot read attr param");
    let owner = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateMutexA cannot read owner param");
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateMutexA cannot read name param") as u64;
    let name = emu.maps.read_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateMutexA '{}' {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    let uri = format!("mutex://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateMutexW(emu: &mut emu::Emu) {
    let attr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateMutexW cannot read attr param");
    let owner = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateMutexW cannot read owner param");
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateMutexW cannot read name param") as u64;
    let name = emu.maps.read_wide_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateMutexW '{}' {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    let uri = format!("mutex://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetLastError(emu: &mut emu::Emu) {
    let err = LAST_ERROR.lock().unwrap();
    emu.regs.rax = *err as u64;
    log::info!(
        "{}** {} kernel32!GetLastError ={} {}",
        emu.colors.light_red,
        emu.pos,
        emu.regs.rax,
        emu.colors.nc
    );
}

fn CreateFileMappingA(emu: &mut emu::Emu) {
    let hFile = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateFileMappingW cannot read hFile param");
    let attr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateFileMappingW cannot read attr param");
    let protect = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!CreateFileMappingW cannot read protect");
    let maxsz_high = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!CreateFileMappingW cannot read max size high");
    let maxsz_low = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!CreateFileMappingW cannot read max size low");
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!CreateFileMappingW cannot read name ptr") as u64;

    let mut name: String = String::new();

    if name_ptr > 0 {
        name = emu.maps.read_string(name_ptr);
    }

    emu.regs.rax = helper::handler_create(&name);

    log::info!(
        "{}** {} kernel32!CreateFileMappingA {} '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        name_ptr,
        name,
        emu.regs.get_eax(),
        emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn CreateFileMappingW(emu: &mut emu::Emu) {
    let hFile = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateFileMappingW cannot read hFile param");
    let attr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateFileMappingW cannot read attr param");
    let protect = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!CreateFileMappingW cannot read protect");
    let maxsz_high = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!CreateFileMappingW cannot read max size high");
    let maxsz_low = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!CreateFileMappingW cannot read max size low");
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!CreateFileMappingW cannot read name ptr") as u64;

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

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn GetSystemTime(emu: &mut emu::Emu) {
    let out_time = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetSystemTime cannot read out_time param") as u64;

    log::info!(
        "{}** {} kernel32!GetSystemTime ptr: 0x{:x}' {}",
        emu.colors.light_red,
        emu.pos,
        out_time,
        emu.colors.nc
    );
    let systime = emu::structures::SystemTime::now();
    systime.save(out_time, &mut emu.maps);

    emu.stack_pop32(false);
}

fn lstrcat(emu: &mut emu::Emu) {
    let str1_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!lstrcat cannot read str1 param") as u64;
    let str2_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!lstrcat cannot read str2 param") as u64;

    let mut str1 = emu.maps.read_string(str1_ptr);
    let str2 = emu.maps.read_string(str2_ptr);

    log::info!(
        "{}** {} kernel32!lstrcat '{}'+'{}' {}",
        emu.colors.light_red,
        emu.pos,
        str1,
        str2,
        emu.colors.nc
    );

    str1.push_str(&str2);

    emu.maps.write_string(str1_ptr, &str1);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn SetErrorMode(emu: &mut emu::Emu) {
    let mode = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!SetErrorMode cannot read mode param");

    log::info!(
        "{}** {} kernel32!SetErrorMode 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        mode,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 0;
}

fn GetVersionExW(emu: &mut emu::Emu) {
    let version_info_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetVersionExW cannot read version_info_ptr param") as u64;

    log::info!(
        "{}** {} kernel32!GetVersionExW 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        version_info_ptr,
        emu.colors.nc
    );

    let os_version_info = emu::structures::OsVersionInfo::new();
    os_version_info.save(version_info_ptr, &mut emu.maps);

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn GetSystemDirectoryA(emu: &mut emu::Emu) {
    let out_buff_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetSystemDirectoryA cannot read out_buff_ptr param") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetSystemDirectoryA cannot read size param");

    emu.maps.write_string(out_buff_ptr, "C:\\Windows\\\x00");

    log::info!(
        "{}** {} kernel32!GetSystemDirectoryA  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 11;
}

fn GetSystemDirectoryW(emu: &mut emu::Emu) {
    let out_buff_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetSystemDirectoryW cannot read out_buff_ptr param") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetSystemDirectoryW cannot read size param");

    emu.maps
        .write_wide_string(out_buff_ptr, "C:\\Windows\\\x00\x00");

    log::info!(
        "{}** {} kernel32!GetSystemDirectoryW  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 11; // * 2;
}

fn GetStartupInfoA(emu: &mut emu::Emu) {
    let startup_info_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetStartupInfoA cannot read startup_info_ptr param") as u64;

    log::info!(
        "{}** {} kernel32!GetStartupInfoA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    if startup_info_ptr > 0 {
        let startupinfo = emu::structures::StartupInfo32::new();
        startupinfo.save(startup_info_ptr, &mut emu.maps);
    }

    emu.stack_pop32(false);
}

fn GetStartupInfoW(emu: &mut emu::Emu) {
    let startup_info_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetStartupInfoW cannot read startup_info_ptr param") as u64;

    log::info!(
        "{}** {} kernel32!GetStartupInfoW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    if startup_info_ptr > 0 {
        let startupinfo = emu::structures::StartupInfo32::new();
        startupinfo.save(startup_info_ptr, &mut emu.maps);
    }

    emu.stack_pop32(false);
}

fn FlsGetValue(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FlsGetValue cannot read idx");

    emu.stack_pop32(false);

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
    let feature = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!IsProcessorFeaturePresent cannot read feature");
    emu.stack_pop32(false);

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
    let ptr_crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!InitializeCriticalSection cannot read ptr_crit_sect");

    emu.stack_pop32(false);

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
    let ptr_crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!InitializeCriticalSectionEx cannot read ptr_crit_sect");
    let spin_count = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!InitializeCriticalSectionEx cannot read spin_count");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!InitializeCriticalSectionEx cannot read flags");

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

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
    let callback = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FlsAlloc cannot read callback");

    log::info!(
        "{}** {} kernel32!FlsAlloc callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        callback,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn FlsSetValue(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FlsSetValue cannot read index");
    let val = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FlsSetValue cannot read value");

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

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn SetLastError(emu: &mut emu::Emu) {
    let err_code = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!SetLastError cannot read err_code");

    log::info!(
        "{}** {} kernel32!SetLastError err: {} {}",
        emu.colors.light_red,
        emu.pos,
        err_code,
        emu.colors.nc
    );

    let mut err = LAST_ERROR.lock().unwrap();
    *err = err_code;

    emu.stack_pop32(false);
}

fn lstrlen(emu: &mut emu::Emu) {
    let s_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!lstrlen cannot read string") as u64;

    emu.stack_pop32(false);
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

fn MultiByteToWideChar(emu: &mut emu::Emu) {
    let codepage = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!MultiByteToWideChar cannot read codepage");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!MultiByteToWideChar cannot read flags");
    let utf8_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!MultiByteToWideChar cannot read utf8_ptr") as u64;
    let cbMultiByte = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!MultiByteToWideChar cannot read cbMultiByte");
    let wide_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!MultiByteToWideChar cannot read wide_ptr") as u64;
    let cchWideChar = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!MultiByteToWideChar cannot read cchWideChar");

    for _ in 0..6 {
        emu.stack_pop32(false);
    }

    let utf8 = emu.maps.read_string(utf8_ptr);
    let mut wide = String::new();
    for c in utf8.chars() {
        wide.push_str(&format!("{}", c));
        wide.push('\x00');
    }

    log::info!(
        "{}** {} kernel32!MultiByteToWideChar '{}' dst:0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        utf8,
        wide_ptr,
        emu.colors.nc
    );

    if cchWideChar > 0 {
        emu.maps.write_string(wide_ptr, &wide);
    }
    emu.regs.rax = wide.len() as u64;
}

fn GetSystemInfo(emu: &mut emu::Emu) {
    let out_sysinfo = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetSystemInfo cannot read out_sysinfo") as u64;

    log::info!(
        "{}** {} kernel32!GetSystemInfo sysinfo: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        out_sysinfo,
        emu.colors.nc
    );

    // let mut sysinfo = emu::structures::SystemInfo32::new();
    // sysinfo.save(out_sysinfo, &mut emu.maps);

    emu.stack_pop32(false);
}

fn HeapFree(emu: &mut emu::Emu) {
    let heap = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!HeapFree cannot read heap handle");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!HeapFree cannot read heap handle");
    let mem = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!HeapFree cannot read heap handle");

    log::info!(
        "{}** {} kernel32!HeapFree mem: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        mem,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn SetThreadLocale(emu: &mut emu::Emu) {
    let locale = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!SetThreadLocale cannot read locale param");

    log::info!(
        "{}** {} kernel32!SetThreadLocale {} {}",
        emu.colors.light_red,
        emu.pos,
        locale,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn GetCommandLineA(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCommandlineA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    let cmdline = emu.alloc("cmdline", 1024);
    emu.maps.write_string(cmdline, "test.exe");
    emu.regs.rax = cmdline;
}

fn GetCommandLineW(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetCommandlineW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    let cmdline = emu.alloc("cmdline", 1024);
    emu.maps.write_string(cmdline, "test.exe");
    emu.regs.rax = cmdline;
}

fn GetAcp(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetAcp {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 1252;
}

fn GetModuleFileNameW(emu: &mut emu::Emu) {
    let hmodule = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetModuleFileNameW cannot read hmodule");
    let out_filename_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp() + 4)
            .expect("kernel32!GetModuleFileNameW cannot read out_filename_ptr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetModuleFileNameW cannot read out_filename_ptr");

    log::info!(
        "{}** {} kernel32!GetModuleFileNameW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.maps.write_wide_string(out_filename_ptr, "jowei3r.exe");
    emu.regs.rax = 11;
}

fn RegOpenKeyExW(emu: &mut emu::Emu) {
    let hkey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegOpenKeyExW cannot read hkey");
    let subkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegOpenKeyExW cannot read subkey") as u64;
    let options = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegOpenKeyExW cannot read options");
    let sam = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!RegOpenKeyExW cannot read sam");
    let result = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!RegOpenKeyExW cannot read result");

    let subkey = emu.maps.read_wide_string(subkey_ptr);
    log::info!(
        "{}** {} kernel32!RegOpenKeyExW {} {}",
        emu.colors.light_red,
        emu.pos,
        subkey,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn GetUserDefaultUILanguage(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetUserDefaultUILanguage (0x0409 en_US) {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = emu::constants::EN_US_LOCALE as u64;
}

fn EnterCriticalSection(emu: &mut emu::Emu) {
    let crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!EnterCriticalSection cannot read crit_sect");

    log::info!(
        "{}** {} kernel32!EnterCriticalSection 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        crit_sect,
        emu.colors.nc
    );
    emu.regs.rax = crit_sect as u64;
    emu.stack_pop32(false);
}

fn LeaveCriticalSection(emu: &mut emu::Emu) {
    let crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!LeaveCriticalSection cannot read crit_sect");

    log::info!(
        "{}** {} kernel32!LeaveCriticalSection {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 1;
    emu.stack_pop32(false);
}

fn IsValidLocale(emu: &mut emu::Emu) {
    let locale = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!IsValidLocale cannot read locale");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!IsValidLocale cannot read flags");

    log::info!(
        "{}** {} kernel32!IsValidLocale {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetThreadUILanguage(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetThreadUILanguage (0x0409 en_US) {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = emu::constants::EN_US_LOCALE as u64;
}

fn GetThreadPreferredUILanguages(emu: &mut emu::Emu) {
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetThreadPreferredUILanguages cannot read flags");
    let num_langs_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetThreadPreferredUILanguages cannot read num_langs_ptr")
        as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetThreadPreferredUILanguages cannot read buff") as u64;
    let out_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!GetThreadPreferredUILanguages cannot read sz") as u64;

    emu.maps.write_dword(num_langs_ptr, 0);
    log::info!(
        "{}** {} kernel32!GetThreadPreferredUILanguages {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_dword(out_sz, 0);
    emu.maps.write_dword(num_langs_ptr, 0);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn lstrcmpA(emu: &mut emu::Emu) {
    let s1_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!lstrcmp cannot read s1_ptr") as u64;
    let s2_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!lstrcmp cannot read s2_ptr") as u64;

    let s1 = emu.maps.read_string(s1_ptr);
    let s2 = emu.maps.read_string(s2_ptr);

    log::info!(
        "{}** {} kernel32!lstrcmpA '{}' == '{}' {}",
        emu.colors.light_red,
        emu.pos,
        s1,
        s2,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    let result = s1.cmp(&s2);
    if result == std::cmp::Ordering::Less {
        emu.regs.rax = 0xffffffff;
    } else if result == std::cmp::Ordering::Greater {
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn lstrcmpW(emu: &mut emu::Emu) {
    let s1_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!lstrcmp cannot read s1_ptr") as u64;
    let s2_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!lstrcmp cannot read s2_ptr") as u64;

    let s1 = emu.maps.read_wide_string(s1_ptr);
    let s2 = emu.maps.read_wide_string(s2_ptr);

    log::info!(
        "{}** {} kernel32!lstrcmpW '{}' == '{}' {}",
        emu.colors.light_red,
        emu.pos,
        s1,
        s2,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    let result = s1.cmp(&s2);
    if result == std::cmp::Ordering::Less {
        emu.regs.rax = 0xffffffff;
    } else if result == std::cmp::Ordering::Greater {
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn GetNativeSystemInfo(emu: &mut emu::Emu) {
    let sysinfo_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetNativeSystemInfo cannot read sysinfo_ptr") as u64;

    let mut sysinfo = emu::structures::SystemInfo32::new();
    sysinfo.save(sysinfo_ptr, &mut emu.maps);

    log::info!(
        "{}** {} kernel32!GetNativeSystemInfo {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
}

fn GetTempPathW(emu: &mut emu::Emu) {
    let bufflen = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetTempPathW cannot read bufflen");
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetTempPathW cannot read buff_ptr") as u64;

    if bufflen >= 14 {
        emu.maps.write_wide_string(buff_ptr, "c:\\tmp\\");
        emu.regs.rax = 14;
    } else {
        emu.regs.rax = 0;
    }

    log::info!(
        "{}** {} kernel32!GetTempPathW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn FileTimeToLocalFileTime(emu: &mut emu::Emu) {
    let lpFileTime =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!FileTimeToLocalFileTime cannot read lpFileTime") as u64;
    let out_lpLocalFileTime = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!FileTimeToLocalFileTime cannot read out_lpLocalFileTime")
        as u64;

    let dwLowDateTime = emu
        .maps
        .read_dword(lpFileTime)
        .expect("kernel32!FileTimeToLocalFileTime cannot read dwLowDateTime");
    let dwHighDateTime = emu
        .maps
        .read_dword(lpFileTime + 4)
        .expect("kernel32!FileTimeToLocalFileTime cannot read dwHighDateTime");

    emu.maps.write_dword(out_lpLocalFileTime, dwLowDateTime);
    emu.maps
        .write_dword(out_lpLocalFileTime + 4, dwHighDateTime);

    log::info!(
        "{}** {} kernel32!FileTimeToLocalFileTime {} {} {}",
        emu.colors.light_red,
        emu.pos,
        dwLowDateTime,
        dwHighDateTime,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn FileTimeToDosDateTime(emu: &mut emu::Emu) {
    let lpFileTime =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!FileTimeToDosDateTime cannot read lpFileTime") as u64;
    let out_lpFatDate =
        emu.maps
            .read_dword(emu.regs.get_esp() + 4)
            .expect("kernel32!FileTimeToDosDateTime cannot read out_lpFatDate") as u64;
    let out_lpFatTime =
        emu.maps
            .read_dword(emu.regs.get_esp() + 8)
            .expect("kernel32!FileTimeToDosDateTime cannot read out_lpFatTime") as u64;

    let dwLowDateTime = emu
        .maps
        .read_dword(lpFileTime)
        .expect("kernel32!FileTimeToLocalFileTime cannot read dwLowDateTime");
    let dwHighDateTime = emu
        .maps
        .read_dword(lpFileTime + 4)
        .expect("kernel32!FileTimeToLocalFileTime cannot read dwHighDateTime");

    /*
    let ftSeconds = (dwLowDateTime as u64) | ((dwHighDateTime as u64) << 32);
    let posix_seconds = (ftSeconds / 10_000_000) - 11_644_473_600;
    let utc_dt = std::time::UNIX_EPOCH + std::time::Duration::from_secs(posix_seconds);
    let local_dt = DateTime::<chrono::Local>::from(utc_dt).with_timezone(&chrono::Local);
    let year = (local_dt.year() - 1980) as u16;
    let month = local_dt.month() as u16;
    let day = local_dt.day() as u16;
    let date = ((year << 9) | (month << 5) | day) as u16;
    let hour = local_dt.hour() as u16;
    let min = local_dt.minute() as u16;
    let sec = (local_dt.second() / 2) as u16;
    let time = ((hour << 11) | (min << 5) | sec) as u16;

    emu.maps.write_dword(out_lpFatDate, date as u32);
    emu.maps.write_dword(out_lpFatTime, time as u32);
    */

    emu.maps.write_dword(out_lpFatDate, 0);
    emu.maps.write_dword(out_lpFatTime, 0);

    log::info!(
        "{}** {} kernel32!FileTimeToDosDateTime {} {} {}",
        emu.colors.light_red,
        emu.pos,
        dwLowDateTime,
        dwHighDateTime,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn VirtualQuery(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualQuery cannot read addr") as u64;
    let out_buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualQuery cannot read out_buff") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualQuery cannot read size");

    log::info!(
        "{}** {} kernel32!VirtualQuery 0x{:x} 0x{:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        out_buff,
        size,
        emu.colors.nc
    );

    if size < 30 {
        log::info!("buffer to short: {}", size);
        emu.regs.rax = 0;
    } else {
        let mbi = structures::MemoryBasicInformation::guess(addr, &mut emu.maps);
        mbi.save(out_buff, &mut emu.maps);
        emu.regs.rax = 1;
    }

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn VirtualFree(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualFree cannot read addr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualFree cannot read out_buff");
    let freeType = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualFree cannot read size") as u64;

    log::info!(
        "{}** {} kernel32!VirtualFree 0x{:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        size,
        emu.colors.nc
    );

    match emu.maps.get_mem_by_addr(addr) {
        Some(mem) => {
            emu.regs.rax = 1;
            let name = mem.get_name();
            emu.maps.free(&name);
        }
        None => {
            emu.regs.rax = 0;
        }
    }

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn RaiseException(emu: &mut emu::Emu) {
    let code = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RaiseException cannot read code");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RaiseException cannot read flags");
    let num_args = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RaiseException cannot read num_args");
    let args = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!RaiseException cannot read args");

    log::info!(
        "{}** {} kernel32!RaiseException {} {} {}",
        emu.colors.light_red,
        emu.pos,
        code,
        flags,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 0;
    //std::process::exit(1);
}

fn VerifyVersionInfoW(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!VerifyVersionInfoW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0xffff;
}

fn GetTimeZoneInformation(emu: &mut emu::Emu) {
    let out_timeZoneInfo = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetTimeZoneInformation cannot read out_timeZoneInfo");

    //TODO: new structure https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information

    log::info!(
        "{}** {} kernel32!GetTimeZoneInformation {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1; // TIME_ZONE_ID_STANDARD
}

fn VirtualQueryEx(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!VirtualQueryEx cannot read proc hndl") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!VirtualQueryEx cannot read addr") as u64;
    let out_buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!VirtualQueryEx cannot read out_buff") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!VirtualQueryEx cannot read size");

    log::info!(
        "{}** {} kernel32!VirtualQueryEx 0x{:x} 0x{:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        out_buff,
        size,
        emu.colors.nc
    );

    if size < 30 {
        log::info!("buffer to short: {}", size);
        emu.regs.rax = 0;
    } else {
        let mbi = structures::MemoryBasicInformation::guess(addr, &mut emu.maps);
        mbi.save(out_buff, &mut emu.maps);
        emu.regs.rax = 1;
    }

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn InterlockedIncrement(emu: &mut emu::Emu) {
    let addend = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!InterlockedIncrement cannot read addend");

    let prev = emu
        .maps
        .read_dword(addend as u64)
        .expect("kernel32!InterlockedIncrement  error derreferencing addend");

    emu.maps.write_dword(addend as u64, prev + 1);

    log::info!(
        "{}** {} kernel32!InterlockedIncrement 0x{:x} {}->{} {}",
        emu.colors.light_red,
        emu.pos,
        addend,
        prev,
        prev + 1,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = prev as u64 + 1;
}

fn GetEnvironmentStrings(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetEnvironmentStrings {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    let ptr = emu.alloc("environment", 1024);
    emu.maps.write_string(ptr, "PATH=c:\\Windows\\System32");
    emu.regs.rax = ptr;
}

fn GetEnvironmentStringsW(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetEnvironmentStringsW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    let addr = emu.alloc("environment", 1024);
    emu.maps
        .write_wide_string(addr, "PATH=c:\\Windows\\System32");
    emu.regs.rax = addr;
}

fn GetStdHandle(emu: &mut emu::Emu) {
    let nstd = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!GetStdHandle error reading nstd param");

    log::info!(
        "{}** {} kernel32!GetStdHandle {} {}",
        emu.colors.light_red,
        emu.pos,
        nstd,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = nstd as u64;
}

fn GetFileType(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!GetFileType error getting hndl param");

    log::info!(
        "{}** {} kernel32!GetFileType 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 3;

    /*
     * FILE_TYPE_CHAR 0x0002
     * FILE_TYPE_DISK 0x0001
     * FILE_TYPE_PIPE 0x0003
     * FILE_TYPE_REMOTE 0x8000
     * FILE_TYPE_UNKNOWN 0x0000
     */
}

fn SetHandleCount(emu: &mut emu::Emu) {
    let num = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!SetHandleCount error getting num param");

    log::info!(
        "{}** {} kernel32!SetHandleCount {} {}",
        emu.colors.light_red,
        emu.pos,
        num,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = num as u64;
}

fn IsValidCodePage(emu: &mut emu::Emu) {
    let codepage = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!IsValidCodePage error geting codepage param");

    log::info!(
        "{}** {} kernel32!IsValidCodePage {} {}",
        emu.colors.light_red,
        emu.pos,
        codepage,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn GetCPInfo(emu: &mut emu::Emu) {
    let codepage = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!GetCPInfo error reading codepage param");
    let info_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!GetCPInfo error reading inmfo_ptr param");

    log::info!(
        "{}** {} kernel32!GetCPInfo {} 0x{} {}",
        emu.colors.light_red,
        emu.pos,
        codepage,
        info_ptr,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;

    // https://learn.microsoft.com/en-us/windows/win32/api/winnls/ns-winnls-cpinfo
}

fn GetStringTypeW(emu: &mut emu::Emu) {
    let info_type = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!GetStringTypeW error reading info_type param");
    let str_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!GetStringTypeW error reading str_ptr param") as u64;
    let sz = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!GetStringTypeW error reading sz param");
    let char_type = emu
        .maps
        .read_dword(emu.regs.rsp + 12)
        .expect("kernel32!GetStringTypeW error reading char_type param");

    let ustr = emu.maps.read_wide_string(str_ptr);

    log::info!(
        "{}** {} kernel32!GetStringTypeW `{}` 0x{} {}",
        emu.colors.light_red,
        emu.pos,
        ustr,
        sz,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn LCMapStringW(emu: &mut emu::Emu) {
    let locale = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!LCMapStringW error reading param");
    let flags = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!LCMapStringW error reading param");
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!LCMapStringW error reading param") as u64;
    let src_sz = emu
        .maps
        .read_dword(emu.regs.rsp + 12)
        .expect("kernel32!LCMapStringW error reading param");
    let dest_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 16)
        .expect("kernel32!LCMapStringW error reading param") as u64;
    let dest_sz = emu
        .maps
        .read_dword(emu.regs.rsp + 20)
        .expect("kernel32!LCMapStringW error reading param");

    let s = emu.maps.read_wide_string(src_ptr);

    log::info!(
        "{}** {} kernel32!LCMapStringW `{}` dst:0x{:x} sz:{}->{} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        dest_ptr,
        src_sz,
        dest_sz,
        emu.colors.nc
    );

    if dest_ptr > 0 {
        emu.maps.write_wide_string(dest_ptr, &s);
    }

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn WideCharToMultiByte(emu: &mut emu::Emu) {
    let codepage = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let flags = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let wstr_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!WideCharToMultiByte error reading param") as u64;
    let wstr_sz = emu
        .maps
        .read_dword(emu.regs.rsp + 12)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let mbytestr_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 16)
        .expect("kernel32!WideCharToMultiByte error reading param") as u64;
    let mbytestr_sz = emu
        .maps
        .read_dword(emu.regs.rsp + 20)
        .expect("kernel32!WideCharToMultiByte error reading param");
    let in_default_char =
        emu.maps
            .read_dword(emu.regs.rsp + 24)
            .expect("kernel32!WideCharToMultiByte error reading param") as u64;
    let out_default_char =
        emu.maps
            .read_dword(emu.regs.rsp + 28)
            .expect("kernel32!WideCharToMultiByte error reading param") as u64;

    //log::info!("default_char_ptr 0x{:x}", in_default_char);
    //let default_char = emu.maps.read_byte(in_default_char)
    //    .expect("kernel32!WideCharToMultiByte error reading default char");

    //emu.maps.write_byte(out_default_char, 0);

    let s = emu.maps.read_wide_string(wstr_ptr);
    if mbytestr_ptr > 0 {
        emu.maps.write_string(mbytestr_ptr, &s);
    }

    log::info!(
        "{}** {} kernel32!WideCharToMultiByte `{}` sz:{}->{} ={} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        wstr_sz,
        mbytestr_sz,
        s.len(),
        emu.colors.nc,
    );

    for _ in 0..8 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = s.len() as u64 + 2;
}

fn CryptCreateHash(emu: &mut emu::Emu) {
    let hprov = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!CryptCreateHash error reading param");
    let algid = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!CryptCreateHash error reading param");
    let hkey = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!CryptCreateHash error reading param");
    let flags = emu
        .maps
        .read_dword(emu.regs.rsp + 12)
        .expect("kernel32!CryptCreateHash error reading param");
    let ptr_hash = emu
        .maps
        .read_dword(emu.regs.rsp + 16)
        .expect("kernel32!CryptCreateHash error reading param") as u64;

    let alg_name = constants::get_cryptoalgorithm_name(algid);

    log::info!(
        "{}** {} kernel32!CryptCreateHash alg:{} {}",
        emu.colors.light_red,
        emu.pos,
        alg_name,
        emu.colors.nc,
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.maps.write_dword(
        ptr_hash,
        helper::handler_create(&format!("alg://{}", alg_name)) as u32,
    );
    emu.regs.rax = 1;
}

fn HeapSetInformation(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!HeapSetInformation error reading param");
    let hinfocls = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!HeapSetInformation error reading param");
    let hinfo = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!HeapSetInformation error reading param");
    let hinfo_sz = emu
        .maps
        .read_dword(emu.regs.rsp + 12)
        .expect("kernel32!HeapSetInformation error reading param");

    log::info!(
        "{}** {} kernel32!HeapSetInformation {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc,
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn FreeEnvironmentStringsW(emu: &mut emu::Emu) {
    let env = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!FreeEnvironmentStringsW error reading param");

    log::info!(
        "{}** {} kernel32!FreeEnvironmentStringsW 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        env,
        emu.colors.nc,
    );
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn OpenProcessToken(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!OpenProcessToken error reading param");
    let access = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!OpenProcessToken error reading param");
    let ptr_token = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!OpenProcessToken error reading param") as u64;

    log::info!(
        "{}** {} kernel32!OpenProcessToken 0x{:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        access,
        emu.colors.nc,
    );

    emu.maps.write_dword(
        ptr_token,
        helper::handler_create(&format!("token://{}", hndl)) as u32,
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn CreateEventA(emu: &mut emu::Emu) {
    let ev_attr_ptr = emu
        .maps
        .read_dword(emu.regs.rsp)
        .expect("kernel32!CreateEventA error reading param") as u64;
    let bManualReset = emu
        .maps
        .read_dword(emu.regs.rsp + 4)
        .expect("kernel32!CreateEventA error reading param");
    let bInitialState = emu
        .maps
        .read_dword(emu.regs.rsp + 8)
        .expect("kernel32!CreateEventA error reading param");
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.rsp + 12)
        .expect("kernel32!CreateEventA error reading param") as u64;

    let name = emu.maps.read_string(name_ptr);

    log::info!(
        "{}** {} kernel32!CreateEventA `{}` {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc,
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn AddVectoredExceptionHandler(emu: &mut emu::Emu) {
    let p1 = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!AddVectoredExceptionHandler: error reading p1") as u64;
    let fptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!AddVectoredExceptionHandler: error reading fptr") as u64;

    log::info!(
        "{}** {} kernel32!AddVectoredExceptionHandler  {} callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        p1,
        fptr,
        emu.colors.nc
    );

    emu.veh = fptr;

    emu.regs.rax = 0x2c2878;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetLongPathNameW(emu: &mut emu::Emu) {
    let short_path_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetLongPathNameW: error reading param") as u64;
    let long_path_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetLongPathNameW: error reading param") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetLongPathNameW: error reading param") as u64;

    let short = emu.maps.read_wide_string(short_path_ptr);

    log::info!(
        "{}** {} kernel32!GetLongPathNameW  {} {:x} {}",
        emu.colors.light_red,
        emu.pos,
        short,
        long_path_ptr,
        emu.colors.nc
    );

    if long_path_ptr > 0 {
        let mut base = String::from("\\.\\");
        base.push_str(&short);
        emu.maps.write_wide_string(long_path_ptr, &base);
    }

    emu.regs.rax = short.len() as u64;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn FreeLibrary(emu: &mut emu::Emu) {
    let hmod = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FreeLibrary: error reading param") as u64;

    log::info!(
        "{}** {} kernel32!FreeLibrary   {:x} {}",
        emu.colors.light_red,
        emu.pos,
        hmod,
        emu.colors.nc
    );

    emu.regs.rax = 1;
    emu.stack_pop32(false);
}

fn AreFileApisANSI(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!AreFileApisANSI {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn CreateFileW(emu: &mut emu::Emu) {
    let fname_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!CreateFileW: error reading param") as u64;
    let access = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!CreateFileW: error reading param");

    let fname = emu.maps.read_wide_string(fname_ptr);

    let mut perm: String = String::new();
    if access & constants::GENERIC_READ != 0 {
        perm.push('r');
    }
    if access & constants::GENERIC_WRITE != 0 {
        perm.push('w');
    }

    if perm.is_empty() {
        perm = "unknown permissions".to_string();
    }

    log::info!(
        "{}** {} kernel32!CreateFileW `{}` {} {}",
        emu.colors.light_red,
        emu.pos,
        fname,
        perm,
        emu.colors.nc
    );

    for _ in 0..7 {
        emu.stack_pop32(false);
    }

    //if perm == "r" {
    //    emu.regs.rax = constants::INVALID_HANDLE_VALUE_32;
    //} else {
    emu.regs.rax = helper::handler_create(&format!("file://{}", fname)) as u64;
    //}
}

fn GetModuleFileNameA(emu: &mut emu::Emu) {
    let hmod = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetModuleFileNameA: error reading param") as u64;
    let fname_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetModuleFileNameA: error reading param") as u64;
    let buff_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!GetModuleFileNameA: error reading param");

    if buff_sz > 8 {
        emu.maps.write_string(fname_ptr, "c:\\test.exe");
    }

    log::info!(
        "{}** {} kernel32!GetModuleFileNameA 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        hmod,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 8;
}

fn lstrcpy(emu: &mut emu::Emu) {
    let dst = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!lstrcpy: error reading dst") as u64;
    let src = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!lstrcpy: error reading src") as u64;
    let s = emu.maps.read_string(src);
    emu.maps.write_string(dst, &s);

    log::info!(
        "{}** {} kernel32!lstrcpy 0x{:x} `{}` {}",
        emu.colors.light_red,
        emu.pos,
        dst,
        s,
        emu.colors.nc
    );

    emu.regs.rax = dst;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetACP(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetACP {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x00000409;
}

fn GetOEMCP(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} kernel32!GetOEMCP {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0x00000409;
}

fn GetWindowsDirectoryA(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetWindowsDirectoryA: error reading param") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetWindowsDirectoryA: error reading param") as u64;

    log::info!(
        "{}** {} kernel32!GetWindowsDirectoryA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_string(ptr, "C:\\Windows\\");
    emu.regs.rax = size;

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetWindowsDirectoryW(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetWindowsDirectoryW: error reading param") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetWindowsDirectoryW: error reading param") as u64;

    log::info!(
        "{}** {} kernel32!GetWindowsDirectoryW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_wide_string(ptr, "C:\\Windows\\");
    emu.regs.rax = size;

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetSystemWindowsDirectoryA(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetSystemWindowsDirectoryA: error reading param") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetSystemWindowsDirectoryA: error reading param") as u64;

    log::info!(
        "{}** {} kernel32!GetSystemWindowsDirectoryA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_string(ptr, "C:\\Windows\\system32\\");
    emu.regs.rax = size;

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetSystemWindowsDirectoryW(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetSystemWindowsDirectoryW: error reading param") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!GetSystemWindowsDirectoryW: error reading param") as u64;

    log::info!(
        "{}** {} kernel32!GetSystemWindowsDirectoryW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_wide_string(ptr, "C:\\Windows\\system32\\");
    emu.regs.rax = size;

    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn RegCreateKeyExA(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegCreateKeyExA: error reading param") as u64;
    let subkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegCreateKeyExA: error reading param") as u64;
    let reserved = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegCreateKeyExA: error reading param") as u64;
    let class_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!RegCreateKeyExA: error reading param") as u64;
    let options = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!RegCreateKeyExA: error reading param") as u64;
    let security_attr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!RegCreateKeyExA: error reading param") as u64;

    let subkey = emu.maps.read_string(subkey_ptr);
    let mut class_name = "".to_string();
    if class_ptr > 0 {
        class_name = emu.maps.read_string(class_ptr);
    }

    log::info!(
        "{}** {} kernel32!RegCreateKeyExA {} {} {}",
        emu.colors.light_red,
        emu.pos,
        subkey,
        class_name,
        emu.colors.nc
    );
    emu.regs.rax = constants::ERROR_SUCCESS;

    for _ in 0..9 {
        emu.stack_pop32(false);
    }
}

fn RegCreateKeyExW(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegCreateKeyExW: error reading param") as u64;
    let subkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegCreateKeyExW: error reading param") as u64;
    let reserved = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegCreateKeyExW: error reading param") as u64;
    let class_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!RegCreateKeyExW: error reading param") as u64;
    let options = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!RegCreateKeyExW: error reading param") as u64;
    let security_attr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!RegCreateKeyExW: error reading param") as u64;

    let subkey = emu.maps.read_wide_string(subkey_ptr);
    let mut class_name = "".to_string();
    if class_ptr > 0 {
        class_name = emu.maps.read_wide_string(class_ptr);
    }

    log::info!(
        "{}** {} kernel32!RegCreateKeyExW {} {} {}",
        emu.colors.light_red,
        emu.pos,
        subkey,
        class_name,
        emu.colors.nc
    );
    emu.regs.rax = constants::ERROR_SUCCESS;

    for _ in 0..9 {
        emu.stack_pop32(false);
    }
}

fn RegSetValueExA(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegSetValueExA: error reading param") as u64;
    let value_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegSetValueExA: error reading param") as u64;
    let reserved = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegSetValueExA: error reading param") as u64;
    let value_type = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!RegSetValueExA: error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!RegSetValueExA: error reading param") as u64;
    let data_size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!RegSetValueExA: error reading param") as u64;

    let value_name = emu.maps.read_string(value_name_ptr);

    log::info!(
        "{}** {} kernel32!RegSetValueExA `{}` type: {} data: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        value_name,
        value_type,
        data_ptr,
        emu.colors.nc
    );
    emu.regs.rax = constants::ERROR_SUCCESS;

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn RegSetValueExW(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegSetValueExW: error reading param") as u64;
    let value_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegSetValueExW: error reading param") as u64;
    let reserved = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegSetValueExW: error reading param") as u64;
    let value_type = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("kernel32!RegSetValueExW: error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("kernel32!RegSetValueExW: error reading param") as u64;
    let data_size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("kernel32!RegSetValueExW: error reading param") as u64;

    let value_name = emu.maps.read_wide_string(value_name_ptr);

    log::info!(
        "{}** {} kernel32!RegSetValueExW `{}` type: {} data: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        value_name,
        value_type,
        data_ptr,
        emu.colors.nc
    );
    emu.regs.rax = constants::ERROR_SUCCESS;

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn RegCloseKey(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegCloseKey: error reading param") as u64;

    log::info!(
        "{}** {} kernel32!RegCloseKey hkey: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        hKey,
        emu.colors.nc
    );
    emu.stack_pop32(false);
    emu.regs.rax = constants::ERROR_SUCCESS;
}

fn RegOpenKeyA(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegOpenKeyA: error reading param") as u64;
    let subkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegOpenKeyA: error reading param") as u64;
    let result = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegOpenKeyA: error reading param") as u64;

    let subkey = emu.maps.read_string(subkey_ptr);
    emu.maps.write_dword(
        result,
        helper::handler_create(&format!("key://{}", subkey)) as u32,
    );

    log::info!(
        "{}** {} kernel32!RegOpenKeyA `{}` {}",
        emu.colors.light_red,
        emu.pos,
        subkey,
        emu.colors.nc
    );
    emu.regs.rax = constants::ERROR_SUCCESS;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn RegOpenKeyW(emu: &mut emu::Emu) {
    let hKey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!RegOpenKeyW: error reading param") as u64;
    let subkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("kernel32!RegOpenKeyW: error reading param") as u64;
    let result = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("kernel32!RegOpenKeyW: error reading param") as u64;

    let subkey = emu.maps.read_wide_string(subkey_ptr);
    emu.maps.write_dword(
        result,
        helper::handler_create(&format!("key://{}", subkey)) as u32,
    );

    log::info!(
        "{}** {} kernel32!RegOpenKeyW `{}` {}",
        emu.colors.light_red,
        emu.pos,
        subkey,
        emu.colors.nc
    );
    emu.regs.rax = constants::ERROR_SUCCESS;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}
