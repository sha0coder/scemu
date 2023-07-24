use crate::emu;
use crate::emu::console;
use crate::emu::constants;
use crate::emu::context32;
use crate::emu::peb32;
use crate::emu::structures;
use crate::emu::winapi32::helper;

use lazy_static::lazy_static;
use std::sync::Mutex;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x75e9395c => LoadLibraryA(emu),
        0x75e847fa => LoadLibraryExA(emu),
        0x75e93951 => LoadLibraryExA(emu), // from jump table
        0x75e84775 => LoadLibraryExW(emu),
        0x75e933d3 => GetProcAddress(emu),
        0x75e93c01 => LoadLibraryW(emu),
        0x75ece5fd => WinExec(emu),
        0x75e8154e => GetVersion(emu),
        0x75e42082 => CreateProcessA(emu),
        0x75e8ba90 => WaitForSingleObject(emu),
        0x75e92fb6 => VirtualAlloc(emu),
        0x75e7c1b6 => VirtualAllocEx(emu),
        0x75e7c1de => WriteProcessMemory(emu),
        0x75ecf33b => CreateRemoteThread(emu),
        0x75ecd44f => CreateNamedPipeA(emu),
        0x75e72727 => ConnectNamedPipe(emu),
        0x75e9f438 => DisconnectNamedPipe(emu),
        0x75e896fb => ReadFile(emu),
        0x75e91400 => WriteFile(emu),
        0x75e8ca7c => CloseHandle(emu),
        0x75e9214f => ExitProcess(emu),
        0x75e82331 => TerminateProcess(emu),
        0x75ea0cc1 => GetThreadContext(emu),
        0x75e7c1ce => ReadProcessMemory(emu),
        0x75e9c13a => GetCurrentDirectoryW(emu),
        0x75e7733c => GetCurrentDirectoryA(emu),
        0x75e82341 => VirtualProtect(emu),
        0x75ecf5d9 => VirtualProtectEx(emu),
        0x75e80f1c => ResumeThread(emu),
        0x75e93735 => GetFullPathNameA(emu),
        0x75e94543 => GetFullPathNameW(emu),
        0x75e7b149 => SystemTimeToTzSpecificLocalTime(emu),
        0x75e85986 => GetLogicalDrives(emu),
        0x75e78a5b => ExpandEnvironmentStringsA(emu),
        0x75e84680 => ExpandEnvironmentStringsW(emu),
        0x75e91de6 => GetFileAttributesA(emu),
        0x75e964ff => GetFileAttributesW(emu),
        0x75e91dfe => FileTimeToSystemTime(emu),
        0x75e92289 => FindFirstFileA(emu),
        0x75e8a187 => FindNextFileA(emu),
        0x75e953b2 => FindFirstFileW(emu),
        0x75e8963a => FindNextFileW(emu),
        0x75ea532c => CopyFileA(emu),
        0x75e767c3 => CopyFileW(emu),
        0x75e90e62 => FindClose(emu),
        0x75eca559 => MoveFileA(emu),
        0x75ea548a => MoveFileW(emu),
        0x75e859d7 => OpenProcess(emu),
        0x75e8cac4 => GetCurrentProcessId(emu),
        0x75ea7e4c => Thread32First(emu),
        0x75ea7edc => Thread32Next(emu),
        0x75e96733 => OpenThread(emu),
        0x75e7f731 => CreateToolhelp32Snapshot(emu),
        0x75e9375d => CreateThread(emu),
        0x75ed0193 => SetThreadContext(emu),
        0x75e8899b => MapViewOfFile(emu),
        0x75e92fde => GetSystemTimeAsFileTime(emu),
        0x75e8bb80 => GetCurrentThreadId(emu),
        0x75e8ba60 => GetTickCount(emu),
        0x75e8bb9f => QueryPerformanceCounter(emu),
        0x75e93ea2 => HeapCreate(emu),
        0x75e8cf41 => GetModuleHandleA(emu),
        0x75e9374d => GetModuleHandleW(emu),
        0x75e935a1 => TlsAlloc(emu),
        0x75e8da88 => TlsSetValue(emu),
        0x75e8da70 => TlsGetValue(emu),
        0x75e913b8 => TlsFree(emu),
        0x75eff02b => EncodePointer(emu),
        0x75efef55 => DecodePointer(emu),
        0x75e8ba46 => Sleep(emu),
        0x75e93939 => InitializeCriticalSectionAndSpinCount(emu),
        0x75eff164 => HeapAlloc(emu),
        0x75e82351 => GetProcessAffinityMask(emu),
        0x75e83ea8 => IsDebuggerPresent(emu),
        0x75e93d01 => SetUnhandledExceptionFilter(emu),
        0x75e9ed38 => UnhandledExceptionFilter(emu),
        0x75e8cdcf => GetCurrentProcess(emu),
        0x75e93363 => LocalAlloc(emu),
        0x75ecf5c9 => VirtualAllocExNuma(emu),
        0x75ea6447 => GetUserDefaultLangID(emu),
        0x75e91280 => GetProcessHeap(emu),
        0x75e76ba9 => GetComputerNameA(emu),
        0x75e93589 => CreateMutexA(emu),
        0x75e8bf00 => GetLastError(emu),
        0x75e80a7f => CreateFileMappingW(emu),
        0x75e8ced8 => GetSystemTime(emu),
        0x75e8a19f => lstrcat(emu),
        0x75e94a51 => SetErrorMode(emu),
        0x75e83b1a => GetVersionExW(emu),
        0x75e88fc5 => GetSystemDirectoryA(emu),
        0x75e940fb => GetSystemDirectoryW(emu),
        0x75e41e10 => GetStartupInfoA(emu),
        0x75e93891 => GetStartupInfoW(emu),
        0x75e91e16 => FlsGetValue(emu),
        0x75e976b5 => IsProcessorFeaturePresent(emu),
        0x75eff1e4 => InitializeCriticalSection(emu),
        0x75e93879 => InitializeCriticalSectionEx(emu),
        0x75e9418d => FlsAlloc(emu),
        0x75e976e6 => FlsSetValue(emu),
        0x75e8bb08 => SetLastError(emu),
        0x75e8a611 => lstrlen(emu),
        0x75e9452b => MultiByteToWideChar(emu),
        0x75e93728 => GetSystemInfo(emu),
        0x75e8bbd0 => HeapFree(emu),
        0x75ea88e6 => SetThreadLocale(emu),
        0x75e9679e => GetCommandLineW(emu),
        0x75e939aa => GetAcp(emu),
        0x75e93c26 => GetModuleFileNameW(emu),
        0x75e8c189 => RegOpenKeyExW(emu),
        0x75e822ef => GetUserDefaultUILanguage(emu),
        0x75eff05f => EnterCriticalSection(emu),
        0x75eff346 => LeaveCriticalSection(emu),
        0x75e83de4 => IsValidLocale(emu),
        0x75e7ae42 => GetThreadUILanguage(emu),
        0x75e822d7 => GetThreadPreferredUILanguages(emu),
        0x75e78c59 => lstrcmp(emu),
        0x75e7be77 => GetNativeSystemInfo(emu),
        0x75e78b33 => GetTempPathW(emu),
        0x75e92004 => FileTimeToLocalFileTime(emu),
        0x75e82ce1 => FileTimeToDosDateTime(emu),
        0x75e82aee => CreateMutexW(emu),
        0x75e976d6 => VirtualQuery(emu),
        0x75e91da4 => VirtualFree(emu),
        0x75e7eb60 => RaiseException(emu),
        0x75e80e91 => VerifyVersionInfoW(emu),
        0x75e78a3b => GetTimeZoneInformation(emu),
        0x75e74e42 => VirtualQueryEx(emu),

        _ => {
            let apiname = guess_api_name(emu, addr);
            println!(
                "calling unimplemented kernel32 API 0x{:x} {}",
                addr, apiname
            );
            return apiname;
        }
    }

    return String::new();
}

lazy_static! {
    static ref COUNT_READ: Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE: Mutex<u32> = Mutex::new(0);
    pub static ref TICK: Mutex<u32> = Mutex::new(0);
    static ref LAST_ERROR: Mutex<u32> = Mutex::new(0);
}

//// kernel32 API ////

pub fn dump_module_iat(emu: &mut emu::Emu, module: &str) {
    let mut flink = peb32::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.mod_name.to_lowercase().contains(module) {
            if flink.export_table_rva > 0 {
                for i in 0..flink.num_of_funcs {
                    if flink.pe_hdr == 0 {
                        continue;
                    }

                    let ordinal = flink.get_function_ordinal(emu, i);
                    println!(
                        "0x{:x} {}!{}",
                        ordinal.func_va, &flink.mod_name, &ordinal.func_name
                    );
                }
            }
        }
        flink.next(emu);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }
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

        //println!("flink: 0x{:x} first_ptr: 0x{:x} num_of_funcs: {}", flink.get_ptr(), first_ptr, flink.num_of_funcs);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    return 0; //TODO: use Option<>
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

    return (0, String::new(), String::new()); //TODO: use Option<>
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

    return "function not found".to_string();
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

    //println!("looking for '{}'", func);

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

                //println!("func name {}!{}", flink.mod_name, ordinal.func_name);

                if ordinal.func_name.to_lowercase() == func {
                    emu.regs.rax = ordinal.func_va;
                    println!(
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
        println!("kernel32!GetProcAddress error searching {}", func);
    }
}

pub fn load_library(emu: &mut emu::Emu, libname: &str) -> u64 {
    let mut dll = libname.to_string().to_lowercase();

    if dll.len() == 0 {
        emu.regs.rax = 0;
        return 0;
    }

    if !dll.ends_with(".dll") {
        dll.push_str(".dll");
    }

    let mut dll_path = emu.cfg.maps_folder.clone();
    dll_path.push_str("/");
    dll_path.push_str(&dll);

    match peb32::get_module_base(&dll, emu) {
        Some(base) => {
            // already linked
            if emu.cfg.verbose > 0 {
                println!("dll {} already linked.", dll);
            }
            return base;
        }
        None => {
            // do link
            if std::path::Path::new(dll_path.as_str()).exists() {
                let (base, pe_off) = emu.load_pe32(&dll_path, false, 0);
                peb32::dynamic_link_module(base as u64, pe_off, &dll, emu);
                return base as u64;
            } else {
                if emu.cfg.verbose > 0 {
                    println!("dll {} not found.", dll_path);
                }
                return 0;
            }
        }
    };
}

fn LoadLibraryA(emu: &mut emu::Emu) {
    let dllptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("bad LoadLibraryA parameter") as u64;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!(
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

    println!(
        "{}** {} kernel32!LoadLibraryExA '{}' {}",
        emu.colors.light_red, emu.pos, libname, emu.colors.nc
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

    println!(
        "{}** {} LoadLibraryExW '{}' {}",
        emu.colors.light_red, emu.pos, libname, emu.colors.nc
    );

    emu.regs.rax = load_library(emu, &libname);

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
    println!(
        "{}** {} LoadLibraryW  '{}'  {}",
        emu.colors.light_red, emu.pos, dll, emu.colors.nc
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

    println!(
        "{}** {} WinExec  '{}'  {}",
        emu.colors.light_red, emu.pos, cmdline, emu.colors.nc
    );

    emu.regs.rax = 0;
    emu.stack_pop32(false);
}

fn GetVersion(emu: &mut emu::Emu) {
    emu.regs.rax = emu::constants::VERSION;
    println!(
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

    println!(
        "{}** {} kernel32!CreateProcessA  {} {} {}",
        emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc
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

    println!(
        "{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}",
        emu.colors.light_red, emu.pos, handle, millis, emu.colors.nc
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
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    println!(
        "{}** {} kernel32!VirtualAlloc sz: {} addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, size, base, emu.colors.nc
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

    println!(
        "{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc
    );

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAllocEx out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

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

    println!(
        "{}** {} kernel32!WriteProcessMemory hproc: 0x{:x} from: 0x{:x } to: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, proc_hndl, buff, addr, size, emu.colors.nc
    );

    if emu.maps.memcpy(buff, addr, size as usize) {
        emu.regs.rax = 1;
        println!(
            "{}\twritten succesfully{}",
            emu.colors.light_red, emu.colors.nc
        );
    } else {
        emu.regs.rax = 0;
        println!(
            "{}\tcouldnt write the bytes{}",
            emu.colors.light_red, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CreateRemoteThread hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}",
        emu.colors.light_red, emu.pos, name, in_buff_sz, out_buff_sz, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ConnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red, emu.pos, handle, emu.colors.nc
    );
    if !helper::handler_exist(handle) {
        println!("\tinvalid handle.");
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

    println!(
        "{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red, emu.pos, handle, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ReadFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
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

    println!(
        "{}** {} kernel32!WriteFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
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

    println!(
        "{}** {} kernel32!CloseHandle 0x{:X} {}",
        emu.colors.light_red, emu.pos, hndl, emu.colors.nc
    );

    if !helper::handler_close(hndl) {
        println!("\tinvalid handle.")
    }
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn ExitProcess(emu: &mut emu::Emu) {
    let code = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!ExitProcess cannot read the exit code");

    println!(
        "{}** {} kernel32!ExitProcess code: {} {}",
        emu.colors.light_red, emu.pos, code, emu.colors.nc
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

    println!(
        "{}** {} kernel32!TerminateProcess hndl: {} code: {} {}",
        emu.colors.light_red, emu.pos, hndl, code, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetThreadContext  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!SetThreadContext  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ReadProcessMemory hndl: {} from: 0x{:x} to: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, hndl, addr, buff, size, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetCurrentDirectoryW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetCurrentDirectoryA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red, emu.pos, addr, size, new_prot, emu.colors.nc
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

    println!(
        "{}** {} kernel32!VirtualProtectEx hproc: {} addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red, emu.pos, hproc, addr, size, new_prot, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ResumeThread hndl: {} {}",
        emu.colors.light_red, emu.pos, hndl, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetFullPathNameA file: {}  {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetFullPathNameW file: {}  {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
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

    println!(
        "{}** {} kernel32!SystemTimeToTzSpecificLocalTime {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn GetLogicalDrives(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetLogicalDrives {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}",
        emu.colors.light_red, emu.pos, src, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}",
        emu.colors.light_red, emu.pos, src, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetFileAttributesA file: {} {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetFileAttributesW file: {} {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FileTimeToSystemTime {} ",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FindFirstFileA file: {} {}",
        emu.colors.light_red, emu.pos, file, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FindFirstFileW file: {} {}",
        emu.colors.light_red, emu.pos, file, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FindNextFileA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FindNextFileW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CopyFileA `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CopyFileW `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FindClose {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!MoveFileA `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
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

    println!(
        "{}** {} kernel32!MoveFileW `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
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

    println!(
        "{}** {} kernel32!OpenProcess pid: {} {}",
        emu.colors.light_red, emu.pos, pid, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    let uri = format!("pid://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetCurrentProcessId(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCurrentProcessId {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!Thread32First {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!Thread32Next {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!OpenThread tid: {} {}",
        emu.colors.light_red, emu.pos, tid, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CreateToolhelp32Snapshot pid: {} {}",
        emu.colors.light_red, emu.pos, pid, emu.colors.nc
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

    emu.maps.write_dword(tid_ptr, 0x123);

    println!(
        "{}** {} kernel32!CreateThread code: 0x{:x} {}",
        emu.colors.light_red, emu.pos, code, emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }

    if flags == constants::CREATE_SUSPENDED {
        println!("\tcreated suspended!");
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
            println!("cannot emulate the thread, the function pointer is not mapped.");
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

    if size > 1024 * 4 {
        size = 1024
    }
    let addr = emu
        .maps
        .alloc(size)
        .expect("kernel32!MapViewOfFile cannot allocate");
    let mem = emu.maps.create_map("file_map");
    mem.set_base(addr);
    mem.set_size(size);
    let loaded = mem.load_chunk(&emu.filename, off, size as usize);

    println!(
        "{}** {} kernel32!MapViewOfFile hndl: {} off: {} sz: {} ={} {}",
        emu.colors.light_red, emu.pos, hndl, off, size, addr, emu.colors.nc
    );

    if off > 0 {
        println!("the non-zero offset is not implemented for now");
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

    println!(
        "{}** {} kernel32!GetSystemTimeAsFileTime {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn GetCurrentThreadId(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCurrentThreadId {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 0x111; //TODO: track pids and tids
}

fn GetTickCount(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetTickCount {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!QueryPerformanceCounter {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 1;
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

    println!(
        "{}** {} kernel32!HeapCreate initSz: {} maxSz: {}  {}",
        emu.colors.light_red, emu.pos, init_sz, max_sz, emu.colors.nc
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
    } else {
        mod_name = emu.maps.read_string(mod_name_ptr);
    }

    println!(
        "{}** {} kernel32!GetModuleHandleA '{}' {}",
        emu.colors.light_red, emu.pos, mod_name, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = helper::handler_create(&mod_name);
}

fn GetModuleHandleW(emu: &mut emu::Emu) {
    let mod_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetModuleHandleW cannot read mod_name_ptr") as u64;
    let mod_name = emu.maps.read_wide_string(mod_name_ptr);

    println!(
        "{}** {} kernel32!GetModuleHandleW '{}' {}",
        emu.colors.light_red, emu.pos, mod_name, emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create(&mod_name);
}

fn TlsAlloc(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!TlsAlloc {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn TlsFree(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!TlsFree cannot read idx");

    println!(
        "{}** {} kernel32!TlsFree idx: {} {}",
        emu.colors.light_red, emu.pos, idx, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
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

    println!(
        "{}** {} kernel32!TlsSetValue idx: {} val: 0x{:x} {}",
        emu.colors.light_red, emu.pos, idx, val, emu.colors.nc
    );

    if emu.tls.len() > idx as usize {
        emu.tls[idx as usize] = val;
    } else {
        for _ in 0..=idx {
            emu.tls.push(0);
        }
        emu.tls[idx as usize] = val;
    }

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn TlsGetValue(emu: &mut emu::Emu) {
    let idx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!TlsGetValue cannot read idx");

    emu.stack_pop32(false);

    if idx as usize > emu.tls.len() {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = emu.tls[idx as usize] as u64;
    }

    println!(
        "{}** {} kernel32!TlsGetValue idx: {} =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        idx,
        emu.regs.get_eax() as u32,
        emu.colors.nc
    );
}

fn EncodePointer(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!EncodePointer cannot read the pointer") as u64;

    println!(
        "{}** {} kernel32!EncodePointer ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = ptr;
}

fn DecodePointer(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!DecodePointer cannot read the pointer") as u64;

    println!(
        "{}** {} kernel32!DecodePointer ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = ptr;
}

fn Sleep(emu: &mut emu::Emu) {
    let millis = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!Sleep cannot read millis");

    println!(
        "{}** {} kernel32!Sleep millis: {} {}",
        emu.colors.light_red, emu.pos, millis, emu.colors.nc
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

    println!("{}** {} kernel32!InitializeCriticalSectionAndSpinCount crit_sect: 0x{:x} spin_count: {} {}", emu.colors.light_red, emu.pos, crit_sect, spin_count, emu.colors.nc);

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

    emu.regs.rax = match emu.maps.alloc(size) {
        Some(sz) => sz,
        None => 0,
    };

    let mem = emu
        .maps
        .create_map(format!("alloc_{:x}", emu.regs.get_eax() as u32).as_str());
    mem.set_base(emu.regs.get_eax());
    mem.set_size(size);

    println!(
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

    println!(
        "{}** {} kernel32!GetProcessAffinityMask {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn IsDebuggerPresent(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!IsDebuggerPresent {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 0; // of course :p
}

fn SetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let callback =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!SetUnhandledExceptionFilter cannot read the callback") as u64;

    println!(
        "{}** {} kernel32!SetUnhandledExceptionFilter  callback: 0x{:x} {}",
        emu.colors.light_red, emu.pos, callback, emu.colors.nc
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

    println!(
        "{}** {} kernel32!UnhandledExceptionFilter  exception_info: 0x{:x} {}",
        emu.colors.light_red, emu.pos, exception_info, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = constants::EXCEPTION_EXECUTE_HANDLER; // a debugger would had answered EXCEPTION_CONTINUE_SEARCH
}

fn GetCurrentProcess(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCurrentProcess {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    emu.regs.rax = match emu.maps.alloc(size) {
        Some(sz) => sz,
        None => 0,
    };

    let mem = emu
        .maps
        .create_map(format!("alloc_{:x}", emu.regs.get_eax() as u32).as_str());
    mem.set_base(emu.regs.get_eax());
    mem.set_size(size);

    println!(
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

    println!(
        "{}** {} kernel32!VirtualAllocExNuma hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc
    );

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAllocExNuma out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    emu.regs.rax = base;

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn GetUserDefaultLangID(emu: &mut emu::Emu) {
    emu.regs.rax = 0x000000000000ffff;
    println!(
        "{}** {} kernel32!GetUserDefaultLangID =0x{:x} {}",
        emu.colors.light_red, emu.pos, emu.regs.rax as u16, emu.colors.nc
    );
}

fn GetProcessHeap(emu: &mut emu::Emu) {
    emu.regs.rax = helper::handler_create("process heap");
    println!(
        "{}** {} kernel32!GetProcessHeap =0x{:x} {}",
        emu.colors.light_red, emu.pos, emu.regs.rax as u32, emu.colors.nc
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

    emu.maps.write_dword(size_ptr, 6);
    emu.maps.write_string(buff_ptr, "medusa");

    println!(
        "{}** {} kernel32!GetComputerName 'medusa' {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
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

    println!(
        "{}** {} kernel32!CreateMutexA '{}' {}",
        emu.colors.light_red, emu.pos, name, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CreateMutexW '{}' {}",
        emu.colors.light_red, emu.pos, name, emu.colors.nc
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
    println!(
        "{}** {} kernel32!GetLastError ={} {}",
        emu.colors.light_red, emu.pos, emu.regs.rax, emu.colors.nc
    );
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

    println!(
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

    println!(
        "{}** {} kernel32!GetSystemTime ptr: 0x{:x}' {}",
        emu.colors.light_red, emu.pos, out_time, emu.colors.nc
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

    println!(
        "{}** {} kernel32!lstrcat '{}'+'{}' {}",
        emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc
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

    println!(
        "{}** {} kernel32!SetErrorMode 0x{:x} {}",
        emu.colors.light_red, emu.pos, mode, emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 0;
}

fn GetVersionExW(emu: &mut emu::Emu) {
    let version_info_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetVersionExW cannot read version_info_ptr param") as u64;

    println!(
        "{}** {} kernel32!GetVersionExW 0x{:x} {}",
        emu.colors.light_red, emu.pos, version_info_ptr, emu.colors.nc
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

    emu.maps.write_string(out_buff_ptr, "C:\\Windows\\");

    println!(
        "{}** {} kernel32!GetSystemDirectoryA  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    emu.maps.write_wide_string(out_buff_ptr, "C:\\Windows\\");

    println!(
        "{}** {} kernel32!GetSystemDirectoryW  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 11 * 2;
}

fn GetStartupInfoA(emu: &mut emu::Emu) {
    let startup_info_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("kernel32!GetStartupInfoA cannot read startup_info_ptr param") as u64;

    println!(
        "{}** {} kernel32!GetStartupInfoA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetStartupInfoW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
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

    println!(
        "{}** {} kernel32!IsProcessorFeaturePresent feature: {} {} {}",
        emu.colors.light_red, emu.pos, feature, msg, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn InitializeCriticalSection(emu: &mut emu::Emu) {
    let ptr_crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!InitializeCriticalSection cannot read ptr_crit_sect");

    emu.stack_pop32(false);

    println!(
        "{}** {} kernel32!InitializeCriticalSection ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr_crit_sect, emu.colors.nc
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

    println!(
        "{}** {} kernel32!InitializeCriticalSectionEx ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr_crit_sect, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FlsAlloc(emu: &mut emu::Emu) {
    let callback = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!FlsAlloc cannot read callback");

    println!(
        "{}** {} kernel32!FlsAlloc callback: 0x{:x} {}",
        emu.colors.light_red, emu.pos, callback, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FlsSetValue idx: {} val: {} {}",
        emu.colors.light_red, emu.pos, idx, val, emu.colors.nc
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

    println!(
        "{}** {} kernel32!SetLastError err: {} {}",
        emu.colors.light_red, emu.pos, err_code, emu.colors.nc
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

    println!(
        "{}** {} kernel32!lstrlen '{}' ={} {}",
        emu.colors.light_red, emu.pos, s, len, emu.colors.nc
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
        wide.push_str("\x00");
    }

    println!(
        "{}** {} kernel32!MultiByteToWideChar '{}' {}",
        emu.colors.light_red, emu.pos, utf8, emu.colors.nc
    );

    emu.maps.write_string(wide_ptr, &wide);
    emu.regs.rax = wide.len() as u64;
}

fn GetSystemInfo(emu: &mut emu::Emu) {
    let out_sysinfo = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!GetSystemInfo cannot read out_sysinfo") as u64;

    println!(
        "{}** {} kernel32!GetSystemInfo sysinfo: 0x{:x} {}",
        emu.colors.light_red, emu.pos, out_sysinfo, emu.colors.nc
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

    println!(
        "{}** {} kernel32!HeapFree mem: 0x{:x} {}",
        emu.colors.light_red, emu.pos, mem, emu.colors.nc
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

    println!(
        "{}** {} kernel32!SetThreadLocale {} {}",
        emu.colors.light_red, emu.pos, locale, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn GetCommandLineW(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCommandlineW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 0;
}

fn GetAcp(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetAcp {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetModuleFileNameW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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
    println!(
        "{}** {} kernel32!RegOpenKeyExW {} {}",
        emu.colors.light_red, emu.pos, subkey, emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn GetUserDefaultUILanguage(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetUserDefaultUILanguage (0x0409 en_US) {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = emu::constants::EN_US_LOCALE as u64;
}

fn EnterCriticalSection(emu: &mut emu::Emu) {
    let crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!EnterCriticalSection cannot read crit_sect");

    println!(
        "{}** {} kernel32!EnterCriticalSection {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn LeaveCriticalSection(emu: &mut emu::Emu) {
    let crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("kernel32!LeaveCriticalSection cannot read crit_sect");

    println!(
        "{}** {} kernel32!LeaveCriticalSection {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 1;
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

    println!(
        "{}** {} kernel32!IsValidLocale {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetThreadUILanguage(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetThreadUILanguage (0x0409 en_US) {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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
    println!(
        "{}** {} kernel32!GetThreadPreferredUILanguages {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.maps.write_dword(out_sz, 0);
    emu.maps.write_dword(num_langs_ptr, 0);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn lstrcmp(emu: &mut emu::Emu) {
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

    println!(
        "{}** {} kernel32!lstrcmp '{}' == '{}' {}",
        emu.colors.light_red, emu.pos, s1, s2, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetNativeSystemInfo {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetTempPathW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FileTimeToLocalFileTime {} {} {}",
        emu.colors.light_red, emu.pos, dwLowDateTime, dwHighDateTime, emu.colors.nc
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

    println!(
        "{}** {} kernel32!FileTimeToDosDateTime {} {} {}",
        emu.colors.light_red, emu.pos, dwLowDateTime, dwHighDateTime, emu.colors.nc
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

    println!(
        "{}** {} kernel32!VirtualQuery 0x{:x} 0x{:x} {} {}",
        emu.colors.light_red, emu.pos, addr, out_buff, size, emu.colors.nc
    );

    if size < 30 {
        println!("buffer to short: {}", size);
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

    println!(
        "{}** {} kernel32!VirtualFree 0x{:x} {} {}",
        emu.colors.light_red, emu.pos, addr, size, emu.colors.nc
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

    println!(
        "{}** {} kernel32!RaiseException {} {} {}",
        emu.colors.light_red, emu.pos, code, flags, emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 0;
    //std::process::exit(1);
}

fn VerifyVersionInfoW(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!VerifyVersionInfoW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!GetTimeZoneInformation {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!VirtualQueryEx 0x{:x} 0x{:x} {} {}",
        emu.colors.light_red, emu.pos, addr, out_buff, size, emu.colors.nc
    );

    if size < 30 {
        println!("buffer to short: {}", size);
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
