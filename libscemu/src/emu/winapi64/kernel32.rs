use crate::emu;
use crate::emu::console;
use crate::emu::constants;
use crate::emu::peb64;
use crate::emu::winapi32::helper;

use crate::emu::context64;
use lazy_static::lazy_static;
use std::sync::Mutex;

// a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    match addr {
        0x76dc7070 => LoadLibraryA(emu),
        0x76dc6f80 => LoadLibraryW(emu),
        0x76dbe3b0 => LoadLibraryExA(emu),
        0x76dc6640 => LoadLibraryExW(emu),
        0x76dd3690 => GetProcAddress(emu),
        0x76e48d80 => WinExec(emu),
        0x76ff9380 => GetVersion(emu),
        0x76dc70c0 => GetVersionExA(emu),
        0x76dbd910 => GetVersionExW(emu),
        0x76e48840 => CreateProcessA(emu),
        0x76dd1bb0 => CreateProcessW(emu),
        0x76db21e0 => CreateToolhelp32Snapshot(emu),
        0x76e0fdb0 => Process32First(emu),
        0x76e0fcc0 => Process32Next(emu),
        0x76db40a0 => LStrCmpI(emu),
        0x76dfc5d0 => AreFileApiIsAnsi(emu),
        0x76e3e420 => BeginUpdateResourceA(emu),
        0x76dccad0 => OpenProcess(emu),
        0x76dc67a0 => VirtualAlloc(emu),
        0x76dfbbd0 => VirtualAllocEx(emu),
        0x76dfaa70 => Thread32First(emu),
        0x76dfa980 => Thread32Next(emu),
        0x76dcc560 => OpenThread(emu),
        0x76dc3f40 => GetSystemTimeAsFileTime(emu),
        0x76dc3ee0 => GetCurrentThreadId(emu),
        0x76dc5a50 => GetCurrentProcessId(emu),
        0x76dc6500 => QueryPerformanceCounter(emu),
        0x76dd3050 => GetProcessHeap(emu),
        0x76e5a504 => HeapAlloc(emu),
        0x76dc1120 => CreateEventA(emu),
        0x76dc6580 => CreateThread(emu),
        0x76dd2b70 => Sleep(emu),
        0x76dc47c0 => LocalAlloc(emu),
        0x76dfbad0 => WriteProcessMemory(emu),
        0x76dfc4f0 => CreateRemoteThread(emu),
        0x76e12ba0 => CreateNamedPipeA(emu),
        0x76db2540 => CreateNamedPipeW(emu),
        0x76db20d0 => ConnectNamedPipe(emu),
        0x76dfc460 => DisconnectNamedPipe(emu),
        0x76dc1500 => ReadFile(emu),
        0x76dd35a0 => WriteFile(emu),
        0x76e4d350 => CloseHandle(emu),
        0x76e5a404 => ExitProcess(emu),
        0x76dfbca0 => TerminateProcess(emu),
        0x76dd2b20 => WaitForSingleObject(emu),
        0x76db2f40 => GetThreadContext(emu),
        0x76dfbdc0 => ReadProcessMemory(emu),
        0x76dbec50 => GetCurrentDirectoryA(emu),
        0x76dcc580 => GetCurrentDirectoryW(emu),
        0x76db2ef0 => VirtualProtect(emu),
        0x76dfbb70 => VirtualProtectEx(emu),
        0x76dc13a0 => ResumeThread(emu),
        0x76dd3670 => GetFullPathNameA(emu),
        0x76dc76e0 => GetFullPathNameW(emu),
        0x76dfbcb0 => SystemTimeToTzSpecificLocalTime(emu),
        0x76dbb930 => GetLogicalDrives(emu),
        0x76db80a0 => ExpandEnvironmentStringsA(emu),
        0x76dc71b0 => ExpandEnvironmentStringsW(emu),
        0x76dc13e0 => GetFileAttributesA(emu),
        0x76dcbdd0 => GetFileAttributesW(emu),
        0x76dbaf20 => FileTimeToSystemTime(emu),
        0x76dfc380 => FindFirstFileA(emu),
        0x76dcbd80 => FindFirstFileW(emu),
        0x76dfc320 => FindNextFileA(emu),
        0x76dc1910 => FindNextFileW(emu),
        0x76e45620 => CopyFileA(emu),
        0x76db92d0 => CopyFileW(emu),
        0x76dcbd60 => FindClose(emu),
        0x76e3f950 => MoveFileA(emu),
        0x76e3f7f0 => MoveFileW(emu),
        0x76dbd390 => MapViewOfFile(emu),
        0x76dd2b00 => GetTickCount(emu),
        0x76dc64e0 => InitializeCriticalSectionAndSpinCount(emu),
        0x76db2e70 => GetProcessAffinityMask(emu),
        0x76db8290 => IsDebuggerPresent(emu),
        0x76dc9b70 => SetUnhandledExceptionFilter(emu),
        0x76e40330 => UnhandledExceptionFilter(emu),
        0x76dc5cf0 => GetCurrentProcess(emu),
        0x76dfbba0 => VirtualAllocExNuma(emu),
        0x76dfc000 => GetUserDefaultLangId(emu),
        0x76dbec70 => GetComputerNameA(emu),
        0x76dbd130 => GetComputerNameW(emu),
        0x76dc7210 => CreateMutexA(emu),
        0x76dc13c0 => CreateMutexW(emu),
        0x76dd2dd0 => GetLastError(emu),
        0x76dbead0 => CreateFileMappingA(emu),
        0x76dbf9f0 => CreateFileMappingW(emu),
        0x76dd3540 => GetSystemTime(emu),
        0x76dfe110 => lstrcatA(emu),
        0x76dfe070 => lstrcatW(emu),
        0x76dcbdc0 => SetErrorMode(emu),
        0x76dc9450 => GetSystemDirectoryA(emu),
        0x76dc7121 => GetSystemDirectoryW(emu),
        0x76dd1e90 => GetStartupInfoA(emu),
        0x76dc8070 => GetStartupInfoW(emu),
        0x76dfcc80 => IsProcessorFeaturePresent(emu),
        0x76e5a584 => InitializeCriticalSection(emu),
        0x76dc79b0 => InitializeCriticalSectionEx(emu),
        0x76dc7190 => FlsAlloc(emu),
        0x76dd3520 => FlsGetValue(emu),
        0x76dcbd90 => FlsSetValue(emu),
        0x76dd2df0 => SetLastError(emu),
        0x76dfbaa0 => lstrlenA(emu),
        0x76dccaf0 => lstrlenA(emu),
        0x76dc3ec0 => lstrlenW(emu),
        0x76dc5b50 => MultiByteToWideChar(emu),
        0x76dc6f70 => GetSystemInfo(emu),
        0x76dd3070 => HeapFree(emu),
        0x76e5a3b2 => EncodePointer(emu),
        0x76e5a2dc => DecodePointer(emu),

        _ => {
            let api = guess_api_name(emu, addr);
            println!(
                "calling unimplemented kernel32 64bits API 0x{:x} {}",
                addr, api
            );
            return api;
        }
    }

    return String::new();
}

lazy_static! {
    static ref COUNT_READ: Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE: Mutex<u32> = Mutex::new(0);
    pub static ref TICK: Mutex<u64> = Mutex::new(0);
    static ref LAST_ERROR: Mutex<u64> = Mutex::new(0);
}

pub fn dump_module_iat(emu: &mut emu::Emu, module: &str) {
    let mut flink = peb64::Flink::new(emu);
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

        //println!("flink: 0x{:x} first_ptr: 0x{:x}", flink.get_ptr(), first_ptr);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    return 0; //TODO: use Option<>
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

    return (0, String::new(), String::new()); //TODO: use Option<>
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

    match peb64::get_module_base(&dll, emu) {
        Some(base) => {
            // already linked
            if emu.cfg.verbose > 0 {
                println!("dll {} already linked.", dll);
            }
            return base;
        }
        None => {
            // do link
            if std::path::Path::new(&dll_path).exists() {
                let (base, pe_off) = emu.load_pe64(&dll_path, false, 0);
                peb64::dynamic_link_module(base as u64, pe_off, &dll, emu);
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
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!(
        "{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}",
        emu.colors.light_red, emu.pos, dll, emu.regs.rax, emu.colors.nc
    );
}

fn LoadLibraryW(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_wide_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!(
        "{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}",
        emu.colors.light_red, emu.pos, dll, emu.regs.rax, emu.colors.nc
    );
}

fn LoadLibraryExA(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!(
        "{}** {} kernel32!LoadLibraryExA  '{}' =0x{:x} {}",
        emu.colors.light_red, emu.pos, dll, emu.regs.rax, emu.colors.nc
    );
}

fn LoadLibraryExW(emu: &mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_wide_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!(
        "{}** {} kernel32!LoadLibraryExW '{}' =0x{:x} {}",
        emu.colors.light_red, emu.pos, dll, emu.regs.rax, emu.colors.nc
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

                // println!("func name {}!{}", flink.mod_name, ordinal.func_name);

                if ordinal.func_name.to_lowercase() == func {
                    emu.regs.rax = ordinal.func_va;
                    println!(
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
    if emu.cfg.verbose >= 1 {
        println!("kernel32!GetProcAddress error searching {}", func);
    }
}

fn WinExec(emu: &mut emu::Emu) {
    let cmdline_ptr = emu.regs.rcx;
    let cmdline = emu.maps.read_string(cmdline_ptr);

    println!(
        "{}** {} kernel32!WinExec  '{}'  {}",
        emu.colors.light_red, emu.pos, cmdline, emu.colors.nc
    );

    emu.regs.rax = 32;
}

fn GetVersion(emu: &mut emu::Emu) {
    emu.regs.rax = emu::constants::VERSION;
    println!(
        "{}** {} kernel32!GetVersion   =0x{:x}  {}",
        emu.colors.light_red, emu.pos, emu.regs.rax, emu.colors.nc
    );
}

fn GetVersionExW(emu: &mut emu::Emu) {
    let version_info_ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetVersionExW 0x{:x} {}",
        emu.colors.light_red, emu.pos, version_info_ptr, emu.colors.nc
    );

    let os_version_info = emu::structures::OsVersionInfo::new();
    os_version_info.save(version_info_ptr, &mut emu.maps);

    emu.regs.rax = 1;
}

fn GetVersionExA(emu: &mut emu::Emu) {
    let version_info_ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetVersionExA 0x{:x} {}",
        emu.colors.light_red, emu.pos, version_info_ptr, emu.colors.nc
    );

    let os_version_info = emu::structures::OsVersionInfo::new();
    os_version_info.save(version_info_ptr, &mut emu.maps);

    emu.regs.rax = 1;
}

fn CreateToolhelp32Snapshot(emu: &mut emu::Emu) {
    let flags = emu.regs.rcx;
    let pid = emu.regs.rdx;

    println!(
        "{}** {} kernel32!CreateToolhelp32Snapshot flags: {:x} pid: {} {}",
        emu.colors.light_red, emu.pos, flags, pid, emu.colors.nc
    );

    let uri = format!("CreateToolhelp32Snapshot://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn Process32First(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let lppe = emu.regs.rdx;

    println!(
        "{}** {} kernel32!Process32First hndl: {:x} lppe: 0x{:x} {}",
        emu.colors.light_red, emu.pos, handle, lppe, emu.colors.nc
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

    println!(
        "{}** {} kernel32!Process32Next hndl: {:x} lppe: 0x{:x} {}",
        emu.colors.light_red, emu.pos, handle, lppe, emu.colors.nc
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
        println!(
            "{}** {} kernel32!lstrcmpi `{}` == `{}` {}",
            emu.colors.light_red, emu.pos, s1, s2, emu.colors.nc
        );
        emu.regs.rax = 0;
    } else {
        println!(
            "{}** {} kernel32!lstrcmpi `{}` != `{}` {}",
            emu.colors.light_red, emu.pos, s1, s2, emu.colors.nc
        );
        emu.regs.rax = 1;
    }
}

fn AreFileApiIsAnsi(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!AreFileApiIsAnsi {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn BeginUpdateResourceA(emu: &mut emu::Emu) {
    let pFileName = emu.regs.rcx;
    let bDeleteExistingResources = emu.regs.rdx;

    let filename = emu.maps.read_string(pFileName);

    println!(
        "{}** {} kernel32!BeginUpdateResourceA `{}` {} {}",
        emu.colors.light_red, emu.pos, filename, bDeleteExistingResources, emu.colors.nc
    );

    emu.regs.rax = helper::handler_create(&filename);
}

fn OpenProcess(emu: &mut emu::Emu) {
    let access = emu.regs.rcx;
    let inherit = emu.regs.rdx;
    let pid = emu.regs.r8;

    println!(
        "{}** {} kernel32!OpenProcess pid: {} {}",
        emu.colors.light_red, emu.pos, pid, emu.colors.nc
    );

    let uri = format!("pid://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn VirtualAlloc(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let typ = emu.regs.r8;
    let prot = emu.regs.r9;

    let base = emu
        .maps
        .alloc(size)
        .expect("kernel32!VirtualAlloc out of memory");

    println!(
        "{}** {} kernel32!VirtualAlloc addr: 0x{:x} sz: {} = 0x{:x} {}",
        emu.colors.light_red, emu.pos, addr, size, base, emu.colors.nc
    );

    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    emu.regs.rax = base;
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

    println!(
        "{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} sz: {} = 0x{:x} {}",
        emu.colors.light_red, emu.pos, proc_hndl, addr, size, base, emu.colors.nc
    );

    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    emu.regs.rax = base;
    emu.stack_pop64(false);
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
        if written_ptr != 0 && !emu.maps.write_qword(written_ptr, size) {
            println!("kernel32!WriteProcessMemory cannot write on written_ptr");
        }
    } else {
        emu.regs.rax = 0;
        println!(
            "{}\tcouldnt write all the bytes{}",
            emu.colors.light_red, emu.colors.nc
        );
        if written_ptr != 0 && !emu.maps.write_qword(written_ptr, 0) {
            println!("kernel32!WriteProcessMemory cannot write on written_ptr");
        }
    }

    emu.stack_pop64(false);
}

fn Thread32First(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let entry = emu.regs.rdx;

    println!(
        "{}** {} kernel32!Thread32First {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
    //emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn Thread32Next(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let entry = emu.regs.rdx;

    println!(
        "{}** {} kernel32!Thread32Next {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn OpenThread(emu: &mut emu::Emu) {
    let access = emu.regs.rcx;
    let inherit = emu.regs.rdx;
    let tid = emu.regs.r8;

    println!(
        "{}** {} kernel32!OpenThread tid: {} {}",
        emu.colors.light_red, emu.pos, tid, emu.colors.nc
    );

    let uri = format!("tid://{}", tid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetSystemTimeAsFileTime(emu: &mut emu::Emu) {
    let sys_time_ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetSystemTimeAsFileTime {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetCurrentThreadId(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCurrentThreadId {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 0x111; //TODO: track pids and tids
}

fn GetCurrentProcessId(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCurrentProcessId {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 0x123;
}

fn QueryPerformanceCounter(emu: &mut emu::Emu) {
    let counter_ptr = emu.regs.rcx;

    emu.maps.write_dword(counter_ptr, 0x1);

    println!(
        "{}** {} kernel32!QueryPerformanceCounter {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetProcessHeap(emu: &mut emu::Emu) {
    emu.regs.rax = helper::handler_create("heap");

    println!(
        "{}** {} kernel32!GetProcessHeap ={} {}",
        emu.colors.light_red, emu.pos, emu.regs.rax, emu.colors.nc
    );
}

fn HeapAlloc(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let size = emu.regs.r8;

    emu.regs.rax = match emu.maps.alloc(size) {
        Some(sz) => sz,
        None => 0,
    };

    let mem = emu
        .maps
        .create_map(format!("alloc_{:x}", emu.regs.rax).as_str());
    mem.set_base(emu.regs.rax);
    mem.set_size(size);

    println!(
        "{}** {} kernel32!HeapAlloc flags: 0x{:x} size: {} =0x{:x} {}",
        emu.colors.light_red, emu.pos, flags, size, emu.regs.rax, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CreateEventA attr: 0x{:x} manual_reset: {} init_state: {} name: {} {}",
        emu.colors.light_red, emu.pos, attributes, bManualReset, bInitialState, name, emu.colors.nc
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
        .expect("kernel32!CreateThread cannot read flags") as u64;
    let tid_ptr = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("kernel32!CreateThread cannot read tid_ptr") as u64;

    emu.maps.write_dword(tid_ptr, 0x123);

    println!(
        "{}** {} kernel32!CreateThread code: 0x{:x} param: 0x{:x} {}",
        emu.colors.light_red, emu.pos, code, param, emu.colors.nc
    );

    for _ in 0..2 {
        emu.stack_pop64(false);
    }

    if flags == constants::CREATE_SUSPENDED {
        println!("\tcreated suspended!");
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
            println!("cannot emulate the thread, the function pointer is not mapped.");
        }
    }

    emu.regs.rax = helper::handler_create("tid://0x123");
}

fn Sleep(emu: &mut emu::Emu) {
    let millis = emu.regs.rcx;

    println!(
        "{}** {} kernel32!Sleep millis: {} {}",
        emu.colors.light_red, emu.pos, millis, emu.colors.nc
    );
    let mut tick = TICK.lock().unwrap();
    *tick += millis;
}

fn LocalAlloc(emu: &mut emu::Emu) {
    let flags = emu.regs.rcx;
    let bytes = emu.regs.rdx;

    println!(
        "{}** {} kernel32!LocalAlloc flags: {:x} sz: {} {}",
        emu.colors.light_red, emu.pos, flags, bytes, emu.colors.nc
    );

    let base = emu
        .maps
        .alloc(bytes)
        .expect("kernel32!LocalAlloc out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(bytes);

    emu.regs.rax = base;
}

fn CreateProcessA(emu: &mut emu::Emu) {
    let appname_ptr = emu.regs.rcx;
    let cmdline_ptr = emu.regs.rdx;
    let appname = emu.maps.read_string(appname_ptr);
    let cmdline = emu.maps.read_string(cmdline_ptr);

    println!(
        "{}** {} kernel32!CreateProcessA  {} {} {}",
        emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CreateProcessW(emu: &mut emu::Emu) {
    let appname_ptr = emu.regs.rcx;
    let cmdline_ptr = emu.regs.rdx;
    let appname = emu.maps.read_wide_string(appname_ptr);
    let cmdline = emu.maps.read_wide_string(cmdline_ptr);

    println!(
        "{}** {} kernel32!CreateProcessW  {} {} {}",
        emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc
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

    println!(
        "{}** {} kernel32!CreateRemoteThread hproc: 0x{:x} addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc
    );

    emu.maps.write_dword(out_tid, 0x123);
    emu.regs.rax = helper::handler_create("tid://0x123");

    emu.stack_pop64(false);
    emu.stack_pop64(false);
    emu.stack_pop64(false);
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

    println!(
        "{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}",
        emu.colors.light_red, emu.pos, name, in_buff_sz, out_buff_sz, emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop64(false);
    }

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

    println!(
        "{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}",
        emu.colors.light_red, emu.pos, name, in_buff_sz, out_buff_sz, emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop64(false);
    }

    emu.regs.rax = helper::handler_create(&name);
}

fn ConnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let overlapped = emu.regs.rdx;

    println!(
        "{}** {} kernel32!ConnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red, emu.pos, handle, emu.colors.nc
    );

    if !helper::handler_exist(handle) {
        println!("\tinvalid handle.");
    }

    emu.regs.rax = 1;
}

fn DisconnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;

    println!(
        "{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}",
        emu.colors.light_red, emu.pos, handle, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ReadFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    emu.stack_pop64(false);
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

    println!(
        "{}** {} kernel32!WriteFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    emu.stack_pop64(false);
    emu.regs.rax = 1;
}

fn CloseHandle(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;

    println!(
        "{}** {} kernel32!CloseHandle 0x{:X} {}",
        emu.colors.light_red, emu.pos, handle, emu.colors.nc
    );

    if !helper::handler_close(handle) {
        println!("\tinvalid handle.")
    }
    emu.regs.rax = 1;
}

fn ExitProcess(emu: &mut emu::Emu) {
    let code = emu.regs.rcx;

    println!(
        "{}** {} kernel32!ExitProcess code: {} {}",
        emu.colors.light_red, emu.pos, code, emu.colors.nc
    );
    std::process::exit(1);
}

fn TerminateProcess(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let code = emu.regs.rdx;

    println!(
        "{}** {} kernel32!TerminateProcess hndl: {} code: {} {}",
        emu.colors.light_red, emu.pos, hndl, code, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn WaitForSingleObject(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let millis = emu.regs.rdx;

    println!(
        "{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}",
        emu.colors.light_red, emu.pos, hndl, millis, emu.colors.nc
    );

    emu.regs.rax = emu::constants::WAIT_TIMEOUT;
}

fn GetThreadContext(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let ctx_ptr = emu.regs.rdx;

    let ctx = context64::Context64::new(&emu.regs);
    ctx.save(ctx_ptr, &mut emu.maps);

    println!(
        "{}** {} kernel32!GetThreadContext  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    println!(
        "{}** {} kernel32!ReadProcessMemory hndl: {} from: 0x{:x} to: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, hndl, addr, buff, size, emu.colors.nc
    );

    emu.maps.write_qword(bytes, size);
    emu.maps.memset(buff, 0x90, size as usize);

    emu.stack_pop64(false);
    emu.regs.rax = 1;
}

fn GetCurrentDirectoryA(emu: &mut emu::Emu) {
    let buff_len = emu.regs.rcx;
    let buff_ptr = emu.regs.rdx;

    emu.maps.write_string(buff_ptr, "c:\\\x00");
    println!(
        "{}** {} kernel32!GetCurrentDirectoryA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 3;
}

fn GetCurrentDirectoryW(emu: &mut emu::Emu) {
    let buff_len = emu.regs.rcx;
    let buff_ptr = emu.regs.rdx;

    emu.maps
        .write_string(buff_ptr, "c\x00:\x00\\\x00\x00\x00\x00\x00");
    println!(
        "{}** {} kernel32!GetCurrentDirectoryW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 6;
}

fn VirtualProtect(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let new_prot = emu.regs.r8;
    let old_prot_ptr = emu.regs.r9;

    emu.maps.write_qword(old_prot_ptr, new_prot);

    println!(
        "{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red, emu.pos, addr, size, new_prot, emu.colors.nc
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

    println!(
        "{}** {} kernel32!VirtualProtectEx hproc: {} addr: 0x{:x} sz: {} prot: {} {}",
        emu.colors.light_red, emu.pos, hproc, addr, size, new_prot, emu.colors.nc
    );

    emu.stack_pop64(false);
    emu.regs.rax = 1;
}

fn ResumeThread(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    println!(
        "{}** {} kernel32!ResumeThread hndl: {} {}",
        emu.colors.light_red, emu.pos, hndl, emu.colors.nc
    );

    emu.regs.rax = 1; // previous suspend count
}

fn GetFullPathNameA(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let buff = emu.regs.r8;
    let path = emu.regs.r9;

    let filename = emu.maps.read_string(file_ptr);
    println!(
        "{}** {} kernel32!GetFullPathNameA file: {}  {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
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
    println!(
        "{}** {} kernel32!GetFullPathNameW file: {}  {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
    );
    // TODO: save the path to buff.
    emu.regs.rax = 10;
}

fn SystemTimeToTzSpecificLocalTime(emu: &mut emu::Emu) {
    let tz_ptr = emu.regs.rcx;
    let ut_ptr = emu.regs.rcx;
    let lt_ptr = emu.regs.r8;

    println!(
        "{}** {} kernel32!SystemTimeToTzSpecificLocalTime {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

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
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let size = emu.regs.r8;

    let src = emu.maps.read_string(src_ptr);

    println!(
        "{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}",
        emu.colors.light_red, emu.pos, src, emu.colors.nc
    );
    // TODO: expand typical environment varsl.
    emu.regs.rax = 1;
}

fn ExpandEnvironmentStringsW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let size = emu.regs.r8;

    let src = emu.maps.read_wide_string(src_ptr);

    println!(
        "{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}",
        emu.colors.light_red, emu.pos, src, emu.colors.nc
    );
    // TODO: expand typical environment varsl.
    emu.regs.rax = 1;
}

fn GetFileAttributesA(emu: &mut emu::Emu) {
    let filename_ptr = emu.regs.rcx;
    let filename = emu.maps.read_string(filename_ptr);

    println!(
        "{}** {} kernel32!GetFileAttributesA file: {} {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
    );
    emu.regs.rax = 0x123;
}

fn GetFileAttributesW(emu: &mut emu::Emu) {
    let filename_ptr = emu.regs.rcx;
    let filename = emu.maps.read_wide_string(filename_ptr);

    println!(
        "{}** {} kernel32!GetFileAttributesW file: {} {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
    );
    emu.regs.rax = 0x123;
}

fn FileTimeToSystemTime(emu: &mut emu::Emu) {
    let file_time = emu.regs.rcx;
    let sys_time_ptr = emu.regs.rdx;

    println!(
        "{}** {} kernel32!FileTimeToSystemTime {} ",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn FindFirstFileA(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    let file = emu.maps.read_string(file_ptr);
    println!(
        "{}** {} kernel32!FindFirstFileA file: {} {}",
        emu.colors.light_red, emu.pos, file, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn FindFirstFileW(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    let file = emu.maps.read_wide_string(file_ptr);
    println!(
        "{}** {} kernel32!FindFirstFileW file: {} {}",
        emu.colors.light_red, emu.pos, file, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn FindNextFileA(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    println!(
        "{}** {} kernel32!FindNextFileA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn FindNextFileW(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    println!(
        "{}** {} kernel32!FindNextFileW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn CopyFileA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let do_fail = emu.regs.r8;

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!(
        "{}** {} kernel32!CopyFileA `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CopyFileW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let do_fail = emu.regs.r8;

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!(
        "{}** {} kernel32!CopyFileW `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FindClose(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    println!(
        "{}** {} kernel32!FindClose {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    helper::handler_close(hndl);
    emu.regs.rax = 1;
}

fn MoveFileA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!(
        "{}** {} kernel32!MoveFileA `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn MoveFileW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!(
        "{}** {} kernel32!MoveFileW `{}` to `{}` {}",
        emu.colors.light_red, emu.pos, src, dst, emu.colors.nc
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

    emu.stack_pop64(false);
    emu.regs.rax = addr;
}

fn GetTickCount(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetTickCount {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    let tick = TICK.lock().unwrap();
    emu.regs.rax = *tick;
}

fn InitializeCriticalSectionAndSpinCount(emu: &mut emu::Emu) {
    let crit_sect = emu.regs.rcx;
    let spin_count = emu.regs.rdx;

    println!("{}** {} kernel32!InitializeCriticalSectionAndSpinCount crit_sect: 0x{:x} spin_count: {} {}", emu.colors.light_red, 
        emu.pos, crit_sect, spin_count, emu.colors.nc);

    emu.regs.rax = 1;
}

fn GetProcessAffinityMask(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let proc_affinity_mask_ptr = emu.regs.rdx;
    let sys_affinity_mask_ptr = emu.regs.r8;

    emu.maps.write_dword(proc_affinity_mask_ptr, 0x1337);
    emu.maps.write_dword(sys_affinity_mask_ptr, 0x1337);

    println!(
        "{}** {} kernel32!GetProcessAffinityMask {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn IsDebuggerPresent(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!IsDebuggerPresent {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 0; // of course :p
}

fn SetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let callback = emu.regs.rcx;

    println!(
        "{}** {} kernel32!SetUnhandledExceptionFilter  callback: 0x{:x} {}",
        emu.colors.light_red, emu.pos, callback, emu.colors.nc
    );

    emu.regs.rax = emu.seh;
    emu.seh = callback;
}

fn UnhandledExceptionFilter(emu: &mut emu::Emu) {
    let exception_info = emu.regs.rcx;

    println!(
        "{}** {} kernel32!UnhandledExceptionFilter  exception_info: 0x{:x} {}",
        emu.colors.light_red, emu.pos, exception_info, emu.colors.nc
    );

    emu.regs.rax = constants::EXCEPTION_EXECUTE_HANDLER; // a debugger would had answered EXCEPTION_CONTINUE_SEARCH
}

fn GetCurrentProcess(emu: &mut emu::Emu) {
    println!(
        "{}** {} kernel32!GetCurrentProcess {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
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

    emu.stack_pop64(false);

    emu.regs.rax = base;
}

fn GetUserDefaultLangId(emu: &mut emu::Emu) {
    emu.regs.rax = 0x000000000000ffff;
    println!(
        "{}** {} kernel32!GetUserDefaultLangID =0x{:x} {}",
        emu.colors.light_red, emu.pos, emu.regs.rax as u16, emu.colors.nc
    );
}

fn GetComputerNameA(emu: &mut emu::Emu) {
    let buff_ptr = emu.regs.rcx;
    let size_ptr = emu.regs.rdx;

    emu.maps.write_dword(size_ptr, 6);
    emu.maps.write_string(buff_ptr, "medusa");

    println!(
        "{}** {} kernel32!GetComputerNameA 'medusa' {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn GetComputerNameW(emu: &mut emu::Emu) {
    let buff_ptr = emu.regs.rcx;
    let size_ptr = emu.regs.rdx;

    emu.maps.write_dword(size_ptr, 12);
    emu.maps.write_wide_string(buff_ptr, "medusa");

    println!(
        "{}** {} kernel32!GetComputerNameW 'medusa' {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn CreateMutexA(emu: &mut emu::Emu) {
    let attr = emu.regs.rcx;
    let owner = emu.regs.rdx;
    let name_ptr = emu.regs.r8;

    let name = emu.maps.read_string(name_ptr);

    println!(
        "{}** {} kernel32!CreateMutexA '{}' {}",
        emu.colors.light_red, emu.pos, name, emu.colors.nc
    );

    let uri = format!("mutex://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateMutexW(emu: &mut emu::Emu) {
    let attr = emu.regs.rcx;
    let owner = emu.regs.rdx;
    let name_ptr = emu.regs.r8;

    let name = emu.maps.read_wide_string(name_ptr);

    println!(
        "{}** {} kernel32!CreateMutexA '{}' {}",
        emu.colors.light_red, emu.pos, name, emu.colors.nc
    );

    let uri = format!("mutex://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetLastError(emu: &mut emu::Emu) {
    let err = LAST_ERROR.lock().unwrap();
    emu.regs.rax = *err;
    println!(
        "{}** {} kernel32!GetLastError ={} {}",
        emu.colors.light_red, emu.pos, emu.regs.rax, emu.colors.nc
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
    println!(
        "{}** {} kernel32!CreateFileMappingA '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.regs.get_eax(),
        emu.colors.nc
    );
    emu.stack_pop64(false);
    emu.stack_pop64(false);
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
    println!(
        "{}** {} kernel32!CreateFileMappingW '{}' ={} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.regs.get_eax(),
        emu.colors.nc
    );
    emu.stack_pop64(false);
    emu.stack_pop64(false);
}

fn GetSystemTime(emu: &mut emu::Emu) {
    let out_time = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetSystemTime ptr: 0x{:x}' {}",
        emu.colors.light_red, emu.pos, out_time, emu.colors.nc
    );

    let systime = emu::structures::SystemTime::now();
    systime.save(out_time, &mut emu.maps);
}

fn lstrcatA(emu: &mut emu::Emu) {
    let str1_ptr = emu.regs.rcx;
    let str2_ptr = emu.regs.rdx;

    let mut str1 = emu.maps.read_string(str1_ptr);
    let str2 = emu.maps.read_string(str2_ptr);

    println!(
        "{}** {} kernel32!lstrcatA '{}'+'{}' {}",
        emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc
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

    println!(
        "{}** {} kernel32!lstrcatW '{}'+'{}' {}",
        emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc
    );

    str1.push_str(&str2);
    emu.maps.write_wide_string(str1_ptr, &str1);

    emu.regs.rax = 1;
}

fn SetErrorMode(emu: &mut emu::Emu) {
    let mode = emu.regs.rcx;

    println!(
        "{}** {} kernel32!SetErrorMode 0x{:x} {}",
        emu.colors.light_red, emu.pos, mode, emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn GetSystemDirectoryA(emu: &mut emu::Emu) {
    let out_buff_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;

    emu.maps.write_string(out_buff_ptr, "C:\\Windows\\");

    println!(
        "{}** {} kernel32!GetSystemDirectoryW  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 11;
}

fn GetSystemDirectoryW(emu: &mut emu::Emu) {
    let out_buff_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;

    emu.maps.write_wide_string(out_buff_ptr, "C:\\Windows\\");

    println!(
        "{}** {} kernel32!GetSystemDirectoryW  {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 11 * 2;
}

fn GetStartupInfoA(emu: &mut emu::Emu) {
    let startup_info_ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetStartupInfoA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    if startup_info_ptr > 0 {
        let startupinfo = emu::structures::StartupInfo64::new();
        startupinfo.save(startup_info_ptr, &mut emu.maps);
    }
}

fn GetStartupInfoW(emu: &mut emu::Emu) {
    let startup_info_ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetStartupInfoW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    if startup_info_ptr > 0 {
        let startupinfo = emu::structures::StartupInfo64::new();
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

    println!(
        "{}** {} kernel32!IsProcessorFeaturePresent feature: {} {} {}",
        emu.colors.light_red, emu.pos, feature, msg, emu.colors.nc
    );
    emu.regs.rax = 1;
}

fn InitializeCriticalSection(emu: &mut emu::Emu) {
    let ptr_crit_sect = emu.regs.rcx;

    println!(
        "{}** {} kernel32!InitializeCriticalSection ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr_crit_sect, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn InitializeCriticalSectionEx(emu: &mut emu::Emu) {
    let ptr_crit_sect = emu.regs.rcx;
    let spin_count = emu.regs.rdx;
    let flags = emu.regs.r9;

    println!(
        "{}** {} kernel32!InitializeCriticalSectionEx ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr_crit_sect, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FlsAlloc(emu: &mut emu::Emu) {
    let callback = emu.regs.rcx;

    println!(
        "{}** {} kernel32!FlsAlloc callback: 0x{:x} {}",
        emu.colors.light_red, emu.pos, callback, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn FlsSetValue(emu: &mut emu::Emu) {
    let idx = emu.regs.rcx;
    let val = emu.regs.rdx as u32;

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

    emu.regs.rax = 1;
}

fn SetLastError(emu: &mut emu::Emu) {
    let err_code = emu.regs.rcx;

    println!(
        "{}** {} kernel32!SetLastError err: {} {}",
        emu.colors.light_red, emu.pos, err_code, emu.colors.nc
    );
    let mut err = LAST_ERROR.lock().unwrap();
    *err = err_code;
}

fn lstrlenA(emu: &mut emu::Emu) {
    let s_ptr = emu.regs.rcx;

    let s = emu.maps.read_string(s_ptr);
    let len = s.len() as u64;

    println!(
        "{}** {} kernel32!lstrlen '{}' ={} {}",
        emu.colors.light_red, emu.pos, s, len, emu.colors.nc
    );

    emu.regs.rax = len;
}

fn lstrlenW(emu: &mut emu::Emu) {
    let s_ptr = emu.regs.rcx;

    let s = emu.maps.read_wide_string(s_ptr);
    let len = s.len() as u64;

    println!(
        "{}** {} kernel32!lstrlen '{}' ={} {}",
        emu.colors.light_red, emu.pos, s, len, emu.colors.nc
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

    emu.stack_pop64(false);
    emu.stack_pop64(false);

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
    let out_sysinfo = emu.regs.rcx;

    println!(
        "{}** {} kernel32!GetSystemInfo sysinfo: 0x{:x} {}",
        emu.colors.light_red, emu.pos, out_sysinfo, emu.colors.nc
    );

    let mut sysinfo = emu::structures::SystemInfo64::new();
    sysinfo.save(out_sysinfo, &mut emu.maps);
}

fn HeapFree(emu: &mut emu::Emu) {
    let heap = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let mem = emu.regs.r8;

    println!(
        "{}** {} kernel32!HeapFree mem: 0x{:x} {}",
        emu.colors.light_red, emu.pos, mem, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn EncodePointer(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!EncodePointer ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr, emu.colors.nc
    );

    emu.regs.rax = ptr;
}

fn DecodePointer(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;

    println!(
        "{}** {} kernel32!DecodePointer ptr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, ptr, emu.colors.nc
    );

    emu.regs.rax = ptr;
}
