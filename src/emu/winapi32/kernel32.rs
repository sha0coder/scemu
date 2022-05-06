use crate::emu;
use crate::emu::winapi32::helper;
use crate::emu::context32;
use crate::emu::constants;
use crate::emu::console;

use lazy_static::lazy_static; 
use std::sync::Mutex;

pub fn gateway(addr:u32, emu:&mut emu::Emu) {
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

        _ => panic!("calling unimplemented kernel32 API 0x{:x}", addr),
    }
}

lazy_static! {
    static ref COUNT_READ:Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE:Mutex<u32> = Mutex::new(0);
}


//// kernel32 API ////


fn GetProcAddress(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetProcAddress cannot read the handle") as u64;
    let func_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetProcAddress cannot read the func name") as u64;

    let func = emu.maps.read_string(func_ptr).to_lowercase();

    //println!("looking for '{}'", func);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    // https://github.com/ssherei/asm/blob/master/get_api.asm

    let peb = emu.maps.get_mem("peb");
    let peb_base = peb.get_base();
    let ldr = peb.read_dword(peb_base + 0x0c) as u64;
    let mut flink = emu.maps.read_dword(ldr + 0x14).expect("kernel32!GetProcAddress error reading flink") as u64;

    loop { // walk modules

        let mod_name_ptr = emu.maps.read_dword(flink + 0x28).expect("kernel32!GetProcAddress error reading mod_name_ptr") as u64;
        let mod_base = emu.maps.read_dword(flink + 0x10).expect("kernel32!GetProcAddress error reading mod_addr") as u64;
        let mod_name = emu.maps.read_wide_string(mod_name_ptr);

        let pe_hdr = match emu.maps.read_dword(mod_base + 0x3c) { //.expect("kernel32!GetProcAddress error reading pe_hdr");
            Some(hdr) => hdr as u64,
            None => { emu.regs.rax = 0; return; }
        };
        let export_table_rva = emu.maps.read_dword(mod_base + pe_hdr + 0x78).expect("kernel32!GetProcAddress error reading export_table_rva") as u64;
        if export_table_rva == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            continue;
        }

        let export_table = export_table_rva + mod_base;
        let mut num_of_funcs = emu.maps.read_dword(export_table + 0x18).expect("kernel32!GetProcAddress error reading the num_of_funcs") as u64;

        let func_name_tbl_rva = emu.maps.read_dword(export_table + 0x20).expect("kernel32!GetProcAddress  error reading func_name_tbl_rva") as u64;
        let func_name_tbl = func_name_tbl_rva + mod_base;

        if num_of_funcs == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            continue;
        }

        loop { // walk functions
                
            num_of_funcs -= 1;
            let func_name_rva = emu.maps.read_dword(func_name_tbl + num_of_funcs * 4).expect("kernel32!GetProcAddress error reading func_rva") as u64;
            let func_name_va = func_name_rva + mod_base;
            let func_name = emu.maps.read_string(func_name_va).to_lowercase();
            
            if func_name == func { 
                let ordinal_tbl_rva = emu.maps.read_dword(export_table + 0x24).expect("kernel32!GetProcAddress error reading ordinal_tbl_rva") as u64;
                let ordinal_tbl = ordinal_tbl_rva + mod_base;
                let ordinal = emu.maps.read_word(ordinal_tbl + 2 * num_of_funcs).expect("kernel32!GetProcAddress error reading ordinal") as u64;
                let func_addr_tbl_rva = emu.maps.read_dword(export_table + 0x1c).expect("kernel32!GetProcAddress  error reading func_addr_tbl_rva") as u64;
                let func_addr_tbl = func_addr_tbl_rva + mod_base;
                
                let func_rva = emu.maps.read_dword(func_addr_tbl + 4 * ordinal).expect("kernel32!GetProcAddress error reading func_rva") as u64;
                let func_va = func_rva + mod_base;

                emu.regs.rax = func_va;

                println!("{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}", emu.colors.light_red, emu.pos, mod_name, func_name, emu.regs.get_eax() as u32, emu.colors.nc);
                return;
            }

            if num_of_funcs == 0 {
                break;
            }
        }

        flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
    } 
}

fn LoadLibraryA(emu:&mut emu::Emu) {
    let dllptr = emu.maps.read_dword(emu.regs.get_esp()).expect("bad LoadLibraryA parameter") as u64;
    let dll = emu.maps.read_string(dllptr);

    if dll.len() == 0 {
        emu.regs.rax = 0;

    } else {

        match dll.to_lowercase().as_str() {
            "ntdll"|"ntdll.dll" => emu.regs.rax = emu.maps.get_mem("ntdll").get_base(),
            "ws2_32"|"ws2_32.dll" => emu.regs.rax = emu.maps.get_mem("ws2_32").get_base(),
            "wininet"|"wininet.dll" => emu.regs.rax = emu.maps.get_mem("wininet").get_base(),
            "advapi32"|"advapi32.dll" => emu.regs.rax = emu.maps.get_mem("advapi32").get_base(),
            "kernel32"|"kernel32.dll" => emu.regs.rax = emu.maps.get_mem("kernel32").get_base(),
            _ => unimplemented!("/!\\ kernel32!LoadLibraryA: lib not found `{}` dllptr:0x{:x}", dll, dllptr),
        }
    }

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, emu.pos, dll, emu.regs.get_eax() as u32, emu.colors.nc);

    emu.stack_pop32(false);
}

fn LoadLibraryExA(emu:&mut emu::Emu) {
    let libname_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32_LoadLibraryExA: error reading libname ptr param") as u64;
    let libname = emu.maps.read_string(libname_ptr);

    println!("{}** {} LoadLibraryExA '{}' {}", emu.colors.light_red, emu.pos, libname, emu.colors.nc);
    panic!();
}

fn LoadLibraryExW(emu:&mut emu::Emu) {
    println!("{}** {} LoadLibraryExW {}", emu.colors.light_red, emu.pos, emu.colors.nc);
}

fn LoadLibraryW(emu:&mut emu::Emu) {
    let dllptr = match emu.maps.read_dword(emu.regs.get_esp()) {
        Some(v) => v as u64,
        None => panic!("bad LoadLibraryW parameter"),
    };
    let dll = emu.maps.read_wide_string(dllptr);
    println!("{}** {} LoadLibraryW  '{}'  {}", emu.colors.light_red, emu.pos, dll, emu.colors.nc);

    if dll == "ntdll.dll" {
        emu.regs.rax = emu.maps.get_mem("ntdll").get_base();
    }

    emu.stack_pop32(false);
}

fn WinExec(emu:&mut emu::Emu) {
    let cmdline_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("cannot read the cmdline parameter of WinExec") as u64;
    let cmdline = emu.maps.read_string(cmdline_ptr);

    //emu.spawn_console();

    println!("{}** {} WinExec  '{}'  {}", emu.colors.light_red, emu.pos, cmdline, emu.colors.nc);

    emu.regs.rax = 0;
    emu.stack_pop32(false);
}

fn GetVersion(emu:&mut emu::Emu) {
    emu.regs.rax = emu::constants::VERSION;
    println!("{}** {} kernel32!GetVersion   =0x{:x}  {}", emu.colors.light_red, emu.pos, emu.regs.get_eax() as u32, emu.colors.nc);
}

fn CreateProcessA(emu:&mut emu::Emu) {
    /*
    [in, optional]      LPCSTR                lpApplicationName,
    [in, out, optional] LPSTR                 lpCommandLine,
    */

    let appname_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CreateProcessA: cannot read stack") as u64;
    let cmdline_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CreateProcessA: cannot read stack2") as u64;
    let appname = emu.maps.read_string(appname_ptr);
    let cmdline = emu.maps.read_string(cmdline_ptr);

    println!("{}** {} kernel32!CreateProcessA  {} {} {}", emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc);

    for _ in 0..10 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn WaitForSingleObject(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!WaitForSingleObject error reading handle") as u64;
    let millis = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!WaitForSingleObject error reading millis");

    println!("{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}", emu.colors.light_red, emu.pos, handle, millis, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = emu::constants::WAIT_TIMEOUT;
}

fn VirtualAlloc(emu:&mut emu::Emu) {
    let addr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!VirtualAlloc error reading addr") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!VirtualAlloc error reading size ptr") as u64;
    let atype = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!VirtualAlloc error reading type"); 
    let protect = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!VirtualAlloc error reading protect");

    let base = emu.maps.alloc(size).expect("kernel32!VirtualAlloc out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    println!("{}** {} kernel32!VirtualAlloc sz: {} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, size, base, emu.colors.nc);

    emu.regs.rax = base;

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn VirtualAllocEx(emu:&mut emu::Emu) {
    let proc_hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!VirtualAllocEx cannot read the proc handle") as u64;
    let addr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!VirtualAllocEx cannot read the address") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!VirtualAllocEx cannot read the size") as u64;
    let alloc_type = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!VirtualAllocEx cannot read the type");
    let protect = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!VirtualAllocEx cannot read the protect");

    println!("{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);

    let base = emu.maps.alloc(size).expect("kernel32!VirtualAllocEx out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);
    
    emu.regs.rax = base;

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
}

fn WriteProcessMemory(emu:&mut emu::Emu) {
    let proc_hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!WriteProcessMemory cannot read the proc handle") as u64;
    let addr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!WriteProcessMemory cannot read the address") as u64;
    let buff = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!WriteProcessMemory cannot read the buffer") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!WriteProcessMemory cannot read the size") as u64;
    let written_ptr = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!WriteProcessMemory cannot read the ptr of num of written bytes");

    println!("{}** {} kernel32!WriteProcessMemory hproc: 0x{:x} from: 0x{:x } to: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, proc_hndl, buff, addr, size, emu.colors.nc);

    if emu.maps.memcpy(buff, addr, size as usize) {
        emu.regs.rax = 1;
        println!("{}\twritten succesfully{}", emu.colors.light_red, emu.colors.nc);
    } else {
        emu.regs.rax = 0;
        println!("{}\tcouldnt write the bytes{}", emu.colors.light_red, emu.colors.nc);
    }

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
}

fn CreateRemoteThread(emu:&mut emu::Emu) {
    let proc_hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CreateRemoteThread cannot read the proc handle") as u64;
    let sec = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CreateRemoteThread cannot read the proc security thread attributs") as u64;
    let stack_size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!CreateRemoteThread cannot read the stack size") as u64;
    let addr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!CreateRemoteThread cannot read the addr") as u64;
    let param = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!CreateRemoteThread cannot read the param");
    let flags = emu.maps.read_dword(emu.regs.get_esp()+20).expect("kernel32!CreateRemoteThread cannot read the flags");
    let out_tid = emu.maps.read_dword(emu.regs.get_esp()+24).expect("kernel32!CreateRemoteThread cannot read the tid") as u64; 

    println!("{}** {} kernel32!CreateRemoteThread hproc: 0x{:x} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);

    emu.maps.write_dword(out_tid, 0x123); 
    emu.regs.rax = helper::handler_create();

    for _ in 0..7 {
        emu.stack_pop32(false);
    }
}

fn CreateNamedPipeA(emu:&mut emu::Emu) {
    let name_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CreateNamedPipeA cannot read the name_ptr") as u64;
    let open_mode = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CreateNamedPipeA cannot read the open_mode");
    let pipe_mode = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!CreateNamedPipeA cannot read the pipe_mode");
    let instances = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!CreateNamedPipeA cannot read the instances");
    let out_buff_sz = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu.maps.read_dword(emu.regs.get_esp()+20).expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu.maps.read_dword(emu.regs.get_esp()+24).expect("kernel32!CreateNamedPipeA cannot read the timeout"); 
    let security = emu.maps.read_dword(emu.regs.get_esp()+28).expect("kernel32!CreateNamedPipeA cannot read the security"); 

    let name = emu.maps.read_string(name_ptr);

    println!("{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}", emu.colors.light_red, emu.pos, name, in_buff_sz, out_buff_sz, emu.colors.nc);

    for _ in 0..8 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = helper::handler_create(); 
}

fn ConnectNamedPipe(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ConnectNamedPipe cannot read the handle") as u64;
    let overlapped = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!ConnectNamedPipe cannot read the overlapped");

    println!("{}** {} kernel32!ConnectNamedPipe hndl: 0x{:x} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);
    if !helper::handler_exist(handle) {
        println!("\tinvalid handle.");
    }
    

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn DisconnectNamedPipe(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!DisconnectNamedPipe cannot read the handle");

    println!("{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn ReadFile(emu:&mut emu::Emu) {
    let file_hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ReadFile cannot read the file_hndl") as u64;
    let buff = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!ReadFile cannot read the buff") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!ReadFile cannot read the size");
    let bytes_read = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!ReadFile cannot read the bytes_read") as u64;
    let overlapped = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!ReadFile cannot read the overlapped");

    let mut count = COUNT_READ.lock().unwrap();
    *count += 1;

    if size == 4 && *count == 1 {
        // probably reading the size
        emu.maps.write_dword(buff, 0x10);
    }

    if *count < 3 { 
        // keep reading bytes
        emu.maps.write_dword(bytes_read, size);
        emu.regs.rax = 1;
    } else {
        // try to force finishing reading and continue the malware logic
        emu.maps.write_dword(bytes_read, 0);
        emu.regs.rax = 0;
    }

    //TODO: write some random bytes to the buffer
    //emu.maps.write_spaced_bytes(buff, "00 00 00 01".to_string());
    
    println!("{}** {} kernel32!ReadFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc);

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    
}

fn WriteFile(emu:&mut emu::Emu) {
    let file_hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!WriteFile cannot read the file_hndl") as u64;
    let buff = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!WriteFile cannot read the buff") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!WriteFile cannot read the size");
    let bytes_written = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!WriteFile cannot read the bytes_written") as u64;
    let overlapped = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!WriteFile cannot read the overlapped");

    let mut count = COUNT_WRITE.lock().unwrap();
    *count += 1;

    emu.maps.write_dword(bytes_written, size);

    println!("{}** {} kernel32!WriteFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc);

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CloseHandle(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CloseHandle cannot read the handle") as u64;

    println!("{}** {} kernel32!CloseHandle 0x{:X} {}", emu.colors.light_red, emu.pos, hndl, emu.colors.nc);

    if !helper::handler_close(hndl) {
        println!("\tinvalid handle.")
    }
    emu.stack_pop32(false);
    emu.regs.rax = 1;

    emu.stack_pop32(false);
}

fn ExitProcess(emu:&mut emu::Emu) {
    let code = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ExitProcess cannot read the exit code");

    println!("{}** {} kernel32!ExitProcess code: {} {}", emu.colors.light_red, emu.pos, code, emu.colors.nc);
    emu.stack_pop32(false);

    std::process::exit(1);
}

fn TerminateProcess(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!TerminateProcess cannot read the handle");
    let code = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!TerminateProcess cannot read the exit code");

    println!("{}** {} kernel32!TerminateProcess hndl: {} code: {} {}", emu.colors.light_red, emu.pos, hndl, code, emu.colors.nc);
    
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn GetThreadContext(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetThreadContext cannot read the handle");
    let ctx_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetThreadContext cannot read the ctx");

    let ctx = context32::Context32::new(&emu.regs);
    ctx.save(ctx_ptr, &mut emu.maps);

    println!("{}** {} kernel32!GetThreadContext  {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn SetThreadContext(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!SetThreadContext cannot read the handle");
    let ctx_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!SetThreadContext cannot read the ctx_ptr");

    println!("{}** {} kernel32!SetThreadContext  {}", emu.colors.light_red, emu.pos, emu.colors.nc);

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

fn ReadProcessMemory(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ReadProcessMemory cannot read the handle");
    let addr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!ReadProcessMemory cannot read the base address");
    let buff = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!ReadProcessMemory cannot read buff");
    let size = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!ReadProcessMemory cannot read size");
    let bytes = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!ReadProcessMemory cannot read bytes") as u64;

    println!("{}** {} kernel32!ReadProcessMemory hndl: {} from: 0x{:x} to: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, hndl, addr, buff, size, emu.colors.nc);

    emu.maps.write_dword(bytes, size);

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn GetCurrentDirectoryW(emu:&mut emu::Emu) {
    let buff_len = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetCurrentDirectoryW cannot read buff_len");
    let buff_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetCurrentDirectoryW cannot read buff_ptr") as u64;

    emu.maps.write_string(buff_ptr, "c\x00:\x00\\\x00\x00\x00\x00\x00");

    println!("{}** {} kernel32!GetCurrentDirectoryW {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 6;
}

fn GetCurrentDirectoryA(emu:&mut emu::Emu) {
    let buff_len = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetCurrentDirectoryW cannot read buff_len");
    let buff_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetCurrentDirectoryW cannot read buff_ptr") as u64;

    emu.maps.write_string(buff_ptr, "c:\\\x00");

    println!("{}** {} kernel32!GetCurrentDirectoryA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 3;
}

fn VirtualProtect(emu:&mut emu::Emu) {
    let addr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!VirtualProtect cannot read addr") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!VirtualProtect cannot read size");
    let new_prot = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!VirtualProtect cannot read new_prot");
    let old_prot_ptr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!VirtualProtect cannot read old_prot") as u64;
    
    emu.maps.write_dword(old_prot_ptr, new_prot);

    println!("{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}", emu.colors.light_red, emu.pos, addr, size, new_prot, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn VirtualProtectEx(emu:&mut emu::Emu) {
    let hproc = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!VirtualProtectEx cannot read hproc") as u64;
    let addr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!VirtualProtectEx cannot read addr") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!VirtualProtectEx cannot read size");
    let new_prot = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!VirtualProtectEx cannot read new_prot");
    let old_prot_ptr = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!VirtualProtectEx cannot read old_prot") as u64;

    emu.maps.write_dword(old_prot_ptr, new_prot);

    println!("{}** {} kernel32!VirtualProtectEx hproc: {} addr: 0x{:x} sz: {} prot: {} {}", emu.colors.light_red, emu.pos, hproc, addr, size, new_prot, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn ResumeThread(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ResumeThread cannot read the handle");
    
    println!("{}** {} kernel32!ResumeThread hndl: {} {}", emu.colors.light_red, emu.pos, hndl, emu.colors.nc);

    emu.stack_pop32(false);

    emu.regs.rax = 1; // previous suspend count
}

fn GetFullPathNameA(emu:&mut emu::Emu) {
    let file_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetFullPathNameA cannot read file_ptr") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetFullPathNameA cannot read size");
    let buff = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!GetFullPathNameA cannot read buff");
    let path = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!GetFullPathNameA cannot read path");

    let filename = emu.maps.read_string(file_ptr);

    println!("{}** {} kernel32!GetFullPathNameA file: {}  {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 10;
}


fn GetFullPathNameW(emu:&mut emu::Emu) {
    let file_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetFullPathNameW cannot read file_ptr") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetFullPathNameW cannot read size");
    let buff = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!GetFullPathNameW cannot read buff");
    let path = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!GetFullPathNameW cannot read path");

    let filename = emu.maps.read_wide_string(file_ptr);

    println!("{}** {} kernel32!GetFullPathNameW file: {}  {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 10;
}

fn SystemTimeToTzSpecificLocalTime(emu:&mut emu::Emu) {
    let tz_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read tz_ptr");
    let ut_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read ut_ptr");
    let lt_ptr = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read lt_ptr");

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn GetLogicalDrives(emu:&mut emu::Emu) {

    println!("{}** {} kernel32!GetLogicalDrives {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 0xc;
}


fn ExpandEnvironmentStringsA(emu:&mut emu::Emu) {
    let src_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ExpandEnvironmentStringsA cannot read src") as u64;
    let dst_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!ExpandEnvironmentStringsA cannot read dst") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!ExpandEnvironmentStringsA cannot read size");

    let src = emu.maps.read_string(src_ptr);

    println!("{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}", emu.colors.light_red, emu.pos, src, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    
    emu.regs.rax = 1;

    //TODO: implement expand
}

fn ExpandEnvironmentStringsW(emu:&mut emu::Emu) {
    let src_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!ExpandEnvironmentStringsW cannot read src") as u64;
    let dst_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!ExpandEnvironmentStringsW cannot read dst") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!ExpandEnvironmentStringsW cannot read size");

    let src = emu.maps.read_wide_string(src_ptr);

    println!("{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}", emu.colors.light_red, emu.pos, src, emu.colors.nc);

    //TODO: implement expand

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    
    emu.regs.rax = 1;
}

fn GetFileAttributesA(emu:&mut emu::Emu) {
    let filename_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetFileAttributesA cannot read filename_ptr") as u64;
    let filename = emu.maps.read_string(filename_ptr);

    println!("{}** {} kernel32!GetFileAttributesA file: {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    emu.regs.rax = 0x123; // file attributes

    emu.stack_pop32(false);

}

fn GetFileAttributesW(emu:&mut emu::Emu) {
    let filename_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetFileAttributesW cannot read filename_ptr") as u64; 
    let filename = emu.maps.read_wide_string(filename_ptr);

    println!("{}** {} kernel32!GetFileAttributesW file: {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    emu.stack_pop32(false);

    emu.regs.rax = 0x123; // file attributes
}

fn FileTimeToSystemTime(emu:&mut emu::Emu) {
    let file_time = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!FileTimeToSystemTime cannot read file_time");
    let sys_time_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!FileTimeToSystemTime cannot read sys_time_ptr");

    println!("{}** {} kernel32!FileTimeToSystemTime {} ", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn FindFirstFileA(emu:&mut emu::Emu) {
    let file_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!FindFirstFileA cannot read file_ptr") as u64;
    let find_data = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!FindFirstFileA cannot read find_data");

    let file = emu.maps.read_string(file_ptr);

    println!("{}** {} kernel32!FindFirstFileA file: {} {}", emu.colors.light_red, emu.pos, file, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn FindFirstFileW(emu:&mut emu::Emu) {
    let file_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!FindFirstFileW cannot read file_ptr") as u64;
    let find_data = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!FindFirstFileW cannot read find_data");

    let file = emu.maps.read_wide_string(file_ptr);

    println!("{}** {} kernel32!FindFirstFileW file: {} {}", emu.colors.light_red, emu.pos, file, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create();
}

fn FindNextFileA(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!FindNextFileA cannot read the handle");
    let find_data = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!FindNextFileA cannot read the find_data");

    println!("{}** {} kernel32!FindNextFileA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn FindNextFileW(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!FindNextFileW cannot read the handle");
    let find_data = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!FindNextFileW cannot read the find_data");

    println!("{}** {} kernel32!FindNextFileW {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn CopyFileA(emu:&mut emu::Emu) {
    let src_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CopyFileA cannot read src_ptr") as u64;
    let dst_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CopyFileA cannot read dst_ptr") as u64;
    let do_fail = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!CopyFileA cannot read do_fail");

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!("{}** {} kernel32!CopyFileA `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn CopyFileW(emu:&mut emu::Emu) {
    let src_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CopyFileW cannot read src_ptr") as u64;
    let dst_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CopyFileW cannot read dst_ptr") as u64;
    let do_fail = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!CopyFileW cannot read do_fail");

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!("{}** {} kernel32!CopyFileW `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn FindClose(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!FindClose cannot read the handle") as u64;

    println!("{}** {} kernel32!FindClose {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);

    helper::handler_close(hndl);
    emu.regs.rax = 1;
}

fn MoveFileA(emu:&mut emu::Emu) {
    let src_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!MoveFileA cannot read src_ptr") as u64;
    let dst_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!MoveFileA cannot read dst_ptr") as u64;

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!("{}** {} kernel32!MoveFileA `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn MoveFileW(emu:&mut emu::Emu) {
    let src_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!MoveFileW cannot read src_ptr") as u64;
    let dst_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!MoveFileW cannot read dst_ptr") as u64;

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!("{}** {} kernel32!MoveFileW `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn OpenProcess(emu:&mut emu::Emu) {
    let access = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!OpenProcess cannot read access");
    let inherit = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!OpenProcess cannot read inherit");
    let pid = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!OpenProcess cannot read pid");

    println!("{}** {} kernel32!OpenProcess pid: {} {}", emu.colors.light_red, emu.pos, pid, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create();
}

fn GetCurrentProcessId(emu:&mut emu::Emu) {

    println!("{}** {} kernel32!GetCurrentProcessId {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 0x123; 
}

fn Thread32First(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!Thread32First cannot read the handle");
    let entry = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!Thread32First cannot read the entry32");

    println!("{}** {} kernel32!Thread32First {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn Thread32Next(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!Thread32Next cannot read the handle");
    let entry = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!Thread32Next cannot read the entry32");
    
    println!("{}** {} kernel32!Thread32Next {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn OpenThread(emu:&mut emu::Emu) {
    let access = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!OpenThread cannot read acess");
    let inherit = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!OpenThread cannot read inherit");
    let tid = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!OpenThread cannot read tid");

    println!("{}** {} kernel32!OpenThread tid: {} {}", emu.colors.light_red, emu.pos, tid, emu.colors.nc);
   
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create();
}

fn CreateToolhelp32Snapshot(emu:&mut emu::Emu) {
    let flags = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CreateToolhelp32Snapshot cannot read flags");
    let pid = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CreateToolhelp32Snapshot cannot read pid");

    println!("{}** {} kernel32!CreateToolhelp32Snapshot pid: {} {}", emu.colors.light_red, emu.pos, pid, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create();
}

fn CreateThread(emu:&mut emu::Emu) {
    let sec_attr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!CreateThread cannot read sec_attr");
    let stack_sz = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!CreateThread cannot read stack_sz");
    let code = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!CreateThread cannot read fptr") as u64;
    let param = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!CreateThread cannot read param"); 
    let flags = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!CreateThread cannot read flags") as u64;
    let tid_ptr = emu.maps.read_dword(emu.regs.get_esp()+20).expect("kernel32!CreateThread cannot read tid_ptr") as u64;

    emu.maps.write_dword(tid_ptr, 0x123);

    println!("{}** {} kernel32!CreateThread code: 0x{:x} {}", emu.colors.light_red, emu.pos, code, emu.colors.nc);

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
            emu.maps.write_dword(emu.regs.get_esp()+4, param);

            // alloc a stack vs reusing stack.
            return;
        } else {
            println!("cannot emulate the thread, the function pointer is not mapped.");
        }
    } 

    emu.regs.rax = helper::handler_create();
}

fn MapViewOfFile(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!MapViewOfFile cannot read the handle");
    let access = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!MapViewOfFile cannot read the acess");
    let off_hight = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!MapViewOfFile cannot read the off_hight") as u64;
    let off_low = emu.maps.read_dword(emu.regs.get_esp()+12).expect("kernel32!MapViewOfFile cannot read the off_low") as u64;
    let size = emu.maps.read_dword(emu.regs.get_esp()+16).expect("kernel32!MapViewOfFile cannot read the size") as u64;

    let off:u64 = (off_hight << 32) + off_low;

    println!("{}** {} kernel32!MapViewOfFile hndl: {} off: {} sz: {} {}", emu.colors.light_red, emu.pos, hndl, off, size, emu.colors.nc);

    let addr = emu.maps.alloc(size).expect("kernel32!MapViewOfFile cannot allocate");
    let mem = emu.maps.create_map("file_map");
    mem.set_base(addr);
    mem.set_size(size);
    //TODO: use mem.load()

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = addr;
}

fn GetSystemTimeAsFileTime(emu:&mut emu::Emu) {
    let sys_time_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetSystemTimeAsFileTime cannot read sys_time_ptr");

    println!("{}** {} kernel32!GetSystemTimeAsFileTime {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn GetCurrentThreadId(emu:&mut emu::Emu) {

    println!("{}** {} kernel32!GetCurrentThreadId {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 0x111; //TODO: track pids and tids
}

fn GetTickCount(emu:&mut emu::Emu) {

    println!("{}** {} kernel32!GetTickCount {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
}

fn QueryPerformanceCounter(emu:&mut emu::Emu) {
    let counter_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!QueryPerformanceCounter cannot read counter_ptr") as u64;

    emu.maps.write_dword(counter_ptr, 0x1);
    

    println!("{}** {} kernel32!QueryPerformanceCounter {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn HeapCreate(emu:&mut emu::Emu) {
    let opts = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!HeapCreate cannot read opts");
    let init_sz = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!HeapCreate cannot read init_sz");
    let max_sz = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!HeapCreate cannot read max_sz");
    
    println!("{}** {} kernel32!HeapCreate initSz: {} maxSz: {}  {}", emu.colors.light_red, emu.pos, init_sz, max_sz, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    
    emu.regs.rax = helper::handler_create();
}

fn GetModuleHandleA(emu:&mut emu::Emu) {
    let mod_name_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetModuleHandleA cannot read mod_name_ptr") as u64;
    let mod_name = emu.maps.read_string(mod_name_ptr);

    println!("{}** {} kernel32!GetModuleHandleA '{}' {}", emu.colors.light_red, emu.pos, mod_name, emu.colors.nc);

    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create();
}

fn GetModuleHandleW(emu:&mut emu::Emu) {
    let mod_name_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetModuleHandleW cannot read mod_name_ptr") as u64;
    let mod_name = emu.maps.read_wide_string(mod_name_ptr);

    println!("{}** {} kernel32!GetModuleHandleW '{}' {}", emu.colors.light_red, emu.pos, mod_name, emu.colors.nc);

    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create();
}

fn TlsAlloc(emu:&mut emu::Emu) { 

    println!("{}** {} kernel32!TlsAlloc {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
}

fn TlsFree(emu:&mut emu::Emu) {
    let idx = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!TlsFree cannot read idx");

    println!("{}** {} kernel32!TlsFree idx: {} {}", emu.colors.light_red, emu.pos, idx, emu.colors.nc);

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn TlsSetValue(emu:&mut emu::Emu) {
    let idx = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!TlsSetValue cannot read idx");
    let val = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!TlsSetValue cannot read val_ptr");

    println!("{}** {} kernel32!TlsSetValue idx: {} val: 0x{:x} {}", emu.colors.light_red, emu.pos, idx, val, emu.colors.nc);

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

fn TlsGetValue(emu:&mut emu::Emu) {
    let idx = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!TlsGetValue cannot read idx");

    emu.stack_pop32(false);

    if idx as usize > emu.tls.len() {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = emu.tls[idx as usize] as u64;
    }

    println!("{}** {} kernel32!TlsGetValue idx: {} =0x{:x} {}", emu.colors.light_red, emu.pos, idx, emu.regs.get_eax() as u32, emu.colors.nc);
}

fn EncodePointer(emu:&mut emu::Emu) {
    let ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!EncodePointer cannot read the pointer") as u64;

    println!("{}** {} kernel32!EncodePointer ptr: 0x{:x} {}", emu.colors.light_red, emu.pos, ptr, emu.colors.nc);

    emu.stack_pop32(false);
    emu.regs.rax = ptr;
}

fn DecodePointer(emu:&mut emu::Emu) {
    let ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!DecodePointer cannot read the pointer") as u64;

    println!("{}** {} kernel32!DecodePointer ptr: 0x{:x} {}", emu.colors.light_red, emu.pos, ptr, emu.colors.nc);

    emu.stack_pop32(false);
    emu.regs.rax = ptr;
}

fn Sleep(emu:&mut emu::Emu) {
    let millis = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!Sleep cannot read millis");

    println!("{}** {} kernel32!Sleep millis: {} {}", emu.colors.light_red, emu.pos, millis, emu.colors.nc);

    emu.stack_pop32(false);
}

fn InitializeCriticalSectionAndSpinCount(emu:&mut emu::Emu) {
    let crit_sect = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!InitializeCriticalSectionAndSpinCount cannot read crit_sect");
    let spin_count = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!InitializeCriticalSectionAndSpinCount cannot read spin_count");

    println!("{}** {} kernel32!InitializeCriticalSectionAndSpinCount crit_sect: 0x{:x} spin_count: {} {}", emu.colors.light_red, emu.pos, crit_sect, spin_count, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn HeapAlloc(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!HeapAlloc cannot read the handle");
    let flags = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!HeapAlloc cannot read the flags");
    let size = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!HeapAlloc cannot read the size") as u64;

    emu.regs.rax = match emu.maps.alloc(size) {
        Some(sz) => sz,
        None => 0,
    };

    let mem = emu.maps.create_map(format!("alloc_{:x}", emu.regs.get_eax() as u32).as_str());
    mem.set_base(emu.regs.get_eax());
    mem.set_size(size);
    
    println!("{}** {} kernel32!HeapAlloc flags: 0x{:x} size: {} =0x{:x} {}", emu.colors.light_red, 
            emu.pos, flags, size, emu.regs.get_eax() as u32, emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn GetProcessAffinityMask(emu:&mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!GetProcessAffinityMask cannot read the handle") as u64;
    let proc_affinity_mask_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("kernel32!GetProcessAffinityMask cannot read the  proc_affinity_mask_ptr") as u64;
    let sys_affinity_mask_ptr = emu.maps.read_dword(emu.regs.get_esp()+8).expect("kernel32!GetProcessAffinityMask cannot read the sys_affinity_mask_ptr") as u64;

    emu.maps.write_dword(proc_affinity_mask_ptr, 0x1337);
    emu.maps.write_dword(sys_affinity_mask_ptr, 0x1337);

    println!("{}** {} kernel32!GetProcessAffinityMask {}", emu.colors.light_red, emu.pos, emu.colors.nc);


    emu.regs.rax = 1;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn IsDebuggerPresent(emu:&mut emu::Emu) {
    println!("{}** {} kernel32!IsDebuggerPresent {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    emu.regs.rax = 0; // of course :p
}

fn SetUnhandledExceptionFilter(emu:&mut emu::Emu) {
    let callback = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!SetUnhandledExceptionFilter cannot read the callback") as u64;

    println!("{}** {} kernel32!SetUnhandledExceptionFilter  callback: 0x{:x} {}", emu.colors.light_red, emu.pos, callback, emu.colors.nc);

    emu.regs.rax = emu.seh;
    emu.seh = callback;

    emu.stack_pop32(false);
}

fn UnhandledExceptionFilter(emu:&mut emu::Emu) {
    let exception_info = emu.maps.read_dword(emu.regs.get_esp()).expect("kernel32!UnhandledExceptionFilter cannot read exception_info");
    
    println!("{}** {} kernel32!UnhandledExceptionFilter  exception_info: 0x{:x} {}", emu.colors.light_red, emu.pos, exception_info, emu.colors.nc);

    emu.stack_pop32(false);
    emu.regs.rax =  constants::EXCEPTION_EXECUTE_HANDLER; // a debugger would had answered EXCEPTION_CONTINUE_SEARCH
}

fn GetCurrentProcess(emu:&mut emu::Emu) {
    println!("{}** {} kernel32!GetCurrentProcess {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    emu.regs.rax = helper::handler_create();
}
