use crate::emu32;
use crate::emu32::winapi::helper;
use crate::emu32::context;
use crate::emu32::constants;
use crate::emu32::console;

use lazy_static::lazy_static; 
use std::sync::Mutex;

pub fn gateway(addr:u32, emu:&mut emu32::Emu32) {
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
        0x75eff02b => EncodePointer(emu),

        _ => panic!("calling unimplemented kernel32 API 0x{:x}", addr),
    }
}

lazy_static! {
    static ref COUNT_READ:Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE:Mutex<u32> = Mutex::new(0);
}


//// kernel32 API ////


fn GetProcAddress(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetProcAddress cannot read the handle");
    let func_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!GetProcAddress cannot read the func name");

    let func = emu.maps.read_string(func_ptr).to_lowercase();

    //println!("looking for '{}'", func);

    // https://github.com/ssherei/asm/blob/master/get_api.asm

    let peb = emu.maps.get_mem("peb");
    let peb_base = peb.get_base();
    let ldr = peb.read_dword(peb_base + 0x0c);
    let mut flink = emu.maps.read_dword(ldr + 0x14).expect("kernel32!GetProcAddress error reading flink");

    loop { // walk modules

        let mod_name_ptr = emu.maps.read_dword(flink + 0x28).expect("kernel32!GetProcAddress error reading mod_name_ptr");
        let mod_base = emu.maps.read_dword(flink + 0x10).expect("kernel32!GetProcAddress error reading mod_addr");
        let mod_name = emu.maps.read_wide_string(mod_name_ptr);

        let pe_hdr = match emu.maps.read_dword(mod_base + 0x3c) { //.expect("kernel32!GetProcAddress error reading pe_hdr");
            Some(hdr) => hdr,
            None => { emu.regs.eax = 0; return; }
        };
        let export_table_rva = emu.maps.read_dword(mod_base + pe_hdr + 0x78).expect("kernel32!GetProcAddress error reading export_table_rva");
        if export_table_rva == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink");
            continue;
        }

        let export_table = export_table_rva + mod_base;
        let mut num_of_funcs = emu.maps.read_dword(export_table + 0x18).expect("kernel32!GetProcAddress error reading the num_of_funcs");

        let func_name_tbl_rva = emu.maps.read_dword(export_table + 0x20).expect("kernel32!GetProcAddress  error reading func_name_tbl_rva");
        let func_name_tbl = func_name_tbl_rva + mod_base;

        if num_of_funcs == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink");                
            continue;
        }

        loop { // walk functions
                
            num_of_funcs -= 1;
            let func_name_rva = emu.maps.read_dword(func_name_tbl + num_of_funcs * 4).expect("kernel32!GetProcAddress error reading func_rva");
            let func_name_va = func_name_rva + mod_base;
            let func_name = emu.maps.read_string(func_name_va).to_lowercase();
            
            if func_name == func { 
                let ordinal_tbl_rva = emu.maps.read_dword(export_table + 0x24).expect("kernel32!GetProcAddress error reading ordinal_tbl_rva");
                let ordinal_tbl = ordinal_tbl_rva + mod_base;
                let ordinal = emu.maps.read_word(ordinal_tbl + 2 * num_of_funcs).expect("kernel32!GetProcAddress error reading ordinal");
                let func_addr_tbl_rva = emu.maps.read_dword(export_table + 0x1c).expect("kernel32!GetProcAddress  error reading func_addr_tbl_rva");
                let func_addr_tbl = func_addr_tbl_rva + mod_base;
                
                let func_rva = emu.maps.read_dword(func_addr_tbl + 4 * ordinal as u32).expect("kernel32!GetProcAddress error reading func_rva");
                let func_va = func_rva + mod_base;

                emu.regs.eax = func_va;

                println!("{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}", emu.colors.light_red, emu.pos, mod_name, func_name, emu.regs.eax, emu.colors.nc);
                return;
            }

            if num_of_funcs == 0 {
                break;
            }
        }

        flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink");
    } 
}

fn LoadLibraryA(emu:&mut emu32::Emu32) {
    let dllptr = emu.maps.read_dword(emu.regs.esp).expect("bad LoadLibraryA parameter");
    let dll = emu.maps.read_string(dllptr);

    match dll.to_lowercase().as_str() {
        "ntdll"|"ntdll.dll" => emu.regs.eax = emu.maps.get_mem("ntdll").get_base(),
        "ws2_32"|"ws2_32.dll" => emu.regs.eax = emu.maps.get_mem("ws2_32").get_base(),
        "wininet"|"wininet.dll" => emu.regs.eax = emu.maps.get_mem("wininet").get_base(),
        "advapi32"|"advapi32.dll" => emu.regs.eax = emu.maps.get_mem("advapi32").get_base(),
        "kernel32"|"kernel32.dll" => emu.regs.eax = emu.maps.get_mem("kernel32").get_base(),
        _ => unimplemented!("/!\\ kernel32!LoadLibraryA: lib not found {}", dll),
    }

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, emu.pos, dll, emu.regs.eax, emu.colors.nc);

    emu.stack_pop(false);
}

fn LoadLibraryExA(emu:&mut emu32::Emu32) {
    let libname_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32_LoadLibraryExA: error reading libname ptr param");
    let libname = emu.maps.read_string(libname_ptr);

    println!("{}** {} LoadLibraryExA '{}' {}", emu.colors.light_red, emu.pos, libname, emu.colors.nc);
    panic!();
}

fn LoadLibraryExW(emu:&mut emu32::Emu32) {
    println!("{}** {} LoadLibraryExW {}", emu.colors.light_red, emu.pos, emu.colors.nc);
}

fn LoadLibraryW(emu:&mut emu32::Emu32) {
    let dllptr = match emu.maps.read_dword(emu.regs.esp) {
        Some(v) => v,
        None => panic!("bad LoadLibraryW parameter"),
    };
    let dll = emu.maps.read_wide_string(dllptr);
    println!("{}** {} LoadLibraryW  '{}'  {}", emu.colors.light_red, emu.pos, dll, emu.colors.nc);

    if dll == "ntdll.dll" {
        emu.regs.eax = emu.maps.get_mem("ntdll").get_base();
    }

    emu.stack_pop(false);
}

fn WinExec(emu:&mut emu32::Emu32) {
    let cmdline_ptr = emu.maps.read_dword(emu.regs.esp).expect("cannot read the cmdline parameter of WinExec");
    let cmdline = emu.maps.read_string(cmdline_ptr);

    //emu.spawn_console();

    println!("{}** {} WinExec  '{}'  {}", emu.colors.light_red, emu.pos, cmdline, emu.colors.nc);

    emu.regs.eax = 0;
    emu.stack_pop(false);
}

fn GetVersion(emu:&mut emu32::Emu32) {
    emu.regs.eax = emu32::constants::VERSION;
    println!("{}** {} kernel32!GetVersion   =0x{:x}  {}", emu.colors.light_red, emu.pos, emu.regs.eax, emu.colors.nc);
}

fn CreateProcessA(emu:&mut emu32::Emu32) {
    /*
    [in, optional]      LPCSTR                lpApplicationName,
    [in, out, optional] LPSTR                 lpCommandLine,
    */

    let appname_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CreateProcessA: cannot read stack");
    let cmdline_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CreateProcessA: cannot read stack2");
    let appname = emu.maps.read_string(appname_ptr);
    let cmdline = emu.maps.read_string(cmdline_ptr);

    println!("{}** {} kernel32!CreateProcessA  {} {} {}", emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc);

    for _ in 0..10 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1;
}

fn WaitForSingleObject(emu:&mut emu32::Emu32) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("kernel32!WaitForSingleObject error reading handle");
    let millis = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!WaitForSingleObject error reading millis");

    println!("{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}", emu.colors.light_red, emu.pos, handle, millis, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.regs.eax = emu32::constants::WAIT_TIMEOUT;
}

fn VirtualAlloc(emu:&mut emu32::Emu32) {
    let addr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!VirtualAlloc error reading addr");
    let size = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!VirtualAlloc error reading size ptr");
    let atype = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!VirtualAlloc error reading type"); 
    let protect = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!VirtualAlloc error reading protect");

    let base = emu.maps.alloc(size).expect("kernel32!VirtualAlloc out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    println!("{}** {} kernel32!VirtualAlloc sz: {} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, size, base, emu.colors.nc);

    emu.regs.eax = base;

    for _ in 0..4 {
        emu.stack_pop(false);
    }
}

fn VirtualAllocEx(emu:&mut emu32::Emu32) {
    let proc_hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!VirtualAllocEx cannot read the proc handle");
    let addr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!VirtualAllocEx cannot read the address");
    let size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!VirtualAllocEx cannot read the size");
    let alloc_type = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!VirtualAllocEx cannot read the type");
    let protect = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!VirtualAllocEx cannot read the protect");

    println!("{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);

    let base = emu.maps.alloc(size).expect("kernel32!VirtualAlloc out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);
    
    emu.regs.eax = base;

    for _ in 0..5 {
        emu.stack_pop(false);
    }
}

fn WriteProcessMemory(emu:&mut emu32::Emu32) {
    let proc_hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!WriteProcessMemory cannot read the proc handle");
    let addr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!WriteProcessMemory cannot read the address");
    let buff = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!WriteProcessMemory cannot read the buffer");
    let size = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!WriteProcessMemory cannot read the size");
    let written_ptr = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!WriteProcessMemory cannot read the ptr of num of written bytes");

    println!("{}** {} kernel32!WriteProcessMemory hproc: 0x{:x} from: 0x{:x } to: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, proc_hndl, buff, addr, size, emu.colors.nc);

    if emu.maps.memcpy(buff, addr, size as usize) {
        emu.regs.eax = 1;
        println!("{}\twritten succesfully{}", emu.colors.light_red, emu.colors.nc);
    } else {
        emu.regs.eax = 0;
        println!("{}\tcouldnt write the bytes{}", emu.colors.light_red, emu.colors.nc);
    }

    for _ in 0..5 {
        emu.stack_pop(false);
    }
}

fn CreateRemoteThread(emu:&mut emu32::Emu32) {
    let proc_hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CreateRemoteThread cannot read the proc handle");
    let sec = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CreateRemoteThread cannot read the proc security thread attributs");
    let stack_size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!CreateRemoteThread cannot read the stack size");
    let addr = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!CreateRemoteThread cannot read the addr");
    let param = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!CreateRemoteThread cannot read the param");
    let flags = emu.maps.read_dword(emu.regs.esp+20).expect("kernel32!CreateRemoteThread cannot read the flags");
    let out_tid = emu.maps.read_dword(emu.regs.esp+24).expect("kernel32!CreateRemoteThread cannot read the tid"); 

    println!("{}** {} kernel32!CreateRemoteThread hproc: 0x{:x} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);

    emu.maps.write_dword(out_tid, 0x123); 
    emu.regs.eax = helper::handler_create();

    for _ in 0..7 {
        emu.stack_pop(false);
    }
}

fn CreateNamedPipeA(emu:&mut emu32::Emu32) {
    let name_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CreateNamedPipeA cannot read the name_ptr");
    let open_mode = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CreateNamedPipeA cannot read the open_mode");
    let pipe_mode = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!CreateNamedPipeA cannot read the pipe_mode");
    let instances = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!CreateNamedPipeA cannot read the instances");
    let out_buff_sz = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu.maps.read_dword(emu.regs.esp+20).expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu.maps.read_dword(emu.regs.esp+24).expect("kernel32!CreateNamedPipeA cannot read the timeout"); 
    let security = emu.maps.read_dword(emu.regs.esp+28).expect("kernel32!CreateNamedPipeA cannot read the security"); 

    let name = emu.maps.read_string(name_ptr);

    println!("{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}", emu.colors.light_red, emu.pos, name, in_buff_sz, out_buff_sz, emu.colors.nc);

    for _ in 0..8 {
        emu.stack_pop(false);
    }

    emu.regs.eax = helper::handler_create(); 
}

fn ConnectNamedPipe(emu:&mut emu32::Emu32) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ConnectNamedPipe cannot read the handle");
    let overlapped = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!ConnectNamedPipe cannot read the overlapped");

    println!("{}** {} kernel32!ConnectNamedPipe hndl: 0x{:x} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);
    if !helper::handler_exist(handle) {
        println!("\tinvalid handle.");
    }
    

    for _ in 0..2 {
        emu.stack_pop(false);
    }
    emu.regs.eax = 1;
}

fn DisconnectNamedPipe(emu:&mut emu32::Emu32) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("kernel32!DisconnectNamedPipe cannot read the handle");

    println!("{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);

    emu.stack_pop(false);
    emu.regs.eax = 1;
}

fn ReadFile(emu:&mut emu32::Emu32) {
    let file_hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ReadFile cannot read the file_hndl");
    let buff = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!ReadFile cannot read the buff");
    let size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!ReadFile cannot read the size");
    let bytes_read = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!ReadFile cannot read the bytes_read");
    let overlapped = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!ReadFile cannot read the overlapped");

    let mut count = COUNT_READ.lock().unwrap();
    *count += 1;

    if size == 4 && *count == 1 {
        // probably reading the size
        emu.maps.write_dword(buff, 0x10);
    }

    if *count < 3 { 
        // keep reading bytes
        emu.maps.write_dword(bytes_read, size);
        emu.regs.eax = 1;
    } else {
        // try to force finishing reading and continue the malware logic
        emu.maps.write_dword(bytes_read, 0);
        emu.regs.eax = 0;
    }

    //TODO: write some random bytes to the buffer
    //emu.maps.write_spaced_bytes(buff, "00 00 00 01".to_string());
    
    println!("{}** {} kernel32!ReadFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc);

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    for _ in 0..5 {
        emu.stack_pop(false);
    }
    
}

fn WriteFile(emu:&mut emu32::Emu32) {
    let file_hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!WriteFile cannot read the file_hndl");
    let buff = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!WriteFile cannot read the buff");
    let size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!WriteFile cannot read the size");
    let bytes_written = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!WriteFile cannot read the bytes_written");
    let overlapped = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!WriteFile cannot read the overlapped");

    let mut count = COUNT_WRITE.lock().unwrap();
    *count += 1;

    emu.maps.write_dword(bytes_written, size);

    println!("{}** {} kernel32!WriteFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, file_hndl, buff, size, emu.colors.nc);

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    for _ in 0..5 {
        emu.stack_pop(false);
    }
    emu.regs.eax = 1;
}

fn CloseHandle(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CloseHandle cannot read the handle");

    println!("{}** {} kernel32!CloseHandle 0x{:X} {}", emu.colors.light_red, emu.pos, hndl, emu.colors.nc);

    if !helper::handler_close(hndl) {
        println!("\tinvalid handle.")
    }
    emu.stack_pop(false);
    emu.regs.eax = 1;

    emu.stack_pop(false);
}

fn ExitProcess(emu:&mut emu32::Emu32) {
    let code = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ExitProcess cannot read the exit code");

    println!("{}** {} kernel32!ExitProcess code: {} {}", emu.colors.light_red, emu.pos, code, emu.colors.nc);
    emu.stack_pop(false);

    std::process::exit(1);
}

fn TerminateProcess(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!TerminateProcess cannot read the handle");
    let code = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!TerminateProcess cannot read the exit code");

    println!("{}** {} kernel32!TerminateProcess hndl: {} code: {} {}", emu.colors.light_red, emu.pos, hndl, code, emu.colors.nc);
    
    emu.stack_pop(false);
    emu.stack_pop(false);
}

fn GetThreadContext(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetThreadContext cannot read the handle");
    let ctx_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!GetThreadContext cannot read the ctx");

    let ctx = context::Context::new(&emu.regs);
    ctx.save(ctx_ptr, &mut emu.maps);

    println!("{}** {} kernel32!GetThreadContext  {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn SetThreadContext(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!SetThreadContext cannot read the handle");
    let ctx_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!SetThreadContext cannot read the ctx_ptr");

    println!("{}** {} kernel32!SetThreadContext  {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    let con = console::Console::new();
    con.print("apply the context (y/n)?");
    let opt = con.cmd();

    if opt == "y" || opt == "yes" {
        let mut ctx = context::Context::new(&emu.regs);
        ctx.load(ctx_ptr, &mut emu.maps);
        ctx.sync(&mut emu.regs);
    }

    emu.stack_pop(false);
    emu.stack_pop(false);
    
    emu.regs.eax = 1;
}

fn ReadProcessMemory(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ReadProcessMemory cannot read the handle");
    let addr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!ReadProcessMemory cannot read the base address");
    let buff = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!ReadProcessMemory cannot read buff");
    let size = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!ReadProcessMemory cannot read size");
    let bytes = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!ReadProcessMemory cannot read bytes");

    println!("{}** {} kernel32!ReadProcessMemory hndl: {} from: 0x{:x} to: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, hndl, addr, buff, size, emu.colors.nc);

    emu.maps.write_dword(bytes, size);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1;
}

fn GetCurrentDirectoryW(emu:&mut emu32::Emu32) {
    let buff_len = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetCurrentDirectoryW cannot read buff_len");
    let buff_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!GetCurrentDirectoryW cannot read buff_ptr");

    emu.maps.write_string(buff_ptr, "c\x00:\x00\\\x00\x00\x00\x00\x00");

    println!("{}** {} kernel32!GetCurrentDirectoryW {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    
    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 6;
}

fn GetCurrentDirectoryA(emu:&mut emu32::Emu32) {
    let buff_len = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetCurrentDirectoryW cannot read buff_len");
    let buff_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!GetCurrentDirectoryW cannot read buff_ptr");

    emu.maps.write_string(buff_ptr, "c:\\\x00");

    println!("{}** {} kernel32!GetCurrentDirectoryA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 3;
}

fn VirtualProtect(emu:&mut emu32::Emu32) {
    let addr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!VirtualProtect cannot read addr");
    let size = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!VirtualProtect cannot read size");
    let new_prot = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!VirtualProtect cannot read new_prot");
    let old_prot_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!VirtualProtect cannot read old_prot");
    
    emu.maps.write_dword(old_prot_ptr, new_prot);

    println!("{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}", emu.colors.light_red, emu.pos, addr, size, new_prot, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1;
}

fn VirtualProtectEx(emu:&mut emu32::Emu32) {
    let hproc = emu.maps.read_dword(emu.regs.esp).expect("kernel32!VirtualProtectEx cannot read hproc");
    let addr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!VirtualProtectEx cannot read addr");
    let size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!VirtualProtectEx cannot read size");
    let new_prot = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!VirtualProtectEx cannot read new_prot");
    let old_prot_ptr = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!VirtualProtectEx cannot read old_prot");

    emu.maps.write_dword(old_prot_ptr, new_prot);

    println!("{}** {} kernel32!VirtualProtectEx hproc: {} addr: 0x{:x} sz: {} prot: {} {}", emu.colors.light_red, emu.pos, hproc, addr, size, new_prot, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1;
}

fn ResumeThread(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ResumeThread cannot read the handle");
    
    println!("{}** {} kernel32!ResumeThread hndl: {} {}", emu.colors.light_red, emu.pos, hndl, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = 1; // previous suspend count
}

fn GetFullPathNameA(emu:&mut emu32::Emu32) {
    let file_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetFullPathNameA cannot read file_ptr");
    let size = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!GetFullPathNameA cannot read size");
    let buff = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!GetFullPathNameA cannot read buff");
    let path = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!GetFullPathNameA cannot read path");

    let filename = emu.maps.read_string(file_ptr);

    println!("{}** {} kernel32!GetFullPathNameA file: {}  {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 10;
}


fn GetFullPathNameW(emu:&mut emu32::Emu32) {
    let file_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetFullPathNameW cannot read file_ptr");
    let size = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!GetFullPathNameW cannot read size");
    let buff = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!GetFullPathNameW cannot read buff");
    let path = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!GetFullPathNameW cannot read path");

    let filename = emu.maps.read_wide_string(file_ptr);

    println!("{}** {} kernel32!GetFullPathNameW file: {}  {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 10;
}

fn SystemTimeToTzSpecificLocalTime(emu:&mut emu32::Emu32) {
    let tz_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read tz_ptr");
    let ut_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read ut_ptr");
    let lt_ptr = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!SystemTimeToTzSpecificLocalTime cannot read lt_ptr");

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn GetLogicalDrives(emu:&mut emu32::Emu32) {

    println!("{}** {} kernel32!GetLogicalDrives {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.eax = 0xc;
}


fn ExpandEnvironmentStringsA(emu:&mut emu32::Emu32) {
    let src_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ExpandEnvironmentStringsA cannot read src");
    let dst_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!ExpandEnvironmentStringsA cannot read dst");
    let size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!ExpandEnvironmentStringsA cannot read size");

    let src = emu.maps.read_string(src_ptr);

    println!("{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}", emu.colors.light_red, emu.pos, src, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);
    
    emu.regs.eax = 1;

    //TODO: implement expand
}

fn ExpandEnvironmentStringsW(emu:&mut emu32::Emu32) {
    let src_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!ExpandEnvironmentStringsW cannot read src");
    let dst_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!ExpandEnvironmentStringsW cannot read dst");
    let size = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!ExpandEnvironmentStringsW cannot read size");

    let src = emu.maps.read_wide_string(src_ptr);

    println!("{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}", emu.colors.light_red, emu.pos, src, emu.colors.nc);

    //TODO: implement expand

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);
    
    emu.regs.eax = 1;
}

fn GetFileAttributesA(emu:&mut emu32::Emu32) {
    let filename_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetFileAttributesA cannot read filename_ptr");    
    let filename = emu.maps.read_string(filename_ptr);

    println!("{}** {} kernel32!GetFileAttributesA file: {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    emu.regs.eax = 0x123; // file attributes

    emu.stack_pop(false);

}

fn GetFileAttributesW(emu:&mut emu32::Emu32) {
    let filename_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetFileAttributesW cannot read filename_ptr");    
    let filename = emu.maps.read_wide_string(filename_ptr);

    println!("{}** {} kernel32!GetFileAttributesW file: {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = 0x123; // file attributes
}

fn FileTimeToSystemTime(emu:&mut emu32::Emu32) {
    let file_time = emu.maps.read_dword(emu.regs.esp).expect("kernel32!FileTimeToSystemTime cannot read file_time");
    let sys_time_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!FileTimeToSystemTime cannot read sys_time_ptr");

    println!("{}** {} kernel32!FileTimeToSystemTime {} ", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn FindFirstFileA(emu:&mut emu32::Emu32) {
    let file_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!FindFirstFileA cannot read file_ptr");
    let find_data = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!FindFirstFileA cannot read find_data");

    let file = emu.maps.read_string(file_ptr);

    println!("{}** {} kernel32!FindFirstFileA file: {} {}", emu.colors.light_red, emu.pos, file, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn FindFirstFileW(emu:&mut emu32::Emu32) {
    let file_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!FindFirstFileW cannot read file_ptr");
    let find_data = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!FindFirstFileW cannot read find_data");

    let file = emu.maps.read_wide_string(file_ptr);

    println!("{}** {} kernel32!FindFirstFileW file: {} {}", emu.colors.light_red, emu.pos, file, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = helper::handler_create();
}

fn FindNextFileA(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!FindNextFileA cannot read the handle");
    let find_data = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!FindNextFileA cannot read the find_data");

    println!("{}** {} kernel32!FindNextFileA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = constants::ERROR_NO_MORE_FILES;
}

fn FindNextFileW(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!FindNextFileW cannot read the handle");
    let find_data = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!FindNextFileW cannot read the find_data");

    println!("{}** {} kernel32!FindNextFileW {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = constants::ERROR_NO_MORE_FILES;
}

fn CopyFileA(emu:&mut emu32::Emu32) {
    let src_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CopyFileA cannot read src_ptr");
    let dst_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CopyFileA cannot read dst_ptr");
    let do_fail = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!CopyFileA cannot read do_fail");

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!("{}** {} kernel32!CopyFileA `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn CopyFileW(emu:&mut emu32::Emu32) {
    let src_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CopyFileW cannot read src_ptr");
    let dst_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CopyFileW cannot read dst_ptr");
    let do_fail = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!CopyFileW cannot read do_fail");

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!("{}** {} kernel32!CopyFileW `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn FindClose(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!FindClose cannot read the handle");

    println!("{}** {} kernel32!FindClose {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);

    helper::handler_close(hndl);
    emu.regs.eax = 1;
}

fn MoveFileA(emu:&mut emu32::Emu32) {
    let src_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!MoveFileA cannot read src_ptr");
    let dst_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!MoveFileA cannot read dst_ptr");

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!("{}** {} kernel32!MoveFileA `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn MoveFileW(emu:&mut emu32::Emu32) {
    let src_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!MoveFileW cannot read src_ptr");
    let dst_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!MoveFileW cannot read dst_ptr");

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!("{}** {} kernel32!MoveFileW `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn OpenProcess(emu:&mut emu32::Emu32) {
    let access = emu.maps.read_dword(emu.regs.esp).expect("kernel32!OpenProcess cannot read access");
    let inherit = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!OpenProcess cannot read inherit");
    let pid = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!OpenProcess cannot read pid");

    println!("{}** {} kernel32!OpenProcess pid: {} {}", emu.colors.light_red, emu.pos, pid, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = helper::handler_create();
}

fn GetCurrentProcessId(emu:&mut emu32::Emu32) {

    println!("{}** {} kernel32!GetCurrentProcessId {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.eax = 0x123; 
}

fn Thread32First(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!Thread32First cannot read the handle");
    let entry = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!Thread32First cannot read the entry32");

    println!("{}** {} kernel32!Thread32First {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn Thread32Next(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!Thread32Next cannot read the handle");
    let entry = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!Thread32Next cannot read the entry32");
    
    println!("{}** {} kernel32!Thread32Next {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = constants::ERROR_NO_MORE_FILES;
}

fn OpenThread(emu:&mut emu32::Emu32) {
    let access = emu.maps.read_dword(emu.regs.esp).expect("kernel32!OpenThread cannot read acess");
    let inherit = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!OpenThread cannot read inherit");
    let tid = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!OpenThread cannot read tid");

    println!("{}** {} kernel32!OpenThread tid: {} {}", emu.colors.light_red, emu.pos, tid, emu.colors.nc);
   
    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = helper::handler_create();
}

fn CreateToolhelp32Snapshot(emu:&mut emu32::Emu32) {
    let flags = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CreateToolhelp32Snapshot cannot read flags");
    let pid = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CreateToolhelp32Snapshot cannot read pid");

    println!("{}** {} kernel32!CreateToolhelp32Snapshot pid: {} {}", emu.colors.light_red, emu.pos, pid, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = helper::handler_create();
}

fn CreateThread(emu:&mut emu32::Emu32) {
    let sec_attr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!CreateThread cannot read sec_attr");
    let stack_sz = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!CreateThread cannot read stack_sz");
    let code = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!CreateThread cannot read fptr");
    let param = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!CreateThread cannot read param");
    let flags = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!CreateThread cannot read flags");
    let tid_ptr = emu.maps.read_dword(emu.regs.esp+20).expect("kernel32!CreateThread cannot read tid_ptr");

    emu.maps.write_dword(tid_ptr, 0x123);

    println!("{}** {} kernel32!CreateThread code: {} {}", emu.colors.light_red, emu.pos, code, emu.colors.nc);

    for _ in 0..6 {
        emu.stack_pop(false);
    }

    if flags == constants::CREATE_SUSPENDED {
        println!("\tcreated suspended!");
    }

    let con = console::Console::new();
    con.print("Continue emulating the created thread (y/n)? ");
    let line = con.cmd();

    if line == "y" || line == "yes" {
        if emu.maps.is_mapped(code) {
            emu.regs.eip = code;
            emu.regs.eax = 0;
            // alloc a stack vs reusing stack.
            return;
        } else {
            println!("cannot emulate the thread, the function pointer is not mapped.");
        }
    } 

    emu.regs.eax = helper::handler_create();
}

fn MapViewOfFile(emu:&mut emu32::Emu32) {
    let hndl = emu.maps.read_dword(emu.regs.esp).expect("kernel32!MapViewOfFile cannot read the handle");
    let access = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!MapViewOfFile cannot read the acess");
    let off_hight = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!MapViewOfFile cannot read the off_hight");
    let off_low = emu.maps.read_dword(emu.regs.esp+12).expect("kernel32!MapViewOfFile cannot read the off_low");
    let size = emu.maps.read_dword(emu.regs.esp+16).expect("kernel32!MapViewOfFile cannot read the size");

    let off:u64 = (off_hight as u64) << 32 + off_low;

    println!("{}** {} kernel32!MapViewOfFile hndl: {} off: {} sz: {} {}", emu.colors.light_red, emu.pos, hndl, off, size, emu.colors.nc);

    let addr = emu.maps.alloc(size).expect("kernel32!MapViewOfFile cannot allocate");
    let mem = emu.maps.create_map("file_map");
    mem.set_base(addr);
    mem.set_size(size);
    //TODO: use mem.load()

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = addr;
}

fn GetSystemTimeAsFileTime(emu:&mut emu32::Emu32) {
    let sys_time_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetSystemTimeAsFileTime cannot read sys_time_ptr");

    println!("{}** {} kernel32!GetSystemTimeAsFileTime {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn GetCurrentThreadId(emu:&mut emu32::Emu32) {

    println!("{}** {} kernel32!GetCurrentThreadId {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.eax = 0x111; //TODO: track pids and tids
}

fn GetTickCount(emu:&mut emu32::Emu32) {

    println!("{}** {} kernel32!GetTickCount {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.eax = 1;
}

fn QueryPerformanceCounter(emu:&mut emu32::Emu32) {
    let counter_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!QueryPerformanceCounter cannot read counter_ptr");

    emu.maps.write_dword(counter_ptr, 0x1);
    

    println!("{}** {} kernel32!QueryPerformanceCounter {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn HeapCreate(emu:&mut emu32::Emu32) {
    let opts = emu.maps.read_dword(emu.regs.esp).expect("kernel32!HeapCreate cannot read opts");
    let init_sz = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!HeapCreate cannot read init_sz");
    let max_sz = emu.maps.read_dword(emu.regs.esp+8).expect("kernel32!HeapCreate cannot read max_sz");
    
    println!("{}** {} kernel32!HeapCreate initSz: {} maxSz: {}  {}", emu.colors.light_red, emu.pos, init_sz, max_sz, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.stack_pop(false);
    
    emu.regs.eax = helper::handler_create();
}

fn GetModuleHandleA(emu:&mut emu32::Emu32) {
    let mod_name_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetModuleHandleA cannot read mod_name_ptr");
    let mod_name = emu.maps.read_string(mod_name_ptr);

    println!("{}** {} kernel32!GetModuleHandleA '{}' {}", emu.colors.light_red, emu.pos, mod_name, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = helper::handler_create();
}

fn GetModuleHandleW(emu:&mut emu32::Emu32) {
    let mod_name_ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!GetModuleHandleW cannot read mod_name_ptr");
    let mod_name = emu.maps.read_wide_string(mod_name_ptr);

    println!("{}** {} kernel32!GetModuleHandleW '{}' {}", emu.colors.light_red, emu.pos, mod_name, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = helper::handler_create();
}

fn TlsAlloc(emu:&mut emu32::Emu32) { 

    println!("{}** {} kernel32!TlsAlloc {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.eax = 1;
}

fn TlsSetValue(emu:&mut emu32::Emu32) {
    let idx = emu.maps.read_dword(emu.regs.esp).expect("kernel32!TlsSetValue cannot read idx");
    let val_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!TlsSetValue cannot read val_ptr");

    let val = match emu.maps.read_dword(val_ptr) {
        Some(v) => v,
        None => 0,
    };

    println!("{}** {} kernel32!TlsSetValue idx: {} val: {} {}", emu.colors.light_red, emu.pos, idx, val, emu.colors.nc);

    if emu.tls.len() > idx as usize {
        emu.tls[idx as usize] = val;
    } else {
        for _ in 0..idx+1 {
            emu.tls.push(0);
        }
        emu.tls[idx as usize] = val;
    }

    emu.stack_pop(false);
    emu.stack_pop(false);

    emu.regs.eax = 1;
}

fn TlsGetValue(emu:&mut emu32::Emu32) {
    let idx = emu.maps.read_dword(emu.regs.esp).expect("kernel32!TlsGetValue cannot read idx");

    println!("{}** {} kernel32!TlsGetValue idx: {} {}", emu.colors.light_red, emu.pos, idx, emu.colors.nc);

    emu.stack_pop(false);

    if idx as usize > emu.tls.len() {
        emu.regs.eax = 0;
    } else {
        emu.regs.eax = emu.tls[idx as usize];
    }
}

fn EncodePointer(emu:&mut emu32::Emu32) {
    let ptr = emu.maps.read_dword(emu.regs.esp).expect("kernel32!EncodePointer cannot read ptr");

    println!("{}** {} kernel32!EncodePointer ptr: 0x{:x} {}", emu.colors.light_red, emu.pos, ptr, emu.colors.nc);

    emu.stack_pop(false);

    emu.regs.eax = ptr;
}
