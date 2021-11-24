use crate::emu32;

pub fn gateway(addr:u32, emu:&mut emu32::Emu32) {
    match addr {
        0x75e9395c => LoadLibraryA(emu),
        0x75e847fa => LoadLibraryExA(emu),
        0x75e93951 => LoadLibraryExA(emu), // from jump table
        0x75e84775 => LoadLibraryExW(emu),
        0x75e93c01 => LoadLibraryW(emu),
        0x75ece5fd => WinExec(emu),
        0x75e8154e => GetVersion(emu),
        0x75e42082 => CreateProcessA(emu),
        0x75e8ba90 => WaitForSingleObject(emu),
        0x75e92fb6 => VirtualAlloc(emu),
        0x75e7c1b6 => VirtualAllocEx(emu),
        0x75e7c1de => WriteProcessMemory(emu),
        0x75ecf33b => CreateRemoteThread(emu),
        _ => panic!("calling unknown kernel32 API 0x{:x}", addr),
    }
}

fn LoadLibraryA(emu:&mut emu32::Emu32) {
    let dllptr = emu.maps.read_dword(emu.regs.esp).expect("bad LoadLibraryA parameter");
    let dll = emu.maps.read_string(dllptr);
    

    match dll.as_str() {
        "ntdll"|"ntdll.dll" => emu.regs.eax = emu.maps.get_mem("ntdll").get_base(),
        "ws2_32"|"ws2_32.dll" => emu.regs.eax = emu.maps.get_mem("ws2_32").get_base(),
        "wininet"|"wininet.dll" => emu.regs.eax = emu.maps.get_mem("wininet").get_base(),
        _ => panic!("/!\\ kernel32!LoadLibraryA: lib not found {}", dll),
    }

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, emu.pos, dll, emu.regs.eax, emu.colors.nc);

    emu.stack_pop(false);
}

fn LoadLibraryExA(emu:&mut emu32::Emu32) {
    /*
    HMODULE LoadLibraryExA(
        [in] LPCSTR lpLibFileName,
             HANDLE hFile,
        [in] DWORD  dwFlags
      );
    */
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

    println!("{}** {} kernel32!WaitForSingleObject  hndl:{} millis:{} {}", emu.colors.light_red, emu.pos, handle, millis, emu.colors.nc);

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

    println!("{}** {} kernel32!VirtualAlloc sz:{} addr:0x{:x} {}", emu.colors.light_red, emu.pos, size, base, emu.colors.nc);

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

    println!("{}** {} kernel32!VirtualAllocEx hproc:0x{:x} addr:0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);

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

    println!("{}** {} kernel32!WriteProcessMemory hproc:0x{:x} from:0x{:x } to:0x{:x} sz:{} {}", emu.colors.light_red, emu.pos, proc_hndl, buff, addr, size, emu.colors.nc);

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
    let tid = emu.maps.read_dword(emu.regs.esp+24).expect("kernel32!CreateRemoteThread cannot read the tid");

    println!("{}** {} kernel32!CreateRemoteThread hproc:0x{:x} addr:0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);

    emu.regs.eax = 0x11223344; // created thread handle

    for _ in 0..7 {
        emu.stack_pop(false);
    }
}
