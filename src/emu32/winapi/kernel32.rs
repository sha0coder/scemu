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

    println!("{}** kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, dll, emu.regs.eax, emu.colors.nc);

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

    println!("{}** LoadLibraryExA '{}' {}", emu.colors.light_red, libname, emu.colors.nc);
    panic!();
}

fn LoadLibraryExW(emu:&mut emu32::Emu32) {
    println!("{}** LoadLibraryExW {}", emu.colors.light_red, emu.colors.nc);
}

fn LoadLibraryW(emu:&mut emu32::Emu32) {
    let dllptr = match emu.maps.read_dword(emu.regs.esp) {
        Some(v) => v,
        None => panic!("bad LoadLibraryW parameter"),
    };
    let dll = emu.maps.read_wide_string(dllptr);
    println!("{}** LoadLibraryW  '{}'  {}", emu.colors.light_red, dll, emu.colors.nc);

    if dll == "ntdll.dll" {
        emu.regs.eax = emu.maps.get_mem("ntdll").get_base();
    }

    emu.stack_pop(false);
}

fn WinExec(emu:&mut emu32::Emu32) {
    let cmdline_ptr = emu.maps.read_dword(emu.regs.esp).expect("cannot read the cmdline parameter of WinExec");
    let cmdline = emu.maps.read_string(cmdline_ptr);

    //emu.spawn_console();

    println!("{}** WinExec  '{}'  {}", emu.colors.light_red, cmdline, emu.colors.nc);

    emu.regs.eax = 0;
    emu.stack_pop(false);
}

fn GetVersion(emu:&mut emu32::Emu32) {
    emu.regs.eax = emu32::constants::VERSION;
    println!("{}** kernel32!GetVersion   =0x{:x}  {}", emu.colors.light_red, emu.regs.eax, emu.colors.nc);
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

    println!("{}** kernel32!CreateProcessA  {} {} {}", emu.colors.light_red, appname, cmdline, emu.colors.nc);

    for _ in 0..10 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1;
}

fn WaitForSingleObject(emu:&mut emu32::Emu32) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("kernel32!WaitForSingleObject error reading handle");
    let millis = emu.maps.read_dword(emu.regs.esp+4).expect("kernel32!WaitForSingleObject error reading millis");

    println!("{}** kernel32!WaitForSingleObject  hndl:{} millis:{} {}", emu.colors.light_red, handle, millis, emu.colors.nc);

    emu.stack_pop(false);
    emu.stack_pop(false);
    emu.regs.eax = emu32::constants::WAIT_TIMEOUT;
}





