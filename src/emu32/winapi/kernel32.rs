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
        _ => panic!("calling unknown kernel32 API 0x{:x}", addr),
    }
}

fn LoadLibraryA(emu:&mut emu32::Emu32) {
    let dllptr = emu.maps.read_dword(emu.regs.esp).expect("bad LoadLibraryA parameter");
    let dll = emu.maps.read_string(dllptr);
    println!("{}** LoadLibraryA  '{}'  {}", emu.colors.light_red, dll, emu.colors.nc);

    match dll.as_str() {
        "ntdll"|"ntdll.dll" => emu.regs.eax = emu.maps.get_mem("ntdll").get_base(),
        "ws2_32"|"ws2_32.dll" => {
            let ws2_32 = emu.maps.create_map("ws2_32");
            ws2_32.set_base(0x77480000);
            ws2_32.load("maps/ws2_32.bin");
            println!("ws2_32 loaded at 0x{:x}", ws2_32.get_base());
            emu.regs.eax = ws2_32.get_base();
            let ws2_32_text = emu.maps.create_map("ws2_32_text");
            ws2_32_text.set_base(0x77481000);
            ws2_32_text.load("maps/ws2_32_text.bin");
        },
        "wininet"|"wininet.dll" => {
            let wininet = emu.maps.create_map("wininet");
            wininet.set_base(0x76310000);
            wininet.load("maps/wininet.bin");
            println!("wininet loaded at 0x{:x}", wininet.get_base());
            emu.regs.eax = wininet.get_base();
            let wininet_text = emu.maps.create_map("wininet_text");
            wininet_text.set_base(0x76311000);
            wininet_text.load("maps/wininet_text.bin");
        },
        _ => panic!("/!\\ kernel32_LoadLibraryA: lib not found {}", dll),
    }

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
    println!("{}** LoadLibraryW  '{}'  {}", emu.colors.red, dll, emu.colors.nc);

    if dll == "ntdll.dll" {
        emu.regs.eax = emu.maps.get_mem("ntdll").get_base();
    }

    emu.stack_pop(false);
}

fn WinExec(emu:&mut emu32::Emu32) {
    let cmdline_ptr = emu.maps.read_dword(emu.regs.esp).expect("cannot read the cmdline parameter of WinExec");
    let cmdline = emu.maps.read_string(cmdline_ptr);

    //emu.spawn_console();

    println!("{}** WinExec  '{}'  {}", emu.colors.red, cmdline, emu.colors.nc);

    emu.regs.eax = 0;
    emu.stack_pop(false);
}

fn GetVersion(emu:&mut emu32::Emu32) {
    emu.regs.eax = emu32::constants::VERSION;
    println!("{}** GetVersion   =0x{:x}  {}", emu.colors.red, emu.regs.eax, emu.colors.nc);
}
