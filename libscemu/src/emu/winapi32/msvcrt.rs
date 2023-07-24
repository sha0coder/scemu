use crate::emu;
use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;
//use crate::emu::endpoint;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x761f1d9d => _initterm_e(emu),
        0x761ec151 => _initterm(emu),
        0x7670d2ac => StrCmpCA(emu),
        0x761fb2c4 => fopen(emu),
        0x761f76ac => fwrite(emu),
        0x761f4142 => fflush(emu),
        0x761f3d79 => fclose(emu),
        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented msvcrt API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

fn _initterm_e(emu: &mut emu::Emu) {
    let start_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!_initterm_e: error reading start pointer") as u64;
    let end_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!_initterm_e: error reading en pointer") as u64;

    println!(
        "{}** {} msvcrt!_initterm_e 0x{:x} - 0x{:x} {}",
        emu.colors.light_red, emu.pos, start_ptr, end_ptr, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn _initterm(emu: &mut emu::Emu) {
    let start_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!_initterm_e: error reading start pointer") as u64;
    let end_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!_initterm_e: error reading end pointer") as u64;

    println!(
        "{}** {} msvcrt!_initterm 0x{:x} - 0x{:x} {}",
        emu.colors.light_red, emu.pos, start_ptr, end_ptr, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn StrCmpCA(emu: &mut emu::Emu) {
    let str1_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!StrCmpA: error reading str1 pointer") as u64;
    let str2_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!StrCmpA: error reading str2 pointer") as u64;

    let str1 = emu.maps.read_string(str1_ptr);
    let str2 = emu.maps.read_string(str2_ptr);

    println!(
        "{}** {} msvcrt!StrCmpA {} == {} {}",
        emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    if str1 == str2 {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = 0xffffffff;
    }
}

fn fopen(emu: &mut emu::Emu) {
    let filepath_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fopen error reading filepath pointer") as u64;
    let mode_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!fopen error reading mode pointer") as u64;

    let filepath = emu.maps.read_string(filepath_ptr);
    let mode = emu.maps.read_string(mode_ptr);

    println!(
        "{}** {} msvcrt!fopen `{}` fmt:`{}` {}",
        emu.colors.light_red, emu.pos, filepath, mode, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create(&filepath);
}

fn fwrite(emu: &mut emu::Emu) {
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fwrite error reading buff_ptr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!fwrite error reading size");
    let nemb = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("msvcrt!fwrite error reading nemb");
    let file = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("msvcrt!fwrite error reading FILE *");

    let filename = helper::handler_get_uri(file as u64);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    println!(
        "{}** {} msvcrt!fwrite `{}` 0x{:x} {} {}",
        emu.colors.light_red, emu.pos, filename, buff_ptr, size, emu.colors.nc
    );

    emu.regs.rax = size as u64;
}

fn fflush(emu: &mut emu::Emu) {
    let file = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fflush error getting FILE *");

    let filename = helper::handler_get_uri(file as u64);

    println!(
        "{}** {} msvcrt!fflush `{}` {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn fclose(emu: &mut emu::Emu) {
    let file = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fclose error getting FILE *");

    let filename = helper::handler_get_uri(file as u64);

    println!(
        "{}** {} msvcrt!fclose `{}` {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
    );

    emu.stack_pop32(false);

    emu.regs.rax = 1;
}
