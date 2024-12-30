use crate::emu;
use crate::serialization;
use crate::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "MessageBoxA" => MessageBoxA(emu),
        "MessageBoxW" => MessageBoxW(emu),
        "GetDesktopWindow" => GetDesktopWindow(emu),
        "wsprintfW" => wsprintfW(emu),
        "GetProcessWindowStation" => GetProcessWindowStation(emu),
        "GetUserObjectInformationW" => GetUserObjectInformationW(emu),
        "CharLowerW" => CharLowerW(emu),
        "wsprintfA" => wsprintfA(emu),
        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("atemmpt to call unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {} at 0x{:x}", addr, api, emu.regs.rip);
            return api;
        }
    }

    String::new()
}

fn MessageBoxA(emu: &mut emu::Emu) {
    let titleptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("user32_MessageBoxA: error reading title") as u64;
    let msgptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("user32_MessageBoxA: error reading message") as u64;
    let msg = emu.maps.read_string(msgptr);
    let title = emu.maps.read_string(titleptr);

    log::info!(
        "{}** {} user32!MessageBoxA {} {} {}",
        emu.colors.light_red,
        emu.pos,
        title,
        msg,
        emu.colors.nc
    );

    emu.regs.rax = 0;
    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn MessageBoxW(emu: &mut emu::Emu) {
    let titleptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("user32_MessageBoxA: error reading title") as u64;
    let msgptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("user32_MessageBoxA: error reading message") as u64;
    let msg = emu.maps.read_wide_string(msgptr);
    let title = emu.maps.read_wide_string(titleptr);

    log::info!(
        "{}** {} user32!MessageBoxW {} {} {}",
        emu.colors.light_red,
        emu.pos,
        title,
        msg,
        emu.colors.nc
    );

    emu.regs.rax = 0;
    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn GetDesktopWindow(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} user32!GetDesktopWindow {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    //emu.regs.rax = 0x11223344; // current window handle
    emu.regs.rax = 0; // no windows handler is more stealthy
}

fn wsprintfW(emu: &mut emu::Emu) {}

fn GetProcessWindowStation(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} user32!GetProcessWindowStation {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 0x1337; // get handler
}

fn GetUserObjectInformationW(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let nidx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let out_vinfo = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let nlen = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let out_len = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;

    log::info!(
        "{}** {} user32!GetUserObjectInformationW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // get handler
}

fn CharLowerW(emu: &mut emu::Emu) {
    let ptr_str = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!CharLowerW: error reading param") as u64;

    let s = emu.maps.read_wide_string(ptr_str);

    log::info!(
        "{}** {} user32!CharLowerW(`{}`) {}",
        emu.colors.light_red,
        emu.pos,
        s,
        emu.colors.nc
    );

    emu.maps.write_wide_string(ptr_str, &s.to_lowercase());

    emu.stack_pop32(false);
    emu.regs.rax = ptr_str;
}

fn wsprintfA(emu: &mut emu::Emu) {
    let out = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!wsprintfA: error reading out") as u64;
    let in_fmt = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("user32!wsprintfA: error reading in_fmt") as u64;
    let mut multiple = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("user32!wsprintfA: error reading multiple") as u64;

    let fmt = emu.maps.read_string(in_fmt);
    let mut args = Vec::new();
    let mut chars = fmt.chars().peekable();
    let mut arg_index = 0;
    let mut result = String::new();

    while let Some(arg) = emu.maps.read_dword(multiple) {
        args.push(arg as u64);
        multiple += 4;
    }

    while let Some(c) = chars.next() {
        if c == '%' {
            if chars.peek() == Some(&'%') {
                result.push('%');
                chars.next();
            } else if arg_index < args.len() {
                let specifier = chars.next();
                match specifier {
                    Some('d') => result.push_str(&format!("{}", args[arg_index] as i32)),
                    Some('u') => result.push_str(&format!("{}", args[arg_index])),
                    Some('x') => result.push_str(&format!("{:x}", args[arg_index])),
                    Some('X') => result.push_str(&format!("{:X}", args[arg_index])),
                    Some('s') => {
                        let addr = args[arg_index];
                        let s = emu.maps.read_string(addr);
                        if !s.is_empty() {
                            result.push_str(&s);
                        } else {
                            result.push_str("<invalid string>");
                        }
                    }
                    Some('c') => result.push(args[arg_index] as u8 as char),
                    _ => result.push_str("<unsupported format>"),
                }
                arg_index += 1;
            } else {
                result.push_str("<missing>");
            }
        } else {
            result.push(c);
        }
    }

    emu.maps.write_string(out, &result);

    log::info!(
        "{}** {} user32!wsprintfA fmt:`{}` out:`{}` {}",
        emu.colors.light_red,
        emu.pos,
        fmt,
        &result,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = result.len() as u64;
}
