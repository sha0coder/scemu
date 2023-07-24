use crate::emu;
use crate::emu::winapi32::kernel32;
//use crate::emu::winapi32::helper;
//use crate::emu::endpoint;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x6dc2a9bc => DnsQuery_A(emu),
        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented dnsapi API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

fn DnsQuery_A(emu: &mut emu::Emu) {
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("dnsapi!DnsQuery_A cant read name ptr param") as u64;
    let wtype = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("dnsapi!DnsQuery_A cant read wtype pram");
    let opt = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("dnsapi!DnsQuery_A cant read options param");
    let extra = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("dnsapi!DnsQuery_A cant read extra param");
    let out_results = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("dnsapi!DnsQuery_A cant read out results param");
    let out_reserved = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("dnsapi!DnsQuery_A cant read out reserved param");

    let name = emu.maps.read_string(name_ptr);

    println!(
        "{}** {} dnsapi!DnsQuery_A '{}' {}",
        emu.colors.light_red, emu.pos, name, emu.colors.nc
    );

    emu.regs.rax = 1;
}
