use crate::emu;
use crate::serialization;
use crate::winapi32::kernel32;
//use crate::winapi32::helper;
//use crate::endpoint;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "DnsQuery_A" => DnsQuery_A(emu),
        "DnsQueryA" => DnsQuery_A(emu),
        "DnsQuery_W" => DnsQuery_W(emu),
        "DnsQueryW" => DnsQuery_W(emu),

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

    log::info!(
        "{}** {} dnsapi!DnsQuery_A '{}' {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn DnsQuery_W(emu: &mut emu::Emu) {
    let name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("dnsapi!DnsQuery_W cant read name ptr param") as u64;
    let wtype = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("dnsapi!DnsQuery_W cant read wtype pram");
    let opt = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("dnsapi!DnsQuery_W cant read options param");
    let extra = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("dnsapi!DnsQuery_W cant read extra param");
    let out_results = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("dnsapi!DnsQuery_W cant read out results param");
    let out_reserved = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("dnsapi!DnsQuery_W cant read out reserved param");

    let name = emu.maps.read_wide_string(name_ptr);

    log::info!(
        "{}** {} dnsapi!DnsQuery_W '{}' {}",
        emu.colors.light_red,
        emu.pos,
        name,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}
