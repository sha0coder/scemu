use crate::emu32;

pub fn gateway(addr:u32, emu:&mut emu32::Emu32) {
    match addr {
        0x77483ab2 => WsaStartup(emu),
        0x7748c82a => WsaSocketA(emu),
        0x77483eb8 => socket(emu),
        0x77493c11 => WsaHtons(emu),
        0x77482d8b => htons(emu),
        0x7748311b => inet_addr(emu),
        0x77486bdd => connect(emu),
        /*0x7748cc3f => WsaConnect(emu),
        0x77484582 => bind(emu),
        0x7748b001 => listen(emu),
        0x774868b6 => accept(emu),
        0x774868d6 => WsaAccept(emu),*/
        _ => panic!("calling unknown ws2_32 API 0x{:x}", addr)
    }
}

fn WsaStartup(emu:&mut emu32::Emu32) {

    println!("{}** ws2_32!WsaStartup() {}", emu.colors.light_red, emu.colors.nc);

    for _ in 0..2 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0;
}

fn WsaSocketA(emu:&mut emu32::Emu32) {
    println!("{}** ws2_32!WsaSocketA() {}", emu.colors.light_red, emu.colors.nc);

    for _ in 0..6 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x10; // socket descriptor
}

fn socket(emu:&mut emu32::Emu32) {
    println!("{}** ws2_32!socket() {}", emu.colors.light_red, emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x10; // socket descriptor
}

fn WsaHtons(emu:&mut emu32::Emu32) {
    let out_port = emu.maps.read_dword(emu.regs.esp+8);

    println!("{}** ws2_32!WsaHtons() {}", emu.colors.light_red, emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0; // socket descriptor
}


fn htons(emu:&mut emu32::Emu32) {
    let port:u16 = match emu.maps.read_word(emu.regs.esp) {
        Some(p) => p,
        None => 0,
    };

    println!("{}** ws2_32!htons({}) {}", emu.colors.light_red, port, emu.colors.nc);

    emu.stack_pop(false);
    emu.regs.eax = port.to_be() as u32;
}


fn inet_addr(emu:&mut emu32::Emu32) {

    println!("{}** ws2_32!inet_addr() {}", emu.colors.light_red, emu.colors.nc);

    emu.stack_pop(false);
    emu.regs.eax = 0; 
}

fn connect(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!connect: error reading sock");
    let sockaddr_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!connect: error reading sockaddr ptr");
    let sockaddr = emu.maps.read_bytes(sockaddr_ptr, 8);

    println!("{}** ws2_32!connect() {:?} {}", emu.colors.light_red, sockaddr, emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }
    emu.regs.eax = 0; 
}