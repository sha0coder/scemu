use crate::emu;
//use crate::endpoint;
use crate::serialization;
use crate::winapi32::helper;
use crate::winapi32::kernel32;

use lazy_static::lazy_static;
use std::sync::Mutex;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "WsaStartup" => WsaStartup(emu),
        "WsaSocketA" => WsaSocketA(emu),
        "socket" => socket(emu),
        "WsaHtons" => WsaHtons(emu),
        "htons" => htons(emu),
        "inet_addr" => inet_addr(emu),
        "connect" => connect(emu),
        "recv" => recv(emu),
        "send" => send(emu),
        "bind" => bind(emu),
        "listen" => listen(emu),
        "accept" => accept(emu),
        "closesocket" => closesocket(emu),
        "setsockopt" => setsockopt(emu),
        "getsockopt" => getsockopt(emu),
        "WsaAccept" => WsaAccept(emu),

        /*
        0x774834b5 => sendto(emu),
        0x7748b6dc => recvfrom(emu),
        0x77487089 => WsaRecv(emu),
        0x7748cba6 => WsaRecvFrom(emu),
        0x7748cc3f => WsaConnect(emu),
        */
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

lazy_static! {
    static ref COUNT_SEND: Mutex<u32> = Mutex::new(0);
    static ref COUNT_RECV: Mutex<u32> = Mutex::new(0);
}

fn WsaStartup(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ws2_32!WsaStartup {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 0;
}

fn WsaSocketA(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ws2_32!WsaSocketA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = helper::socket_create();
}

fn socket(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ws2_32!socket {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = helper::socket_create();
}

fn WsaHtons(emu: &mut emu::Emu) {
    let host_port = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!WsaHtons cannot read host_port");
    let out_port = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!WsaHtons cannot read out_port");

    log::info!(
        "{}** {} ws2_32!WsaHtons {} {}",
        emu.colors.light_red,
        emu.pos,
        host_port,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    //TODO: implement this

    emu.regs.rax = 0;
}

fn htons(emu: &mut emu::Emu) {
    let port: u16 = emu.maps.read_word(emu.regs.get_esp()).unwrap_or_default();

    log::info!(
        "{}** {} ws2_32!htons port: {} {}",
        emu.colors.light_red,
        emu.pos,
        port,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = port.to_be() as u64;
}

fn inet_addr(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!inet_addr: error reading addr");

    log::info!(
        "{}** {} ws2_32!inet_addr {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn connect(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!connect: error reading sock") as u64;
    let sockaddr_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!connect: error reading sockaddr ptr") as u64;
    //let sockaddr = emu.maps.read_bytes(sockaddr_ptr, 8);
    let family: u16 = emu
        .maps
        .read_word(sockaddr_ptr)
        .expect("ws2_32!connect: error reading family");
    let port: u16 = emu
        .maps
        .read_word(sockaddr_ptr + 2)
        .expect("ws2_32!connect: error reading port")
        .to_be();
    let ip: u32 = emu
        .maps
        .read_dword(sockaddr_ptr + 4)
        .expect("ws2_32!connect: error reading ip");

    let sip = format!(
        "{}.{}.{}.{}",
        ip & 0xff,
        (ip & 0xff00) >> 8,
        (ip & 0xff0000) >> 16,
        (ip & 0xff000000) >> 24
    );
    log::info!(
        "{}** {} ws2_32!connect  family: {} {}:{} {}",
        emu.colors.light_red,
        emu.pos,
        family,
        sip,
        port,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    if emu.cfg.endpoint {
        /*
        if endpoint::sock_connect(sip.as_str(), port) {
            log::info!("\tconnected to the endpoint.");
        } else {
            log::info!("\tcannot connect. dont use -e");
        }*/
        emu.regs.rax = 0;
    } else {
        // offline mode

        if !helper::socket_exist(sock) {
            log::info!("\tinvalid socket.");
            emu.regs.rax = 1;
        } else {
            emu.regs.rax = 0;
        }
    }
}

fn recv(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!recv: error reading sock") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!recv: error reading buff") as u64;
    let mut len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!recv: error reading len") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ws2_32!recv: error reading flags") as u64;

    log::info!(
        "{}** {} ws2_32!recv   buff: 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        buff,
        len,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
        return;
    }

    if emu.cfg.endpoint {
        /*
        let mut rbuff: Vec<u8> = vec![0; len as usize];
        let n = endpoint::sock_recv(&mut rbuff);

        emu.maps.write_buffer(buff, &rbuff);

        log::info!("\nreceived {} bytes from the endpoint.", n);
        emu.regs.rax = n as u64;
        */
    } else {
        let mut count_recv = COUNT_RECV.lock().unwrap();
        *count_recv += 1;
        if *count_recv > 3 {
            len = 0; // finish the recv loop
        }

        if helper::socket_exist(sock) {
            //emu.maps.write_spaced_bytes(buff, "6c 73 0d 0a".to_string()); // send a ls\r\n
            if len == 4 {
                emu.maps.write_dword(buff, 0x0100); // probably expect a size
            } else {
                emu.maps.memset(buff, 0x90, len as usize);
            }

            emu.regs.rax = len;
        }
    }
}

fn send(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!send: error reading sock") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!send: error reading buff") as u64;
    let mut len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!send: error reading len") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ws2_32!send: error reading flags") as u64;

    let bytes = emu.maps.read_string_of_bytes(buff, len as usize);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    log::info!(
        "{}** {} ws2_32!send {{{}}}   {}",
        emu.colors.light_red,
        emu.pos,
        bytes,
        emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 0;
        return;
    }

    if emu.cfg.endpoint {
        /*
        let buffer = emu.maps.read_buffer(buff, len as usize);
        let n = endpoint::sock_send(&buffer);
        log::info!("\tsent {} bytes.", n);
        emu.regs.rax = n as u64;
        */
    } else {
        let mut count_send = COUNT_SEND.lock().unwrap();
        *count_send += 1;
        if *count_send > 3 {
            len = 0; // finish the send loop
        }

        emu.regs.rax = len;
    }
}

fn bind(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!send: error reading sock") as u64;
    let saddr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!send: error reading addr") as u64;
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!send: error reading len") as u64;

    let family: u16 = emu
        .maps
        .read_word(saddr)
        .expect("ws2_32!connect: error reading family");
    let port: u16 = emu
        .maps
        .read_word(saddr + 2)
        .expect("ws2_32!connect: error reading port");
    let ip: u32 = emu
        .maps
        .read_dword(saddr + 4)
        .expect("ws2_32!connect: error reading ip");

    let sip = format!(
        "{}.{}.{}.{}",
        ip & 0xff,
        (ip & 0xff00) >> 8,
        (ip & 0xff0000) >> 16,
        (ip & 0xff000000) >> 24
    );

    log::info!(
        "{}** {} ws2_32!bind  family: {} {}:{}  {}",
        emu.colors.light_red,
        emu.pos,
        family,
        sip,
        port.to_be(),
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tbad socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn listen(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!send: error reading sock") as u64;
    let connections = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!send: error reading num of connections") as u64;

    log::info!(
        "{}** {} ws2_32!listen  connections: {}  {}",
        emu.colors.light_red,
        emu.pos,
        connections,
        emu.colors.nc
    );

    for _ in 0..2 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn accept(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!accept: error reading sock") as u64;
    let saddr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!accept: error reading sockaddr") as u64;
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!seacceptnd: error reading len") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ws2_32!accept: error reading flags") as u64;

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    log::info!(
        "{}** {} ws2_32!accept  connections: {}  {}",
        emu.colors.light_red,
        emu.pos,
        bytes,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn closesocket(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!send: error reading sock") as u64;

    log::info!(
        "{}** {} ws2_32!closesocket {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    helper::socket_close(sock);

    /*
    if emu.cfg.endpoint {
        endpoint::sock_close();
    }*/

    emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn setsockopt(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!setsockopt: error reading sock") as u64;
    let level = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!setsockopt: error reading level") as u64;
    let optname = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!setsockopt: error reading optname") as u64;
    let optval = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ws2_32!setsockopt: error reading optval") as u64;
    let optlen = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("ws2_32!setsockopt: error reading optlen") as u64;

    let val = emu.maps.read_dword(optval).unwrap_or_default();

    log::info!(
        "{}** {} ws2_32!setsockopt  lvl: {} opt: {} val: {} {}",
        emu.colors.light_red,
        emu.pos,
        level,
        optname,
        val,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn getsockopt(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!getsockopt: error reading sock") as u64;
    let level = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!getsockopt: error reading level") as u64;
    let optname = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!getsockopt: error reading optname") as u64;
    let optval = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ws2_32!getsockopt: error reading optval") as u64;
    let optlen = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("ws2_32!getsockopt: error reading optlen") as u64;

    emu.maps.write_dword(optval, 1);

    log::info!(
        "{}** {} ws2_32!getsockopt  lvl: {} opt: {} {}",
        emu.colors.light_red,
        emu.pos,
        level,
        optname,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn WsaAccept(emu: &mut emu::Emu) {
    let sock = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ws2_32!WsaAccept: error reading sock") as u64;
    let saddr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ws2_32!WsaAccept: error reading sockaddr") as u64;
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ws2_32!WsaAccept: error reading len") as u64;
    let cond = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ws2_32!WsaAccept: error reading cond") as u64;
    let callback = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("ws2_32!WsaAccept: error reading callback") as u64;

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    log::info!(
        "{}** {} ws2_32!WsaAccept  connections: {} callback: {} {}",
        emu.colors.light_red,
        emu.pos,
        bytes,
        callback,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}
