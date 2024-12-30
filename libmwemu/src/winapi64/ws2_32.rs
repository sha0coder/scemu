use crate::emu;
use crate::serialization;
//use crate::endpoint;
use crate::structures::*;
use crate::winapi32::helper;
use crate::winapi64;

use lazy_static::lazy_static;
use std::sync::Mutex;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "WSAStartup" => WsaStartup(emu),
        "WSASocketA" => WsaSocketA(emu),
        "connect" => connect(emu),
        "recv" => recv(emu),
        "send" => send(emu),
        "socket" => socket(emu),
        "WsaHtons" => WsaHtons(emu),
        "htons" => htons(emu),
        "inet_addr" => inet_addr(emu),
        "bind" => bind(emu),
        "listen" => listen(emu),
        "accept" => accept(emu),
        "closesocket" => closesocket(emu),
        "setsockopt" => setsockopt(emu),
        "getsockopt" => getsockopt(emu),
        "WsaAccept" => WsaAccept(emu),
        "GetSockName" => GetSockName(emu),
        "gethostbyname" => gethostbyname(emu),
        /*
        "sendto" => sendto(emu),
        "recvfrom" => recvfrom(emu),
        "WsaRecv" => WsaRecv(emu),
        "WsaRecvFrom" => WsaRecvFrom(emu),
        "WsaConnect" => WsaConnect(emu),
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

    emu.regs.rax = 0;
}

fn WsaSocketA(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ws2_32!WsaSocketA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = helper::socket_create();
}

fn socket(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ws2_32!socket {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = helper::socket_create();
}

fn WsaHtons(emu: &mut emu::Emu) {
    let host_port = emu.regs.rdx;
    let out_port = emu.regs.r8;

    log::info!(
        "{}** {} ws2_32!WsaHtons {} {}",
        emu.colors.light_red,
        emu.pos,
        host_port,
        emu.colors.nc
    );

    //TODO: implement this
    emu.regs.rax = 0;
}

fn htons(emu: &mut emu::Emu) {
    let port: u16 = emu.regs.rcx as u16;

    log::info!(
        "{}** {} ws2_32!htons port: {} {}",
        emu.colors.light_red,
        emu.pos,
        port,
        emu.colors.nc
    );

    emu.regs.rax = port.to_be() as u64;
}

fn inet_addr(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;

    //TODO: derreferece addr

    log::info!(
        "{}** {} ws2_32!inet_addr {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn connect(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let sockaddr_ptr = emu.regs.rdx;
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
    let sock = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let mut len = emu.regs.r8;
    let flags = emu.regs.r9;

    log::info!(
        "{}** {} ws2_32!recv   buff: 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        buff,
        len,
        emu.colors.nc
    );

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
    let sock = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let mut len = emu.regs.r8;
    let flags = emu.regs.r9;

    let bytes = emu.maps.read_string_of_bytes(buff, len as usize);

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
    let sock = emu.regs.rcx;
    let saddr = emu.regs.rdx;
    let len = emu.regs.r8;

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

    if !helper::socket_exist(sock) {
        log::info!("\tbad socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn listen(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let connections = emu.regs.rdx;

    log::info!(
        "{}** {} ws2_32!listen  connections: {}  {}",
        emu.colors.light_red,
        emu.pos,
        connections,
        emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn accept(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let saddr = emu.regs.rdx;
    let len = emu.regs.r8;
    let flags = emu.regs.r9;

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    log::info!(
        "{}** {} ws2_32!accept  connections: {}  {}",
        emu.colors.light_red,
        emu.pos,
        bytes,
        emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn closesocket(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;

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

    emu.regs.rax = 0;
}

fn setsockopt(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let level = emu.regs.rdx;
    let optname = emu.regs.r8;
    let optval = emu.regs.r9;
    let optlen = emu
        .maps
        .read_qword(emu.regs.get_esp())
        .expect("ws2_32!setsockopt: error reading optlen");

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

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn getsockopt(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let level = emu.regs.rdx;
    let optname = emu.regs.r8;
    let optval = emu.regs.r9;
    let optlen = emu
        .maps
        .read_qword(emu.regs.get_esp())
        .expect("ws2_32!getsockopt: error reading optlen");

    emu.maps.write_dword(optval, 1);

    log::info!(
        "{}** {} ws2_32!getsockopt  lvl: {} opt: {} {}",
        emu.colors.light_red,
        emu.pos,
        level,
        optname,
        emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn WsaAccept(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let saddr = emu.regs.rdx;
    let len = emu.regs.r8;
    let cond = emu.regs.r9;
    let callback = emu
        .maps
        .read_qword(emu.regs.get_esp())
        .expect("ws2_32!WsaAccept: error reading callback");

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    log::info!(
        "{}** {} ws2_32!WsaAccept  connections: {} callback: {} {}",
        emu.colors.light_red,
        emu.pos,
        bytes,
        callback,
        emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        log::info!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn GetSockName(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let sockaddr_ptr = emu.regs.rdx;
    let namelen_ptr = emu.regs.r8;

    emu.maps.write_dword(sockaddr_ptr, 0);
    emu.maps.write_dword(namelen_ptr, 4);

    log::info!(
        "{}** {} ws2_32!GetSockName sock: {} {}",
        emu.colors.light_red,
        emu.pos,
        sock,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn gethostbyname(emu: &mut emu::Emu) {
    let domain_name_ptr = emu.regs.rcx;
    let domain_name = emu.maps.read_string(domain_name_ptr);

    log::info!(
        "{}** {} ws2_32!gethostbyname `{}` {}",
        emu.colors.light_red,
        emu.pos,
        domain_name,
        emu.colors.nc
    );

    let addr = emu.maps.alloc(1024).expect("low memory");
    let str_addr = addr + 1024 - 100;
    let mem = emu
        .maps
        .create_map("hostent", addr, 1024)
        .expect("cannot create hostent map");
    mem.write_dword(addr, 0x04030201);
    mem.write_qword(addr + 8, addr);
    mem.write_qword(addr + 16, 0);
    mem.write_string(str_addr, &domain_name);

    let mut hostent = Hostent::new();
    hostent.hname = str_addr;
    hostent.alias_list = 0;
    hostent.length = 4;
    hostent.addr_list = addr + 8;
    hostent.save(addr + 30, &mut emu.maps);

    emu.regs.rax = addr + 30;
}
