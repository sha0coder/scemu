use crate::emu;
use crate::constants;
use crate::structures;
use crate::console::Console;
//use crate::endpoint;
use crate::winapi32::helper;

use std::fs;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/*
 * /usr/include/asm/unistd_64.h
 *
 *  params: RDI, RSI, RDX, R10, R8, R9
 *
 *
 */

//TODO: check if buff is mapped

pub fn gateway(emu: &mut emu::Emu) {
    match emu.regs.rax {
        constants::NR64_RESTART_SYSCALL => {
            log::info!(
                "{}** {} syscall restart_syscall {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_EXIT => {
            log::info!(
                "{}** {} syscall exit()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
            std::process::exit(1);
        }

        constants::NR64_FORK => {
            log::info!(
                "{}** {} syscall fork()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
            Console::spawn_console(emu);
        }

        constants::NR64_READ => {
            let fd = emu.regs.rdi;
            let buff = emu.regs.rsi;
            let sz = emu.regs.rdx;

            if helper::handler_exist(fd) {
                let filepath = helper::handler_get_uri(fd);
                if filepath.contains(".so") {
                    // linker needs to read libraries

                    let mut lib_buff: Vec<u8> = Vec::new();

                    // log::info!("opening lib: {}", filepath);
                    match File::open(&filepath) {
                        Ok(f) => {
                            let len = f.metadata().unwrap().len();
                            let mut reader = BufReader::new(&f);
                            reader
                                .read_to_end(&mut lib_buff)
                                .expect("kernel64 cannot load dynamic library");
                            f.sync_all();

                            //log::info!("readed a lib with sz: {} buff:0x{:x}", lib_buff.len(), buff);

                            let map = emu
                                .maps
                                .get_mem_by_addr(buff)
                                .expect("buffer send to read syscall point to no map");

                            // does the file data bypasses mem end?
                            let mem_end = map.get_base() + map.size() as u64 - 1;
                            let buff_end = buff + lib_buff.len() as u64 - 1;
                            if buff_end > mem_end {
                                let overflow = buff_end - mem_end;
                                lib_buff = lib_buff[0..lib_buff.len() - overflow as usize].to_vec();
                            }

                            emu.maps.write_bytes(buff, lib_buff);
                            emu.regs.rax = sz;
                        }
                        Err(_) => {
                            log::info!("file not found");
                            emu.regs.rax = 0;
                        }
                    };
                }
            } else {
                emu.regs.rax = sz;
            }

            log::info!(
                "{}** {} syscall read(fd:{} buf:0x{:x} sz:{}) ={} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                buff,
                sz,
                emu.regs.rax,
                emu.colors.nc
            );
        }

        constants::NR64_WRITE => {
            let fd = emu.regs.rdi;
            let buff = emu.regs.rsi;
            let sz = emu.regs.rdx;
            emu.regs.rax = sz;
            log::info!(
                "{}** {} syscall write() fd: {} buf: 0x{:x} sz: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                buff,
                sz,
                emu.colors.nc
            );
            if fd == 1 {
                let s = emu.maps.read_string(buff);
                log::info!("stdout: `{}`", s)
            }
            if fd == 2 {
                let s = emu.maps.read_string(buff);
                log::info!("stderr: `{}`", s)
            }
        }

        /*
        constants::NR64_WRITEV => {
            let fd = emu.regs.rdi;
            let buff = emu.regs.rsi;
            let sz = emu.regs.rdx;
            emu.regs.rax = sz;
            log::info!(
                "{}** {} syscall write() fd: {} buf: 0x{:x} sz: {} {}",
                emu.colors.light_red, emu.pos, fd, buff, sz, emu.colors.nc
            );
            if fd == 1 {
                let s = emu.maps.read_string(buff);
                log::info!("stdout: `{}`", s)
            }
            if fd == 2 {
                let s = emu.maps.read_string(buff);
                log::info!("stderr: `{}`", s)
            }
        }*/
        constants::NR64_OPEN => {
            let file_path = emu.maps.read_string(emu.regs.rdi);
            let fd = helper::handler_create(&file_path);

            emu.regs.rax = fd;
            log::info!(
                "{}** {} syscall open({}) ={} {}",
                emu.colors.light_red,
                emu.pos,
                file_path,
                fd,
                emu.colors.nc
            );
        }

        constants::NR64_OPENAT => {
            let dirfd = emu.regs.rdi;
            let file_path = emu.maps.read_string(emu.regs.rsi);
            let mut fd: u64 = 0xffffffff_ffffffff;

            let path = Path::new(&file_path);
            if path.exists() {
                fd = helper::handler_create(&file_path);
            }

            log::info!(
                "{}** {} syscall openat({} '{}') ={} {}",
                emu.colors.light_red,
                emu.pos,
                dirfd,
                file_path,
                fd as i64,
                emu.colors.nc
            );

            emu.regs.rax = fd;
        }

        constants::NR64_CLOSE => {
            let fd = emu.regs.rdi;

            if helper::handler_exist(fd) {
                helper::handler_close(fd);
                emu.regs.rax = 0;
            } else {
                helper::socket_close(fd);
                emu.regs.rax = 0xffffffff_ffffffff;
            }

            /*
            if emu.cfg.endpoint {
                endpoint::sock_close();
            }*/

            log::info!(
                "{}** {} syscall close(fd:{}) ={} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                emu.regs.rax,
                emu.colors.nc
            );
        }

        constants::NR64_BRK => {
            let heap_base = 0x4b5b00;
            let heap_size = 0x4d8000 - 0x4b5000;

            let heap = emu
                .maps
                .create_map("heap", heap_base, heap_size)
                .expect("cannot create heap map from brk syscall");

            if emu.regs.rdi == 0 {
                emu.regs.r11 = 0x346;
                emu.regs.rcx = 0x4679f7;
                emu.regs.rax = heap.get_base();
            } else {
                let bottom = emu.regs.rdi;
                let new_sz = bottom - heap_base;
                heap.set_size(new_sz);
                emu.regs.rax = emu.regs.rdi;
                emu.regs.rcx = 0x4679f7;
                emu.regs.rdx = 0x2f;
                emu.regs.r11 = 0x302;
            }

            //emu.fs.insert(0xffffffffffffffc8, 0x4b6c50);

            log::info!(
                "{}** {} syscall brk({:x}) ={:x} {}",
                emu.colors.light_red,
                emu.pos,
                emu.regs.rdi,
                emu.regs.rax,
                emu.colors.nc
            );
        }

        constants::NR64_EXECVE => {
            let cmd = emu.maps.read_string(emu.regs.rdi);
            log::info!(
                "{}** {} syscall execve()  cmd: {} {}",
                emu.colors.light_red,
                emu.pos,
                cmd,
                emu.colors.nc
            );
            emu.regs.rax = 0;
        }

        constants::NR64_CHDIR => {
            let path = emu.maps.read_string(emu.regs.rdi);
            log::info!(
                "{}** {} syscall chdir() path: {} {}",
                emu.colors.light_red,
                emu.pos,
                path,
                emu.colors.nc
            );
        }

        constants::NR64_CHMOD => {
            let file_path = emu.maps.read_string(emu.regs.rdi);
            let perm = emu.regs.rsi;
            log::info!(
                "{}** {} syscall chmod() file: {} perm: {} {}",
                emu.colors.light_red,
                emu.pos,
                file_path,
                perm,
                emu.colors.nc
            );
        }

        constants::NR64_LSEEK => {
            let fd = emu.regs.rdi;
            log::info!(
                "{}** {} syscall lseek()  fd: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                emu.colors.nc
            );
        }

        constants::NR64_KILL => {
            let pid = emu.regs.rdi;
            let sig = emu.regs.rsi;
            log::info!(
                "{}** {} syscall kill() pid: {} sig: {} {}",
                emu.colors.light_red,
                emu.pos,
                pid,
                sig,
                emu.colors.nc
            );
        }

        constants::NR64_DUP => {
            let fd = emu.regs.rdi;
            log::info!(
                "{}** {} syscall dup() fd: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                emu.colors.nc
            );
        }

        constants::NR64_DUP2 => {
            let old_fd = emu.regs.rdi;
            let new_fd = emu.regs.rsi;
            log::info!(
                "{}** {} syscall dup2() oldfd: {} newfd: {} {}",
                emu.colors.light_red,
                emu.pos,
                old_fd,
                new_fd,
                emu.colors.nc
            );
        }

        constants::NR64_SOCKET => {
            let sock = helper::socket_create();
            let fam = emu.regs.rdi;
            let typ = emu.regs.rsi;
            let proto = emu.regs.rdx;

            log::info!(
                "{}** {} syscall socketcall socket()  fam: {} type: {} proto: {} sock: {} {}",
                emu.colors.light_red,
                emu.pos,
                fam,
                typ,
                proto,
                sock,
                emu.colors.nc
            );
            emu.regs.rax = sock;
        }

        constants::NR64_BIND => {
            let sock = emu.regs.rdi;
            let sockaddr = emu.regs.rsi;
            let len = emu.regs.rdx;

            let fam: u16 = emu.maps.read_word(sockaddr).expect("cannot read family id");
            let port: u16 = emu
                .maps
                .read_word(sockaddr + 2)
                .expect("cannot read the port")
                .to_be();
            let ip: u32 = emu
                .maps
                .read_dword(sockaddr + 4)
                .expect("cannot read the ip");
            let sip = format!(
                "{}.{}.{}.{}",
                ip & 0xff,
                (ip & 0xff00) >> 8,
                (ip & 0xff0000) >> 16,
                (ip & 0xff000000) >> 24
            );

            log::info!(
                "{}** {} syscall socketcall bind() sock: {} fam: {} {}:{} {}",
                emu.colors.light_red,
                emu.pos,
                sock,
                fam,
                sip,
                port,
                emu.colors.nc
            );

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
            } else {
                emu.regs.rax = 0;
            }
        }

        constants::NR64_CONNECT => {
            let sock = emu.regs.rdi;
            let sockaddr = emu.regs.rsi;
            let len = emu.regs.rdx;

            let fam: u16 = emu.maps.read_word(sockaddr).expect("cannot read family id");
            let port: u16 = emu
                .maps
                .read_word(sockaddr + 2)
                .expect("cannot read the port")
                .to_be();
            let ip: u32 = emu
                .maps
                .read_dword(sockaddr + 4)
                .expect("cannot read the ip");
            let sip = format!(
                "{}.{}.{}.{}",
                ip & 0xff,
                (ip & 0xff00) >> 8,
                (ip & 0xff0000) >> 16,
                (ip & 0xff000000) >> 24
            );

            log::info!(
                "{}** {} syscall socketcall connect() sock: {} fam: {} {}:{} {}",
                emu.colors.light_red,
                emu.pos,
                sock,
                fam,
                sip,
                port,
                emu.colors.nc
            );

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
                return;
            }

            /*
            if emu.cfg.endpoint {
                if endpoint::sock_connect(sip.as_str(), port) {
                    log::info!("\tconnected to the endpoint.");
                } else {
                    log::info!("\tcannot connect. dont use -e");
                }
            }*/

            emu.regs.rax = 0;
        }

        constants::NR64_LISTEN => {
            let sock = emu.regs.rdi;
            let conns = emu.regs.rsi;

            log::info!(
                "{}** {} syscall socketcall listen() sock: {} conns: {} {}",
                emu.colors.light_red,
                emu.pos,
                sock,
                conns,
                emu.colors.nc
            );

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
            } else {
                emu.regs.rax = 0;
            }
        }

        constants::NR64_ACCEPT => {
            let sock = emu.regs.rdi;
            let sockaddr = emu.regs.rsi;
            let len = emu.regs.rdx;

            let port: u16 = 8080;
            let incoming_ip: u32 = 0x11223344;

            if sockaddr != 0 && emu.maps.is_mapped(sockaddr) {
                emu.maps.write_word(sockaddr, 0x0002);
                emu.maps.write_word(sockaddr + 2, port.to_le()); //TODO: port should be the same than bind()
                emu.maps.write_dword(sockaddr + 4, incoming_ip);
            }

            log::info!(
                "{}** {} syscall socketcall accept() {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
            } else {
                emu.regs.rax = 0;
            }
        }

        constants::NR64_GETSOCKNAME => {
            let sock = emu.regs.rdi;
            log::info!(
                "{}** {} syscall socketcall getsockname() sock: {} {}",
                emu.colors.light_red,
                emu.pos,
                sock,
                emu.colors.nc
            );
            todo!("implement this");
        }

        constants::NR64_GETPEERNAME => {
            log::info!(
                "{}** {} syscall socketcall getpeername()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_SOCKETPAIR => {
            log::info!(
                "{}** {} syscall socketcall socketpair()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        /*constants::NR64_SEND => {
            let sock = emu.maps.read_dword(emu.regs.rsp).expect("send() cannot read sock");
            let buf = emu.maps.read_dword(emu.regs.rsp+4).expect("send() cannot read buff");
            let len = emu.maps.read_dword(emu.regs.rsp+8).expect("send() cannot read len");
            let flags = emu.maps.read_dword(emu.regs.rsp+12).expect("send() cannot read flags");

            log::info!("{}** {} syscall socketcall send() sock: {} buff: {} len: {} {}", emu.colors.light_red, emu.pos, sock, buf, len, emu.colors.nc);

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
                return;
            }

            if emu.cfg.endpoint {
                let buffer = emu.maps.read_buffer(buf, len as usize);
                let n = endpoint::sock_send(&buffer);
                log::info!("\tsent {} bytes.", n);
                emu.regs.rax = n;
            } else {
                emu.regs.rax = len;
            }
        }

        constants::NR64_RECV => {
            let sock = emu.maps.read_dword(emu.regs.rsp).expect("recv() cannot read sock");
            let buf = emu.maps.read_dword(emu.regs.rsp+4).expect("recv() cannot read buff");
            let len = emu.maps.read_dword(emu.regs.rsp+8).expect("recv() cannot read len");
            let flags = emu.maps.read_dword(emu.regs.rsp+12).expect("recv() cannot read flags");

            log::info!("{}** {} syscall socketcall recv() sock: {} buff: {} len: {}  {}", emu.colors.light_red, emu.pos, sock, buf, len, emu.colors.nc);

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
                return;
            }

            if emu.cfg.endpoint {

                let mut rbuff:Vec<u8> = vec![0;len as usize];
                let n = endpoint::sock_recv(&mut rbuff);
                emu.maps.write_buffer(buf, &rbuff);
                log::info!("\nreceived {} bytes from the endpoint.", n);
                emu.regs.rax = n;

            } else {
                emu.regs.rax = len; //TODO: avoid loops
            }
        }*/
        constants::NR64_SENDTO => {
            let sock = emu.regs.rdi;
            let buf = emu.regs.rsi;
            let len = emu.regs.rdx;
            let flags = emu.regs.r10;
            let sockaddr = emu.regs.r8;
            let addrlen = emu.regs.r9;

            if sockaddr != 0 && emu.maps.is_mapped(sockaddr) {
                let fam: u16 = emu.maps.read_word(sockaddr).expect("cannot read family id");
                let port: u16 = emu
                    .maps
                    .read_word(sockaddr + 2)
                    .expect("cannot read the port")
                    .to_be();
                let ip: u32 = emu
                    .maps
                    .read_dword(sockaddr + 4)
                    .expect("cannot read the ip");
                let sip = format!(
                    "{}.{}.{}.{}",
                    ip & 0xff,
                    (ip & 0xff00) >> 8,
                    (ip & 0xff0000) >> 16,
                    (ip & 0xff000000) >> 24
                );

                log::info!("{}** {} syscall socketcall sendto() sock: {} buff: {} len: {} fam: {} {}:{} {}", emu.colors.light_red, emu.pos, sock, buf, len, fam, sip, port, emu.colors.nc);
            } else {
                log::info!(
                    "{}** {} syscall socketcall sendto() sock: {} buff: {} len: {} {}",
                    emu.colors.light_red,
                    emu.pos,
                    sock,
                    buf,
                    len,
                    emu.colors.nc
                );
            }

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
            } else {
                emu.regs.rax = len;
            }
        }

        constants::NR64_RECVFROM => {
            let sock = emu.regs.rdi;
            let buf = emu.regs.rsi;
            let len = emu.regs.rdx;
            let flags = emu.regs.r10;
            let sockaddr = emu.regs.r8;
            let addrlen = emu.regs.r9;

            if sockaddr != 0 && emu.maps.is_mapped(sockaddr) {
                let port: u16 = 8080;
                let incoming_ip: u32 = 0x11223344;

                emu.maps.write_word(sockaddr, 0x0002);
                emu.maps.write_word(sockaddr + 2, port.to_le()); //TODO: port should be the same than bind()
                emu.maps.write_dword(sockaddr + 4, incoming_ip);
            }

            log::info!(
                "{}** {} syscall socketcall recvfrom() sock: {} buff: {} len: {} {}",
                emu.colors.light_red,
                emu.pos,
                sock,
                buf,
                len,
                emu.colors.nc
            );

            if !helper::socket_exist(sock) {
                log::info!("\tbad socket/");
                emu.regs.rax = constants::ENOTSOCK;
            } else {
                emu.regs.rax = len; //TODO: avoid loops
            }
        }

        constants::NR64_SHUTDOWN => {
            log::info!(
                "{}** {} syscall socketcall shutdown()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
            //endpoint::sock_close();
        }

        constants::NR64_SETSOCKOPT => {
            log::info!(
                "{}** {} syscall socketcall setsockopt()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_GETSOCKOPT => {
            log::info!(
                "{}** {} syscall socketcall getsockopt()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_SENDMSG => {
            log::info!(
                "{}** {} syscall socketcall sendmsg()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_RECVMSG => {
            log::info!(
                "{}** {} syscall socketcall recvmsg()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_ACCEPT4 => {
            log::info!(
                "{}** {} syscall socketcall accept4()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_RECVMMSG => {
            log::info!(
                "{}** {} syscall socketcall recvmsg()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_SENDMMSG => {
            log::info!(
                "{}** {} syscall socketcall sendmsg()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        constants::NR64_ARCH_PRCTL => {
            let mode = emu.regs.rdi;
            let ptr = emu.regs.rsi;
            emu.regs.rax = 0;
            let mut op: String = "unimplemented operation".to_string();

            match mode {
                constants::ARCH_SET_GS => {
                    op = "set gs".to_string();
                    emu.regs.gs = emu
                        .maps
                        .read_qword(ptr)
                        .expect("kernel64 cannot read ptr for set gs");
                }
                constants::ARCH_SET_FS => {
                    op = "set fs".to_string();
                    emu.regs.fs = emu
                        .maps
                        .read_qword(ptr)
                        .expect("kernel64 cannot read ptr for set fs");
                }
                constants::ARCH_GET_FS => {
                    op = "get fs".to_string();
                    emu.maps.write_qword(ptr, emu.regs.fs);
                }
                constants::ARCH_GET_GS => {
                    op = "get gs".to_string();
                    emu.maps.write_qword(ptr, emu.regs.gs);
                }
                _ => {}
            }

            log::info!(
                "{}** {} syscall arch_prctl({})  {}",
                emu.colors.light_red,
                emu.pos,
                op,
                emu.colors.nc
            );
        }

        constants::NR64_UNAME => {
            emu.regs.rax = 0;
            let ptr = emu.regs.rdi;
            emu.maps.write_bytes(ptr, constants::UTSNAME.to_vec());

            log::info!(
                "{}** {} syscall uname(0x{:x})  {}",
                emu.colors.light_red,
                emu.pos,
                ptr,
                emu.colors.nc
            );
        }

        constants::NR64_ACCESS => {
            let filename = emu.maps.read_string(emu.regs.rdi);

            log::info!(
                "{}** {} syscall access({})  {}",
                emu.colors.light_red,
                emu.pos,
                filename,
                emu.colors.nc
            );

            if filename == "/etc/ld.so.preload" {
                emu.regs.rax = constants::ENOENT;
            } else {
                emu.regs.rax = 0;
            }
        }

        constants::NR64_MUNMAP => {
            let addr = emu.regs.rdi;
            let sz = emu.regs.rsi;

            emu.maps.free(&format!("mmap_{:x}", addr));

            log::info!(
                "{}** {} syscall munmap(0x{:x} sz:{})  {}",
                emu.colors.light_red,
                emu.pos,
                addr,
                sz,
                emu.colors.nc
            );

            emu.regs.rax = 0;
        }

        constants::NR64_MMAP => {
            let mut addr = emu.regs.rdi;
            let mut sz = emu.regs.rsi;
            let prot = emu.regs.rdx;
            let flags = emu.regs.r10;
            let fd = emu.regs.r8;
            let off = emu.regs.r9;

            if addr == 0 {
                if sz > 0xffffff {
                    log::info!("/!\\ Warning trying to allocate {} bytes", sz);
                    sz = 0xffffff;
                }
                addr = emu
                    .maps
                    .lib64_alloc(sz)
                    .expect("syscall64 mmap cannot alloc");
            }

            let map = emu
                .maps
                .create_map(&format!("mmap_{:x}", addr), addr, sz)
                .expect("cannot create mmap map");

            if helper::handler_exist(fd) {
                let filepath = helper::handler_get_uri(fd);
                if filepath.contains(".so") {
                    let mut lib_buff: Vec<u8> = Vec::new();

                    //log::info!("opening lib: {}", filepath);
                    match File::open(&filepath) {
                        Ok(f) => {
                            let len = f.metadata().unwrap().len();
                            let mut reader = BufReader::new(&f);
                            reader
                                .seek(SeekFrom::Start(off))
                                .expect("mmap offset out of file");
                            reader
                                .read_to_end(&mut lib_buff)
                                .expect("kernel64 cannot load dynamic library");
                            f.sync_all();

                            //log::info!("readed a lib with sz: {} buff:0x{:x}", lib_buff.len(), addr);

                            let map = emu
                                .maps
                                .get_mem_by_addr(addr)
                                .expect("buffer send to read syscall point to no map");

                            // does the file data bypasses mem end?
                            let mem_end = map.get_base() + map.size() as u64 - 1;
                            let buff_end = addr + lib_buff.len() as u64 - 1;
                            if buff_end > mem_end {
                                let overflow = buff_end - mem_end;
                                lib_buff = lib_buff[0..lib_buff.len() - overflow as usize].to_vec();
                            }

                            emu.maps.write_bytes(addr, lib_buff);
                            emu.regs.rax = sz;
                        }
                        Err(_) => {
                            log::info!("file not found");
                            emu.regs.rax = 0;
                        }
                    };
                }
            }

            log::info!(
                "{}** {} syscall mmap(fd:{} sz:{} off:{}) =0x{:x}  {}",
                emu.colors.light_red,
                emu.pos,
                fd as i32,
                sz,
                off,
                addr,
                emu.colors.nc
            );

            emu.regs.rax = addr;
        }

        constants::NR64_FSTAT => {
            let fd = emu.regs.rdi;
            let stat_ptr = emu.regs.rsi;
            let mut stat = structures::Stat::fake();

            if helper::handler_exist(fd) {
                let filepath = helper::handler_get_uri(fd);
                let path = Path::new(&filepath);
                let metadata = fs::metadata(path)
                    .expect("this file should exist because was opened by kernel64");
                let file_size = metadata.len();
                stat.size = file_size as i64;
            }

            stat.save(stat_ptr, &mut emu.maps);

            log::info!(
                "{}** {} syscall ftat(0x{:x})  =0 {}",
                emu.colors.light_red,
                emu.pos,
                emu.regs.rdi,
                emu.colors.nc
            );

            emu.regs.rax = 0;
        }

        constants::NR64_STAT => {
            let filename_ptr = emu.regs.rdi;
            let stat_ptr = emu.regs.rsi;
            let filename = emu.maps.read_string(filename_ptr);

            let mut stat = structures::Stat::fake();
            let path = Path::new(&filename);
            let metadata =
                fs::metadata(path).expect("this file should exist because was opened by kernel64");
            let file_size = metadata.len();
            stat.size = file_size as i64;
            stat.save(stat_ptr, &mut emu.maps);

            log::info!(
                "{}** {} syscall stat({})  =0 {}",
                emu.colors.light_red,
                emu.pos,
                filename,
                emu.colors.nc
            );

            emu.regs.rax = 0;
        }

        constants::NR64_READLINK => {
            let link_ptr = emu.regs.rdi;
            let buff = emu.regs.rsi;
            let buffsz = emu.regs.rdx;

            let link = emu.maps.read_string(link_ptr);
            let sym_link_dest = match fs::read_link(&link) {
                Ok(link) => link,
                Err(_) => {
                    emu.regs.rax = 0xffffffffffffffff;
                    log::info!(
                        "{}** {} syscall uname({}) err! {}",
                        emu.colors.light_red,
                        emu.pos,
                        link,
                        emu.colors.nc
                    );
                    return;
                }
            };

            emu.maps.write_string(buff, sym_link_dest.to_str().unwrap());

            log::info!(
                "{}** {} syscall uname({})  {}",
                emu.colors.light_red,
                emu.pos,
                link,
                emu.colors.nc
            );

            emu.regs.rax = sym_link_dest.as_os_str().len() as u64;
        }

        constants::NR64_MPROTECT => {
            let addr = emu.regs.rdi;
            let sz = emu.regs.rsi;
            let prot = emu.regs.rdx;

            /*if emu.maps.is_mapped(addr) {
                emu.regs.rax = 0;
            } else {
                emu.regs.rax = 0xffffffff_ffffffff;
            }*/
            emu.regs.rax = 0;

            log::info!(
                "{}** {} syscall mprotect(0x{:x}) ={:x} {}",
                emu.colors.light_red,
                emu.pos,
                addr,
                emu.regs.rax,
                emu.colors.nc
            );
        }

        _ => {
            let data: Vec<String> = vec![
                "read".to_string(),
                "write".to_string(),
                "open".to_string(),
                "close".to_string(),
                "stat".to_string(),
                "fstat".to_string(),
                "lstat".to_string(),
                "poll".to_string(),
                "lseek".to_string(),
                "mmap".to_string(),
                "mprotect".to_string(),
                "munmap".to_string(),
                "brk".to_string(),
                "rt_sigaction".to_string(),
                "rt_sigprocmask".to_string(),
                "rt_sigreturn".to_string(),
                "ioctl".to_string(),
                "pread64".to_string(),
                "pwrite64".to_string(),
                "readv".to_string(),
                "writev".to_string(),
                "access".to_string(),
                "pipe".to_string(),
                "select".to_string(),
                "sched_yield".to_string(),
                "mremap".to_string(),
                "msync".to_string(),
                "mincore".to_string(),
                "madvise".to_string(),
                "shmget".to_string(),
                "shmat".to_string(),
                "shmctl".to_string(),
                "dup".to_string(),
                "dup2".to_string(),
                "pause".to_string(),
                "nanosleep".to_string(),
                "getitimer".to_string(),
                "alarm".to_string(),
                "setitimer".to_string(),
                "getpid".to_string(),
                "sendfile".to_string(),
                "socket".to_string(),
                "connect".to_string(),
                "accept".to_string(),
                "sendto".to_string(),
                "recvfrom".to_string(),
                "sendmsg".to_string(),
                "recvmsg".to_string(),
                "shutdown".to_string(),
                "bind".to_string(),
                "listen".to_string(),
                "getsockname".to_string(),
                "getpeername".to_string(),
                "socketpair".to_string(),
                "setsockopt".to_string(),
                "getsockopt".to_string(),
                "clone".to_string(),
                "fork".to_string(),
                "vfork".to_string(),
                "execve".to_string(),
                "exit".to_string(),
                "wait4".to_string(),
                "kill".to_string(),
                "uname".to_string(),
                "semget".to_string(),
                "semop".to_string(),
                "semctl".to_string(),
                "shmdt".to_string(),
                "msgget".to_string(),
                "msgsnd".to_string(),
                "msgrcv".to_string(),
                "msgctl".to_string(),
                "fcntl".to_string(),
                "flock".to_string(),
                "fsync".to_string(),
                "fdatasync".to_string(),
                "truncate".to_string(),
                "ftruncate".to_string(),
                "getdents".to_string(),
                "getcwd".to_string(),
                "chdir".to_string(),
                "fchdir".to_string(),
                "rename".to_string(),
                "mkdir".to_string(),
                "rmdir".to_string(),
                "creat".to_string(),
                "link".to_string(),
                "unlink".to_string(),
                "symlink".to_string(),
                "readlink".to_string(),
                "chmod".to_string(),
                "fchmod".to_string(),
                "chown".to_string(),
                "fchown".to_string(),
                "lchown".to_string(),
                "umask".to_string(),
                "gettimeofday".to_string(),
                "getrlimit".to_string(),
                "getrusage".to_string(),
                "sysinfo".to_string(),
                "times".to_string(),
                "ptrace".to_string(),
                "getuid".to_string(),
                "syslog".to_string(),
                "getgid".to_string(),
                "setuid".to_string(),
                "setgid".to_string(),
                "geteuid".to_string(),
                "getegid".to_string(),
                "setpgid".to_string(),
                "getppid".to_string(),
                "getpgrp".to_string(),
                "setsid".to_string(),
                "setreuid".to_string(),
                "setregid".to_string(),
                "getgroups".to_string(),
                "setgroups".to_string(),
                "setresuid".to_string(),
                "getresuid".to_string(),
                "setresgid".to_string(),
                "getresgid".to_string(),
                "getpgid".to_string(),
                "setfsuid".to_string(),
                "setfsgid".to_string(),
                "getsid".to_string(),
                "capget".to_string(),
                "capset".to_string(),
                "rt_sigpending".to_string(),
                "rt_sigtimedwait".to_string(),
                "rt_sigqueueinfo".to_string(),
                "rt_sigsuspend".to_string(),
                "sigaltstack".to_string(),
                "utime".to_string(),
                "mknod".to_string(),
                "uselib".to_string(),
                "personality".to_string(),
                "ustat".to_string(),
                "statfs".to_string(),
                "fstatfs".to_string(),
                "sysfs".to_string(),
                "getpriority".to_string(),
                "setpriority".to_string(),
                "sched_setparam".to_string(),
                "sched_getparam".to_string(),
                "sched_setscheduler".to_string(),
                "sched_getscheduler".to_string(),
                "sched_get_priority_max".to_string(),
                "sched_get_priority_min".to_string(),
                "sched_rr_get_interval".to_string(),
                "mlock".to_string(),
                "munlock".to_string(),
                "mlockall".to_string(),
                "munlockall".to_string(),
                "vhangup".to_string(),
                "modify_ldt".to_string(),
                "pivot_root".to_string(),
                "_sysctl".to_string(),
                "prctl".to_string(),
                "arch_prctl".to_string(),
                "adjtimex".to_string(),
                "setrlimit".to_string(),
                "chroot".to_string(),
                "sync".to_string(),
                "acct".to_string(),
                "settimeofday".to_string(),
                "mount".to_string(),
                "umount2".to_string(),
                "swapon".to_string(),
                "swapoff".to_string(),
                "reboot".to_string(),
                "sethostname".to_string(),
                "setdomainname".to_string(),
                "iopl".to_string(),
                "ioperm".to_string(),
                "create_module".to_string(),
                "init_module".to_string(),
                "delete_module".to_string(),
                "get_kernel_syms".to_string(),
                "query_module".to_string(),
                "quotactl".to_string(),
                "nfsservctl".to_string(),
                "getpmsg".to_string(),
                "putpmsg".to_string(),
                "afs_syscall".to_string(),
                "tuxcall".to_string(),
                "security".to_string(),
                "gettid".to_string(),
                "readahead".to_string(),
                "setxattr".to_string(),
                "lsetxattr".to_string(),
                "fsetxattr".to_string(),
                "getxattr".to_string(),
                "lgetxattr".to_string(),
                "fgetxattr".to_string(),
                "listxattr".to_string(),
                "llistxattr".to_string(),
                "flistxattr".to_string(),
                "removexattr".to_string(),
                "lremovexattr".to_string(),
                "fremovexattr".to_string(),
                "tkill".to_string(),
                "time".to_string(),
                "futex".to_string(),
                "sched_setaffinity".to_string(),
                "sched_getaffinity".to_string(),
                "set_thread_area".to_string(),
                "io_setup".to_string(),
                "io_destroy".to_string(),
                "io_getevents".to_string(),
                "io_submit".to_string(),
                "io_cancel".to_string(),
                "get_thread_area".to_string(),
                "lookup_dcookie".to_string(),
                "epoll_create".to_string(),
                "epoll_ctl_old".to_string(),
                "epoll_wait_old".to_string(),
                "remap_file_pages".to_string(),
                "getdents64".to_string(),
                "set_tid_address".to_string(),
                "restart_syscall".to_string(),
                "semtimedop".to_string(),
                "fadvise64".to_string(),
                "timer_create".to_string(),
                "timer_settime".to_string(),
                "timer_gettime".to_string(),
                "timer_getoverrun".to_string(),
                "timer_delete".to_string(),
                "clock_settime".to_string(),
                "clock_gettime".to_string(),
                "clock_getres".to_string(),
                "clock_nanosleep".to_string(),
                "exit_group".to_string(),
                "epoll_wait".to_string(),
                "epoll_ctl".to_string(),
                "tgkill".to_string(),
                "utimes".to_string(),
                "vserver".to_string(),
                "mbind".to_string(),
                "set_mempolicy".to_string(),
                "get_mempolicy".to_string(),
                "mq_open".to_string(),
                "mq_unlink".to_string(),
                "mq_timedsend".to_string(),
                "mq_timedreceive".to_string(),
                "mq_notify".to_string(),
                "mq_getsetattr".to_string(),
                "kexec_load".to_string(),
                "waitid".to_string(),
                "add_key".to_string(),
                "request_key".to_string(),
                "keyctl".to_string(),
                "ioprio_set".to_string(),
                "ioprio_get".to_string(),
                "inotify_init".to_string(),
                "inotify_add_watch".to_string(),
                "inotify_rm_watch".to_string(),
                "migrate_pages".to_string(),
                "openat".to_string(),
                "mkdirat".to_string(),
                "mknodat".to_string(),
                "fchownat".to_string(),
                "futimesat".to_string(),
                "newfstatat".to_string(),
                "unlinkat".to_string(),
                "renameat".to_string(),
                "linkat".to_string(),
                "symlinkat".to_string(),
                "readlinkat".to_string(),
                "fchmodat".to_string(),
                "faccessat".to_string(),
                "pselect6".to_string(),
                "ppoll".to_string(),
                "unshare".to_string(),
                "set_robust_list".to_string(),
                "get_robust_list".to_string(),
                "splice".to_string(),
                "tee".to_string(),
                "sync_file_range".to_string(),
                "vmsplice".to_string(),
                "move_pages".to_string(),
                "utimensat".to_string(),
                "epoll_pwait".to_string(),
                "signalfd".to_string(),
                "timerfd_create".to_string(),
                "eventfd".to_string(),
                "fallocate".to_string(),
                "timerfd_settime".to_string(),
                "timerfd_gettime".to_string(),
                "accept4".to_string(),
                "signalfd4".to_string(),
                "eventfd2".to_string(),
                "epoll_create1".to_string(),
                "dup3".to_string(),
                "pipe2".to_string(),
                "inotify_init1".to_string(),
                "preadv".to_string(),
                "pwritev".to_string(),
                "rt_tgsigqueueinfo".to_string(),
                "perf_event_open".to_string(),
                "recvmmsg".to_string(),
                "fanotify_init".to_string(),
                "fanotify_mark".to_string(),
                "prlimit64".to_string(),
                "name_to_handle_at".to_string(),
                "open_by_handle_at".to_string(),
                "clock_adjtime".to_string(),
                "syncfs".to_string(),
                "sendmmsg".to_string(),
                "setns".to_string(),
                "getcpu".to_string(),
                "process_vm_readv".to_string(),
                "process_vm_writev".to_string(),
                "kcmp".to_string(),
                "finit_module".to_string(),
                "sched_setattr".to_string(),
                "sched_getattr".to_string(),
                "renameat2".to_string(),
                "seccomp".to_string(),
                "getrandom".to_string(),
                "memfd_create".to_string(),
                "kexec_file_load".to_string(),
                "bpf".to_string(),
                "execveat".to_string(),
                "userfaultfd".to_string(),
                "membarrier".to_string(),
                "mlock2".to_string(),
                "copy_file_range".to_string(),
                "preadv2".to_string(),
                "pwritev2".to_string(),
                "pkey_mprotect".to_string(),
                "pkey_alloc".to_string(),
                "pkey_free".to_string(),
                "statx".to_string(),
                "io_pgetevents".to_string(),
                "rseq".to_string(),
                "pidfd_send_signal".to_string(),
                "io_uring_setup".to_string(),
                "io_uring_enter".to_string(),
                "io_uring_register".to_string(),
                "open_tree".to_string(),
                "move_mount".to_string(),
                "fsopen".to_string(),
                "fsconfig".to_string(),
                "fsmount".to_string(),
                "fspick".to_string(),
                "pidfd_open".to_string(),
                "clone3".to_string(),
                "close_range".to_string(),
                "openat2".to_string(),
                "pidfd_getfd".to_string(),
                "faccessat2".to_string(),
                "process_madvise".to_string(),
                "epoll_pwait2".to_string(),
                "mount_setattr".to_string(),
                "quotactl_fd".to_string(),
                "landlock_create_ruleset".to_string(),
                "landlock_add_rule".to_string(),
                "landlock_restrict_self".to_string(),
                "memfd_secret".to_string(),
                "process_mrelease".to_string(),
            ];

            if emu.regs.rax >= data.len() as u64 {
                log::info!(
                    "{}** interrupt 0x80 bad rax value 0x{:x} {}",
                    emu.colors.light_red,
                    emu.regs.rax,
                    emu.colors.nc
                );
            } else {
                log::info!(
                    "{}** interrupt 0x80 function:{} {}",
                    emu.colors.light_red,
                    data[emu.regs.rax as usize],
                    emu.colors.nc
                );
            }
        }
    }
}
