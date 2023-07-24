use crate::emu;
use crate::emu::constants;
use crate::emu::endpoint;
use crate::emu::winapi32::helper;

//  /usr/include/asm/unistd_32.h

//TODO: check if buff is mapped

pub fn gateway(emu: &mut emu::Emu) {
    emu.regs.sanitize32();

    match emu.regs.get_eax() {
        0 => {
            println!(
                "{}** {} syscall restart_syscall {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        1 => {
            println!(
                "{}** {} syscall exit()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
            std::process::exit(1);
        }

        2 => {
            println!(
                "{}** {} syscall fork()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
            emu.spawn_console();
        }

        3 => {
            let fd = emu.regs.rbx;
            let buff = emu.regs.rcx;
            let sz = emu.regs.rdx;
            emu.regs.rax = buff;
            println!(
                "{}** {} syscall read() fd: {} buf: 0x{:x} sz: {} {}",
                emu.colors.light_red, emu.pos, fd, buff, sz, emu.colors.nc
            );
        }

        4 => {
            let fd = emu.regs.rbx;
            let buff = emu.regs.rcx;
            let sz = emu.regs.rdx;
            emu.regs.rax = sz;
            println!(
                "{}** {} syscall write() fd: {} buf: 0x{:x} sz: {} {}",
                emu.colors.light_red, emu.pos, fd, buff, sz, emu.colors.nc
            );
        }

        5 => {
            let file_path = emu.maps.read_string(emu.regs.rbx);
            let fd = helper::socket_create();
            emu.regs.rax = fd as u64;
            println!(
                "{}** {} syscall open() file: {} fd:{} {}",
                emu.colors.light_red, emu.pos, file_path, fd, emu.colors.nc
            );
        }

        6 => {
            let fd = emu.regs.rbx;
            println!(
                "{}** {} syscall close() fd: {}  {}",
                emu.colors.light_red, emu.pos, fd, emu.colors.nc
            );
            helper::socket_close(fd);
            endpoint::sock_close();
        }

        7 => {
            println!(
                "{}** {} syscall waitpid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        8 => {
            println!(
                "{}** {} syscall creat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        9 => {
            println!(
                "{}** {} syscall link()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        10 => {
            println!(
                "{}** {} syscall unlink()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        11 => {
            let cmd = emu.maps.read_string(emu.regs.rbx);
            println!(
                "{}** {} syscall execve()  cmd: {} {}",
                emu.colors.light_red, emu.pos, cmd, emu.colors.nc
            );
            emu.regs.rax = 0;
        }

        12 => {
            let path = emu.maps.read_string(emu.regs.rbx);
            println!(
                "{}** {} syscall chdir() path: {} {}",
                emu.colors.light_red, emu.pos, path, emu.colors.nc
            );
        }

        13 => {
            println!(
                "{}** {} syscall time()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        14 => {
            println!(
                "{}** {} syscall mknod()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        15 => {
            let file_path = emu.maps.read_string(emu.regs.rbx);
            let perm = emu.regs.rcx;
            println!(
                "{}** {} syscall chmod() file: {} perm: {} {}",
                emu.colors.light_red, emu.pos, file_path, perm, emu.colors.nc
            );
        }

        16 => {
            println!(
                "{}** {} syscall lchown()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        17 => {
            println!(
                "{}** {} syscall break()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        18 => {
            println!(
                "{}** {} syscall oldstat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        19 => {
            let fd = emu.regs.rbx;
            println!(
                "{}** {} syscall lseek()  fd: {} {}",
                emu.colors.light_red, emu.pos, fd, emu.colors.nc
            );
        }

        20 => {
            println!(
                "{}** {} syscall getpid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        21 => {
            println!(
                "{}** {} syscall mount()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        22 => {
            println!(
                "{}** {} syscall umount()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        23 => {
            println!(
                "{}** {} syscall setuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        24 => {
            println!(
                "{}** {} syscall getuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        25 => {
            println!(
                "{}** {} syscall stime()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        26 => {
            println!(
                "{}** {} syscall ptrace()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        27 => {
            println!(
                "{}** {} syscall alarm()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        28 => {
            println!(
                "{}** {} syscall oldfstat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        29 => {
            println!(
                "{}** {} syscall pause()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        30 => {
            println!(
                "{}** {} syscall utime()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        31 => {
            println!(
                "{}** {} syscall stty()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        32 => {
            println!(
                "{}** {} syscall gtty()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        33 => {
            println!(
                "{}** {} syscall access()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        34 => {
            println!(
                "{}** {} syscall nice()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        35 => {
            println!(
                "{}** {} syscall ftime()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        36 => {
            println!(
                "{}** {} syscall sync()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        37 => {
            let pid = emu.regs.rbx;
            let sig = emu.regs.rcx;
            println!(
                "{}** {} syscall kill() pid: {} sig: {} {}",
                emu.colors.light_red, emu.pos, pid, sig, emu.colors.nc
            );
        }

        38 => {
            println!(
                "{}** {} syscall rename()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        39 => {
            println!(
                "{}** {} syscall mkdir()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        40 => {
            println!(
                "{}** {} syscall rmdir()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        41 => {
            let fd = emu.regs.rbx;
            println!(
                "{}** {} syscall dup() fd: {} {}",
                emu.colors.light_red, emu.pos, fd, emu.colors.nc
            );
        }

        42 => {
            println!(
                "{}** {} syscall pipe()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        43 => {
            println!(
                "{}** {} syscall times()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        44 => {
            println!(
                "{}** {} syscall prof()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        45 => {
            println!(
                "{}** {} syscall brk()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        46 => {
            println!(
                "{}** {} syscall setgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        47 => {
            println!(
                "{}** {} syscall getgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        48 => {
            println!(
                "{}** {} syscall signal()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        49 => {
            println!(
                "{}** {} syscall geteuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        50 => {
            println!(
                "{}** {} syscall getegid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        51 => {
            println!(
                "{}** {} syscall acct()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        52 => {
            println!(
                "{}** {} syscall umount2()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        53 => {
            println!(
                "{}** {} syscall lock()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        54 => {
            println!(
                "{}** {} syscall ioctl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        55 => {
            println!(
                "{}** {} syscall fcntl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        56 => {
            println!(
                "{}** {} syscall mpx()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        57 => {
            println!(
                "{}** {} syscall setpgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        58 => {
            println!(
                "{}** {} syscall ulimit()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        59 => {
            println!(
                "{}** {} syscall oldolduname()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        60 => {
            println!(
                "{}** {} syscall umask()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        61 => {
            println!(
                "{}** {} syscall chroot()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        62 => {
            println!(
                "{}** {} syscall ustat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        63 => {
            let old_fd = emu.regs.get_ebx();
            let new_fd = emu.regs.get_ecx();
            println!(
                "{}** {} syscall dup2() oldfd: {} newfd: {} {}",
                emu.colors.light_red, emu.pos, old_fd, new_fd, emu.colors.nc
            );
        }

        64 => {
            println!(
                "{}** {} syscall getppid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        65 => {
            println!(
                "{}** {} syscall getpgrp()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        66 => {
            println!(
                "{}** {} syscall setsid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        67 => {
            println!(
                "{}** {} syscall sigaction()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        68 => {
            println!(
                "{}** {} syscall sgetmask()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        69 => {
            println!(
                "{}** {} syscall ssetmask()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        70 => {
            println!(
                "{}** {} syscall setreuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        71 => {
            println!(
                "{}** {} syscall setregid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        72 => {
            println!(
                "{}** {} syscall sigsuspend()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        73 => {
            println!(
                "{}** {} syscall sigpending()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        74 => {
            println!(
                "{}** {} syscall sethostname()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        75 => {
            println!(
                "{}** {} syscall setrlimit()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        76 => {
            println!(
                "{}** {} syscall getrlimit()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        77 => {
            println!(
                "{}** {} syscall getrusage()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        78 => {
            println!(
                "{}** {} syscall gettimeofday()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        79 => {
            println!(
                "{}** {} syscall settimeofday()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        80 => {
            println!(
                "{}** {} syscall getgroups()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        81 => {
            println!(
                "{}** {} syscall setgroups()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        82 => {
            println!(
                "{}** {} syscall select()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        83 => {
            println!(
                "{}** {} syscall symlink()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        84 => {
            println!(
                "{}** {} syscall oldlstat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        85 => {
            println!(
                "{}** {} syscall readlink()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        86 => {
            println!(
                "{}** {} syscall uselib()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        87 => {
            println!(
                "{}** {} syscall swapon()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        88 => {
            println!(
                "{}** {} syscall reboot()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        89 => {
            println!(
                "{}** {} syscall readdir()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        90 => {
            println!(
                "{}** {} syscall mmap()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        91 => {
            println!(
                "{}** {} syscall munmap()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        92 => {
            println!(
                "{}** {} syscall truncate()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        93 => {
            println!(
                "{}** {} syscall ftruncate()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        94 => {
            println!(
                "{}** {} syscall fchmod()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        95 => {
            println!(
                "{}** {} syscall fchown()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        96 => {
            println!(
                "{}** {} syscall getpriority()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        97 => {
            println!(
                "{}** {} syscall setpriority()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        98 => {
            println!(
                "{}** {} syscall profil()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        99 => {
            println!(
                "{}** {} syscall statfs()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        100 => {
            println!(
                "{}** {} syscall fstatfs()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        101 => {
            println!(
                "{}** {} syscall ioperm()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        102 => {
            match emu.regs.rbx as u32 {
                constants::SYS_SOCKET => {
                    let sock = helper::socket_create();
                    let fam = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("socket() cannot read family");
                    let typ = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("socket() cannot ready type");
                    let proto = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("socket() cannot read proto");

                    println!("{}** {} syscall socketcall socket()  fam: {} type: {} proto: {} sock: {} {}", emu.colors.light_red, emu.pos, fam, typ, proto, sock, emu.colors.nc);
                    emu.regs.rax = sock;
                }

                constants::SYS_BIND => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("bind() cannot read sock");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("bind() cannot read sockaddr");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("bind() cannot read len");

                    let fam: u16 = emu
                        .maps
                        .read_word(sockaddr as u64)
                        .expect("cannot read family id");
                    let port: u16 = emu
                        .maps
                        .read_word((sockaddr + 2) as u64)
                        .expect("cannot read the port")
                        .to_be();
                    let ip: u32 = emu
                        .maps
                        .read_dword((sockaddr + 4) as u64)
                        .expect("cannot read the ip");
                    let sip = format!(
                        "{}.{}.{}.{}",
                        ip & 0xff,
                        (ip & 0xff00) >> 8,
                        (ip & 0xff0000) >> 16,
                        (ip & 0xff000000) >> 24
                    );

                    println!(
                        "{}** {} syscall socketcall bind() sock: {} fam: {} {}:{} {}",
                        emu.colors.light_red, emu.pos, sock, fam, sip, port, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = 0;
                    }
                }

                constants::SYS_CONNECT => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("connect() cannot read sock");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("connect() cannot read sockaddr");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("connect() cannot read len");

                    let fam: u16 = emu
                        .maps
                        .read_word(sockaddr as u64)
                        .expect("cannot read family id");
                    let port: u16 = emu
                        .maps
                        .read_word((sockaddr + 2) as u64)
                        .expect("cannot read the port")
                        .to_be();
                    let ip: u32 = emu
                        .maps
                        .read_dword((sockaddr + 4) as u64)
                        .expect("cannot read the ip");
                    let sip = format!(
                        "{}.{}.{}.{}",
                        ip & 0xff,
                        (ip & 0xff00) >> 8,
                        (ip & 0xff0000) >> 16,
                        (ip & 0xff000000) >> 24
                    );

                    println!(
                        "{}** {} syscall socketcall connect() sock: {} fam: {} {}:{} {}",
                        emu.colors.light_red, emu.pos, sock, fam, sip, port, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                        return;
                    }

                    if emu.cfg.endpoint {
                        if endpoint::sock_connect(sip.as_str(), port) {
                            println!("\tconnected to the endpoint.");
                        } else {
                            println!("\tcannot connect. dont use -e");
                        }
                    }

                    emu.regs.rax = 0;
                }

                constants::SYS_LISTEN => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("listen() cannot read sock");
                    let conns = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("listen() cannot read num of conns");

                    println!(
                        "{}** {} syscall socketcall listen() sock: {} conns: {} {}",
                        emu.colors.light_red, emu.pos, sock, conns, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = 0;
                    }
                }

                constants::SYS_ACCEPT => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("accept() cannot read sock");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("accept() cannot read sockaddr");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("accept() cannot read len");
                    let port: u16 = 8080;
                    let incoming_ip: u32 = 0x11223344;

                    if sockaddr != 0 && emu.maps.is_mapped(sockaddr as u64) {
                        emu.maps.write_word(sockaddr as u64, 0x0002);
                        emu.maps.write_word((sockaddr + 2) as u64, port.to_le()); //TODO: port should be the same than bind()
                        emu.maps.write_dword((sockaddr + 4) as u64, incoming_ip);
                    }

                    println!(
                        "{}** {} syscall socketcall accept() {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = 0;
                    }
                }

                constants::SYS_GETSOCKNAME => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("getsockname() cannot read sock");
                    println!(
                        "{}** {} syscall socketcall getsockname() sock: {} {}",
                        emu.colors.light_red, emu.pos, sock, emu.colors.nc
                    );
                    todo!("implement this");
                }

                constants::SYS_GETPEERNAME => {
                    println!(
                        "{}** {} syscall socketcall getpeername()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_SOCKETPAIR => {
                    println!(
                        "{}** {} syscall socketcall socketpair()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_SEND => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("send() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("send() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("send() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("send() cannot read flags");

                    println!(
                        "{}** {} syscall socketcall send() sock: {} buff: {} len: {} {}",
                        emu.colors.light_red, emu.pos, sock, buf, len, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                        return;
                    }

                    if emu.cfg.endpoint {
                        let buffer = emu.maps.read_buffer(buf as u64, len as usize);
                        let n = endpoint::sock_send(&buffer);
                        println!("\tsent {} bytes.", n);
                        emu.regs.rax = n as u64;
                    } else {
                        emu.regs.rax = len as u64;
                    }
                }

                constants::SYS_RECV => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("recv() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("recv() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("recv() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("recv() cannot read flags");

                    println!(
                        "{}** {} syscall socketcall recv() sock: {} buff: {} len: {}  {}",
                        emu.colors.light_red, emu.pos, sock, buf, len, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                        return;
                    }

                    if emu.cfg.endpoint {
                        let mut rbuff: Vec<u8> = vec![0; len as usize];
                        let n = endpoint::sock_recv(&mut rbuff);
                        emu.maps.write_buffer(buf as u64, &rbuff);
                        println!("\nreceived {} bytes from the endpoint.", n);
                        emu.regs.rax = n as u64;
                    } else {
                        emu.regs.rax = len as u64; //TODO: avoid loops
                    }
                }

                constants::SYS_SENDTO => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("sendto() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("sendto() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("sendto() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("sendto() cannot read flags");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 16)
                        .expect("sendto() cannot read sockaddr");
                    let addrlen = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 20)
                        .expect("sendto() cannot read addrlen");

                    if sockaddr != 0 && emu.maps.is_mapped(sockaddr as u64) {
                        let fam: u16 = emu
                            .maps
                            .read_word(sockaddr as u64)
                            .expect("cannot read family id");
                        let port: u16 = emu
                            .maps
                            .read_word((sockaddr + 2) as u64)
                            .expect("cannot read the port")
                            .to_be();
                        let ip: u32 = emu
                            .maps
                            .read_dword((sockaddr + 4) as u64)
                            .expect("cannot read the ip");
                        let sip = format!(
                            "{}.{}.{}.{}",
                            ip & 0xff,
                            (ip & 0xff00) >> 8,
                            (ip & 0xff0000) >> 16,
                            (ip & 0xff000000) >> 24
                        );

                        println!("{}** {} syscall socketcall sendto() sock: {} buff: {} len: {} fam: {} {}:{} {}", emu.colors.light_red, emu.pos, sock, buf, len, fam, sip, port, emu.colors.nc);
                    } else {
                        println!(
                            "{}** {} syscall socketcall sendto() sock: {} buff: {} len: {} {}",
                            emu.colors.light_red, emu.pos, sock, buf, len, emu.colors.nc
                        );
                    }

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = len as u64;
                    }
                }

                constants::SYS_RECVFROM => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("recvfrom() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("recvfrom() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("recvfrom() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 16)
                        .expect("recvfrom() cannot read flags");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 20)
                        .expect("recvfrom() cannot read sockaddr");
                    let addrlen = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 24)
                        .expect("recvfrom() cannot read sockaddr len");

                    if sockaddr != 0 && emu.maps.is_mapped(sockaddr as u64) {
                        let port: u16 = 8080;
                        let incoming_ip: u32 = 0x11223344;

                        emu.maps.write_word(sockaddr as u64, 0x0002);
                        emu.maps.write_word((sockaddr + 2) as u64, port.to_le()); //TODO: port should be the same than bind()
                        emu.maps.write_dword((sockaddr + 4) as u64, incoming_ip);
                    }

                    println!(
                        "{}** {} syscall socketcall recvfrom() sock: {} buff: {} len: {} {}",
                        emu.colors.light_red, emu.pos, sock, buf, len, emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        println!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = len as u64; //TODO: avoid loops
                    }
                }

                constants::SYS_SHUTDOWN => {
                    println!(
                        "{}** {} syscall socketcall shutdown()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                    endpoint::sock_close();
                }

                constants::SYS_SETSOCKOPT => {
                    println!(
                        "{}** {} syscall socketcall setsockopt()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_GETSOCKOPT => {
                    println!(
                        "{}** {} syscall socketcall getsockopt()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_SENDMSG => {
                    println!(
                        "{}** {} syscall socketcall sendmsg()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_RECVMSG => {
                    println!(
                        "{}** {} syscall socketcall recvmsg()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_ACCEPT4 => {
                    println!(
                        "{}** {} syscall socketcall accept4()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_RECVMMSG => {
                    println!(
                        "{}** {} syscall socketcall recvmsg()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                constants::SYS_SENDMMSG => {
                    println!(
                        "{}** {} syscall socketcall sendmsg()  {}",
                        emu.colors.light_red, emu.pos, emu.colors.nc
                    );
                }

                _ => panic!("invalid socket call {} ", emu.regs.rbx),
            }
        }

        103 => {
            println!(
                "{}** {} syscall syslog()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        104 => {
            println!(
                "{}** {} syscall setitimer()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        105 => {
            println!(
                "{}** {} syscall getitimer()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        106 => {
            println!(
                "{}** {} syscall stat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        107 => {
            println!(
                "{}** {} syscall lstat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        108 => {
            println!(
                "{}** {} syscall fstat()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        109 => {
            println!(
                "{}** {} syscall olduname()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        110 => {
            println!(
                "{}** {} syscall iopl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        111 => {
            println!(
                "{}** {} syscall vhanghup()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        112 => {
            println!(
                "{}** {} syscall idle()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        113 => {
            println!(
                "{}** {} syscall vm86old()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        114 => {
            println!(
                "{}** {} syscall wait4()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        115 => {
            println!(
                "{}** {} syscall swapoff()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        116 => {
            println!(
                "{}** {} syscall sysinfo()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        117 => {
            println!(
                "{}** {} syscall ipc()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        118 => {
            println!(
                "{}** {} syscall fsync()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        119 => {
            println!(
                "{}** {} syscall sigreturn()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        120 => {
            println!(
                "{}** {} syscall clone()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        121 => {
            println!(
                "{}** {} syscall setdomainname()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        122 => {
            println!(
                "{}** {} syscall uname()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        123 => {
            println!(
                "{}** {} syscall modify_ltd()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        124 => {
            println!(
                "{}** {} syscall adjtimex()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        125 => {
            println!(
                "{}** {} syscall mprotect()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        126 => {
            println!(
                "{}** {} syscall sigprocmask()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        127 => {
            println!(
                "{}** {} syscall create_module()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        128 => {
            println!(
                "{}** {} syscall init_module()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        129 => {
            println!(
                "{}** {} syscall delete_module()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        130 => {
            println!(
                "{}** {} syscall get_kernel_syms()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        131 => {
            println!(
                "{}** {} syscall quotactl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        132 => {
            println!(
                "{}** {} syscall getpgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        133 => {
            println!(
                "{}** {} syscall fchdir()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        134 => {
            println!(
                "{}** {} syscall bdflush()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        135 => {
            println!(
                "{}** {} syscall sysfs()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        136 => {
            println!(
                "{}** {} syscall personality()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        137 => {
            println!(
                "{}** {} syscall afs_syscall()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        138 => {
            println!(
                "{}** {} syscall setfsuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        139 => {
            println!(
                "{}** {} syscall setfsgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        140 => {
            println!(
                "{}** {} syscall _llseek()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        141 => {
            println!(
                "{}** {} syscall getdents()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        142 => {
            println!(
                "{}** {} syscall _newselect()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        143 => {
            println!(
                "{}** {} syscall flock()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        144 => {
            println!(
                "{}** {} syscall msync()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        145 => {
            println!(
                "{}** {} syscall readv()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        146 => {
            println!(
                "{}** {} syscall writev()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        147 => {
            println!(
                "{}** {} syscall getsid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        148 => {
            println!(
                "{}** {} syscall fdatasync()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        149 => {
            println!(
                "{}** {} syscall _sysctl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        150 => {
            println!(
                "{}** {} syscall mlock()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        151 => {
            println!(
                "{}** {} syscall munlock()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        152 => {
            println!(
                "{}** {} syscall mlockall()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        153 => {
            println!(
                "{}** {} syscall munlockall()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        154 => {
            println!(
                "{}** {} syscall sched_setparam()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        155 => {
            println!(
                "{}** {} syscall sched_getparam()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        156 => {
            println!(
                "{}** {} syscall sched_setscheduler()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        157 => {
            println!(
                "{}** {} syscall sched_getscheduler()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        158 => {
            println!(
                "{}** {} syscall sched_yield()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        159 => {
            println!(
                "{}** {} syscall sched_get_priority_max()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        160 => {
            println!(
                "{}** {} syscall sched_get_priority_min()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        161 => {
            println!(
                "{}** {} syscall sched_rr_get_inverval()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        162 => {
            println!(
                "{}** {} syscall nanosleep()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        163 => {
            println!(
                "{}** {} syscall mremap()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        164 => {
            println!(
                "{}** {} syscall setresuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        165 => {
            println!(
                "{}** {} syscall getresuid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        166 => {
            println!(
                "{}** {} syscall vm86()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        167 => {
            println!(
                "{}** {} syscall query_module()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        168 => {
            println!(
                "{}** {} syscall poll()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        169 => {
            println!(
                "{}** {} syscall nfsservctrl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        170 => {
            println!(
                "{}** {} syscall setresgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        171 => {
            println!(
                "{}** {} syscall getresgid()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        172 => {
            println!(
                "{}** {} syscall prctl()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        173 => {
            println!(
                "{}** {} syscall rt_sigreturn()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        174 => {
            println!(
                "{}** {} syscall rt_sigcation()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        175 => {
            println!(
                "{}** {} syscall rt_sigprocmask()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        176 => {
            println!(
                "{}** {} syscall rt_sigpending()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        177 => {
            println!(
                "{}** {} syscall rt_sigtimedwait()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        178 => {
            println!(
                "{}** {} syscall rt_sigqueueinfo()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        179 => {
            println!(
                "{}** {} syscall rt_sigsuspend()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        180 => {
            println!(
                "{}** {} syscall pread64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        181 => {
            println!(
                "{}** {} syscall pwrite64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        182 => {
            println!(
                "{}** {} syscall chown()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        183 => {
            println!(
                "{}** {} syscall getcwd()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        184 => {
            println!(
                "{}** {} syscall capget()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        185 => {
            println!(
                "{}** {} syscall capset()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        186 => {
            println!(
                "{}** {} syscall sigaltstack()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        187 => {
            println!(
                "{}** {} syscall sendfile()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        188 => {
            println!(
                "{}** {} syscall getpmsg()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        189 => {
            println!(
                "{}** {} syscall putpmsg()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        190 => {
            println!(
                "{}** {} syscall vfork()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        191 => {
            println!(
                "{}** {} syscall ugetrlimit()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        192 => {
            println!(
                "{}** {} syscall mmap2()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        193 => {
            println!(
                "{}** {} syscall truncate64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        194 => {
            println!(
                "{}** {} syscall ftruncate64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        195 => {
            println!(
                "{}** {} syscall stat64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        196 => {
            println!(
                "{}** {} syscall lstat64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        197 => {
            println!(
                "{}** {} syscall fstat64()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        198 => {
            println!(
                "{}** {} syscall lchown32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        199 => {
            println!(
                "{}** {} syscall getuid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        200 => {
            println!(
                "{}** {} syscall getgid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        201 => {
            println!(
                "{}** {} syscall geteuid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        202 => {
            println!(
                "{}** {} syscall getegid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        203 => {
            println!(
                "{}** {} syscall getreuid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        204 => {
            println!(
                "{}** {} syscall getregid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        205 => {
            println!(
                "{}** {} syscall getgrups32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        206 => {
            println!(
                "{}** {} syscall setgroups32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        207 => {
            println!(
                "{}** {} syscall fchown32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        208 => {
            println!(
                "{}** {} syscall setresuid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        209 => {
            println!(
                "{}** {} syscall getresuid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        210 => {
            println!(
                "{}** {} syscall setresgid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        211 => {
            println!(
                "{}** {} syscall getresgid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        212 => {
            println!(
                "{}** {} syscall chown32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        213 => {
            println!(
                "{}** {} syscall setuid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        214 => {
            println!(
                "{}** {} syscall setgid32()  {}",
                emu.colors.light_red, emu.pos, emu.colors.nc
            );
        }

        _ => {
            let data: Vec<String> = vec![
                "restart_syscall".to_string(),
                "exit".to_string(),
                "fork".to_string(),
                "read".to_string(),
                "write".to_string(),
                "open".to_string(),
                "close".to_string(),
                "waitpid".to_string(),
                "creat".to_string(),
                "link".to_string(),
                "unlink".to_string(),
                "execve".to_string(),
                "chdir".to_string(),
                "time".to_string(),
                "mknod".to_string(),
                "chmod".to_string(),
                "lchown".to_string(),
                "break".to_string(),
                "oldstat".to_string(),
                "lseek".to_string(),
                "getpid".to_string(),
                "mount".to_string(),
                "umount".to_string(),
                "setuid".to_string(),
                "getuid".to_string(),
                "stime".to_string(),
                "ptrace".to_string(),
                "alarm".to_string(),
                "oldfstat".to_string(),
                "pause".to_string(),
                "utime".to_string(),
                "stty".to_string(),
                "gtty".to_string(),
                "access".to_string(),
                "nice".to_string(),
                "ftime".to_string(),
                "sync".to_string(),
                "kill".to_string(),
                "rename".to_string(),
                "mkdir".to_string(),
                "rmdir".to_string(),
                "dup".to_string(),
                "pipe".to_string(),
                "times".to_string(),
                "prof".to_string(),
                "brk".to_string(),
                "setgid".to_string(),
                "getgid".to_string(),
                "signal".to_string(),
                "geteuid".to_string(),
                "getegid".to_string(),
                "acct".to_string(),
                "umount2".to_string(),
                "lock".to_string(),
                "ioctl".to_string(),
                "fcntl".to_string(),
                "mpx".to_string(),
                "setpgid".to_string(),
                "ulimit".to_string(),
                "oldolduname".to_string(),
                "umask".to_string(),
                "chroot".to_string(),
                "ustat".to_string(),
                "dup2".to_string(),
                "getppid".to_string(),
                "getpgrp".to_string(),
                "setsid".to_string(),
                "sigaction".to_string(),
                "sgetmask".to_string(),
                "ssetmask".to_string(),
                "setreuid".to_string(),
                "setregid".to_string(),
                "sigsuspend".to_string(),
                "sigpending".to_string(),
                "sethostname".to_string(),
                "setrlimit".to_string(),
                "getrlimit".to_string(),
                "getrusage".to_string(),
                "gettimeofday".to_string(),
                "settimeofday".to_string(),
                "getgroups".to_string(),
                "setgroups".to_string(),
                "select".to_string(),
                "symlink".to_string(),
                "oldlstat".to_string(),
                "readlink".to_string(),
                "uselib".to_string(),
                "swapon".to_string(),
                "reboot".to_string(),
                "readdir".to_string(),
                "mmap".to_string(),
                "munmap".to_string(),
                "truncate".to_string(),
                "ftruncate".to_string(),
                "fchmod".to_string(),
                "fchown".to_string(),
                "getpriority".to_string(),
                "setpriority".to_string(),
                "profil".to_string(),
                "statfs".to_string(),
                "fstatfs".to_string(),
                "ioperm".to_string(),
                "socketcall".to_string(),
                "syslog".to_string(),
                "setitimer".to_string(),
                "getitimer".to_string(),
                "stat".to_string(),
                "lstat".to_string(),
                "fstat".to_string(),
                "olduname".to_string(),
                "iopl".to_string(),
                "vhangup".to_string(),
                "idle".to_string(),
                "vm86old".to_string(),
                "wait4".to_string(),
                "swapoff".to_string(),
                "sysinfo".to_string(),
                "ipc".to_string(),
                "fsync".to_string(),
                "sigreturn".to_string(),
                "clone".to_string(),
                "setdomainname".to_string(),
                "uname".to_string(),
                "modify_ldt".to_string(),
                "adjtimex".to_string(),
                "mprotect".to_string(),
                "sigprocmask".to_string(),
                "create_module".to_string(),
                "init_module".to_string(),
                "delete_module".to_string(),
                "get_kernel_syms".to_string(),
                "quotactl".to_string(),
                "getpgid".to_string(),
                "fchdir".to_string(),
                "bdflush".to_string(),
                "sysfs".to_string(),
                "personality".to_string(),
                "afs_syscall".to_string(),
                "setfsuid".to_string(),
                "setfsgid".to_string(),
                "_llseek".to_string(),
                "getdents".to_string(),
                "_newselect".to_string(),
                "flock".to_string(),
                "msync".to_string(),
                "readv".to_string(),
                "writev".to_string(),
                "getsid".to_string(),
                "fdatasync".to_string(),
                "_sysctl".to_string(),
                "mlock".to_string(),
                "munlock".to_string(),
                "mlockall".to_string(),
                "munlockall".to_string(),
                "sched_setparam".to_string(),
                "sched_getparam".to_string(),
                "sched_setscheduler".to_string(),
                "sched_getscheduler".to_string(),
                "sched_yield".to_string(),
                "sched_get_priority_max".to_string(),
                "sched_get_priority_min".to_string(),
                "sched_rr_get_interval".to_string(),
                "nanosleep".to_string(),
                "mremap".to_string(),
                "setresuid".to_string(),
                "getresuid".to_string(),
                "vm86".to_string(),
                "query_module".to_string(),
                "poll".to_string(),
                "nfsservctl".to_string(),
                "setresgid".to_string(),
                "getresgid".to_string(),
                "prctl".to_string(),
                "rt_sigreturn".to_string(),
                "rt_sigaction".to_string(),
                "rt_sigprocmask".to_string(),
                "rt_sigpending".to_string(),
                "rt_sigtimedwait".to_string(),
                "rt_sigqueueinfo".to_string(),
                "rt_sigsuspend".to_string(),
                "pread64".to_string(),
                "pwrite64".to_string(),
                "chown".to_string(),
                "getcwd".to_string(),
                "capget".to_string(),
                "capset".to_string(),
                "sigaltstack".to_string(),
                "sendfile".to_string(),
                "getpmsg".to_string(),
                "putpmsg".to_string(),
                "vfork".to_string(),
                "ugetrlimit".to_string(),
                "mmap2".to_string(),
                "truncate64".to_string(),
                "ftruncate64".to_string(),
                "stat64".to_string(),
                "lstat64".to_string(),
                "fstat64".to_string(),
                "lchown32".to_string(),
                "getuid32".to_string(),
                "getgid32".to_string(),
                "geteuid32".to_string(),
                "getegid32".to_string(),
                "setreuid32".to_string(),
                "setregid32".to_string(),
                "getgroups32".to_string(),
                "setgroups32".to_string(),
                "fchown32".to_string(),
                "setresuid32".to_string(),
                "getresuid32".to_string(),
                "setresgid32".to_string(),
                "getresgid32".to_string(),
                "chown32".to_string(),
                "setuid32".to_string(),
                "setgid32".to_string(),
                "setfsuid32".to_string(),
                "setfsgid32".to_string(),
                "pivot_root".to_string(),
                "mincore".to_string(),
                "madvise".to_string(),
                "getdents64".to_string(),
                "fcntl64".to_string(),
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
                "sendfile64".to_string(),
                "futex".to_string(),
                "sched_setaffinity".to_string(),
                "sched_getaffinity".to_string(),
                "set_thread_area".to_string(),
                "get_thread_area".to_string(),
                "io_setup".to_string(),
                "io_destroy".to_string(),
                "io_getevents".to_string(),
                "io_submit".to_string(),
                "io_cancel".to_string(),
                "fadvise64".to_string(),
                "exit_group".to_string(),
                "lookup_dcookie".to_string(),
                "epoll_create".to_string(),
                "epoll_ctl".to_string(),
                "epoll_wait".to_string(),
                "remap_file_pages".to_string(),
                "set_tid_address".to_string(),
                "timer_create".to_string(),
                "timer_settime".to_string(),
                "timer_gettime".to_string(),
                "timer_getoverrun".to_string(),
                "timer_delete".to_string(),
                "clock_settime".to_string(),
                "clock_gettime".to_string(),
                "clock_getres".to_string(),
                "clock_nanosleep".to_string(),
                "statfs64".to_string(),
                "fstatfs64".to_string(),
                "tgkill".to_string(),
                "utimes".to_string(),
                "fadvise64_64".to_string(),
                "vserver".to_string(),
                "mbind".to_string(),
                "get_mempolicy".to_string(),
                "set_mempolicy".to_string(),
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
                "fstatat64".to_string(),
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
                "sync_file_range".to_string(),
                "tee".to_string(),
                "vmsplice".to_string(),
                "move_pages".to_string(),
                "getcpu".to_string(),
                "epoll_pwait".to_string(),
                "utimensat".to_string(),
                "signalfd".to_string(),
                "timerfd_create".to_string(),
                "eventfd".to_string(),
                "fallocate".to_string(),
                "timerfd_settime".to_string(),
                "timerfd_gettime".to_string(),
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
                "bpf".to_string(),
                "execveat".to_string(),
                "socket".to_string(),
                "socketpair".to_string(),
                "bind".to_string(),
                "connect".to_string(),
                "listen".to_string(),
                "accept4".to_string(),
                "getsockopt".to_string(),
                "setsockopt".to_string(),
                "getsockname".to_string(),
                "getpeername".to_string(),
                "sendto".to_string(),
                "sendmsg".to_string(),
                "recvfrom".to_string(),
                "recvmsg".to_string(),
                "shutdown".to_string(),
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
                "arch_prctl".to_string(),
                "io_pgetevents".to_string(),
                "rseq".to_string(),
                "semget".to_string(),
                "semctl".to_string(),
                "shmget".to_string(),
                "shmctl".to_string(),
                "shmat".to_string(),
                "shmdt".to_string(),
                "msgget".to_string(),
                "msgsnd".to_string(),
                "msgrcv".to_string(),
                "msgctl".to_string(),
                "clock_gettime64".to_string(),
                "clock_settime64".to_string(),
                "clock_adjtime64".to_string(),
                "clock_getres_time64".to_string(),
                "clock_nanosleep_time64".to_string(),
                "timer_gettime64".to_string(),
                "timer_settime64".to_string(),
                "timerfd_gettime64".to_string(),
                "timerfd_settime64".to_string(),
                "utimensat_time64".to_string(),
                "pselect6_time64".to_string(),
                "ppoll_time64".to_string(),
                "io_pgetevents_time64".to_string(),
                "recvmmsg_time64".to_string(),
                "mq_timedsend_time64".to_string(),
                "mq_timedreceive_time64".to_string(),
                "semtimedop_time64".to_string(),
                "rt_sigtimedwait_time64".to_string(),
                "futex_time64".to_string(),
                "sched_rr_get_interval_time64".to_string(),
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
                println!(
                    "{}** interrupt 0x80 bad rax value 0x{:x} {}",
                    emu.colors.light_red, emu.regs.rax, emu.colors.nc
                );
            } else {
                println!(
                    "{}** interrupt 0x80 function:{} {}",
                    emu.colors.light_red, data[emu.regs.rax as usize], emu.colors.nc
                );
            }
        }
    }
}
