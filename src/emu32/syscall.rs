use crate::emu32;
use crate::emu32::constants;
use crate::emu32::winapi::helper;

   //  /usr/include/asm/unistd_32.h

pub fn gateway(emu:&mut emu32::Emu32) {

    match emu.regs.eax {      

        1 => {
            println!("{}** {} syscall exit()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
            std::process::exit(1);
        }

        2 => {
            println!("{}** {} syscall fork()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
            emu.spawn_console();
        }

        3 => {
            let fd = emu.regs.ebx;
            let buff = emu.regs.ecx;
            let sz = emu.regs.edx;
            emu.regs.eax = buff;
            println!("{}** {} syscall read() fd: {} buf: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, fd, buff, sz, emu.colors.nc);
        }

        4 => {
            let fd = emu.regs.ebx;
            let buff = emu.regs.ecx;
            let sz = emu.regs.edx;
            emu.regs.eax = sz;
            println!("{}** {} syscall write() fd: {} buf: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, fd, buff, sz, emu.colors.nc);
        }

        5 => {
            let file_path = emu.maps.read_string(emu.regs.ebx);
            let fd = helper::socket_create();
            emu.regs.eax = fd;
            println!("{}** {} syscall open() file: {} fd:{} {}", emu.colors.light_red, emu.pos, file_path, fd, emu.colors.nc);
        }

        6 => {
            let fd = emu.regs.ebx;
            println!("{}** {} syscall close() fd: {}  {}", emu.colors.light_red, emu.pos, fd, emu.colors.nc);
            helper::socket_close(fd);
        }

        7 => {
            println!("{}** {} syscall waitpid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        8 => {
            println!("{}** {} syscall creat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        9 => {
            println!("{}** {} syscall link()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        10 => {
            println!("{}** {} syscall unlink()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        11 => {
            let cmd = emu.maps.read_string(emu.regs.ebx);
            println!("{}** {} syscall execve()  cmd: {} {}", emu.colors.light_red, emu.pos, cmd, emu.colors.nc);
        }

        12 => {
            let path = emu.maps.read_string(emu.regs.ebx);
            println!("{}** {} syscall chdir() path: {} {}", emu.colors.light_red, emu.pos, path, emu.colors.nc);
        }

        13 => {
            println!("{}** {} syscall time()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        14 => {
            println!("{}** {} syscall mknod()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        15 => {
            let file_path = emu.maps.read_string(emu.regs.ebx);
            let perm = emu.regs.ecx;
            println!("{}** {} syscall chmod() file: {} perm: {} {}", emu.colors.light_red, emu.pos, file_path, perm, emu.colors.nc);
        }

        16 => {
            println!("{}** {} syscall lchown()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        17 => {
            println!("{}** {} syscall break()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }
        
        18 => {
            println!("{}** {} syscall oldstat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        19 => {
            let fd = emu.regs.ebx;
            println!("{}** {} syscall lseek()  fd: {} {}", emu.colors.light_red, emu.pos, fd, emu.colors.nc);
        }

        20 => {
            println!("{}** {} syscall getpid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        21 => {
            println!("{}** {} syscall mount()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        22 => {
            println!("{}** {} syscall umount()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        23 => {
            println!("{}** {} syscall setuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        24 => {
            println!("{}** {} syscall getuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        25 => {
            println!("{}** {} syscall stime()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        26 => {
            println!("{}** {} syscall ptrace()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        27 => {
            println!("{}** {} syscall alarm()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        28 => {
            println!("{}** {} syscall oldfstat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        29 => {
            println!("{}** {} syscall pause()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        30 => {
            println!("{}** {} syscall utime()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        31 => {
            println!("{}** {} syscall stty()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        32 => {
            println!("{}** {} syscall gtty()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        33 => {
            println!("{}** {} syscall access()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        34 => {
            println!("{}** {} syscall nice()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        35 => {
            println!("{}** {} syscall ftime()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        36 => {
            println!("{}** {} syscall sync()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        37 => {
            let pid = emu.regs.ebx;
            let sig = emu.regs.ecx;
            println!("{}** {} syscall kill() pid: {} sig: {} {}", emu.colors.light_red, emu.pos, pid, sig, emu.colors.nc);
        }

        38 => {
            println!("{}** {} syscall rename()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        39 => {
            println!("{}** {} syscall mkdir()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        40 => {
            println!("{}** {} syscall rmdir()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        41 => {
            let fd = emu.regs.ebx;
            println!("{}** {} syscall dup() fd: {} {}", emu.colors.light_red, emu.pos, fd, emu.colors.nc);
        }

        42 => {
            println!("{}** {} syscall pipe()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        43 => {
            println!("{}** {} syscall times()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        44 => {
            println!("{}** {} syscall prof()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        45 => {
            println!("{}** {} syscall brk()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        46 => {
            println!("{}** {} syscall setgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        47 => {
            println!("{}** {} syscall getgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        48 => {
            println!("{}** {} syscall signal()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        49 => {
            println!("{}** {} syscall geteuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        50 => {
            println!("{}** {} syscall getegid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        51 => {
            println!("{}** {} syscall acct()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        52 => {
            println!("{}** {} syscall umount2()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        53 => {
            println!("{}** {} syscall lock()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        54 => {
            println!("{}** {} syscall ioctl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        55 => {
            println!("{}** {} syscall fcntl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        56 => {
            println!("{}** {} syscall mpx()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        57 => {
            println!("{}** {} syscall setpgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        58 => {
            println!("{}** {} syscall ulimit()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        59 => {
            println!("{}** {} syscall oldolduname()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        60 => {
            println!("{}** {} syscall umask()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        61 => {
            println!("{}** {} syscall chroot()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        62 => {
            println!("{}** {} syscall ustat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        63 => {
            let old_fd = emu.regs.ebx;
            let new_fd = emu.regs.ecx;
            println!("{}** {} syscall dup2() oldfd: {} newfd: {} {}", emu.colors.light_red, emu.pos, old_fd, new_fd, emu.colors.nc);
        }

        64 => {
            println!("{}** {} syscall getppid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        65 => {
            println!("{}** {} syscall getpgrp()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        66 => {
            println!("{}** {} syscall setsid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        67 => {
            println!("{}** {} syscall sigaction()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }                                    

        68 => {
            println!("{}** {} syscall sgetmask()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        69 => {
            println!("{}** {} syscall ssetmask()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        70 => {
            println!("{}** {} syscall setreuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        71 => {
            println!("{}** {} syscall setregid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        72 => {
            println!("{}** {} syscall sigsuspend()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        73 => {
            println!("{}** {} syscall sigpending()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        74 => {
            println!("{}** {} syscall sethostname()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        75 => {
            println!("{}** {} syscall setrlimit()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        76 => {
            println!("{}** {} syscall getrlimit()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        77 => {
            println!("{}** {} syscall getrusage()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        78 => {
            println!("{}** {} syscall gettimeofday()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        79 => {
            println!("{}** {} syscall settimeofday()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        80 => {
            println!("{}** {} syscall getgroups()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        81 => {
            println!("{}** {} syscall setgroups()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        82 => {
            println!("{}** {} syscall select()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        83 => {
            println!("{}** {} syscall symlink()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        84 => {
            println!("{}** {} syscall oldlstat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        85 => {
            println!("{}** {} syscall readlink()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        86 => {
            println!("{}** {} syscall uselib()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        87 => {
            println!("{}** {} syscall swapon()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        88 => {
            println!("{}** {} syscall reboot()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        89 => {
            println!("{}** {} syscall readdir()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        90 => {
            println!("{}** {} syscall mmap()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        91 => {
            println!("{}** {} syscall munmap()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        92 => {
            println!("{}** {} syscall truncate()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        93 => {
            println!("{}** {} syscall ftruncate()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        94 => {
            println!("{}** {} syscall fchmod()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        95 => {
            println!("{}** {} syscall fchown()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        96 => {
            println!("{}** {} syscall getpriority()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        97 => {
            println!("{}** {} syscall setpriority()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        98 => {
            println!("{}** {} syscall profil()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        99 => {
            println!("{}** {} syscall statfs()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        100 => {
            println!("{}** {} syscall fstatfs()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        101 => {
            println!("{}** {} syscall ioperm()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        102 => {

            match emu.regs.ebx {
                constants::SYS_SOCKET => {
                    let sock = helper::socket_create();
                    emu.regs.eax = sock;
                    println!("{}** {} syscall socketcall socket() sock: {} {}", emu.colors.light_red, emu.pos, sock, emu.colors.nc);
                    emu.stack_pop(false);
                    emu.stack_pop(false);
                    emu.stack_pop(false);
                }

                constants::SYS_BIND => {
                    let fd = emu.stack_pop(false);
                    let sockaddr = emu.stack_pop(false);
                    let len = emu.stack_pop(false);

                    println!("{}** {} syscall socketcall bind()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_CONNECT => {
                    println!("{}** {} syscall socketcall connect()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_LISTEN => {
                    println!("{}** {} syscall socketcall listen()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_ACCEPT => {
                    println!("{}** {} syscall socketcall accept() {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_GETSOCKNAME => {
                    println!("{}** {} syscall socketcall getsockname() {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_GETPEERNAME => {
                    println!("{}** {} syscall socketcall getpeername()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SOCKETPAIR => {
                    println!("{}** {} syscall socketcall socketpair()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SEND => {
                    println!("{}** {} syscall socketcall send()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_RECV => {
                    println!("{}** {} syscall socketcall recv()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SENDTO => {
                    println!("{}** {} syscall socketcall sendto()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_RECVFROM => {
                    println!("{}** {} syscall socketcall recvfrom()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SHUTDOWN => {
                    println!("{}** {} syscall socketcall shutdown()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SETSOCKOPT => {
                    println!("{}** {} syscall socketcall setsockopt()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_GETSOCKOPT => {
                    println!("{}** {} syscall socketcall getsockopt()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SENDMSG => {
                    println!("{}** {} syscall socketcall sendmsg()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_RECVMSG => {
                    println!("{}** {} syscall socketcall recvmsg()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_ACCEPT4 => {
                    println!("{}** {} syscall socketcall accept4()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_RECVMMSG => {
                    println!("{}** {} syscall socketcall recvmsg()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }

                constants::SYS_SENDMMSG => {
                    println!("{}** {} syscall socketcall sendmsg()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
                }


                

                _=> panic!("invalid socket call {} ", emu.regs.ebx),
            }



            

        }

        103 => {
            println!("{}** {} syscall syslog()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        104 => {
            println!("{}** {} syscall setitimer()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        105 => {
            println!("{}** {} syscall getitimer()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        106 => {
            println!("{}** {} syscall stat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        107 => {
            println!("{}** {} syscall lstat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        108 => {
            println!("{}** {} syscall fstat()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        109 => {
            println!("{}** {} syscall olduname()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        110 => {
            println!("{}** {} syscall iopl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        111 => {
            println!("{}** {} syscall vhanghup()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        112 => {
            println!("{}** {} syscall idle()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        113 => {
            println!("{}** {} syscall vm86old()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        114 => {
            println!("{}** {} syscall wait4()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        115 => {
            println!("{}** {} syscall swapoff()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        116 => {
            println!("{}** {} syscall sysinfo()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        117 => {
            println!("{}** {} syscall ipc()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        118 => {
            println!("{}** {} syscall fsync()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        119 => {
            println!("{}** {} syscall sigreturn()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        120 => {
            println!("{}** {} syscall clone()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        121 => {
            println!("{}** {} syscall setdomainname()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        122 => {
            println!("{}** {} syscall uname()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        123 => {
            println!("{}** {} syscall modify_ltd()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        124 => {
            println!("{}** {} syscall adjtimex()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        125 => {
            println!("{}** {} syscall mprotect()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        126 => {
            println!("{}** {} syscall sigprocmask()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        127 => {
            println!("{}** {} syscall create_module()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        128 => {
            println!("{}** {} syscall init_module()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        129 => {
            println!("{}** {} syscall delete_module()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        130 => {
            println!("{}** {} syscall get_kernel_syms()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        131 => {
            println!("{}** {} syscall quotactl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        132 => {
            println!("{}** {} syscall getpgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        133 => {
            println!("{}** {} syscall fchdir()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        134 => {
            println!("{}** {} syscall bdflush()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        135 => {
            println!("{}** {} syscall sysfs()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        136 => {
            println!("{}** {} syscall personality()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        137 => {
            println!("{}** {} syscall afs_syscall()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        138 => {
            println!("{}** {} syscall setfsuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        139 => {
            println!("{}** {} syscall setfsgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        140 => {
            println!("{}** {} syscall _llseek()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        141 => {
            println!("{}** {} syscall getdents()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        142 => {
            println!("{}** {} syscall _newselect()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        143 => {
            println!("{}** {} syscall flock()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        144 => {
            println!("{}** {} syscall msync()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        145 => {
            println!("{}** {} syscall readv()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        146 => {
            println!("{}** {} syscall writev()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        147 => {
            println!("{}** {} syscall getsid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        148 => {
            println!("{}** {} syscall fdatasync()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        149 => {
            println!("{}** {} syscall _sysctl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        150 => {
            println!("{}** {} syscall mlock()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        151 => {
            println!("{}** {} syscall munlock()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        152 => {
            println!("{}** {} syscall mlockall()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        153 => {
            println!("{}** {} syscall munlockall()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        154 => {
            println!("{}** {} syscall sched_setparam()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        155 => {
            println!("{}** {} syscall sched_getparam()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        156 => {
            println!("{}** {} syscall sched_setscheduler()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        157 => {
            println!("{}** {} syscall sched_getscheduler()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        158 => {
            println!("{}** {} syscall sched_yield()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        159 => {
            println!("{}** {} syscall sched_get_priority_max()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        160 => {
            println!("{}** {} syscall sched_get_priority_min()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        161 => {
            println!("{}** {} syscall sched_rr_get_inverval()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        162 => {
            println!("{}** {} syscall nanosleep()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        163 => {
            println!("{}** {} syscall mremap()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        164 => {
            println!("{}** {} syscall setresuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        165 => {
            println!("{}** {} syscall getresuid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        166 => {
            println!("{}** {} syscall vm86()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        167 => {
            println!("{}** {} syscall query_module()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        168 => {
            println!("{}** {} syscall poll()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        169 => {
            println!("{}** {} syscall nfsservctrl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        170 => {
            println!("{}** {} syscall setresgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        171 => {
            println!("{}** {} syscall getresgid()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        172 => {
            println!("{}** {} syscall prctl()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        173 => {
            println!("{}** {} syscall rt_sigreturn()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        174 => {
            println!("{}** {} syscall rt_sigcation()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        175 => {
            println!("{}** {} syscall rt_sigprocmask()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        176 => {
            println!("{}** {} syscall rt_sigpending()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        177 => {
            println!("{}** {} syscall rt_sigtimedwait()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        178 => {
            println!("{}** {} syscall rt_sigqueueinfo()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        179 => {
            println!("{}** {} syscall rt_sigsuspend()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        180 => {
            println!("{}** {} syscall pread64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        181 => {
            println!("{}** {} syscall pwrite64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        182 => {
            println!("{}** {} syscall chown()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        183 => {
            println!("{}** {} syscall getcwd()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        184 => {
            println!("{}** {} syscall capget()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        185 => {
            println!("{}** {} syscall capset()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        186 => {
            println!("{}** {} syscall sigaltstack()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        187 => {
            println!("{}** {} syscall sendfile()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        188 => {
            println!("{}** {} syscall getpmsg()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        189 => {
            println!("{}** {} syscall putpmsg()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        190 => {
            println!("{}** {} syscall vfork()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        191 => {
            println!("{}** {} syscall ugetrlimit()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        192 => {
            println!("{}** {} syscall mmap2()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        193 => {
            println!("{}** {} syscall truncate64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        194 => {
            println!("{}** {} syscall ftruncate64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        195 => {
            println!("{}** {} syscall stat64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        196 => {
            println!("{}** {} syscall lstat64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        197 => {
            println!("{}** {} syscall fstat64()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        198 => {
            println!("{}** {} syscall lchown32()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        199 => {
            println!("{}** {} syscall getuid32()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        200 => {
            println!("{}** {} syscall getgid32()  {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        }

        _ => {
            println!("{}** interrupt 0x80 function:{} {}", emu.colors.light_red, emu.regs.eax, emu.colors.nc);
        }
    }

}