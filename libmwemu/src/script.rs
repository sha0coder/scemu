use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::vec::Vec;

use crate::emu::Emu;
use crate::peb32;
use crate::peb64;
use crate::structures;
use crate::console::Console;
use crate::winapi32;
use crate::winapi64;

pub struct Script {
    code: Vec<String>,
    result: u64,
    skip: bool,
    looped: u64,
    trace: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl Script {
    pub fn new() -> Script {
        Script {
            code: Vec::new(),
            result: 0,
            skip: false,
            looped: 0,
            trace: false,
        }
    }

    pub fn load(&mut self, filename: &str) {
        // log::info!("loading script: {}", filename);
        let file = File::open(filename).unwrap();
        let buf = BufReader::new(file);

        for line in buf.lines().flatten() {
            self.code.push(line);
        }
    }

    pub fn resolve(&self, arg: &str, i: usize, emu: &mut Emu) -> u64 {
        if arg == "result" {
            return self.result;
        } else if arg.starts_with("0x") {
            let a = match self.to_hex(arg) {
                Some(v) => v,
                None => {
                    panic!("error in line {}, bad hexa", i);
                }
            };
            return a;
        }
        emu.regs.get_by_name(arg)
    }

    pub fn to_int(&self, s: &str) -> Option<u64> {
        let value: u64 = match s.parse::<u64>() {
            Ok(value) => value,
            Err(_) => return None,
        };

        Some(value)
    }

    pub fn to_hex(&self, s: &str) -> Option<u64> {
        let mut x = s.to_string();
        if x.ends_with('h') {
            x = x[0..x.len() - 1].to_string();
        }
        if x.starts_with("0x") {
            x = x[2..x.len()].to_string();
        }

        let value: u64 = match u64::from_str_radix(x.as_str(), 16) {
            Ok(value) => value,
            Err(_) => return None,
        };

        Some(value)
    }

    pub fn run(&mut self, emu: &mut Emu) {
        emu.running_script = true;
        let mut i = 0;

        loop {
            i += 1;

            if i > self.code.len() {
                break;
            }
            let line = &self.code[i - 1];
            if line.is_empty() || line.starts_with(";") {
                continue;
            }
            let args: Vec<&str> = line.split_whitespace().collect();

            if self.trace {
                log::info!("==> {} {}", i, line);
            }

            if line == "endif" {
                self.skip = false;
                continue;
            }

            if self.skip {
                continue;
            }

            match args[0] {
                "pr" => {
                    log::info!("result: 0x{:x}", self.result);
                }
                "p" => {
                    if args.len() < 2 {
                        log::info!(
                            "error in line {}, `p` command needs a message to be printed",
                            i
                        );
                        return;
                    }
                    let msg = args
                        .iter()
                        .skip(1)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    log::info!("{}", msg);
                }
                "q" => std::process::exit(1),
                "r" => {
                    if args.len() == 1 {
                        if emu.cfg.is_64bits {
                            emu.featured_regs64();
                        } else {
                            emu.featured_regs32();
                        }
                    } else {
                        self.result = emu.regs.get_by_name(args[1]);

                        match args[1] {
                            "rax" => emu.regs.show_rax(&emu.maps, 0),
                            "rbx" => emu.regs.show_rbx(&emu.maps, 0),
                            "rcx" => emu.regs.show_rcx(&emu.maps, 0),
                            "rdx" => emu.regs.show_rdx(&emu.maps, 0),
                            "rsi" => emu.regs.show_rsi(&emu.maps, 0),
                            "rdi" => emu.regs.show_rdi(&emu.maps, 0),
                            "rbp" => log::info!("\trbp: 0x{:x}", emu.regs.rbp),
                            "rsp" => log::info!("\trsp: 0x{:x}", emu.regs.rsp),
                            "rip" => log::info!("\trip: 0x{:x}", emu.regs.rip),
                            "eax" => emu.regs.show_eax(&emu.maps, 0),
                            "ebx" => emu.regs.show_ebx(&emu.maps, 0),
                            "ecx" => emu.regs.show_ecx(&emu.maps, 0),
                            "edx" => emu.regs.show_edx(&emu.maps, 0),
                            "esi" => emu.regs.show_esi(&emu.maps, 0),
                            "edi" => emu.regs.show_edi(&emu.maps, 0),
                            "esp" => log::info!("\tesp: 0x{:x}", emu.regs.get_esp() as u32),
                            "ebp" => log::info!("\tebp: 0x{:x}", emu.regs.get_ebp() as u32),
                            "eip" => log::info!("\teip: 0x{:x}", emu.regs.get_eip() as u32),
                            "r8" => emu.regs.show_r8(&emu.maps, 0),
                            "r9" => emu.regs.show_r9(&emu.maps, 0),
                            "r10" => emu.regs.show_r10(&emu.maps, 0),
                            "r11" => emu.regs.show_r11(&emu.maps, 0),
                            "r12" => emu.regs.show_r12(&emu.maps, 0),
                            "r13" => emu.regs.show_r13(&emu.maps, 0),
                            "r14" => emu.regs.show_r14(&emu.maps, 0),
                            "r15" => emu.regs.show_r15(&emu.maps, 0),
                            "r8d" => emu.regs.show_r8d(&emu.maps, 0),
                            "r9d" => emu.regs.show_r9d(&emu.maps, 0),
                            "r10d" => emu.regs.show_r10d(&emu.maps, 0),
                            "r11d" => emu.regs.show_r11d(&emu.maps, 0),
                            "r12d" => emu.regs.show_r12d(&emu.maps, 0),
                            "r13d" => emu.regs.show_r13d(&emu.maps, 0),
                            "r14d" => emu.regs.show_r14d(&emu.maps, 0),
                            "r15d" => emu.regs.show_r15d(&emu.maps, 0),
                            "r8w" => emu.regs.show_r8w(&emu.maps, 0),
                            "r9w" => emu.regs.show_r9w(&emu.maps, 0),
                            "r10w" => emu.regs.show_r10w(&emu.maps, 0),
                            "r11w" => emu.regs.show_r11w(&emu.maps, 0),
                            "r12w" => emu.regs.show_r12w(&emu.maps, 0),
                            "r13w" => emu.regs.show_r13w(&emu.maps, 0),
                            "r14w" => emu.regs.show_r14w(&emu.maps, 0),
                            "r15w" => emu.regs.show_r15w(&emu.maps, 0),
                            "r8l" => emu.regs.show_r8l(&emu.maps, 0),
                            "r9l" => emu.regs.show_r9l(&emu.maps, 0),
                            "r10l" => emu.regs.show_r10l(&emu.maps, 0),
                            "r11l" => emu.regs.show_r11l(&emu.maps, 0),
                            "r12l" => emu.regs.show_r12l(&emu.maps, 0),
                            "r13l" => emu.regs.show_r13l(&emu.maps, 0),
                            "r14l" => emu.regs.show_r14l(&emu.maps, 0),
                            "r15l" => emu.regs.show_r15l(&emu.maps, 0),
                            "xmm0" => log::info!("\txmm0: 0x{:x}", emu.regs.xmm0),
                            "xmm1" => log::info!("\txmm1: 0x{:x}", emu.regs.xmm1),
                            "xmm2" => log::info!("\txmm2: 0x{:x}", emu.regs.xmm2),
                            "xmm3" => log::info!("\txmm3: 0x{:x}", emu.regs.xmm3),
                            "xmm4" => log::info!("\txmm4: 0x{:x}", emu.regs.xmm4),
                            "xmm5" => log::info!("\txmm5: 0x{:x}", emu.regs.xmm5),
                            "xmm6" => log::info!("\txmm6: 0x{:x}", emu.regs.xmm6),
                            "xmm7" => log::info!("\txmm7: 0x{:x}", emu.regs.xmm7),
                            "xmm8" => log::info!("\txmm8: 0x{:x}", emu.regs.xmm8),
                            "xmm9" => log::info!("\txmm9: 0x{:x}", emu.regs.xmm9),
                            "xmm10" => log::info!("\txmm10: 0x{:x}", emu.regs.xmm10),
                            "xmm11" => log::info!("\txmm11: 0x{:x}", emu.regs.xmm11),
                            "xmm12" => log::info!("\txmm12: 0x{:x}", emu.regs.xmm12),
                            "xmm13" => log::info!("\txmm13: 0x{:x}", emu.regs.xmm13),
                            "xmm14" => log::info!("\txmm14: 0x{:x}", emu.regs.xmm14),
                            "xmm15" => log::info!("\txmm15: 0x{:x}", emu.regs.xmm15),
                            _ => log::info!("unknown register r `{}` in line {}", args[1], i),
                        }
                    }
                }
                "rc" => {
                    if args.len() != 3 {
                        log::info!("expected: rc <register> <value>");
                    } else {
                        let value: u64 = self.resolve(args[2], i, emu);
                        emu.regs.set_by_name(args[1], value);
                    }
                }
                "mr" | "rm" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, command `mr` without arguments", i);
                        return;
                    }

                    let ins = args
                        .iter()
                        .skip(1)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    let addr: u64 = emu.memory_operand_to_address(&ins);
                    let value = match emu.memory_read(&ins) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad address.", i);
                            return;
                        }
                    };
                    self.result = value;
                    log::info!("0x{:x}", value);
                }
                "mw" | "wm" => {
                    // mw 0x11223344 dword ptr [eax + 3]

                    if args.len() < 3 {
                        log::info!("error in line {}, command `mw` without arguments", i);
                        return;
                    }

                    let ins = args
                        .iter()
                        .skip(2)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    let value = self.resolve(args[1], i, emu);

                    if !emu.memory_write(&ins, value) {
                        log::info!("error in line {}, cannot write on `{}`", i, args[1]);
                        return;
                    }
                }
                "mwb" => {
                    let addr = self.resolve(args[1], i, emu);
                    let bytes = args
                        .iter()
                        .skip(1)
                        .take(args.len() - 2)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    emu.maps.write_spaced_bytes(addr, &bytes);
                }
                "b" => {
                    emu.bp.show();
                }
                "ba" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }
                    let addr = self.resolve(args[1], i, emu);
                    emu.bp.set_bp(addr);
                }
                "bmr" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }
                    let addr = self.resolve(args[1], i, emu);

                    emu.bp.set_mem_read(addr);
                }
                "bmw" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }
                    let addr = self.resolve(args[1], i, emu);
                    emu.bp.set_mem_write(addr);
                }
                "bi" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, number is missing", i);
                        return;
                    }
                    let num = match self.to_int(args[1]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad number", i);
                            return;
                        }
                    };
                    emu.bp.set_instruction(num);
                    emu.exp = num;
                }
                "bc" => {
                    emu.bp.clear_bp();
                    emu.exp = emu.pos + 1;
                }
                "bcmp" => {
                    emu.break_on_next_cmp = true;
                }
                "cls" => {
                    log::info!("{}", emu.colors.clear_screen);
                }
                "s" => {
                    if emu.cfg.is_64bits {
                        emu.maps.dump_qwords(emu.regs.rsp, 10);
                    } else {
                        emu.maps.dump_dwords(emu.regs.get_esp(), 10);
                    }
                }
                "v" => {
                    if emu.cfg.is_64bits {
                        emu.maps.dump_qwords(emu.regs.rbp - 0x100, 100);
                    } else {
                        emu.maps.dump_dwords(emu.regs.get_ebp() - 0x100, 100);
                    }
                    emu.maps
                        .get_mem("stack")
                        .print_dwords_from_to(emu.regs.get_ebp(), emu.regs.get_ebp() + 0x100);
                }
                "sv" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, number is missing", i);
                        return;
                    }
                    let num = match self.to_int(args[1]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad number", i);
                            return;
                        }
                    };
                    emu.cfg.verbose = num as u32;
                }
                "tr" => {
                    if args.len() < 2 {
                        log::info!("error in line {}, register is missing", i);
                        return;
                    }
                    emu.cfg.trace_reg = true;
                    emu.cfg.reg_names.push(args[1].to_string());
                }
                "trc" => {
                    emu.cfg.trace_reg = false;
                    emu.cfg.reg_names.clear();
                }
                "pos" => {
                    log::info!("pos = 0x{:x}", emu.pos);
                }
                "c" => {
                    emu.is_running
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                    emu.run(None);
                }
                "cr" => {
                    emu.break_on_next_return = true;
                    emu.is_running
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                    emu.run(None);
                }
                "f" => emu.flags.print(),
                "fc" => emu.flags.clear(),
                "fz" => emu.flags.f_zf = !emu.flags.f_zf,
                "fs" => emu.flags.f_sf = !emu.flags.f_sf,
                "mc" => {
                    // mc mymap 1024
                    if args.len() != 3 {
                        log::info!("error in line {}, mc <mapname> <size>", i);
                        return;
                    }
                    let sz = match self.to_int(args[2]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad size", i);
                            return;
                        }
                    };
                    let addr = match emu.maps.alloc(sz) {
                        Some(a) => a,
                        None => {
                            log::info!("error in line {}, memory full", i);
                            return;
                        }
                    };
                    emu.maps.create_map(args[1], addr, sz);
                    log::info!("allocated {} at 0x{:x} sz: {}", &args[1], addr, sz);
                    self.result = addr;
                }
                "mca" => {
                    // mc mymap <addr> <sz>
                    if args.len() != 4 {
                        log::info!("error in line {}, mc <mapname> <addr> <size>", i);
                        return;
                    }
                    let addr = self.resolve(args[2], i, emu);
                    let sz = match self.to_int(args[3]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad size", i);
                            return;
                        }
                    };
                    emu.maps.create_map(args[1], addr, sz);
                    log::info!("allocated {} at 0x{:x} sz: {}", &args[1], addr, sz);
                }
                "ml" => {
                    // ml <mapname> <file>
                    if args.len() != 3 {
                        log::info!("error in line {}, `ml` needs mapname and a filename", i);
                        return;
                    }
                    emu.maps.get_mem(args[1]).load(args[2]);
                }
                "mn" => {
                    // mn <address>
                    if args.len() != 2 {
                        log::info!("error in line {}, `mn` needs an address", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    let name = match emu.maps.get_addr_name(addr) {
                        Some(n) => n,
                        None => {
                            log::info!("error in line {}, address not found on any map", i);
                            return;
                        }
                    };

                    let mem = emu.maps.get_mem(&name);
                    if emu.cfg.is_64bits {
                        log::info!(
                            "map: {} 0x{:x}-0x{:x} ({})",
                            name,
                            mem.get_base(),
                            mem.get_bottom(),
                            mem.size()
                        );
                    } else {
                        log::info!(
                            "map: {} 0x{:x}-0x{:x} ({})",
                            name,
                            mem.get_base() as u32,
                            mem.get_bottom() as u32,
                            mem.size()
                        );
                    }
                }
                "ma" => {
                    emu.maps.show_allocs();
                }
                "md" => {
                    // md <addr>
                    if args.len() != 2 {
                        log::info!("error in line {}, address missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    emu.maps.dump(addr);
                }
                "mrd" => {
                    // mrd <addr> <n>
                    if args.len() != 3 {
                        log::info!("error in line {}, address or number of dwords missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    let num = match self.to_int(args[2]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad number", i);
                            return;
                        }
                    };

                    emu.maps.dump_dwords(addr, num);
                }
                "mrq" => {
                    // mrq <addr> <n>
                    if args.len() != 3 {
                        log::info!("error in line {}, address or number of qwords missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    let num = match self.to_int(args[2]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad number", i);
                            return;
                        }
                    };

                    emu.maps.dump_qwords(addr, num);
                }
                "mds" => {
                    // mds <addr>
                    if args.len() != 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    if emu.cfg.is_64bits {
                        log::info!("0x{:x}: '{}'", addr, emu.maps.read_string(addr));
                    } else {
                        log::info!("0x{:x}: '{}'", addr as u32, emu.maps.read_string(addr));
                    }
                }
                "mdw" => {
                    // mdw <addr>
                    if args.len() != 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    if emu.cfg.is_64bits {
                        log::info!("0x{:x}: '{}'", addr, emu.maps.read_wide_string(addr));
                    } else {
                        log::info!("0x{:x}: '{}'", addr as u32, emu.maps.read_wide_string(addr));
                    }
                }
                "mdd" => {
                    // mdd <addr> <sz> <filename>
                    if args.len() != 4 {
                        log::info!("error in line {}, address, size or filename is missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    let sz = match self.to_int(args[2]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad size", i);
                            return;
                        }
                    };

                    if sz <= 0 {
                        log::info!("error in line {}, bad size", i);
                        return;
                    }
                    emu.maps.save(addr, sz, args[3].to_string());
                }
                "mdda" => {
                    // mdda <folder>
                    if args.len() != 2 {
                        log::info!("error in line {}, foler is needed", i);
                        return;
                    }
                    emu.maps.save_all_allocs(args[1].to_string());
                }
                "mt" => {
                    if emu.maps.mem_test() {
                        log::info!("mem tests passed ok.");
                    } else {
                        log::info!("memory errors.");
                    }
                }
                "eip" => {
                    // eip <addr>
                    if args.len() != 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    emu.set_eip(addr, false);
                }
                "rip" => {
                    // rip <addr>
                    if args.len() != 2 {
                        log::info!("error in line {}, address is missing", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    emu.set_rip(addr, false);
                }
                "push" => {
                    // push <hexvalue>
                    if args.len() != 2 {
                        log::info!("error in line {}, hex value is missing", i);
                        return;
                    }

                    let value = self.resolve(args[1], i, emu);

                    if emu.cfg.is_64bits {
                        emu.stack_push64(value);
                    } else {
                        emu.stack_push32((value & 0xffffffff) as u32);
                    }
                }
                "pop" => {
                    // pop
                    if args.len() != 1 {
                        log::info!("error in line {}, no args required.", i);
                        return;
                    }

                    if emu.cfg.is_64bits {
                        let value = emu.stack_pop64(false).expect("pop failed");
                        log::info!("poped value 0x{:x}", value);
                        self.result = value;
                    } else {
                        let value = emu.stack_pop32(false).expect("pop failed");
                        log::info!("poped value 0x{:x}", value);
                        self.result = value as u64;
                    }
                }
                "fpu" => emu.fpu.print(),
                "md5" => {
                    // md5 <mapname>
                    if args.len() != 2 {
                        log::info!("error in line {}, no args required.", i);
                        return;
                    }

                    let mem = emu.maps.get_mem(args[1]);
                    let md5 = mem.md5();
                    log::info!("md5sum: {:x}", md5);
                }
                "ss" => {
                    // ss <mapname> <string>
                    if args.len() < 2 {
                        log::info!("error in line {}, need map name and string", i);
                        return;
                    }

                    let kw = args
                        .iter()
                        .skip(2)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    let result = match emu.maps.search_string(&kw, args[1]) {
                        Some(v) => v,
                        None => {
                            log::info!("string not found");
                            return;
                        }
                    };

                    for addr in result.iter() {
                        if emu.cfg.is_64bits {
                            log::info!("found 0x{:x} '{}'", *addr, emu.maps.read_string(*addr));
                        } else {
                            log::info!(
                                "found 0x{:x} '{}'",
                                *addr as u32,
                                emu.maps.read_string(*addr)
                            );
                        }
                    }
                }
                "sb" => {
                    // sb <map> <spaced bytes>
                    if args.len() < 2 {
                        log::info!("error in line {}, need map name and spaced bytes", i);
                        return;
                    }

                    let bytes = args
                        .iter()
                        .skip(2)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    if emu.maps.search_spaced_bytes(&bytes, args[1]).len() == 0 {
                        log::info!("bytes not found.");
                    }
                }
                "sba" => {
                    // sba <spaced bytes>

                    let bytes = args
                        .iter()
                        .skip(1)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    let results = emu.maps.search_spaced_bytes_in_all(&bytes);
                    for addr in results.iter() {
                        log::info!("found at 0x{:x}", addr);
                        self.result = *addr;
                    }
                }
                "ssa" => {
                    // ssa <string>

                    let s = args
                        .iter()
                        .skip(1)
                        .map(|s| s.to_owned())
                        .collect::<Vec<_>>()
                        .join(" ");

                    emu.maps.search_string_in_all(s);
                }
                "seh" => {
                    log::info!("0x{:x}", emu.seh);
                }
                "veh" => {
                    log::info!("0x{:x}", emu.veh);
                }
                "ll" => {
                    // ll <addr>
                    let addr = self.resolve(args[1], i, emu);
                    let mut ptr = addr;
                    loop {
                        log::info!("- 0x{:x}", ptr);
                        ptr = match emu.maps.read_dword(ptr) {
                            Some(v) => v.into(),
                            None => break,
                        };
                        if ptr == 0 || ptr == addr {
                            break;
                        }
                    }
                }
                "n" => {
                    emu.step();
                }
                "m" => {
                    emu.maps.print_maps();
                }
                "ms" => {
                    // ms <keyword>
                    if args.len() != 2 {
                        log::info!("error in line {}, `ms` command needs a keyword", i);
                        return;
                    }
                    emu.maps.print_maps_keyword(args[1]);
                }
                "d" => {
                    // d <addr> <sz>
                    if args.len() != 3 {
                        log::info!("error in line {}, `d` command needs an address to disasemble and amount of bytes", i);
                        return;
                    }

                    let addr = self.resolve(args[1], i, emu);

                    let sz = match self.to_int(args[2]) {
                        Some(v) => v,
                        None => {
                            log::info!("error in line {}, bad size", i);
                            return;
                        }
                    };

                    emu.disassemble(addr, sz as u32);
                }
                "ldr" => {
                    // ldr
                    if emu.cfg.is_64bits {
                        peb64::show_linked_modules(emu);
                    } else {
                        peb32::show_linked_modules(emu);
                    }
                }
                "iat" => {
                    // iat <keyword>
                    if args.len() != 2 {
                        log::info!("error in line {}, keyword expected", i);
                        return;
                    }

                    let addr: u64;
                    let lib: String;
                    let name: String;
                    if emu.cfg.is_64bits {
                        (addr, lib, name) = winapi64::kernel32::search_api_name(emu, args[1]);
                    } else {
                        (addr, lib, name) = winapi32::kernel32::search_api_name(emu, args[1]);
                    }

                    if addr == 0 {
                        log::info!("api not found on iat.");
                    } else {
                        log::info!("found: 0x{:x} {}!{}", addr, lib, name);
                    }
                }
                "iatx" => {
                    // iatx <api>
                    //TODO: implement this well
                    if args.len() != 2 {
                        log::info!("error in line {}, api expected", i);
                        return;
                    }

                    let addr: u64;
                    let lib: String;
                    let name: String;
                    if emu.cfg.is_64bits {
                        (addr, lib, name) = winapi64::kernel32::search_api_name(emu, args[1]);
                    } else {
                        (addr, lib, name) = winapi32::kernel32::search_api_name(emu, args[1]);
                    }

                    if addr == 0 {
                        log::info!("api not found on iat.");
                    } else {
                        log::info!("found: 0x{:x} {}!{}", addr, lib, name);
                    }
                }
                "iatd" => {
                    // iatd <module>
                    if args.len() != 2 {
                        log::info!("error in line {}, module expected", i);
                        return;
                    }
                    if emu.cfg.is_64bits {
                        winapi64::kernel32::dump_module_iat(emu, args[1]);
                    } else {
                        winapi32::kernel32::dump_module_iat(emu, args[1]);
                    }
                }
                "dt" => {
                    // dt <structure> <address>
                    if args.len() != 3 {
                        log::info!("error in line {}, structure and address expected", i);
                        return;
                    }

                    let addr = self.resolve(args[2], i, emu);

                    match args[1] {
                        "peb" => {
                            let s = structures::PEB::load(addr, &emu.maps);
                            s.print();
                        }
                        "teb" => {
                            let s = structures::TEB::load(addr, &emu.maps);
                            s.print();
                        }
                        "peb_ldr_data" => {
                            let s = structures::PebLdrData::load(addr, &emu.maps);
                            s.print();
                        }
                        "ldr_data_table_entry" => {
                            let s = structures::LdrDataTableEntry::load(addr, &emu.maps);
                            s.print();
                        }
                        "list_entry" => {
                            let s = structures::ListEntry::load(addr, &emu.maps);
                            s.print();
                        }
                        "cppeh_record" => {
                            let s = structures::CppEhRecord::load(addr, &emu.maps);
                            s.print();
                        }
                        "exception_pointers" => {
                            let s = structures::ExceptionPointers::load(addr, &emu.maps);
                            s.print();
                        }
                        "eh3_exception_registgration" => {
                            let s = structures::Eh3ExceptionRegistration::load(addr, &emu.maps);
                            s.print();
                        }
                        "memory_basic_information" => {
                            let s = structures::MemoryBasicInformation::load(addr, &emu.maps);
                            s.print();
                        }
                        "peb64" => {
                            let s = structures::PEB64::load(addr, &emu.maps);
                            s.print();
                        }
                        "teb64" => {
                            let s = structures::TEB64::load(addr, &emu.maps);
                            s.print();
                        }
                        "ldrdatatableentry64" => {
                            let s = structures::LdrDataTableEntry64::load(addr, &emu.maps);
                            s.print();
                        }
                        "image_export_directory" => {
                            let s = structures::ImageExportDirectory::load(addr, &emu.maps);
                            s.print();
                        }

                        _ => log::info!("unrecognized structure."),
                    }
                }
                "if" => {
                    // if result == rax
                    // if rbx > 0x123

                    if args.len() != 4 {
                        log::info!("error in line {}, incomplete `if`", i);
                        return;
                    }

                    let a: u64 = self.resolve(args[1], i, emu);
                    let b: u64 = self.resolve(args[3], i, emu);

                    if args[2] == "==" {
                        if a != b {
                            self.skip = true;
                        }
                    } else if args[2] == "!=" {
                        if a == b {
                            self.skip = true;
                        }
                    } else if args[2] == ">" {
                        if a <= b {
                            self.skip = true;
                        }
                    } else if args[2] == "<" {
                        if a >= b {
                            self.skip = true;
                        }
                    } else if args[2] == ">=" {
                        if a < b {
                            self.skip = true;
                        }
                    } else if args[2] == "<=" {
                        if a > b {
                            self.skip = true;
                        }
                    } else {
                        log::info!("error in line {}, if with worng operator", i);
                        return;
                    }
                }
                "console" => {
                    Console::spawn_console(emu);
                }
                "call" => {
                    // call <addr> <args>
                    if args.len() < 2 {
                        panic!("error in line {}, call with no address", i);
                    }

                    let addr = self.resolve(args[1], i, emu);

                    // push arguments
                    for j in (2..args.len()).rev() {
                        let v = self.resolve(args[j], i, emu);
                        if emu.cfg.is_64bits {
                            emu.stack_push64(v);
                        } else {
                            emu.stack_push32(v as u32);
                        }
                    }

                    // push return address
                    let retaddr: u64;
                    if emu.cfg.is_64bits {
                        retaddr = emu.regs.rip;
                        emu.stack_push64(emu.regs.rip);
                    } else {
                        retaddr = emu.regs.get_eip();
                        emu.stack_push32(emu.regs.get_eip() as u32);
                    }

                    if emu.cfg.is_64bits {
                        emu.set_rip(addr, false);
                    } else {
                        emu.set_eip(addr, false);
                    }

                    emu.is_running
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                    emu.run(Some(retaddr));
                }
                "set" => {
                    //set <hexnum>
                    if args.len() < 2 {
                        panic!("error in line {}, call with no value", i);
                    }

                    let value = self.resolve(args[1], i, emu);

                    self.result = value;
                }
                "loop" => {
                    self.looped = i as u64;
                }
                "endloop" => {
                    if self.result <= 1 {
                        self.looped = 0;
                        continue;
                    }

                    self.result -= 1;
                    i = self.looped as usize;
                    continue;
                }
                "trace" => {
                    self.trace = true;
                }

                _ => panic!("error in line {}, unknown command", i),
            }
        }
    }
}
