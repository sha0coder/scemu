use std::io::Write;
use std::num::ParseIntError;
use std::sync::atomic;

use crate::emu::Emu;
use crate::structures;
use crate::peb32;
use crate::peb64;
use crate::winapi32;
use crate::winapi64;
use crate::to32;

pub struct Console {}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    pub fn new() -> Console {
        log::info!("--- console ---");
        Console {}
    }

    pub fn print(&self, msg: &str) {
        print!("{}", msg);
        std::io::stdout().flush().unwrap();
    }

    pub fn cmd(&self) -> String {
        let mut line = String::new();
        self.print("=>");
        std::io::stdin().read_line(&mut line).unwrap();
        line = line.replace("\r", ""); // some shells (windows) also add \r  thanks Alberto Segura
        line.truncate(line.len() - 1);
        line.to_lowercase()
    }

    pub fn cmd2(&self) -> String {
        let mut line = String::new();
        self.print("=>");
        std::io::stdin().read_line(&mut line).unwrap();
        line = line.replace("\r", ""); // some shells (windows) also add \r  thanks Alberto Segura
        line.truncate(line.len() - 1);
        line
    }

    pub fn cmd_hex32(&self) -> Result<u32, ParseIntError> {
        let mut x = self.cmd();

        if x.ends_with('h') {
            x = x[0..x.len() - 1].to_string();
        }
        if x.starts_with("0x") {
            x = x[2..x.len()].to_string();
        }

        u32::from_str_radix(x.as_str(), 16)
    }

    pub fn cmd_hex64(&self) -> Result<u64, ParseIntError> {
        let mut x = self.cmd();
        if x.ends_with('h') {
            x = x[0..x.len() - 1].to_string();
        }
        if x.starts_with("0x") {
            x = x[2..x.len()].to_string();
        }

        u64::from_str_radix(x.as_str(), 16)
    }

    pub fn cmd_num(&self) -> Result<u64, ParseIntError> {
        self.cmd().as_str().parse::<u64>()
    }

    /*
    pub fn cmd_num<T>(&self) -> Result<T,ParseIntError> {
        self.cmd().as_str().parse::<T>()
    }*/

    pub fn help(&self) {
        log::info!("--- help ---");
        log::info!("q ...................... quit");
        log::info!("cls .................... clear screen");
        log::info!("h ...................... help");
        log::info!("s ...................... stack");
        log::info!("v ...................... vars");
        log::info!("sv ..................... set verbose level 0, 1 or 2");
        log::info!("r ...................... register show all");
        log::info!("r reg .................. show reg");
        log::info!("rc ..................... register change");
        log::info!("f ...................... show all flags");
        log::info!("fc ..................... clear all flags");
        log::info!("fz ..................... toggle flag zero");
        log::info!("fs ..................... toggle flag sign");
        log::info!("c ...................... continue");
        log::info!("b ...................... breakpoint list");
        log::info!("ba ..................... breakpoint on address");
        log::info!("bi ..................... breakpoint on instruction number");
        log::info!("bmr .................... breakpoint on read memory");
        log::info!("bmw .................... breakpoint on write memory");
        log::info!("bmx .................... breakpoint on execute memory");
        log::info!("bcmp ................... break on next cmp or test");
        log::info!("bc ..................... clear breakpoint");
        log::info!("n ...................... next instruction");
        log::info!("eip .................... change eip");
        log::info!("rip .................... change rip");
        log::info!("push ................... push dword to the stack");
        log::info!("pop .................... pop dword from stack");
        log::info!("fpu .................... fpu view");
        log::info!("md5 .................... check the md5 of a memory map");
        log::info!("seh .................... view SEH");
        log::info!("veh .................... view vectored execption pointer");
        log::info!("m ...................... memory maps");
        log::info!("ms ..................... memory filtered by keyword string");
        log::info!("ma ..................... memory allocs");
        log::info!("mc ..................... memory create map");
        log::info!("mn ..................... memory name of an address");
        log::info!("ml ..................... memory load file content to map");
        log::info!("mr ..................... memory read, speficy ie: dword ptr [esi]");
        log::info!(
            "mw ..................... memory write, speficy ie: dword ptr [esi]  and then: 1af"
        );
        log::info!("mwb .................... memory write bytes, input spaced bytes");
        log::info!("md ..................... memory dump");
        log::info!("mrd .................... memory read dwords");
        log::info!("mrq .................... memory read qwords");
        log::info!("mds .................... memory dump string");
        log::info!("mdw .................... memory dump wide string");
        log::info!("mdd .................... memory dump to disk");
        log::info!("mdda ................... memory dump all allocations to disk");
        log::info!("mt ..................... memory test");
        log::info!("ss ..................... search string");
        log::info!("sb ..................... search bytes");
        log::info!("sba .................... search bytes in all the maps");
        log::info!("ssa .................... search string in all the maps");
        log::info!("ll ..................... linked list walk");
        log::info!("d ...................... dissasemble");
        log::info!("dt ..................... dump structure");
        log::info!("pos .................... print current position");
        log::info!("enter .................. step into");
        log::info!("tr ..................... trace reg");
        log::info!("trc .................... trace regs clear");
        log::info!("ldr .................... show ldr linked list");
        log::info!("iat .................... find api name in all iat's ");
        log::info!("iatx ................... addr to api name");
        log::info!("iatd ................... dump the iat of specific module");

        //log::info!("o ...................... step over");
        log::info!("");
        log::info!("---");
    }

    pub fn spawn_console(emu: &mut Emu) {
        if !emu.cfg.console_enabled {
            return;
        }

        let con = Console::new();
        if emu.pos > 0 {
            emu.pos -= 1;
        }
        loop {
            let cmd = con.cmd();
            match cmd.as_str() {
                "q" => std::process::exit(1),
                "h" => con.help(),
                "r" => {
                    if emu.cfg.is_64bits {
                        emu.featured_regs64();
                    } else {
                        emu.featured_regs32();
                    }
                }
                "r rax" => emu.regs.show_rax(&emu.maps, 0),
                "r rbx" => emu.regs.show_rbx(&emu.maps, 0),
                "r rcx" => emu.regs.show_rcx(&emu.maps, 0),
                "r rdx" => emu.regs.show_rdx(&emu.maps, 0),
                "r rsi" => emu.regs.show_rsi(&emu.maps, 0),
                "r rdi" => emu.regs.show_rdi(&emu.maps, 0),
                "r rbp" => log::info!("\trbp: 0x{:x}", emu.regs.rbp),
                "r rsp" => log::info!("\trsp: 0x{:x}", emu.regs.rsp),
                "r rip" => log::info!("\trip: 0x{:x}", emu.regs.rip),
                "r eax" => emu.regs.show_eax(&emu.maps, 0),
                "r ebx" => emu.regs.show_ebx(&emu.maps, 0),
                "r ecx" => emu.regs.show_ecx(&emu.maps, 0),
                "r edx" => emu.regs.show_edx(&emu.maps, 0),
                "r esi" => emu.regs.show_esi(&emu.maps, 0),
                "r edi" => emu.regs.show_edi(&emu.maps, 0),
                "r esp" => log::info!("\tesp: 0x{:x}", emu.regs.get_esp() as u32),
                "r ebp" => log::info!("\tebp: 0x{:x}", emu.regs.get_ebp() as u32),
                "r eip" => log::info!("\teip: 0x{:x}", emu.regs.get_eip() as u32),
                "r r8" => emu.regs.show_r8(&emu.maps, 0),
                "r r9" => emu.regs.show_r9(&emu.maps, 0),
                "r r10" => emu.regs.show_r10(&emu.maps, 0),
                "r r11" => emu.regs.show_r11(&emu.maps, 0),
                "r r12" => emu.regs.show_r12(&emu.maps, 0),
                "r r13" => emu.regs.show_r13(&emu.maps, 0),
                "r r14" => emu.regs.show_r14(&emu.maps, 0),
                "r r15" => emu.regs.show_r15(&emu.maps, 0),
                "r r8d" => emu.regs.show_r8d(&emu.maps, 0),
                "r r9d" => emu.regs.show_r9d(&emu.maps, 0),
                "r r10d" => emu.regs.show_r10d(&emu.maps, 0),
                "r r11d" => emu.regs.show_r11d(&emu.maps, 0),
                "r r12d" => emu.regs.show_r12d(&emu.maps, 0),
                "r r13d" => emu.regs.show_r13d(&emu.maps, 0),
                "r r14d" => emu.regs.show_r14d(&emu.maps, 0),
                "r r15d" => emu.regs.show_r15d(&emu.maps, 0),
                "r r8w" => emu.regs.show_r8w(&emu.maps, 0),
                "r r9w" => emu.regs.show_r9w(&emu.maps, 0),
                "r r10w" => emu.regs.show_r10w(&emu.maps, 0),
                "r r11w" => emu.regs.show_r11w(&emu.maps, 0),
                "r r12w" => emu.regs.show_r12w(&emu.maps, 0),
                "r r13w" => emu.regs.show_r13w(&emu.maps, 0),
                "r r14w" => emu.regs.show_r14w(&emu.maps, 0),
                "r r15w" => emu.regs.show_r15w(&emu.maps, 0),
                "r r8l" => emu.regs.show_r8l(&emu.maps, 0),
                "r r9l" => emu.regs.show_r9l(&emu.maps, 0),
                "r r10l" => emu.regs.show_r10l(&emu.maps, 0),
                "r r11l" => emu.regs.show_r11l(&emu.maps, 0),
                "r r12l" => emu.regs.show_r12l(&emu.maps, 0),
                "r r13l" => emu.regs.show_r13l(&emu.maps, 0),
                "r r14l" => emu.regs.show_r14l(&emu.maps, 0),
                "r r15l" => emu.regs.show_r15l(&emu.maps, 0),
                "r xmm0" => log::info!("\txmm0: 0x{:x}", emu.regs.xmm0),
                "r xmm1" => log::info!("\txmm1: 0x{:x}", emu.regs.xmm1),
                "r xmm2" => log::info!("\txmm2: 0x{:x}", emu.regs.xmm2),
                "r xmm3" => log::info!("\txmm3: 0x{:x}", emu.regs.xmm3),
                "r xmm4" => log::info!("\txmm4: 0x{:x}", emu.regs.xmm4),
                "r xmm5" => log::info!("\txmm5: 0x{:x}", emu.regs.xmm5),
                "r xmm6" => log::info!("\txmm6: 0x{:x}", emu.regs.xmm6),
                "r xmm7" => log::info!("\txmm7: 0x{:x}", emu.regs.xmm7),
                "r xmm8" => log::info!("\txmm8: 0x{:x}", emu.regs.xmm8),
                "r xmm9" => log::info!("\txmm9: 0x{:x}", emu.regs.xmm9),
                "r xmm10" => log::info!("\txmm10: 0x{:x}", emu.regs.xmm10),
                "r xmm11" => log::info!("\txmm11: 0x{:x}", emu.regs.xmm11),
                "r xmm12" => log::info!("\txmm12: 0x{:x}", emu.regs.xmm12),
                "r xmm13" => log::info!("\txmm13: 0x{:x}", emu.regs.xmm13),
                "r xmm14" => log::info!("\txmm14: 0x{:x}", emu.regs.xmm14),
                "r xmm15" => log::info!("\txmm15: 0x{:x}", emu.regs.xmm15),
                "r ymm0" => log::info!("\tymm0: 0x{:x}", emu.regs.ymm0),
                "r ymm1" => log::info!("\tymm1: 0x{:x}", emu.regs.ymm1),
                "r ymm2" => log::info!("\tymm2: 0x{:x}", emu.regs.ymm2),
                "r ymm3" => log::info!("\tymm3: 0x{:x}", emu.regs.ymm3),
                "r ymm4" => log::info!("\tymm4: 0x{:x}", emu.regs.ymm4),
                "r ymm5" => log::info!("\tymm5: 0x{:x}", emu.regs.ymm5),
                "r ymm6" => log::info!("\tymm6: 0x{:x}", emu.regs.ymm6),
                "r ymm7" => log::info!("\tymm7: 0x{:x}", emu.regs.ymm7),
                "r ymm8" => log::info!("\tymm8: 0x{:x}", emu.regs.ymm8),
                "r ymm9" => log::info!("\tymm9: 0x{:x}", emu.regs.ymm9),
                "r ymm10" => log::info!("\tymm10: 0x{:x}", emu.regs.ymm10),
                "r ymm11" => log::info!("\tymm11: 0x{:x}", emu.regs.ymm11),
                "r ymm12" => log::info!("\tymm12: 0x{:x}", emu.regs.ymm12),
                "r ymm13" => log::info!("\tymm13: 0x{:x}", emu.regs.ymm13),
                "r ymm14" => log::info!("\tymm14: 0x{:x}", emu.regs.ymm14),
                "r ymm15" => log::info!("\tymm15: 0x{:x}", emu.regs.ymm15),

                "rc" => {
                    con.print("register name");
                    let reg = con.cmd();
                    con.print("value");
                    let value = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };
                    emu.regs.set_by_name(reg.as_str(), value);
                }
                "mr" | "rm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    let addr: u64 = emu.memory_operand_to_address(operand.as_str());
                    let value = match emu.memory_read(operand.as_str()) {
                        Some(v) => v,
                        None => {
                            log::info!("bad address.");
                            continue;
                        }
                    };
                    log::info!("0x{:x}: 0x{:x}", to32!(addr), value);
                }
                "mw" | "wm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    con.print("value");
                    let value = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    if emu.memory_write(operand.as_str(), value) {
                        log::info!("done.");
                    } else {
                        log::info!("cannot write there.");
                    }
                }
                "mwb" => {
                    con.print("addr");
                    let addr = match con.cmd_hex64() {
                        Ok(a) => a,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };
                    con.print("spaced bytes");
                    let bytes = con.cmd();
                    emu.maps.write_spaced_bytes(addr, &bytes);
                    log::info!("done.");
                }
                "b" => {
                    emu.bp.show();
                }
                "ba" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.bp.set_bp(addr);
                }
                "bmr" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.bp.set_mem_read(addr);
                }
                "bmw" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.bp.set_mem_write(addr);
                }
                "bi" => {
                    con.print("instruction number");
                    let num = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad instruction number.");
                            continue;
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
                "cls" => log::info!("{}", emu.colors.clear_screen),
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
                    con.print("verbose level");
                    emu.cfg.verbose = match con.cmd_num() {
                        Ok(v) => to32!(v),
                        Err(_) => {
                            log::info!("incorrect verbose level, set 0, 1 or 2");
                            continue;
                        }
                    };
                }
                "tr" => {
                    con.print("register");
                    let reg = con.cmd();
                    emu.cfg.trace_reg = true;
                    emu.cfg.reg_names.push(reg);
                }
                "trc" => {
                    emu.cfg.trace_reg = false;
                    emu.cfg.reg_names.clear();
                }
                "pos" => {
                    log::info!("pos = 0x{:x}", emu.pos);
                }
                "c" => {
                    emu.is_running.store(1, atomic::Ordering::Relaxed);
                    return;
                }
                "cr" => {
                    emu.break_on_next_return = true;
                    emu.is_running.store(1, atomic::Ordering::Relaxed);
                    return;
                }
                "f" => emu.flags.print(),
                "fc" => emu.flags.clear(),
                "fz" => emu.flags.f_zf = !emu.flags.f_zf,
                "fs" => emu.flags.f_sf = !emu.flags.f_sf,
                "mc" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("size ");
                    let sz = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad size.");
                            continue;
                        }
                    };

                    let addr = match emu.maps.alloc(sz) {
                        Some(a) => a,
                        None => {
                            log::info!("memory full");
                            continue;
                        }
                    };
                    emu.maps
                        .create_map(&name, addr, sz)
                        .expect("cannot create map from console mc");
                    log::info!("allocated {} at 0x{:x} sz: {}", name, addr, sz);
                }
                "mca" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("address ");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad size.");
                            continue;
                        }
                    };

                    con.print("size ");
                    let sz = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad size.");
                            continue;
                        }
                    };

                    emu.maps
                        .create_map(&name, addr, sz)
                        .expect("cannot create map from console mca");
                    log::info!("allocated {} at 0x{:x} sz: {}", name, addr, sz);
                }
                "ml" => {
                    con.print("map name");
                    let name = con.cmd();
                    con.print("filename");
                    let filename = con.cmd();
                    emu.maps.get_mem(name.as_str()).load(filename.as_str());
                }
                "mn" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.maps.show_addr_names(addr);
                    let name = match emu.maps.get_addr_name(addr) {
                        Some(n) => n,
                        None => {
                            if !emu.cfg.skip_unimplemented {
                                log::info!("address not found on any map");
                                continue;
                            }

                            "code".to_string()
                        }
                    };

                    let mem = emu.maps.get_mem(name.as_str());
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
                            to32!(mem.get_base()),
                            to32!(mem.get_bottom()),
                            mem.size()
                        );
                    }
                }
                "ma" => {
                    emu.maps.show_allocs();
                }
                "md" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.maps.dump(addr);
                }
                "mrd" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.maps.dump_dwords(addr, 10);
                }
                "mrq" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    emu.maps.dump_qwords(addr, 10);
                }
                "mds" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    if emu.cfg.is_64bits {
                        log::info!("0x{:x}: '{}'", addr, emu.maps.read_string(addr));
                    } else {
                        log::info!("0x{:x}: '{}'", to32!(addr), emu.maps.read_string(addr));
                    }
                }
                "mdw" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    if emu.cfg.is_64bits {
                        log::info!("0x{:x}: '{}'", addr, emu.maps.read_wide_string(addr));
                    } else {
                        log::info!(
                            "0x{:x}: '{}'",
                            to32!(addr),
                            emu.maps.read_wide_string(addr)
                        );
                    }
                }
                "mdd" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };
                    con.print("size");
                    let sz = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad numeric decimal value.");
                            continue;
                        }
                    };
                    if sz > 0 {
                        con.print("file");
                        let filename = con.cmd();
                        emu.maps.save(addr, sz, filename);
                    }
                }
                "mdda" => {
                    con.print("path:");
                    let path = con.cmd2();
                    emu.maps.save_all_allocs(path);
                }
                "mt" => {
                    if emu.maps.mem_test() {
                        log::info!("mem test passed ok.");
                    } else {
                        log::info!("memory errors.");
                    }
                }
                "eip" => {
                    con.print("=");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };
                    //emu.force_break = true;
                    //emu.regs.set_eip(addr);
                    emu.set_eip(addr, false);
                }
                "rip" => {
                    con.print("=");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };
                    //emu.force_break = true;
                    //emu.regs.rip = addr;
                }
                "push" => {
                    con.print("value");
                    if emu.cfg.is_64bits {
                        let value = match con.cmd_hex64() {
                            Ok(v) => v,
                            Err(_) => {
                                log::info!("bad hex value");
                                continue;
                            }
                        };
                        emu.stack_push64(value);
                    } else {
                        let value = match con.cmd_hex32() {
                            Ok(v) => v,
                            Err(_) => {
                                log::info!("bad hex value");
                                continue;
                            }
                        };
                        emu.stack_push32(value);
                    }
                    log::info!("pushed.");
                }
                "pop" => {
                    if emu.cfg.is_64bits {
                        let value = emu.stack_pop64(false).unwrap_or(0);
                        log::info!("poped value 0x{:x}", value);
                    } else {
                        let value = emu.stack_pop32(false).unwrap_or(0);
                        log::info!("poped value 0x{:x}", value);
                    }
                }
                "fpu" => {
                    emu.fpu.print();
                }
                "md5" => {
                    con.print("map name");
                    let mem_name = con.cmd();
                    let mem = emu.maps.get_mem(&mem_name);
                    let md5 = mem.md5();
                    log::info!("md5sum: {:x}", md5);
                }
                "ss" => {
                    con.print("map name");
                    let mem_name = con.cmd();
                    con.print("string");
                    let kw = con.cmd2();
                    let result = match emu.maps.search_string(&kw, &mem_name) {
                        Some(v) => v,
                        None => {
                            log::info!("not found.");
                            continue;
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
                    con.print("map name");
                    let mem_name = con.cmd();
                    con.print("spaced bytes");
                    let sbs = con.cmd();
                    let results = emu.maps.search_spaced_bytes(&sbs, &mem_name);
                    if results.is_empty() {
                        log::info!("not found.");
                    } else if emu.cfg.is_64bits {
                        for addr in results.iter() {
                            log::info!("found at 0x{:x}", addr);
                        }
                    } else {
                        for addr in results.iter() {
                            log::info!("found at 0x{:x}", to32!(addr));
                        }
                    }
                }
                "sba" => {
                    con.print("spaced bytes");
                    let sbs = con.cmd();
                    let results = emu.maps.search_spaced_bytes_in_all(&sbs);
                    if results.is_empty() {
                        log::info!("not found.");
                    } else if emu.cfg.is_64bits {
                        for addr in results.iter() {
                            log::info!("found at 0x{:x}", addr);
                        }
                    } else {
                        for addr in results.iter() {
                            log::info!("found at 0x{:x}", to32!(addr));
                        }
                    }
                }
                "ssa" => {
                    con.print("string");
                    let kw = con.cmd2();
                    emu.maps.search_string_in_all(kw);
                }
                "seh" => {
                    log::info!("0x{:x}", emu.seh);
                }
                "veh" => {
                    log::info!("0x{:x}", emu.veh);
                }
                "ll" => {
                    con.print("ptr");
                    let ptr1 = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };
                    let mut ptr = ptr1;
                    loop {
                        log::info!("- 0x{:x}", ptr);
                        ptr = match emu.maps.read_dword(ptr) {
                            Some(v) => v.into(),
                            None => break,
                        };
                        if ptr == 0 || ptr == ptr1 {
                            break;
                        }
                    }
                }
                "n" | "" => {
                    //emu.exp = emu.pos + 1;
                    let prev_verbose = emu.cfg.verbose;
                    emu.cfg.verbose = 3;
                    emu.step();
                    emu.cfg.verbose = prev_verbose;
                    //return;
                }
                "m" => emu.maps.print_maps(),
                "ms" => {
                    con.print("keyword");
                    let kw = con.cmd2();
                    emu.maps.print_maps_keyword(&kw);
                }
                "d" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };
                    log::info!("{}", emu.disassemble(addr, 10));
                }
                "ldr" => {
                    if emu.cfg.is_64bits {
                        peb64::show_linked_modules(emu);
                    } else {
                        peb32::show_linked_modules(emu);
                    }
                }
                "iat" => {
                    con.print("api keyword");
                    let kw = con.cmd2();
                    let addr: u64;
                    let lib: String;
                    let name: String;

                    if emu.cfg.is_64bits {
                        (addr, lib, name) = winapi64::kernel32::search_api_name(emu, &kw);
                    } else {
                        (addr, lib, name) = winapi32::kernel32::search_api_name(emu, &kw);
                    }

                    if addr == 0 {
                        log::info!("api not found");
                    } else {
                        log::info!("found: 0x{:x} {}!{}", addr, lib, name);
                    }
                }
                "iatx" => {
                    // addr to name
                    con.print("api addr");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value.");
                            continue;
                        }
                    };

                    let name: String = if emu.cfg.is_64bits {
                        winapi64::kernel32::resolve_api_addr_to_name(emu, addr)
                    } else {
                        winapi32::kernel32::resolve_api_addr_to_name(emu, addr)
                    };

                    if name.is_empty() {
                        log::info!("api addr not found");
                    } else {
                        log::info!("found: 0x{:x} {}", addr, name);
                    }
                }
                "iatd" => {
                    con.print("module");
                    let lib = con.cmd2().to_lowercase();
                    if emu.cfg.is_64bits {
                        winapi64::kernel32::dump_module_iat(emu, &lib);
                    } else {
                        winapi32::kernel32::dump_module_iat(emu, &lib);
                    }
                }
                "dt" => {
                    con.print("structure");
                    let struc = con.cmd();
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            log::info!("bad hex value");
                            continue;
                        }
                    };

                    match struc.as_str() {
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
                        "peb64" => {
                            let s = structures::PEB64::load(addr, &emu.maps);
                            s.print();
                        }
                        "teb64" => {
                            let s = structures::TEB64::load(addr, &emu.maps);
                            s.print();
                        }
                        "peb_ldr_data64" => {
                            let s = structures::PebLdrData64::load(addr, &emu.maps);
                            s.print();
                        }
                        "ldr_data_table_entry64" => {
                            let s = structures::LdrDataTableEntry64::load(addr, &emu.maps);
                            s.print();
                        }
                        "list_entry64" => {
                            let s = structures::ListEntry64::load(addr, &emu.maps);
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
                        "image_export_directory" => {
                            let s = structures::ImageExportDirectory::load(addr, &emu.maps);
                            s.print();
                        }

                        _ => log::info!("unrecognized structure."),
                    }
                } // end dt command

                _ => log::info!("command not found, type h"),
            } // match commands
        } // end loop
    } // end commands function
}
