pub mod logic;

use iced_x86::{Instruction, Mnemonic, Register};
use crate::emu::Emu;
use crate::regs64;
use crate::exception;
use crate::inline;
use crate::syscall32;
use crate::syscall64;
use crate::ntapi32;
use crate::console::Console;
use crate::{to32, get_bit, set_bit};

pub fn emulate_instruction(
    emu: &mut Emu,
    ins: &Instruction,
    instruction_sz: usize,
    rep_step: bool,
) -> bool {
    match ins.mnemonic() {
        Mnemonic::Jmp => {
            emu.show_instruction(&emu.colors.yellow, ins);

            if ins.op_count() != 1 {
                unimplemented!("weird variant of jmp");
            }

            let addr = match emu.get_operand_value(ins, 0, true) {
                Some(a) => a,
                None => return false,
            };

            if emu.cfg.is_64bits {
                return emu.set_rip(addr, false);
            } else {
                return emu.set_eip(addr, false);
            }
        }

        Mnemonic::Call => {
            emu.show_instruction(&emu.colors.yellow, ins);

            if ins.op_count() != 1 {
                unimplemented!("weird variant of call");
            }

            let addr = match emu.get_operand_value(ins, 0, true) {
                Some(a) => a,
                None => return false,
            };

            if emu.cfg.is_64bits {
                if !emu.stack_push64(emu.regs.rip + instruction_sz as u64) {
                    return false;
                }
                return emu.set_rip(addr, false);
            } else {
                if !emu.stack_push32(emu.regs.get_eip() as u32 + instruction_sz as u32) {
                    return false;
                }
                return emu.set_eip(addr, false);
            }
        }

        Mnemonic::Push => {
            let value = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            emu.show_instruction_pushpop(&emu.colors.blue, ins, value);

            if emu.cfg.is_64bits {
                if !emu.stack_push64(value) {
                    return false;
                }
            } else if !emu.stack_push32(to32!(value)) {
                return false;
            }
        }

        Mnemonic::Pop => {
            let value: u64 = if emu.cfg.is_64bits {
                match emu.stack_pop64(true) {
                    Some(v) => v,
                    None => return false,
                }
            } else {
                match emu.stack_pop32(true) {
                    Some(v) => v as u64,
                    None => return false,
                }
            };

            emu.show_instruction_pushpop(&emu.colors.blue, ins, value);

            if !emu.set_operand_value(ins, 0, value) {
                return false;
            }
        }

        Mnemonic::Pushad => {
            emu.show_instruction(&emu.colors.blue, ins);

            // only 32bits instruction
            let tmp_esp = emu.regs.get_esp() as u32;
            if !emu.stack_push32(emu.regs.get_eax() as u32) {
                return false;
            }
            if !emu.stack_push32(emu.regs.get_ecx() as u32) {
                return false;
            }
            if !emu.stack_push32(emu.regs.get_edx() as u32) {
                return false;
            }
            if !emu.stack_push32(emu.regs.get_ebx() as u32) {
                return false;
            }
            if !emu.stack_push32(tmp_esp) {
                return false;
            }
            if !emu.stack_push32(emu.regs.get_ebp() as u32) {
                return false;
            }
            if !emu.stack_push32(emu.regs.get_esi() as u32) {
                return false;
            }
            if !emu.stack_push32(emu.regs.get_edi() as u32) {
                return false;
            }
        }

        Mnemonic::Popad => {
            emu.show_instruction(&emu.colors.blue, ins);
            let mut poped: u64;

            // only 32bits instruction
            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_edi(poped);
            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_esi(poped);
            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_ebp(poped);

            emu.regs.set_esp(emu.regs.get_esp() + 4); // skip esp

            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_ebx(poped);
            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_edx(poped);
            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_ecx(poped);
            poped = emu.stack_pop32(false).unwrap_or(0) as u64;
            emu.regs.set_eax(poped);
        }

        Mnemonic::Cdqe => {
            emu.show_instruction(&emu.colors.blue, ins);

            emu.regs.rax = emu.regs.get_eax() as u32 as i32 as i64 as u64;
            // sign extend
        }

        Mnemonic::Cdq => {
            emu.show_instruction(&emu.colors.blue, ins);

            let num: i64 = emu.regs.get_eax() as u32 as i32 as i64; // sign-extend
            let unum: u64 = num as u64;
            emu.regs.set_edx((unum & 0xffffffff00000000) >> 32);
            // preserve upper 64-bits from getting overriden
            let rax_upper = emu.regs.rax >> 32;
            emu.regs.rax = (rax_upper << 32) | (unum & 0xffffffff);
        }

        Mnemonic::Cqo => {
            emu.show_instruction(&emu.colors.blue, ins);

            let sigextend: u128 = emu.regs.rax as i64 as i128 as u128;
            emu.regs.rdx = ((sigextend & 0xffffffff_ffffffff_00000000_00000000) >> 64) as u64
        }

        Mnemonic::Ret => {
            let ret_addr: u64 = if emu.cfg.is_64bits {
                match emu.stack_pop64(false) {
                    Some(v) => v,
                    None => return false,
                }
            } else {
                match emu.stack_pop32(false) {
                    Some(v) => v as u64,
                    None => return false,
                }
            };

            emu.show_instruction_ret(&emu.colors.yellow, ins, ret_addr);

            if emu.run_until_ret {
                return true; //TODO: fix this
            }

            if emu.break_on_next_return {
                emu.break_on_next_return = false;
                Console::spawn_console(emu);
            }

            if ins.op_count() > 0 {
                let mut arg = emu
                    .get_operand_value(ins, 0, true)
                    .expect("weird crash on ret");
                // apply stack compensation of ret operand

                if emu.cfg.is_64bits {
                    if arg % 8 != 0 {
                        panic!("weird ret argument!");
                    }

                    arg /= 8;

                    for _ in 0..arg {
                        emu.stack_pop64(false);
                    }
                } else {
                    if arg % 4 != 0 {
                        log::info!("weird ret argument!");
                        return false;
                    }

                    arg /= 4;

                    for _ in 0..arg {
                        emu.stack_pop32(false);
                    }
                }
            }

            if emu.eh_ctx != 0 {
                exception::exit(emu);
                return true;
            }

            if emu.cfg.is_64bits {
                return emu.set_rip(ret_addr, false);
            } else {
                return emu.set_eip(ret_addr, false);
            }
        }

        Mnemonic::Xchg => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if !emu.set_operand_value(ins, 0, value1) {
                return false;
            }
            if !emu.set_operand_value(ins, 1, value0) {
                return false;
            }
        }

        Mnemonic::Aad => {
            emu.show_instruction(&emu.colors.light_cyan, ins);
            assert!(ins.op_count() <= 1);

            let mut low: u64 = emu.regs.get_al();
            let high: u64 = emu.regs.get_ah();

            let imm: u64 = if ins.op_count() == 0 {
                10
            } else {
                match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                }
            };

            low = (low + (imm * high)) & 0xff;
            emu.regs.set_al(low);
            emu.regs.set_ah(0);

            emu.flags.calc_flags(low, 8);
        }

        Mnemonic::Les => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if !emu.set_operand_value(ins, 0, value1) {
                return false;
            }
        }

        Mnemonic::Mov | Mnemonic::Movnti => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if !emu.set_operand_value(ins, 0, value1) {
                return false;
            }
        }

        Mnemonic::Xor => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);
            assert!(emu.get_operand_sz(ins, 0) == emu.get_operand_sz(ins, 1));

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            let result = value0 ^ value1;

            if emu.cfg.test_mode && result != inline::xor(value0, value1) {
                panic!(
                    "0x{:x} should be 0x{:x}",
                    result,
                    inline::xor(value0, value1)
                );
            }

            emu.flags.calc_flags(result, sz);
            emu.flags.f_of = false;
            emu.flags.f_cf = false;
            emu.flags.calc_pf(result as u8);

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Add => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let res: u64 = match emu.get_operand_sz(ins, 1) {
                64 => emu.flags.add64(value0, value1, emu.flags.f_cf, false),
                32 => emu.flags.add32(
                    (value0 & 0xffffffff) as u32,
                    (value1 & 0xffffffff) as u32,
                    emu.flags.f_cf,
                    false,
                ),
                16 => emu.flags.add16(
                    (value0 & 0xffff) as u16,
                    (value1 & 0xffff) as u16,
                    emu.flags.f_cf,
                    false,
                ),
                8 => emu.flags.add8(
                    (value0 & 0xff) as u8,
                    (value1 & 0xff) as u8,
                    emu.flags.f_cf,
                    false,
                ),
                _ => unreachable!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Adc => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 2);

            let cf = emu.flags.f_cf as u64;

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let res = match emu.get_operand_sz(ins, 1) {
                64 => emu.flags.add64(value0, value1, emu.flags.f_cf, true),
                32 => emu.flags.add32(
                    (value0 & 0xffffffff) as u32,
                    (value1 & 0xffffffff) as u32,
                    emu.flags.f_cf,
                    true,
                ),
                16 => emu.flags.add16(
                    (value0 & 0xffff) as u16,
                    (value1 & 0xffff) as u16,
                    emu.flags.f_cf,
                    true,
                ),
                8 => emu.flags.add8(
                    (value0 & 0xff) as u8,
                    (value1 & 0xff) as u8,
                    emu.flags.f_cf,
                    true,
                ),
                _ => unreachable!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Sbb => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 2);

            let cf: u64 = if emu.flags.f_cf { 1 } else { 0 };

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 1);
            let res: u64 = match sz {
                64 => emu.flags.sub64(value0, value1.wrapping_add(cf)),
                32 => emu
                    .flags
                    .sub32(value0, (value1 & 0xffffffff).wrapping_add(cf)),
                16 => emu.flags.sub16(value0, (value1 & 0xffff).wrapping_add(cf)),
                8 => emu.flags.sub8(value0, (value1 & 0xff).wrapping_add(cf)),
                _ => panic!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Sub => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let res: u64 = match emu.get_operand_sz(ins, 0) {
                64 => emu.flags.sub64(value0, value1),
                32 => emu.flags.sub32(value0, value1),
                16 => emu.flags.sub16(value0, value1),
                8 => emu.flags.sub8(value0, value1),
                _ => panic!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Inc => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let res = match emu.get_operand_sz(ins, 0) {
                64 => emu.flags.inc64(value0),
                32 => emu.flags.inc32(value0),
                16 => emu.flags.inc16(value0),
                8 => emu.flags.inc8(value0),
                _ => panic!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Dec => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let res = match emu.get_operand_sz(ins, 0) {
                64 => emu.flags.dec64(value0),
                32 => emu.flags.dec32(value0),
                16 => emu.flags.dec16(value0),
                8 => emu.flags.dec8(value0),
                _ => panic!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Neg => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            let res = match sz {
                64 => emu.flags.neg64(value0),
                32 => emu.flags.neg32(value0),
                16 => emu.flags.neg16(value0),
                8 => emu.flags.neg8(value0),
                _ => panic!("weird size"),
            };

            if emu.cfg.test_mode && res != inline::neg(value0, sz) {
                panic!("0x{:x} should be 0x{:x}", res, inline::neg(value0, sz));
            }

            emu.flags.f_cf = value0 != 0;

            emu.flags.f_af = ((res | value0) & 0x8) != 0;

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Not => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let val: u64;

            /*let mut ival = value0 as i32;
            ival = !ival;*/

            let sz = emu.get_operand_sz(ins, 0);
            match sz {
                64 => {
                    let mut ival = value0 as i64;
                    ival = !ival;
                    val = ival as u64;
                }
                32 => {
                    let mut ival = value0 as u32 as i32;
                    ival = !ival;
                    //val = value0 & 0xffffffff_00000000 | ival as u32 as u64;
                    val = ival as u32 as u64;
                }
                16 => {
                    let mut ival = value0 as u16 as i16;
                    ival = !ival;
                    val = value0 & 0xffffffff_ffff0000 | ival as u16 as u64;
                }
                8 => {
                    let mut ival = value0 as u8 as i8;
                    ival = !ival;
                    val = value0 & 0xffffffff_ffffff00 | ival as u8 as u64;
                }
                _ => unimplemented!("weird"),
            }

            if emu.cfg.test_mode && val != inline::not(value0, sz) {
                panic!("0x{:x} should be 0x{:x}", val, inline::not(value0, sz));
            }

            if !emu.set_operand_value(ins, 0, val) {
                return false;
            }
        }

        Mnemonic::And => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            let result1: u64;
            let result2: u64;

            match sz {
                8 => {
                    result1 = (value0 & 0xff) & (value1 & 0xff);
                    result2 = (value0 & 0xffffffffffffff00) + result1;
                }
                16 => {
                    result1 = (value0 & 0xffff) & (value1 & 0xffff);
                    result2 = (value0 & 0xffffffffffff0000) + result1;
                }
                32 => {
                    result1 = (value0 & 0xffffffff) & (value1 & 0xffffffff);
                    result2 = (value0 & 0xffffffff00000000) + result1;
                }
                64 => {
                    result1 = value0 & value1;
                    result2 = result1;
                }
                _ => unreachable!(""),
            }

            if emu.cfg.test_mode && result2 != inline::and(value0, value1) {
                panic!(
                    "0x{:x} should be 0x{:x}",
                    result2,
                    inline::and(value0, value1)
                );
            }

            emu.flags.calc_flags(result1, emu.get_operand_sz(ins, 0));
            emu.flags.f_of = false;
            emu.flags.f_cf = false;
            emu.flags.calc_pf(result1 as u8);

            if !emu.set_operand_value(ins, 0, result2) {
                return false;
            }
        }

        Mnemonic::Or => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);
            assert!(emu.get_operand_sz(ins, 0) == emu.get_operand_sz(ins, 1));

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            let result1: u64;
            let result2: u64;

            match sz {
                8 => {
                    result1 = (value0 & 0xff) | (value1 & 0xff);
                    result2 = (value0 & 0xffffffffffffff00) + result1;
                }
                16 => {
                    result1 = (value0 & 0xffff) | (value1 & 0xffff);
                    result2 = (value0 & 0xffffffffffff0000) + result1;
                }
                32 => {
                    result1 = (value0 & 0xffffffff) | (value1 & 0xffffffff);
                    result2 = (value0 & 0xffffffff00000000) + result1;
                }
                64 => {
                    result1 = value0 | value1;
                    result2 = result1;
                }
                _ => unreachable!(""),
            }

            if emu.cfg.test_mode && result2 != inline::or(value0, value1) {
                panic!(
                    "0x{:x} should be 0x{:x}",
                    result2,
                    inline::or(value0, value1)
                );
            }

            emu.flags.calc_flags(result1, emu.get_operand_sz(ins, 0));
            emu.flags.f_of = false;
            emu.flags.f_cf = false;
            emu.flags.calc_pf(result1 as u8);

            if !emu.set_operand_value(ins, 0, result2) {
                return false;
            }
        }

        Mnemonic::Sal => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if ins.op_count() == 1 {
                // 1 param

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.sal1p64(value0),
                    32 => emu.flags.sal1p32(value0),
                    16 => emu.flags.sal1p16(value0),
                    8 => emu.flags.sal1p8(value0),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::sal(value0, 1, sz) {
                    panic!(
                        "sal1p 0x{:x} should be 0x{:x}",
                        result,
                        inline::sal(value0, 1, sz)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            } else {
                // 2 params

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.sal2p64(value0, value1),
                    32 => emu.flags.sal2p32(value0, value1),
                    16 => emu.flags.sal2p16(value0, value1),
                    8 => emu.flags.sal2p8(value0, value1),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::sal(value0, value1, sz) {
                    panic!(
                        "sal1p 0x{:x} should be 0x{:x}",
                        result,
                        inline::sal(value0, value1, sz)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            }
        }

        Mnemonic::Sar => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if ins.op_count() == 1 {
                // 1 param

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.sar1p64(value0),
                    32 => emu.flags.sar1p32(value0),
                    16 => emu.flags.sar1p16(value0),
                    8 => emu.flags.sar1p8(value0),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::sar1p(value0, sz, emu.flags.f_cf) {
                    panic!(
                        "0x{:x} should be 0x{:x}",
                        result,
                        inline::sar1p(value0, sz, emu.flags.f_cf)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            } else {
                // 2 params

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.sar2p64(value0, value1),
                    32 => emu.flags.sar2p32(value0, value1),
                    16 => emu.flags.sar2p16(value0, value1),
                    8 => emu.flags.sar2p8(value0, value1),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode
                    && result != inline::sar2p(value0, value1, sz, emu.flags.f_cf)
                {
                    panic!(
                        "0x{:x} should be 0x{:x}",
                        result,
                        inline::sar2p(value0, value1, sz, emu.flags.f_cf)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            }
        }

        Mnemonic::Shl => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if ins.op_count() == 1 {
                // 1 param

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.shl1p64(value0),
                    32 => emu.flags.shl1p32(value0),
                    16 => emu.flags.shl1p16(value0),
                    8 => emu.flags.shl1p8(value0),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::shl(value0, 1, sz) {
                    panic!(
                        "SHL 0x{:x} should be 0x{:x}",
                        result,
                        inline::shl(value0, 1, sz)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            } else {
                // 2 params

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.shl2p64(value0, value1),
                    32 => emu.flags.shl2p32(value0, value1),
                    16 => emu.flags.shl2p16(value0, value1),
                    8 => emu.flags.shl2p8(value0, value1),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::shl(value0, value1, sz) {
                    panic!(
                        "SHL 0x{:x} should be 0x{:x}",
                        result,
                        inline::shl(value0, value1, sz)
                    );
                }

                //log::info!("0x{:x}: 0x{:x} SHL 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, result);

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            }
        }

        Mnemonic::Shr => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if ins.op_count() == 1 {
                // 1 param

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.shr1p64(value0),
                    32 => emu.flags.shr1p32(value0),
                    16 => emu.flags.shr1p16(value0),
                    8 => emu.flags.shr1p8(value0),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::shr(value0, 1, sz) {
                    panic!(
                        "SHR 0x{:x} should be 0x{:x}",
                        result,
                        inline::shr(value0, 1, sz)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            } else {
                // 2 params

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.shr2p64(value0, value1),
                    32 => emu.flags.shr2p32(value0, value1),
                    16 => emu.flags.shr2p16(value0, value1),
                    8 => emu.flags.shr2p8(value0, value1),
                    _ => panic!("weird size"),
                };

                if emu.cfg.test_mode && result != inline::shr(value0, value1, sz) {
                    panic!(
                        "SHR 0x{:x} should be 0x{:x}",
                        result,
                        inline::shr(value0, value1, sz)
                    );
                }

                //log::info!("0x{:x} SHR 0x{:x} >> 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, result);

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            }
        }

        Mnemonic::Ror => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let result: u64;
            let sz = emu.get_operand_sz(ins, 0);

            if ins.op_count() == 1 {
                // 1 param
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::ror(emu, value0, 1, sz);
                emu.flags.calc_flags(result, sz);

                if emu.cfg.test_mode && result != inline::ror(value0, 1, sz) {
                    panic!(
                        "0x{:x} should be 0x{:x}",
                        result,
                        inline::ror(value0, 1, sz)
                    )
                }
            } else {
                // 2 params
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::ror(emu, value0, value1, sz);

                if emu.cfg.test_mode && result != inline::ror(value0, value1, sz) {
                    panic!(
                        "0x{:x} should be 0x{:x}",
                        result,
                        inline::ror(value0, value1, sz)
                    )
                }

                let masked_counter = if sz == 64 {
                    value1 & 0b111111
                } else {
                    value1 & 0b11111
                };

                if masked_counter > 0 {
                    if masked_counter == 1 {
                        // the OF flag is set to the exclusive OR of the two most-significant bits of the result.
                        let of = match sz {
                            64 => (result >> 62) ^ ((result >> 63) & 0b1),
                            32 => (result >> 31) ^ ((result >> 30) & 0b1),
                            16 => (result >> 15) ^ ((result >> 14) & 0b1),
                            8 => (result >> 7) ^ ((result >> 6) & 0b1),
                            _ => panic!("weird size"),
                        };
                        emu.flags.f_of = of == 1;
                    } else {
                        // OF flag is undefined?
                    }
                }
            }

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Rcr => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let result: u64;
            let sz = emu.get_operand_sz(ins, 0);

            if ins.op_count() == 1 {
                // 1 param
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::rcr(emu, value0, 1, sz);
                emu.flags.rcr_of_and_cf(value0, 1, sz);
                emu.flags.calc_flags(result, sz);
            } else {
                // 2 params
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::rcr(emu, value0, value1, sz);
                emu.flags.rcr_of_and_cf(value0, value1, sz);

                let masked_counter = if sz == 64 {
                    value1 & 0b111111
                } else {
                    value1 & 0b11111
                };

                if masked_counter > 0 {
                    emu.flags.calc_flags(result, sz);
                }
            }

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Rol => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let result: u64;
            let sz = emu.get_operand_sz(ins, 0);

            if ins.op_count() == 1 {
                // 1 param
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::rol(emu, value0, 1, sz);

                if emu.cfg.test_mode && result != inline::rol(value0, 1, sz) {
                    panic!(
                        "0x{:x} should be 0x{:x}",
                        result,
                        inline::rol(value0, 1, sz)
                    );
                }

                emu.flags.calc_flags(result, sz);
            } else {
                // 2 params
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let pre_cf = if emu.flags.f_cf { 1 } else { 0 };

                result = logic::rol(emu, value0, value1, sz);

                if emu.cfg.test_mode && result != inline::rol(value0, value1, sz) {
                    panic!(
                        "0x{:x} should be 0x{:x}",
                        result,
                        inline::rol(value0, value1, sz)
                    );
                }

                let masked_counter = if sz == 64 {
                    value1 & 0b111111
                } else {
                    value1 & 0b11111
                };

                // If the masked count is 0, the flags are not affected.
                // If the masked count is 1, then the OF flag is affected, otherwise (masked count is greater than 1) the OF flag is undefined.
                // The CF flag is affected when the masked count is nonzero.
                // The SF, ZF, AF, and PF flags are always unaffected.
                if masked_counter > 0 {
                    if masked_counter == 1 {
                        // the OF flag is set to the exclusive OR of the two most-significant bits of the result.
                        let of = match sz {
                            64 => (result >> 62) ^ pre_cf,
                            32 => (result >> 31) ^ pre_cf,
                            16 => (result >> 15) ^ pre_cf,
                            8 => (result >> 7) ^ pre_cf,
                            _ => panic!("weird size"),
                        };
                        emu.flags.f_of = of == 1;
                    } else {
                        // OF flag is undefined?
                    }
                }
            }

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Rcl => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2);

            let result: u64;
            let sz = emu.get_operand_sz(ins, 0);

            if ins.op_count() == 1 {
                // 1 param
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::rcl(emu, value0, 1, sz);
                emu.flags.calc_flags(result, sz);
            } else {
                // 2 params
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                result = logic::rcl(emu, value0, value1, sz);

                let masked_counter = if sz == 64 {
                    value1 & 0b111111
                } else {
                    value1 & 0b11111
                };

                if masked_counter > 0 {
                    emu.flags.calc_flags(result, sz);
                }
            }

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Mul => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let pre_rax = emu.regs.rax;
            let pre_rdx = emu.regs.rdx;

            let sz = emu.get_operand_sz(ins, 0);
            match sz {
                64 => logic::mul64(emu, value0),
                32 => logic::mul32(emu, value0),
                16 => logic::mul16(emu, value0),
                8 => logic::mul8(emu, value0),
                _ => unimplemented!("wrong size"),
            }

            if emu.cfg.test_mode {
                let (post_rdx, post_rax) = inline::mul(value0, pre_rax, pre_rdx, sz);
                if post_rax != emu.regs.rax || post_rdx != emu.regs.rdx {
                    log::info!(
                        "sz: {} value0: 0x{:x} pre_rax: 0x{:x} pre_rdx: 0x{:x}",
                        sz,
                        value0,
                        pre_rax,
                        pre_rdx
                    );
                    log::info!(
                        "mul rax is 0x{:x} and should be 0x{:x}",
                        emu.regs.rax,
                        post_rax
                    );
                    log::info!(
                        "mul rdx is 0x{:x} and should be 0x{:x}",
                        emu.regs.rdx,
                        post_rdx
                    );
                    panic!("inline asm test failed");
                }
            }
        }

        Mnemonic::Div => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let pre_rax = emu.regs.rax;
            let pre_rdx = emu.regs.rdx;

            let sz = emu.get_operand_sz(ins, 0);
            match sz {
                64 => logic::div64(emu, value0),
                32 => logic::div32(emu, value0),
                16 => logic::div16(emu, value0),
                8 => logic::div8(emu, value0),
                _ => unimplemented!("wrong size"),
            }

            if emu.cfg.test_mode {
                let (post_rdx, post_rax) = inline::div(value0, pre_rax, pre_rdx, sz);
                if post_rax != emu.regs.rax || post_rdx != emu.regs.rdx {
                    log::info!("pos: {}", emu.pos);
                    log::info!(
                        "sz: {} value0: 0x{:x} pre_rax: 0x{:x} pre_rdx: 0x{:x}",
                        sz,
                        value0,
                        pre_rax,
                        pre_rdx
                    );
                    log::info!(
                        "div{} rax is 0x{:x} and should be 0x{:x}",
                        sz,
                        emu.regs.rax,
                        post_rax
                    );
                    log::info!(
                        "div{} rdx is 0x{:x} and should be 0x{:x}",
                        sz,
                        emu.regs.rdx,
                        post_rdx
                    );
                    panic!("inline asm test failed");
                }
            }
        }

        Mnemonic::Idiv => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let pre_rax = emu.regs.rax;
            let pre_rdx = emu.regs.rdx;

            let sz = emu.get_operand_sz(ins, 0);
            match sz {
                64 => logic::idiv64(emu, value0),
                32 => logic::idiv32(emu, value0),
                16 => logic::idiv16(emu, value0),
                8 => logic::idiv8(emu, value0),
                _ => unimplemented!("wrong size"),
            }

            if emu.cfg.test_mode {
                let (post_rdx, post_rax) = inline::idiv(value0, pre_rax, pre_rdx, sz);
                if post_rax != emu.regs.rax || post_rdx != emu.regs.rdx {
                    log::info!(
                        "sz: {} value0: 0x{:x} pre_rax: 0x{:x} pre_rdx: 0x{:x}",
                        sz,
                        value0,
                        pre_rax,
                        pre_rdx
                    );
                    log::info!(
                        "idiv rax is 0x{:x} and should be 0x{:x}",
                        emu.regs.rax,
                        post_rax
                    );
                    log::info!(
                        "idiv rdx is 0x{:x} and should be 0x{:x}",
                        emu.regs.rdx,
                        post_rdx
                    );
                    panic!("inline asm test failed");
                }
            }
        }

        Mnemonic::Imul => {
            emu.show_instruction(&emu.colors.cyan, ins);

            assert!(ins.op_count() == 1 || ins.op_count() == 2 || ins.op_count() == 3);

            if ins.op_count() == 1 {
                // 1 param

                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let pre_rax = emu.regs.rax;
                let pre_rdx = emu.regs.rdx;

                let sz = emu.get_operand_sz(ins, 0);
                match sz {
                    64 => logic::imul64p1(emu, value0),
                    32 => logic::imul32p1(emu, value0),
                    16 => logic::imul16p1(emu, value0),
                    8 => logic::imul8p1(emu, value0),
                    _ => unimplemented!("wrong size"),
                }

                if emu.cfg.test_mode {
                    let (post_rdx, post_rax) = inline::imul1p(value0, pre_rax, pre_rdx, sz);
                    if post_rax != emu.regs.rax || post_rdx != emu.regs.rdx {
                        log::info!(
                            "sz: {} value0: 0x{:x} pre_rax: 0x{:x} pre_rdx: 0x{:x}",
                            sz,
                            value0,
                            pre_rax,
                            pre_rdx
                        );
                        log::info!(
                            "imul1p rax is 0x{:x} and should be 0x{:x}",
                            emu.regs.rax,
                            post_rax
                        );
                        log::info!(
                            "imul1p rdx is 0x{:x} and should be 0x{:x}",
                            emu.regs.rdx,
                            post_rdx
                        );
                        panic!("inline asm test failed");
                    }
                }
            } else if ins.op_count() == 2 {
                // 2 params
                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.imul64p2(value0, value1),
                    32 => emu.flags.imul32p2(value0, value1),
                    16 => emu.flags.imul16p2(value0, value1),
                    8 => emu.flags.imul8p2(value0, value1),
                    _ => unimplemented!("wrong size"),
                };

                if emu.cfg.test_mode && result != inline::imul2p(value0, value1, sz) {
                    panic!(
                        "imul{}p2 gives 0x{:x} and should be 0x{:x}",
                        sz,
                        result,
                        inline::imul2p(value0, value1, sz)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            } else {
                // 3 params

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value2 = match emu.get_operand_value(ins, 2, true) {
                    Some(v) => v,
                    None => return false,
                };

                let sz = emu.get_operand_sz(ins, 0);
                let result = match sz {
                    64 => emu.flags.imul64p2(value1, value2),
                    32 => emu.flags.imul32p2(value1, value2),
                    16 => emu.flags.imul16p2(value1, value2),
                    8 => emu.flags.imul8p2(value1, value2),
                    _ => unimplemented!("wrong size"),
                };

                if emu.cfg.test_mode && result != inline::imul2p(value1, value2, sz) {
                    panic!(
                        "imul{}p3 gives 0x{:x} and should be 0x{:x}",
                        sz,
                        result,
                        inline::imul2p(value1, value2, sz)
                    );
                }

                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            }
        }

        Mnemonic::Bt => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let mut bit = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let value = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 1);
            if sz > 8 {
                bit %= sz as u64;
            }

            if bit < 64 {
                emu.flags.f_cf = get_bit!(value, bit) == 1;
            }
        }

        Mnemonic::Btc => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let mut bitpos = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            bitpos %= sz as u64;

            let cf = get_bit!(value0, bitpos);
            emu.flags.f_cf = cf == 1;

            let mut result = value0;
            set_bit!(result, bitpos, cf ^ 1);

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Bts => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let mut bit = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let value = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            bit %= sz as u64;

            let cf = get_bit!(value, bit);
            emu.flags.f_cf = cf == 1;

            let mut result = value;
            set_bit!(result, bit, 1);

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Btr => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let mut bit = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let value = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            bit %= sz as u64;

            let cf = get_bit!(value, bit);
            emu.flags.f_cf = cf == 1;

            let mut result = value;
            set_bit!(result, bit, 0);

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Bsf => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);

            if value1 == 0 {
                emu.flags.f_zf = true;

                if emu.cfg.verbose >= 1 {
                    log::info!("/!\\ undefined behavior on BSF with src == 0");
                }
            } else {
                emu.flags.f_zf = false;

                if !emu.set_operand_value(ins, 0, value1.trailing_zeros() as u64) {
                    return false;
                }
            }

            // cf flag undefined behavior apple mac x86_64 problem
            if emu.regs.rip == 0x144ed424a {
                if emu.cfg.verbose >= 1 {
                    log::info!("/!\\ f_cf undefined behaviour");
                }
                emu.flags.f_cf = false;
            }

            /*
            if src == 0 {
                emu.flags.f_zf = true;
                if emu.cfg.verbose >= 1 {
                    log::info!("/!\\ bsf src == 0 is undefined behavior");
                }
            } else {
                let sz = emu.get_operand_sz(&ins, 0);
                let mut bitpos: u8 = 0;
                let mut dest: u64 = 0;

                while bitpos < sz && get_bit!(src, bitpos) == 0 {
                    dest += 1;
                    bitpos += 1;
                }

                if dest == 0 {
                    emu.flags.f_zf = true;
                } else {
                    emu.flags.f_zf = false;
                }

                if !emu.set_operand_value(&ins, 0, dest) {
                    return false;
                }
            }*/
        }

        Mnemonic::Bsr => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);

            let (result, new_flags) = inline::bsr(value0, value1, sz, emu.flags.dump());

            emu.flags.load(new_flags);

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }

            /*
            if value1 == 0 {
                emu.flags.f_zf = true;
                if emu.cfg.verbose >= 1 {
                    log::info!("/!\\ bsr src == 0 is undefined behavior");
                }
            } else {
                let sz = emu.get_operand_sz(&ins, 0);
                let mut dest: u64 = sz as u64 -1;

                while dest > 0 && get_bit!(value1, dest) == 0 {
                    dest -= 1;
                }

                if dest == 0 {
                    emu.flags.f_zf = true;
                } else {
                    emu.flags.f_zf = false;
                }

                if !emu.set_operand_value(&ins, 0, dest) {
                    return false;
                }
            }*/
        }

        Mnemonic::Bswap => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 1);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1;
            let sz = emu.get_operand_sz(ins, 0);

            if sz == 32 {
                value1 = (value0 & 0x00000000_000000ff) << 24
                    | (value0 & 0x00000000_0000ff00) << 8
                    | (value0 & 0x00000000_00ff0000) >> 8
                    | (value0 & 0x00000000_ff000000) >> 24
                    | (value0 & 0xffffffff_00000000);
            } else if sz == 64 {
                value1 = (value0 & 0xff000000_00000000) >> 56
                    | (value0 & 0x00ff0000_00000000) >> 40
                    | (value0 & 0x0000ff00_00000000) >> 24
                    | (value0 & 0x000000ff_00000000) >> 8
                    | (value0 & 0x00000000_ff000000) << 8
                    | (value0 & 0x00000000_00ff0000) << 24
                    | (value0 & 0x00000000_0000ff00) << 40
                    | (value0 & 0x00000000_000000ff) << 56;
            } else if sz == 16 {
                value1 = 0;
                if emu.cfg.verbose >= 1 {
                    log::info!("/!\\ bswap of 16bits has undefined behaviours");
                }
            } else {
                unimplemented!("bswap <16bits makes no sense, isn't it?");
            }

            if emu.cfg.test_mode && value1 != inline::bswap(value0, sz) {
                panic!(
                    "bswap test failed, 0x{:x} should be 0x{:x}",
                    value1,
                    inline::bswap(value0, sz)
                );
            }

            /*
            for i in 0..sz {
                let bit = get_bit!(value0, i);
                set_bit!(value1, sz-i-1, bit);
            }*/

            if !emu.set_operand_value(ins, 0, value1) {
                return false;
            }
        }

        Mnemonic::Xadd => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if !emu.set_operand_value(ins, 1, value0) {
                return false;
            }

            let res: u64 = match emu.get_operand_sz(ins, 1) {
                64 => emu.flags.add64(value0, value1, emu.flags.f_cf, false),
                32 => emu.flags.add32(
                    (value0 & 0xffffffff) as u32,
                    (value1 & 0xffffffff) as u32,
                    emu.flags.f_cf,
                    false,
                ),
                16 => emu.flags.add16(
                    (value0 & 0xffff) as u16,
                    (value1 & 0xffff) as u16,
                    emu.flags.f_cf,
                    false,
                ),
                8 => emu.flags.add8(
                    (value0 & 0xff) as u8,
                    (value1 & 0xff) as u8,
                    emu.flags.f_cf,
                    false,
                ),
                _ => unreachable!("weird size"),
            };

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Ucomiss => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let val1 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let val2 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let low_val1 = (val1 & 0xFFFFFFFF) as u32;
            let low_val2 = (val2 & 0xFFFFFFFF) as u32;

            let f1 = f32::from_bits(low_val1);
            let f2 = f32::from_bits(low_val2);

            emu.flags.f_zf = false;
            emu.flags.f_pf = false;
            emu.flags.f_cf = false;

            if f1.is_nan() || f2.is_nan() {
                emu.flags.f_pf = true;
            } else if f1 == f2 {
                emu.flags.f_zf = true;
            } else if f1 < f2 {
                emu.flags.f_cf = true;
            }
        }

        Mnemonic::Ucomisd => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value2 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let low_val1 = (value1 & 0xFFFFFFFFFFFFFFFF) as u64;
            let low_val2 = (value2 & 0xFFFFFFFFFFFFFFFF) as u64;

            let f1 = f64::from_bits(low_val1);
            let f2 = f64::from_bits(low_val2);

            emu.flags.f_zf = false;
            emu.flags.f_pf = false;
            emu.flags.f_cf = false;

            if f1.is_nan() || f2.is_nan() {
                emu.flags.f_pf = true;
            } else if f1 == f2 {
                emu.flags.f_zf = true;
            } else if f1 < f2 {
                emu.flags.f_cf = true;
            }
        }

        Mnemonic::Movss => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            if ins.op_count() > 2 {
                unimplemented!("Movss with 3 operands is not implemented yet");
            }

            assert!(ins.op_count() == 2);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz1 == 128 {
                let val = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let vf32: f32 = f32::from_bits((val & 0xFFFFFFFF) as u32);
                let result: u32 = vf32.to_bits();

                if !emu.set_operand_value(ins, 0, result as u64) {
                    return false;
                }
            } else if sz0 == 128 && sz1 < 128 {
                let val = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1_f32: f32 = f32::from_bits(val as u32);
                let result: u32 = value1_f32.to_bits();
                let xmm_value: u128 = result as u128;

                emu.set_operand_xmm_value_128(ins, 0, xmm_value);
            } else {
                unimplemented!("Movss unimplemented operation");
            }
        }

        Mnemonic::Movsxd => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let result: u64 = value1 as u32 as i32 as i64 as u64;

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Movsx => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            assert!(
                !(sz1 != 8 || sz0 != 16 && sz0 != 32)
                    || (sz0 == 32 && sz1 == 16)
                    || (sz0 == 64 && sz1 == 32)
                    || (sz0 == 64 && sz1 == 16)
                    || (sz0 == 64 && sz1 == 8)
            );

            let mut result: u64 = 0;

            if sz0 == 16 {
                assert!(sz1 == 8);
                result = value1 as u8 as i8 as i16 as u16 as u64;
            } else if sz0 == 32 {
                if sz1 == 8 {
                    result = value1 as u8 as i8 as i64 as u64;
                } else if sz1 == 16 {
                    result = value1 as u16 as i16 as i32 as u32 as u64;
                }
            } else if sz0 == 64 {
                if sz1 == 8 {
                    result = value1 as u8 as i8 as i64 as u64;
                } else if sz1 == 16 {
                    result = value1 as u16 as i16 as i64 as u64;
                } else if sz1 == 32 {
                    result = value1 as u32 as i32 as i64 as u64;
                }
            }

            if emu.cfg.test_mode && result != inline::movsx(value1, sz0, sz1) {
                panic!(
                    "MOVSX sz:{}->{}  0x{:x} should be 0x{:x}",
                    sz0,
                    sz1,
                    result,
                    inline::movsx(value1, sz0, sz1)
                );
            }

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Movzx => {
            emu.show_instruction(&emu.colors.light_cyan, ins);
            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            assert!(
                !(sz1 != 8 || sz0 != 16 && sz0 != 32)
                    || (sz0 == 32 && sz1 == 16)
                    || (sz0 == 64 && sz1 == 32)
                    || (sz0 == 64 && sz1 == 16)
                    || (sz0 == 64 && sz1 == 8)
            );

            let result: u64 = value1;

            //log::info!("0x{:x}: MOVZX 0x{:x}", ins.ip32(), result);

            /*
            if emu.cfg.test_mode {
                if result != inline::movzx(value1) {
                    panic!("MOVZX sz:{}->{} 0x{:x} should be 0x{:x}",
                           sz1, sz0, result, inline::movzx(value1));
                }
            }*/

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Movsb => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                let val = match emu.maps.read_byte(emu.regs.rsi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read memory on rsi");
                        return false;
                    }
                };
                if !emu.maps.write_byte(emu.regs.rdi, val) {
                    log::info!("cannot write memoryh on rdi");
                    return false;
                }

                if !emu.flags.f_df {
                    emu.regs.rsi += 1;
                    emu.regs.rdi += 1;
                } else {
                    emu.regs.rsi -= 1;
                    emu.regs.rdi -= 1;
                }
            } else {
                let val = match emu.maps.read_byte(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read memory on esi");
                        return false;
                    }
                };
                if !emu.maps.write_byte(emu.regs.get_edi(), val) {
                    log::info!("cannot write memory on edi");
                    return false;
                }

                if !emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() + 1);
                    emu.regs.set_edi(emu.regs.get_edi() + 1);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() - 1);
                    emu.regs.set_edi(emu.regs.get_edi() - 1);
                }
            }
        }

        Mnemonic::Movsw => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                let val = emu
                    .maps
                    .read_word(emu.regs.rsi)
                    .expect("cannot read memory");
                emu.maps.write_word(emu.regs.rdi, val);

                if !emu.flags.f_df {
                    emu.regs.rsi += 2;
                    emu.regs.rdi += 2;
                } else {
                    emu.regs.rsi -= 2;
                    emu.regs.rdi -= 2;
                }
            } else {
                // 32bits
                let val = emu
                    .maps
                    .read_word(emu.regs.get_esi())
                    .expect("cannot read memory");
                emu.maps.write_word(emu.regs.get_edi(), val);

                if !emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() + 2);
                    emu.regs.set_edi(emu.regs.get_edi() + 2);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() - 2);
                    emu.regs.set_edi(emu.regs.get_edi() - 2);
                }
            }
        }

        Mnemonic::Movsq => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }
            emu.pos += 1;

            assert!(emu.cfg.is_64bits);

            let val = emu
                .maps
                .read_qword(emu.regs.rsi)
                .expect("cannot read memory");
            emu.maps.write_qword(emu.regs.rdi, val);

            if !emu.flags.f_df {
                emu.regs.rsi += 8;
                emu.regs.rdi += 8;
            } else {
                emu.regs.rsi -= 8;
                emu.regs.rdi -= 8;
            }
        }

        Mnemonic::Movsd => {
            if ins.op_count() == 2
                && (emu.get_operand_sz(ins, 0) == 128 || emu.get_operand_sz(ins, 1) == 128)
            {
                emu.show_instruction(&emu.colors.light_cyan, ins);
                let src = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v & 0xffffffff_ffffffff,
                    None => return false,
                };

                let mut dst = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                dst = (dst & 0xffffffff_ffffffff_00000000_00000000) | src;

                emu.set_operand_xmm_value_128(ins, 0, dst);
            } else {
                // legacy mode of movsd

                if emu.rep.is_some() {
                    if emu.rep.unwrap() == 0 {
                        emu.show_instruction(&emu.colors.light_cyan, ins);
                    }
                } else {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }

                if emu.cfg.is_64bits {
                    let val = emu
                        .maps
                        .read_dword(emu.regs.rsi)
                        .expect("cannot read memory");

                    emu.maps.write_dword(emu.regs.rdi, val);

                    if !emu.flags.f_df {
                        emu.regs.rsi += 4;
                        emu.regs.rdi += 4;
                    } else {
                        emu.regs.rsi -= 4;
                        emu.regs.rdi -= 4;
                    }
                } else {
                    // 32bits

                    let val = match emu.maps.read_dword(emu.regs.get_esi()) {
                        Some(v) => v,
                        None => {
                            log::info!("cannot read memory at esi");
                            return false;
                        }
                    };
                    emu.maps.write_dword(emu.regs.get_edi(), val);

                    if !emu.flags.f_df {
                        emu.regs.set_esi(emu.regs.get_esi() + 4);
                        emu.regs.set_edi(emu.regs.get_edi() + 4);
                    } else {
                        emu.regs.set_esi(emu.regs.get_esi() - 4);
                        emu.regs.set_edi(emu.regs.get_edi() - 4);
                    }
                }
            }
        }

        Mnemonic::Cmova => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_cf && !emu.flags.f_zf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovae => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_cf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovb => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_cf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovbe => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_cf || emu.flags.f_zf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmove => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_zf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovg => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_zf && emu.flags.f_sf == emu.flags.f_of {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovge => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_sf == emu.flags.f_of {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovl => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_sf != emu.flags.f_of {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovle => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_zf || emu.flags.f_sf != emu.flags.f_of {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovno => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_of {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovne => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_zf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovp => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_pf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        // https://hjlebbink.github.io/x86doc/html/CMOVcc.html
        Mnemonic::Cmovnp => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_pf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovs => {
            emu.show_instruction(&emu.colors.orange, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if emu.flags.f_sf {
                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            } else {
                // clear upper bits of register?
                if !emu.set_operand_value(ins, 0, value0) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovns => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_sf {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Cmovo => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_of {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            }
        }

        Mnemonic::Seta => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_cf && !emu.flags.f_zf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setae => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_cf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setb => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_cf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setbe => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_cf || emu.flags.f_zf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Sete => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_zf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setg => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_zf && emu.flags.f_sf == emu.flags.f_of {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setge => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_sf == emu.flags.f_of {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setl => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_sf != emu.flags.f_of {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setle => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_zf || emu.flags.f_sf != emu.flags.f_of {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setne => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_zf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setno => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_of {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setnp => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_pf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setns => {
            emu.show_instruction(&emu.colors.orange, ins);

            if !emu.flags.f_sf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Seto => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_of {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Setp => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_pf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Sets => {
            emu.show_instruction(&emu.colors.orange, ins);

            if emu.flags.f_sf {
                if !emu.set_operand_value(ins, 0, 1) {
                    return false;
                }
            } else if !emu.set_operand_value(ins, 0, 0) {
                return false;
            }
        }

        Mnemonic::Stosb => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                if !emu
                    .maps
                    .write_byte(emu.regs.rdi, emu.regs.get_al() as u8)
                {
                    return false;
                }
                if emu.flags.f_df {
                    emu.regs.rdi -= 1;
                } else {
                    emu.regs.rdi += 1;
                }
            } else {
                // 32bits
                if !emu
                    .maps
                    .write_byte(emu.regs.get_edi(), emu.regs.get_al() as u8)
                {
                    return false;
                }
                if emu.flags.f_df {
                    emu.regs.set_edi(emu.regs.get_edi() - 1);
                } else {
                    emu.regs.set_edi(emu.regs.get_edi() + 1);
                }
            }
        }

        Mnemonic::Stosw => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            if emu.cfg.is_64bits {
                emu.maps
                    .write_word(emu.regs.rdi, emu.regs.get_ax() as u16);

                if emu.flags.f_df {
                    emu.regs.rdi -= 2;
                } else {
                    emu.regs.rdi += 2;
                }
            } else {
                // 32bits
                emu.maps
                    .write_word(emu.regs.get_edi(), emu.regs.get_ax() as u16);

                if emu.flags.f_df {
                    emu.regs.set_edi(emu.regs.get_edi() - 2);
                } else {
                    emu.regs.set_edi(emu.regs.get_edi() + 2);
                }
            }
        }

        Mnemonic::Stosd => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                if !emu
                    .maps
                    .write_dword(emu.regs.rdi, emu.regs.get_eax() as u32)
                {
                    return false;
                }
                if emu.flags.f_df {
                    emu.regs.rdi -= 4;
                } else {
                    emu.regs.rdi += 4;
                }
            } else {
                // 32bits
                if !emu
                    .maps
                    .write_dword(emu.regs.get_edi(), emu.regs.get_eax() as u32)
                {
                    return false;
                }

                if emu.flags.f_df {
                    emu.regs.set_edi(emu.regs.get_edi() - 4);
                } else {
                    emu.regs.set_edi(emu.regs.get_edi() + 4);
                }
            }
        }

        Mnemonic::Stosq => {
            assert!(emu.cfg.is_64bits);

            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            emu.maps.write_qword(emu.regs.rdi, emu.regs.rax);

            if emu.flags.f_df {
                emu.regs.rdi -= 8;
            } else {
                emu.regs.rdi += 8;
            }
        }

        Mnemonic::Scasb => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            let value0: u64 = match emu.maps.read_byte(emu.regs.rdi) {
                Some(value) => value.into(),
                None => {
                    log::info!("/!\\ error reading byte on rdi 0x{:x}", emu.regs.rdi);
                    return false;
                }
            };

            emu.flags.sub8(emu.regs.get_al(), value0);

            if emu.cfg.is_64bits {
                if emu.flags.f_df {
                    emu.regs.rdi -= 1;
                } else {
                    emu.regs.rdi += 1;
                }
            } else {
                // 32bits
                if emu.flags.f_df {
                    emu.regs.set_edi(emu.regs.get_edi() - 1);
                } else {
                    emu.regs.set_edi(emu.regs.get_edi() + 1);
                }
            }
        }

        Mnemonic::Scasw => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            emu.flags.sub16(emu.regs.get_ax(), value0);

            if emu.cfg.is_64bits {
                if emu.flags.f_df {
                    emu.regs.rdi -= 2;
                } else {
                    emu.regs.rdi += 2;
                }
            } else {
                // 32bits
                if emu.flags.f_df {
                    emu.regs.set_edi(emu.regs.get_edi() - 2);
                } else {
                    emu.regs.set_edi(emu.regs.get_edi() + 2);
                }
            }
        }

        Mnemonic::Scasd => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            emu.flags.sub32(emu.regs.get_eax(), value0);

            if emu.cfg.is_64bits {
                if emu.flags.f_df {
                    emu.regs.rdi -= 4;
                } else {
                    emu.regs.rdi += 4;
                }
            } else {
                // 32bits
                if emu.flags.f_df {
                    emu.regs.set_edi(emu.regs.get_edi() - 4);
                } else {
                    emu.regs.set_edi(emu.regs.get_edi() + 4);
                }
            }
        }

        Mnemonic::Scasq => {
            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            emu.flags.sub64(emu.regs.rax, value0);

            if emu.flags.f_df {
                emu.regs.rdi -= 8;
            } else {
                emu.regs.rdi += 8;
            }
        }

        Mnemonic::Test => {
            emu.show_instruction(&emu.colors.orange, ins);

            assert!(ins.op_count() == 2);

            if emu.break_on_next_cmp {
                Console::spawn_console(emu);
                emu.break_on_next_cmp = false;
            }

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);

            emu.flags.test(value0, value1, sz);
        }

        Mnemonic::Cmpxchg => {
            emu.show_instruction(&emu.colors.orange, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if emu.cfg.is_64bits {
                if value0 == emu.regs.rax {
                    emu.flags.f_zf = true;
                    if !emu.set_operand_value(ins, 0, value1) {
                        return false;
                    }
                } else {
                    emu.flags.f_zf = false;
                    emu.regs.rax = value1;
                }
            } else {
                // 32bits
                if value0 == emu.regs.get_eax() {
                    emu.flags.f_zf = true;
                    if !emu.set_operand_value(ins, 0, value1) {
                        return false;
                    }
                } else {
                    emu.flags.f_zf = false;
                    emu.regs.set_eax(value1);
                }
            }
        }

        Mnemonic::Cmpxchg8b => {
            emu.show_instruction(&emu.colors.orange, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if value0 as u8 == (emu.regs.get_al() as u8) {
                emu.flags.f_zf = true;
                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            } else {
                emu.flags.f_zf = false;
                emu.regs.set_al(value1 & 0xff);
            }
        }

        Mnemonic::Cmpxchg16b => {
            emu.show_instruction(&emu.colors.orange, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if value0 as u16 == (emu.regs.get_ax() as u16) {
                emu.flags.f_zf = true;
                if !emu.set_operand_value(ins, 0, value1) {
                    return false;
                }
            } else {
                emu.flags.f_zf = false;
                emu.regs.set_ax(value1 & 0xffff);
            }
        }

        Mnemonic::Cmp => {
            emu.show_instruction(&emu.colors.orange, ins);

            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            if emu.cfg.verbose >= 2 {
                if value0 > value1 {
                    log::info!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                } else if value0 < value1 {
                    log::info!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                } else {
                    log::info!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                }
            }

            if emu.break_on_next_cmp {
                Console::spawn_console(emu);
                emu.break_on_next_cmp = false;

                let value0 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.verbose >= 2 {
                    if value0 > value1 {
                        log::info!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                    } else if value0 < value1 {
                        log::info!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                    } else {
                        log::info!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                    }
                }
            }

            match emu.get_operand_sz(ins, 0) {
                64 => {
                    emu.flags.sub64(value0, value1);
                }
                32 => {
                    emu.flags.sub32(value0, value1);
                }
                16 => {
                    emu.flags.sub16(value0, value1);
                }
                8 => {
                    emu.flags.sub8(value0, value1);
                }
                _ => {
                    panic!("wrong size {}", emu.get_operand_sz(ins, 0));
                }
            }
        }

        Mnemonic::Cmpsq => {
            assert!(emu.cfg.is_64bits);

            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            let value0: u64 = match emu.maps.read_qword(emu.regs.rsi) {
                Some(v) => v,
                None => {
                    log::info!("cannot read rsi");
                    return false;
                }
            };
            let value1: u64 = match emu.maps.read_qword(emu.regs.rdi) {
                Some(v) => v,
                None => {
                    log::info!("cannot read rdi");
                    return false;
                }
            };

            if emu.flags.f_df {
                emu.regs.rsi -= 8;
                emu.regs.rdi -= 8;
            } else {
                emu.regs.rsi += 8;
                emu.regs.rdi += 8;
            }

            emu.flags.sub64(value0, value1);

            if emu.cfg.verbose >= 2 {
                if value0 > value1 {
                    log::info!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                } else if value0 < value1 {
                    log::info!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                } else {
                    log::info!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                }
            }
        }

        Mnemonic::Cmpsd => {
            let value0: u32;
            let value1: u32;

            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                value0 = match emu.maps.read_dword(emu.regs.rsi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read rsi");
                        return false;
                    }
                };
                value1 = match emu.maps.read_dword(emu.regs.rdi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read rdi");
                        return false;
                    }
                };

                if emu.flags.f_df {
                    emu.regs.rsi -= 4;
                    emu.regs.rdi -= 4;
                } else {
                    emu.regs.rsi += 4;
                    emu.regs.rdi += 4;
                }
            } else {
                // 32bits
                value0 = match emu.maps.read_dword(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read esi");
                        return false;
                    }
                };
                value1 = match emu.maps.read_dword(emu.regs.get_edi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read edi");
                        return false;
                    }
                };

                if emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() - 4);
                    emu.regs.set_edi(emu.regs.get_edi() - 4);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() + 4);
                    emu.regs.set_edi(emu.regs.get_edi() + 4);
                }
            }

            emu.flags.sub32(value0 as u64, value1 as u64);

            if emu.cfg.verbose >= 2 {
                if value0 > value1 {
                    log::info!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                } else if value0 < value1 {
                    log::info!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                } else {
                    log::info!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                }
            }
        }

        Mnemonic::Cmpsw => {
            let value0: u16;
            let value1: u16;

            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                value0 = match emu.maps.read_word(emu.regs.rsi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read rsi");
                        return false;
                    }
                };
                value1 = match emu.maps.read_word(emu.regs.rdi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read rdi");
                        return false;
                    }
                };

                if emu.flags.f_df {
                    emu.regs.rsi -= 2;
                    emu.regs.rdi -= 2;
                } else {
                    emu.regs.rsi += 2;
                    emu.regs.rdi += 2;
                }
            } else {
                // 32bits
                value0 = match emu.maps.read_word(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read esi");
                        return false;
                    }
                };
                value1 = match emu.maps.read_word(emu.regs.get_edi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read edi");
                        return false;
                    }
                };

                if emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() - 2);
                    emu.regs.set_edi(emu.regs.get_edi() - 2);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() + 2);
                    emu.regs.set_edi(emu.regs.get_edi() + 2);
                }
            }

            emu.flags.sub16(value0 as u64, value1 as u64);

            if emu.cfg.verbose >= 2 {
                if value0 > value1 {
                    log::info!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                } else if value0 < value1 {
                    log::info!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                } else {
                    log::info!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                }
            }
        }

        Mnemonic::Cmpsb => {
            let value0: u8;
            let value1: u8;

            if emu.rep.is_some() {
                if emu.rep.unwrap() == 0 || emu.cfg.verbose >= 3 {
                    emu.show_instruction(&emu.colors.light_cyan, ins);
                }
            } else {
                emu.show_instruction(&emu.colors.light_cyan, ins);
            }

            if emu.cfg.is_64bits {
                value0 = match emu.maps.read_byte(emu.regs.rsi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read rsi");
                        return false;
                    }
                };
                value1 = match emu.maps.read_byte(emu.regs.rdi) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read rdi");
                        return false;
                    }
                };

                if emu.flags.f_df {
                    emu.regs.rsi -= 1;
                    emu.regs.rdi -= 1;
                } else {
                    emu.regs.rsi += 1;
                    emu.regs.rdi += 1;
                }
            } else {
                // 32bits
                value0 = match emu.maps.read_byte(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read esi");
                        return false;
                    }
                };
                value1 = match emu.maps.read_byte(emu.regs.get_edi()) {
                    Some(v) => v,
                    None => {
                        log::info!("cannot read edi");
                        return false;
                    }
                };

                if emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() - 1);
                    emu.regs.set_edi(emu.regs.get_edi() - 1);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() + 1);
                    emu.regs.set_edi(emu.regs.get_edi() + 1);
                }
            } // end 32bits

            emu.flags.sub8(value0 as u64, value1 as u64);

            if emu.cfg.verbose >= 2 {
                if value0 > value1 {
                    log::info!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                } else if value0 < value1 {
                    log::info!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                } else {
                    log::info!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                }
            }
        }

        //branches: https://web.itu.edu.tr/kesgin/mul06/intel/instr/jxx.html
        //          https://c9x.me/x86/html/file_module_x86_id_146.html
        //          http://unixwiz.net/techtips/x86-jumps.html <---aqui

        //esquema global -> https://en.wikipedia.org/wiki/X86_instruction_listings
        // test jnle jpe jpo loopz loopnz int 0x80
        Mnemonic::Jo => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_of {
                emu.show_instruction_taken(&emu.colors.orange, ins);

                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jno => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_of {
                emu.show_instruction_taken(&emu.colors.orange, ins);

                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Js => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_sf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jns => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_sf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Je => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_zf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jne => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_zf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jb => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_cf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jae => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_cf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jbe => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_cf || emu.flags.f_zf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Ja => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_cf && !emu.flags.f_zf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jl => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_sf != emu.flags.f_of {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jge => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_sf == emu.flags.f_of {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jle => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_zf || emu.flags.f_sf != emu.flags.f_of {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jg => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_zf && emu.flags.f_sf == emu.flags.f_of {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jp => {
            assert!(ins.op_count() == 1);

            if emu.flags.f_pf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jnp => {
            assert!(ins.op_count() == 1);

            if !emu.flags.f_pf {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jcxz => {
            assert!(ins.op_count() == 1);

            if emu.regs.get_cx() == 0 {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jecxz => {
            assert!(ins.op_count() == 1);

            if emu.regs.get_cx() == 0 {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Jrcxz => {
            if emu.regs.rcx == 0 {
                emu.show_instruction_taken(&emu.colors.orange, ins);
                let addr = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => return false,
                };

                if emu.cfg.is_64bits {
                    return emu.set_rip(addr, true);
                } else {
                    return emu.set_eip(addr, true);
                }
            } else {
                emu.show_instruction_not_taken(&emu.colors.orange, ins);
            }
        }

        Mnemonic::Int3 => {
            emu.show_instruction(&emu.colors.red, ins);
            log::info!("/!\\ int 3 sigtrap!!!!");
            emu.exception();
            return true;
        }

        Mnemonic::Nop => {
            emu.show_instruction(&emu.colors.light_purple, ins);
        }

        Mnemonic::Fnop => {
            emu.show_instruction(&emu.colors.light_purple, ins);
        }

        Mnemonic::Mfence | Mnemonic::Lfence | Mnemonic::Sfence => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Cpuid => {
            emu.show_instruction(&emu.colors.red, ins);

            // guloader checks bit31 which is if its hipervisor with command
            // https://c9x.me/x86/html/file_module_x86_id_45.html
            // TODO: implement 0x40000000 -> get the virtualization vendor

            if emu.cfg.verbose >= 1 {
                log::info!(
                    "\tcpuid input value: 0x{:x}, 0x{:x}",
                    emu.regs.rax,
                    emu.regs.rcx
                );
            }

            match emu.regs.rax {
                0x00 => {
                    emu.regs.rax = 0x16;
                    emu.regs.rbx = 0x756e6547;
                    emu.regs.rcx = 0x6c65746e;
                    emu.regs.rdx = 0x49656e69;
                }
                0x01 => {
                    emu.regs.rax = 0x906ed; // Version Information (Type, Family, Model, and Stepping ID)
                    emu.regs.rbx = 0x5100800;
                    emu.regs.rcx = 0x7ffafbbf;
                    emu.regs.rdx = 0xbfebfbff; // feature
                }
                0x02 => {
                    emu.regs.rax = 0x76036301;
                    emu.regs.rbx = 0xf0b5ff;
                    emu.regs.rcx = 0;
                    emu.regs.rdx = 0xc30000;
                }
                0x03 => {
                    emu.regs.rax = 0;
                    emu.regs.rbx = 0;
                    emu.regs.rcx = 0;
                    emu.regs.rdx = 0;
                }
                0x04 => {
                    emu.regs.rax = 0;
                    emu.regs.rbx = 0x1c0003f;
                    emu.regs.rcx = 0x3f;
                    emu.regs.rdx = 0;
                }
                0x05 => {
                    emu.regs.rax = 0x40;
                    emu.regs.rbx = 0x40;
                    emu.regs.rcx = 3;
                    emu.regs.rdx = 0x11142120;
                }
                0x06 => {
                    emu.regs.rax = 0x27f7;
                    emu.regs.rbx = 2;
                    emu.regs.rcx = 9;
                    emu.regs.rdx = 0;
                }
                0x0d => {
                    match emu.regs.rcx {
                        1 => {
                            emu.regs.rax = 0xf;
                            emu.regs.rbx = 0x3c0;
                            emu.regs.rcx = 0x100;
                            emu.regs.rdx = 0;
                        }
                        0 => {
                            emu.regs.rax = 0x1f;
                            emu.regs.rbx = 0x440;
                            emu.regs.rcx = 0x440;
                            emu.regs.rdx = 0;
                        }
                        2 => {
                            emu.regs.rax = 0x100;
                            emu.regs.rbx = 0x240;
                            emu.regs.rcx = 0;
                            emu.regs.rdx = 0;
                        }
                        3 => {
                            emu.regs.rax = 0x40;
                            emu.regs.rbx = 0x3c0;
                            emu.regs.rcx = 0;
                            emu.regs.rdx = 0;
                        }
                        5..=7 => {
                            emu.regs.rax = 0;
                            emu.regs.rbx = 0;
                            emu.regs.rcx = 0;
                            emu.regs.rdx = 0;
                        }
                        _ => {
                            emu.regs.rax = 0x1f; //0x1f
                            emu.regs.rbx = 0x440; //0x3c0; // 0x440
                            emu.regs.rcx = 0x440; //0x100; // 0x440
                            emu.regs.rdx = 0;
                        }
                    }
                }
                0x07..=0x6d => {
                    emu.regs.rax = 0;
                    emu.regs.rbx = 0x29c67af;
                    emu.regs.rcx = 0x40000000;
                    emu.regs.rdx = 0xbc000600;
                }
                0x6e => {
                    emu.regs.rax = 0x960;
                    emu.regs.rbx = 0x1388;
                    emu.regs.rcx = 0x64;
                    emu.regs.rdx = 0;
                }
                0x80000000 => {
                    emu.regs.rax = 0x80000008;
                    emu.regs.rbx = 0;
                    emu.regs.rcx = 0;
                    emu.regs.rdx = 0;
                }
                0x80000001 => {
                    emu.regs.rax = 0;
                    emu.regs.rbx = 0;
                    emu.regs.rcx = 0x121;
                    emu.regs.rdx = 0x2c100800;
                    emu.regs.rsi = 0x80000008;
                }
                0x80000007 => {
                    emu.regs.rax = 0;
                    emu.regs.rbx = 0;
                    emu.regs.rcx = 0;
                    emu.regs.rdx = 0x100;
                }
                0x80000008 => {
                    emu.regs.rax = 0x3027;
                    emu.regs.rbx = 0;
                    emu.regs.rcx = 0;
                    emu.regs.rdx = 0; //0x100;
                }
                _ => {
                    log::info!("unimplemented cpuid call 0x{:x}", emu.regs.rax);
                    return false;
                }
            }
        }

        Mnemonic::Clc => {
            emu.show_instruction(&emu.colors.light_gray, ins);
            emu.flags.f_cf = false;
        }

        Mnemonic::Rdtsc => {
            emu.show_instruction(&emu.colors.red, ins);

            let elapsed = emu.now.elapsed();
            let cycles: u64 = elapsed.as_nanos() as u64;
            emu.regs.rax = cycles & 0xffffffff;
            emu.regs.rdx = cycles >> 32;
        }

        Mnemonic::Rdtscp => {
            emu.show_instruction(&emu.colors.red, ins);

            let elapsed = emu.now.elapsed();
            let cycles: u64 = elapsed.as_nanos() as u64;
            emu.regs.rax = cycles & 0xffffffff;
            emu.regs.rdx = cycles >> 32;
            emu.regs.rcx = 1; // core id
        }

        Mnemonic::Loop => {
            emu.show_instruction(&emu.colors.yellow, ins);

            assert!(ins.op_count() == 1);

            let addr = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if addr > 0xffffffff {
                if emu.regs.rcx == 0 {
                    emu.regs.rcx = 0xffffffffffffffff;
                } else {
                    emu.regs.rcx -= 1;
                }

                if emu.regs.rcx > 0 {
                    return emu.set_rip(addr, false);
                }
            } else if addr > 0xffff {
                if emu.regs.get_ecx() == 0 {
                    emu.regs.set_ecx(0xffffffff);
                } else {
                    emu.regs.set_ecx(emu.regs.get_ecx() - 1);
                }

                if emu.regs.get_ecx() > 0 {
                    if emu.cfg.is_64bits {
                        return emu.set_rip(addr, false);
                    } else {
                        return emu.set_eip(addr, false);
                    }
                }
            } else {
                if emu.regs.get_cx() == 0 {
                    emu.regs.set_cx(0xffff);
                } else {
                    emu.regs.set_cx(emu.regs.get_cx() - 1);
                }

                if emu.regs.get_cx() > 0 {
                    if emu.cfg.is_64bits {
                        return emu.set_rip(addr, false);
                    } else {
                        return emu.set_eip(addr, false);
                    }
                }
            }
        }

        Mnemonic::Loope => {
            emu.show_instruction(&emu.colors.yellow, ins);

            assert!(ins.op_count() == 1);

            let addr = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if addr > 0xffffffff {
                if emu.regs.rcx == 0 {
                    emu.regs.rcx = 0xffffffffffffffff;
                } else {
                    emu.regs.rcx -= 1;
                }

                if emu.regs.rcx > 0 && emu.flags.f_zf {
                    return emu.set_rip(addr, false);
                }
            } else if addr > 0xffff {
                if emu.regs.get_ecx() == 0 {
                    emu.regs.set_ecx(0xffffffff);
                } else {
                    emu.regs.set_ecx(emu.regs.get_ecx() - 1);
                }

                if emu.regs.get_ecx() > 0 && emu.flags.f_zf {
                    if emu.cfg.is_64bits {
                        return emu.set_rip(addr, false);
                    } else {
                        return emu.set_eip(addr, false);
                    }
                }
            } else {
                if emu.regs.get_cx() == 0 {
                    emu.regs.set_cx(0xffff);
                } else {
                    emu.regs.set_cx(emu.regs.get_cx() - 1);
                }

                if emu.regs.get_cx() > 0 && emu.flags.f_zf {
                    if emu.cfg.is_64bits {
                        return emu.set_rip(addr, false);
                    } else {
                        return emu.set_eip(addr, false);
                    }
                }
            }
        }

        Mnemonic::Loopne => {
            emu.show_instruction(&emu.colors.yellow, ins);

            assert!(ins.op_count() == 1);

            let addr = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            if addr > 0xffffffff {
                if emu.regs.rcx == 0 {
                    emu.regs.rcx = 0xffffffffffffffff;
                } else {
                    emu.regs.rcx -= 1;
                }

                if emu.regs.rcx > 0 && !emu.flags.f_zf {
                    return emu.set_rip(addr, false);
                }
            } else if addr > 0xffff {
                if emu.regs.get_ecx() == 0 {
                    emu.regs.set_ecx(0xffffffff);
                } else {
                    emu.regs.set_ecx(emu.regs.get_ecx() - 1);
                }

                if emu.regs.get_ecx() > 0 && !emu.flags.f_zf {
                    if emu.cfg.is_64bits {
                        return emu.set_rip(addr, false);
                    } else {
                        return emu.set_eip(addr, false);
                    }
                }
            } else {
                if emu.regs.get_cx() == 0 {
                    emu.regs.set_cx(0xffff);
                } else {
                    emu.regs.set_cx(emu.regs.get_cx() - 1);
                }

                if emu.regs.get_cx() > 0 && !emu.flags.f_zf {
                    if emu.cfg.is_64bits {
                        return emu.set_rip(addr, false);
                    } else {
                        return emu.set_eip(addr, false);
                    }
                }
            }
        }

        Mnemonic::Lea => {
            emu.show_instruction(&emu.colors.light_cyan, ins);

            assert!(ins.op_count() == 2);

            let value1 = match emu.get_operand_value(ins, 1, false) {
                Some(v) => v,
                None => return false,
            };

            if !emu.set_operand_value(ins, 0, value1) {
                return false;
            }
        }

        Mnemonic::Leave => {
            emu.show_instruction(&emu.colors.red, ins);

            if emu.cfg.is_64bits {
                emu.regs.rsp = emu.regs.rbp;
                emu.regs.rbp = match emu.stack_pop64(true) {
                    Some(v) => v,
                    None => return false,
                };
            } else {
                emu.regs.set_esp(emu.regs.get_ebp());
                let val = match emu.stack_pop32(true) {
                    Some(v) => v as u64,
                    None => return false,
                };
                emu.regs.set_ebp(val);
            }
        }

        Mnemonic::Int => {
            emu.show_instruction(&emu.colors.red, ins);

            assert!(ins.op_count() == 1);

            let interrupt = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let handle_interrupts = match emu.hooks.hook_on_interrupt {
                Some(hook_fn) => hook_fn(emu, emu.regs.rip, interrupt),
                None => true,
            };

            if handle_interrupts {
                match interrupt {
                    0x80 => {
                        emu.linux = true;
                        syscall32::gateway(emu);
                    }

                    0x29 => {
                        log::info!("int 0x21: __fastfail {}", emu.regs.rcx);
                        std::process::exit(1);
                    }

                    0x03 => {
                        emu.show_instruction(&emu.colors.red, ins);
                        log::info!("/!\\ int 0x3 sigtrap!!!!");
                        emu.exception();
                        return false;
                    }

                    0xdc => {
                        log::info!("/!\\ direct syscall: NtAlpcSendWaitReceivePort");
                    }

                    _ => {
                        log::info!("unimplemented interrupt {}", interrupt);
                        return false;
                    }
                }
            }
        }

        Mnemonic::Syscall => {
            emu.show_instruction(&emu.colors.red, ins);

            syscall64::gateway(emu);
        }

        Mnemonic::Std => {
            emu.show_instruction(&emu.colors.blue, ins);
            emu.flags.f_df = true;
        }

        Mnemonic::Stc => {
            emu.show_instruction(&emu.colors.blue, ins);
            emu.flags.f_cf = true;
        }

        Mnemonic::Cmc => {
            emu.show_instruction(&emu.colors.blue, ins);
            emu.flags.f_cf = !emu.flags.f_cf;
        }

        Mnemonic::Cld => {
            emu.show_instruction(&emu.colors.blue, ins);
            emu.flags.f_df = false;
        }

        Mnemonic::Lodsq => {
            emu.show_instruction(&emu.colors.cyan, ins);
            //TODO: crash if arrive to zero or max value

            if emu.cfg.is_64bits {
                let val = match emu.maps.read_qword(emu.regs.rsi) {
                    Some(v) => v,
                    None => panic!("lodsq: memory read error"),
                };

                emu.regs.rax = val;
                if emu.flags.f_df {
                    emu.regs.rsi -= 8;
                } else {
                    emu.regs.rsi += 8;
                }
            } else {
                unreachable!("lodsq dont exists in 32bit");
            }
        }

        Mnemonic::Lodsd => {
            emu.show_instruction(&emu.colors.cyan, ins);
            //TODO: crash if arrive to zero or max value

            if emu.cfg.is_64bits {
                let val = match emu.maps.read_dword(emu.regs.rsi) {
                    Some(v) => v,
                    None => return false,
                };

                emu.regs.set_eax(val as u64);
                if emu.flags.f_df {
                    emu.regs.rsi -= 4;
                } else {
                    emu.regs.rsi += 4;
                }
            } else {
                let val = match emu.maps.read_dword(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => return false,
                };

                emu.regs.set_eax(val as u64);
                if emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() - 4);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() + 4);
                }
            }
        }

        Mnemonic::Lodsw => {
            emu.show_instruction(&emu.colors.cyan, ins);
            //TODO: crash if rsi arrive to zero or max value

            if emu.cfg.is_64bits {
                let val = match emu.maps.read_word(emu.regs.rsi) {
                    Some(v) => v,
                    None => return false,
                };

                emu.regs.set_ax(val as u64);
                if emu.flags.f_df {
                    emu.regs.rsi -= 2;
                } else {
                    emu.regs.rsi += 2;
                }
            } else {
                let val = match emu.maps.read_word(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => return false,
                };

                emu.regs.set_ax(val as u64);
                if emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() - 2);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() + 2);
                }
            }
        }

        Mnemonic::Lodsb => {
            emu.show_instruction(&emu.colors.cyan, ins);
            //TODO: crash if arrive to zero or max value

            if emu.cfg.is_64bits {
                let val = match emu.maps.read_byte(emu.regs.rsi) {
                    Some(v) => v,
                    None => {
                        log::info!("lodsb: memory read error");
                        Console::spawn_console(emu);
                        0
                    }
                };

                emu.regs.set_al(val as u64);
                if emu.flags.f_df {
                    emu.regs.rsi -= 1;
                } else {
                    emu.regs.rsi += 1;
                }
            } else {
                let val = match emu.maps.read_byte(emu.regs.get_esi()) {
                    Some(v) => v,
                    None => {
                        log::info!("lodsb: memory read error");
                        Console::spawn_console(emu);
                        0
                    }
                };

                emu.regs.set_al(val as u64);
                if emu.flags.f_df {
                    emu.regs.set_esi(emu.regs.get_esi() - 1);
                } else {
                    emu.regs.set_esi(emu.regs.get_esi() + 1);
                }
            }
        }

        Mnemonic::Cbw => {
            emu.show_instruction(&emu.colors.green, ins);

            let sigextend = emu.regs.get_al() as u8 as i8 as i16 as u16;
            emu.regs.set_ax(sigextend as u64);
        }

        Mnemonic::Cwde => {
            emu.show_instruction(&emu.colors.green, ins);

            let sigextend = emu.regs.get_ax() as u16 as i16 as i32 as u32;

            emu.regs.set_eax(sigextend as u64);
        }

        Mnemonic::Cwd => {
            emu.show_instruction(&emu.colors.green, ins);

            let sigextend = emu.regs.get_ax() as u16 as i16 as i32 as u32;
            emu.regs.set_ax((sigextend & 0x0000ffff) as u64);
            emu.regs.set_dx(((sigextend & 0xffff0000) >> 16) as u64);
        }

        ///// FPU /////  https://github.com/radare/radare/blob/master/doc/xtra/fpu
        Mnemonic::Fninit => {
            emu.fpu.clear();
        }

        Mnemonic::Finit => {
            emu.fpu.clear();
        }

        Mnemonic::Ffree => {
            emu.show_instruction(&emu.colors.green, ins);

            match ins.op_register(0) {
                Register::ST0 => emu.fpu.clear_st(0),
                Register::ST1 => emu.fpu.clear_st(1),
                Register::ST2 => emu.fpu.clear_st(2),
                Register::ST3 => emu.fpu.clear_st(3),
                Register::ST4 => emu.fpu.clear_st(4),
                Register::ST5 => emu.fpu.clear_st(5),
                Register::ST6 => emu.fpu.clear_st(6),
                Register::ST7 => emu.fpu.clear_st(7),
                _ => unimplemented!("impossible case"),
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fbld => {
            emu.show_instruction(&emu.colors.green, ins);

            let value = match emu.get_operand_value(ins, 0, false) {
                Some(v) => v as u16,
                None => return false,
            };

            //log::info!("{} {}", value, value as f32);
            emu.fpu.set_st(0, value as f64);
        }

        Mnemonic::Fldcw => {
            emu.show_instruction(&emu.colors.green, ins);

            let value = match emu.get_operand_value(ins, 0, false) {
                Some(v) => v as u16,
                None => return false,
            };

            emu.fpu.set_ctrl(value);
        }

        Mnemonic::Fnstenv => {
            emu.show_instruction(&emu.colors.green, ins);

            let addr = match emu.get_operand_value(ins, 0, false) {
                Some(v) => v,
                None => return false,
            };

            if emu.cfg.is_64bits {
                let env = emu.fpu.get_env64();

                for i in 0..4 {
                    emu.maps.write_qword(addr + (i * 4), env[i as usize]);
                }
            } else {
                let env = emu.fpu.get_env32();
                for i in 0..4 {
                    emu.maps.write_dword(addr + (i * 4), env[i as usize]);
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fld => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fldz => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(0.0);
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fld1 => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(1.0);
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fldpi => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(std::f64::consts::PI);
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fldl2t => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(10f64.log2());
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fldlg2 => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(2f64.log10());
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fldln2 => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(2f64.log(std::f64::consts::E));
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fldl2e => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.push(std::f64::consts::E.log2());
            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fst => {
            emu.show_instruction(&emu.colors.green, ins);

            let res = emu.fpu.get_st(0) as u64;

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }
        }

        Mnemonic::Fsubrp => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let st1 = emu.fpu.get_st(1);
            let result = st1 - st0;

            emu.fpu.set_st(1, result);
            emu.fpu.pop();
        }

        Mnemonic::Fstp => {
            emu.show_instruction(&emu.colors.green, ins);

            let res = emu.fpu.get_st(0) as u64;

            if !emu.set_operand_value(ins, 0, res) {
                return false;
            }

            emu.fpu.pop();
        }

        Mnemonic::Fincstp => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.f_c1 = false;
            emu.fpu.inc_top();
        }

        Mnemonic::Fild => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.dec_top();

            //C1  Set to 1 if stack overflow occurred; set to 0 otherwise.

            //log::info!("operands: {}", ins.op_count());
            let value1 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v as i64 as f64,
                None => return false,
            };

            emu.fpu.set_st(0, value1);
        }

        Mnemonic::Fist => {
            emu.show_instruction(&emu.colors.green, ins);

            let value = emu.fpu.get_st(0) as i64;
            let value2 = match emu.get_operand_sz(ins, 0) {
                16 => value as i16 as u16 as u64,
                32 => value as i32 as u32 as u64,
                64 => value as u64,
                _ => return false,
            };
            emu.set_operand_value(ins, 0, value2);
        }

        Mnemonic::Fxtract => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);
            let (mantissa, exponent) = emu.fpu.frexp(st0);
            emu.fpu.set_st(0, mantissa);
            emu.fpu.push(exponent as f64);
        }

        Mnemonic::Fxsave => {
            emu.show_instruction(&emu.colors.green, ins);

            let addr = match emu.get_operand_value(ins, 0, false) {
                Some(v) => v,
                None => return false,
            };

            let state = emu.fpu.fxsave();
            state.save(addr, emu);
        }

        Mnemonic::Fistp => {
            emu.show_instruction(&emu.colors.green, ins);

            let value = emu.fpu.get_st(0) as i64;
            let value2 = match emu.get_operand_sz(ins, 0) {
                16 => value as i16 as u16 as u64,
                32 => value as i32 as u32 as u64,
                64 => value as u64,
                _ => return false,
            };
            if !emu.set_operand_value(ins, 0, value2) {
                return false;
            }

            emu.fpu.pop();
            emu.fpu.set_st(0, 0.0);
            emu.fpu.inc_top();
        }

        Mnemonic::Fcmove => {
            emu.show_instruction(&emu.colors.green, ins);

            if emu.flags.f_zf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovb => {
            emu.show_instruction(&emu.colors.green, ins);

            if emu.flags.f_cf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovbe => {
            emu.show_instruction(&emu.colors.green, ins);

            if emu.flags.f_cf || emu.flags.f_zf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovu => {
            emu.show_instruction(&emu.colors.green, ins);

            if emu.flags.f_pf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovnb => {
            emu.show_instruction(&emu.colors.green, ins);

            if !emu.flags.f_cf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovne => {
            emu.show_instruction(&emu.colors.green, ins);

            if !emu.flags.f_zf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovnbe => {
            emu.show_instruction(&emu.colors.green, ins);

            if !emu.flags.f_cf && !emu.flags.f_zf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fcmovnu => {
            emu.show_instruction(&emu.colors.green, ins);

            if !emu.flags.f_pf {
                match ins.op_register(0) {
                    Register::ST0 => emu.fpu.move_to_st0(0),
                    Register::ST1 => emu.fpu.move_to_st0(1),
                    Register::ST2 => emu.fpu.move_to_st0(2),
                    Register::ST3 => emu.fpu.move_to_st0(3),
                    Register::ST4 => emu.fpu.move_to_st0(4),
                    Register::ST5 => emu.fpu.move_to_st0(5),
                    Register::ST6 => emu.fpu.move_to_st0(6),
                    Register::ST7 => emu.fpu.move_to_st0(7),
                    _ => unimplemented!("impossible case"),
                }
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fxch => {
            emu.show_instruction(&emu.colors.blue, ins);
            match ins.op_register(1) {
                Register::ST0 => emu.fpu.xchg_st(0),
                Register::ST1 => emu.fpu.xchg_st(1),
                Register::ST2 => emu.fpu.xchg_st(2),
                Register::ST3 => emu.fpu.xchg_st(3),
                Register::ST4 => emu.fpu.xchg_st(4),
                Register::ST5 => emu.fpu.xchg_st(5),
                Register::ST6 => emu.fpu.xchg_st(6),
                Register::ST7 => emu.fpu.xchg_st(7),
                _ => unimplemented!("impossible case"),
            }

            emu.fpu.set_ip(emu.regs.rip);
        }

        Mnemonic::Fsqrt => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);

            emu.fpu.set_st(0, st0.sqrt());
        }

        Mnemonic::Fchs => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);

            emu.fpu.set_st(0, st0 * -1f64);
            emu.fpu.f_c0 = false;
        }

        Mnemonic::Fptan => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);

            emu.fpu.set_st(0, st0.tan());
            emu.fpu.push(1.0);
        }

        Mnemonic::Fmulp => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0) as usize;
            let value1 = emu.get_operand_value(ins, 1, false).unwrap_or(0) as usize;
            let result = emu.fpu.get_st(value1) * emu.fpu.get_st(value0);

            emu.fpu.set_st(value1, result);
            emu.fpu.pop();
        }

        Mnemonic::Fdivp => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0) as usize;
            let value1 = emu.get_operand_value(ins, 1, false).unwrap_or(0) as usize;
            let result = emu.fpu.get_st(value1) / emu.fpu.get_st(value0);

            emu.fpu.set_st(value1, result);
            emu.fpu.pop();
        }

        Mnemonic::Fsubp => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0) as usize;
            let value1 = 0;
            let result = emu.fpu.get_st(value0) - emu.fpu.get_st(value1);

            emu.fpu.set_st(value0, result);
            emu.fpu.pop();
        }

        Mnemonic::Fsubr => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0) as usize;
            let value1 = emu.get_operand_value(ins, 1, false).unwrap_or(0) as usize;
            let result = emu.fpu.get_st(value1) - emu.fpu.get_st(value0);

            emu.fpu.set_st(value1, result);
        }

        Mnemonic::Fsub => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0);
            let value1 = emu.get_operand_value(ins, 1, false).unwrap_or(0);
            let stA = emu.fpu.get_st(value0 as usize);
            let stB = emu.fpu.get_st(value1 as usize);
            emu.fpu.set_st(value0 as usize, stA - stB);
        }

        Mnemonic::Fadd => {
            emu.show_instruction(&emu.colors.green, ins);
            //assert!(ins.op_count() == 2); there are with 1 operand

            if ins.op_register(0) == Register::ST0 {
                match ins.op_register(1) {
                    Register::ST0 => emu.fpu.add_to_st0(0),
                    Register::ST1 => emu.fpu.add_to_st0(1),
                    Register::ST2 => emu.fpu.add_to_st0(2),
                    Register::ST3 => emu.fpu.add_to_st0(3),
                    Register::ST4 => emu.fpu.add_to_st0(4),
                    Register::ST5 => emu.fpu.add_to_st0(5),
                    Register::ST6 => emu.fpu.add_to_st0(6),
                    Register::ST7 => emu.fpu.add_to_st0(7),
                    _ => emu.fpu.add_to_st0(0),
                }
            } else {
                let i = match ins.op_register(0) {
                    Register::ST0 => 0,
                    Register::ST1 => 1,
                    Register::ST2 => 2,
                    Register::ST3 => 3,
                    Register::ST4 => 4,
                    Register::ST5 => 5,
                    Register::ST6 => 6,
                    Register::ST7 => 7,
                    _ => 0,
                };

                let j = match ins.op_register(1) {
                    Register::ST0 => 0,
                    Register::ST1 => 1,
                    Register::ST2 => 2,
                    Register::ST3 => 3,
                    Register::ST4 => 4,
                    Register::ST5 => 5,
                    Register::ST6 => 6,
                    Register::ST7 => 7,
                    _ => 0,
                };

                emu.fpu.add(i, j);
            }
        }

        Mnemonic::Fucom => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);
            let st1 = emu.fpu.get_st(1);
            emu.fpu.f_c0 = st0 < st1;
            emu.fpu.f_c2 = st0.is_nan() || st1.is_nan();
            emu.fpu.f_c3 = st0 == st1;
        }

        Mnemonic::F2xm1 => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let result = (2.0f64.powf(st0)) - 1.0;
            emu.fpu.set_st(0, result);
        }

        Mnemonic::Fyl2x => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.fyl2x();
        }

        Mnemonic::Fyl2xp1 => {
            emu.show_instruction(&emu.colors.green, ins);

            emu.fpu.fyl2xp1();
        }

        // end fpu
        Mnemonic::Popf => {
            emu.show_instruction(&emu.colors.blue, ins);

            let flags: u16 = match emu.maps.read_word(emu.regs.rsp) {
                Some(v) => v,
                None => {
                    log::error!("popf cannot read the stack");
                    emu.exception();
                    return false;
                }
            };

            let flags2: u32 = (emu.flags.dump() & 0xffff0000) + (flags as u32);
            emu.flags.load(flags2);
            emu.regs.rsp += 2;
        }

        Mnemonic::Popfd => {
            emu.show_instruction(&emu.colors.blue, ins);

            let flags = match emu.stack_pop32(true) {
                Some(v) => v,
                None => return false,
            };
            emu.flags.load(flags);
        }

        Mnemonic::Popfq => {
            emu.show_instruction(&emu.colors.blue, ins);

            let eflags = match emu.stack_pop64(true) {
                Some(v) => v as u32,
                None => return false,
            };
            emu.flags.load(eflags);
        }

        Mnemonic::Daa => {
            emu.show_instruction(&emu.colors.green, ins);

            let old_al = emu.regs.get_al();
            let old_cf = emu.flags.f_cf;
            emu.flags.f_cf = false;

            if (emu.regs.get_al() & 0x0f > 9) || emu.flags.f_af {
                let sum = emu.regs.get_al() + 6;
                emu.regs.set_al(sum & 0xff);
                if sum > 0xff {
                    emu.flags.f_cf = true;
                } else {
                    emu.flags.f_cf = old_cf;
                }

                emu.flags.f_af = true;
            } else {
                emu.flags.f_af = false;
            }

            if old_al > 0x99 || old_cf {
                emu.regs.set_al(emu.regs.get_al() + 0x60);
                emu.flags.f_cf = true;
            } else {
                emu.flags.f_cf = false;
            }
        }

        Mnemonic::Shld => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let counter = match emu.get_operand_value(ins, 2, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);

            if value0 == 0xde2f && value1 == 0x4239 && counter == 0x3c && sz == 16 {
                if emu.cfg.verbose >= 1 {
                    log::info!("/!\\ shld undefined behaviour");
                }
                let result = 0x9de2;
                // TODO: flags?
                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            } else {
                let (result, new_flags) =
                    inline::shld(value0, value1, counter, sz, emu.flags.dump());
                emu.flags.load(new_flags);
                if !emu.set_operand_value(ins, 0, result) {
                    return false;
                }
            }
        }

        Mnemonic::Shrd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let counter = match emu.get_operand_value(ins, 2, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0);
            let (result, new_flags) =
                inline::shrd(value0, value1, counter, sz, emu.flags.dump());
            emu.flags.load(new_flags);

            //log::info!("0x{:x} SHRD 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, counter, result);
            /*
            if emu.cfg.test_mode { //&& !undef {
                if result != inline::shrd(value0, value1, counter, sz) {
                    panic!("SHRD{} 0x{:x} should be 0x{:x}", sz, result, inline::shrd(value0, value1, counter, sz));
                }
            }*/

            if !emu.set_operand_value(ins, 0, result) {
                return false;
            }
        }

        Mnemonic::Sysenter => {
            if emu.cfg.is_64bits {
                unimplemented!("ntapi64 not implemented yet");
            } else {
                ntapi32::gateway(emu.regs.get_eax(), emu.regs.get_edx(), emu);
            }
        }

        //// SSE XMM ////
        // scalar: only gets the less significative part.
        // scalar simple: only 32b less significative part.
        // scalar double: only 54b less significative part.
        // packed: compute all parts.
        // packed double
        Mnemonic::Pcmpeqd => {
            emu.show_instruction(&emu.colors.green, ins);
            if emu.get_operand_sz(ins, 0) != 128 || emu.get_operand_sz(ins, 1) != 128 {
                log::info!("unimplemented");
                return false;
            }

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..4 {
                let mask = 0xFFFFFFFFu128;
                let shift = i * 32;

                let dword0 = (value0 >> shift) & mask;
                let dword1 = (value1 >> shift) & mask;

                if dword0 == dword1 {
                    result |= mask << shift;
                }
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psubusb => {
            emu.show_instruction(&emu.colors.green, ins);
            if emu.get_operand_sz(ins, 0) != 128 || emu.get_operand_sz(ins, 1) != 128 {
                log::info!("unimplemented");
                return false;
            }

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;
            for i in 0..16 {
                let byte0 = ((value0 >> (i * 8)) & 0xFF) as u8;
                let byte1 = ((value1 >> (i * 8)) & 0xFF) as u8;
                let res_byte = byte0.saturating_sub(byte1);

                result |= (res_byte as u128) << (i * 8);
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Punpckhbw => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let bytes0 = value0.to_le_bytes();
            let bytes1 = value1.to_le_bytes();

            let mut result_bytes = [0u8; 16];
            result_bytes[0] = bytes0[8];
            result_bytes[1] = bytes1[8];
            result_bytes[2] = bytes0[9];
            result_bytes[3] = bytes1[9];
            result_bytes[4] = bytes0[10];
            result_bytes[5] = bytes1[10];
            result_bytes[6] = bytes0[11];
            result_bytes[7] = bytes1[11];
            result_bytes[8] = bytes0[12];
            result_bytes[9] = bytes1[12];
            result_bytes[10] = bytes0[13];
            result_bytes[11] = bytes1[13];
            result_bytes[12] = bytes0[14];
            result_bytes[13] = bytes1[14];
            result_bytes[14] = bytes0[15];
            result_bytes[15] = bytes1[15];

            let result = u128::from_le_bytes(result_bytes);
            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pand => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let result: u128 = value0 & value1;
            emu.flags.calc_flags(result as u64, 32);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Por => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let result: u128 = value0 | value1;
            emu.flags.calc_flags(result as u64, 32);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pxor => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let result: u128 = value0 ^ value1;
            emu.flags.calc_flags(result as u64, 32);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Punpcklbw => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);
            let sz0 = emu.get_operand_sz(ins, 0);
            if sz0 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value0");
                        return false;
                    }
                };
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let mut result: u128 = 0;
                let mask_byte = 0xff;

                for i in 0..8 {
                    let byte_value0 = (value0 >> (8 * i)) & mask_byte;
                    let byte_value1 = (value1 >> (8 * i)) & mask_byte;

                    result |= byte_value0 << (16 * i);
                    result |= byte_value1 << (16 * i + 8);
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!("unimplemented size");
            }
        }

        Mnemonic::Punpcklwd => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);
            let sz0 = emu.get_operand_sz(ins, 0);
            if sz0 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value0");
                        return false;
                    }
                };
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let mut result = 0u128;
                for i in 0..2 {
                    let word_value0 = (value0 >> (i * 16)) & 0xFFFF;
                    let word_value1 = (value1 >> (i * 16)) & 0xFFFF;
                    result |= word_value0 << (i * 32);
                    result |= word_value1 << (i * 32 + 16);
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!("unimplemented size");
            }
        }

        Mnemonic::Xorps => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff) ^ (value1 & 0xffffffff);
            let b: u128 = (value0 & 0xffffffff_00000000) ^ (value1 & 0xffffffff_00000000);
            let c: u128 = (value0 & 0xffffffff_00000000_00000000)
                ^ (value1 & 0xffffffff_00000000_00000000);
            let d: u128 = (value0 & 0xffffffff_00000000_00000000_00000000)
                ^ (value1 & 0xffffffff_00000000_00000000_00000000);

            let result: u128 = a | b | c | d;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Xorpd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff_ffffffff) ^ (value1 & 0xffffffff_ffffffff);
            let b: u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000)
                ^ (value1 & 0xffffffff_ffffffff_00000000_00000000);
            let result: u128 = a | b;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        /*            Mnemonic::Psubb
        | Mnemonic::Psubw
        | Mnemonic::Psubd
        | Mnemonic::Psubq
        | Mnemonic::Psubsb
        | Mnemonic::Psubsw
        | Mnemonic::Psubusb
        | Mnemonic::Psubusw => {*/
        Mnemonic::Psubb => {
            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let mut result = 0u128;
                for i in 0..16 {
                    let byte0 = (value0 >> (8 * i)) & 0xFF;
                    let byte1 = (value1 >> (8 * i)) & 0xFF;
                    let res_byte = byte0.wrapping_sub(byte1);
                    result |= res_byte << (8 * i);
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!();
            }
        }

        Mnemonic::Psubw => {
            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let mut result = 0u128;
                for i in 0..8 {
                    let word0 = (value0 >> (16 * i)) & 0xFFFF;
                    let word1 = (value1 >> (16 * i)) & 0xFFFF;
                    let res_word = word0.wrapping_sub(word1);
                    result |= res_word << (16 * i);
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!();
            }
        }

        Mnemonic::Psubd => {
            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let mut result = 0u128;
                for i in 0..4 {
                    let dword0 = (value0 >> (32 * i)) & 0xFFFFFFFF;
                    let dword1 = (value1 >> (32 * i)) & 0xFFFFFFFF;
                    let res_dword = dword0.wrapping_sub(dword1);
                    result |= res_dword << (32 * i);
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!();
            }
        }

        Mnemonic::Psubq => {
            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let mut result = 0u128;
                for i in 0..2 {
                    let qword0 = (value0 >> (64 * i)) & 0xFFFFFFFFFFFFFFFF;
                    let qword1 = (value1 >> (64 * i)) & 0xFFFFFFFFFFFFFFFF;
                    let res_qword = qword0.wrapping_sub(qword1);
                    result |= res_qword << (64 * i);
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!();
            }
        }

        // movlpd: packed double, movlps: packed simple, cvtsi2sd: int to scalar double 32b to 64b,
        // cvtsi2ss: int to scalar single copy 32b to 32b, movd: doubleword move
        Mnemonic::Movhpd => {
            // we keep the high part of xmm destination

            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_xmm_value_128(ins, 0, value1);
            } else if sz0 == 128 && sz1 == 32 {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                unimplemented!("mov 32bits to the 64bits highest part of the xmm1 u128");
                //emu.set_operand_xmm_value_128(&ins, 0, value1 as u128);
            } else if sz0 == 32 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                unimplemented!("mov 32bits to the 64bits highest part of the xmm1 u128");
                //emu.set_operand_value(&ins, 0, value1 as u64);
            } else if sz0 == 128 && sz1 == 64 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm address value1");
                        return false;
                    }
                };
                let addr = match emu.get_operand_value(ins, 1, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm address value1");
                        return false;
                    }
                };
                let value1 = match emu.maps.read_qword(addr) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm qword value1");
                        return false;
                    }
                };

                let result: u128 = (value1 as u128) << 64 | value0 & 0xffffffffffffffff;

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else if sz0 == 64 && sz1 == 128 {
                let mut value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                value1 >>= 64;

                emu.set_operand_value(ins, 0, value1 as u64);
            } else {
                log::info!("SSE with other size combinations sz0:{} sz1:{}", sz0, sz1);
                return false;
            }
        }

        Mnemonic::Movlpd | Mnemonic::Movlps | Mnemonic::Cvtsi2sd | Mnemonic::Cvtsi2ss => {
            // we keep the high part of xmm destination

            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_xmm_value_128(ins, 0, value1);
            } else if sz0 == 128 && sz1 == 32 {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_xmm_value_128(ins, 0, value1 as u128);
            } else if sz0 == 32 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_value(ins, 0, value1 as u64);
            } else if sz0 == 128 && sz1 == 64 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm address value1");
                        return false;
                    }
                };
                let addr = match emu.get_operand_value(ins, 1, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm address value1");
                        return false;
                    }
                };
                let value1 = match emu.maps.read_qword(addr) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm qword value1");
                        return false;
                    }
                };

                let mask: u128 = 0xFFFFFFFFFFFFFFFF_0000000000000000;
                let result: u128 = (value0 & mask) | (value1 as u128);

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else if sz0 == 64 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_value(ins, 0, value1 as u64);
            } else {
                log::info!("SSE with other size combinations sz0:{} sz1:{}", sz0, sz1);
                return false;
            }
        }

        Mnemonic::Movhps => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 64 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value0");
                        return false;
                    }
                };

                let value1 = match emu.get_operand_value(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting value1");
                        return false;
                    }
                };

                let lower_value0 = value0 & 0x00000000_FFFFFFFF_00000000_FFFFFFFF;
                let upper_value1 = (value1 as u128) << 64;
                let result = lower_value0 | upper_value1;

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else if sz0 == 64 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                let result = (value1 >> 64) as u64;

                emu.set_operand_value(ins, 0, result);
            } else if sz0 == 128 && sz1 == 32 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value0");
                        return false;
                    }
                };

                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => (v & 0xffffffff) as u32,
                    None => {
                        log::info!("error getting value1");
                        return false;
                    }
                };

                let lower_value0 = value0 & 0x00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF;
                let upper_value1 = (value1 as u128) << 96;
                let result = lower_value0 | upper_value1;

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                unimplemented!("case of movhps unimplemented {} {}", sz0, sz1);
            }
        }

        Mnemonic::Punpcklqdq => {
            emu.show_instruction(&emu.colors.green, ins);
            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value0");
                        return false;
                    }
                };

                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => (v & 0xffffffff) as u32,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                let value0_low_qword = value0 as u64;
                let value1_low_qword = value1 as u64;
                let result = ((value0_low_qword as u128) << 64) | (value1_low_qword as u128);

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                log::info!("unimplemented case punpcklqdq {} {}", sz0, sz1);
                return false;
            }
        }

        Mnemonic::Movq => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);
            let value1: u128;

            if sz1 == 128 {
                value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
            } else if sz1 < 128 {
                value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v as u128,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
            } else {
                unimplemented!("ymm zmm unimplemented on movq");
            }

            if sz0 == 128 {
                emu.set_operand_xmm_value_128(ins, 0, value1);
            } else if sz0 < 128 {
                emu.set_operand_value(ins, 0, value1 as u64);
            } else {
                unimplemented!("ymm zmm unimplemented on movq");
            }
        }

        Mnemonic::Punpckhdq => {
            emu.show_instruction(&emu.colors.cyan, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let dword0_0 = (value0 >> 96) as u32;
            let dword0_1 = (value0 >> 64) as u32;
            let dword1_0 = (value1 >> 96) as u32;
            let dword1_1 = (value1 >> 64) as u32;

            let result: u128 = ((dword0_0 as u128) << 96)
                | ((dword1_0 as u128) << 64)
                | ((dword0_1 as u128) << 32)
                | (dword1_1 as u128);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Punpckldq => {
            emu.show_instruction(&emu.colors.cyan, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting xmm value1");
                    return false;
                }
            };

            let dword0_0 = (value0 & 0xFFFFFFFF) as u32;
            let dword0_1 = ((value0 >> 32) & 0xFFFFFFFF) as u32;
            let dword1_0 = (value1 & 0xFFFFFFFF) as u32;
            let dword1_1 = ((value1 >> 32) & 0xFFFFFFFF) as u32;

            let result: u128 = ((dword0_0 as u128) << 96)
                | ((dword1_0 as u128) << 64)
                | ((dword0_1 as u128) << 32)
                | (dword1_1 as u128);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Movd => {
            // the high part is cleared to zero

            emu.show_instruction(&emu.colors.cyan, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 128 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_xmm_value_128(ins, 0, value1);
            } else if sz0 == 128 && sz1 == 32 {
                let value1 = match emu.get_operand_value(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_xmm_value_128(ins, 0, value1 as u128);
            } else if sz0 == 32 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_value(ins, 0, value1 as u64);
            } else if sz0 == 128 && sz1 == 64 {
                let addr = match emu.get_operand_value(ins, 1, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm address value1");
                        return false;
                    }
                };
                let value1 = match emu.maps.read_qword(addr) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm qword value1");
                        return false;
                    }
                };

                emu.set_operand_xmm_value_128(ins, 0, value1 as u128);
            } else if sz0 == 64 && sz1 == 128 {
                let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                emu.set_operand_value(ins, 0, value1 as u64);
            } else {
                log::info!("SSE with other size combinations sz0:{} sz1:{}", sz0, sz1);
                return false;
            }
        }

        Mnemonic::Movdqa => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);

            if sz0 == 32 && sz1 == 128 {
                let xmm = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };
                let addr = match emu.get_operand_value(ins, 0, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting address value0");
                        return false;
                    }
                };
                //log::info!("addr: 0x{:x} value: 0x{:x}", addr, xmm);
                emu.maps.write_dword(
                    addr,
                    ((xmm & 0xffffffff_00000000_00000000_00000000) >> (12 * 8)) as u32,
                );
                emu.maps.write_dword(
                    addr + 4,
                    ((xmm & 0xffffffff_00000000_00000000) >> (8 * 8)) as u32,
                );
                emu.maps
                    .write_dword(addr + 8, ((xmm & 0xffffffff_00000000) >> (4 * 8)) as u32);
                emu.maps.write_dword(addr + 12, (xmm & 0xffffffff) as u32);
            } else if sz0 == 128 && sz1 == 32 {
                let addr = match emu.get_operand_value(ins, 1, false) {
                    Some(v) => v,
                    None => {
                        log::info!("error reading address value1");
                        return false;
                    }
                };

                let bytes = emu.maps.read_bytes(addr, 16);
                if bytes.len() != 16 {
                    log::info!("error reading 16 bytes");
                    return false;
                }

                let result = u128::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                    bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
                    bytes[14], bytes[15],
                ]);

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else if sz0 == 128 && sz1 == 128 {
                let xmm = match emu.get_operand_xmm_value_128(ins, 1, true) {
                    Some(v) => v,
                    None => {
                        log::info!("error getting xmm value1");
                        return false;
                    }
                };

                emu.set_operand_xmm_value_128(ins, 0, xmm);
            } else {
                log::info!("sz0: {}  sz1: {}\n", sz0, sz1);
                unimplemented!("movdqa");
            }
        }

        Mnemonic::Andpd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u128 = value0 & value1;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Orpd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u128 = value0 | value1;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Addps => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff) + (value1 & 0xffffffff);
            let b: u128 = (value0 & 0xffffffff_00000000) + (value1 & 0xffffffff_00000000);
            let c: u128 = (value0 & 0xffffffff_00000000_00000000)
                + (value1 & 0xffffffff_00000000_00000000);
            let d: u128 = (value0 & 0xffffffff_00000000_00000000_00000000)
                + (value1 & 0xffffffff_00000000_00000000_00000000);

            let result: u128 = a | b | c | d;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Addpd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff_ffffffff) + (value1 & 0xffffffff_ffffffff);
            let b: u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000)
                + (value1 & 0xffffffff_ffffffff_00000000_00000000);
            let result: u128 = a | b;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Addsd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u64 = value0 as u64 + value1 as u64;
            let r128: u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128;
            emu.set_operand_xmm_value_128(ins, 0, r128);
        }

        Mnemonic::Addss => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u32 = value0 as u32 + value1 as u32;
            let r128: u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128;
            emu.set_operand_xmm_value_128(ins, 0, r128);
        }

        Mnemonic::Subps => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff) - (value1 & 0xffffffff);
            let b: u128 = (value0 & 0xffffffff_00000000) - (value1 & 0xffffffff_00000000);
            let c: u128 = (value0 & 0xffffffff_00000000_00000000)
                - (value1 & 0xffffffff_00000000_00000000);
            let d: u128 = (value0 & 0xffffffff_00000000_00000000_00000000)
                - (value1 & 0xffffffff_00000000_00000000_00000000);

            let result: u128 = a | b | c | d;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Subpd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff_ffffffff) - (value1 & 0xffffffff_ffffffff);
            let b: u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000)
                - (value1 & 0xffffffff_ffffffff_00000000_00000000);
            let result: u128 = a | b;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Subsd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u64 = value0 as u64 - value1 as u64;
            let r128: u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128;
            emu.set_operand_xmm_value_128(ins, 0, r128);
        }

        Mnemonic::Subss => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u32 = value0 as u32 - value1 as u32;
            let r128: u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128;
            emu.set_operand_xmm_value_128(ins, 0, r128);
        }

        Mnemonic::Mulpd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let left: u128 = ((value0 & 0xffffffffffffffff0000000000000000) >> 64)
                * ((value1 & 0xffffffffffffffff0000000000000000) >> 64);
            let right: u128 = (value0 & 0xffffffffffffffff) * (value1 & 0xffffffffffffffff);
            let result: u128 = left << 64 | right;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Mulps => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let a: u128 = (value0 & 0xffffffff) * (value1 & 0xffffffff);
            let b: u128 = (value0 & 0xffffffff00000000) * (value1 & 0xffffffff00000000);
            let c: u128 =
                (value0 & 0xffffffff0000000000000000) * (value1 & 0xffffffff0000000000000000);
            let d: u128 = (value0 & 0xffffffff000000000000000000000000)
                * (value1 & 0xffffffff000000000000000000000000);

            let result: u128 = a | b | c | d;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Mulsd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u64 = value0 as u64 * value1 as u64;
            let r128: u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128;
            emu.set_operand_xmm_value_128(ins, 0, r128);
        }

        Mnemonic::Mulss => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };

            let result: u32 = value0 as u32 * value1 as u32;
            let r128: u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128;
            emu.set_operand_xmm_value_128(ins, 0, r128);
        }

        Mnemonic::Packsswb => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };
            let mut result: u128;

            result = (value0 & 0xffff) as u16 as i16 as i8 as u8 as u128;
            result |= (((value0 & 0xffff0000) >> 16) as u16 as i16 as i8 as u8 as u128) << 8;
            result |=
                (((value0 & 0xffff00000000) >> 32) as u16 as i16 as i8 as u8 as u128) << 16;
            result |=
                (((value0 & 0xffff000000000000) >> 48) as u16 as i16 as i8 as u8 as u128) << 24;
            result |= (((value0 & 0xffff0000000000000000) >> 64) as u16 as i16 as i8 as u8
                as u128)
                << 32;
            result |= (((value0 & 0xffff00000000000000000000) >> 80) as u16 as i16 as i8 as u8
                as u128)
                << 40;
            result |= (((value0 & 0xffff000000000000000000000000) >> 96) as u16 as i16 as i8
                as u8 as u128)
                << 48;
            result |= (((value0 & 0xffff0000000000000000000000000000) >> 112) as u16 as i16
                as i8 as u8 as u128)
                << 56;
            result |= ((value1 & 0xffff) as u16 as i16 as i8 as u8 as u128) << 64;
            result |= (((value1 & 0xffff0000) >> 16) as u16 as i16 as i8 as u8 as u128) << 72;
            result |=
                (((value1 & 0xffff00000000) >> 32) as u16 as i16 as i8 as u8 as u128) << 80;
            result |=
                (((value1 & 0xffff000000000000) >> 48) as u16 as i16 as i8 as u8 as u128) << 88;
            result |= (((value1 & 0xffff0000000000000000) >> 64) as u16 as i16 as i8 as u8
                as u128)
                << 96;
            result |= (((value1 & 0xffff00000000000000000000) >> 80) as u16 as i16 as i8 as u8
                as u128)
                << 104;
            result |= (((value1 & 0xffff000000000000000000000000) >> 96) as u16 as i16 as i8
                as u8 as u128)
                << 112;
            result |= (((value1 & 0xffff0000000000000000000000000000) >> 112) as u16 as i16
                as i8 as u8 as u128)
                << 120;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Packssdw => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };
            let mut result: u128;

            result = (value0 & 0xffffffff) as u32 as i32 as i16 as u16 as u128;
            result |= (((value0 & 0xffffffff00000000) >> 32) as u32 as i32 as i16 as u16
                as u128)
                << 16;
            result |= (((value0 & 0xffffffff0000000000000000) >> 64) as u32 as i32 as i16 as u16
                as u128)
                << 32;
            result |= (((value0 & 0xffffffff000000000000000000000000) >> 96) as u32 as i32
                as i16 as u16 as u128)
                << 48;
            result |= ((value1 & 0xffffffff) as u32 as i32 as i16 as u16 as u128) << 64;
            result |= (((value1 & 0xffffffff00000000) >> 32) as u32 as i32 as i16 as u16
                as u128)
                << 80;
            result |= (((value1 & 0xffffffff0000000000000000) >> 64) as u32 as i32 as i16 as u16
                as u128)
                << 96;
            result |= (((value1 & 0xffffffff000000000000000000000000) >> 96) as u32 as i32
                as i16 as u16 as u128)
                << 112;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psrldq => {
            emu.show_instruction(&emu.colors.green, ins);

            if ins.op_count() == 2 {
                let sz0 = emu.get_operand_sz(ins, 0);

                if sz0 == 128 {
                    let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error getting value0");
                            return false;
                        }
                    };
                    let mut value1 = match emu.get_operand_value(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error getting value1");
                            return false;
                        }
                    };

                    if value1 > 15 {
                        value1 = 16;
                    }

                    let result: u128 = value0 >> (value1 * 8);

                    emu.set_operand_xmm_value_128(ins, 0, result);
                } else {
                    unimplemented!("size unimplemented");
                }
            } else if ins.op_count() == 3 {
                let sz0 = emu.get_operand_sz(ins, 0);

                if sz0 == 128 {
                    let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error getting value0");
                            return false;
                        }
                    };
                    let mut value2 = match emu.get_operand_value(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error getting value1");
                            return false;
                        }
                    };

                    if value2 > 15 {
                        value2 = 16;
                    }

                    let result: u128 = value1 >> (value2 * 8);

                    emu.set_operand_xmm_value_128(ins, 0, result);
                } else {
                    unimplemented!("size unimplemented");
                }
            } else {
                unreachable!();
            }
        }

        Mnemonic::Pslld => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let shift_amount = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0) as u32;

            let mut result = 0u128;

            for i in 0..4 {
                let mask = 0xFFFFFFFFu128;
                let shift = i * 32;

                let dword = ((value0 >> shift) & mask) as u32;
                let shifted = dword.wrapping_shl(shift_amount);

                result |= (shifted as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pslldq => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let shift_amount = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0) as u32;
            let byte_shift = (shift_amount % 16) * 8; // Desplazamiento en bits

            let result = if byte_shift < 128 {
                value0 << byte_shift
            } else {
                0u128
            };

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psllq => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let shift_amount = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0) as u32;

            let mut result = 0u128;

            for i in 0..2 {
                let mask = 0xFFFFFFFFFFFFFFFFu128;
                let shift = i * 64;

                let qword = ((value0 >> shift) & mask) as u64;
                let shifted = qword.wrapping_shl(shift_amount);

                result |= (shifted as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psllw => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };
            let mut result: u128;

            if value1 > 15 {
                result = value0 & 0xffffffffffffffff_0000000000000000;
            } else {
                result = (((value0 & 0xffff) as u16) << value1) as u128;
                result |= (((((value0 & 0xffff0000) >> 16) as u16) << value1) as u128) << 16;
                result |=
                    (((((value0 & 0xffff00000000) >> 32) as u16) << value1) as u128) << 32;
                result |=
                    (((((value0 & 0xffff000000000000) >> 48) as u16) << value1) as u128) << 48;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Paddsw => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..8 {
                let mask = 0xFFFFu128;
                let shift = i * 16;

                let word0 = ((value0 >> shift) & mask) as i16;
                let word1 = ((value1 >> shift) & mask) as i16;

                let sum = word0.saturating_add(word1);

                result |= (sum as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Paddsb => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..16 {
                let mask = 0xFFu128;
                let shift = i * 8;
                let byte0 = ((value0 >> shift) & mask) as i8;
                let byte1 = ((value1 >> shift) & mask) as i8;
                let sum = byte0.saturating_add(byte1);

                result |= (sum as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psrad => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;
            let shift_amount = (value1 & 0xFF) as u32;

            for i in 0..4 {
                let mask = 0xFFFFFFFFu128;
                let shift = i * 32;
                let dword = ((value0 >> shift) & mask) as i32;
                let shifted = dword >> shift_amount;

                result |= (shifted as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Paddusb | Mnemonic::Paddb => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };
            let sz = emu.get_operand_sz(ins, 0);
            let mut result: u128;

            if sz == 64 {
                result = ((value0 & 0xff) as u8 + (value1 & 0xff) as u8) as u128;
                result |= ((((value0 & 0xff00) >> 8) as u8 + ((value1 & 0xff00) >> 8) as u8)
                    as u128)
                    << 8;
                result |= ((((value0 & 0xff0000) >> 16) as u8
                    + ((value1 & 0xff0000) >> 16) as u8)
                    as u128)
                    << 16;
                result |= ((((value0 & 0xff000000) >> 24) as u8
                    + ((value1 & 0xff000000) >> 24) as u8)
                    as u128)
                    << 24;
                result |= ((((value0 & 0xff00000000) >> 32) as u8
                    + ((value1 & 0xff00000000) >> 32) as u8)
                    as u128)
                    << 32;
                result |= ((((value0 & 0xff0000000000) >> 40) as u8
                    + ((value1 & 0xff0000000000) >> 40) as u8)
                    as u128)
                    << 40;
                result |= ((((value0 & 0xff000000000000) >> 48) as u8
                    + ((value1 & 0xff000000000000) >> 48) as u8)
                    as u128)
                    << 48;
                result |= ((((value0 & 0xff00000000000000) >> 56) as u8
                    + ((value1 & 0xff00000000000000) >> 56) as u8)
                    as u128)
                    << 56;
            } else if sz == 128 {
                result = ((value0 & 0xff) as u8 + (value1 & 0xff) as u8) as u128;
                result |= ((((value0 & 0xff00) >> 8) as u8 + ((value1 & 0xff00) >> 8) as u8)
                    as u128)
                    << 8;
                result |= ((((value0 & 0xff0000) >> 16) as u8
                    + ((value1 & 0xff0000) >> 16) as u8)
                    as u128)
                    << 16;
                result |= ((((value0 & 0xff000000) >> 24) as u8
                    + ((value1 & 0xff000000) >> 24) as u8)
                    as u128)
                    << 24;
                result |= ((((value0 & 0xff00000000) >> 32) as u8
                    + ((value1 & 0xff00000000) >> 32) as u8)
                    as u128)
                    << 32;
                result |= ((((value0 & 0xff0000000000) >> 40) as u8
                    + ((value1 & 0xff0000000000) >> 40) as u8)
                    as u128)
                    << 40;
                result |= ((((value0 & 0xff000000000000) >> 48) as u8
                    + ((value1 & 0xff000000000000) >> 48) as u8)
                    as u128)
                    << 48;
                result |= ((((value0 & 0xff00000000000000) >> 56) as u8
                    + ((value1 & 0xff00000000000000) >> 56) as u8)
                    as u128)
                    << 56;

                result |= ((((value0 & 0xff_0000000000000000) >> 64) as u8
                    + ((value1 & 0xff_0000000000000000) >> 64) as u8)
                    as u128)
                    << 64;
                result |= ((((value0 & 0xff00_0000000000000000) >> 72) as u8
                    + ((value1 & 0xff00_0000000000000000) >> 72) as u8)
                    as u128)
                    << 72;
                result |= ((((value0 & 0xff0000_0000000000000000) >> 80) as u8
                    + ((value1 & 0xff0000_0000000000000000) >> 80) as u8)
                    as u128)
                    << 80;
                result |= ((((value0 & 0xff000000_0000000000000000) >> 88) as u8
                    + ((value1 & 0xff000000_0000000000000000) >> 88) as u8)
                    as u128)
                    << 88;
                result |= ((((value0 & 0xff00000000_0000000000000000) >> 96) as u8
                    + ((value1 & 0xff00000000_0000000000000000) >> 96) as u8)
                    as u128)
                    << 96;
                result |= ((((value0 & 0xff0000000000_0000000000000000) >> 104) as u8
                    + ((value1 & 0xff0000000000_0000000000000000) >> 104) as u8)
                    as u128)
                    << 104;
                result |= ((((value0 & 0xff000000000000_0000000000000000) >> 112) as u8
                    + ((value1 & 0xff000000000000_0000000000000000) >> 112) as u8)
                    as u128)
                    << 112;
                result |= ((((value0 & 0xff00000000000000_0000000000000000) >> 120) as u8
                    + ((value1 & 0xff00000000000000_0000000000000000) >> 120) as u8)
                    as u128)
                    << 120;
            } else {
                unimplemented!("bad operand size");
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Paddusw | Mnemonic::Paddw => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value0");
                    return false;
                }
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error getting value1");
                    return false;
                }
            };
            let sz = emu.get_operand_sz(ins, 0);
            let mut result: u128;

            if sz == 64 {
                result = ((value0 & 0xffff) as u16 + (value1 & 0xffff) as u16) as u128;
                result |= ((((value0 & 0xffff0000) >> 16) as u16
                    + ((value1 & 0xffff0000) >> 16) as u16)
                    as u128)
                    << 16;
                result |= ((((value0 & 0xffff00000000) >> 32) as u16
                    + ((value1 & 0xffff00000000) >> 32) as u16)
                    as u128)
                    << 32;
                result |= ((((value0 & 0xffff000000000000) >> 48) as u16
                    + ((value1 & 0xffff000000000000) >> 48) as u16)
                    as u128)
                    << 48;
            } else if sz == 128 {
                result = ((value0 & 0xffff) as u16 + (value1 & 0xffff) as u16) as u128;
                result |= ((((value0 & 0xffff0000) >> 16) as u16
                    + ((value1 & 0xffff0000) >> 16) as u16)
                    as u128)
                    << 16;
                result |= ((((value0 & 0xffff00000000) >> 32) as u16
                    + ((value1 & 0xffff00000000) >> 32) as u16)
                    as u128)
                    << 32;
                result |= ((((value0 & 0xffff000000000000) >> 48) as u16
                    + ((value1 & 0xffff000000000000) >> 48) as u16)
                    as u128)
                    << 48;

                result |= ((((value0 & 0xffff_0000000000000000) >> 64) as u16
                    + ((value1 & 0xffff_0000000000000000) >> 64) as u16)
                    as u128)
                    << 64;
                result |= ((((value0 & 0xffff0000_0000000000000000) >> 80) as u16
                    + ((value1 & 0xffff0000_0000000000000000) >> 80) as u16)
                    as u128)
                    << 80;
                result |= ((((value0 & 0xffff00000000_0000000000000000) >> 96) as u16
                    + ((value1 & 0xffff00000000_0000000000000000) >> 96) as u16)
                    as u128)
                    << 96;
                result |= ((((value0 & 0xffff0000000000_0000000000000000) >> 112) as u16
                    + ((value1 & 0xffff0000000000_0000000000000000) >> 112) as u16)
                    as u128)
                    << 112;
            } else {
                unimplemented!("bad operand size");
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pshufd => {
            emu.show_instruction(&emu.colors.green, ins);

            let source = emu
                .get_operand_xmm_value_128(ins, 1, true)
                .expect("error getting source");
            let order = emu
                .get_operand_value(ins, 2, true)
                .expect("error getting order");

            let order1 = get_bit!(order, 0) | (get_bit!(order, 1) << 1);
            let order2 = get_bit!(order, 2) | (get_bit!(order, 3) << 1);
            let order3 = get_bit!(order, 4) | (get_bit!(order, 5) << 1);
            let order4 = get_bit!(order, 6) | (get_bit!(order, 7) << 1);

            let mut dest: u128 = (source >> (order1 * 32)) as u32 as u128;
            dest |= ((source >> (order2 * 32)) as u32 as u128) << 32;
            dest |= ((source >> (order3 * 32)) as u32 as u128) << 64;
            dest |= ((source >> (order4 * 32)) as u32 as u128) << 96;

            emu.set_operand_xmm_value_128(ins, 0, dest);
        }

        Mnemonic::Movups => {
            emu.show_instruction(&emu.colors.green, ins);

            let source = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => emu.get_operand_value(ins, 1, true).unwrap_or(0) as u128,
            };

            emu.set_operand_xmm_value_128(ins, 0, source);
        }

        Mnemonic::Movdqu => {
            emu.show_instruction(&emu.colors.green, ins);

            let source = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error reading memory xmm 1 source operand");
                    return false;
                }
            };

            emu.set_operand_xmm_value_128(ins, 0, source);
        }

        // ymmX registers
        Mnemonic::Vzeroupper => {
            emu.show_instruction(&emu.colors.green, ins);

            let mask_lower = regs64::U256::from(0xffffffffffffffffu64);
            let mask = mask_lower | (mask_lower << 64);

            emu.regs.ymm0 &= mask;
            emu.regs.ymm1 &= mask;
            emu.regs.ymm2 &= mask;
            emu.regs.ymm3 &= mask;
            emu.regs.ymm4 &= mask;
            emu.regs.ymm5 &= mask;
            emu.regs.ymm6 &= mask;
            emu.regs.ymm7 &= mask;
            emu.regs.ymm8 &= mask;
            emu.regs.ymm9 &= mask;
            emu.regs.ymm10 &= mask;
            emu.regs.ymm11 &= mask;
            emu.regs.ymm12 &= mask;
            emu.regs.ymm13 &= mask;
            emu.regs.ymm14 &= mask;
            emu.regs.ymm15 &= mask;
        }

        Mnemonic::Vmovdqu => {
            emu.show_instruction(&emu.colors.green, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);
            let sz_max = sz0.max(sz1);

            match sz_max {
                128 => {
                    let source = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_xmm_value_128(ins, 0, source);
                }
                256 => {
                    let source = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_ymm_value_256(ins, 0, source);
                }
                _ => {
                    unimplemented!(
                        "unimplemented operand size {}",
                        emu.get_operand_sz(ins, 1)
                    );
                }
            }
        }

        Mnemonic::Vmovdqa => {
            //TODO: exception if memory address is unaligned to 16,32,64
            emu.show_instruction(&emu.colors.green, ins);

            let sz0 = emu.get_operand_sz(ins, 0);
            let sz1 = emu.get_operand_sz(ins, 1);
            let sz_max = sz0.max(sz1);

            match sz_max {
                128 => {
                    let source = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_xmm_value_128(ins, 0, source);
                }
                256 => {
                    let source = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_ymm_value_256(ins, 0, source);
                }
                _ => unimplemented!("unimplemented operand size"),
            }
        }

        Mnemonic::Movaps | Mnemonic::Movapd => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);

            let source = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error reading memory xmm 1 source operand");
                    return false;
                }
            };

            emu.set_operand_xmm_value_128(ins, 0, source);
        }

        Mnemonic::Vmovd => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);
            assert!(emu.get_operand_sz(ins, 1) == 32);

            let value = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error reading second operand");
                    return false;
                }
            };

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    emu.set_operand_xmm_value_128(ins, 0, value as u128);
                }
                256 => {
                    let result = regs64::U256::from(value);
                    emu.set_operand_ymm_value_256(ins, 0, result);
                }
                _ => unimplemented!(""),
            }
        }

        Mnemonic::Vmovq => {
            emu.show_instruction(&emu.colors.green, ins);

            assert!(ins.op_count() == 2);
            assert!(emu.get_operand_sz(ins, 1) == 64);

            let value = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("error reading second operand");
                    return false;
                }
            };

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    emu.set_operand_xmm_value_128(ins, 0, value as u128);
                }
                256 => {
                    let result = regs64::U256::from(value);
                    emu.set_operand_ymm_value_256(ins, 0, result);
                }
                _ => unimplemented!(""),
            }
        }

        Mnemonic::Vpbroadcastb => {
            emu.show_instruction(&emu.colors.green, ins);

            let byte: u8 = match emu.get_operand_sz(ins, 1) {
                128 => {
                    let source = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    (source & 0xff) as u8
                }

                256 => {
                    let source = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    (source & regs64::U256::from(0xFF)).low_u64() as u8
                }
                _ => unreachable!(""),
            };

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    let mut result: u128 = 0;
                    for _ in 0..16 {
                        result <<= 8;
                        result |= byte as u128;
                    }
                    emu.set_operand_xmm_value_128(ins, 0, result);
                }
                256 => {
                    let mut result = regs64::U256::zero();
                    for _ in 0..32 {
                        result <<= 8;
                        result |= regs64::U256::from(byte);
                    }
                    emu.set_operand_ymm_value_256(ins, 0, result);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Vpor => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 1) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_xmm_value_128(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 2 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_xmm_value_128(ins, 0, source1 | source2);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_ymm_value_256(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 2 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_ymm_value_256(ins, 0, source1 | source2);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Vpxor => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_xmm_value_128(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 2 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_xmm_value_128(ins, 0, source1 ^ source2);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_ymm_value_256(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 2 source operand");
                            return false;
                        }
                    };

                    emu.set_operand_ymm_value_256(ins, 0, source1 ^ source2);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Pcmpeqb => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 2 source operand");
                            return false;
                        }
                    };

                    let a_bytes = source1.to_le_bytes();
                    let b_bytes = source2.to_le_bytes();

                    let mut result = [0u8; 16];

                    for i in 0..16 {
                        if a_bytes[i] == b_bytes[i] {
                            result[i] = 0xFF;
                        } else {
                            result[i] = 0;
                        }
                    }

                    let result = u128::from_le_bytes(result);

                    emu.set_operand_xmm_value_128(ins, 0, result);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 0, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 2 source operand");
                            return false;
                        }
                    };

                    let mut bytes1: Vec<u8> = vec![0; 32];
                    source1.to_little_endian(&mut bytes1);
                    let mut bytes2: Vec<u8> = vec![0; 32];
                    source2.to_little_endian(&mut bytes2);

                    let mut result = [0u8; 32];

                    for i in 0..32 {
                        if bytes1[i] == bytes2[i] {
                            result[i] = 0xFF;
                        } else {
                            result[i] = 0;
                        }
                    }

                    let result256: regs64::U256 = regs64::U256::from_little_endian(&result);

                    emu.set_operand_ymm_value_256(ins, 0, result256);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Psubsb => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..16 {
                let mask = 0xFFu128;
                let shift = i * 8;
                let byte0 = ((value0 >> shift) & mask) as i8;
                let byte1 = ((value1 >> shift) & mask) as i8;
                let diff = byte0.saturating_sub(byte1);

                result |= (diff as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Fcomp => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0) as usize;
            let value2 = emu.get_operand_value(ins, 1, false).unwrap_or(2) as usize;

            let sti = emu.fpu.get_st(value0);
            let stj = emu.fpu.get_st(value2);

            emu.fpu.f_c0 = sti < stj;
            emu.fpu.f_c2 = sti.is_nan() || stj.is_nan();
            emu.fpu.f_c3 = sti == stj;

            emu.fpu.pop();
        }

        Mnemonic::Psrlq => {
            emu.show_instruction(&emu.colors.green, ins);

            let destination = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let shift_amount = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let result = destination.wrapping_shr(shift_amount as u32);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psubsw => {
            emu.show_instruction(&emu.colors.green, ins);

            // Obtener los valores de los registros XMM (128 bits cada uno)
            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0); // xmm6
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0); // xmm5
            let mut result = 0u128;

            for i in 0..8 {
                let mask = 0xFFFFu128;
                let shift = i * 16;
                let word0 = ((value0 >> shift) & mask) as i16;
                let word1 = ((value1 >> shift) & mask) as i16;
                let diff = word0.saturating_sub(word1);

                result |= (diff as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Fsincos => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let sin_value = st0.sin();
            let cos_value = st0.cos();

            emu.fpu.set_st(0, sin_value);
            emu.fpu.push(cos_value);
        }

        Mnemonic::Packuswb => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..8 {
                let mask = 0xFFFFu128;
                let shift = i * 16;
                let word0 = ((value0 >> shift) & mask) as i16;
                let word1 = ((value1 >> shift) & mask) as i16;
                let byte0 = if word0 > 255 {
                    255
                } else if word0 < 0 {
                    0
                } else {
                    word0 as u8
                };
                let byte1 = if word1 > 255 {
                    255
                } else if word1 < 0 {
                    0
                } else {
                    word1 as u8
                };

                result |= (byte0 as u128) << (i * 8);
                result |= (byte1 as u128) << ((i + 8) * 8);
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pandn => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0); // xmm1
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0); // xmm5
            let result = (!value0) & value1;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psrld => {
            emu.show_instruction(&emu.colors.green, ins);

            let value = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let shift_amount = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0) as u32;
            let mut result = 0u128;

            for i in 0..4 {
                let mask = 0xFFFFFFFFu128;
                let shift = i * 32;
                let dword = ((value >> shift) & mask) as u32;
                let shifted = dword.wrapping_shr(shift_amount);

                result |= (shifted as u128 & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Punpckhwd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);

            let mut result = 0u128;

            for i in 0..4 {
                let mask = 0xFFFFu128;
                let shift = i * 16;

                let word0 = ((value0 >> (shift + 48)) & mask) as u16;
                let word1 = ((value1 >> (shift + 48)) & mask) as u16;

                result |= (word0 as u128) << (i * 32);
                result |= (word1 as u128) << (i * 32 + 16);
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Psraw => {
            emu.show_instruction(&emu.colors.green, ins);

            let value1 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value6 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;
            let shift_amount = (value6 & 0xFF) as u32;

            for i in 0..8 {
                let mask = 0xFFFFu128;
                let shift = i * 16;

                let word = ((value1 >> shift) & mask) as i16;
                let shifted_word = (word as i32 >> shift_amount) as i16;

                result |= (shifted_word as u128) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Frndint => {
            emu.show_instruction(&emu.colors.green, ins);

            let value = emu.fpu.get_st(0);
            let rounded_value = value.round();

            emu.fpu.set_st(0, rounded_value);
        }

        Mnemonic::Psrlw => {
            emu.show_instruction(&emu.colors.green, ins);

            if emu.get_operand_sz(ins, 1) < 128 {
                let value = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);

                let shift_amount = match emu.get_operand_value(ins, 1, false) {
                    Some(v) => (v & 0xFF) as u32,
                    None => 0,
                };

                let mut result = 0u128;

                for i in 0..8 {
                    let mask = 0xFFFFu128;
                    let shift = i * 16;
                    let word = ((value >> shift) & mask) as u16;
                    let shifted_word = (word as u32 >> shift_amount) as u16;

                    result |= (shifted_word as u128) << shift;
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            } else {
                let value = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);

                let shift_amount = match emu.get_operand_xmm_value_128(ins, 1, false) {
                    Some(v) => (v & 0xFF) as u32,
                    None => 0,
                };

                let mut result = 0u128;

                for i in 0..8 {
                    let mask = 0xFFFFu128;
                    let shift = i * 16;
                    let word = ((value >> shift) & mask) as u16;
                    let shifted_word = (word as u32 >> shift_amount) as u16;

                    result |= (shifted_word as u128) << shift;
                }

                emu.set_operand_xmm_value_128(ins, 0, result);
            }
        }

        Mnemonic::Paddd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);

            let mut result = 0u128;

            for i in 0..4 {
                let mask = 0xFFFFFFFFu128;
                let shift = i * 32;
                let word0 = ((value0 >> shift) & mask) as u32;
                let word1 = ((value1 >> shift) & mask) as u32;
                let sum = word0.wrapping_add(word1);

                result |= (sum as u128) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Fscale => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let st1 = emu.fpu.get_st(1);

            let scale_factor = 2.0f64.powf(st1.trunc());
            let result = st0 * scale_factor;

            emu.fpu.set_st(0, result);
        }

        Mnemonic::Vpcmpeqb => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_xmm_value_128(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 2 source operand");
                            return false;
                        }
                    };

                    let a_bytes = source1.to_le_bytes();
                    let b_bytes = source2.to_le_bytes();

                    let mut result = [0u8; 16];

                    for i in 0..16 {
                        if a_bytes[i] == b_bytes[i] {
                            result[i] = 0xFF;
                        } else {
                            result[i] = 0;
                        }
                    }

                    let result = u128::from_le_bytes(result);

                    emu.set_operand_xmm_value_128(ins, 0, result);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_ymm_value_256(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 2 source operand");
                            return false;
                        }
                    };

                    let mut bytes1: Vec<u8> = vec![0; 32];
                    source1.to_little_endian(&mut bytes1);
                    let mut bytes2: Vec<u8> = vec![0; 32];
                    source2.to_little_endian(&mut bytes2);

                    let mut result = [0u8; 32];

                    for i in 0..32 {
                        if bytes1[i] == bytes2[i] {
                            result[i] = 0xFF;
                        } else {
                            result[i] = 0;
                        }
                    }

                    let result256: regs64::U256 = regs64::U256::from_little_endian(&result);

                    emu.set_operand_ymm_value_256(ins, 0, result256);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Pmullw => {
            emu.show_instruction(&emu.colors.green, ins);

            let source0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let source1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..8 {
                let mask = 0xFFFFu128;
                let shift = i * 16;
                let word0 = ((source0 >> shift) & mask) as u16;
                let word1 = ((source1 >> shift) & mask) as u16;
                let product = word0.wrapping_mul(word1) as u128;
                result |= (product & mask) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pmulhw => {
            emu.show_instruction(&emu.colors.green, ins);

            let source0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let source1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let mut result = 0u128;

            for i in 0..8 {
                let mask = 0xFFFFu128;
                let shift = i * 16;

                let word0 = ((source0 >> shift) & mask) as i16;
                let word1 = ((source1 >> shift) & mask) as i16;
                let product = (word0 as i32) * (word1 as i32);
                let high_word = ((product >> 16) & 0xFFFF) as u128;
                result |= high_word << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pmovmskb => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 1) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let mut result: u16 = 0;

                    for i in 0..16 {
                        let byte = ((source1 >> (i * 8)) & 0xff) as u16;
                        let msb = (byte & 0x80) >> 7;
                        result |= msb << i;
                    }

                    emu.set_operand_value(ins, 0, result as u64);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let mut result: u32 = 0;
                    let mut input_bytes = [0u8; 32];
                    source1.to_little_endian(&mut input_bytes);

                    for (i, byte) in input_bytes.iter().enumerate() {
                        let msb = (byte & 0x80) >> 7;
                        result |= (msb as u32) << i;
                    }

                    emu.set_operand_value(ins, 0, result as u64);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Vpmovmskb => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 1) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let mut result: u16 = 0;

                    for i in 0..16 {
                        let byte = ((source1 >> (i * 8)) & 0xff) as u16;
                        let msb = (byte & 0x80) >> 7;
                        result |= msb << i;
                    }

                    emu.set_operand_value(ins, 0, result as u64);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let mut result: u32 = 0;
                    let mut input_bytes = [0u8; 32];
                    source1.to_little_endian(&mut input_bytes);

                    for (i, byte) in input_bytes.iter().enumerate() {
                        let msb = (byte & 0x80) >> 7;
                        result |= (msb as u32) << i;
                    }

                    emu.set_operand_value(ins, 0, result as u64);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Vpminub => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_xmm_value_128(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 2 source operand");
                            return false;
                        }
                    };

                    let mut result: u128 = 0;
                    for i in 0..16 {
                        let byte1 = (source1 >> (8 * i)) & 0xFF;
                        let byte2 = (source2 >> (8 * i)) & 0xFF;
                        let min_byte = byte1.min(byte2);
                        result |= min_byte << (8 * i);
                    }

                    emu.set_operand_xmm_value_128(ins, 0, result);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_ymm_value_256(ins, 2, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 2 source operand");
                            return false;
                        }
                    };

                    let mut bytes1: Vec<u8> = vec![0; 32];
                    source1.to_little_endian(&mut bytes1);
                    let mut bytes2: Vec<u8> = vec![0; 32];
                    source2.to_little_endian(&mut bytes2);

                    let mut result = [0u8; 32];

                    for i in 0..32 {
                        result[i] = bytes1[i].min(bytes2[i]);
                    }

                    let result256: regs64::U256 = regs64::U256::from_little_endian(&result);

                    emu.set_operand_ymm_value_256(ins, 0, result256);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Fdecstp => {
            emu.show_instruction(&emu.colors.green, ins);
            emu.fpu.dec_top();
        }

        Mnemonic::Ftst => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            emu.fpu.f_c0 = st0 < 0.0;
            emu.fpu.f_c2 = st0.is_nan();
            emu.fpu.f_c3 = st0 == 0.0;
        }

        Mnemonic::Emms => {
            emu.show_instruction(&emu.colors.green, ins);
        }

        Mnemonic::Fxam => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0: f64 = emu.fpu.get_st(0);

            emu.fpu.f_c0 = st0 < 0f64;

            emu.fpu.f_c1 = false;

            if st0.is_nan() {
                emu.fpu.f_c2 = true;
                emu.fpu.f_c3 = true;
            } else {
                emu.fpu.f_c2 = false;
                emu.fpu.f_c3 = false;
            }
        }

        Mnemonic::Pcmpgtw => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);
            assert!(emu.get_operand_sz(ins, 0) == 128);
            assert!(emu.get_operand_sz(ins, 1) == 128);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let mut result = 0u128;

            for i in 0..8 {
                let shift = i * 16;
                let word0 = (value0 >> shift) & 0xFFFF;
                let word1 = (value1 >> shift) & 0xFFFF;

                let cmp_result = if word0 > word1 {
                    0xFFFFu128
                } else {
                    0x0000u128
                };

                result |= cmp_result << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pcmpgtb => {
            emu.show_instruction(&emu.colors.green, ins);
            assert!(ins.op_count() == 2);
            assert!(emu.get_operand_sz(ins, 0) == 128);
            assert!(emu.get_operand_sz(ins, 1) == 128);

            let value0 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };
            let value1 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let mut result = 0u128;

            for i in 0..16 {
                let shift = i * 8;
                let byte0 = (value0 >> shift) & 0xFF;
                let byte1 = (value1 >> shift) & 0xFF;

                let cmp_result = if byte0 > byte1 { 0xFFu128 } else { 0x00u128 };

                result |= cmp_result << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Faddp => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.pop();
            let st1 = emu.fpu.pop();

            emu.fpu.push(st0 + st1);
        }

        Mnemonic::Pcmpeqw => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.get_operand_sz(ins, 0) {
                128 => {
                    let source1 = match emu.get_operand_xmm_value_128(ins, 0, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_xmm_value_128(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory xmm 2 source operand");
                            return false;
                        }
                    };

                    let a_words = source1.to_le_bytes();
                    let b_words = source2.to_le_bytes();

                    let mut result = [0u8; 16];

                    for i in 0..8 {
                        let word_a = u16::from_le_bytes([a_words[2 * i], a_words[2 * i + 1]]);
                        let word_b = u16::from_le_bytes([b_words[2 * i], b_words[2 * i + 1]]);
                        let cmp_result: u16 = if word_a == word_b { 0xFFFF } else { 0x0000 };
                        let [low, high] = cmp_result.to_le_bytes();
                        result[2 * i] = low;
                        result[2 * i + 1] = high;
                    }
                    let result = u128::from_le_bytes(result);
                    emu.set_operand_xmm_value_128(ins, 0, result);
                }
                256 => {
                    let source1 = match emu.get_operand_ymm_value_256(ins, 0, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 1 source operand");
                            return false;
                        }
                    };

                    let source2 = match emu.get_operand_ymm_value_256(ins, 1, true) {
                        Some(v) => v,
                        None => {
                            log::info!("error reading memory ymm 2 source operand");
                            return false;
                        }
                    };

                    let mut bytes1: Vec<u8> = vec![0; 32];
                    source1.to_little_endian(&mut bytes1);
                    let mut bytes2: Vec<u8> = vec![0; 32];
                    source2.to_little_endian(&mut bytes2);
                    let mut result = [0u8; 32];

                    for i in 0..16 {
                        let word1 = u16::from_le_bytes([bytes1[2 * i], bytes1[2 * i + 1]]);
                        let word2 = u16::from_le_bytes([bytes2[2 * i], bytes2[2 * i + 1]]);
                        let cmp_result = if word1 == word2 { 0xFFFFu16 } else { 0x0000u16 };
                        let [low, high] = cmp_result.to_le_bytes();

                        result[2 * i] = low;
                        result[2 * i + 1] = high;
                    }

                    let result256: regs64::U256 = regs64::U256::from_little_endian(&result);
                    emu.set_operand_ymm_value_256(ins, 0, result256);
                }
                _ => unreachable!(""),
            }
        }

        Mnemonic::Fnclex => {
            emu.show_instruction(&emu.colors.green, ins);
            emu.fpu.stat &= !(0b10000011_11111111);
        }

        Mnemonic::Fcom => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);

            let value1 = match emu.get_operand_value(ins, 1, false) {
                Some(v1) => v1,
                None => 0,
            };

            let st4 = emu.fpu.get_st(value1 as usize);

            if st0.is_nan() || st4.is_nan() {
                emu.fpu.f_c0 = false;
                emu.fpu.f_c2 = true;
                emu.fpu.f_c3 = false;
            } else {
                emu.fpu.f_c0 = st0 < st4;
                emu.fpu.f_c2 = false;
                emu.fpu.f_c3 = st0 == st4;
            }
        }

        Mnemonic::Fmul => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);

            let value1 = match emu.get_operand_value(ins, 1, false) {
                Some(v1) => v1,
                None => 0,
            };

            let stn = emu.fpu.get_st(value1 as usize);
            emu.fpu.set_st(0, st0 * stn);
        }

        Mnemonic::Fabs => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);
            emu.fpu.set_st(0, st0.abs());
        }

        Mnemonic::Fsin => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);
            emu.fpu.set_st(0, st0.sin());
        }

        Mnemonic::Fcos => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);
            emu.fpu.set_st(0, st0.cos());
        }

        Mnemonic::Fdiv => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);

            let value1 = match emu.get_operand_value(ins, 1, false) {
                Some(v1) => v1,
                None => 0,
            };

            let stn = emu.fpu.get_st(value1 as usize);
            emu.fpu.set_st(0, st0 / stn);
        }

        Mnemonic::Fdivr => {
            emu.show_instruction(&emu.colors.green, ins);
            let st0 = emu.fpu.get_st(0);
            let value1 = emu.get_operand_value(ins, 1, false).unwrap_or(0);
            let stn = emu.fpu.get_st(value1 as usize);
            emu.fpu.set_st(0, stn / st0);
        }

        Mnemonic::Fdivrp => {
            emu.show_instruction(&emu.colors.green, ins);
            let value0 = emu.get_operand_value(ins, 0, false).unwrap_or(0) as usize;
            let value1 = emu.get_operand_value(ins, 1, false).unwrap_or(0) as usize;
            let st0 = emu.fpu.get_st(value0);
            let st7 = emu.fpu.get_st(value1);

            let result = st7 / st0;

            emu.fpu.set_st(value1, result);
            emu.fpu.pop();
        }

        Mnemonic::Fpatan => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let st1 = emu.fpu.get_st(1);
            let result = (st1 / st0).atan();
            emu.fpu.set_st(1, result);
            emu.fpu.pop();
        }

        Mnemonic::Fprem => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let st1 = emu.fpu.get_st(1);

            let quotient = (st0 / st1).floor();
            let result = st0 - quotient * st1;

            emu.fpu.set_st(0, result);
        }

        Mnemonic::Fprem1 => {
            emu.show_instruction(&emu.colors.green, ins);

            let st0 = emu.fpu.get_st(0);
            let st1 = emu.fpu.get_st(1);

            let quotient = (st0 / st1).round();
            let remainder = st0 - quotient * st1;

            emu.fpu.set_st(0, remainder);
        }

        Mnemonic::Pcmpgtd => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);

            let mut result = 0u128;

            for i in 0..4 {
                let shift = i * 32;
                let word0 = ((value0 >> shift) & 0xFFFFFFFFu128) as u32;
                let word1 = ((value1 >> shift) & 0xFFFFFFFFu128) as u32;
                let comparison_result = if word0 > word1 {
                    0xFFFFFFFFu32
                } else {
                    0x00000000u32
                };

                result |= (comparison_result as u128) << shift;
            }

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pmaddwd => {
            emu.show_instruction(&emu.colors.green, ins);

            let src0 = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let src1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);

            let mut result = [0i32; 2];

            for i in 0..4 {
                let shift = i * 16;
                let a = ((src0 >> shift) & 0xFFFF) as i16 as i32;
                let b = ((src1 >> shift) & 0xFFFF) as i16 as i32;

                let product = a * b;

                if i < 2 {
                    result[0] += product;
                } else {
                    result[1] += product;
                }
            }

            let final_result = ((result[1] as u64) << 32) | (result[0] as u64);

            emu.set_operand_xmm_value_128(ins, 0, final_result as u128);
        }

        // end SSE
        Mnemonic::Tzcnt => {
            emu.show_instruction(&emu.colors.green, ins);

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let sz = emu.get_operand_sz(ins, 0) as u64;
            let mut temp: u64 = 0;
            let mut dest: u64 = 0;

            while temp < sz && get_bit!(value1, temp) == 0 {
                temp += 1;
                dest += 1;
            }

            emu.flags.f_cf = dest == sz;
            emu.flags.f_zf = dest == 0;

            emu.set_operand_value(ins, 1, dest);
        }

        Mnemonic::Xgetbv => {
            emu.show_instruction(&emu.colors.green, ins);

            match emu.regs.get_ecx() {
                0 => {
                    emu.regs.set_edx(0);
                    emu.regs.set_eax(0x1f); //7
                }
                _ => {
                    emu.regs.set_edx(0);
                    emu.regs.set_eax(7);
                }
            }
        }

        Mnemonic::Arpl => {
            emu.show_instruction(&emu.colors.green, ins);

            let value0 = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let value1 = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            emu.flags.f_zf = value1 < value0;

            emu.set_operand_value(ins, 0, value0);
        }

        Mnemonic::Pushf => {
            emu.show_instruction(&emu.colors.blue, ins);

            let val: u16 = (emu.flags.dump() & 0xffff) as u16;

            emu.regs.rsp -= 2;

            if !emu.maps.write_word(emu.regs.rsp, val) {
                log::info!("/!\\ exception writing word at rsp 0x{:x}", emu.regs.rsp);
                emu.exception();
                return false;
            }
        }

        Mnemonic::Pushfd => {
            emu.show_instruction(&emu.colors.blue, ins);

            // 32bits only instruction
            let flags = emu.flags.dump();
            if !emu.stack_push32(flags) {
                return false;
            }
        }

        Mnemonic::Pushfq => {
            emu.show_instruction(&emu.colors.blue, ins);
            emu.flags.f_tf = false;
            if !emu.stack_push64(emu.flags.dump() as u64) {
                return false;
            }
        }

        Mnemonic::Bound => {
            emu.show_instruction(&emu.colors.red, ins);

            let array_index = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => {
                    log::info!("cannot read first opreand of bound");
                    return false;
                }
            };
            let lower_upper_bound = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => {
                    log::info!("cannot read second opreand of bound");
                    return false;
                }
            };

            log::info!(
                "bound idx:{} lower_upper:{}",
                array_index,
                lower_upper_bound
            );
            log::info!("Bound unimplemented");
            return false;
            // https://www.felixcloutier.com/x86/bound
        }

        Mnemonic::Lahf => {
            emu.show_instruction(&emu.colors.red, ins);

            //log::info!("\tlahf: flags = {:?}", emu.flags);

            let mut result: u8 = 0;
            set_bit!(result, 0, emu.flags.f_cf as u8);
            set_bit!(result, 1, true as u8);
            set_bit!(result, 2, emu.flags.f_pf as u8);
            set_bit!(result, 3, false as u8);
            set_bit!(result, 4, emu.flags.f_af as u8);
            set_bit!(result, 5, false as u8);
            set_bit!(result, 6, emu.flags.f_zf as u8);
            set_bit!(result, 7, emu.flags.f_sf as u8);
            emu.regs.set_ah(result as u64);
        }

        Mnemonic::Salc => {
            emu.show_instruction(&emu.colors.red, ins);

            if emu.flags.f_cf {
                emu.regs.set_al(1);
            } else {
                emu.regs.set_al(0);
            }
        }

        Mnemonic::Movlhps => {
            emu.show_instruction(&emu.colors.red, ins);
            assert!(ins.op_count() == 2);

            let dest = emu.get_operand_xmm_value_128(ins, 0, true).unwrap_or(0);
            let source = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);

            let low_qword = dest & 0xFFFFFFFFFFFFFFFF;
            let high_qword = (source & 0xFFFFFFFFFFFFFFFF) << 64;
            let result = low_qword | high_qword;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pshuflw => {
            emu.show_instruction(&emu.colors.red, ins);
            assert!(ins.op_count() == 3);

            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let value2 = emu.get_operand_value(ins, 2, true).unwrap_or(0);

            let high_qword = value1 & 0xFFFFFFFFFFFFFFFF_0000000000000000;
            let lw0 = value1 & 0xFFFF;
            let lw1 = (value1 >> 16) & 0xFFFF;
            let lw2 = (value1 >> 32) & 0xFFFF;
            let lw3 = (value1 >> 48) & 0xFFFF;
            let low_words = [lw0, lw1, lw2, lw3];
            let mut low_qword: u64 = 0;
            low_qword |= (low_words[(value2 & 0b11) as usize]) as u64;
            low_qword |= (low_words[((value2 >> 2) & 0b11) as usize] as u64) << 16;
            low_qword |= (low_words[((value2 >> 4) & 0b11) as usize] as u64) << 32;
            low_qword |= (low_words[((value2 >> 6) & 0b11) as usize] as u64) << 48;
            let result = high_qword | low_qword as u128;

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Pshufhw => {
            emu.show_instruction(&emu.colors.red, ins);
            assert!(ins.op_count() == 3);

            let value1 = emu.get_operand_xmm_value_128(ins, 1, true).unwrap_or(0);
            let value2 = emu.get_operand_value(ins, 2, true).unwrap_or(0);

            let low_qword = value1 & 0xFFFFFFFFFFFFFFFF;
            let hw0 = (value1 >> 64) & 0xFFFF;
            let hw1 = (value1 >> 80) & 0xFFFF;
            let hw2 = (value1 >> 96) & 0xFFFF;
            let hw3 = (value1 >> 112) & 0xFFFF;
            let high_words = [hw0, hw1, hw2, hw3];
            let mut high_qword: u64 = 0;

            high_qword |= (high_words[(value2 & 0b11) as usize]) as u64;
            high_qword |= (high_words[((value2 >> 2) & 0b11) as usize] as u64) << 16;
            high_qword |= (high_words[((value2 >> 4) & 0b11) as usize] as u64) << 32;
            high_qword |= (high_words[((value2 >> 6) & 0b11) as usize] as u64) << 48;

            let result = low_qword | ((high_qword as u128) << 64);

            emu.set_operand_xmm_value_128(ins, 0, result);
        }

        Mnemonic::Stmxcsr => {
            emu.show_instruction(&emu.colors.red, ins);

            let value = emu.fpu.mxcsr;
            emu.set_operand_value(ins, 0, value as u64);
        }

        Mnemonic::Ldmxcsr => {
            emu.show_instruction(&emu.colors.red, ins);

            let value = emu.get_operand_value(ins, 0, true).unwrap_or(0);
            emu.fpu.mxcsr = value as u32;
        }

        Mnemonic::Fnstcw => {
            emu.show_instruction(&emu.colors.red, ins);

            let addr = emu.get_operand_value(ins, 0, false).unwrap_or(0);
            if addr > 0 {
                emu.maps.write_word(addr, emu.fpu.fpu_control_word);
            }
        }

        Mnemonic::Prefetchnta => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Prefetchw => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Pause => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Wait => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Mwait => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Endbr64 => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Endbr32 => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Enqcmd => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Enqcmds => {
            emu.show_instruction(&emu.colors.red, ins);
        }

        Mnemonic::Enter => {
            emu.show_instruction(&emu.colors.red, ins);

            let allocSZ = match emu.get_operand_value(ins, 0, true) {
                Some(v) => v,
                None => return false,
            };

            let nestingLvl = match emu.get_operand_value(ins, 1, true) {
                Some(v) => v,
                None => return false,
            };

            let frameTmp = if emu.cfg.is_64bits {
                emu.stack_push64(emu.regs.rbp);
                emu.regs.rsp
            } else {
                emu.stack_push32(emu.regs.get_ebp() as u32);
                emu.regs.get_esp()
            };

            if nestingLvl > 1 {
                for i in 1..nestingLvl {
                    if emu.cfg.is_64bits {
                        emu.regs.rbp -= 8;
                        emu.stack_push64(emu.regs.rbp);
                    } else {
                        emu.regs.set_ebp(emu.regs.get_ebp() - 4);
                        emu.stack_push32(emu.regs.get_ebp() as u32);
                    }
                }
            } else if emu.cfg.is_64bits {
                emu.stack_push64(frameTmp);
            } else {
                emu.stack_push32(frameTmp as u32);
            }

            if emu.cfg.is_64bits {
                emu.regs.rbp = frameTmp;
                emu.regs.rsp -= allocSZ;
            } else {
                emu.regs.set_ebp(frameTmp);
                emu.regs.set_esp(emu.regs.get_esp() - allocSZ);
            }
        }

        ////   Ring0  ////
        Mnemonic::Rdmsr => {
            emu.show_instruction(&emu.colors.red, ins);

            match emu.regs.rcx {
                0x176 => {
                    emu.regs.rdx = 0;
                    emu.regs.rax = emu.cfg.code_base_addr + 0x42;
                }
                _ => {
                    log::info!("/!\\ unimplemented rdmsr with value {}", emu.regs.rcx);
                    return false;
                }
            }
        }

        _ => {
            if emu.cfg.verbose >= 2 || !emu.cfg.skip_unimplemented {
                if emu.cfg.is_64bits {
                    log::info!(
                        "{}{} 0x{:x}: {}{}",
                        emu.colors.red,
                        emu.pos,
                        ins.ip(),
                        emu.out,
                        emu.colors.nc
                    );
                } else {
                    log::info!(
                        "{}{} 0x{:x}: {}{}",
                        emu.colors.red,
                        emu.pos,
                        ins.ip32(),
                        emu.out,
                        emu.colors.nc
                    );
                }
            }

            if !emu.cfg.skip_unimplemented {
                log::info!("unimplemented or invalid instruction. use --banzai (cfg.skip_unimplemented) mode to skip");
                if emu.cfg.console_enabled {
                    Console::spawn_console(emu);
                }
                return false;
                //unimplemented!("unimplemented instruction");
            }
        }
    }

    true // result_ok
}
