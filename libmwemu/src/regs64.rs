use crate::maps::Maps;
use iced_x86::Register;
use rand;
use serde::{Serialize, Deserialize};
use uint::construct_uint;

macro_rules! set_reg32 {
    ($reg:expr, $val:expr) => {
        $reg = ($val & 0x00000000ffffffff);
    };
}

macro_rules! set_reg16 {
    ($reg:expr, $val:expr) => {
        $reg &= 0xffffffffffff0000;
        $reg += ($val & 0x000000000000ffff);
    };
}

macro_rules! set_reg8l {
    ($reg:expr, $val:expr) => {
        $reg &= 0xffffffffffffff00;
        $reg += ($val & 0x00000000000000ff);
    };
}

macro_rules! set_reg8h {
    ($reg:expr, $val:expr) => {
        $reg &= 0xffffffffffff00ff;
        $reg += (($val & 0x00000000000000ff) << 8);
    };
}

macro_rules! get_reg32l {
    ($reg:expr) => {
        return $reg & 0x00000000ffffffff;
    };
}

macro_rules! get_reg32h {
    ($reg:expr) => {
        return $reg >> 32;
    };
}

macro_rules! get_reg16 {
    ($reg:expr) => {
        return $reg & 0x000000000000ffff;
    };
}

macro_rules! get_reg8l {
    ($reg:expr) => {
        return $reg & 0x00000000000000ff;
    };
}

macro_rules! get_reg8h {
    ($reg:expr) => {
        return ($reg & 0x000000000000ff00) >> 8;
    };
}

//  https://wiki.osdev.org/CPU_Registers_x86-64

construct_uint! {
    #[derive(Serialize, Deserialize)]
    pub struct U256(4);
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Regs64 {
    pub dr0: u64, // bp
    pub dr1: u64, // bp
    pub dr2: u64, // bp
    pub dr3: u64, // bp
    pub dr6: u64, // dbg stat
    pub dr7: u64, // dbg ctrl

    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,

    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    pub cr0: u64,
    pub cr1: u64, // reserved
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr5: u64, // reserved
    pub cr6: u64, // reserved
    pub cr7: u64, // reserved
    pub cr8: u64,
    pub cr9: u64,  // reserved
    pub cr10: u64, // reserved
    pub cr11: u64, // reserved
    pub cr12: u64, // reserved
    pub cr13: u64, // reserved
    pub cr14: u64, // reserved
    pub cr15: u64, // reserved

    pub msr: u64,

    pub tr3: u64,
    pub tr4: u64,
    pub tr5: u64,
    pub tr6: u64,
    pub tr7: u64,

    pub xmm0: u128,
    pub xmm1: u128,
    pub xmm2: u128,
    pub xmm3: u128,
    pub xmm4: u128,
    pub xmm5: u128,
    pub xmm6: u128,
    pub xmm7: u128,
    pub xmm8: u128,
    pub xmm9: u128,
    pub xmm10: u128,
    pub xmm11: u128,
    pub xmm12: u128,
    pub xmm13: u128,
    pub xmm14: u128,
    pub xmm15: u128,

    pub ymm0: U256,
    pub ymm1: U256,
    pub ymm2: U256,
    pub ymm3: U256,
    pub ymm4: U256,
    pub ymm5: U256,
    pub ymm6: U256,
    pub ymm7: U256,
    pub ymm8: U256,
    pub ymm9: U256,
    pub ymm10: U256,
    pub ymm11: U256,
    pub ymm12: U256,
    pub ymm13: U256,
    pub ymm14: U256,
    pub ymm15: U256,

    pub mm0: u128,
    pub mm1: u128,
    pub mm2: u128,
    pub mm3: u128,
    pub mm4: u128,
    pub mm5: u128,
    pub mm6: u128,
    pub mm7: u128,

    pub gs: u64,
    pub fs: u64,
}

impl Default for Regs64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Regs64 {
    pub fn new() -> Regs64 {
        Regs64 {
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,

            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            rip: 0,

            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,

            cr0: 0,
            cr1: 0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            cr5: 0,
            cr6: 0,
            cr7: 0,
            cr8: 0,
            cr9: 0,
            cr10: 0,
            cr11: 0,
            cr12: 0,
            cr13: 0,
            cr14: 0,
            cr15: 0,

            msr: 0,

            tr3: 0,
            tr4: 0,
            tr5: 0,
            tr6: 0,
            tr7: 0,

            xmm0: 0,
            xmm1: 0,
            xmm2: 0,
            xmm3: 0,
            xmm4: 0,
            xmm5: 0,
            xmm6: 0,
            xmm7: 0,
            xmm8: 0,
            xmm9: 0,
            xmm10: 0,
            xmm11: 0,
            xmm12: 0,
            xmm13: 0,
            xmm14: 0,
            xmm15: 0,

            ymm0: U256::from(0),
            ymm1: U256::from(0),
            ymm2: U256::from(0),
            ymm3: U256::from(0),
            ymm4: U256::from(0),
            ymm5: U256::from(0),
            ymm6: U256::from(0),
            ymm7: U256::from(0),
            ymm8: U256::from(0),
            ymm9: U256::from(0),
            ymm10: U256::from(0),
            ymm11: U256::from(0),
            ymm12: U256::from(0),
            ymm13: U256::from(0),
            ymm14: U256::from(0),
            ymm15: U256::from(0),

            mm0: 0,
            mm1: 0,
            mm2: 0,
            mm3: 0,
            mm4: 0,
            mm5: 0,
            mm6: 0,
            mm7: 0,

            gs: 0,
            fs: 0,
        }
    }

    pub fn diff(a: Regs64, b: Regs64) -> String {
        let mut output = String::new();
        if a.dr0 != b.dr0 {
            output = format!("{}{}: {:x} -> {:x} ", output, "dr0", a.dr0, b.dr0);
        }
        if a.dr1 != b.dr1 {
            output = format!("{}{}: {:x} -> {:x} ", output, "dr1", a.dr1, b.dr1);
        }
        if a.dr2 != b.dr2 {
            output = format!("{}{}: {:x} -> {:x} ", output, "dr2", a.dr2, b.dr2);
        }
        if a.dr3 != b.dr3 {
            output = format!("{}{}: {:x} -> {:x} ", output, "dr3", a.dr3, b.dr3);
        }
        if a.dr6 != b.dr6 {
            output = format!("{}{}: {:x} -> {:x} ", output, "dr6", a.dr6, b.dr6);
        }
        if a.dr7 != b.dr7 {
            output = format!("{}{}: {:x} -> {:x} ", output, "dr7", a.dr7, b.dr7);
        }
        if a.rax != b.rax {
            output = format!("{}{}: {:x} -> {:x} ", output, "rax", a.rax, b.rax);
        }
        if a.rbx != b.rbx {
            output = format!("{}{}: {:x} -> {:x} ", output, "rbx", a.rbx, b.rbx);
        }
        if a.rcx != b.rcx {
            output = format!("{}{}: {:x} -> {:x} ", output, "rcx", a.rcx, b.rcx);
        }
        if a.rdx != b.rdx {
            output = format!("{}{}: {:x} -> {:x} ", output, "rdx", a.rdx, b.rdx);
        }
        if a.rsi != b.rsi {
            output = format!("{}{}: {:x} -> {:x} ", output, "rsi", a.rsi, b.rsi);
        }
        if a.rdi != b.rdi {
            output = format!("{}{}: {:x} -> {:x} ", output, "rdi", a.rdi, b.rdi);
        }
        if a.rbp != b.rbp {
            output = format!("{}{}: {:x} -> {:x} ", output, "rbp", a.rbp, b.rbp);
        }
        if a.rsp != b.rsp {
            output = format!("{}{}: {:x} -> {:x} ", output, "rsp", a.rsp, b.rsp);
        }
        //if a.rip != b.rip { output = format!("{}{}: {:x} -> {:x} ", output, "rip", a.rip, b.rip) }
        if a.r8 != b.r8 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r8", a.r8, b.r8);
        }
        if a.r9 != b.r9 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r9", a.r9, b.r9);
        }
        if a.r10 != b.r10 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r10", a.r10, b.r10);
        }
        if a.r11 != b.r11 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r11", a.r11, b.r11);
        }
        if a.r12 != b.r12 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r12", a.r12, b.r12);
        }
        if a.r13 != b.r13 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r13", a.r13, b.r13);
        }
        if a.r14 != b.r14 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r14", a.r14, b.r14);
        }
        if a.r15 != b.r15 {
            output = format!("{}{}: {:x} -> {:x} ", output, "r15", a.r15, b.r15);
        }
        if a.cr0 != b.cr0 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr0", a.cr0, b.cr0);
        }
        if a.cr1 != b.cr1 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr1", a.cr1, b.cr1);
        }
        if a.cr2 != b.cr2 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr2", a.cr2, b.cr2);
        }
        if a.cr3 != b.cr3 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr3", a.cr3, b.cr3);
        }
        if a.cr4 != b.cr4 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr4", a.cr4, b.cr4);
        }
        if a.cr5 != b.cr5 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr5", a.cr5, b.cr5);
        }
        if a.cr6 != b.cr6 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr6", a.cr6, b.cr6);
        }
        if a.cr7 != b.cr7 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr7", a.cr7, b.cr7);
        }
        if a.cr8 != b.cr8 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr8", a.cr8, b.cr8);
        }
        if a.cr9 != b.cr9 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr9", a.cr9, b.cr9);
        }
        if a.cr10 != b.cr10 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr10", a.cr10, b.cr10);
        }
        if a.cr11 != b.cr11 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr11", a.cr11, b.cr11);
        }
        if a.cr12 != b.cr12 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr12", a.cr12, b.cr12);
        }
        if a.cr13 != b.cr13 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr13", a.cr13, b.cr13);
        }
        if a.cr14 != b.cr14 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr14", a.cr14, b.cr14);
        }
        if a.cr15 != b.cr15 {
            output = format!("{}{}: {:x} -> {:x} ", output, "cr15", a.cr15, b.cr15);
        }
        if a.msr != b.msr {
            output = format!("{}{}: {:x} -> {:x} ", output, "msr", a.msr, b.msr);
        }
        if a.tr3 != b.tr3 {
            output = format!("{}{}: {:x} -> {:x} ", output, "tr3", a.tr3, b.tr3);
        }
        if a.tr4 != b.tr4 {
            output = format!("{}{}: {:x} -> {:x} ", output, "tr4", a.tr4, b.tr4);
        }
        if a.tr5 != b.tr5 {
            output = format!("{}{}: {:x} -> {:x} ", output, "tr5", a.tr5, b.tr5);
        }
        if a.tr6 != b.tr6 {
            output = format!("{}{}: {:x} -> {:x} ", output, "tr6", a.tr6, b.tr6);
        }
        if a.tr7 != b.tr7 {
            output = format!("{}{}: {:x} -> {:x} ", output, "tr7", a.tr7, b.tr7);
        }
        if a.xmm0 != b.xmm0 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm0", a.xmm0, b.xmm0);
        }
        if a.xmm1 != b.xmm1 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm1", a.xmm1, b.xmm1);
        }
        if a.xmm2 != b.xmm2 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm2", a.xmm2, b.xmm2);
        }
        if a.xmm3 != b.xmm3 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm3", a.xmm3, b.xmm3);
        }
        if a.xmm4 != b.xmm4 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm4", a.xmm4, b.xmm4);
        }
        if a.xmm5 != b.xmm5 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm5", a.xmm5, b.xmm5);
        }
        if a.xmm6 != b.xmm6 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm6", a.xmm6, b.xmm6);
        }
        if a.xmm7 != b.xmm7 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm7", a.xmm7, b.xmm7);
        }
        if a.xmm8 != b.xmm8 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm8", a.xmm8, b.xmm8);
        }
        if a.xmm9 != b.xmm9 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm9", a.xmm9, b.xmm9);
        }
        if a.xmm10 != b.xmm10 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm10", a.xmm10, b.xmm10);
        }
        if a.xmm11 != b.xmm11 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm11", a.xmm11, b.xmm11);
        }
        if a.xmm12 != b.xmm12 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm12", a.xmm12, b.xmm12);
        }
        if a.xmm13 != b.xmm13 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm13", a.xmm13, b.xmm13);
        }
        if a.xmm14 != b.xmm14 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm14", a.xmm14, b.xmm14);
        }
        if a.xmm15 != b.xmm15 {
            output = format!("{}{}: {:x} -> {:x} ", output, "xmm15", a.xmm15, b.xmm15);
        }
        if a.ymm0 != b.ymm0 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm0", a.ymm0, b.ymm0);
        }
        if a.ymm1 != b.ymm1 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm1", a.ymm1, b.ymm1);
        }
        if a.ymm2 != b.ymm2 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm2", a.ymm2, b.ymm2);
        }
        if a.ymm3 != b.ymm3 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm3", a.ymm3, b.ymm3);
        }
        if a.ymm4 != b.ymm4 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm4", a.ymm4, b.ymm4);
        }
        if a.ymm5 != b.ymm5 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm5", a.ymm5, b.ymm5);
        }
        if a.ymm6 != b.ymm6 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm6", a.ymm6, b.ymm6);
        }
        if a.ymm7 != b.ymm7 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm7", a.ymm7, b.ymm7);
        }
        if a.ymm8 != b.ymm8 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm8", a.ymm8, b.ymm8);
        }
        if a.ymm9 != b.ymm9 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm9", a.ymm9, b.ymm9);
        }
        if a.ymm10 != b.ymm10 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm10", a.ymm10, b.ymm10);
        }
        if a.ymm11 != b.ymm11 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm11", a.ymm11, b.ymm11);
        }
        if a.ymm12 != b.ymm12 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm12", a.ymm12, b.ymm12);
        }
        if a.ymm13 != b.ymm13 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm13", a.ymm13, b.ymm13);
        }
        if a.ymm14 != b.ymm14 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm14", a.ymm14, b.ymm14);
        }
        if a.ymm15 != b.ymm15 {
            output = format!("{}{}: {:x} -> {:x} ", output, "ymm15", a.ymm15, b.ymm15);
        }
        if a.mm0 != b.mm0 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm0", a.mm0, b.mm0);
        }
        if a.mm1 != b.mm1 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm1", a.mm1, b.mm1);
        }
        if a.mm2 != b.mm2 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm2", a.mm2, b.mm2);
        }
        if a.mm3 != b.mm3 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm3", a.mm3, b.mm3);
        }
        if a.mm4 != b.mm4 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm4", a.mm4, b.mm4);
        }
        if a.mm5 != b.mm5 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm5", a.mm5, b.mm5);
        }
        if a.mm6 != b.mm6 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm6", a.mm6, b.mm6);
        }
        if a.mm7 != b.mm7 {
            output = format!("{}{}: {:x} -> {:x} ", output, "mm7", a.mm7, b.mm7);
        }
        if a.gs != b.gs {
            output = format!("{}{}: {:x} -> {:x} ", output, "gs", a.gs, b.gs);
        }
        if a.fs != b.fs {
            output = format!("{}{}: {:x} -> {:x} ", output, "fs", a.fs, b.fs);
        }
        output
    }

    pub fn clear<const B: usize>(&mut self) {
        match B {
            64 => {
                self.rax = 0;
                self.rbx = 0;
                self.rcx = 0;
                self.rdx = 0;
                self.rsi = 0;
                self.rdi = 0;
                self.rbp = 0;
                self.rsp = 0;
                self.rip = 0;
                self.r8 = 0;
                self.r9 = 0;
                self.r10 = 0;
                self.r11 = 0;
                self.r12 = 0;
                self.r13 = 0;
                self.r14 = 0;
                self.r15 = 0;
            }
            32 => {
                self.set_eax(0);
                self.set_ebx(0);
                self.set_ecx(0);
                self.set_edx(0);
                self.set_esi(0);
                self.set_edi(0);
                self.set_esp(0);
                self.set_ebp(0);
                self.set_eip(0);
            }
            16 => {
                self.set_ax(0);
                self.set_bx(0);
                self.set_cx(0);
                self.set_dx(0);
                self.set_si(0);
                self.set_di(0);
                self.set_sp(0);
                self.set_bp(0);
                self.set_ip(0);
            }
            _ => unimplemented!(),
        }
    }

    pub fn rand(&mut self) {
        self.rax = rand::random::<u64>();
        self.rbx = rand::random::<u64>();
        self.rcx = rand::random::<u64>();
        self.rdx = rand::random::<u64>();
        self.rsi = rand::random::<u64>();
        self.rdi = rand::random::<u64>();
        self.rbp = rand::random::<u64>();
        self.rsp = rand::random::<u64>();
        self.rip = rand::random::<u64>();
    }

    pub fn sanitize32(&mut self) {
        let mask: u64 = 0x00000000ffffffff;
        self.rax &= mask;
        self.rbx &= mask;
        self.rcx &= mask;
        self.rdx &= mask;
        self.rsi &= mask;
        self.rdi &= mask;
        self.rbp &= mask;
        self.rsp &= mask;
        self.rip &= mask;
    }

    pub fn print<const B: usize>(&self) {
        log::info!("regs:");

        match B {
            64 => {
                log::info!("  rax: 0x{:x}", self.rax);
                log::info!("  rbx: 0x{:x}", self.rbx);
                log::info!("  rcx: 0x{:x}", self.rcx);
                log::info!("  rdx: 0x{:x}", self.rdx);
                log::info!("  rsi: 0x{:x}", self.rsi);
                log::info!("  rdi: 0x{:x}", self.rdi);
                log::info!("  rbp: 0x{:x}", self.rbp);
                log::info!("  rsp: 0x{:x}", self.rsp);
                log::info!("  rip: 0x{:x}", self.rip);
            }
            32 => {
                log::info!("  eax: 0x{:x}", self.get_eax());
                log::info!("  ebx: 0x{:x}", self.get_ebx());
                log::info!("  ecx: 0x{:x}", self.get_ecx());
                log::info!("  edx: 0x{:x}", self.get_edx());
                log::info!("  esi: 0x{:x}", self.get_esi());
                log::info!("  edi: 0x{:x}", self.get_edi());
                log::info!("  ebp: 0x{:x}", self.get_ebp());
                log::info!("  esp: 0x{:x}", self.get_esp());
                log::info!("  eip: 0x{:x}", self.get_eip());
            }
            _ => unimplemented!(),
        }

        log::info!("---");
    }

    pub fn print_xmm(&self) {
        log::info!("xmm regs:");
        log::info!("  xmm0: {}", self.xmm0);
        log::info!("  xmm1: {}", self.xmm1);
        log::info!("  xmm2: {}", self.xmm2);
        log::info!("  xmm3: {}", self.xmm3);
        log::info!("  xmm4: {}", self.xmm4);
        log::info!("  xmm5: {}", self.xmm5);
        log::info!("  xmm6: {}", self.xmm6);
        log::info!("  xmm7: {}", self.xmm7);
        log::info!("  xmm8: {}", self.xmm8);
        log::info!("  xmm9: {}", self.xmm9);
        log::info!("  xmm10: {}", self.xmm10);
        log::info!("  xmm11: {}", self.xmm11);
        log::info!("  xmm12: {}", self.xmm12);
        log::info!("  xmm13: {}", self.xmm13);
        log::info!("  xmm14: {}", self.xmm14);
        log::info!("  xmm15: {}", self.xmm15);
    }

    pub fn print_ymm(&self) {
        log::info!("ymm regs:");
        log::info!("  ymm0: {}", self.ymm0);
        log::info!("  ymm1: {}", self.ymm1);
        log::info!("  ymm2: {}", self.ymm2);
        log::info!("  ymm3: {}", self.ymm3);
        log::info!("  ymm4: {}", self.ymm4);
        log::info!("  ymm5: {}", self.ymm5);
        log::info!("  ymm6: {}", self.ymm6);
        log::info!("  ymm7: {}", self.ymm7);
        log::info!("  ymm8: {}", self.ymm8);
        log::info!("  ymm9: {}", self.ymm9);
        log::info!("  ymm10: {}", self.ymm10);
        log::info!("  ymm11: {}", self.ymm11);
        log::info!("  ymm12: {}", self.ymm12);
        log::info!("  ymm13: {}", self.ymm13);
        log::info!("  ymm14: {}", self.ymm14);
        log::info!("  ymm15: {}", self.ymm15);
    }

    // get 16 bits

    pub fn get_ax(&self) -> u64 {
        get_reg16!(self.rax);
    }

    pub fn get_bx(&self) -> u64 {
        get_reg16!(self.rbx);
    }

    pub fn get_cx(&self) -> u64 {
        get_reg16!(self.rcx);
    }

    pub fn get_dx(&self) -> u64 {
        get_reg16!(self.rdx);
    }

    pub fn get_si(&self) -> u64 {
        get_reg16!(self.rsi);
    }

    pub fn get_di(&self) -> u64 {
        get_reg16!(self.rdi);
    }

    pub fn get_sp(&self) -> u64 {
        get_reg16!(self.rsp);
    }

    pub fn get_bp(&self) -> u64 {
        get_reg16!(self.rbp);
    }

    pub fn get_ip(&self) -> u64 {
        get_reg16!(self.rip);
    }

    pub fn get_r8w(&self) -> u64 {
        get_reg16!(self.r8);
    }

    pub fn get_r9w(&self) -> u64 {
        get_reg16!(self.r9);
    }

    pub fn get_r10w(&self) -> u64 {
        get_reg16!(self.r10);
    }

    pub fn get_r11w(&self) -> u64 {
        get_reg16!(self.r11);
    }

    pub fn get_r12w(&self) -> u64 {
        get_reg16!(self.r12);
    }

    pub fn get_r13w(&self) -> u64 {
        get_reg16!(self.r13);
    }

    pub fn get_r14w(&self) -> u64 {
        get_reg16!(self.r14);
    }

    pub fn get_r15w(&self) -> u64 {
        get_reg16!(self.r15);
    }

    // get 8bits

    pub fn get_ah(&self) -> u64 {
        get_reg8h!(self.rax);
    }

    pub fn get_al(&self) -> u64 {
        get_reg8l!(self.rax);
    }

    pub fn get_bh(&self) -> u64 {
        get_reg8h!(self.rbx);
    }

    pub fn get_bl(&self) -> u64 {
        get_reg8l!(self.rbx);
    }

    pub fn get_ch(&self) -> u64 {
        get_reg8h!(self.rcx);
    }

    pub fn get_cl(&self) -> u64 {
        get_reg8l!(self.rcx);
    }

    pub fn get_dh(&self) -> u64 {
        get_reg8h!(self.rdx);
    }

    pub fn get_dl(&self) -> u64 {
        get_reg8l!(self.rdx);
    }

    pub fn get_r8l(&self) -> u64 {
        get_reg8l!(self.r8);
    }

    pub fn get_r9l(&self) -> u64 {
        get_reg8l!(self.r9);
    }

    pub fn get_r10l(&self) -> u64 {
        get_reg8l!(self.r10);
    }

    pub fn get_r11l(&self) -> u64 {
        get_reg8l!(self.r11);
    }

    pub fn get_r12l(&self) -> u64 {
        get_reg8l!(self.r12);
    }

    pub fn get_r13l(&self) -> u64 {
        get_reg8l!(self.r13);
    }

    pub fn get_r14l(&self) -> u64 {
        get_reg8l!(self.r14);
    }

    pub fn get_r15l(&self) -> u64 {
        get_reg8l!(self.r15);
    }

    pub fn get_r8h(&self) -> u64 {
        get_reg8h!(self.r8);
    }

    pub fn get_r9h(&self) -> u64 {
        get_reg8h!(self.r9);
    }

    pub fn get_r10h(&self) -> u64 {
        get_reg8h!(self.r10);
    }

    pub fn get_r11h(&self) -> u64 {
        get_reg8h!(self.r11);
    }

    pub fn get_r12h(&self) -> u64 {
        get_reg8h!(self.r12);
    }

    pub fn get_r13h(&self) -> u64 {
        get_reg8h!(self.r13);
    }

    pub fn get_r14h(&self) -> u64 {
        get_reg8h!(self.r14);
    }

    pub fn get_r15h(&self) -> u64 {
        get_reg8h!(self.r15);
    }

    pub fn get_sil(&self) -> u64 {
        get_reg8l!(self.rsi);
    }

    pub fn get_dil(&self) -> u64 {
        get_reg8l!(self.rdi);
    }

    pub fn get_bpl(&self) -> u64 {
        get_reg8l!(self.rbp);
    }

    pub fn get_spl(&self) -> u64 {
        get_reg8l!(self.rsp);
    }

    // get 32bits

    pub fn get_eax(&self) -> u64 {
        get_reg32l!(self.rax);
    }

    pub fn get_ebx(&self) -> u64 {
        get_reg32l!(self.rbx);
    }

    pub fn get_ecx(&self) -> u64 {
        get_reg32l!(self.rcx);
    }

    pub fn get_edx(&self) -> u64 {
        get_reg32l!(self.rdx);
    }

    pub fn get_esi(&self) -> u64 {
        get_reg32l!(self.rsi);
    }

    pub fn get_edi(&self) -> u64 {
        get_reg32l!(self.rdi);
    }

    pub fn get_esp(&self) -> u64 {
        get_reg32l!(self.rsp);
    }

    pub fn get_ebp(&self) -> u64 {
        get_reg32l!(self.rbp);
    }

    pub fn get_eip(&self) -> u64 {
        get_reg32l!(self.rip);
    }

    pub fn get_r8d(&self) -> u64 {
        get_reg32l!(self.r8);
    }

    pub fn get_r9d(&self) -> u64 {
        get_reg32l!(self.r9);
    }

    pub fn get_r10d(&self) -> u64 {
        get_reg32l!(self.r10);
    }

    pub fn get_r11d(&self) -> u64 {
        get_reg32l!(self.r11);
    }

    pub fn get_r12d(&self) -> u64 {
        get_reg32l!(self.r12);
    }

    pub fn get_r13d(&self) -> u64 {
        get_reg32l!(self.r13);
    }

    pub fn get_r14d(&self) -> u64 {
        get_reg32l!(self.r14);
    }

    pub fn get_r15d(&self) -> u64 {
        get_reg32l!(self.r15);
    }

    // get 32-bits (upper)
    pub fn get_r8u(&self) -> u64 {
        get_reg32h!(self.r8);
    }

    pub fn get_r9u(&self) -> u64 {
        get_reg32h!(self.r9);
    }

    pub fn get_r10u(&self) -> u64 {
        get_reg32h!(self.r10);
    }

    pub fn get_r11u(&self) -> u64 {
        get_reg32h!(self.r11);
    }

    pub fn get_r12u(&self) -> u64 {
        get_reg32h!(self.r12);
    }

    pub fn get_r13u(&self) -> u64 {
        get_reg32h!(self.r13);
    }

    pub fn get_r14u(&self) -> u64 {
        get_reg32h!(self.r14);
    }

    pub fn get_r15u(&self) -> u64 {
        get_reg32h!(self.r15);
    }

    // set 16bits

    pub fn set_ax(&mut self, val: u64) {
        set_reg16!(self.rax, val);
    }

    pub fn set_bx(&mut self, val: u64) {
        set_reg16!(self.rbx, val);
    }

    pub fn set_cx(&mut self, val: u64) {
        set_reg16!(self.rcx, val);
    }

    pub fn set_dx(&mut self, val: u64) {
        set_reg16!(self.rdx, val);
    }

    pub fn set_si(&mut self, val: u64) {
        set_reg16!(self.rsi, val);
    }

    pub fn set_di(&mut self, val: u64) {
        set_reg16!(self.rdi, val);
    }

    pub fn set_sp(&mut self, val: u64) {
        set_reg16!(self.rsp, val);
    }

    pub fn set_bp(&mut self, val: u64) {
        set_reg16!(self.rbp, val);
    }

    pub fn set_ip(&mut self, val: u64) {
        set_reg16!(self.rip, val);
    }

    pub fn set_r8w(&mut self, val: u64) {
        set_reg16!(self.r8, val);
    }

    pub fn set_r9w(&mut self, val: u64) {
        set_reg16!(self.r9, val);
    }

    pub fn set_r10w(&mut self, val: u64) {
        set_reg16!(self.r10, val);
    }

    pub fn set_r11w(&mut self, val: u64) {
        set_reg16!(self.r11, val);
    }

    pub fn set_r12w(&mut self, val: u64) {
        set_reg16!(self.r12, val);
    }

    pub fn set_r13w(&mut self, val: u64) {
        set_reg16!(self.r13, val);
    }

    pub fn set_r14w(&mut self, val: u64) {
        set_reg16!(self.r14, val);
    }

    pub fn set_r15w(&mut self, val: u64) {
        set_reg16!(self.r15, val);
    }

    // set 32bits

    pub fn set_eax(&mut self, val: u64) {
        set_reg32!(self.rax, val);
    }

    pub fn set_ebx(&mut self, val: u64) {
        set_reg32!(self.rbx, val);
    }

    pub fn set_ecx(&mut self, val: u64) {
        set_reg32!(self.rcx, val);
    }

    pub fn set_edx(&mut self, val: u64) {
        set_reg32!(self.rdx, val);
    }

    pub fn set_esi(&mut self, val: u64) {
        set_reg32!(self.rsi, val);
    }

    pub fn set_edi(&mut self, val: u64) {
        set_reg32!(self.rdi, val);
    }

    pub fn set_ebp(&mut self, val: u64) {
        set_reg32!(self.rbp, val);
    }

    pub fn set_esp(&mut self, val: u64) {
        set_reg32!(self.rsp, val);
    }

    pub fn set_eip(&mut self, val: u64) {
        set_reg32!(self.rip, val);
    }

    pub fn set_r8d(&mut self, val: u64) {
        set_reg32!(self.r8, val);
    }

    pub fn set_r9d(&mut self, val: u64) {
        set_reg32!(self.r9, val);
    }

    pub fn set_r10d(&mut self, val: u64) {
        set_reg32!(self.r10, val);
    }

    pub fn set_r11d(&mut self, val: u64) {
        set_reg32!(self.r11, val);
    }

    pub fn set_r12d(&mut self, val: u64) {
        set_reg32!(self.r12, val);
    }

    pub fn set_r13d(&mut self, val: u64) {
        set_reg32!(self.r13, val);
    }

    pub fn set_r14d(&mut self, val: u64) {
        set_reg32!(self.r14, val);
    }

    pub fn set_r15d(&mut self, val: u64) {
        set_reg32!(self.r15, val);
    }

    // set 8bits

    pub fn set_ah(&mut self, val: u64) {
        set_reg8h!(self.rax, val);
    }

    pub fn set_bh(&mut self, val: u64) {
        set_reg8h!(self.rbx, val);
    }

    pub fn set_ch(&mut self, val: u64) {
        set_reg8h!(self.rcx, val);
    }

    pub fn set_dh(&mut self, val: u64) {
        set_reg8h!(self.rdx, val);
    }

    pub fn set_al(&mut self, val: u64) {
        set_reg8l!(self.rax, val);
    }

    pub fn set_bl(&mut self, val: u64) {
        set_reg8l!(self.rbx, val);
    }

    pub fn set_cl(&mut self, val: u64) {
        set_reg8l!(self.rcx, val);
    }

    pub fn set_dl(&mut self, val: u64) {
        set_reg8l!(self.rdx, val);
    }

    pub fn set_r8l(&mut self, val: u64) {
        set_reg8l!(self.r8, val);
    }

    pub fn set_r9l(&mut self, val: u64) {
        set_reg8l!(self.r9, val);
    }

    pub fn set_r10l(&mut self, val: u64) {
        set_reg8l!(self.r10, val);
    }

    pub fn set_r11l(&mut self, val: u64) {
        set_reg8l!(self.r11, val);
    }

    pub fn set_r12l(&mut self, val: u64) {
        set_reg8l!(self.r12, val);
    }

    pub fn set_r13l(&mut self, val: u64) {
        set_reg8l!(self.r13, val);
    }

    pub fn set_r14l(&mut self, val: u64) {
        set_reg8l!(self.r14, val);
    }

    pub fn set_r15l(&mut self, val: u64) {
        set_reg8l!(self.r15, val);
    }

    pub fn set_r8h(&mut self, val: u64) {
        set_reg8h!(self.r8, val);
    }

    pub fn set_r9h(&mut self, val: u64) {
        set_reg8h!(self.r9, val);
    }

    pub fn set_r10h(&mut self, val: u64) {
        set_reg8h!(self.r10, val);
    }

    pub fn set_r11h(&mut self, val: u64) {
        set_reg8h!(self.r11, val);
    }

    pub fn set_r12h(&mut self, val: u64) {
        set_reg8h!(self.r12, val);
    }

    pub fn set_r13h(&mut self, val: u64) {
        set_reg8h!(self.r13, val);
    }

    pub fn set_r14h(&mut self, val: u64) {
        set_reg8h!(self.r14, val);
    }

    pub fn set_r15h(&mut self, val: u64) {
        set_reg8h!(self.r15, val);
    }

    pub fn set_sil(&mut self, val: u64) {
        set_reg8l!(self.rsi, val);
    }

    pub fn set_dil(&mut self, val: u64) {
        set_reg8l!(self.rdi, val);
    }

    pub fn set_bpl(&mut self, val: u64) {
        set_reg8l!(self.rbp, val);
    }

    pub fn set_spl(&mut self, val: u64) {
        set_reg8l!(self.rsp, val);
    }

    // xmm

    pub fn is_xmm(&self, reg: Register) -> bool {
        let result = matches!(
            reg,
            Register::XMM0
                | Register::XMM1
                | Register::XMM2
                | Register::XMM3
                | Register::XMM4
                | Register::XMM5
                | Register::XMM6
                | Register::XMM7
                | Register::XMM8
                | Register::XMM9
                | Register::XMM10
                | Register::XMM11
                | Register::XMM12
                | Register::XMM13
                | Register::XMM14
                | Register::XMM15
                | Register::MM0
                | Register::MM1
                | Register::MM2
                | Register::MM3
                | Register::MM4
                | Register::MM5
                | Register::MM6
                | Register::MM7
        );
        result
    }

    pub fn get_xmm_reg(&self, reg: Register) -> u128 {
        let value = match reg {
            Register::XMM0 => self.xmm0,
            Register::XMM1 => self.xmm1,
            Register::XMM2 => self.xmm2,
            Register::XMM3 => self.xmm3,
            Register::XMM4 => self.xmm4,
            Register::XMM5 => self.xmm5,
            Register::XMM6 => self.xmm6,
            Register::XMM7 => self.xmm7,
            Register::XMM8 => self.xmm8,
            Register::XMM9 => self.xmm9,
            Register::XMM10 => self.xmm10,
            Register::XMM11 => self.xmm11,
            Register::XMM12 => self.xmm12,
            Register::XMM13 => self.xmm13,
            Register::XMM14 => self.xmm14,
            Register::XMM15 => self.xmm15,
            Register::MM0 => self.mm0,
            Register::MM1 => self.mm1,
            Register::MM2 => self.mm2,
            Register::MM3 => self.mm3,
            Register::MM4 => self.mm4,
            Register::MM5 => self.mm5,
            Register::MM6 => self.mm6,
            Register::MM7 => self.mm7,

            _ => unimplemented!("SSE  XMM register: {:?} ", reg),
        };
        value
    }

    pub fn set_xmm_reg(&mut self, reg: Register, value: u128) {
        match reg {
            Register::XMM0 => self.xmm0 = value,
            Register::XMM1 => self.xmm1 = value,
            Register::XMM2 => self.xmm2 = value,
            Register::XMM3 => self.xmm3 = value,
            Register::XMM4 => self.xmm4 = value,
            Register::XMM5 => self.xmm5 = value,
            Register::XMM6 => self.xmm6 = value,
            Register::XMM7 => self.xmm7 = value,
            Register::XMM8 => self.xmm8 = value,
            Register::XMM9 => self.xmm9 = value,
            Register::XMM10 => self.xmm10 = value,
            Register::XMM11 => self.xmm11 = value,
            Register::XMM12 => self.xmm12 = value,
            Register::XMM13 => self.xmm13 = value,
            Register::XMM14 => self.xmm14 = value,
            Register::XMM15 => self.xmm15 = value,
            Register::MM0 => self.mm0 = value,
            Register::MM1 => self.mm1 = value,
            Register::MM2 => self.mm2 = value,
            Register::MM3 => self.mm3 = value,
            Register::MM4 => self.mm4 = value,
            Register::MM5 => self.mm5 = value,
            Register::MM6 => self.mm6 = value,
            Register::MM7 => self.mm7 = value,

            _ => unimplemented!("SSE  XMM register: {:?} ", reg),
        };
    }

    // ymm

    pub fn is_ymm(&self, reg: Register) -> bool {
        let result = matches!(
            reg,
            Register::YMM0
                | Register::YMM1
                | Register::YMM2
                | Register::YMM3
                | Register::YMM4
                | Register::YMM5
                | Register::YMM6
                | Register::YMM7
                | Register::YMM8
                | Register::YMM9
                | Register::YMM10
                | Register::YMM11
                | Register::YMM12
                | Register::YMM13
                | Register::YMM14
                | Register::YMM15
                | Register::MM0
                | Register::MM1
                | Register::MM2
                | Register::MM3
                | Register::MM4
                | Register::MM5
                | Register::MM6
                | Register::MM7
        );
        result
    }

    pub fn get_ymm_reg(&self, reg: Register) -> U256 {
        let value = match reg {
            Register::YMM0 => self.ymm0,
            Register::YMM1 => self.ymm1,
            Register::YMM2 => self.ymm2,
            Register::YMM3 => self.ymm3,
            Register::YMM4 => self.ymm4,
            Register::YMM5 => self.ymm5,
            Register::YMM6 => self.ymm6,
            Register::YMM7 => self.ymm7,
            Register::YMM8 => self.ymm8,
            Register::YMM9 => self.ymm9,
            Register::YMM10 => self.ymm10,
            Register::YMM11 => self.ymm11,
            Register::YMM12 => self.ymm12,
            Register::YMM13 => self.ymm13,
            Register::YMM14 => self.ymm14,
            Register::YMM15 => self.ymm15,

            _ => unimplemented!("SSE  YMM register: {:?} ", reg),
        };
        value
    }

    pub fn set_ymm_reg(&mut self, reg: Register, value: U256) {
        match reg {
            Register::YMM0 => self.ymm0 = value,
            Register::YMM1 => self.ymm1 = value,
            Register::YMM2 => self.ymm2 = value,
            Register::YMM3 => self.ymm3 = value,
            Register::YMM4 => self.ymm4 = value,
            Register::YMM5 => self.ymm5 = value,
            Register::YMM6 => self.ymm6 = value,
            Register::YMM7 => self.ymm7 = value,
            Register::YMM8 => self.ymm8 = value,
            Register::YMM9 => self.ymm9 = value,
            Register::YMM10 => self.ymm10 = value,
            Register::YMM11 => self.ymm11 = value,
            Register::YMM12 => self.ymm12 = value,
            Register::YMM13 => self.ymm13 = value,
            Register::YMM14 => self.ymm14 = value,
            Register::YMM15 => self.ymm15 = value,

            _ => unimplemented!("SSE  YMM register: {:?} ", reg),
        };
    }

    pub fn get_reg(&self, reg: Register) -> u64 {
        let value = match reg {
            // 64bits
            Register::RAX => self.rax,
            Register::RBX => self.rbx,
            Register::RCX => self.rcx,
            Register::RDX => self.rdx,
            Register::RSI => self.rsi,
            Register::RDI => self.rdi,
            Register::RSP => self.rsp,
            Register::RBP => self.rbp,
            Register::RIP => self.rip,
            Register::R8 => self.r8,
            Register::R9 => self.r9,
            Register::R10 => self.r10,
            Register::R11 => self.r11,
            Register::R12 => self.r12,
            Register::R13 => self.r13,
            Register::R14 => self.r14,
            Register::R15 => self.r15,
            // 32bits
            Register::EAX => self.get_eax(),
            Register::EBX => self.get_ebx(),
            Register::ECX => self.get_ecx(),
            Register::EDX => self.get_edx(),
            Register::ESI => self.get_esi(),
            Register::EDI => self.get_edi(),
            Register::ESP => self.get_esp(),
            Register::EBP => self.get_ebp(),
            Register::EIP => self.get_eip(),
            Register::R8D => self.get_r8d(),
            Register::R9D => self.get_r9d(),
            Register::R10D => self.get_r10d(),
            Register::R11D => self.get_r11d(),
            Register::R12D => self.get_r12d(),
            Register::R13D => self.get_r13d(),
            Register::R14D => self.get_r14d(),
            Register::R15D => self.get_r15d(),
            // 16bits
            Register::AX => self.get_ax(),
            Register::BX => self.get_bx(),
            Register::CX => self.get_cx(),
            Register::DX => self.get_dx(),
            Register::SI => self.get_si(),
            Register::DI => self.get_di(),
            Register::BP => self.get_bp(),
            Register::SP => self.get_sp(),
            Register::R8W => self.get_r8w(),
            Register::R9W => self.get_r9w(),
            Register::R10W => self.get_r10w(),
            Register::R11W => self.get_r11w(),
            Register::R12W => self.get_r12w(),
            Register::R13W => self.get_r13w(),
            Register::R14W => self.get_r14w(),
            Register::R15W => self.get_r15w(),
            // 8bits
            Register::AH => self.get_ah(),
            Register::AL => self.get_al(),
            Register::BH => self.get_bh(),
            Register::BL => self.get_bl(),
            Register::CH => self.get_ch(),
            Register::CL => self.get_cl(),
            Register::DH => self.get_dh(),
            Register::DL => self.get_dl(),
            Register::R8L => self.get_r8l(),
            Register::R9L => self.get_r9l(),
            Register::R10L => self.get_r10l(),
            Register::R11L => self.get_r11l(),
            Register::R12L => self.get_r12l(),
            Register::R13L => self.get_r13l(),
            Register::R14L => self.get_r14l(),
            Register::R15L => self.get_r15l(),
            Register::SIL => self.get_sil(),
            Register::DIL => self.get_dil(),
            Register::BPL => self.get_bpl(),
            Register::SPL => self.get_spl(),

            Register::ST0 => 0,
            Register::ST1 => 1,
            Register::ST2 => 2,
            Register::ST3 => 3,
            Register::ST4 => 4,
            Register::ST5 => 5,
            Register::ST6 => 6,
            Register::ST7 => 7,

            // segmets
            Register::DS => 0,
            Register::CS => 0,
            Register::SS => 0,
            Register::ES => 0,
            Register::FS => 0,
            Register::GS => 0,
            Register::DR0 => 0,
            Register::DR1 => 0,
            Register::DR2 => 0,
            Register::DR3 => 0,
            Register::DR4 => 0,
            Register::DR5 => 0,
            Register::DR6 => 0,
            Register::DR7 => 0,
            Register::CR0 => 0,
            Register::CR1 => 0,
            Register::CR2 => 0,
            Register::CR3 => 0,
            Register::CR4 => 0,
            Register::CR5 => 0,

            _ => unimplemented!("unimplemented register {:?}", reg),
        };

        value
    }

    pub fn set_reg(&mut self, reg: Register, value: u64) {
        match reg {
            // 64bits
            Register::RAX => self.rax = value,
            Register::RBX => self.rbx = value,
            Register::RCX => self.rcx = value,
            Register::RDX => self.rdx = value,
            Register::RSI => self.rsi = value,
            Register::RDI => self.rdi = value,
            Register::RSP => self.rsp = value,
            Register::RBP => self.rbp = value,
            Register::RIP => self.rip = value,
            Register::R8 => self.r8 = value,
            Register::R9 => self.r9 = value,
            Register::R10 => self.r10 = value,
            Register::R11 => self.r11 = value,
            Register::R12 => self.r12 = value,
            Register::R13 => self.r13 = value,
            Register::R14 => self.r14 = value,
            Register::R15 => self.r15 = value,
            // 32bits
            Register::EAX => self.set_eax(value),
            Register::EBX => self.set_ebx(value),
            Register::ECX => self.set_ecx(value),
            Register::EDX => self.set_edx(value),
            Register::ESI => self.set_esi(value),
            Register::EDI => self.set_edi(value),
            Register::ESP => self.set_esp(value),
            Register::EBP => self.set_ebp(value),
            Register::EIP => self.set_eip(value),
            Register::R8D => self.set_r8d(value),
            Register::R9D => self.set_r9d(value),
            Register::R10D => self.set_r10d(value),
            Register::R11D => self.set_r11d(value),
            Register::R12D => self.set_r12d(value),
            Register::R13D => self.set_r13d(value),
            Register::R14D => self.set_r14d(value),
            Register::R15D => self.set_r15d(value),
            // 16bits
            Register::AX => self.set_ax(value),
            Register::BX => self.set_bx(value),
            Register::CX => self.set_cx(value),
            Register::DX => self.set_dx(value),
            Register::SI => self.set_si(value),
            Register::DI => self.set_di(value),
            Register::SP => self.set_sp(value),
            Register::BP => self.set_bp(value),
            Register::R8W => self.set_r8w(value),
            Register::R9W => self.set_r9w(value),
            Register::R10W => self.set_r10w(value),
            Register::R11W => self.set_r11w(value),
            Register::R12W => self.set_r12w(value),
            Register::R13W => self.set_r13w(value),
            Register::R14W => self.set_r14w(value),
            Register::R15W => self.set_r15w(value),
            // 8bits
            Register::AH => self.set_ah(value),
            Register::AL => self.set_al(value),
            Register::BH => self.set_bh(value),
            Register::BL => self.set_bl(value),
            Register::CH => self.set_ch(value),
            Register::CL => self.set_cl(value),
            Register::DH => self.set_dh(value),
            Register::DL => self.set_dl(value),
            Register::R8L => self.set_r8l(value),
            Register::R9L => self.set_r9l(value),
            Register::R10L => self.set_r10l(value),
            Register::R11L => self.set_r11l(value),
            Register::R12L => self.set_r12l(value),
            Register::R13L => self.set_r13l(value),
            Register::R14L => self.set_r14l(value),
            Register::R15L => self.set_r15l(value),
            Register::SIL => self.set_sil(value),
            Register::DIL => self.set_dil(value),
            Register::BPL => self.set_bpl(value),
            Register::SPL => self.set_spl(value),
            // segments
            Register::SS => {}
            Register::ES => {}
            Register::FS => {}
            Register::GS => {}
            Register::DS => {}
            Register::DR0 => {}
            Register::DR1 => {}
            Register::DR2 => {}
            Register::DR3 => {}
            Register::DR4 => {}
            Register::DR5 => {}
            Register::DR6 => {}
            Register::DR7 => {}
            Register::CR0 => {}
            Register::CR1 => {}
            Register::CR2 => {}
            Register::CR3 => {}
            Register::CR4 => {}
            Register::CR5 => {}
            _ => unimplemented!("unimplemented register {:?}", reg),
        };
    }

    pub fn set_reg_by_name(&mut self, reg_name: &str, value: u64) {
        let reg = match reg_name {
            "rax" => Register::RAX,
            "rbx" => Register::RBX,
            "rcx" => Register::RCX,
            "rdx" => Register::RDX,
            "rsp" => Register::RSP,
            "rbp" => Register::RBP,
            "rsi" => Register::RSI,
            "rdi" => Register::RDI,
            "r8" => Register::R8,
            "r9" => Register::R9,
            "r10" => Register::R10,
            "r11" => Register::R11,
            "r12" => Register::R12,
            "r13" => Register::R13,
            "r14" => Register::R14,
            "r15" => Register::R15,
            _ => unimplemented!("unimplemented register {:?}", reg_name),
        };
        self.set_reg(reg, value);
    }

    pub fn is_fpu(&self, reg: Register) -> bool {
        matches!(
            reg,
            Register::ST0
                | Register::ST1
                | Register::ST2
                | Register::ST3
                | Register::ST4
                | Register::ST5
                | Register::ST6
                | Register::ST7
        )
    }

    pub fn get_size(&self, reg: Register) -> u32 {
        let sz: u32 = match reg {
            Register::RAX => 64,
            Register::RBX => 64,
            Register::RCX => 64,
            Register::RDX => 64,
            Register::RSI => 64,
            Register::RDI => 64,
            Register::RSP => 64,
            Register::RBP => 64,
            Register::RIP => 64,
            Register::R8 => 64,
            Register::R9 => 64,
            Register::R10 => 64,
            Register::R11 => 64,
            Register::R12 => 64,
            Register::R13 => 64,
            Register::R14 => 64,
            Register::R15 => 64,
            Register::EAX => 32,
            Register::EBX => 32,
            Register::ECX => 32,
            Register::EDX => 32,
            Register::ESI => 32,
            Register::EDI => 32,
            Register::ESP => 32,
            Register::EBP => 32,
            Register::EIP => 32,
            Register::R8D => 32,
            Register::R9D => 32,
            Register::R10D => 32,
            Register::R11D => 32,
            Register::R12D => 32,
            Register::R13D => 32,
            Register::R14D => 32,
            Register::R15D => 32,
            Register::AX => 16,
            Register::BX => 16,
            Register::CX => 16,
            Register::DX => 16,
            Register::BP => 16,
            Register::SP => 16,
            Register::SI => 16,
            Register::DI => 16,
            Register::R8W => 16,
            Register::R9W => 16,
            Register::R10W => 16,
            Register::R11W => 16,
            Register::R12W => 16,
            Register::R13W => 16,
            Register::R14W => 16,
            Register::R15W => 16,
            Register::AH => 8,
            Register::AL => 8,
            Register::BH => 8,
            Register::BL => 8,
            Register::CH => 8,
            Register::CL => 8,
            Register::DH => 8,
            Register::DL => 8,
            Register::R8L => 8,
            Register::R9L => 8,
            Register::R10L => 8,
            Register::R11L => 8,
            Register::R12L => 8,
            Register::R13L => 8,
            Register::R14L => 8,
            Register::R15L => 8,
            Register::SIL => 8,
            Register::DIL => 8,
            Register::BPL => 8,
            Register::SPL => 8,
            // sse
            Register::XMM0 => 128,
            Register::XMM1 => 128,
            Register::XMM2 => 128,
            Register::XMM3 => 128,
            Register::XMM4 => 128,
            Register::XMM5 => 128,
            Register::XMM6 => 128,
            Register::XMM7 => 128,
            Register::XMM8 => 128,
            Register::XMM9 => 128,
            Register::XMM10 => 128,
            Register::XMM11 => 128,
            Register::XMM12 => 128,
            Register::XMM13 => 128,
            Register::XMM14 => 128,
            Register::XMM15 => 128,
            Register::YMM0 => 256,
            Register::YMM1 => 256,
            Register::YMM2 => 256,
            Register::YMM3 => 256,
            Register::YMM4 => 256,
            Register::YMM5 => 256,
            Register::YMM6 => 256,
            Register::YMM7 => 256,
            Register::YMM8 => 256,
            Register::YMM9 => 256,
            Register::YMM10 => 256,
            Register::YMM11 => 256,
            Register::YMM12 => 256,
            Register::YMM13 => 256,
            Register::YMM14 => 256,
            Register::YMM15 => 256,
            Register::MM0 => 128,
            Register::MM1 => 128,
            Register::MM2 => 128,
            Register::MM3 => 128,
            Register::MM4 => 128,
            Register::MM5 => 128,
            Register::MM6 => 128,
            Register::MM7 => 128,
            _ => unimplemented!("unimplemented register {:?}", reg),
        };

        sz
    }

    pub fn get_xmm_by_name(&self, reg_name: &str) -> u128 {
        match reg_name {
            "xmm0" => self.xmm0,
            "xmm1" => self.xmm1,
            "xmm2" => self.xmm2,
            "xmm3" => self.xmm3,
            "xmm4" => self.xmm4,
            "xmm5" => self.xmm5,
            "xmm6" => self.xmm6,
            "xmm7" => self.xmm7,
            "xmm8" => self.xmm8,
            "xmm9" => self.xmm9,
            "xmm10" => self.xmm10,
            "xmm11" => self.xmm11,
            "xmm12" => self.xmm12,
            "xmm13" => self.xmm13,
            "xmm14" => self.xmm14,
            "xmm15" => self.xmm15,
            &_ => unimplemented!("weird register name parsed {}", reg_name),
        }
    }

    pub fn get_ymm_by_name(&self, reg_name: &str) -> U256 {
        match reg_name {
            "ymm0" => self.ymm0,
            "ymm1" => self.ymm1,
            "ymm2" => self.ymm2,
            "ymm3" => self.ymm3,
            "ymm4" => self.ymm4,
            "ymm5" => self.ymm5,
            "ymm6" => self.ymm6,
            "ymm7" => self.ymm7,
            "ymm8" => self.ymm8,
            "ymm9" => self.ymm9,
            "ymm10" => self.ymm10,
            "ymm11" => self.ymm11,
            "ymm12" => self.ymm12,
            "ymm13" => self.ymm13,
            "ymm14" => self.ymm14,
            "ymm15" => self.ymm15,
            &_ => unimplemented!("weird register name parsed {}", reg_name),
        }
    }

    pub fn get_by_name(&self, reg_name: &str) -> u64 {
        match reg_name {
            // 64bits
            "rax" => self.rax,
            "rbx" => self.rbx,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rbp" => self.rbp,
            "rsp" => self.rsp,
            "rip" => self.rip,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            // 32bits
            "eax" => self.get_eax(),
            "ebx" => self.get_ebx(),
            "ecx" => self.get_ecx(),
            "edx" => self.get_edx(),
            "esi" => self.get_esi(),
            "edi" => self.get_edi(),
            "ebp" => self.get_ebp(),
            "esp" => self.get_esp(),
            "eip" => self.get_eip(),
            "r8d" => self.get_r8d(),
            "r9d" => self.get_r9d(),
            "r10d" => self.get_r10d(),
            "r11d" => self.get_r11d(),
            "r12d" => self.get_r12d(),
            "r13d" => self.get_r13d(),
            "r14d" => self.get_r14d(),
            "r15d" => self.get_r15d(),
            // 16bits
            "ax" => self.get_ax(),
            "bx" => self.get_bx(),
            "cx" => self.get_cx(),
            "dx" => self.get_dx(),
            "si" => self.get_si(),
            "di" => self.get_di(),
            "bp" => self.get_bp(),
            "sp" => self.get_sp(),
            "r8w" => self.get_r8w(),
            "r9w" => self.get_r9w(),
            "r10w" => self.get_r10w(),
            "r11w" => self.get_r11w(),
            "r12w" => self.get_r12w(),
            "r13w" => self.get_r13w(),
            "r14w" => self.get_r14w(),
            "r15w" => self.get_r15w(),
            // 8bits
            "ah" => self.get_ah(),
            "al" => self.get_al(),
            "bh" => self.get_bh(),
            "bl" => self.get_bl(),
            "ch" => self.get_ch(),
            "cl" => self.get_cl(),
            "dh" => self.get_dh(),
            "dl" => self.get_dl(),
            "r8l" => self.get_r8l(),
            "r9l" => self.get_r9l(),
            "r10l" => self.get_r10l(),
            "r11l" => self.get_r11l(),
            "r12l" => self.get_r12l(),
            "r13l" => self.get_r13l(),
            "r14l" => self.get_r14l(),
            "r15l" => self.get_r15l(),
            "sil" => self.get_sil(),
            "dil" => self.get_dil(),
            "bpl" => self.get_bpl(),
            "spl" => self.get_spl(),
            &_ => unimplemented!("weird register name parsed {}", reg_name),
        }
    }

    pub fn set_xmm_by_name(&mut self, reg_name: &str, value: u128) {
        match reg_name {
            "xmm0" => self.xmm0 = value,
            "xmm1" => self.xmm1 = value,
            "xmm2" => self.xmm2 = value,
            "xmm3" => self.xmm3 = value,
            "xmm4" => self.xmm4 = value,
            "xmm5" => self.xmm5 = value,
            "xmm6" => self.xmm6 = value,
            "xmm7" => self.xmm7 = value,
            "xmm8" => self.xmm8 = value,
            "xmm9" => self.xmm9 = value,
            "xmm10" => self.xmm10 = value,
            "xmm11" => self.xmm11 = value,
            "xmm12" => self.xmm12 = value,
            "xmm13" => self.xmm13 = value,
            "xmm14" => self.xmm14 = value,
            "xmm15" => self.xmm15 = value,
            &_ => unimplemented!("weird register name parsed {}", reg_name),
        }
    }

    pub fn set_ymm_by_name(&mut self, reg_name: &str, value: U256) {
        match reg_name {
            "ymm0" => self.ymm0 = value,
            "ymm1" => self.ymm1 = value,
            "ymm2" => self.ymm2 = value,
            "ymm3" => self.ymm3 = value,
            "ymm4" => self.ymm4 = value,
            "ymm5" => self.ymm5 = value,
            "ymm6" => self.ymm6 = value,
            "ymm7" => self.ymm7 = value,
            "ymm8" => self.ymm8 = value,
            "ymm9" => self.ymm9 = value,
            "ymm10" => self.ymm10 = value,
            "ymm11" => self.ymm11 = value,
            "ymm12" => self.ymm12 = value,
            "ymm13" => self.ymm13 = value,
            "ymm14" => self.ymm14 = value,
            "ymm15" => self.ymm15 = value,
            &_ => unimplemented!("weird register name parsed {}", reg_name),
        }
    }

    pub fn set_by_name(&mut self, reg_name: &str, value: u64) {
        match reg_name {
            // 64bits
            "rax" => self.rax = value,
            "rbx" => self.rbx = value,
            "rcx" => self.rcx = value,
            "rdx" => self.rdx = value,
            "rsi" => self.rsi = value,
            "rdi" => self.rdi = value,
            "rbp" => self.rbp = value,
            "rsp" => self.rsp = value,
            "rip" => self.rip = value,
            "r8" => self.r8 = value,
            "r9" => self.r9 = value,
            "r10" => self.r10 = value,
            "r11" => self.r11 = value,
            "r12" => self.r12 = value,
            "r13" => self.r13 = value,
            "r14" => self.r14 = value,
            "r15" => self.r15 = value,
            // 32bits
            "eax" => self.set_eax(value),
            "ebx" => self.set_ebx(value),
            "ecx" => self.set_ecx(value),
            "edx" => self.set_edx(value),
            "esi" => self.set_esi(value),
            "edi" => self.set_edi(value),
            "ebp" => self.set_ebp(value),
            "esp" => self.set_esp(value),
            "eip" => self.set_eip(value),
            "r8d" => self.set_r8d(value),
            "r9d" => self.set_r9d(value),
            "r10d" => self.set_r10d(value),
            "r11d" => self.set_r11d(value),
            "r12d" => self.set_r12d(value),
            "r13d" => self.set_r13d(value),
            "r14d" => self.set_r14d(value),
            "r15d" => self.set_r15d(value),
            // 16bits
            "ax" => self.set_ax(value),
            "bx" => self.set_bx(value),
            "cx" => self.set_cx(value),
            "dx" => self.set_dx(value),
            "di" => self.set_di(value),
            "si" => self.set_si(value),
            "bp" => self.set_bp(value),
            "sp" => self.set_sp(value),
            "r8w" => self.set_r8w(value),
            "r9w" => self.set_r9w(value),
            "r10w" => self.set_r10w(value),
            "r11w" => self.set_r11w(value),
            "r12w" => self.set_r12w(value),
            "r13w" => self.set_r13w(value),
            "r14w" => self.set_r14w(value),
            "r15w" => self.set_r15w(value),
            // 8bits
            "ah" => self.set_ah(value),
            "al" => self.set_al(value),
            "bh" => self.set_bh(value),
            "bl" => self.set_bl(value),
            "ch" => self.set_ch(value),
            "cl" => self.set_cl(value),
            "dh" => self.set_dh(value),
            "dl" => self.set_dl(value),
            "r8l" => self.set_r8l(value),
            "r9l" => self.set_r9l(value),
            "r10l" => self.set_r10l(value),
            "r11l" => self.set_r11l(value),
            "r12l" => self.set_r12l(value),
            "r13l" => self.set_r13l(value),
            "r14l" => self.set_r14l(value),
            "r15l" => self.set_r15l(value),
            "sil" => self.set_sil(value),
            "dil" => self.set_dil(value),
            "bpl" => self.set_bpl(value),
            "spl" => self.set_spl(value),
            &_ => panic!("weird register name parsed {}", reg_name),
        }
    }

    pub fn show_reg64(&self, maps: &Maps, sreg: &str, value: u64, pos: u64) {
        if maps.is_mapped(value) {
            let mut s = maps.read_string(value);
            if s.len() < 2 {
                s = maps.read_wide_string(value);
            }

            maps.filter_string(&mut s);

            if s.len() > 50 {
                s = s[..50].to_string();
            }

            let name = match maps.get_addr_name(value) {
                Some(v) => format!("({})", v),
                None => "".to_string(),
            };

            if s.len() > 1 {
                if pos > 0 {
                    log::info!(
                        "\t{} {}: 0x{:x} {} '{}' {}",
                        pos,
                        sreg,
                        value,
                        value,
                        s,
                        name
                    );
                } else {
                    log::info!("\t{}: 0x{:x} {} '{}' {}", sreg, value, value, s, name);
                }
            } else if pos > 0 {
                log::info!("\t{} {}: 0x{:x} {} {}", pos, sreg, value, value, name);
            } else {
                log::info!("\t{}: 0x{:x} {} {}", sreg, value, value, name);
            }
        } else if pos > 0 {
            log::info!("\t{} {}: 0x{:x} {}", pos, sreg, value, value);
        } else {
            log::info!("\t{}: 0x{:x} {}", sreg, value, value);
        }
    }

    pub fn show_reg32(&self, maps: &Maps, sreg: &str, value: u64, pos: u64) {
        if maps.is_mapped(value) {
            let mut s = maps.read_string(value);
            if s.len() < 2 {
                s = maps.read_wide_string(value);
            }

            maps.filter_string(&mut s);

            if s.len() > 50 {
                s = s[..50].to_string();
            }

            let name = match maps.get_addr_name(value) {
                Some(v) => format!("({})", v),
                None => "".to_string(),
            };

            if s.len() > 1 {
                if pos > 0 {
                    log::info!(
                        "\t{} {}: 0x{:x} {} '{}' {}",
                        pos,
                        sreg,
                        value as u32,
                        value as u32,
                        s,
                        name
                    );
                } else {
                    log::info!(
                        "\t{}: 0x{:x} {} '{}' {}",
                        sreg,
                        value as u32,
                        value as u32,
                        s,
                        name
                    );
                }
            } else if pos > 0 {
                log::info!(
                    "\t{} {}: 0x{:x} {} {}",
                    pos,
                    sreg,
                    value as u32,
                    value as u32,
                    name
                );
            } else {
                log::info!("\t{}: 0x{:x} {} {}", sreg, value as u32, value as u32, name);
            }
        } else if pos > 0 {
            log::info!("\t{} {}: 0x{:x} {}", pos, sreg, value as u32, value as u32);
        } else {
            log::info!("\t{}: 0x{:x} {}", sreg, value as u32, value as u32);
        }
    }

    pub fn show_eax(&self, maps: &Maps, pos: u64) {
        self.show_reg32(maps, "eax", self.get_eax(), pos);
    }

    pub fn show_ebx(&self, maps: &Maps, pos: u64) {
        self.show_reg32(maps, "ebx", self.get_ebx(), pos);
    }

    pub fn show_ecx(&self, maps: &Maps, pos: u64) {
        self.show_reg32(maps, "ecx", self.get_ecx(), pos);
    }

    pub fn show_edx(&self, maps: &Maps, pos: u64) {
        self.show_reg32(maps, "edx", self.get_edx(), pos);
    }

    pub fn show_esi(&self, maps: &Maps, pos: u64) {
        self.show_reg32(maps, "esi", self.get_esi(), pos);
    }

    pub fn show_edi(&self, maps: &Maps, pos: u64) {
        self.show_reg32(maps, "edi", self.get_edi(), pos);
    }

    pub fn show_rax(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "rax", self.rax, pos);
    }

    pub fn show_rbx(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "rbx", self.rbx, pos);
    }

    pub fn show_rcx(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "rcx", self.rcx, pos);
    }

    pub fn show_rdx(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "rdx", self.rdx, pos);
    }

    pub fn show_rsi(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "rsi", self.rsi, pos);
    }

    pub fn show_rdi(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "rdi", self.rdi, pos);
    }

    pub fn show_r8(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r8", self.r8, pos);
    }

    pub fn show_r9(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r9", self.r9, pos);
    }

    pub fn show_r10(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r10", self.r10, pos);
    }

    pub fn show_r11(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r11", self.r11, pos);
    }

    pub fn show_r12(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r12", self.r12, pos);
    }

    pub fn show_r13(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r13", self.r13, pos);
    }

    pub fn show_r14(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r14", self.r14, pos);
    }

    pub fn show_r15(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r15", self.r15, pos);
    }

    pub fn show_r8d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r8d", self.get_r8d(), pos);
    }

    pub fn show_r9d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r9d", self.get_r9d(), pos);
    }

    pub fn show_r10d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r10d", self.get_r10d(), pos);
    }

    pub fn show_r11d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r11d", self.get_r11d(), pos);
    }

    pub fn show_r12d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r12d", self.get_r12d(), pos);
    }

    pub fn show_r13d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r13d", self.get_r13d(), pos);
    }

    pub fn show_r14d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r14d", self.get_r14d(), pos);
    }

    pub fn show_r15d(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r15d", self.get_r15d(), pos);
    }

    pub fn show_r8w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r8w", self.get_r8w(), pos);
    }

    pub fn show_r9w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r9w", self.get_r9w(), pos);
    }

    pub fn show_r10w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r10w", self.get_r10w(), pos);
    }

    pub fn show_r11w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r11w", self.get_r11w(), pos);
    }

    pub fn show_r12w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r12w", self.get_r12w(), pos);
    }

    pub fn show_r13w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r13w", self.get_r13w(), pos);
    }

    pub fn show_r14w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r14w", self.get_r14w(), pos);
    }

    pub fn show_r15w(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r15w", self.get_r15w(), pos);
    }

    pub fn show_r8l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r8l", self.get_r8l(), pos);
    }

    pub fn show_r9l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r9l", self.get_r9l(), pos);
    }

    pub fn show_r10l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r10l", self.get_r10l(), pos);
    }

    pub fn show_r11l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r11l", self.get_r11l(), pos);
    }

    pub fn show_r12l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r12l", self.get_r12l(), pos);
    }

    pub fn show_r13l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r13l", self.get_r13l(), pos);
    }

    pub fn show_r14l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r14l", self.get_r14l(), pos);
    }

    pub fn show_r15l(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "r15l", self.get_r15l(), pos);
    }

    pub fn show_sil(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "sil", self.get_sil(), pos);
    }

    pub fn show_dil(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "dil", self.get_dil(), pos);
    }

    pub fn show_bpl(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "bpl", self.get_bpl(), pos);
    }

    pub fn show_spl(&self, maps: &Maps, pos: u64) {
        self.show_reg64(maps, "spl", self.get_spl(), pos);
    }

    pub fn is_xmm_by_name(&self, reg: &str) -> bool {
        match reg {
            "xmm0" | "xmm1" | "xmm2" | "xmm3" | "xmm4" | "xmm5" | "xmm6" | "xmm7" | "xmm8"
            | "xmm9" | "xmm10" | "xmm11" | "xmm12" | "xmm13" | "xmm14" | "xmm15" => true,
            &_ => false,
        }
    }

    pub fn is_ymm_by_name(&self, reg: &str) -> bool {
        match reg {
            "ymm0" | "ymm1" | "ymm2" | "ymm3" | "ymm4" | "ymm5" | "ymm6" | "ymm7" | "ymm8"
            | "ymm9" | "ymm10" | "ymm11" | "ymm12" | "ymm13" | "ymm14" | "ymm15" => true,
            &_ => false,
        }
    }

    pub fn is_reg(&self, reg: &str) -> bool {
        match reg {
            "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" | "rip" | "r8" | "r9"
            | "r10" | "r11" | "r12" | "r13" | "r14" | "r15" | "eax" | "ebx" | "ecx" | "edx"
            | "esi" | "edi" | "esp" | "ebp" | "eip" | "r8d" | "r9d" | "r10d" | "r11d" | "r12d"
            | "r13d" | "r14d" | "r15d" | "ax" | "bx" | "cx" | "dx" | "bp" | "sp" | "r8w"
            | "r9w" | "r10w" | "r11w" | "r12w" | "r13w" | "r14w" | "r15w" | "si" | "di" | "al"
            | "ah" | "bl" | "bh" | "cl" | "ch" | "dl" | "dh" | "r8l" | "r9l" | "r10l" | "r11l"
            | "r12l" | "r13l" | "r14l" | "r15l" | "sil" | "dil" | "bpl" | "spl" => true,
            &_ => false,
        }
    }
}
