use crate::emu::maps::Maps;
use iced_x86::Register;
use rand;

macro_rules! set_reg32 {
    ($reg:expr, $val:expr) => (
        $reg &= 0xffffffff00000000;
        $reg += ($val & 0x00000000ffffffff);
    )
}

macro_rules! set_reg16 {
    ($reg:expr, $val:expr) => (
        $reg &= 0xffffffffffff0000;
        $reg += ($val & 0x000000000000ffff);
    )
}

macro_rules! set_reg8l {
    ($reg:expr, $val:expr) => (
        $reg &= 0xffffffffffffff00;
        $reg += ($val & 0x00000000000000ff);
    )
}

macro_rules! set_reg8h {
    ($reg:expr, $val:expr) => (
        $reg &= 0xffffffffffff00ff;
        $reg = $reg + (($val & 0x00000000000000ff) << 8);
    )
}

macro_rules! get_reg32 {
    ($reg:expr) => (
        return $reg & 0x00000000ffffffff;
    )
}

macro_rules! get_reg16 {
    ($reg:expr) => (
        return $reg & 0x000000000000ffff;
    )
}

macro_rules! get_reg8l {
    ($reg:expr) => (
        return $reg & 0x00000000000000ff;
    )
}

macro_rules! get_reg8h {
    ($reg:expr) => (
        return ($reg & 0x000000000000ff00) >> 8;
    )
}


//  https://wiki.osdev.org/CPU_Registers_x86-64

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
    pub cr9: u64, // reserved
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
}

impl Regs64 {
    pub fn new() -> Regs64 {
        Regs64{
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
        }
    }

    pub fn clear<const B:usize>(&mut self) {
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
        let mask:u64 = 0x00000000ffffffff;
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

    pub fn print<const B:usize>(&self) {
        println!("regs:");

        match B {
            64 => {
                println!("  rax: 0x{:x}", self.rax);
                println!("  rbx: 0x{:x}", self.rbx);
                println!("  rcx: 0x{:x}", self.rcx);
                println!("  rdx: 0x{:x}", self.rdx);
                println!("  rsi: 0x{:x}", self.rsi);
                println!("  rdi: 0x{:x}", self.rdi);
                println!("  rbp: 0x{:x}", self.rbp);
                println!("  rsp: 0x{:x}", self.rsp);
                println!("  rip: 0x{:x}", self.rip);
            }
            32 => {
                println!("  eax: 0x{:x}", self.get_eax());
                println!("  ebx: 0x{:x}", self.get_ebx());
                println!("  ecx: 0x{:x}", self.get_ecx());
                println!("  edx: 0x{:x}", self.get_edx());
                println!("  esi: 0x{:x}", self.get_esi());
                println!("  edi: 0x{:x}", self.get_edi());
                println!("  ebp: 0x{:x}", self.get_ebp());
                println!("  esp: 0x{:x}", self.get_esp());
                println!("  eip: 0x{:x}", self.get_eip());
            }
            _ => unimplemented!(),
        }

        println!("---");
    }

    pub fn print_xmm(&self) {
        println!("xmm regs:");
        println!("  xmm0: {}", self.xmm0);
        println!("  xmm1: {}", self.xmm1);
        println!("  xmm2: {}", self.xmm2);
        println!("  xmm3: {}", self.xmm3);
        println!("  xmm4: {}", self.xmm4);
        println!("  xmm5: {}", self.xmm5);
        println!("  xmm6: {}", self.xmm6);
        println!("  xmm7: {}", self.xmm7);
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

    // get 32bits

    pub fn get_eax(&self) -> u64 {
        get_reg32!(self.rax);
    }

    pub fn get_ebx(&self) -> u64 {
        get_reg32!(self.rbx);
    }

    pub fn get_ecx(&self) -> u64 {
        get_reg32!(self.rcx);
    }

    pub fn get_edx(&self) -> u64 {
        get_reg32!(self.rdx);
    }

    pub fn get_esi(&self) -> u64 {
        get_reg32!(self.rsi);
    }

    pub fn get_edi(&self) -> u64 {
        get_reg32!(self.rdi);
    }

    pub fn get_esp(&self) -> u64 {
        get_reg32!(self.rsp);
    }

    pub fn get_ebp(&self) -> u64 {
        get_reg32!(self.rbp);
    }

    pub fn get_eip(&self) -> u64 {
        get_reg32!(self.rip);
    }

    pub fn get_r8d(&self) -> u64 {
        get_reg32!(self.r8);
    }

    pub fn get_r9d(&self) -> u64 {
        get_reg32!(self.r9);
    }

    pub fn get_r10d(&self) -> u64 {
        get_reg32!(self.r10);
    }

    pub fn get_r11d(&self) -> u64 {
        get_reg32!(self.r11);
    }

    pub fn get_r12d(&self) -> u64 {
        get_reg32!(self.r12);
    }

    pub fn get_r13d(&self) -> u64 {
        get_reg32!(self.r13);
    }

    pub fn get_r14d(&self) -> u64 {
        get_reg32!(self.r14);
    }

    pub fn get_r15d(&self) -> u64 {
        get_reg32!(self.r15);
    }

    // set 16bits

    pub fn set_ax(&mut self, val:u64) {
        set_reg16!(self.rax, val);
    }

    pub fn set_bx(&mut self, val:u64) {
        set_reg16!(self.rbx, val);
    }

    pub fn set_cx(&mut self, val:u64) {
        set_reg16!(self.rcx, val);
    }

    pub fn set_dx(&mut self, val:u64) {
        set_reg16!(self.rdx, val);
    }

    pub fn set_si(&mut self, val:u64) {
        set_reg16!(self.rsi, val);
    }

    pub fn set_di(&mut self, val:u64) {
        set_reg16!(self.rdi, val);
    }

    pub fn set_sp(&mut self, val:u64) {
        set_reg16!(self.rsp, val);
    }

    pub fn set_bp(&mut self, val:u64) {
        set_reg16!(self.rbp, val);
    }

    pub fn set_ip(&mut self, val:u64) {
        set_reg16!(self.rip, val);
    }

    pub fn set_r8w(&mut self, val:u64) {
        set_reg16!(self.r8, val);
    }

    pub fn set_r9w(&mut self, val:u64) {
        set_reg16!(self.r9, val);
    }

    pub fn set_r10w(&mut self, val:u64) {
        set_reg16!(self.r10, val);
    }

    pub fn set_r11w(&mut self, val:u64) {
        set_reg16!(self.r11, val);
    }

    pub fn set_r12w(&mut self, val:u64) {
        set_reg16!(self.r12, val);
    }

    pub fn set_r13w(&mut self, val:u64) {
        set_reg16!(self.r13, val);
    }

    pub fn set_r14w(&mut self, val:u64) {
        set_reg16!(self.r14, val);
    }

    pub fn set_r15w(&mut self, val:u64) {
        set_reg16!(self.r15, val);
    }

    // set 32bits

    pub fn set_eax(&mut self, val:u64) {
        set_reg32!(self.rax, val);
    }

    pub fn set_ebx(&mut self, val:u64) {
        set_reg32!(self.rbx, val);
    }

    pub fn set_ecx(&mut self, val:u64) {
        set_reg32!(self.rcx, val);
    }

    pub fn set_edx(&mut self, val:u64) {
        set_reg32!(self.rdx, val);
    }

    pub fn set_esi(&mut self, val:u64) {
        set_reg32!(self.rsi, val);
    }

    pub fn set_edi(&mut self, val:u64) {
        set_reg32!(self.rdi, val);
    }

    pub fn set_ebp(&mut self, val:u64) {
        set_reg32!(self.rbp, val);
    }

    pub fn set_esp(&mut self, val:u64) {
        set_reg32!(self.rsp, val);
    }

    pub fn set_eip(&mut self, val:u64) {
        set_reg32!(self.rip, val);
    }

    pub fn set_r8d(&mut self, val:u64) {
        set_reg32!(self.r8, val);
    }

    pub fn set_r9d(&mut self, val:u64) {
        set_reg32!(self.r9, val);
    }

    pub fn set_r10d(&mut self, val:u64) {
        set_reg32!(self.r10, val);
    }

    pub fn set_r11d(&mut self, val:u64) {
        set_reg32!(self.r11, val);
    }

    pub fn set_r12d(&mut self, val:u64) {
        set_reg32!(self.r12, val);
    }

    pub fn set_r13d(&mut self, val:u64) {
        set_reg32!(self.r13, val);
    }

    pub fn set_r14d(&mut self, val:u64) {
        set_reg32!(self.r14, val);
    }

    pub fn set_r15d(&mut self, val:u64) {
        set_reg32!(self.r15, val);
    }


    // set 8bits

    pub fn set_ah(&mut self, val:u64) {
        set_reg8h!(self.rax, val);
    }

    pub fn set_bh(&mut self, val:u64) {
        set_reg8h!(self.rbx, val);
    }

    pub fn set_ch(&mut self, val:u64) {
        set_reg8h!(self.rcx, val);
    }

    pub fn set_dh(&mut self, val:u64) {
        set_reg8h!(self.rdx, val);
    }

    pub fn set_al(&mut self, val:u64) {
        set_reg8l!(self.rax, val);
    }
    
    pub fn set_bl(&mut self, val:u64) {
        set_reg8l!(self.rbx, val);
    }

    pub fn set_cl(&mut self, val:u64) {
        set_reg8l!(self.rcx, val);
    }

    pub fn set_dl(&mut self, val:u64) {
        set_reg8l!(self.rdx, val);
    }

    pub fn set_r8l(&mut self, val:u64) {
        set_reg8l!(self.r8, val);
    }

    pub fn set_r9l(&mut self, val:u64) {
        set_reg8l!(self.r9, val);
    }

    pub fn set_r10l(&mut self, val:u64) {
        set_reg8l!(self.r10, val);
    }

    pub fn set_r11l(&mut self, val:u64) {
        set_reg8l!(self.r11, val);
    }

    pub fn set_r12l(&mut self, val:u64) {
        set_reg8l!(self.r12, val);
    }

    pub fn set_r13l(&mut self, val:u64) {
        set_reg8l!(self.r13, val);
    }

    pub fn set_r14l(&mut self, val:u64) {
        set_reg8l!(self.r14, val);
    }

    pub fn set_r15l(&mut self, val:u64) {
        set_reg8l!(self.r15, val);
    }

    pub fn set_r8h(&mut self, val:u64) {
        set_reg8h!(self.r8, val);
    }

    pub fn set_r9h(&mut self, val:u64) {
        set_reg8h!(self.r9, val);
    }

    pub fn set_r10h(&mut self, val:u64) {
        set_reg8h!(self.r10, val);
    }

    pub fn set_r11h(&mut self, val:u64) {
        set_reg8h!(self.r11, val);
    }

    pub fn set_r12h(&mut self, val:u64) {
        set_reg8h!(self.r12, val);
    }

    pub fn set_r13h(&mut self, val:u64) {
        set_reg8h!(self.r13, val);
    }

    pub fn set_r14h(&mut self, val:u64) {
        set_reg8h!(self.r14, val);
    }

    pub fn set_r15h(&mut self, val:u64) {
        set_reg8h!(self.r15, val);
    }

    // xmm 

    pub fn is_xmm(&self, reg:Register) -> bool {
        let result = match reg {
            Register::XMM0 => true,
            Register::XMM1 => true,
            Register::XMM2 => true,
            Register::XMM3 => true,
            Register::XMM4 => true,
            Register::XMM5 => true,
            Register::XMM6 => true,
            Register::XMM7 => true,
            _ => false,
        };
        return result;
    }

    pub fn get_xmm_reg(&self, reg:Register) -> u128 {
        let value = match reg {
            Register::XMM0 => self.xmm0,
            Register::XMM1 => self.xmm1,
            Register::XMM2 => self.xmm2,
            Register::XMM3 => self.xmm3,
            Register::XMM4 => self.xmm4,
            Register::XMM5 => self.xmm5,
            Register::XMM6 => self.xmm6,
            Register::XMM7 => self.xmm7,
            _ => unimplemented!("SSE  XMM re gister: {:?} ", reg),
        };
        return value;
    }

    pub fn set_xmm_reg(&mut self, reg:Register, value:u128)  {
        match reg {
            Register::XMM0 => self.xmm0 = value,
            Register::XMM1 => self.xmm1 = value,
            Register::XMM2 => self.xmm2 = value,
            Register::XMM3 => self.xmm3 = value,
            Register::XMM4 => self.xmm4 = value,
            Register::XMM5 => self.xmm5 = value,
            Register::XMM6 => self.xmm6 = value,
            Register::XMM7 => self.xmm7 = value,
            _ => unimplemented!("SSE  XMM re gister: {:?} ", reg),
        };
    }



    pub fn get_reg(&self, reg:Register) -> u64 {
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
            // segmets
            Register::DS => 0,
            Register::CS => 0,
            Register::SS => 0,
            Register::ES => 0,
            Register::FS => 0,
            Register::GS => 0,
            _ => unimplemented!("unimplemented register {:?}", reg),
        };

        return value;
    }

    pub fn set_reg(&mut self, reg:Register, value:u64) {
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
            // segments
            Register::SS => { },
            Register::ES => { },
            Register::FS => { },
            Register::GS => { },
            _ => unimplemented!("unimplemented register {:?}", reg),
        };
    }

    pub fn get_size(&self, reg:Register) -> u8 {
        let sz:u8 = match reg {
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
            _ => unimplemented!("unimplemented register {:?}", reg),
        };

        return sz;
    }

    pub fn get_by_name(&self, reg_name:&str) -> u64 {
        match reg_name {
            // 64bits
            "rax" => return self.rax,
            "rbx" => return self.rbx,
            "rcx" => return self.rcx,
            "rdx" => return self.rdx,
            "rsi" => return self.rsi,
            "rdi" => return self.rdi,
            "rbp" => return self.rbp,
            "rsp" => return self.rsp,
            "rip" => return self.rip,
            "r8" => return self.r8,
            "r9" => return self.r9,
            "r10" => return self.r10,
            "r11" => return self.r11,
            "r12" => return self.r12,
            "r13" => return self.r13,
            "r14" => return self.r14,
            "r15" => return self.r15,
            // 32bits
            "eax" => return self.get_eax(),
            "ebx" => return self.get_ebx(),
            "ecx" => return self.get_ecx(),
            "edx" => return self.get_edx(),
            "esi" => return self.get_esi(),
            "edi" => return self.get_edi(),
            "ebp" => return self.get_ebp(),
            "esp" => return self.get_esp(),
            "eip" => return self.get_eip(),
            "r8d" => return self.get_r8d(),
            "r9d" => return self.get_r9d(),
            "r10d" => return self.get_r10d(),
            "r11d" => return self.get_r11d(),
            "r12d" => return self.get_r12d(),
            "r13d" => return self.get_r13d(),
            "r14d" => return self.get_r14d(),
            "r15d" => return self.get_r15d(),
            // 16bits
            "ax" => return self.get_ax(),
            "bx" => return self.get_bx(),
            "cx" => return self.get_cx(),
            "dx" => return self.get_dx(),
            "si" => return self.get_si(),
            "di" => return self.get_di(),
            "bp" => return self.get_bp(),
            "sp" => return self.get_sp(),
            "r8w" => return self.get_r8w(),
            "r9w" => return self.get_r9w(),
            "r10w" => return self.get_r10w(),
            "r11w" => return self.get_r11w(),
            "r12w" => return self.get_r12w(),
            "r13w" => return self.get_r13w(),
            "r14w" => return self.get_r14w(),
            "r15w" => return self.get_r15w(),
            // 8bits
            "ah" => return self.get_ah(),
            "al" => return self.get_al(),
            "bh" => return self.get_bh(),
            "bl" => return self.get_bl(),
            "ch" => return self.get_ch(),
            "cl" => return self.get_cl(),
            "dh" => return self.get_dh(),
            "dl" => return self.get_dl(),
            "r8l" => return self.get_r8l(),
            "r9l" => return self.get_r9l(),
            "r10l" => return self.get_r10l(),
            "r11l" => return self.get_r11l(),
            "r12l" => return self.get_r12l(),
            "r13l" => return self.get_r13l(),
            "r14l" => return self.get_r14l(),
            "r15l" => return self.get_r15l(),
            &_ => unimplemented!("weird register name parsed {}", reg_name),
        }
    }

    pub fn set_by_name(&mut self, reg_name:&str, value:u64) {
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
            &_ => panic!("weird register name parsed {}", reg_name),
        }
    }

    pub fn show_reg64(&self, maps:&Maps, sreg:&str, value:u64, pos:u64) {
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
                    println!("\t{} {}: 0x{:x} {} '{}' {}", pos, sreg, value, value, s, name);
                } else {
                    println!("\t{}: 0x{:x} {} '{}' {}", sreg, value, value, s, name);
                }
            } else {
                if pos > 0 {
                    println!("\t{} {}: 0x{:x} {} {}", pos, sreg, value, value, name);
                } else {
                    println!("\t{}: 0x{:x} {} {}", sreg, value, value, name);
                }
            }

        } else {
            if pos > 0 {
                println!("\t{} {}: 0x{:x} {}", pos, sreg, value, value);
            } else {
                    println!("\t{}: 0x{:x} {}", sreg, value, value);
            }
        }
    }

    pub fn show_reg32(&self, maps:&Maps, sreg:&str, value:u64, pos:u64) {
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
                    println!("\t{} {}: 0x{:x} {} '{}' {}", pos, sreg, value as u32, value as u32, s, name);
                } else {
                    println!("\t{}: 0x{:x} {} '{}' {}", sreg, value as u32, value as u32, s, name);
                }
            } else {
                if pos > 0 {
                    println!("\t{} {}: 0x{:x} {} {}", pos, sreg, value as u32, value as u32, name);
                } else {
                    println!("\t{}: 0x{:x} {} {}", sreg, value as u32, value as u32, name);
                }
            }

        } else {
            if pos > 0 {
                println!("\t{} {}: 0x{:x} {}", pos, sreg, value as u32, value as u32);
            } else {
                println!("\t{}: 0x{:x} {}", sreg, value as u32, value as u32);
            }
        }
    }


    pub fn show_eax(&self, maps:&Maps, pos:u64) {
        self.show_reg32(maps, "eax", self.get_eax(), pos);
    }

    pub fn show_ebx(&self, maps:&Maps, pos:u64) {
        self.show_reg32(maps, "ebx", self.get_ebx(), pos);
    }

    pub fn show_ecx(&self, maps:&Maps, pos:u64) {
        self.show_reg32(maps, "ecx", self.get_ecx(), pos);
    }

    pub fn show_edx(&self, maps:&Maps, pos:u64) {
        self.show_reg32(maps, "edx", self.get_edx(), pos);
    }

    pub fn show_esi(&self, maps:&Maps, pos:u64) {
        self.show_reg32(maps, "esi", self.get_esi(), pos);
    }

    pub fn show_edi(&self, maps:&Maps, pos:u64) {
        self.show_reg32(maps, "edi", self.get_edi(), pos);
    }

    pub fn show_rax(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "rax", self.rax, pos);
    }

    pub fn show_rbx(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "rbx", self.rbx, pos);
    }

    pub fn show_rcx(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "rcx", self.rcx, pos);
    }

    pub fn show_rdx(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "rdx", self.rdx, pos);
    }

    pub fn show_rsi(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "rsi", self.rsi, pos);
    }

    pub fn show_rdi(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "rdi", self.rdi, pos);
    }

    pub fn show_r8(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r8", self.r8, pos);
    }

    pub fn show_r9(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r9", self.r9, pos);
    }

    pub fn show_r10(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r10", self.r10, pos);
    }

    pub fn show_r11(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r11", self.r11, pos);
    }

    pub fn show_r12(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r12", self.r12, pos);
    }

    pub fn show_r13(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r13", self.r13, pos);
    }

    pub fn show_r14(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r14", self.r14, pos);
    }

    pub fn show_r15(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r15", self.r15, pos);
    }

    pub fn show_r8d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r8d", self.get_r8d(), pos);
    }

    pub fn show_r9d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r9d", self.get_r9d(), pos);
    }

    pub fn show_r10d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r10d", self.get_r10d(), pos);
    }

    pub fn show_r11d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r11d", self.get_r11d(), pos);
    }

    pub fn show_r12d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r12d", self.get_r12d(), pos);
    }

    pub fn show_r13d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r13d", self.get_r13d(), pos);
    }

    pub fn show_r14d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r14d", self.get_r14d(), pos);
    }

    pub fn show_r15d(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r15d", self.get_r15d(), pos);
    }

    pub fn show_r8w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r8w", self.get_r8w(), pos);
    }

    pub fn show_r9w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r9w", self.get_r9w(), pos);
    }

    pub fn show_r10w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r10w", self.get_r10w(), pos);
    }

    pub fn show_r11w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r11w", self.get_r11w(), pos);
    }

    pub fn show_r12w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r12w", self.get_r12w(), pos);
    }

    pub fn show_r13w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r13w", self.get_r13w(), pos);
    }

    pub fn show_r14w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r14w", self.get_r14w(), pos);
    }

    pub fn show_r15w(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r15w", self.get_r15w(), pos);
    }

    pub fn show_r8l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r8l", self.get_r8l(), pos);
    }

    pub fn show_r9l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r9l", self.get_r9l(), pos);
    }

    pub fn show_r10l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r10l", self.get_r10l(), pos);
    }

    pub fn show_r11l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r11l", self.get_r11l(), pos);
    }

    pub fn show_r12l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r12l", self.get_r12l(), pos);
    }

    pub fn show_r13l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r13l", self.get_r13l(), pos);
    }

    pub fn show_r14l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r14l", self.get_r14l(), pos);
    }

    pub fn show_r15l(&self, maps:&Maps, pos:u64) {
        self.show_reg64(maps, "r15l", self.get_r15l(), pos);
    }


    pub fn is_reg(&self, reg:&str) -> bool {
        match reg {
            "rax"|"rbx"|"rcx"|"rdx"|"rsi"|"rdi"|"rbp"|"rsp"|"rip"|"r8"|"r9"|"r10"|"r11"|"r12"|
            "eax"|"ebx"|"ecx"|"edx"|"esi"|"edi"|"esp"|"ebp"|"eip"|"r8d"|"r9d"|"r10d"|"r11d"|"r12d"|
            "ax"|"bx"|"cx"|"dx"|"bp"|"sp"|"r8w"|"r9w"|"r10w"|"r11w"|"r12w"|
            "si"|"di"|"al"|"ah"|"bl"|"bh"|"cl"|"ch"|"dl"|"dh"|"r8l"|"r9l"|"r10l"|"r11l"|"r12l" => true,
            &_ => false,
        }
    }
}
