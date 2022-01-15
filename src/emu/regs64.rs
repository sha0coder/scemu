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
            Register::EAX => self.get_eax(),
            Register::EBX => self.get_ebx(),
            Register::ECX => self.get_ecx(),
            Register::EDX => self.get_edx(),
            Register::ESI => self.get_esi(),
            Register::EDI => self.get_edi(),
            Register::ESP => self.get_esp(),
            Register::EBP => self.get_ebp(),
            Register::EIP => self.get_eip(),
            Register::AX => self.get_ax(),
            Register::BX => self.get_bx(),
            Register::CX => self.get_cx(),
            Register::DX => self.get_dx(),
            Register::SI => self.get_si(),
            Register::DI => self.get_di(),
            Register::AH => self.get_ah(),
            Register::AL => self.get_al(),
            Register::BH => self.get_bh(),
            Register::BL => self.get_bl(),
            Register::CH => self.get_ch(),
            Register::CL => self.get_cl(),
            Register::DH => self.get_dh(),
            Register::DL => self.get_dl(),
            Register::DS => 0,
            Register::CS => 0,
            Register::SS => 0,
            Register::SP => 0, 
            Register::BP => 0,
            Register::ES => 0,
            Register::FS => 0,
            Register::GS => 0,
            _ => unimplemented!("unimplemented register {:?}", reg),
        };

        return value;
    }

    pub fn set_reg(&mut self, reg:Register, value:u64) {
        match reg {
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
            Register::EAX => self.set_eax(value),
            Register::EBX => self.set_ebx(value),
            Register::ECX => self.set_ecx(value),
            Register::EDX => self.set_edx(value),
            Register::ESI => self.set_esi(value),
            Register::EDI => self.set_edi(value),
            Register::ESP => self.set_esp(value),
            Register::EBP => self.set_ebp(value),
            Register::EIP => self.set_eip(value),
            Register::AX => self.set_ax(value),
            Register::BX => self.set_bx(value),
            Register::CX => self.set_cx(value),
            Register::DX => self.set_dx(value),
            Register::SI => self.set_si(value),
            Register::DI => self.set_di(value),
            Register::AH => self.set_ah(value),
            Register::AL => self.set_al(value),
            Register::BH => self.set_bh(value),
            Register::BL => self.set_bl(value),
            Register::CH => self.set_ch(value),
            Register::CL => self.set_cl(value),
            Register::DH => self.set_dh(value),
            Register::DL => self.set_dl(value),
            Register::SP => { },
            Register::SS => { },
            Register::BP => { },
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
            Register::AX => 16,
            Register::BX => 16,
            Register::CX => 16,
            Register::DX => 16,
            Register::SI => 16,
            Register::DI => 16,
            Register::AH => 8,
            Register::AL => 8,
            Register::BH => 8,
            Register::BL => 8,
            Register::CH => 8,
            Register::CL => 8,
            Register::DH => 8,
            Register::DL => 8,
            _ => unimplemented!("unimplemented register {:?}", reg),
        };

        return sz;
    }

    pub fn get_by_name(&self, reg_name:&str) -> u64 {
        match reg_name {
            "rax" => return self.rax,
            "rbx" => return self.rbx,
            "rcx" => return self.rcx,
            "rdx" => return self.rdx,
            "rsi" => return self.rsi,
            "rdi" => return self.rdi,
            "rbp" => return self.rbp,
            "rsp" => return self.rsp,
            "rip" => return self.rip,
            "eax" => return self.get_eax(),
            "ebx" => return self.get_ebx(),
            "ecx" => return self.get_ecx(),
            "edx" => return self.get_edx(),
            "esi" => return self.get_esi(),
            "edi" => return self.get_edi(),
            "ebp" => return self.get_ebp(),
            "esp" => return self.get_esp(),
            "eip" => return self.get_eip(),
            "ax" => return self.get_ax(),
            "bx" => return self.get_bx(),
            "cx" => return self.get_cx(),
            "dx" => return self.get_dx(),
            "si" => return self.get_si(),
            "di" => return self.get_di(),
            "ah" => return self.get_ah(),
            "al" => return self.get_al(),
            "bh" => return self.get_bh(),
            "bl" => return self.get_bl(),
            "ch" => return self.get_ch(),
            "cl" => return self.get_cl(),
            "dh" => return self.get_dh(),
            "dl" => return self.get_dl(),
            &_ => panic!("weird register name parsed {}", reg_name),
        }
    }

    pub fn set_by_name(&mut self, reg_name:&str, value:u64) {
        match reg_name {
            "rax" => self.rax = value,
            "rbx" => self.rbx = value,
            "rcx" => self.rcx = value,
            "rdx" => self.rdx = value,
            "rsi" => self.rsi = value,
            "rdi" => self.rdi = value,
            "rbp" => self.rbp = value,
            "rsp" => self.rsp = value,
            "rip" => self.rip = value,
            "eax" => self.set_eax(value),
            "ebx" => self.set_ebx(value),
            "ecx" => self.set_ecx(value),
            "edx" => self.set_edx(value),
            "esi" => self.set_esi(value),
            "edi" => self.set_edi(value),
            "ebp" => self.set_ebp(value),
            "esp" => self.set_esp(value),
            "eip" => self.set_eip(value),
            "ax" => self.set_ax(value),
            "bx" => self.set_bx(value),
            "cx" => self.set_cx(value),
            "dx" => self.set_dx(value),
            "di" => self.set_di(value),
            "si" => self.set_si(value),
            "ah" => self.set_ah(value),
            "al" => self.set_al(value),
            "bh" => self.set_bh(value),
            "bl" => self.set_bl(value),
            "ch" => self.set_ch(value),
            "cl" => self.set_cl(value),
            "dh" => self.set_dh(value),
            "dl" => self.set_dl(value),
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

    pub fn is_reg(&self, reg:&str) -> bool {
        match reg {
            "rax"|"rbx"|"rcx"|"rdx"|"rsi"|"rdi"|"rbp"|"rsp"|"rip"|"eax"|"ebx"|"ecx"|"edx"|"esi"|"edi"|"esp"|"ebp"|"eip"|"ax"|"bx"|"cx"|"dx"|"si"|"di"|"al"|"ah"|"bl"|"bh"|"cl"|"ch"|"dl"|"dh" => true,
            &_ => false,
        }
    }
}
