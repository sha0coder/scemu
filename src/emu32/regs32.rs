use crate::emu32::maps::Maps;
use iced_x86::Register;


    /*
        DR0-DR3 – breakpoint registers
        DR4 & DR5 – reserved
        DR6 – debug status
        DR7 – debug control
    */

pub struct Regs32 {
    pub dr0: u32, // bp
    pub dr1: u32, // bp
    pub dr2: u32, // bp
    pub dr3: u32, // bp
    pub dr6: u32, // dbg stat
    pub dr7: u32, // dbg ctrl
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub xmm0: u128,
    pub xmm1: u128,
    pub xmm2: u128,
    pub xmm3: u128,
    pub xmm4: u128,
    pub xmm5: u128,
    pub xmm6: u128,
    pub xmm7: u128, //TODO: 32 XMM registers
}

impl Regs32 {
    pub fn new() -> Regs32 {
        Regs32{
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            esp: 0,
            eip: 0,
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

    pub fn clear(&mut self) {
        self.eax = 0;
        self.ebx = 0;
        self.ecx = 0;
        self.edx = 0;
        self.esi = 0;
        self.edi = 0;
        self.ebp = 0;
        self.esp = 0;
        self.eip = 0;
    }

    pub fn print(&self) {
        println!("regs:");
        println!("  eax: 0x{:x}", self.eax);
        println!("  ebx: 0x{:x}", self.ebx);
        println!("  ecx: 0x{:x}", self.ecx);
        println!("  edx: 0x{:x}", self.edx);
        println!("  esi: 0x{:x}", self.esi);
        println!("  edi: 0x{:x}", self.edi);
        println!("  ebp: 0x{:x}", self.ebp);
        println!("  esp: 0x{:x}", self.esp);
        println!("  eip: 0x{:x}", self.eip);
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

    pub fn get_ax(&self) -> u32 {
        return self.eax & 0xffff;
    }

    pub fn get_bx(&self) -> u32 {
        return self.ebx & 0xffff;
    }

    pub fn get_cx(&self) -> u32 {
        return self.ecx & 0xffff;
    }

    pub fn get_dx(&self) -> u32 {
        return self.edx & 0xffff;
    }

    pub fn get_si(&self) -> u32 {
        return self.esi & 0xffff;
    }

    pub fn get_di(&self) -> u32 {
        return self.edi & 0xffff;
    }

    pub fn get_ah(&self) -> u32 {
        return (self.eax & 0xff00) >> 8;
    }

    pub fn get_al(&self) -> u32 {
        return self.eax & 0xff;
    }

    pub fn get_bh(&self) -> u32 {
        return (self.ebx & 0xff00) >> 8;
    }

    pub fn get_bl(&self) -> u32 {
        return self.ebx & 0xff;
    }

    pub fn get_ch(&self) -> u32 {
        return (self.ecx & 0xff00) >> 8;
    }

    pub fn get_cl(&self) -> u32 {
        return self.ecx & 0xff;
    }

    pub fn get_dh(&self) -> u32 {
        return (self.edx & 0xff00) >> 8;
    }

    pub fn get_dl(&self) -> u32 {
        return self.edx & 0xff;
    }

    pub fn set_ax(&mut self, val:u32) {
        self.eax = self.eax & 0xffff0000;
        self.eax += val & 0x0000ffff;
    }

    pub fn set_bx(&mut self, val:u32) {
        self.ebx = self.ebx & 0xffff0000;
        self.ebx += val & 0x0000ffff;
    }

    pub fn set_cx(&mut self, val:u32) {
        self.ecx = self.ecx & 0xffff0000;
        self.ecx += val & 0x0000ffff;
    }

    pub fn set_dx(&mut self, val:u32) {
        self.edx = self.edx & 0xffff0000;
        self.edx += val & 0x0000ffff;
    }

    pub fn set_si(&mut self, val:u32) {
        self.esi = self.esi & 0xffff0000;
        self.esi += val & 0x0000ffff;
    }

    pub fn set_di(&mut self, val:u32) {
        self.edi = self.edi & 0xffff0000;
        self.edi += val & 0x0000ffff;
    }

    pub fn set_ah(&mut self, val:u32) {
        let low:u32 = self.eax & 0x000000ff;
        self.eax = (self.eax & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_bh(&mut self, val:u32) {
        let low:u32 = self.ebx & 0x000000ff;
        self.ebx = (self.ebx & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_ch(&mut self, val:u32) {
        let low:u32 = self.ecx & 0x000000ff;
        self.ecx = (self.ecx & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_dh(&mut self, val:u32) {
        let low:u32 = self.edx & 0x000000ff;
        self.edx = (self.edx & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_al(&mut self, val:u32) {
        self.eax = self.eax & 0xffffff00;
        self.eax += val & 0x000000ff;
    }
    
    pub fn set_bl(&mut self, val:u32) {
        self.ebx = self.ebx & 0xffffff00;
        self.ebx += val & 0x000000ff;
    }
    pub fn set_cl(&mut self, val:u32) {
        self.ecx = self.ecx & 0xffffff00;
        self.ecx += val & 0x000000ff;
    }
    pub fn set_dl(&mut self, val:u32) {
        self.edx = self.edx & 0xffffff00;
        self.edx += val & 0x000000ff;
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

    pub fn get_reg(&self, reg:Register) -> u32 {
        let value = match reg {
            Register::EAX => self.eax,
            Register::EBX => self.ebx,
            Register::ECX => self.ecx,
            Register::EDX => self.edx,
            Register::ESI => self.esi,
            Register::EDI => self.edi,
            Register::ESP => self.esp,
            Register::EBP => self.ebp,
            Register::EIP => self.eip,
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

    pub fn set_reg(&mut self, reg:Register, value:u32) {
        match reg {
            Register::EAX => self.eax = value,
            Register::EBX => self.ebx = value,
            Register::ECX => self.ecx = value,
            Register::EDX => self.edx = value,
            Register::ESI => self.esi = value,
            Register::EDI => self.edi = value,
            Register::ESP => self.esp = value,
            Register::EBP => self.ebp = value,
            Register::EIP => self.eip = value,
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

    pub fn get_size(&self, reg:Register) -> usize {
        let sz:usize = match reg {
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





    pub fn get_by_name(&self, reg_name:&str) -> u32 {
        match reg_name {
            "eax" => return self.eax,
            "ebx" => return self.ebx,
            "ecx" => return self.ecx,
            "edx" => return self.edx,
            "esi" => return self.esi,
            "edi" => return self.edi,
            "ebp" => return self.ebp,
            "esp" => return self.esp,
            "eip" => return self.eip,
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

    pub fn set_by_name(&mut self, reg_name:&str, value:u32) {
        match reg_name {
            "eax" => self.eax = value,
            "ebx" => self.ebx = value,
            "ecx" => self.ecx = value,
            "edx" => self.edx = value,
            "esi" => self.esi = value,
            "edi" => self.edi = value,
            "ebp" => self.ebp = value,
            "esp" => self.esp = value,
            "eip" => self.eip = value,
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

    pub fn show_reg(&self, maps:&Maps, sreg:&str, value:u32, pos:u64) {
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

    pub fn show_eax(&self, maps:&Maps, pos:u64) {
        self.show_reg(maps, "eax", self.eax, pos);
    }

    pub fn show_ebx(&self, maps:&Maps, pos:u64) {
        self.show_reg(maps, "ebx", self.ebx, pos);
    }

    pub fn show_ecx(&self, maps:&Maps, pos:u64) {
        self.show_reg(maps, "ecx", self.ecx, pos);
    }

    pub fn show_edx(&self, maps:&Maps, pos:u64) {
        self.show_reg(maps, "edx", self.edx, pos);
    }

    pub fn show_esi(&self, maps:&Maps, pos:u64) {
        self.show_reg(maps, "esi", self.esi, pos);
    }

    pub fn show_edi(&self, maps:&Maps, pos:u64) {
        self.show_reg(maps, "edi", self.edi, pos);
    }
}
