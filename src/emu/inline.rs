use std::arch::asm;

// this unsafe blocks are used only on --test mode

pub fn or(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("or {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn xor(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("xor {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn and(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("and {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn not(a:u64, bits:u8) -> u64 {
    let mut r:u64 = a;
    match bits {
        64 => {
            unsafe {   
                asm!("not {}", inout(reg) r);
            }   
        }
        32 => {
            let mut rr:u32 = a as u32; 
            unsafe {   
                asm!("not {:e}", inout(reg) rr);
            }   
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = a as u16; 
            unsafe {   
                asm!("not {:x}", inout(reg) rr);
            }   
            r = rr as u64;
        }
        8 => {
            let mut rr:u8 = a as u8; 
            unsafe {   
                asm!("not {}", inout(reg_byte) rr);
            }   
            r = rr as u64;
        }
        _ => unimplemented!("weird"),
    }
    
    r
}

pub fn neg(a:u64, bits:u8) -> u64 {
    let mut r:u64 = a;
    match bits {
        64 => {
            unsafe {   
                asm!("neg {}", inout(reg) r);
            }   
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {   
                asm!("neg {:e}", inout(reg) rr);
            }   
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {   
                asm!("neg {:x}", inout(reg) rr);
            }   
            r = rr as u64;
        }
        8 => {
            let mut rr:u8 = r as u8;
            unsafe {   
                asm!("neg {}", inout(reg_byte) rr);
            }   
            r = rr as u64;
        }
        _ => unimplemented!("weird"),
    }
    
    r
}

pub fn ror(a:u64, b:u64, bits:u8) -> u64 {
    let bb = b as u8;
    let mut r:u64 = a;


    match bits {
        64 => {
            unsafe {   
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("ror {}, cl", inout(reg) r);
            }   
        }
        32 => {
            let a32 = a as u32;
            let rr:u32;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("mov eax, {:e}", in(reg) a32);
                asm!("ror eax, cl");
                asm!("mov {:e}, eax", out(reg) rr);
            }   
            r = rr as u64;
        }
        16 => {
            let a16 = a as u16;
            let rr:u16;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("mov ax, {:x}", in(reg) a16);
                asm!("ror ax, cl");
                asm!("mov {:x}, ax", out(reg) rr);
            }   
            r = rr as u64
        }
        8 => {
            let a8 = a as u8;
            let rr:u8;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("mov al, {}", in(reg_byte) a8);
                asm!("ror al, cl");
                asm!("mov {}, al", out(reg_byte) rr);
            }   
            r = rr as u64
        }
        _ => unimplemented!("inline ror"),
    }
    
    r
}

pub fn rol(a:u64, b:u64, sz:u8) -> u64 {
    let bb = b as u8;
    let mut r:u64 = a;
    
    match sz {
        64 => {
            unsafe {   
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("rol {}, cl", inout(reg) r);
            }   
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {   
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("rol {:e}, cl", inout(reg) rr);
            }   
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {   
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("rol {:x}, cl", inout(reg) rr);
            }   
            r = rr as u64;
        }
        8 => {
            let mut rr:u8 = r as u8;
            unsafe {   
                asm!("mov cl, {}", in(reg_byte) bb);
                asm!("rol {}, cl", inout(reg_byte) rr);
            }   
            r = rr as u64;
        }
        _ => unimplemented!("weird"),
    }
    
    r
}

pub fn rcl(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("rcl {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}


pub fn rcr(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("rcr {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn sar(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("sar {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn sal(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("sal {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn shl(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("shl {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn shr(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("shl {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn bswap(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("bswap {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn movzx(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("movzx {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn movsx(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("movsx {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn movsxd(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("movsxd {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn cmovs(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("cmovs {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn cmovo(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("cmovs {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}


pub fn btc(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("btc {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}

pub fn bts(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("bts {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}


pub fn bsf(a:u64, b:u64) -> u64 {
    let mut r:u64 = a;
    unsafe {   
        asm!("bsf {}, {}", inout(reg) r, in(reg) b);
    }   
    
    r
}


