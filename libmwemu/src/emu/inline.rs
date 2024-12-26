// use std::arch::asm;

// this unsafe blocks are disabled

pub fn or(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("or {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn xor(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("xor {}, {}", inout(reg) r, in(reg) b);
    }*/

    r
}

pub fn and(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("and {}, {}", inout(reg) r, in(reg) b);
    }*/

    r
}

pub fn not(a: u64, bits: u32) -> u64 {
    let r: u64 = a;
    /*
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
    */

    r
}

pub fn neg(a: u64, bits: u32) -> u64 {
    let r: u64 = a;
    /*
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
    */

    r
}

pub fn ror(a: u64, b: u64, bits: u32) -> u64 {
    let bb = b as u8;
    let r: u64 = a;

    /*
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
    }*/

    r
}

pub fn rol(a: u64, b: u64, sz: u32) -> u64 {
    let bb = b as u8;
    let r: u64 = a;
    /*
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
    */

    r
}

pub fn rcl(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("rcl {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn rcr(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("rcr {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn sar1p(a: u64, bits: u32, cf: bool) -> u64 {
    let r: u64 = a;

    /*
    if cf {
        unsafe {
            asm!("mov al, 0xff");
            asm!("add al, 1");
        }
    } else {
        unsafe {
            asm!("mov al, 0xee");
            asm!("add al, 1");
        }
    }

    match bits {
        64 => {
            unsafe {
                asm!("sar {}", inout(reg) r);
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!("sar {:e}", inout(reg) rr);
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!("sar {:x}", inout(reg) rr);
            }
            r = rr as u64;
        }
        8 => {
            let mut rr:u8 = r as u8;
            unsafe {
                asm!("sar {}", inout(reg_byte) rr);
            }
            r = rr as u64;
        }
        _ => unimplemented!("weird case"),
    }*/

    r
}

pub fn sar2p(a: u64, b: u64, bits: u32, cf: bool) -> u64 {
    let r: u64 = a;
    let b8 = b as u8;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sar {}, cl", inout(reg) r);
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sar {:e}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sar {:x}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        8 => {
            let mut rr = r as u8;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sar {}, cl", inout(reg_byte) rr);
            }
            r = rr as u64;
        }
        _ => unimplemented!("weird case"),
    }
    */

    r
}

pub fn sal(a: u64, b: u64, bits: u32) -> u64 {
    let r: u64 = a;
    let b8 = b as u8;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sal {}, cl", inout(reg) r);
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sal {:e}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sal {:x}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        8 => {
            let mut rr = r as u8;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("sal {}, cl", inout(reg_byte) rr);
            }
            r = rr as u64;
        }
        _ => unimplemented!("weird case"),
    }*/

    r
}

pub fn shl(a: u64, b: u64, bits: u32) -> u64 {
    let r: u64 = a;
    let b8 = b as u8;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shl {}, cl", inout(reg) r);
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shl {:e}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shl {:x}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        8 => {
            let mut rr = r as u8;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shl {}, cl", inout(reg_byte) rr);
            }
            r = rr as u64;
        }
        _ => unimplemented!("weird case"),
    }*/

    r
}

pub fn shr(a: u64, b: u64, bits: u32) -> u64 {
    let r: u64 = a;
    let b8 = b as u8;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shr {}, cl", inout(reg) r);
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shr {:e}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shr {:x}, cl", inout(reg) rr);
            }
            r = rr as u64;
        }
        8 => {
            let mut rr = r as u8;
            unsafe {
                asm!("mov cl, {}", in(reg_byte) b8);
                asm!("shr {}, cl", inout(reg_byte) rr);
            }
            r = rr as u64;
        }
        _ => unimplemented!("weird case"),
    }*/

    r
}

pub fn shld(a: u64, b: u64, c: u64, bits: u32, flags: u32) -> (u64, u32) {
    let r: u64 = a;
    let c8 = c as u8;
    let new_flags: u32 = 0;

    /*
    match bits {
        64 => {
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",

                    "mov cl, {}",
                    "mov rdx, {}",
                    "shld {}, rdx, cl",

                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",

                    in(reg) flags,
                    in(reg_byte) c8, in(reg) b, inout(reg) r,
                    out(reg) new_flags,
                );
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",

                    "mov cl, {}",
                    "mov rdx, {}",
                    "shld {:e}, edx, cl",

                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",

                    in(reg) flags,
                    in(reg_byte) c8, in(reg) b, inout(reg) rr,
                    out(reg) new_flags,
                );
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",

                    "mov cl, {}",
                    "mov rdx, {}",
                    "shld {:x}, dx, cl",

                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",

                    in(reg) flags,
                    in(reg_byte) c8, in(reg) b, inout(reg) rr,
                    out(reg) new_flags,
                );
            }
            r = rr as u64;
        }
        8 => {
            unimplemented!("doesnt exit shld of 8bits");
        }
        _ => {
            log::info!("sz: {}", bits);
            unimplemented!("weird case");
        }
    }*/

    (r, new_flags)
}

pub fn shrd(a: u64, b: u64, c: u64, bits: u32, flags: u32) -> (u64, u32) {
    let r: u64 = a;
    let c8 = c as u8;
    let new_flags: u32 = 0;

    /*
    match bits {
        64 => {
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",

                    "mov cl, {}",
                    "mov rdx, {}",
                    "shrd {}, rdx, cl",

                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",

                    in(reg) flags,
                    in(reg_byte) c8, in(reg) b, inout(reg) r,
                    out(reg) new_flags,
                );
            }
        }
        32 => {
            let mut rr:u32 = r as u32;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",

                    "mov cl, {}",
                    "mov rdx, {}",
                    "shrd {:e}, edx, cl",

                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",

                    in(reg) flags,
                    in(reg_byte) c8, in(reg) b, inout(reg) rr,
                    out(reg) new_flags,
                );
            }
            r = rr as u64;
        }
        16 => {
            let mut rr:u16 = r as u16;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",

                    "mov cl, {}",
                    "mov rdx, {}",
                    "shrd {:x}, dx, cl",

                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",

                    in(reg) flags,
                    in(reg_byte) c8, in(reg) b, inout(reg) rr,
                    out(reg) new_flags,
                );
            }
            r = rr as u64;
        }
        8 => {
            unimplemented!("doesnt exit shrd of 8bits");
        }
        _ => {
            log::info!("sz: {}", bits);
            unimplemented!("weird case");
        }
    }*/

    (r, new_flags)
}

pub fn div(a: u64, rax: u64, rdx: u64, bits: u32) -> (u64, u64) {
    let r_rax: u64 = 0;
    let r_rdx: u64 = 0;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("div {}", in(reg) a);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        32 => {
            let a32 = a as u32;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("div {:e}", in(reg) a32);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        16 => {
            let a16 = a as u16;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("div {:x}", in(reg) a16);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        8 => {
            let a8 = a as u8;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("div {}", in(reg_byte) a8);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        _ => unimplemented!("weird case"),
    }*/

    (r_rdx, r_rax)
}

pub fn idiv(a: u64, rax: u64, rdx: u64, bits: u32) -> (u64, u64) {
    let r_rax: u64 = 0;
    let r_rdx: u64 = 0;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("idiv {}", in(reg) a);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        32 => {
            let a32 = a as u32;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("idiv {:e}", in(reg) a32);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        16 => {
            let a16 = a as u16;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("idiv {:x}", in(reg) a16);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        8 => {
            let a8 = a as u8;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("idiv {}", in(reg_byte) a8);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        _ => unimplemented!("weird case"),
    }
    */

    (r_rdx, r_rax)
}

pub fn mul(a: u64, rax: u64, rdx: u64, bits: u32) -> (u64, u64) {
    let r_rax: u64 = 0;
    let r_rdx: u64 = 0;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("mul {}", in(reg) a);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        32 => {
            let a32 = a as u32;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("mul {:e}", in(reg) a32);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        16 => {
            let a16 = a as u16;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("mul {:x}", in(reg) a16);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        8 => {
            let a8 = a as u8;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("mul {}", in(reg_byte) a8);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        _ => unimplemented!("weird case"),
    }*/

    (r_rdx, r_rax)
}

pub fn imul1p(a: u64, rax: u64, rdx: u64, bits: u32) -> (u64, u64) {
    let r_rax: u64 = 0;
    let r_rdx: u64 = 0;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("imul {}", in(reg) a);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        32 => {
            let a32 = a as u32;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("imul {:e}", in(reg) a32);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        16 => {
            let a16 = a as u16;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("imul {:x}", in(reg) a16);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        8 => {
            let a8 = a as u8;
            unsafe {
                asm!("mov rax, {}", in(reg) rax);
                asm!("mov rdx, {}", in(reg) rdx);
                asm!("imul {}", in(reg_byte) a8);
                asm!("mov rsi, rax", "mov rdi, rdx", out("rsi") r_rax, out("rdi") r_rdx);
            }
        }
        _ => unimplemented!("weird case"),
    }
    */

    (r_rdx, r_rax)
}

pub fn imul2p(a: u64, b: u64, bits: u32) -> u64 {
    let r: u64 = a;

    /*
    match bits {
        64 => {
            let mut aa = a;
            unsafe {
                asm!("imul {}, {}", inout(reg) aa, in(reg) b);
            }
            r = aa;
        }
        32 => {
            let mut a32 = a as u32;
            let b32 = b as u32;
            unsafe {
                asm!("imul {:e}, {:e}", inout(reg) a32, in(reg) b32);
            }
            r = a32 as u64;
        }
        16 => {
            let mut a16 = a as u16;
            let b16 = b as u16;
            unsafe {
                asm!("imul {:x}, {:x}", inout(reg) a16, in(reg) b16);
            }
            r = a16 as u64;
        }
        8 => {
            panic!("imul of 2params and 8 bits doesn't exist");
        }
        _ => unimplemented!("weird case"),
    }*/

    r
}

/*
pub fn imul3p(b:u64, c:u64, bits:u8) -> u64 {
    let r:u64;

    match bits {
        64 => {
            let a64:u64;
            unsafe {
                asm!("imul {}, {}, {}", out(reg) a64, in(reg) b, in(reg) c);
            }
            r = a64;
        }
        32 => {
            let a32:u32;
            let b32 = b as u32;
            let c32 = c as u32;
            unsafe {
                asm!("imul {:e}, {:e}, {:e}", out(reg) a32, in(reg) b32, in(reg) c32);
            }
            r = a32 as u64;
        }
        16 => {
            let a16:u16;
            let b16 = b as u16;
            let c16 = c as u16;
            unsafe {
                asm!("imul {:x}, {:x}, {:x}", out(reg) a16, in(reg) b16, in(reg) c16);
            }
            r = a16 as u64;
        }
        8 => {
            panic!("imul of 3params and 8 bits doesn't exist");
        }
        _ => unimplemented!("weird case"),
    }

    r
}*/

pub fn bswap(a: u64, bits: u32) -> u64 {
    let r: u64 = a;

    /*
    match bits {
        64 => {
            unsafe {
                asm!("bswap {}", inout(reg) r);
            }
        }
        32 => {
            let mut a32 = a as u32;
            unsafe {
                asm!("bswap {:e}", inout(reg) a32);
            }
            r = a32 as u64;
        }
        16 => {
            r = 0;
        }
        _ => {
            unimplemented!("doesnt exist this bswap");
        }
    }*/

    r
}

pub fn movzx(b: u64) -> u64 {
    let r: u64 = 0;

    /*
    unsafe {
        asm!("movzx {}, {}", out(reg) r, in(reg) b);
    } */

    r
}

pub fn movsx(b: u64, bits0: u32, bits1: u32) -> u64 {
    let r: u64 = 0;
    let b32 = b as u32;
    let b16 = b as u16;
    let b8 = b as u8;

    /*
    match bits0 {
        64 => {
            match bits1 {
                32 => {
                    panic!("this movsx case doesn't exist");
                }
                16 => {
                    unsafe {
                        asm!("movsx {}, {:x}", out(reg) r, in(reg) b16);
                    }
                }
                8 => {
                    unsafe {
                        asm!("movsx {}, {}", out(reg) r, in(reg_byte) b8);
                    }
                }
                _ => panic!("wrong case"),
            }
        }
        32 => {
            let mut r32:u32;
            match bits1 {
                16 => {
                    unsafe {
                        asm!("movsx {:e}, {:x}", out(reg) r32, in(reg) b16);
                    }
                }
                8 => {
                    unsafe {
                        asm!("movsx {:e}, {}", out(reg) r32, in(reg_byte) b8);
                    }
                }
                _ => panic!("wrong case"),
            }
            r = r32 as u64;
        }
        16 => {
            let mut r16:u16;
            unsafe {
                asm!("movsx {:x}, {}", out(reg) r16, in(reg_byte) b8);
            }
            r = r16 as u64
        }
        _ => panic!("wrong case"),
    }*/

    r
}

pub fn movsxd(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("movsxd {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn cmovs(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("cmovs {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn cmovo(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("cmovs {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn btc(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("btc {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn bts(a: u64, b: u64) -> u64 {
    let r: u64 = a;
    /*
    unsafe {
        asm!("bts {}, {}", inout(reg) r, in(reg) b);
    } */

    r
}

pub fn bsf(a: u64, b: u64, bits: u32, flags: u32) -> (u64, u32) {
    let new_flags: u32 = 0;
    let r: u64 = a;
    /*
    match bits {
        64 => {
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",
                    "bsf {}, {}",
                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",
                    in(reg) flags,
                    inout(reg) r, in(reg) b,
                    out(reg) new_flags,
                );
            }
        }
        32 => {
            let mut r32 = a as u32;
            let b32 = b as u32;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",
                    "bsf {:e}, {:e}",
                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",
                    in(reg) flags,
                    inout(reg) r32, in(reg) b32,
                    out(reg) new_flags,
                );
            }
            r = r32 as u64;
        }
        16 => {
            let mut r16 = a as u16;
            let b16 = b as u16;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",
                    "bsf {:x}, {:x}",
                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",
                    in(reg) flags,
                    inout(reg) r16, in(reg) b16,
                    out(reg) new_flags,
                );
            }
            r = r16 as u64;
        }
        _ => panic!("weird size"),
    }*/

    (r, new_flags)
}

pub fn bsr(a: u64, b: u64, bits: u32, flags: u32) -> (u64, u32) {
    let new_flags: u32 = 0;
    let r: u64 = a;
    /*
    match bits {
        64 => {
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",
                    "bsr {}, {}",
                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",
                    in(reg) flags,
                    inout(reg) r, in(reg) b,
                    out(reg) new_flags,
                );
            }
        }
        32 => {
            let mut r32 = a as u32;
            let b32 = b as u32;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",
                    "bsr {:e}, {:e}",
                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",
                    in(reg) flags,
                    inout(reg) r32, in(reg) b32,
                    out(reg) new_flags,
                );
            }
            r = r32 as u64;
        }
        16 => {
            let mut r16 = a as u16;
            let b16 = b as u16;
            unsafe {
                asm!(
                    "xor rax, rax",
                    "mov eax, {:e}",
                    "push rax",
                    "popfq",
                    "bsr {:x}, {:x}",
                    "pushfq",
                    "pop rax",
                    "mov {:e}, eax",
                    in(reg) flags,
                    inout(reg) r16, in(reg) b16,
                    out(reg) new_flags,
                );
            }
            r = r16 as u64;
        }
        _ => panic!("weird size"),
    }*/

    (r, new_flags)
}
