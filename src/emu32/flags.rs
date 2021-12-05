pub const MIN_I8:i8 = -128;
pub const MAX_I8:i8 = 0x7f;
pub const MIN_U8:u8 = 0;
pub const MAX_U8:u8 = 0xff;

pub const MIN_I16:i16 = -32768;
pub const MAX_I16:i16 = 0x7fff;
pub const MIN_U16:u16 = 0;
pub const MAX_U16:u16 = 0xffff;

pub const MIN_I32:i32 = -2147483648;
pub const MAX_I32:i32 = 0x7fffffff;
pub const MIN_U32:u32 = 0;
pub const MAX_U32:u32 = 0xffffffff;


pub struct Flags {
    pub f_cf: bool,
    pub f_pf: bool,
    pub f_af: bool,
    pub f_zf: bool,
    pub f_sf: bool,
    pub f_tf: bool,
    pub f_if: bool,
    pub f_df: bool,
    pub f_of: bool,
    pub f_nt: bool,
}

impl Flags {
    pub fn new() -> Flags {
        Flags {
            f_cf: false,
            f_pf: false,
            f_af: false,
            f_zf: false,
            f_sf: false,
            f_tf: false,
            f_if: false,
            f_df: false,
            f_of: false,
            f_nt: false, 
        }
    }


    pub fn clear(&mut self) {
        self.f_cf = false;
        self.f_pf = false;
        self.f_af = false;
        self.f_zf = false;
        self.f_sf = false;
        self.f_tf = false;
        self.f_if = false;
        self.f_df = false;
        self.f_of = false;
        self.f_nt = false;
    }

    pub fn print(&self) {
        println!("--- flags ---");
        println!("cf: {}", self.f_cf);
        println!("pf: {}", self.f_pf);
        println!("af: {}", self.f_af);
        println!("zf: {}", self.f_zf);
        println!("sf: {}", self.f_sf);
        println!("tf: {}", self.f_tf);
        println!("if: {}", self.f_if);
        println!("df: {}", self.f_df);
        println!("of: {}", self.f_of);
        println!("nt: {}", self.f_nt);
        println!("---");
    }



    /// FLAGS ///
    /// 
    /// overflow 0xffffffff + 1     
    /// carry    0x7fffffff + 1     o  0x80000000 - 1       o    0 - 1
    


    pub fn check_carry_sub_byte(&mut self, a:u32, b:u32) {
        self.f_cf = (b as u8) > (a as u8);
    }

    pub fn check_overflow_sub_byte(&mut self, a:u32, b:u32) -> i8 {
        let cf = false;
        let rs:i16;
    
        if cf {
            rs = (a as i8) as i16 - (b as i8) as i16 - 1;
        } else {
            rs = (a as i8) as i16 - (b as i8) as i16;
        }
    
        self.f_of = rs < MIN_I8 as i16 || rs > MAX_I8 as i16;
        return (((rs as u16) & 0xff) as u8) as  i8;
    }

    pub fn check_carry_sub_word(&mut self, a:u32, b:u32) {
        self.f_cf = (b as u16) > (a as u16);
    }

    pub fn check_overflow_sub_word(&mut self, a:u32, b:u32) -> i16 {
        let cf = false;
        let rs:i32;
    
        if cf {
            rs = (a as i16) as i32 - (b as i16) as i32 - 1;
        } else {
            rs = (a as i16) as i32 - (b as i16) as i32;
        }
    
        self.f_of = rs < MIN_I16 as i32 || rs > MAX_I16 as i32;
        return (((rs as u32) & 0xffff) as u16) as i16;
    }

    pub fn check_carry_sub_dword(&mut self, a:u32, b:u32) {
        self.f_cf = (b as u32) > (a as u32);
    }

    pub fn check_overflow_sub_dword(&mut self, a:u32, b:u32) -> i32 {
        let cf = false;
        let rs:i64;
    
        if cf {
            rs = (a as i32) as i64 - (b as i32) as i64 - 1;
        } else {
            rs = (a as i32) as i64 - (b as i32) as i64;
        }
    
        self.f_of = rs < MIN_I32 as i64 || rs > MAX_I32 as i64;
        return (((rs as u64) & 0xffffffff) as u32) as i32;
    }

    
    pub fn calc_flags(&mut self, final_value:u32, bits:u8) {
        
        match bits {
            32 => self.f_sf = (final_value as i32) < 0,
            16 => self.f_sf = (final_value as i16) < 0,
            8  => self.f_sf = (final_value as i8) < 0,
            _ => panic!("weird size")
        }
        
        self.f_zf = final_value == 0;
        self.f_pf = (final_value & 0xff) % 2 == 0;
        self.f_tf = false;        
    }

    


    pub fn add32(&mut self, value1:u32, value2:u32) -> u32 {
        let unsigned:u64 = value1 as u64 + value2 as u64;

        self.f_sf = (unsigned as i32) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.f_of = (value1 as i32) > 0 && (unsigned as i32) < 0;
        self.f_cf = unsigned > 0xffffffff;

        return (unsigned & 0xffffffff) as u32;
    }

    pub fn add16(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xffff || value2 > 0xffff {
            panic!("add16 with a bigger precision");
        }

        let unsigned:u32 = value1 as u32 + value2 as u32;

        self.f_sf = (unsigned as i16) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.f_of = (value1 as i16) > 0 && (unsigned as i16) < 0;
        self.f_cf = unsigned > 0xffff;

        return (unsigned & 0xffff) as u32;
    }

    pub fn add8(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xff || value2 > 0xff {
            panic!("add8 with a bigger precision");
        }

        let unsigned:u16 = value1 as u16 + value2 as u16;

        self.f_sf = (unsigned as i8) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = unsigned % 2 == 0;
        self.f_of = (value1 as i8) > 0 && (unsigned as i8) < 0;
        self.f_cf = unsigned > 0xff;

        return (unsigned & 0xff) as u32;
    }

    pub fn sub32(&mut self, value1:u32, value2:u32) -> u32 {
        let r:i32;


        self.check_carry_sub_dword(value1, value2);
        r = self.check_overflow_sub_dword(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = r < 0;
        self.f_pf = ((r as u32) & 0xff) % 2 == 0;

        return r as u32;
    }

    pub fn sub16(&mut self, value1:u32, value2:u32) -> u32 {
        let r:i16;


        self.check_carry_sub_word(value1, value2);
        r = self.check_overflow_sub_word(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = r < 0;
        self.f_pf = ((r as u16) & 0xff) % 2 == 0;

        return (r as u16) as u32;
    }

    pub fn sub8(&mut self, value1:u32, value2:u32) -> u32 {
        let r:i8;

        self.check_carry_sub_byte(value1, value2);
        r = self.check_overflow_sub_byte(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = r < 0;
        self.f_pf = ((r as u8) & 0xff) % 2 == 0;
        return (r as u8) as u32;
    }

    pub fn inc32(&mut self, value:u32) -> u32 { 
        if value == 0xffffffff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7fffffff;
        self.f_sf = value > 0x7fffffff;
        self.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        return value + 1;
    }

    pub fn inc16(&mut self, value:u32) -> u32 {
        if value == 0xffff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7fff;
        self.f_sf = value > 0x7fff;
        self.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        return value + 1;
    }

    pub fn inc8(&mut self, value:u32) -> u32 {
        if value == 0xff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7f;
        self.f_sf = value > 0x7f;
        self.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        return value + 1;
    }

    pub fn dec32(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xffffffff;
        }
        self.f_of = value == 0x80000000;
        self.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = false;

        self.f_zf = value == 1;

        return value - 1;
    }

    pub fn dec16(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xffff;
        }
        self.f_of = value == 0x8000;
        self.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = false;

        self.f_zf = value == 1;

        return value - 1;
    }

    pub fn dec8(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xff;
        }
        self.f_of = value == 0x80;
        self.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = false;

        self.f_zf = value == 1;

        return value - 1;
    }

    pub fn neg32(&mut self, value:u32) -> u32 {
        self.f_of = value == 0x80000000;
        self.f_cf = true;

        let mut ival = value as i32;
        ival = ival * -1;

        let res = ival as u32;

        self.calc_flags(res, 32);
        return res;
    }

    pub fn neg16(&mut self, value:u32) -> u32 {
        self.f_of = value == 0x8000;
        self.f_cf = true;
        
        let mut ival = value as i16;
        ival = ival * -1;

        let res = ival as u16 as u32;

        self.calc_flags(res, 16);
        return res;
    }

    pub fn neg8(&mut self, value:u32) -> u32 {
        self.f_of = value == 0x80;
        self.f_cf = true;
        
        let mut ival = value as i8;
        ival = ival * -1;

        let res = ival as u8 as u32;

        self.calc_flags(res, 8);
        return res;
    }

    //// sal sar signed ////

    pub fn sal2p32(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffffffff;
        let result  = (unsigned64 & 0xffffffff) as u32;
        self.calc_flags(result, 32);
        return result;
    }

    pub fn sal2p16(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffff;
        let result  = (unsigned64 & 0xffff) as u32;
        self.calc_flags(result, 16);
        return result;
    }

    pub fn sal2p8(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xff;
        let result  = (unsigned64 & 0xff) as u32;
        self.calc_flags(result, 8);
        return result;
    }

    pub fn sal1p32(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) * 2;
        self.f_cf = unsigned64 > 0xffffffff;
        let res = (unsigned64 & 0xffffffff) as u32;
        self.calc_flags(res, 32);
        return res;
    }

    pub fn sal1p16(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) * 2;
        self.f_cf = unsigned64 > 0xffff;
        let res = (unsigned64 & 0xffff) as u32;
        self.calc_flags(res, 16);
        return res;
    }

    pub fn sal1p8(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) * 2;
        self.f_cf = unsigned64 > 0xff;
        let res = (unsigned64 & 0xff) as u32;
        self.calc_flags(res, 8);
        return res;
    }

    pub fn sar2p32(&mut self, value0:u32, value1:u32) -> u32 {
        let mut signed64:i64 = value0 as i32 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xffffffff;
        let result  = signed64 as i32 as u32;
        self.calc_flags(result, 32);
        return result;
    }

    pub fn sar2p16(&mut self, value0:u32, value1:u32) -> u32 {
        let mut signed64:i64 = value0 as i32 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xffff;
        let result  = signed64 as i32 as u32;
        self.calc_flags(result, 16);
        return result;
    }

    pub fn sar2p8(&mut self, value0:u32, value1:u32) -> u32 {
        let mut signed64:i64 = value0 as i32 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xff;
        let result  = signed64 as i32 as u32;
        self.calc_flags(result, 8);
        return result;
    }

    pub fn sar1p32(&mut self, value:u32) -> u32 {
        let signed64:i64 = (value as i32 as i64) / 2;
        self.f_cf = signed64 > 0xffffffff;
        let res = signed64 as i32 as u32;
        self.calc_flags(res, 32);
        return res;
    }

    pub fn sar1p16(&mut self, value:u32) -> u32 {
        let signed64:i64 = (value as i32 as i64) / 2;
        self.f_cf = signed64 > 0xffff;
        let res = signed64 as i32 as u32;
        self.calc_flags(res, 16);
        return res;
    }

    pub fn sar1p8(&mut self, value:u32) -> u32 {
        let signed64:i64 = (value as i32 as i64) / 2;
        self.f_cf = signed64 > 0xff;
        let res = signed64 as i32 as u32;
        self.calc_flags(res, 8);
        return res;
    }

    //// shr shl unsigned ////
    
    pub fn shl2p32(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffffffff;
        let result  = (unsigned64 & 0xffffffff) as u32;
        self.calc_flags(result, 32);
        return result;
    }

    pub fn shl2p16(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffff;
        let result  = (unsigned64 & 0xffff) as u32;
        self.calc_flags(result, 16);
        return result;
    }

    pub fn shl2p8(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xff;
        let result  = (unsigned64 & 0xff) as u32;
        self.calc_flags(result, 8);
        return result;
    }

    pub fn shl1p32(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) * 2;
        self.f_cf = unsigned64 > 0xffffffff;
        let res = (unsigned64 & 0xffffffff) as u32;
        self.calc_flags(res, 32);
        return res;
    }

    pub fn shl1p16(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) * 2;
        self.f_cf = unsigned64 > 0xffff;
        let res = (unsigned64 & 0xffff) as u32;
        self.calc_flags(res, 16);
        return res;
    }

    pub fn shl1p8(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) * 2;
        self.f_cf = unsigned64 > 0xff;
        let res = (unsigned64 & 0xff) as u32;
        self.calc_flags(res, 8);
        return res;
    }

    pub fn shr2p32(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 /= 2;
        }

        self.f_cf = unsigned64 > 0xffffffff;
        let result  = (unsigned64 & 0xffffffff) as u32;
        self.calc_flags(result, 32);
        return result;
    }

    pub fn shr2p16(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 /= 2;
        }

        self.f_cf = unsigned64 > 0xffff;
        let result  = (unsigned64 & 0xffff) as u32;
        self.calc_flags(result, 16);
        return result;
    }

    pub fn shr2p8(&mut self, value0:u32, value1:u32) -> u32 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 /= 2;
        }

        self.f_cf = unsigned64 > 0xff;
        let result  = (unsigned64 & 0xff) as u32;
        self.calc_flags(result, 8);
        return result;
    }

    pub fn shr1p32(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) / 2;
        self.f_cf = unsigned64 > 0xffffffff;
        let res = (unsigned64 & 0xffffffff) as u32;
        self.calc_flags(res, 32);
        return res;
    }

    pub fn shr1p16(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) / 2;
        self.f_cf = unsigned64 > 0xffff;
        let res = (unsigned64 & 0xffff) as u32;
        self.calc_flags(res, 16);
        return res;
    }

    pub fn shr1p8(&mut self, value:u32) -> u32 {
        let unsigned64:u64 = (value as u64) / 2;
        self.f_cf = unsigned64 > 0xff;
        let res = (unsigned64 & 0xff) as u32;
        self.calc_flags(res, 8);
        return res;
    }

    pub fn test(&mut self, value0:u32, value1:u32, sz:usize) {
        let result:u32 = value0 & value1;

        self.f_zf = result == 0;
        self.f_cf = false;
        self.f_of = false;
        self.f_pf = (result & 0xff) % 2 == 0;

        match sz {
            32 => self.f_sf = (result as i32) < 0,
            16 => self.f_sf = (result as i16) < 0,
            8  => self.f_sf = (result as i8) < 0,
            _  => panic!("weird size")
        }
    }
}
