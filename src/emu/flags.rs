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

pub const MIN_I64:i64 = -9223372036854775808;
pub const MAX_I64:i64 = 0x7fffffffffffffff;
pub const MIN_U64:u64 = 0;
pub const MAX_U64:u64 = 0xffffffffffffffff;

#[derive(Clone)]
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

    pub fn dump(&self) -> u32 {
        let mut flags:u32 = 0;

        if self.f_cf { flags |= 1; }
        if self.f_pf { flags |= 4; }
        if self.f_af { flags |= 0x10; }
        if self.f_zf { flags |= 0x40; }
        if self.f_sf { flags |= 0x80; }
        if self.f_tf { flags |= 0x100; }
        if self.f_if { flags |= 0x200; }
        if self.f_of { flags |= 0x800; }

        flags
    }

    pub fn load(&mut self, flags:u32) {
        self.f_cf = flags & 1 == 1;
        self.f_pf = flags & 4 >> 2 == 1;
        self.f_af = flags & 0x10 >> 4 == 1;
        self.f_zf = flags & 0x40 >> 6 == 1;
        self.f_sf = flags & 0x80 >> 7 == 1;
        self.f_tf = flags & 0x100 >> 8 == 1;
        self.f_of = flags & 0x800 >> 11 == 1;
    }



    /// FLAGS ///
    /// 
    /// overflow 0xffffffff + 1     
    /// carry    0x7fffffff + 1     o  0x80000000 - 1       o    0 - 1
    


    pub fn check_carry_sub_byte(&mut self, a:u64, b:u64) {
        self.f_cf = (b as u8) > (a as u8);
    }

    pub fn check_overflow_sub_byte(&mut self, a:u64, b:u64) -> i8 {
        let cf = false;
        let rs:i16;
    
        if cf {
            rs = (a as i8) as i16 - (b as i8) as i16 - 1;
        } else {
            rs = (a as i8) as i16 - (b as i8) as i16;
        }
    
        self.f_of = rs < MIN_I8 as i16 || rs > MAX_I8 as i16;

        (((rs as u16) & 0xff) as u8) as  i8
    }

    pub fn check_carry_sub_word(&mut self, a:u64, b:u64) {
        self.f_cf = (b as u16) > (a as u16);
    }

    pub fn check_overflow_sub_word(&mut self, a:u64, b:u64) -> i16 {
        let cf = false;
        let rs:i32;
    
        if cf {
            rs = (a as i16) as i32 - (b as i16) as i32 - 1;
        } else {
            rs = (a as i16) as i32 - (b as i16) as i32;
        }
    
        self.f_of = rs < MIN_I16 as i32 || rs > MAX_I16 as i32;
        (((rs as u32) & 0xffff) as u16) as i16
    }

    pub fn check_carry_sub_qword(&mut self, a:u64, b:u64) {
        self.f_cf = b > a;
    }

    pub fn check_carry_sub_dword(&mut self, a:u64, b:u64) {
        self.f_cf = (b as u32) > (a as u32);
    }

    pub fn check_overflow_sub_qword(&mut self, a:u64, b:u64) -> i64 {
        let cf = false;
        let rs:i128;
    
        if cf {
            rs = (a as i64) as i128 - (b as i64) as i128 - 1;
        } else {
            rs = (a as i64) as i128 - (b as i64) as i128;
        }
    
        self.f_of = rs < MIN_I64 as i128 || rs > MAX_I64 as i128;
        (((rs as u128) & 0xffffffff_ffffffff) as u64) as i64
    }

    pub fn check_overflow_sub_dword(&mut self, a:u64, b:u64) -> i32 {
        let cf = false;
        let rs:i64;
    
        if cf {
            rs = (a as i32) as i64 - (b as i32) as i64 - 1;
        } else {
            rs = (a as i32) as i64 - (b as i32) as i64;
        }
    
        self.f_of = rs < MIN_I32 as i64 || rs > MAX_I32 as i64;
        (((rs as u64) & 0xffffffff) as u32) as i32
    }

    
    pub fn calc_flags(&mut self, final_value:u64, bits:u8) {
        
        match bits {
            64 => self.f_sf = (final_value as i64) < 0,
            32 => self.f_sf = (final_value as i32) < 0,
            16 => self.f_sf = (final_value as i16) < 0,
            8  => self.f_sf = (final_value as i8) < 0,
            _ => panic!("weird size")
        }
        
        self.f_zf = final_value == 0;
        self.f_pf = (final_value & 0xff) % 2 == 0;
        self.f_tf = false;        
    }

    

    pub fn add64(&mut self, value1:u64, value2:u64) -> u64 {
        let unsigned:u128 = value1 as u128 + value2 as u128;

        self.f_sf = (unsigned as i64) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.f_of = (value1 as i64) > 0 && (unsigned as i64) < 0;
        self.f_cf = unsigned > 0xffffffffffffffff;

        (unsigned & 0xffffffffffffffff) as u64
    }

    pub fn add32(&mut self, value1:u64, value2:u64) -> u64 {
        let unsigned:u64 = value1 + value2;

        self.f_sf = (unsigned as i32) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.f_of = (value1 as i32) > 0 && (unsigned as i32) < 0;
        self.f_cf = unsigned > 0xffffffff;

        unsigned & 0xffffffff 
    }

    pub fn add16(&mut self, value1:u64, value2:u64) -> u64 {
        if value1 > 0xffff || value2 > 0xffff {
            panic!("add16 with a bigger precision");
        }

        let unsigned:u32 = value1 as u32 + value2 as u32;

        self.f_sf = (unsigned as i16) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.f_of = (value1 as i16) > 0 && (unsigned as i16) < 0;
        self.f_cf = unsigned > 0xffff;

        (unsigned & 0xffff) as u64
    }

    pub fn add8(&mut self, value1:u64, value2:u64) -> u64 {
        if value1 > 0xff || value2 > 0xff {
            panic!("add8 with a bigger precision");
        }

        let unsigned:u16 = value1 as u16 + value2 as u16;

        self.f_sf = (unsigned as i8) < 0;
        self.f_zf = unsigned == 0;
        self.f_pf = unsigned % 2 == 0;
        self.f_of = (value1 as i8) > 0 && (unsigned as i8) < 0;
        self.f_cf = unsigned > 0xff;

        (unsigned & 0xff) as u64
    }

    pub fn sub64(&mut self, value1:u64, value2:u64) -> u64 {
        let r:i64;

        self.check_carry_sub_qword(value1, value2);
        r = self.check_overflow_sub_qword(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = r < 0;
        self.f_pf = ((r as u64) & 0xff) % 2 == 0;

        r as u64
    }

    pub fn sub32(&mut self, value1:u64, value2:u64) -> u64 {
        let r:i32;

        let val1 = value1 & 0xffffffff;
        let val2 = value2 & 0xffffffff;

        self.check_carry_sub_dword(value1, value2);
        r = self.check_overflow_sub_dword(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = r < 0;
        self.f_pf = ((r as u32) & 0xff) % 2 == 0;

        r as u64
    }

    pub fn sub16(&mut self, value1:u64, value2:u64) -> u64 {
        let r:i16;

        let val1 = value1 & 0xffff;
        let val2 = value2 & 0xffff;

        self.check_carry_sub_word(val1, val2);
        r = self.check_overflow_sub_word(val1, val2);
        self.f_zf = val1 == val2;

        self.f_sf = r < 0;
        self.f_pf = ((r as u16) & 0xff) % 2 == 0;

        (r as u16) as u64
    }

    pub fn sub8(&mut self, value1:u64, value2:u64) -> u64 {
        let r:i8;

        let val1:u64 = value1 & 0xff;
        let val2:u64 = value2 & 0xff;
   
        self.check_carry_sub_byte(val1, val2);
        r = self.check_overflow_sub_byte(val1, val2);
        self.f_zf = val1 == val2;

        self.f_sf = r < 0;
        self.f_pf = (r as u8) % 2 == 0;
        (r as u8) as u64
    }

    pub fn inc64(&mut self, value:u64) -> u64 { 
        if value == 0xffffffffffffffff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7fffffffffffffff;
        self.f_sf = value > 0x7fffffffffffffff;
        self.f_pf = (((value as i64) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        value + 1
    }

    pub fn inc32(&mut self, value:u64) -> u64 { 
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
        value + 1
    }

    pub fn inc16(&mut self, value:u64) -> u64 {
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
        value + 1
    }

    pub fn inc8(&mut self, value:u64) -> u64 {
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
        value + 1
    }

    pub fn dec64(&mut self, value:u64) -> u64 { 
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xffffffffffffffff;
        }
        self.f_of = value == 0x8000000000000000;
        self.f_pf = (((value as i64) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = false;

        self.f_zf = value == 1;

        value - 1
    }

    pub fn dec32(&mut self, value:u64) -> u64 { 
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

        value - 1
    }

    pub fn dec16(&mut self, value:u64) -> u64 { 
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

        value - 1
    }

    pub fn dec8(&mut self, value:u64) -> u64 { 
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

        value - 1
    }

    pub fn neg64(&mut self, value:u64) -> u64 {
        self.f_of = value == 0x8000000000000000;
        self.f_cf = true;

        let mut ival = value as i32;
        ival = -ival;

        let res = ival as u64;

        self.calc_flags(res, 64);
        res
    }

    pub fn neg32(&mut self, value:u64) -> u64 {
        self.f_of = value == 0x80000000;
        self.f_cf = true;

        let mut ival = value as i32;
        ival = -ival;

        let res = ival as u64;

        self.calc_flags(res, 32);
        res
    }

    pub fn neg16(&mut self, value:u64) -> u64 {
        self.f_of = value == 0x8000;
        self.f_cf = true;
        
        let mut ival = value as i16;
        ival = -ival;

        let res = ival as u16 as u64;

        self.calc_flags(res, 16);
        res
    }

    pub fn neg8(&mut self, value:u64) -> u64 {
        self.f_of = value == 0x80;
        self.f_cf = true;
        
        let mut ival = value as i8;
        ival = -ival;

        let res = ival as u8 as u64;

        self.calc_flags(res, 8);
        res
    }

    //// sal sar signed ////

    pub fn sal2p64(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned128:u128 = value0 as u128;

        for _ in 0..value1 {
            unsigned128 *= 2;
        }

        self.f_cf = unsigned128 > 0xffffffffffffffff;
        let result = (unsigned128 & 0xffffffffffffffff) as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn sal2p32(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffffffff;
        let result = unsigned64 & 0xffffffff;
        self.calc_flags(result, 32);
        result
    }

    pub fn sal2p16(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffff;
        let result = unsigned64 & 0xffff;
        self.calc_flags(result, 16);
        result
    }

    pub fn sal2p8(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xff;
        let result  = unsigned64 & 0xff;
        self.calc_flags(result, 8);
        result
    }

    pub fn sal1p64(&mut self, value:u64) -> u64 {
        let unsigned64:u128 = value as u128 * 2;
        self.f_cf = unsigned64 > 0xffffffffffffffff;
        let res = (unsigned64 & 0xffffffffffffffff) as u64;
        self.calc_flags(res, 64);
        res
    }

    pub fn sal1p32(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value * 2;
        self.f_cf = unsigned64 > 0xffffffff;
        let res = unsigned64 & 0xffffffff;
        self.calc_flags(res, 32);
        res
    }

    pub fn sal1p16(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value * 2;
        self.f_cf = unsigned64 > 0xffff;
        let res = unsigned64 & 0xffff;
        self.calc_flags(res, 16);
        res
    }

    pub fn sal1p8(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value * 2;
        self.f_cf = unsigned64 > 0xff;
        let res = unsigned64 & 0xff;
        self.calc_flags(res, 8);
        res
    }

    pub fn sar2p64(&mut self, value0:u64, value1:u64) -> u64 {
        let mut signed64:i64 = value0 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xffffffff;
        let result  = signed64 as i32 as u32 as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn sar2p32(&mut self, value0:u64, value1:u64) -> u64 {
        let mut signed64:i64 = value0 as i32 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xffffffff;
        let result  = signed64 as i32 as u32 as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn sar2p16(&mut self, value0:u64, value1:u64) -> u64 {
        let mut signed64:i64 = value0 as i32 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xffff;
        let result  = signed64 as i32 as u32 as u64;
        self.calc_flags(result, 16);
        result
    }

    pub fn sar2p8(&mut self, value0:u64, value1:u64) -> u64 {
        let mut signed64:i64 = value0 as i32 as i64;

        for _ in 0..value1 {
            signed64 /= 2;
        }

        self.f_cf = signed64 > 0xff;
        let result  = signed64 as i32 as u32 as u64;
        self.calc_flags(result, 8);
        result
    }

    pub fn sar1p64(&mut self, value:u64) -> u64 {
        let signed128:i128 = (value as i64 as i128) / 2;
        self.f_cf = signed128 > 0xffffffffffffffff;
        let res = signed128 as i64 as u64;
        self.calc_flags(res, 64);
        res
    }

    pub fn sar1p32(&mut self, value:u64) -> u64 {
        let signed64:i64 = (value as i32 as i64) / 2;
        self.f_cf = signed64 > 0xffffffff;
        let res = signed64 as i32 as u32 as u64;
        self.calc_flags(res, 32);
        res
    }

    pub fn sar1p16(&mut self, value:u64) -> u64 {
        let signed64:i64 = (value as i32 as i64) / 2;
        self.f_cf = signed64 > 0xffff;
        let res = signed64 as i32 as u32 as u64;
        self.calc_flags(res, 16);
        res
    }

    pub fn sar1p8(&mut self, value:u64) -> u64 {
        let signed64:i64 = (value as i32 as i64) / 2;
        self.f_cf = signed64 > 0xff;
        let res = signed64 as i32 as u32 as u64;
        self.calc_flags(res, 8);
        res
    }

    //// shr shl unsigned ////
    
    pub fn shl2p64(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned128:u128 = value0 as u128;

        for _ in 0..value1 {
            unsigned128 *= 2;
        }

        self.f_cf = unsigned128 > 0xffffffffffffffff;
        let result = (unsigned128 & 0xffffffffffffffff) as u64;
        self.calc_flags(result, 64);

        result
    }

    pub fn shl2p32(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffffffff;
        let result = unsigned64 & 0xffffffff;
        self.calc_flags(result, 32);

        result
    }

    pub fn shl2p16(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xffff;
        let result  = unsigned64 & 0xffff;
        self.calc_flags(result, 16);
        result
    }

    pub fn shl2p8(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 *= 2;
        }

        self.f_cf = unsigned64 > 0xff;
        let result  = unsigned64 & 0xff;
        self.calc_flags(result, 8);
        result
    }
    
    pub fn shl1p64(&mut self, value:u64) -> u64 {
        let unsigned64:u128 = value as u128 * 2;
        self.f_cf = unsigned64 > 0xffffffffffffffff;
        let res = (unsigned64 & 0xffffffffffffffff) as u64;
        self.calc_flags(res, 64);
        res
    }

    pub fn shl1p32(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value * 2;
        self.f_cf = unsigned64 > 0xffffffff;
        let res = unsigned64 & 0xffffffff;
        self.calc_flags(res, 32);
        res
    }

    pub fn shl1p16(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value * 2;
        self.f_cf = unsigned64 > 0xffff;
        let res = unsigned64 & 0xffff;
        self.calc_flags(res, 16);
        res
    }

    pub fn shl1p8(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value * 2;
        self.f_cf = unsigned64 > 0xff;
        let res = unsigned64 & 0xff;
        self.calc_flags(res, 8);
        res
    }

    pub fn shr2p64(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned128:u128 = value0 as u128;

        for _ in 0..value1 {
            unsigned128 /= 2;
        }

        self.f_cf = unsigned128 > 0xffffffffffffffff;
        let result = unsigned128 as u64;
        self.calc_flags(result, 64);
        result
    }

    pub fn shr2p32(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 /= 2;
        }

        self.f_cf = unsigned64 > 0xffffffff;
        let result = unsigned64 & 0xffffffff;
        self.calc_flags(result, 32);
        result
    }

    pub fn shr2p16(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0;

        for _ in 0..value1 {
            unsigned64 /= 2;
        }

        self.f_cf = unsigned64 > 0xffff;
        let result = unsigned64 & 0xffff;
        self.calc_flags(result, 16);
        result
    }

    pub fn shr2p8(&mut self, value0:u64, value1:u64) -> u64 {
        let mut unsigned64:u64 = value0 as u64;

        for _ in 0..value1 {
            unsigned64 /= 2;
        }

        self.f_cf = unsigned64 > 0xff;
        let result  = unsigned64 & 0xff;
        self.calc_flags(result, 8);
        result
    }

    pub fn shr1p64(&mut self, value:u64) -> u64 {
        let unsigned128:u128 = (value as u128) / 2;
        self.f_cf = unsigned128 > 0xffffffffffffffff;
        let res = unsigned128 as u64;
        self.calc_flags(res, 64);
        res
    }

    pub fn shr1p32(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value / 2;
        self.f_cf = unsigned64 > 0xffffffff;
        let res = unsigned64 & 0xffffffff;
        self.calc_flags(res, 32);
        res
    }

    pub fn shr1p16(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value / 2;
        self.f_cf = unsigned64 > 0xffff;
        let res = unsigned64 & 0xffff;
        self.calc_flags(res, 16);
        res
    }

    pub fn shr1p8(&mut self, value:u64) -> u64 {
        let unsigned64:u64 = value / 2;
        self.f_cf = unsigned64 > 0xff;
        let res = unsigned64 & 0xff;
        self.calc_flags(res, 8);
        res
    }

    pub fn test(&mut self, value0:u64, value1:u64, sz:u8) {
        let result:u64 = value0 & value1;

        self.f_zf = result == 0;
        self.f_cf = false;
        self.f_of = false;
        self.f_pf = (result & 0xff) % 2 == 0;

        match sz {
            64 => self.f_sf = (result as i64) < 0,
            32 => self.f_sf = (result as i32) < 0,
            16 => self.f_sf = (result as i16) < 0,
            8  => self.f_sf = (result as i8) < 0,
            _  => unreachable!("weird size")
        }
    }

    //// imul //// 

    pub fn imul64p2(&mut self, value0:u64, value1:u64) -> u64 {
        let result:i128 = value0 as i64 as i128 * value1 as i64 as i128;
        let uresult:u128 = result as u128;

        if uresult > 0xffffffffffffffff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res:u64 = (uresult & 0xffffffffffffffff) as u64;

        self.calc_flags(res, 64);
        res
    }
    
    pub fn imul32p2(&mut self, value0:u64, value1:u64) -> u64 {
        let result:i64 = value0 as i32 as i64 * value1 as i32 as i64;
        let uresult:u64 = result as u64;

        if uresult > 0xffffffff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res:u64 = uresult & 0xffffffff;

        self.calc_flags(res, 32);
        res
    }

    pub fn imul16p2(&mut self, value0:u64, value1:u64) -> u64 {
        let result:i32 = value0 as i16 as i32 * value1 as i16 as i32;
        let uresult:u32 = result as u32;

        if uresult > 0xffff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res = (uresult & 0xffff) as u64;

        self.calc_flags(res, 16);
        res
    }

    pub fn imul8p2(&mut self, value0:u64, value1:u64) -> u64 {
        let result:i16 = value0 as i8 as i16 * value1 as i8 as i16;
        let uresult:u16 = result as u16;

        if uresult > 0xff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res = (uresult & 0xff) as u64;

        self.calc_flags(res, 8);
        res
    }

}
