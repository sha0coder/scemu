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
        return (((rs as u16) & 0xff) as u8) as  i8
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
  
}