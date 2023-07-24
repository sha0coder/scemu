pub const MIN_I8: i8 = -128;
pub const MAX_I8: i8 = 0x7f;
pub const MIN_U8: u8 = 0;
pub const MAX_U8: u8 = 0xff;

pub const MIN_I16: i16 = -32768;
pub const MAX_I16: i16 = 0x7fff;
pub const MIN_U16: u16 = 0;
pub const MAX_U16: u16 = 0xffff;

pub const MIN_I32: i32 = -2147483648;
pub const MAX_I32: i32 = 0x7fffffff;
pub const MIN_U32: u32 = 0;
pub const MAX_U32: u32 = 0xffffffff;

pub const MIN_I64: i64 = -9223372036854775808;
pub const MAX_I64: i64 = 0x7fffffffffffffff;
pub const MIN_U64: u64 = 0;
pub const MAX_U64: u64 = 0xffffffffffffffff;

macro_rules! get_bit {
    ($val:expr, $count:expr) => {
        ($val & (1 << $count)) >> $count
    };
}

macro_rules! set_bit {
    ($val:expr, $count:expr, $bit:expr) => {
        if $bit == 1 {
            $val |= 1 << $count;
        } else {
            $val &= !(1 << $count);
        }
    };
}

macro_rules! xor2 {
    ($val:expr) => {
        ($val ^ (($val) >> 1)) & 0x1
    };
}

#[derive(Clone, Copy, Debug)]
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
    pub f_iopl1: bool,
    pub f_iopl2: bool,
    pub f_nt: bool,
    pub f_rf: bool,
    pub f_vm: bool,
    pub f_ac: bool,
    pub f_vif: bool,
    pub f_vip: bool,
    pub f_id: bool,
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
            f_iopl1: false,
            f_iopl2: false,
            f_nt: false,
            f_rf: false,
            f_vm: false,
            f_ac: false,
            f_vif: false,
            f_vip: false,
            f_id: false,
        }
    }

    pub fn diff(rip: u64, pos: u64, a: Flags, b: Flags) {
        let mut output = format!(
            "\tdiff_flags: pos = {} rip = {:x} in = {:x} out = {:x} ",
            pos,
            rip,
            a.dump(),
            b.dump()
        );
        if a.f_cf != b.f_cf {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_cf", a.f_cf as u8, b.f_cf as u8
            );
        }
        if a.f_pf != b.f_pf {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_pf", a.f_pf as u8, b.f_pf as u8
            );
        }
        if a.f_af != b.f_af {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_af", a.f_af as u8, b.f_af as u8
            );
        }
        if a.f_zf != b.f_zf {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_zf", a.f_zf as u8, b.f_zf as u8
            );
        }
        if a.f_sf != b.f_sf {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_sf", a.f_sf as u8, b.f_sf as u8
            );
        }
        if a.f_tf != b.f_tf {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_tf", a.f_tf as u8, b.f_tf as u8
            );
        }
        if a.f_if != b.f_if {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_if", a.f_if as u8, b.f_if as u8
            );
        }
        if a.f_df != b.f_df {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_df", a.f_df as u8, b.f_df as u8
            );
        }
        if a.f_of != b.f_of {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_of", a.f_of as u8, b.f_of as u8
            );
        }
        if a.f_iopl1 != b.f_iopl1 {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_iopl1", a.f_iopl1 as u8, b.f_iopl1 as u8
            );
        }
        if a.f_iopl2 != b.f_iopl2 {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_iopl2", a.f_iopl2 as u8, b.f_iopl2 as u8
            );
        }
        if a.f_nt != b.f_nt {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_nt", a.f_nt as u8, b.f_nt as u8
            );
        }
        if a.f_rf != b.f_rf {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_rf", a.f_rf as u8, b.f_rf as u8
            );
        }
        if a.f_vm != b.f_vm {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_vm", a.f_vm as u8, b.f_vm as u8
            );
        }
        if a.f_ac != b.f_ac {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_ac", a.f_ac as u8, b.f_ac as u8
            );
        }
        if a.f_vif != b.f_vif {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_vif", a.f_vif as u8, b.f_vif as u8
            );
        }
        if a.f_vip != b.f_vip {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_vip", a.f_vip as u8, b.f_vip as u8
            );
        }
        if a.f_id != b.f_id {
            output = format!(
                "{}{} {:x} -> {:x}; ",
                output, "f_id", a.f_id as u8, b.f_id as u8
            );
        }

        println!("{}", output);
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
        self.f_iopl1 = false;
        self.f_iopl2 = false;
        self.f_nt = false;
        self.f_rf = false;
        self.f_vm = false;
        self.f_ac = false;
        self.f_vif = false;
        self.f_vip = false;
        self.f_id = false;
    }

    pub fn print(&self) {
        println!("--- flags ---");
        println!("0x{:x}", self.dump());
        println!("cf: {}", self.f_cf);
        println!("pf: {}", self.f_pf);
        println!("af: {}", self.f_af);
        println!("zf: {}", self.f_zf);
        println!("sf: {}", self.f_sf);
        println!("tf: {}", self.f_tf);
        println!("if: {}", self.f_if);
        println!("df: {}", self.f_df);
        println!("of: {}", self.f_of);
        println!("iopl1: {}", self.f_iopl1);
        println!("iopl2: {}", self.f_iopl2);
        println!("nt: {}", self.f_nt);
        println!("rf: {}", self.f_rf);
        println!("vm: {}", self.f_vm);
        println!("ac: {}", self.f_ac);
        println!("vif: {}", self.f_vif);
        println!("vip: {}", self.f_vip);
        println!("id: {}", self.f_id);
        println!("---");
    }

    pub fn dump(&self) -> u32 {
        let mut flags: u32 = 0;

        if self.f_cf {
            set_bit!(flags, 0, 1);
        }
        set_bit!(flags, 1, 1); // always 1 in EFLAGS
        if self.f_pf {
            set_bit!(flags, 2, 1);
        }
        // 3 is reserved
        if self.f_af {
            set_bit!(flags, 4, 1);
        }
        // 5 is reserved
        if self.f_zf {
            set_bit!(flags, 6, 1);
        }
        if self.f_sf {
            set_bit!(flags, 7, 1);
        }
        if self.f_tf {
            set_bit!(flags, 8, 1);
        }
        if self.f_if {
            set_bit!(flags, 9, 1);
        }
        if self.f_df {
            set_bit!(flags, 10, 1);
        }
        if self.f_of {
            set_bit!(flags, 11, 1);
        }

        if self.f_iopl1 {
            set_bit!(flags, 12, 1);
        }
        if self.f_iopl2 {
            set_bit!(flags, 13, 1);
        }

        if self.f_nt {
            set_bit!(flags, 14, 1);
        }
        set_bit!(flags, 15, 0);
        if self.f_rf {
            set_bit!(flags, 16, 1);
        }
        if self.f_vm {
            set_bit!(flags, 17, 1);
        }
        if self.f_ac {
            set_bit!(flags, 18, 1);
        }
        if self.f_vif {
            set_bit!(flags, 19, 1);
        }
        if self.f_vip {
            set_bit!(flags, 20, 1);
        }
        if self.f_id {
            set_bit!(flags, 21, 1);
        }

        flags
    }

    pub fn load(&mut self, flags: u32) {
        self.f_cf = get_bit!(flags, 0) == 1;
        self.f_pf = get_bit!(flags, 2) == 1;
        self.f_af = get_bit!(flags, 4) == 1;
        self.f_zf = get_bit!(flags, 6) == 1;
        self.f_sf = get_bit!(flags, 7) == 1;
        self.f_tf = get_bit!(flags, 8) == 1;
        self.f_if = get_bit!(flags, 9) == 1;
        self.f_df = get_bit!(flags, 10) == 1;
        self.f_of = get_bit!(flags, 11) == 1;
        self.f_iopl1 = get_bit!(flags, 12) == 1;
        self.f_iopl2 = get_bit!(flags, 13) == 1;
        self.f_nt = get_bit!(flags, 14) == 1;
        self.f_rf = get_bit!(flags, 16) == 1;
        self.f_vm = get_bit!(flags, 17) == 1;
        self.f_ac = get_bit!(flags, 18) == 1;
        self.f_vif = get_bit!(flags, 19) == 1;
        self.f_vip = get_bit!(flags, 20) == 1;
        self.f_id = get_bit!(flags, 21) == 1;
    }

    /// FLAGS ///
    ///
    /// overflow 0xffffffff + 1     
    /// carry    0x7fffffff + 1     or  0x80000000 - 1       or   0 - 1

    pub fn check_carry_sub_byte(&mut self, a: u64, b: u64) {
        self.f_cf = (b as u8) > (a as u8);
    }

    pub fn check_overflow_sub_byte(&mut self, a: u64, b: u64) -> i8 {
        let cf = false;
        let rs: i16;

        if cf {
            rs = (a as i8) as i16 - (b as i8) as i16 - 1;
        } else {
            rs = (a as i8) as i16 - (b as i8) as i16;
        }

        self.f_of = rs < MIN_I8 as i16 || rs > MAX_I8 as i16;

        (((rs as u16) & 0xff) as u8) as i8
    }

    pub fn check_carry_sub_word(&mut self, a: u64, b: u64) {
        self.f_cf = (b as u16) > (a as u16);
    }

    pub fn check_overflow_sub_word(&mut self, a: u64, b: u64) -> i16 {
        let cf = false;
        let rs: i32;

        if cf {
            rs = (a as i16) as i32 - (b as i16) as i32 - 1;
        } else {
            rs = (a as i16) as i32 - (b as i16) as i32;
        }

        self.f_of = rs < MIN_I16 as i32 || rs > MAX_I16 as i32;
        (((rs as u32) & 0xffff) as u16) as i16
    }

    pub fn check_carry_sub_qword(&mut self, a: u64, b: u64) {
        self.f_cf = b > a;
    }

    pub fn check_carry_sub_dword(&mut self, a: u64, b: u64) {
        self.f_cf = (b as u32) > (a as u32);
    }

    pub fn check_overflow_sub_qword(&mut self, a: u64, b: u64) -> i64 {
        let cf = false;
        let rs: i128;

        if cf {
            rs = (a as i64) as i128 - (b as i64) as i128 - 1;
        } else {
            rs = (a as i64) as i128 - (b as i64) as i128;
        }

        self.f_of = rs < MIN_I64 as i128 || rs > MAX_I64 as i128;
        (((rs as u128) & 0xffffffff_ffffffff) as u64) as i64
    }

    pub fn check_overflow_sub_dword(&mut self, a: u64, b: u64) -> i32 {
        let cf = false;
        let rs: i64;

        if cf {
            rs = (a as i32) as i64 - (b as i32) as i64 - 1;
        } else {
            rs = (a as i32) as i64 - (b as i32) as i64;
        }

        self.f_of = rs < MIN_I32 as i64 || rs > MAX_I32 as i64;
        (((rs as u64) & 0xffffffff) as u32) as i32
    }

    pub fn calc_flags(&mut self, final_value: u64, bits: u32) {
        match bits {
            64 => self.f_sf = (final_value as i64) < 0,
            32 => self.f_sf = (final_value as i32) < 0,
            16 => self.f_sf = (final_value as i16) < 0,
            8 => self.f_sf = (final_value as i8) < 0,
            _ => unreachable!("weird size"),
        }

        self.f_zf = final_value == 0;
        self.f_tf = false;
    }

    pub fn calc_pf(&mut self, final_value: u8) {
        let lsb = (final_value & 0xFF) as u8;
        let mut count = 0;
        for i in 0..8 {
            if (lsb & (1 << i)) != 0 {
                count += 1;
            }
        }
        self.f_pf = count % 2 == 0;
    }

    pub fn calc_af(&mut self, value1: u64, value2: u64, result: u64, bits: u64) {
        //let mask = bits*8-4;
        let mask = 1<<4;
        self.f_af = ((value1 ^ value2 ^ result) & mask) != 0;
        //self.f_af = (value1 & 0x0f) + (value2 & 0x0f) > 0x09;
    }



    pub fn add64(&mut self, value1: u64, value2: u64) -> u64 {
        let unsigned: u128 = value1 as u128 + value2 as u128;

        self.f_sf = (unsigned as i64) < 0;
        self.f_zf = (unsigned & 0xffffffff_ffffffff) == 0;
        //self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.calc_pf(unsigned as u8);
        let (result, carry) = (value2).overflowing_add(value1);
        let (_, overflow) = (value2 as i64).overflowing_add(value1 as i64);
        self.f_of = overflow;
        self.f_cf = carry;
        self.calc_af(value1, value2, result, 64);
        
        /*
        let low_nibble_value1 = value1 & 0xf;
        let low_nibble_value2 = value2 & 0xf;
        self.f_af = (low_nibble_value1 > 0x7) && (low_nibble_value2 > 0x7);
        */

        result
    }

    pub fn add32(&mut self, value1: u64, value2: u64) -> u64 {
        let unsigned: u64 = value1 + value2;

        self.f_sf = (unsigned as i32) < 0;
        self.f_zf = (unsigned & 0xffffffff) == 0;
        //self.f_pf = (unsigned & 0xff) % 2 == 0;
        self.calc_pf(unsigned as u8);
        let (result, carry) = (value2 as u32).overflowing_add(value1 as u32);
        let (_, overflow) = (value2 as u32 as i32).overflowing_add(value1 as u32 as i32);
        self.f_of = overflow;
        self.f_cf = carry;
        self.calc_af(value1, value2, result as u64, 32);

        result as u64
    }

    pub fn add16(&mut self, value1: u64, value2: u64) -> u64 {
        if value1 > 0xffff || value2 > 0xffff {
            panic!("add16 with a bigger precision");
        }

        let unsigned: u32 = value1 as u32 + value2 as u32;

        self.f_sf = (unsigned as i16) < 0;
        self.f_zf = (unsigned & 0xffff) == 0;
        self.calc_pf(unsigned as u8);
        let (result, carry) = (value2 as u16).overflowing_add(value1 as u16);
        let (_, overflow) = (value2 as u16 as i16).overflowing_add(value1 as u16 as i16);
        self.f_of = overflow;
        self.f_cf = carry;
        self.calc_af(value1, value2, result as u64, 16);

        result as u64
    }

    pub fn add8(&mut self, value1: u64, value2: u64) -> u64 {
        let unsigned: u16 = value1 as u8 as u16 + value2 as u8 as u16;

        self.f_sf = (unsigned as i8) < 0;
        self.f_zf = (unsigned & 0xff) == 0;
        self.calc_pf(unsigned as u8);
        let (result, carry) = (value2 as u8).overflowing_add(value1 as u8);
        let (_, overflow) = (value2 as u8 as i8).overflowing_add(value1 as u8 as i8);
        self.f_of = overflow;
        self.f_cf = carry;
        self.calc_af(value1, value2, result as u64, 8);

        result as u64
    }

    pub fn sub64(&mut self, value1: u64, value2: u64) -> u64 {
        // let r:i64;

        let (r, carry) = (value1).overflowing_sub(value2);
        let (_, overflow) = (value1 as i64).overflowing_sub(value2 as i64);
        self.f_cf = carry;
        self.f_of = overflow;

        //self.check_carry_sub_qword(value1, value2);
        //r = self.check_overflow_sub_qword(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = (r as i64) < 0;
        self.calc_pf(r as u64 as u8);
        self.calc_af(value1, value2, r, 64);
       
        /*
        let low_nibble_value1 = value1 & 0xf;
        let low_nibble_value2 = value2 & 0xf;
        self.f_af = low_nibble_value2 > low_nibble_value1;
        */

        //self.f_af = (r & 0x1000000000000000) != 0;

        r as u64
    }

    pub fn sub32(&mut self, value1: u64, value2: u64) -> u64 {
        //let r:i32;

        let (r, carry) = (value1 as u32).overflowing_sub(value2 as u32);
        let (_, overflow) = (value1 as u32 as i32).overflowing_sub(value2 as u32 as i32);
        self.f_cf = carry;
        self.f_of = overflow;

        //self.check_carry_sub_dword(value1, value2);
        //r = self.check_overflow_sub_dword(value1, value2);
        self.f_zf = value1 == value2;

        self.f_sf = (r as i32) < 0;
        self.calc_pf(r as u32 as u8);
        //self.f_af = (r & 0x10000000) != 0;
        self.calc_af(value1, value2, r as u64, 32);

        r as u64
    }

    pub fn sub16(&mut self, value1: u64, value2: u64) -> u64 {
        //let r:i16;

        let (r, carry) = (value1 as u16).overflowing_sub(value2 as u16);
        let (_, overflow) = (value1 as u16 as i16).overflowing_sub(value2 as u16 as i16);
        self.f_cf = carry;
        self.f_of = overflow;

        //let val1 = value1 & 0xffff;
        //let val2 = value2 & 0xffff;

        //self.check_carry_sub_word(val1, val2);
        //r = self.check_overflow_sub_word(val1, val2);
        self.f_zf = value1 == value2;

        self.f_sf = (r as i16) < 0;
        self.calc_pf(r as u8);
        //self.f_af = (r & 0x1000) != 0;
        self.calc_af(value1, value2, r as u64, 16);

        (r as u16) as u64
    }

    pub fn sub8(&mut self, value1: u64, value2: u64) -> u64 {
        //let r:i8;
        let (r, carry) = (value1 as u8).overflowing_sub(value2 as u8);
        let (_, overflow) = (value1 as u8 as i8).overflowing_sub(value2 as u8 as i8);
        self.f_cf = carry;
        self.f_of = overflow;

        //let val1:u64 = value1 & 0xff;
        //let val2:u64 = value2 & 0xff;

        //self.check_carry_sub_byte(val1, val2);
        //r = self.check_overflow_sub_byte(val1, val2);
        self.f_zf = value1 == value2;

        self.f_sf = (r as i8) < 0;
        self.calc_pf(r as u8);
        //self.f_af = (r & 16) != 0;
        self.calc_af(value1, value2, r as u64, 8);

        r as u64
    }

    pub fn inc64(&mut self, value: u64) -> u64 {
        if value == 0xffffffffffffffff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }

        self.f_of = value == 0x7fffffff_ffffffff;
        self.f_sf = value > 0x7fffffff_ffffffff;
        self.calc_pf((value + 1) as u8);
        self.f_zf = false;
        value + 1
    }

    pub fn inc32(&mut self, value: u64) -> u64 {
        if value == 0xffffffff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7fffffff;
        self.f_sf = value > 0x7fffffff;
        self.calc_pf((value + 1) as u8);
        //self.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        value + 1
    }

    pub fn inc16(&mut self, value: u64) -> u64 {
        if value == 0xffff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7fff;
        self.f_sf = value > 0x7fff;
        self.calc_pf((value + 1) as u8);
        //self.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        value + 1
    }

    pub fn inc8(&mut self, value: u64) -> u64 {
        if value == 0xff {
            self.f_zf = true;
            self.f_pf = true;
            self.f_af = true;
            return 0;
        }
        self.f_of = value == 0x7f;
        self.f_sf = value > 0x7f;
        self.calc_pf((value + 1) as u8);
        //self.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.f_zf = false;
        value + 1
    }

    pub fn dec64(&mut self, value: u64) -> u64 {
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xffffffffffffffff;
        }
        self.f_of = value == 0x8000000000000000;
        self.calc_pf((value - 1) as u8);
        //self.f_pf = (((value as i64) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = ((value - 1) as i64) < 0;
        self.f_zf = value == 1;

        value - 1
    }

    pub fn dec32(&mut self, value: u64) -> u64 {
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xffffffff;
        }
        self.f_of = value == 0x80000000;
        self.calc_pf((value - 1) as u8);
        //self.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = ((value - 1) as u32 as i32) < 0;
        self.f_zf = value == 1;

        value - 1
    }

    pub fn dec16(&mut self, value: u64) -> u64 {
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xffff;
        }
        self.f_of = value == 0x8000;
        self.calc_pf((value - 1) as u8);
        //self.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = ((value - 1) as u16 as i16) < 0;
        self.f_zf = value == 1;

        value - 1
    }

    pub fn dec8(&mut self, value: u64) -> u64 {
        if value == 0 {
            self.f_pf = true;
            self.f_af = true;
            self.f_sf = true;
            return 0xff;
        }
        self.f_of = value == 0x80;
        self.calc_pf((value - 1) as u8);
        //self.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.f_af = false;
        self.f_sf = ((value - 1) as u8 as i8) < 0;
        self.f_zf = value == 1;

        value - 1
    }

    pub fn neg64(&mut self, value: u64) -> u64 {
        self.f_of = value == 0x8000000000000000;
        self.f_cf = true;

        let mut ival = value as i64;
        if ival != i64::MIN {
            ival = -ival;
        }

        let res = ival as u64;

        self.calc_flags(res, 64);
        self.calc_pf(res as u8);
        res
    }

    pub fn neg32(&mut self, value: u64) -> u64 {
        self.f_of = value == 0x80000000;
        self.f_cf = true;

        let mut ival = value as i32;
        if ival != i32::MIN {
            ival = -ival;
        }

        let res = ival as u32 as u64;

        self.calc_flags(res, 32);
        self.calc_pf(res as u8);
        res
    }

    pub fn neg16(&mut self, value: u64) -> u64 {
        self.f_of = value == 0x8000;
        self.f_cf = true;

        let mut ival = value as i16;
        if ival != i16::MIN {
            ival = -ival;
        }

        let res = ival as u16 as u64;

        self.calc_flags(res, 16);
        self.calc_pf(res as u8);
        res
    }

    pub fn neg8(&mut self, value: u64) -> u64 {
        self.f_of = value == 0x80;
        self.f_cf = true;

        let mut ival = value as i8;
        if ival != i8::MIN {
            ival = -ival;
        }

        let res = ival as u8 as u64;

        self.calc_flags(res, 8);
        self.calc_pf(res as u8);
        res
    }

    //// sal sar signed ////

    pub fn sal2p64(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s64 = value0 as i64;
        let sign_mask = 0x3f;

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s64, 63) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s64 <<= 1;
        }

        let result = s64 as u64;
        self.calc_flags(result, 64);
        result
    }

    pub fn sal2p32(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s32 = value0 as u32 as i32;
        let sign_mask = 0x1f;

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s32, 31) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s32 <<= 1;
        }

        let result = s32 as u32 as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn sal2p16(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s16 = value0 as u16 as i16;
        let sign_mask = 0x1f;

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s16, 15) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s16 <<= 1;
        }

        let result = s16 as u16 as u64;
        self.calc_flags(result, 16);
        result
    }

    pub fn sal2p8(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s8 = value0 as u8 as i8;
        let sign_mask = 0x1f;

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s8, 7) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s8 <<= 1;
        }

        let result = s8 as u8 as u64;
        self.calc_flags(result, 8);
        result
    }

    pub fn sal1p64(&mut self, value: u64) -> u64 {
        let mut s64 = value as i64;

        if get_bit!(s64, 63) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s64 <<= 1;

        let res = s64 as u64;
        self.calc_flags(res, 64);
        if self.f_cf && get_bit!(s64, 63) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s64, 63) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn sal1p32(&mut self, value: u64) -> u64 {
        let mut s32 = value as u32 as i32;

        if get_bit!(s32, 31) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s32 <<= 1;

        let res = s32 as u32 as u64;
        self.calc_flags(res, 32);
        if self.f_cf && get_bit!(s32, 31) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s32, 31) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn sal1p16(&mut self, value: u64) -> u64 {
        let mut s16 = value as u16 as i16;

        if get_bit!(s16, 15) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s16 <<= 1;

        let res = s16 as u16 as u64;
        self.calc_flags(res, 16);
        if self.f_cf && get_bit!(s16, 15) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s16, 15) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn sal1p8(&mut self, value: u64) -> u64 {
        let mut s8 = value as u8 as i8;

        if get_bit!(s8, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s8 <<= 1;

        let res = s8 as u8 as u64;
        self.calc_flags(res, 8);
        if self.f_cf && get_bit!(s8, 7) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s8, 7) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn sar2p64(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s64: i64 = value0 as i64;
        let sign_bit = get_bit!(value0, 63);
        let count_mask = 0x3f;

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s64, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s64 >>= 1;
            set_bit!(s64, 63, sign_bit);
        }

        let result = s64 as u64;
        self.calc_flags(result, 64);
        result
    }

    pub fn sar2p32(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s32: i32 = value0 as u32 as i32;
        let sign_bit = get_bit!(value0, 31);
        let count_mask = 0x1f;

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s32, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s32 >>= 1;
            set_bit!(s32, 31, sign_bit);
        }

        let result = s32 as u32 as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn sar2p16(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s16: u16 = value0 as u16;
        let sign_bit = get_bit!(value0, 15);
        let count_mask = 0x1f;

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s16, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s16 >>= 1;
            set_bit!(s16, 15, sign_bit);
        }

        let result = s16 as u64;
        self.calc_flags(result, 16);
        result
    }

    pub fn sar2p8(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s8: i8 = value0 as u8 as i8;
        let sign_bit = get_bit!(value0, 7);
        let count_mask = 0x1f;

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s8, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s8 >>= 1;
            set_bit!(s8, 7, sign_bit);
        }

        let result = s8 as u8 as u64;
        self.calc_flags(result, 8);
        result
    }

    pub fn sar1p64(&mut self, value: u64) -> u64 {
        let mut s64 = value as i64;
        let sign_bit = get_bit!(s64, 63);

        if get_bit!(s64, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s64 >>= 1;
        set_bit!(s64, 63, sign_bit);

        let res = s64 as u64;
        self.calc_flags(res, 64);
        self.f_of = false;
        res
    }

    pub fn sar1p32(&mut self, value: u64) -> u64 {
        let mut s32 = value as u32 as i32;
        let sign_bit = get_bit!(s32, 31);

        if get_bit!(s32, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s32 >>= 1;
        set_bit!(s32, 31, sign_bit);

        let res = s32 as u32 as u64;
        self.calc_flags(res, 32);
        self.f_of = false;
        res
    }

    pub fn sar1p16(&mut self, value: u64) -> u64 {
        let mut s16 = value as u16 as i16;
        let sign_bit = get_bit!(s16, 15);

        if get_bit!(s16, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s16 >>= 1;
        set_bit!(s16, 15, sign_bit);

        let res = s16 as u16 as u64;
        self.calc_flags(res, 16);
        self.f_of = false;
        res
    }

    pub fn sar1p8(&mut self, value: u64) -> u64 {
        let mut s8 = value as u8 as i8;
        let sign_bit = get_bit!(s8, 7);

        if get_bit!(s8, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s8 >>= 1;
        set_bit!(s8, 7, sign_bit);

        let res = s8 as u8 as u64;
        self.calc_flags(res, 8);
        self.f_of = false;
        res
    }

    //// shr shl unsigned ////

    pub fn shl2p64(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s64 = value0 as i64;
        let sign_mask = 0x3f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s64, 63) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s64 <<= 1;
        }

        let result = s64 as u64;
        self.calc_flags(result, 64);
        result
    }

    pub fn shl2p32(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s32 = value0 as u32 as i32;
        let sign_mask = 0x1f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s32, 31) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s32 <<= 1;
        }

        let result = s32 as u32 as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn shl2p16(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s16 = value0 as u16 as i16;
        let sign_mask = 0x1f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s16, 15) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s16 <<= 1;
        }

        let result = s16 as u16 as u64;
        self.calc_flags(result, 16);
        result
    }

    pub fn shl2p8(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s8 = value0 as u8 as i8;
        let sign_mask = 0x1f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & sign_mask) {
            if get_bit!(s8, 7) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s8 <<= 1;
        }

        let result = s8 as u8 as u64;
        self.calc_flags(result, 8);
        result
    }

    pub fn shl1p64(&mut self, value: u64) -> u64 {
        let mut s64 = value as i64;

        if get_bit!(s64, 63) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s64 <<= 1;

        let res = s64 as u64;
        self.calc_flags(res, 64);
        if self.f_cf && get_bit!(s64, 63) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s64, 63) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn shl1p32(&mut self, value: u64) -> u64 {
        let mut s32 = value as u32 as i32;

        if get_bit!(s32, 31) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s32 <<= 1;

        let res = s32 as u32 as u64;
        self.calc_flags(res, 32);
        if self.f_cf && get_bit!(s32, 31) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s32, 31) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn shl1p16(&mut self, value: u64) -> u64 {
        let mut s16 = value as u16 as i16;

        if get_bit!(s16, 15) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s16 <<= 1;

        let res = s16 as u16 as u64;
        self.calc_flags(res, 16);
        if self.f_cf && get_bit!(s16, 15) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s16, 15) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn shl1p8(&mut self, value: u64) -> u64 {
        let mut s8 = value as u8 as i8;

        if get_bit!(s8, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s8 <<= 1;

        let res = s8 as u8 as u64;
        self.calc_flags(res, 8);
        if self.f_cf && get_bit!(s8, 7) == 1 {
            self.f_of = false;
        } else if !self.f_cf && get_bit!(s8, 7) == 0 {
            self.f_of = false;
        } else {
            self.f_of = true;
        }
        res
    }

    pub fn shr2p64(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s64: i64 = value0 as i64;
        let count_mask = 0x3f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s64, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s64 >>= 1;
            set_bit!(s64, 63, 0);
        }

        let result = s64 as u64;
        self.calc_flags(result, 64);
        result
    }

    pub fn shr2p32(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s32: i32 = value0 as u32 as i32;
        let count_mask = 0x1f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s32, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s32 >>= 1;
            set_bit!(s32, 31, 0);
        }

        let result = s32 as u32 as u64;
        self.calc_flags(result, 32);
        result
    }

    pub fn shr2p16(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s16: u16 = value0 as u16;
        let count_mask = 0x1f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s16, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s16 >>= 1;
            set_bit!(s16, 15, 0);
        }

        let result = s16 as u64;
        self.calc_flags(result, 16);
        result
    }

    pub fn shr2p8(&mut self, value0: u64, value1: u64) -> u64 {
        let mut s8: i8 = value0 as u8 as i8;
        let count_mask = 0x1f;

        if value1 == 0 {
            return value0;
        }

        for _ in 0..(value1 & count_mask) {
            if get_bit!(s8, 0) == 1 {
                self.f_cf = true;
            } else {
                self.f_cf = false;
            }
            s8 >>= 1;
            set_bit!(s8, 7, 0);
        }

        let result = s8 as u8 as u64;
        self.calc_flags(result, 8);
        result
    }

    pub fn shr1p64(&mut self, value: u64) -> u64 {
        let mut s64 = value as i64;

        if get_bit!(s64, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s64 >>= 1;
        set_bit!(s64, 63, 0);

        let res = s64 as u64;
        self.calc_flags(res, 64);
        if get_bit!(value, 63) == 1 {
            self.f_of = true;
        } else {
            self.f_of = false;
        }
        res
    }

    pub fn shr1p32(&mut self, value: u64) -> u64 {
        let mut s32 = value as u32 as i32;

        if get_bit!(s32, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s32 >>= 1;
        set_bit!(s32, 31, 0);

        let res = s32 as u32 as u64;
        self.calc_flags(res, 32);
        if get_bit!(value, 31) == 1 {
            self.f_of = true;
        } else {
            self.f_of = false;
        }
        res
    }

    pub fn shr1p16(&mut self, value: u64) -> u64 {
        let mut s16 = value as u16 as i16;

        if get_bit!(s16, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s16 >>= 1;
        set_bit!(s16, 15, 0);

        let res = s16 as u16 as u64;
        self.calc_flags(res, 16);
        if get_bit!(value, 15) == 1 {
            self.f_of = true;
        } else {
            self.f_of = false;
        }
        res
    }

    pub fn shr1p8(&mut self, value: u64) -> u64 {
        let mut s8 = value as u8 as i8;

        if get_bit!(s8, 0) == 1 {
            self.f_cf = true;
        } else {
            self.f_cf = false;
        }

        s8 >>= 1;
        set_bit!(s8, 7, 0);

        let res = s8 as u8 as u64;
        self.calc_flags(res, 8);
        if get_bit!(value, 7) == 1 {
            self.f_of = true;
        } else {
            self.f_of = false;
        }
        res
    }

    pub fn test(&mut self, value0: u64, value1: u64, sz: u32) {
        let result: u64 = value0 & value1;

        self.f_zf = result == 0;
        self.f_cf = false;
        self.f_of = false;
        self.calc_pf(result as u8);

        match sz {
            64 => self.f_sf = (result as i64) < 0,
            32 => self.f_sf = (result as i32) < 0,
            16 => self.f_sf = (result as i16) < 0,
            8 => self.f_sf = (result as i8) < 0,
            _ => unreachable!("weird size"),
        }
        //undefined behavior: self.calc_af(value0, value1, result as u64, sz as u64);
    }

    //// imul ////

    pub fn imul64p2(&mut self, value0: u64, value1: u64) -> u64 {
        let result: i128 = value0 as i64 as i128 * value1 as i64 as i128;
        let uresult: u128 = result as u128;

        if uresult > 0xffffffffffffffff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res: u64 = (uresult & 0xffffffffffffffff) as u64;

        self.calc_flags(res, 64);
        self.calc_pf(res as u8);
        res
    }

    pub fn imul32p2(&mut self, value0: u64, value1: u64) -> u64 {
        let result: i64 = value0 as i32 as i64 * value1 as i32 as i64;
        let uresult: u64 = result as u64;

        if uresult > 0xffffffff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res: u64 = uresult & 0xffffffff;

        self.calc_flags(res, 32);
        self.calc_pf(res as u8);
        res
    }

    pub fn imul16p2(&mut self, value0: u64, value1: u64) -> u64 {
        let result: i32 = value0 as i16 as i32 * value1 as i16 as i32;
        let uresult: u32 = result as u32;

        if uresult > 0xffff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res = (uresult & 0xffff) as u64;

        self.calc_flags(res, 16);
        self.calc_pf(res as u8);
        res
    }

    pub fn imul8p2(&mut self, value0: u64, value1: u64) -> u64 {
        let result: i16 = value0 as i8 as i16 * value1 as i8 as i16;
        let uresult: u16 = result as u16;

        if uresult > 0xff {
            self.f_cf = true;
            self.f_of = true;
        }

        let res = (uresult & 0xff) as u64;

        self.calc_flags(res, 8);
        self.calc_pf(res as u8);
        res
    }

    pub fn rcr_of_and_cf(&mut self, value0: u64, value1: u64, sz: u32) {
        let cnt = value1 % ((sz + 1) as u64);
        let mut ocf = 0;
        let cf;

        if cnt != 0 {
            if cnt == 1 {
                cf = (value0 & 1) == 1;
                if self.f_cf {
                    ocf = 1;
                } else {
                    ocf = 0;
                }
            } else {
                cf = ((value0 >> (cnt - 1)) & 0x1) == 1;
            }

            let mask: u64 = (1 << ((sz as u64) - cnt)) - 1;
            self.f_cf = cf;
            if cnt == 1 {
                self.f_of = xor2!(ocf + ((value0 >> (sz - 2)) & 0x2)) == 1;
            }
        }
    }

    pub fn rcr(&mut self, value0: u64, value1: u64, sz: u32) -> u64 {
        let mut res: u64 = value0;
        let cnt = value1 % ((sz + 1) as u64);
        let mut ocf = 0;
        let cf;

        if cnt != 0 {
            if cnt == 1 {
                cf = (value0 & 1) == 1;
                if self.f_cf {
                    ocf = 1;
                } else {
                    ocf = 0;
                }
            } else {
                cf = ((value0 >> (cnt - 1)) & 0x1) == 1;
            }

            let mask: u64 = (1 << ((sz as u64) - cnt)) - 1;
            if cnt != 1 {
                res |= value0 << ((sz + 1) as u64 - cnt);
            }
            if self.f_cf {
                res |= 1 << (sz as u64 - cnt);
            }
            self.f_cf = cf;
            if cnt == 1 {
                self.f_of = xor2!(ocf + ((value0 >> (sz - 2)) & 0x2)) == 1;
            }
        }

        res
    }
}
