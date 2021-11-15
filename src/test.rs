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


fn carry(a:u32, b:u32) {
    if (b as u8) > (a as u8) {
        println!("carry: true");
    } else {
        println!("carry: false");
    }
}

fn overflow(a:u32, b:u32) -> u8 {
    let cf = false;
    let rs:i16;

    if cf {
        rs = (a as i8) as i16 - (b as i8) as i16 - 1;
    } else {
        rs = (a as i8) as i16 - (b as i8) as i16;
    }

    println!("rs:{} {:x}", rs, rs);

    if rs < MIN_I8 as i16 || rs > MAX_I8 as i16 {
        println!("overflow: true");
    } else{
        println!("overflow: false");
    }

    return ((rs as u16) & 0xff) as u8
}


fn main() {
    //carry(0xfe, 0xff);
    let n:u8 = overflow(0x7f, 0x80);

    println!("{:x}", n);
}