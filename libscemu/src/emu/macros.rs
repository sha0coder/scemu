#[macro_export]

macro_rules! popn {
    ($emu:expr, $n:expr) => {
        for _ in 0..$n {
            $emu.stack_pop(false);
        }
    };
}

macro_rules! stack_param {
    ($emu:expr, $num:expr, $msg:expr) => (
        $emu.read_dword($emu.regs.esp+($num*4)).expect($msg);
    )
}

macro_rules! get_ip {
    ($emu:expr, $ptr:expr) => (
        let ip = $emu.maps.read_dword($ptr+4).expect("cannot read the ip");
        format!("{}.{}.{}.{}", ip&0xff, (ip&0xff00)>>8, (ip&0xff0000)>>16, (ip&0xff000000)>>24);
    )
}

macro_rules! read_u8 {
    ($raw:expr, $off:expr) => {
        $raw[$off]
    };
}

macro_rules! read_u16_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 1] as u16) << 8) | ($raw[$off] as u16)
    };
}

macro_rules! read_u32_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 3] as u32) << 24)
            | (($raw[$off + 2] as u32) << 16)
            | (($raw[$off + 1] as u32) << 8)
            | ($raw[$off] as u32)
    };
}

macro_rules! write_u32_le {
    ($raw:expr, $off:expr, $val:expr) => {
        $raw[$off + 0] = ($val & 0x000000ff) as u8;
        $raw[$off + 1] = (($val & 0x0000ff00) >> 8) as u8;
        $raw[$off + 2] = (($val & 0x00ff0000) >> 16) as u8;
        $raw[$off + 3] = (($val & 0xff000000) >> 24) as u8;
    };
}

macro_rules! read_u64_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 7] as u64) << 56)
            | (($raw[$off + 6] as u64) << 48)
            | (($raw[$off + 5] as u64) << 40)
            | (($raw[$off + 4] as u64) << 32)
            | (($raw[$off + 3] as u64) << 24)
            | (($raw[$off + 2] as u64) << 16)
            | (($raw[$off + 1] as u64) << 8)
            | ($raw[$off] as u64)
    };
}

macro_rules! write_u64_le {
    ($raw:expr, $off:expr, $val:expr) => {
      $raw[$off+0]  = ($val & 0x00000000_000000ff) as u8;
      $raw[$off+1] = (($val & 0x00000000_0000ff00) >> 8) as u8;
      $raw[$off+2] = (($val & 0x00000000_00ff0000) >> 16) as u8;
      $raw[$off+3] = (($val & 0x00000000_ff000000) >> 24) as u8;
      $raw[$off+4] = (($val & 0x000000ff_00000000) >> 32) as u8;
      $raw[$off+5] = (($val & 0x0000ff00_00000000) >> 40) as u8;
      $raw[$off+6] = (($val & 0x00ff0000_00000000) >> 48) as u8;
      $raw[$off+7] = (($val & 0xff000000_00000000) >> 56) as u8;
    }
}

