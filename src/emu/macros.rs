
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