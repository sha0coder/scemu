use crate::emu;

pub fn gateway(addr:u64, emu:&mut emu::Emu) {
    match addr {
        /*0x77733553 => StartServiceCtrlDispatcherA(emu),
        0x776fa965 => StartServiceCtrlDispatcherW(emu),*/
        _ => panic!("calling unimplemented winhttp API 0x{:x}", addr)
    }
}
