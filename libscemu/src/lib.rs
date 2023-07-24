pub mod config;
pub mod emu;

use config::Config;
use emu::Emu;

pub fn emu64() -> Emu {
    let mut emu = Emu::new();
    let mut cfg = Config::new();
    cfg.is_64bits = true;
    emu.set_config(cfg);
    emu.disable_ctrlc();

    emu
}

pub fn emu32() -> Emu {
    let mut emu = Emu::new();
    let mut cfg = Config::new();
    cfg.is_64bits = false;
    emu.set_config(cfg);
    emu.disable_ctrlc();

    emu
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn test() {
        /*
        let mut emu = emu64();
        emu.set_maps_folder("../scemu/maps64/");
        emu.cfg.test_mode = false;
        emu.init();
        emu.load_code("../scemu/shellcodes64/");
        emu.cfg.nocolors = true;
        emu.set_verbose(0);
        emu.cfg.trace_regs = false;
        emu.spawn_console_at(2586);
        emu.run(0);*/

        assert!(1 == 1);

        // cannot do tests, maps folder cannot be predicted on test time.

        /*
        use crate::emu32;

        let mut emu = emu32();
        emu.set_maps_folder("/tmp/maps32/");
        emu.init();
        emu.load_code("/tmp/maps32/test");
        emu.run(0x3c00a4);
        assert!(emu.regs.get_eax() == 0x75e9395c);

        emu = emu64();
        emu.set_maps_folder("/tmp/maps64/");
        emu.init();
        emu.load_code("/tmp/maps64/test");
        emu.run(0x3c002b);
        assert!(emu.regs.rax == 0x29);
        */
    }
}
