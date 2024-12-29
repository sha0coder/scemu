// cargo test -- --nocapture

#[cfg(test)]
mod tests {
    use std::sync::Once;
    use std::io::Write as _;

    use crate::emu::Emu;
    use crate::emu64;
    use crate::serialization::SerializableEmu;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .format(|buf, record| writeln!(buf, "{}", record.args()))
                .init();
        });
    }

    #[test]
    #[ignore]
    fn should_serialize() {
        setup();

        // init
        let mut emu = emu64();

        // load maps
        emu.cfg.maps_folder = "../maps64/".to_string();
        emu.init(false, false);

        // load binary
        let filename = format!("/Users/{username}/Desktop/enigma/surprise.dll", username = std::env::var("USER").unwrap());
        emu.load_code(&filename);

        // set registers
        emu.regs.rdx = 0x1;

        // serialize
        let serializedable_emu: SerializableEmu = emu.into();
        let serialized = serde_json::to_string(&serializedable_emu).unwrap();

        // deserialize
        let parsed: SerializableEmu = serde_json::from_str(&serialized).unwrap();
        let emu: Emu = parsed.into();

        // assert
        assert_eq!(emu.regs.rdx, 0x1);
    }

    #[test]
    #[ignore]
    fn should_run() {
        setup();

        // init
        let mut emu = emu64();

        // load maps
        emu.cfg.maps_folder = "../maps64/".to_string();
        emu.init(false, false);

        // load binary
        let filename = format!("/Users/{username}/Desktop/enigma/surprise.dll", username = std::env::var("USER").unwrap());
        emu.load_code(&filename);

        // set registers
        emu.regs.rdx = 0x1;

        // set exit position
        emu.cfg.exit_position = 100;

        // run
        let exit_addr = None;
        emu.run(exit_addr);

        // assert
        assert_eq!(emu.regs.rdx, 0x7FFFFFFFFFFFFFFF);
    }
}
