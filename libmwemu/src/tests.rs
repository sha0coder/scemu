#[cfg(test)]
mod tests {
    //use super::*;

    use crate::emu::Emu;
    use crate::emu64;
    use crate::serialization::SerializableEmu;
    #[test]
    fn should_serialize() {
        let mut emu = emu64();

        // load maps
        emu.cfg.maps_folder = "../maps64/".to_string();
        emu.init(false, false);

        // load binary
        let filename = "/Users/brandon/Desktop/enigma/surprise.dll".to_string();
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
}
