use crate::emu;
use crate::emu::context32::Context32;

pub fn enter(emu: &mut emu::Emu) {
    emu.stack_push32(0x10f00);
    emu.stack_push32(emu.regs.get_eip() as u32);

    emu.eh_ctx = 0x10f08;
    emu.maps.write_dword(0x10f04, emu.eh_ctx);
    let ctx = Context32::new(&emu.regs);
    ctx.save(emu.eh_ctx, &mut emu.maps);
}

pub fn exit(emu: &mut emu::Emu) {
    let mut ctx = Context32::new(&emu.regs);
    ctx.load(emu.eh_ctx, &mut emu.maps);
    ctx.sync(&mut emu.regs);
    emu.eh_ctx = 0;
    emu.force_reload = true;
}
