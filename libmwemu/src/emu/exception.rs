use crate::emu;
use crate::emu::context32::Context32;
use crate::emu::context64::Context64;

pub fn enter(emu: &mut emu::Emu) {
    if emu.cfg.is_64bits {
        enter64(emu);
    } else {
        enter32(emu);
    }
}

pub fn exit(emu: &mut emu::Emu) {
    if emu.cfg.is_64bits {
        exit64(emu);
    } else {
        exit32(emu);
    }
}

pub fn enter32(emu: &mut emu::Emu) {
    emu.stack_push32(0x10f00);
    emu.stack_push32(emu.regs.get_eip() as u32);

    emu.eh_ctx = 0x10f08;
    emu.maps.write_dword(0x10f04, emu.eh_ctx);
    let ctx = Context32::new(&emu.regs);
    ctx.save(emu.eh_ctx, &mut emu.maps);
}

pub fn exit32(emu: &mut emu::Emu) {
    let mut ctx = Context32::new(&emu.regs);
    ctx.load(emu.eh_ctx, &mut emu.maps);
    ctx.sync(&mut emu.regs);
    emu.eh_ctx = 0;
    emu.force_reload = true;
}

pub fn enter64(emu: &mut emu::Emu) {
    emu.stack_push64(0x10f00);
    emu.stack_push64(emu.regs.rip);

    emu.eh_ctx = 0x10f08;
    emu.maps.write_qword(0x10f04, emu.eh_ctx as u64);
    let ctx = Context64::new(&emu.regs);
    ctx.save(emu.eh_ctx as u64, &mut emu.maps);
}

pub fn exit64(emu: &mut emu::Emu) {
    let mut ctx = Context64::new(&emu.regs);
    ctx.load(emu.eh_ctx as u64, &mut emu.maps);
    ctx.sync(&mut emu.regs);
    emu.eh_ctx = 0;
    emu.force_reload = true;
}
