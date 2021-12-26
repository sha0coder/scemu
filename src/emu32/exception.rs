use crate::emu32;
use crate::emu32::context::Context;

pub fn enter(emu: &mut emu32::Emu32) {
    emu.stack_push(0x10f00);
    emu.stack_push(emu.regs.eip); 

    emu.eh_ctx = 0x10f08;
    emu.maps.write_dword(0x10f04, emu.eh_ctx);
    let ctx = Context::new(&emu.regs);
    ctx.save(emu.eh_ctx, &mut emu.maps);
}

pub fn exit(emu: &mut emu32::Emu32) {

    let mut ctx = Context::new(&emu.regs);
    ctx.load(emu.eh_ctx, &mut emu.maps);
    ctx.sync(&mut emu.regs);
    emu.eh_ctx = 0;

    //ret_addr = self.maps.read_dword(self.eh_ctx + 0xb8).expect("cannot read from context saved eip"); //TODO: do ctx.load()
}