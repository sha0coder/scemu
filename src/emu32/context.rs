
use crate::emu32::fpu::FPU;
use crate::emu32::regs32::Regs32;
use crate::emu32::maps::Maps;

pub struct Context {
    ctx_flags:u32,
    dr0:u32,
    dr1:u32,
    dr2:u32,
    dr3:u32,
    dr6:u32,
    dr7:u32,
    fpu:FPU,
    seg_gs:u32,
    seg_fd:u32,
    seg_es:u32,
    seg_ds:u32,
    edi:u32,  // +9c
    esi:u32,  // +a0
    ebx:u32,  // +a4
    edx:u32,  // +a8
    ecx:u32,  // +ac
    eax:u32,  // +b0
    ebp:u32,  // +b4
    eip:u32,  // +b8
    seg_cs:u32, // +bc
    eflags:u32, // +c0
    esp:u32, // +c4
    seg_ss:u32,
}

impl Context {
    pub fn new(regs:&Regs32) -> Context {
        Context {
            ctx_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            fpu: FPU::new(),
            seg_gs: 0,
            seg_fd: 0,
            seg_es: 0,
            seg_ds: 0,
            edi: regs.edi,
            esi: regs.esi,
            ebx: regs.ebx,
            edx: regs.edx,
            ecx: regs.ecx,
            eax: regs.eax,
            ebp: regs.ebp,
            eip: regs.eip,
            seg_cs: 0,
            eflags: 0,
            esp: regs.esp,
            seg_ss: 0,
        }
    }

    pub fn save(&self, addr:u32, maps:&mut Maps) {
        maps.write_dword(addr+4, self.dr0);
        maps.write_dword(addr+8, self.dr1);
        maps.write_dword(addr+12, self.dr2);
        maps.write_dword(addr+16, self.dr3);
        maps.write_dword(addr+20, self.dr6);
        maps.write_dword(addr+24, self.dr7);

        maps.write_dword(addr+0x9c, self.edi);
        maps.write_dword(addr+0xa0, self.esi);
        maps.write_dword(addr+0xa4, self.ebx);
        maps.write_dword(addr+0xa8, self.edx);
        maps.write_dword(addr+0xac, self.ecx);
        maps.write_dword(addr+0xb0, self.eax);
        maps.write_dword(addr+0xb4, self.ebp);
        maps.write_dword(addr+0xb8, self.eip);
        maps.write_dword(addr+0xc4, self.esp);        
    }

}