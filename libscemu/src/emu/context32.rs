use crate::emu::fpu::FPU;
use crate::emu::maps::Maps;
use crate::emu::regs64::Regs64;

pub struct Context32 {
    ctx_flags: u32,
    dr0: u32,
    dr1: u32,
    dr2: u32,
    dr3: u32,
    dr6: u32,
    dr7: u32,
    fpu: FPU,
    seg_gs: u32,
    seg_fd: u32,
    seg_es: u32,
    seg_ds: u32,
    edi: u32,    // +9c
    esi: u32,    // +a0
    ebx: u32,    // +a4
    edx: u32,    // +a8
    ecx: u32,    // +ac
    eax: u32,    // +b0
    ebp: u32,    // +b4
    eip: u32,    // +b8
    seg_cs: u32, // +bc
    eflags: u32, // +c0
    esp: u32,    // +c4
    seg_ss: u32,
}

impl Context32 {
    pub fn new(regs: &Regs64) -> Context32 {
        Context32 {
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
            edi: regs.get_edi() as u32,
            esi: regs.get_esi() as u32,
            ebx: regs.get_ebx() as u32,
            edx: regs.get_edx() as u32,
            ecx: regs.get_ecx() as u32,
            eax: regs.get_eax() as u32,
            ebp: regs.get_ebp() as u32,
            eip: regs.get_eip() as u32,
            seg_cs: 0,
            eflags: 0,
            esp: regs.get_esp() as u32,
            seg_ss: 0,
        }
    }

    pub fn save(&self, addr: u32, maps: &mut Maps) {
        maps.write_dword((addr + 4) as u64, self.dr0);
        maps.write_dword((addr + 8) as u64, self.dr1);
        maps.write_dword((addr + 12) as u64, self.dr2);
        maps.write_dword((addr + 16) as u64, self.dr3);
        maps.write_dword((addr + 20) as u64, self.dr6);
        maps.write_dword((addr + 24) as u64, self.dr7);

        maps.write_dword((addr + 0x9c) as u64, self.edi);
        maps.write_dword((addr + 0xa0) as u64, self.esi);
        maps.write_dword((addr + 0xa4) as u64, self.ebx);
        maps.write_dword((addr + 0xa8) as u64, self.edx);
        maps.write_dword((addr + 0xac) as u64, self.ecx);
        maps.write_dword((addr + 0xb0) as u64, self.eax);
        maps.write_dword((addr + 0xb4) as u64, self.ebp);
        maps.write_dword((addr + 0xb8) as u64, self.eip);
        maps.write_dword((addr + 0xc4) as u64, self.esp);
    }

    pub fn load(&mut self, addr: u32, maps: &mut Maps) {
        self.dr0 = maps
            .read_dword((addr + 4) as u64)
            .expect("cannot read dr0 from ctx");
        self.dr1 = maps
            .read_dword((addr + 8) as u64)
            .expect("cannot read dr1 from ctx");
        self.dr2 = maps
            .read_dword((addr + 12) as u64)
            .expect("cannot read dr2 from ctx");
        self.dr3 = maps
            .read_dword((addr + 16) as u64)
            .expect("cannot read dr3 from ctx");
        self.dr6 = maps
            .read_dword((addr + 20) as u64)
            .expect("cannot read dr6 from ctx");
        self.dr7 = maps
            .read_dword((addr + 24) as u64)
            .expect("cannot read dr7 from ctx");

        self.edi = maps
            .read_dword((addr + 0x9c) as u64)
            .expect("cannot read edi from ctx");
        self.esi = maps
            .read_dword((addr + 0xa0) as u64)
            .expect("cannot read esi from ctx");
        self.ebx = maps
            .read_dword((addr + 0xa4) as u64)
            .expect("cannot read ebx from ctx");
        self.edx = maps
            .read_dword((addr + 0xa8) as u64)
            .expect("cannot read edx from ctx");
        self.ecx = maps
            .read_dword((addr + 0xac) as u64)
            .expect("cannot read ecx from ctx");
        self.eax = maps
            .read_dword((addr + 0xb0) as u64)
            .expect("cannot read eax from ctx");
        self.ebp = maps
            .read_dword((addr + 0xb4) as u64)
            .expect("cannot read ebp from ctx");
        self.eip = maps
            .read_dword((addr + 0xb8) as u64)
            .expect("cannot read eip from ctx");
        self.esp = maps
            .read_dword((addr + 0xc4) as u64)
            .expect("cannot read esp from ctx");
    }

    pub fn sync(&self, regs: &mut Regs64) {
        regs.set_eax(self.eax as u64);
        regs.set_ebx(self.ebx as u64);
        regs.set_ecx(self.ecx as u64);
        regs.set_edx(self.edx as u64);
        regs.set_esi(self.esi as u64);
        regs.set_edi(self.edi as u64);
        regs.set_esp(self.esp as u64);
        regs.set_ebp(self.ebp as u64);
        regs.set_eip(self.eip as u64);
    }
}
