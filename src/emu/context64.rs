use crate::emu::fpu::FPU;
use crate::emu::regs64::Regs64;
use crate::emu::maps::Maps;

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context

pub struct Context64 {
    ctx_flags:u32,
    dr0:u64,
    dr1:u64,
    dr2:u64,
    dr3:u64,
    dr6:u64,
    dr7:u64,
    fpu:FPU,
    seg_gs:u32,
    seg_fd:u32,
    seg_es:u32,
    seg_ds:u32,
    rdi:u64,  // +9c
    rsi:u64,  // +a0
    rbx:u64,  // +a4
    rdx:u64,  // +a8
    rcx:u64,  // +ac
    rax:u64,  // +b0
    rbp:u64,  // +b4
    rip:u64,  // +b8
    seg_cs:u32, // +bc
    eflags:u32, // +c0
    rsp:u64, // +c4
    seg_ss:u32,
}

impl Context64 {
    pub fn new(regs:&Regs64) -> Context64 {
        Context64 {
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
            rdi: regs.rdi,
            rsi: regs.rsi,
            rbx: regs.rbx,
            rdx: regs.rdx,
            rcx: regs.rcx,
            rax: regs.rax,
            rbp: regs.rbp,
            rip: regs.rip,
            seg_cs: 0,
            eflags: 0,
            rsp: regs.rsp,
            seg_ss: 0,
        }
    }

    pub fn save(&self, addr:u64, maps:&mut Maps) {
        /*
        maps.write_qword((addr+4) , self.dr0);
        maps.write_qword((addr+8) , self.dr1);
        maps.write_qword((addr+12) , self.dr2);
        maps.write_qword((addr+16) , self.dr3);
        maps.write_qword((addr+20) , self.dr6);
        maps.write_qword((addr+24) , self.dr7);

        maps.write_qword((addr+0x9c) , self.rdi);
        maps.write_qword((addr+0xa0) , self.rsi);
        maps.write_qword((addr+0xa4) , self.rbx);
        maps.write_qword((addr+0xa8) , self.rdx);
        maps.write_qword((addr+0xac) , self.rcx);
        maps.write_qword((addr+0xb0) , self.rax);
        maps.write_qword((addr+0xb4) , self.rbp);
        maps.write_qword((addr+0xb8) , self.rip);
        maps.write_qword((addr+0xc4) , self.rsp);        */
    }

    pub fn load(&mut self, addr:u64, maps:&mut Maps) {
        /*
        self.dr0 = maps.read_qword((addr+4) ).expect("cannot read dr0 from ctx");
        self.dr1 = maps.read_qword((addr+8) ).expect("cannot read dr1 from ctx");
        self.dr2 = maps.read_qword((addr+12) ).expect("cannot read dr2 from ctx");
        self.dr3 = maps.read_qword((addr+16) ).expect("cannot read dr3 from ctx");
        self.dr6 = maps.read_qword((addr+20) ).expect("cannot read dr6 from ctx");
        self.dr7 = maps.read_qword((addr+24) ).expect("cannot read dr7 from ctx");

        self.rdi = maps.read_qword((addr+0x9c) ).expect("cannot read rdi from ctx");
        self.rsi = maps.read_qword((addr+0xa0) ).expect("cannot read rsi from ctx");
        self.rbx = maps.read_qword((addr+0xa4) ).expect("cannot read rbx from ctx");
        self.rdx = maps.read_qword((addr+0xa8) ).expect("cannot read rdx from ctx");
        self.rcx = maps.read_qword((addr+0xac) ).expect("cannot read rcx from ctx");
        self.rax = maps.read_qword((addr+0xb0) ).expect("cannot read rax from ctx");
        self.rbp = maps.read_qword((addr+0xb4) ).expect("cannot read rbp from ctx");
        self.rip = maps.read_qword((addr+0xb8) ).expect("cannot read rip from ctx");
        self.rsp = maps.read_qword((addr+0xc4) ).expect("cannot read rsp from ctx");*/
    }

    pub fn sync(&self, regs:&mut Regs64) {
        regs.rax = self.rax;
        regs.rbx = self.rbx;
        regs.rcx = self.rcx;
        regs.rdx = self.rdx;
        regs.rsi = self.rsi;
        regs.rdi = self.rdi;
        regs.rsp = self.rsp;
        regs.rbp = self.rbp;
        regs.rip = self.rip;
    }

}
