use crate::emu::fpu::FPU;
use crate::emu::maps::Maps;
use crate::emu::regs64::Regs64;

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context

pub struct Context64 {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    ctx_flags: u32,
    mx_csr: u16,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    fpu: FPU,
}

impl Context64 {
    pub fn new(regs: &Regs64) -> Context64 {
        Context64 {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            ctx_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            mx_csr: 0,
            seg_fs: 0,
            seg_gs: 0,
            seg_es: 0,
            seg_ds: 0,
            seg_cs: 0,
            seg_ss: 0,
            eflags: 0,
            rdi: regs.rdi,
            rsi: regs.rsi,
            rbx: regs.rbx,
            rdx: regs.rdx,
            rcx: regs.rcx,
            rax: regs.rax,
            rbp: regs.rbp,
            rip: regs.rip,
            rsp: regs.rsp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            fpu: FPU::new(),
        }
    }

    /*
    typedef struct _CONTEXT {
      DWORD64 P1Home; 0
      DWORD64 P2Home; 8
      DWORD64 P3Home; 16
      DWORD64 P4Home; 24
      DWORD64 P5Home; 32
      DWORD64 P6Home; 40
      DWORD   ContextFlags; 48
      DWORD   MxCsr; 52
      WORD    SegCs; 56
      WORD    SegDs; 58
      WORD    SegEs; 60
      WORD    SegFs; 62
      WORD    SegGs; 64
      WORD    SegSs; 66
      DWORD   EFlags; 68
      DWORD64 Dr0; 72
      DWORD64 Dr1; 80
      DWORD64 Dr2; 88
      DWORD64 Dr3; 96
      DWORD64 Dr6; 104
      DWORD64 Dr7; 112
      DWORD64 Rax; 120
      DWORD64 Rcx; 128
      DWORD64 Rdx; 136
      DWORD64 Rbx; 144
      DWORD64 Rsp; 152
      DWORD64 Rbp; 160
      DWORD64 Rsi; 168
      DWORD64 Rdi; 176
      DWORD64 R8; 184
      DWORD64 R9; 192
      DWORD64 R10; 200
      DWORD64 R11; 208
      DWORD64 R12; 216
      DWORD64 R13; 224
      DWORD64 R14; 232
      DWORD64 R15; 240
      DWORD64 Rip; 248
        */

    pub fn save(&self, addr: u64, maps: &mut Maps) {
        maps.write_qword(addr + 72, self.dr0);
        maps.write_qword(addr + 80, self.dr1);
        maps.write_qword(addr + 88, self.dr2);
        maps.write_qword(addr + 96, self.dr3);
        maps.write_qword(addr + 104, self.dr6);
        maps.write_qword(addr + 112, self.dr7);

        maps.write_qword(addr + 120, self.rax);
        maps.write_qword(addr + 128, self.rcx);
        maps.write_qword(addr + 136, self.rdx);
        maps.write_qword(addr + 144, self.rbx);
        maps.write_qword(addr + 152, self.rsp);
        maps.write_qword(addr + 160, self.rbp);
        maps.write_qword(addr + 168, self.rdi);
        maps.write_qword(addr + 176, self.rsi);

        maps.write_qword(addr + 184, self.r8);
        maps.write_qword(addr + 192, self.r9);
        maps.write_qword(addr + 200, self.r10);
        maps.write_qword(addr + 208, self.r11);
        maps.write_qword(addr + 216, self.r12);
        maps.write_qword(addr + 224, self.r13);
        maps.write_qword(addr + 232, self.r14);
        maps.write_qword(addr + 240, self.r15);

        maps.write_qword(addr + 248, self.rip);
    }

    pub fn load(&mut self, addr: u64, maps: &mut Maps) {
        self.dr0 = maps
            .read_qword(addr + 72)
            .expect("cannot read dr0 from ctx");
        self.dr1 = maps
            .read_qword(addr + 80)
            .expect("cannot read dr1 from ctx");
        self.dr2 = maps
            .read_qword(addr + 88)
            .expect("cannot read dr2 from ctx");
        self.dr3 = maps
            .read_qword(addr + 96)
            .expect("cannot read dr3 from ctx");
        self.dr6 = maps
            .read_qword(addr + 104)
            .expect("cannot read dr6 from ctx");
        self.dr7 = maps
            .read_qword(addr + 112)
            .expect("cannot read dr7 from ctx");

        self.rax = maps
            .read_qword(addr + 120)
            .expect("cannot read rax from ctx");
        self.rcx = maps
            .read_qword(addr + 128)
            .expect("cannot read rcx from ctx");
        self.rdx = maps
            .read_qword(addr + 136)
            .expect("cannot read rdx from ctx");
        self.rbx = maps
            .read_qword(addr + 144)
            .expect("cannot read rbx from ctx");
        self.rsp = maps
            .read_qword(addr + 152)
            .expect("cannot read rsp from ctx");
        self.rbp = maps
            .read_qword(addr + 160)
            .expect("cannot read rbp from ctx");
        self.rdi = maps
            .read_qword(addr + 168)
            .expect("cannot read rdi from ctx");
        self.rsi = maps
            .read_qword(addr + 176)
            .expect("cannot read rsi from ctx");

        self.r8 = maps
            .read_qword(addr + 184)
            .expect("cannot read r8 from ctx");
        self.r9 = maps
            .read_qword(addr + 192)
            .expect("cannot read r9 from ctx");
        self.r10 = maps
            .read_qword(addr + 200)
            .expect("cannot read r10 from ctx");
        self.r11 = maps
            .read_qword(addr + 208)
            .expect("cannot read r11 from ctx");
        self.r12 = maps
            .read_qword(addr + 216)
            .expect("cannot read r12 from ctx");
        self.r13 = maps
            .read_qword(addr + 224)
            .expect("cannot read r13 from ctx");
        self.r14 = maps
            .read_qword(addr + 232)
            .expect("cannot read r14 from ctx");
        self.r15 = maps
            .read_qword(addr + 240)
            .expect("cannot read r15 from ctx");

        self.rip = maps
            .read_qword(addr + 248)
            .expect("cannot read rip from ctx");
    }

    pub fn sync(&self, regs: &mut Regs64) {
        regs.rax = self.rax;
        regs.rbx = self.rbx;
        regs.rcx = self.rcx;
        regs.rdx = self.rdx;
        regs.rsi = self.rsi;
        regs.rdi = self.rdi;
        regs.rsp = self.rsp;
        regs.rbp = self.rbp;
        regs.rip = self.rip;

        regs.r8 = self.r8;
        regs.r9 = self.r9;
        regs.r10 = self.r10;
        regs.r11 = self.r11;
        regs.r12 = self.r12;
        regs.r13 = self.r13;
        regs.r14 = self.r14;
        regs.r15 = self.r15;
    }
}
