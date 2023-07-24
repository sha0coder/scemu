#[derive(Clone)]
pub struct FPU {
    st: Vec<f32>,
    tag: u16,
    stat: u16,
    ctrl: u16,
    ip: u64,
    err_off: u32,
    err_sel: u32,
    stack: Vec<f32>,
    code_segment: u16,
    data_segment: u16,
    operand_ptr: u64,
    reserved: [u8; 14],
    reserved2: [u8; 96],
    xmm: [u64; 16],
    top: i8,
    pub f_c0: bool,
    pub f_c1: bool,
    pub f_c2: bool,
    pub f_c3: bool,
}

impl FPU {
    pub fn new() -> FPU {
        FPU {
            st: vec![0.0; 8],
            tag: 0xffff,
            stat: 0,
            ctrl: 0x027f,
            ip: 0,
            err_off: 0,
            err_sel: 0,
            stack: Vec::new(),
            code_segment: 0,
            data_segment: 0,
            operand_ptr: 0,
            reserved: [0; 14],
            reserved2: [0; 96],
            xmm: [0; 16],
            top: 0,
            f_c0: false,
            f_c1: false,
            f_c2: false,
            f_c3: false,
        }
    }

    pub fn clear(&mut self) {
        self.st.clear();
        self.st = vec![0.0; 8];
        self.tag = 0xffff;
        self.stat = 0;
        self.ctrl = 0x037f;
        self.ip = 0;
        self.err_off = 0;
        self.err_sel = 0;
        self.stack.clear();
        self.code_segment = 0;
        self.data_segment = 0;
        self.operand_ptr = 0;
        self.reserved = [0; 14];
        self.reserved2 = [0; 96];
        self.xmm = [0; 16];
    }

    pub fn set_ctrl(&mut self, ctrl: u16) {
        self.ctrl = ctrl;
    }

    pub fn get_ctrl(&self) -> u16 {
        return self.ctrl;
    }

    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip;
    }

    pub fn inc_top(&mut self) {
        self.top += 1;
        if self.top > 7 {
            self.top = 0;
        }
    }

    pub fn dec_top(&mut self) {
        self.top -= 1;
        if self.top < 0 {
            self.top = 7;
        }
    }

    pub fn get_env32(&self) -> Vec<u32> {
        let mut r: Vec<u32> = Vec::new();
        let mut r1: u32 = self.tag as u32;
        r1 <<= 16;
        r1 += self.ctrl as u32;
        r.push(r1);
        r.push(0xffff0000);
        r.push(0xffffffff);
        r.push(self.ip as u32);
        r
    }

    pub fn get_env64(&self) -> Vec<u64> {
        let mut r: Vec<u64> = Vec::new();
        let mut r1: u64 = self.tag as u64;
        r1 <<= 16;
        r1 += self.ctrl as u64;
        r.push(r1);
        r.push(0xffff0000);
        r.push(0xffffffff);
        r.push(self.ip);
        r
    }

    pub fn print(&self) {
        println!("---- fpu ----");
        for i in 0..self.st.len() {
            println!("st({}): {}", i, self.st[i]);
        }

        println!("stat: 0x{:x}", self.stat);
        println!("ctrl: 0x{:x}", self.ctrl);
        println!("eip:  0x{:x}", self.ip);

        println!("--------");
    }

    pub fn set_st(&mut self, i: usize, value: f32) {
        self.st[i] = value;
    }

    pub fn get_st(&self, i: usize) -> f32 {
        return self.st[i].clone();
    }

    pub fn xchg_st(&mut self, i: usize) {
        let tmp = self.st[0];
        self.st[0] = self.st[i];
        self.st[i] = tmp;
    }

    pub fn clear_st(&mut self, i: usize) {
        self.st[i] = 0.0;
    }

    pub fn move_to_st0(&mut self, i: usize) {
        self.st[0] = self.st[i];
    }

    pub fn add_to_st0(&mut self, i: usize) {
        self.st[0] = self.st[0] + self.st[i];
    }

    pub fn add(&mut self, i: usize, j: usize) {
        self.st[i] = self.st[i] + self.st[j];
    }

    pub fn push(&mut self, value: f32) {
        self.stack.push(value);
    }

    pub fn pop(&mut self) -> f32 {
        return self.stack.pop().unwrap_or(0.0);
    }

    pub fn fyl2x(&mut self) {
        self.st[1] = self.st[1] * self.st[0].log2();
        self.pop();
    }

    pub fn fyl2xp1(&mut self) {
        self.st[1] = self.st[1] * (self.st[0].log2() + 1.0);
        self.pop();
    }

    pub fn check_pending_exceptions(self) {}
}
