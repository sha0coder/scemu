use iced_x86::Register;

#[derive(Clone)]
pub struct FPU {
    st: Vec<f64>,
    st_depth: u8,
    tag: u16,
    pub stat: u16,
    ctrl: u16,
    ip: u64,
    err_off: u32,
    err_sel: u32,
    code_segment: u16,
    data_segment: u16,
    operand_ptr: u64,
    reserved: [u8; 14],
    reserved2: [u8; 96],
    xmm: [u64; 16],
    top: i8,
    pub f_c0: bool, // overflow
    pub f_c1: bool, // underflow
    pub f_c2: bool, // div by zero
    pub f_c3: bool, // precission
    pub f_c4: bool, // stack fault
    pub mxcsr: u32,
}

impl Default for FPU {
    fn default() -> Self {
        Self::new()
    }
}

impl FPU {
    pub fn new() -> FPU {
        FPU {
            st: vec![0.0; 8],
            st_depth: 0,
            tag: 0xffff,
            stat: 0,
            ctrl: 0x027f,
            ip: 0,
            err_off: 0,
            err_sel: 0,
            code_segment: 0,
            data_segment: 0,
            operand_ptr: 0,
            reserved: [0; 14],
            reserved2: [0; 96],
            xmm: [0; 16],
            top: 0,
            f_c0: false, // overflow
            f_c1: false, // underflow
            f_c2: false, // div by zero
            f_c3: false, // precision
            f_c4: false, // stack fault
            mxcsr: 0,
        }
    }

    pub fn clear(&mut self) {
        self.st.clear();
        self.st_depth = 0;
        self.st = vec![0.0; 8];
        self.tag = 0xffff;
        self.stat = 0;
        self.ctrl = 0x037f;
        self.ip = 0;
        self.err_off = 0;
        self.err_sel = 0;
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
        self.ctrl
    }

    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip;
    }

    pub fn inc_top(&mut self) {
        self.top = (self.top + 1) % 8;
    }

    pub fn dec_top(&mut self) {
        if self.top == 0 {
            self.top = 7;
        } else {
            self.top -= 1;
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
        log::info!("---- fpu ----");
        for i in 0..self.st.len() {
            log::info!("st({}): {}", i, self.st[i]);
        }

        log::info!("stat: 0x{:x}", self.stat);
        log::info!("ctrl: 0x{:x}", self.ctrl);
        log::info!("eip:  0x{:x}", self.ip);

        log::info!("--------");
    }

    pub fn set_st(&mut self, i: usize, value: f64) {
        self.st[i] = value;
    }

    pub fn get_st(&mut self, i: usize) -> f64 {
        self.f_c4 = self.st_depth == 0;
        return self.st[i];
    }

    pub fn xchg_st(&mut self, i: usize) {
        let i = i;
        self.st.swap(0, i);
    }

    pub fn clear_st(&mut self, i: usize) {
        self.st[i] = 0.0;
    }

    pub fn move_to_st0(&mut self, i: usize) {
        self.st[0] = self.st[i];
    }

    pub fn add_to_st0(&mut self, i: usize) {
        self.st[0] += self.st[i];
    }

    pub fn add(&mut self, i: usize, j: usize) {
        self.st[i] += self.st[j];
    }

    pub fn push(&mut self, value: f64) {
        if self.st_depth >= 8 {
            self.f_c0 = true; // overflow
        } else {
            self.st_depth += 1;
            self.f_c0 = false;
        }
        self.st[7] = self.st[6];
        self.st[6] = self.st[5];
        self.st[5] = self.st[4];
        self.st[4] = self.st[3];
        self.st[3] = self.st[2];
        self.st[2] = self.st[1];
        self.st[1] = self.st[0];
        self.st[0] = value;
    }

    pub fn pop(&mut self) -> f64 {
        if self.st_depth == 0 {
            self.f_c1 = true;
        } else {
            self.st_depth -= 1;
            self.f_c1 = false;
        }
        let result = self.st[0];
        self.st[0] = self.st[1];
        self.st[1] = self.st[2];
        self.st[2] = self.st[3];
        self.st[3] = self.st[4];
        self.st[4] = self.st[5];
        self.st[5] = self.st[6];
        self.st[6] = self.st[7];
        self.st[7] = 0.0;
        result
    }

    pub fn fyl2x(&mut self) {
        self.st[1] *= self.st[0].log2();
        self.pop();
    }

    pub fn fyl2xp1(&mut self) {
        self.st[1] *= self.st[0].log2() + 1.0;
        self.pop();
    }

    pub fn check_pending_exceptions(self) {}

    pub fn set_streg(&mut self, reg: Register, value: f64) {
        match reg {
            Register::ST0 => self.st[0] = value,
            Register::ST1 => self.st[1] = value,
            Register::ST2 => self.st[2] = value,
            Register::ST3 => self.st[3] = value,
            Register::ST4 => self.st[4] = value,
            Register::ST5 => self.st[5] = value,
            Register::ST6 => self.st[6] = value,
            Register::ST7 => self.st[7] = value,
            _ => unreachable!(),
        }
    }

    pub fn frexp(&self, value: f64) -> (f64, i32) {
        if value == 0.0 {
            (0.0, 0)
        } else {
            let exponent = value.abs().log2().floor() as i32 + 1;
            let mantissa = value / (2f64.powi(exponent));

            (mantissa, exponent)
        }
    }
}
