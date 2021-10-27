

pub struct Flags {
    pub f_cf: bool,
    pub f_pf: bool,
    pub f_af: bool,
    pub f_zf: bool,
    pub f_sf: bool,
    pub f_tf: bool,
    pub f_if: bool,
    pub f_df: bool,
    pub f_of: bool,
    pub f_nt: bool,
}

impl Flags {
    pub fn new() -> Flags {
        Flags {
            f_cf: false,
            f_pf: false,
            f_af: false,
            f_zf: false,
            f_sf: false,
            f_tf: false,
            f_if: false,
            f_df: false,
            f_of: false,
            f_nt: false, 
        }
    }


    pub fn clear(&mut self) {
        self.f_cf = false;
        self.f_pf = false;
        self.f_af = false;
        self.f_zf = false;
        self.f_sf = false;
        self.f_tf = false;
        self.f_if = false;
        self.f_df = false;
        self.f_of = false;
        self.f_nt = false;
    }

    pub fn print(&self) {
        println!("--- flags ---");
        println!("cf: {}", self.f_cf);
        println!("pf: {}", self.f_pf);
        println!("af: {}", self.f_af);
        println!("zf: {}", self.f_zf);
        println!("sf: {}", self.f_sf);
        println!("tf: {}", self.f_tf);
        println!("if: {}", self.f_if);
        println!("df: {}", self.f_df);
        println!("of: {}", self.f_of);
        println!("nt: {}", self.f_nt);
        println!("---");
    }
}