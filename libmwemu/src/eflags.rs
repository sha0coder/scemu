use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Eflags {
    pub rf: bool,
    pub vm: bool,
    pub ac: bool,
    pub vif: bool,
    pub id: bool,
}

impl Default for Eflags {
    fn default() -> Self {
        Self::new()
    }
}

impl Eflags {
    pub fn new() -> Eflags {
        Eflags {
            rf: false,
            vm: false,
            ac: false,
            vif: false,
            id: false,
        }
    }
}
