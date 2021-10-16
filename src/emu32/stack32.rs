use std::vec::Vec;

pub struct Stack32 {
    stack: Vec<u32>
}

impl Stack32 {
    pub fn new() -> Stack32 {
        Stack32 {
            stack: Vec::new()
        }
    }
}

