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

    pub fn print(&self) {
        println!("--stack--");
        for i in (0..self.stack.len()).rev() {
            println!("{:#02x}", self.stack[i]);
        }
        println!("---");
    }

    pub fn push(&mut self, value:u32) {
        self.stack.push(value);
    }

    pub fn pop(&mut self) -> u32 {
        match self.stack.pop() {
            Some(item) => return item,
            None => {
                println!("stack error, poping on empty stack.");
                return 0
            }
        };
    }
}

