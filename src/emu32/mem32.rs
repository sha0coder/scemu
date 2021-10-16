use std::collections::HashMap;

pub struct Mem32 {
    mem: HashMap<u8, u8>
}

impl Mem32 {
    pub fn new() -> Mem32 {
        Mem32 {
            mem: HashMap::new()
        }
    }

    pub fn clear(&mut self) {
        self.mem.clear();
    }
    
    pub fn put(&mut self, key:u8, value:u8) {
        self.mem.insert(key,value);
    }

    pub fn get(&self, key:&u8) -> u8 {
        if self.mem.contains_key(key) {
            return self.mem[key];
        } else {
            return 0;
        }
    }
}




/*

let mem = Mem.new();

mem.put(0x123, 'AAAA')
mem.put(0x1111, 'ZZZZ')

? = mem.get(0x123)

*/

