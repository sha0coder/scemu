mod emu32;

use std::env;
use emu32::Emu32;

fn usage(arg0:&String) {
    println!("{0} [shellcode file]", arg0);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage(&args[0]);
        return;
    }


    let mut x : [u8; 10] = [1,2,3,4,5,6,7,8,9,0];
    println!("{:?}", x.get(0..));


    
    let mut emu32 = Emu32::new();

    emu32.init();
    emu32.load_code(&args[1]);
    emu32.run();

    


}
