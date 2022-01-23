/*
    TODO:
        - flag for maps folder
        - entry point offset
*/


extern crate clap;

mod emu;
mod config;

use emu::Emu;
use config::Config;
use clap::{Arg, App};

fn main() {
    let mut cfg = Config::new();
    let matches = App::new("SCEMU emulator for Shellcodes")
                    .version("0.3.1")
                    .author("@sha0coder")
                    .arg(Arg::with_name("filename")
                        .short("f")
                        .long("filename")
                        .value_name("FILE")
                        .help("set the shellcode binary file.")
                        .takes_value(true))
                    .arg(Arg::with_name("verbose")
                        .short("v")
                        .long("verbose")
                        .multiple(true)
                        .help("-vv for view the assembly, -v only messages, without verbose only see the api calls and goes faster")
                        .takes_value(false))
                    .arg(Arg::with_name("64bits")
                        .short("6")
                        .long("64bits")
                        .help("enable 64bits architecture emulation")
                        .takes_value(false))
                    .arg(Arg::with_name("memory")
                        .short("m")
                        .long("memory")
                        .help("trace all the memory accesses read and write.")
                        .takes_value(false))
                    .arg(Arg::with_name("maps")
                        .short("M")
                        .long("maps")
                        .help("select the memory maps folder")
                        .takes_value(true)
                        .value_name("PATH"))
                    .arg(Arg::with_name("registers")
                        .short("r")
                        .long("regs")
                        .help("print the register values in every step.")
                        .takes_value(false))
                    .arg(Arg::with_name("register")
                        .short("R")
                        .long("reg")
                        .value_name("REGISTER1,REGISTER2")
                        .help("trace a specific register in every step, value and content")
                        .takes_value(true))
                    .arg(Arg::with_name("console")
                        .short("c")
                        .long("console")
                        .help("select in which moment will spawn the console to inspect.")
                        .value_name("NUMBER")
                        .takes_value(true))
                    .arg(Arg::with_name("loops")
                        .short("l")
                        .long("loops")
                        .help("show loop interations, it is slow.")
                        .takes_value(false))
                    .arg(Arg::with_name("nocolors")
                        .short("n")
                        .long("nocolors")
                        .help("print without colors for redirectin to a file >out")
                        .takes_value(false))
                    .arg(Arg::with_name("string")
                        .short("s")
                        .long("string")
                        .help("monitor string on a specific address")
                        .value_name("ADDRESS")
                        .takes_value(true))
                    .arg(Arg::with_name("inspect")
                        .short("i")
                        .long("inspect")
                        .help("monitor memory like: -i 'dword ptr [ebp + 0x24]")
                        .value_name("DIRECTION")
                        .takes_value(true))
                    .arg(Arg::with_name("endpoint")
                        .short("e")
                        .long("endpoint")
                        .help("perform communications with the endpoint, use tor or vpn!")
                        .takes_value(false))
                    .arg(Arg::with_name("console_addr")
                        .short("C")
                        .long("console_addr")
                        .help("spawn console on first eip = address")
                        .takes_value(true)
                        .value_name("ADDRESS"))
                    .arg(Arg::with_name("entry_point")
                        .short("a")
                        .long("entry")
                        .help("entry point of the shellcode, by default starts from the beginning.")
                        .takes_value(true)
                        .value_name("ADDRESS"))
                    .arg(Arg::with_name("code_base_address")
                        .short("b")
                        .long("base")
                        .help("set base address for code")
                        .takes_value(true)
                        .value_name("ADDRESS"))
                    .arg(Arg::with_name("stack_trace")
                        .short("p")
                        .long("stack")
                        .help("trace stack on push/pop")
                        .takes_value(false))
                    .get_matches();


    if !matches.is_present("filename") {
        println!("the filename is mandatory, try -f <FILENAME> or --help");
    }

    let filename = matches.value_of("filename").expect("please enter the filename.");
    cfg.verbose = matches.occurrences_of("verbose") as u32;
    if cfg.verbose == 0 {
        println!("use -vv to see the assembly code emulated, and -v to see the messages");
    }
    
    cfg.trace_mem = matches.is_present("memory");
    cfg.trace_regs = matches.is_present("registers");

    if matches.is_present("register") {
        cfg.trace_reg = true;
        let regs:String = matches.value_of("register").expect("select the register example: eax,ebx").to_string();
        cfg.reg_names = regs.split(',').into_iter().map(|x| x.to_string()).collect();
    }

    if matches.is_present("console") {
        cfg.console = true;
        cfg.console_num = u64::from_str_radix(matches.value_of("console").expect("select the number of moment to inspect"), 10).expect("select a valid number to spawn console");
    }

    cfg.loops = matches.is_present("loops");
    cfg.nocolors = matches.is_present("nocolors");

    if matches.is_present("string") {
        cfg.trace_string = true;
        cfg.string_addr = u64::from_str_radix(matches.value_of("string").expect("select the address of the string").trim_start_matches("0x"), 16).expect("invalid address");
    }

    if matches.is_present("inspect") {
        cfg.inspect = true;
        cfg.inspect_seq = matches.value_of("inspect").expect("select the address in the way 'dword ptr [eax + 0xa]'").to_string();
    }

    if matches.is_present("64bits") {
        cfg.is_64bits = true;
    }

    if matches.is_present("maps") {
        cfg.maps_folder = matches.value_of("maps").expect("specify the maps folder").to_string();
    } else {  // if maps is not selected, by default ...
        if cfg.is_64bits {
            cfg.maps_folder = "maps64/".to_string();
        } else {
            cfg.maps_folder = "maps32/".to_string();
        }
    }

    if matches.is_present("endpoint") {
        emu::endpoint::warning();
        cfg.endpoint = true;
    }
    if matches.is_present("console_addr") {
        cfg.console2 = true;
        cfg.console_addr = u64::from_str_radix(matches.value_of("console_addr").expect("select the address to spawn console with -C").trim_start_matches("0x"), 16).expect("invalid address");
    }
    if matches.is_present("entry_point") {
        cfg.entry_point = u64::from_str_radix(matches.value_of("entry_point").expect("select the entry point address -a").trim_start_matches("0x"), 16).expect("invalid address");
    }
    if matches.is_present("code_base_address") {
        cfg.code_base_addr = u64::from_str_radix(matches.value_of("entry_point").expect("select the code base address -b").trim_start_matches("0x"), 16).expect("invalid address");
        if !matches.is_present("entry_point") {
            eprintln!("if the code base is selected, you have to select the entry point ie -b 0x600000 -a 0x600000");
            std::process::exit(1);
        }
    }
    if matches.is_present("stack_trace") {
        cfg.stack_trace = true;
    }

    let mut emu = Emu::new();
    
    emu.set_config(cfg);
    emu.init();
    emu.load_code(&filename.to_string());

    emu.run();
}
