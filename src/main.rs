extern crate clap;

use std::io::Write as _;
use clap::{App, Arg};
use libscemu::emu32;
use libscemu::emu64;
use env_logger::Env;

macro_rules! register_arg {
    ($reg:expr) => {
        Arg::with_name($reg)
            .long($reg)
            .help(concat!("set ", $reg, " register"))
            .takes_value(true)
            .value_name(&$reg.to_uppercase())
    }
}

macro_rules! match_register_arg {
    ($matches:expr, $emu:expr, $reg:expr) => {
        if $matches.is_present($reg) {
            let value = u64::from_str_radix(
                $matches
                    .value_of($reg)
                    .expect(concat!("select the ", $reg, " register"))
                    .trim_start_matches("0x"),
                16,
            )
            .expect("invalid address");
            $emu.regs.set_reg_by_name($reg, value);
        }
    }
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "{}",
                record.args()
            )
        })
        .init();

    let matches = App::new("SCEMU emulator for malware")
        .version(env!("CARGO_PKG_VERSION"))
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
        /*
        .arg(Arg::with_name("endpoint")
            .short("e")
            .long("endpoint")
            .help("perform communications with the endpoint, use tor or vpn!")
            .takes_value(false))*/

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
        .arg(Arg::with_name("stack_address")
            .long("stack_address")
            .help("set stack address")
            .takes_value(true)
            .value_name("ADDRESS"))
        .arg(Arg::with_name("stack_trace")
            .short("p")
            .long("stack")
            .help("trace stack on push/pop")
            .takes_value(false))
        .arg(Arg::with_name("test_mode")
            .short("t")
            .long("test")
            .help("test mode")
            .takes_value(false))
        .arg(Arg::with_name("banzai")
                .long("banzai")
                .help("skip unimplemented instructions, and keep up emulating what can be emulated")
                .takes_value(false))
        .arg(Arg::with_name("script")
            .long("script")
            .short("x")
            .help("launch an emulation script, see scripts_examples folder")
            .takes_value(true)
            .value_name("SCRIPT"))
        .arg(Arg::with_name("trace")
            .long("trace")
            .short("T")
            .help("output trace to specified file")
            .takes_value(true)
            .value_name("TRACE_FILENAME"))
        .arg(register_arg!("rax"))
        .arg(register_arg!("rbx"))
        .arg(register_arg!("rcx"))
        .arg(register_arg!("rdx"))
        .arg(register_arg!("rsp"))
        .arg(register_arg!("rbp"))
        .arg(register_arg!("rsi"))
        .arg(register_arg!("rdi"))
        .arg(register_arg!("r8"))
        .arg(register_arg!("r9"))
        .arg(register_arg!("r10"))
        .arg(register_arg!("r11"))
        .arg(register_arg!("r12"))
        .arg(register_arg!("r13"))
        .arg(register_arg!("r14"))
        .arg(register_arg!("r15"))
        .arg(register_arg!("rflags"))
        .arg(register_arg!("mxcsr"))
        .get_matches();

    if !matches.is_present("filename") {
        log::error!("the filename is mandatory, try -f <FILENAME> or --help");
    }

    let mut emu: libscemu::emu::Emu;

    // 32 or 64 bit
    if matches.is_present("64bits") {
        emu = emu64();
        emu.cfg.is_64bits = true;
    } else {
        emu = emu32();
        emu.cfg.is_64bits = false;
    }

    // filename
    let filename = matches
        .value_of("filename")
        .expect("please enter the filename.")
        .to_string();
    emu.cfg.filename = filename.clone();

    // verbose
    emu.cfg.verbose = matches.occurrences_of("verbose") as u32;
    emu.set_verbose(emu.cfg.verbose);
    if emu.cfg.verbose == 0 {
        log::info!("use -vv to see the assembly code emulated, and -v to see the messages");
    }

    // tracing
    emu.cfg.trace_mem = matches.is_present("memory");
    emu.cfg.trace_regs = matches.is_present("registers");
    if matches.is_present("register") {
        emu.cfg.trace_reg = true;
        let regs: String = matches
            .value_of("register")
            .expect("select the register example: eax,ebx")
            .to_string();
        emu.cfg.reg_names = regs.split(',').into_iter().map(|x| x.to_string()).collect();
    }
    if matches.is_present("string") {
        emu.cfg.trace_string = true;
        emu.cfg.string_addr = u64::from_str_radix(
            matches
                .value_of("string")
                .expect("select the address of the string")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
    }
    if matches.is_present("trace") {
        let trace_filename = matches
            .value_of("trace")
            .expect("specify the trace output file")
            .to_string();
        let mut trace_file = std::fs::File::create(&trace_filename)
            .expect("Failed to create trace file");
        writeln!(
            trace_file,
            r#""Index","Address","Bytes","Disassembly","Registers","Memory","Comments""#
        ).expect("Failed to write trace file header");
        emu.cfg.trace_file = Some(trace_file);
    }

    // console
    if matches.is_present("console") {
        emu.cfg.console = true;
        emu.cfg.console_num = u64::from_str_radix(
            matches
                .value_of("console")
                .expect("select the number of moment to inspect"),
            10,
        )
        .expect("select a valid number to spawn console");
        emu.spawn_console_at(emu.cfg.console_num);
    }
    emu.cfg.loops = matches.is_present("loops");
    emu.cfg.nocolors = matches.is_present("nocolors");

    // inspect
    if matches.is_present("inspect") {
        emu.cfg.inspect = true;
        emu.cfg.inspect_seq = matches
            .value_of("inspect")
            .expect("select the address in the way 'dword ptr [eax + 0xa]'")
            .to_string();
    }

    // banzai
    if matches.is_present("banzai") {
        emu.cfg.skip_unimplemented = true;
    }

    // maps
    if matches.is_present("maps") {
        emu.set_maps_folder(matches.value_of("maps").expect("specify the maps folder"));
    } else {
        // if maps is not selected, by default ...
        if emu.cfg.is_64bits {
            emu.set_maps_folder("maps64/");
        } else {
            emu.set_maps_folder("maps32/");
        }
    }

    // code base address
    if matches.is_present("code_base_address") {
        emu.cfg.code_base_addr = u64::from_str_radix(
            matches
                .value_of("code_base_address")
                .expect("select the code base address -b")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        if !matches.is_present("entry_point") {
            log::error!("if the code base is selected, you have to select the entry point ie -b 0x600000 -a 0x600000");
            std::process::exit(1);
        }
    }

    // stack address
    if matches.is_present("stack_address") {
        emu.cfg.stack_addr = u64::from_str_radix(
            matches
                .value_of("stack_address")
                .expect("select the stack address")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
    }

    // register values
    match_register_arg!(matches, emu, "rax");
    match_register_arg!(matches, emu, "rbx");
    match_register_arg!(matches, emu, "rcx");
    match_register_arg!(matches, emu, "rdx");
    match_register_arg!(matches, emu, "rsp");
    match_register_arg!(matches, emu, "rbp");
    match_register_arg!(matches, emu, "rsi");
    match_register_arg!(matches, emu, "rdi");
    match_register_arg!(matches, emu, "r8");
    match_register_arg!(matches, emu, "r9");
    match_register_arg!(matches, emu, "r10");
    match_register_arg!(matches, emu, "r11");
    match_register_arg!(matches, emu, "r12");
    match_register_arg!(matches, emu, "r13");
    match_register_arg!(matches, emu, "r14");
    match_register_arg!(matches, emu, "r15");
    if matches.is_present("rflags") {
        let value = u64::from_str_radix(
            matches
                .value_of("rflags")
                .expect("select the rflags register")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        emu.flags.load(value as u32);
    }
    if matches.is_present("mxcsr") {
        let value = u64::from_str_radix(
            matches
                .value_of("mxcsr")
                .expect("select the mxcsr register")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        emu.fpu.mxcsr = value as u32;
    }

    // init
    let clear_registers = false; // TODO: this needs to be more dynamic, like if we have a register set via args or not
    let clear_flags = false; // TODO: this needs to be more dynamic, like if we have a flag set via args or not
    emu.init(clear_registers, clear_flags);

    // endpoint
    if matches.is_present("endpoint") {
        //TODO: emu::endpoint::warning();
        emu.cfg.endpoint = true;
    }

    // console
    if matches.is_present("console_addr") {
        emu.cfg.console2 = true;
        emu.cfg.console_addr = u64::from_str_radix(
            matches
                .value_of("console_addr")
                .expect("select the address to spawn console with -C")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        emu.spawn_console_at_addr(emu.cfg.console_addr);
    }

    // entry point
    if matches.is_present("entry_point") {
        emu.cfg.entry_point = u64::from_str_radix(
            matches
                .value_of("entry_point")
                .expect("select the entry point address -a")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");    
    }

    // stack trace
    if matches.is_present("stack_trace") {
        emu.cfg.stack_trace = true;
    }

    // test mode
    if matches.is_present("test_mode") {
        emu.cfg.test_mode = true;
    }

    // load code
    emu.load_code(&filename);

    // script
    if matches.is_present("script") {
        emu.disable_ctrlc();
        let mut script = libscemu::emu::script::Script::new();
        script.load(
            matches
                .value_of("script")
                .expect("select a script filename"),
        );
        script.run(&mut emu);
    } else {
        //emu.enable_ctrlc(); // TODO: make configurable with command line arg
        emu.run(None).unwrap();
    }
}
