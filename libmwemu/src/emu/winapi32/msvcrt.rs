use crate::emu;
use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;
//use crate::emu::endpoint;

// msvcrt is an exception and these functions dont have to compensate the stack.

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "_initterm_e" => _initterm_e(emu),
        "_initterm" => _initterm(emu),
        "StrCmpCA" => StrCmpCA(emu),
        "fopen" => fopen(emu),
        "fwrite" => fwrite(emu),
        "fflush" => fflush(emu),
        "fclose" => fclose(emu),
        "__p___argv" => __p___argv(emu),
        "__p___argc" => __p___argc(emu),
        "malloc" => malloc(emu),
        "_onexit" => _onexit(emu),
        "_lock" => _lock(emu),
        "free" => free(emu),
        "realloc" => realloc(emu),
        "strtok" => strtok(emu),

        _ => {
            log::info!("calling unimplemented msvcrt API 0x{:x} {}", addr, api);
            return api;
        }
    }

    String::new()
}

fn _initterm_e(emu: &mut emu::Emu) {
    let start_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!_initterm_e: error reading start pointer") as u64;
    let end_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!_initterm_e: error reading en pointer") as u64;

    log::info!(
        "{}** {} msvcrt!_initterm_e 0x{:x} - 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        start_ptr,
        end_ptr,
        emu.colors.nc
    );

    //emu.stack_pop32(false);
    //emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn _initterm(emu: &mut emu::Emu) {
    let start_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!_initterm_e: error reading start pointer") as u64;
    let end_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!_initterm_e: error reading end pointer") as u64;

    log::info!(
        "{}** {} msvcrt!_initterm 0x{:x} - 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        start_ptr,
        end_ptr,
        emu.colors.nc
    );

    //emu.stack_pop32(false);
    //emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn StrCmpCA(emu: &mut emu::Emu) {
    let str1_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!StrCmpA: error reading str1 pointer") as u64;
    let str2_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!StrCmpA: error reading str2 pointer") as u64;

    let str1 = emu.maps.read_string(str1_ptr);
    let str2 = emu.maps.read_string(str2_ptr);

    log::info!(
        "{}** {} msvcrt!StrCmpA {} == {} {}",
        emu.colors.light_red,
        emu.pos,
        str1,
        str2,
        emu.colors.nc
    );

    //emu.stack_pop32(false);
    //emu.stack_pop32(false);

    if str1 == str2 {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = 0xffffffff;
    }
}

fn fopen(emu: &mut emu::Emu) {
    let filepath_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fopen error reading filepath pointer") as u64;
    let mode_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!fopen error reading mode pointer") as u64;

    let filepath = emu.maps.read_string(filepath_ptr);
    let mode = emu.maps.read_string(mode_ptr);

    log::info!(
        "{}** {} msvcrt!fopen `{}` fmt:`{}` {}",
        emu.colors.light_red,
        emu.pos,
        filepath,
        mode,
        emu.colors.nc
    );

    //emu.stack_pop32(false);
    //emu.stack_pop32(false);

    emu.regs.rax = helper::handler_create(&filepath);
}

fn fwrite(emu: &mut emu::Emu) {
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fwrite error reading buff_ptr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!fwrite error reading size");
    let nemb = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("msvcrt!fwrite error reading nemb");
    let file = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("msvcrt!fwrite error reading FILE *");

    let filename = helper::handler_get_uri(file as u64);

    /*for _ in 0..4 {
        emu.stack_pop32(false);
    }*/
    log::info!(
        "{}** {} msvcrt!fwrite `{}` 0x{:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        buff_ptr,
        size,
        emu.colors.nc
    );

    emu.regs.rax = size as u64;
}

fn fflush(emu: &mut emu::Emu) {
    let file = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fflush error getting FILE *");

    let filename = helper::handler_get_uri(file as u64);

    log::info!(
        "{}** {} msvcrt!fflush `{}` {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );

    //emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn fclose(emu: &mut emu::Emu) {
    let file = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!fclose error getting FILE *");

    let filename = helper::handler_get_uri(file as u64);

    log::info!(
        "{}** {} msvcrt!fclose `{}` {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
    );

    //emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn __p___argv(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} msvcrt!__p___argc {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0;
}

fn __p___argc(emu: &mut emu::Emu) {
    let args = match emu.maps.get_map_by_name("args") {
        Some(a) => a,
        None => {
            let addr = emu.maps.alloc(1024).expect("out of memory");
            emu.maps
                .create_map("args", addr, 1024)
                .expect("cannot create args map")
        }
    };

    log::info!(
        "{}** {} msvcrt!__p___argc {} {}",
        emu.colors.light_red,
        emu.pos,
        args.get_base(),
        emu.colors.nc
    );

    emu.regs.rax = args.get_base();
}

fn malloc(emu: &mut emu::Emu) {
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!malloc error reading size") as u64;

    if size > 0 {
        let base = emu.maps.alloc(size).expect("msvcrt!malloc out of memory");

        emu.maps
            .create_map(&format!("alloc_{:x}", base), base, size)
            .expect("msvcrt!malloc cannot create map");

        log::info!(
            "{}** {} msvcrt!malloc sz: {} addr: 0x{:x} {}",
            emu.colors.light_red,
            emu.pos,
            size,
            base,
            emu.colors.nc
        );

        emu.regs.rax = base;
    } else {
        emu.regs.rax = 0x1337; // weird msvcrt has to return a random unallocated pointer, and the program has to do free() on it
    }
}

fn __p__acmdln(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} msvcrt!__p___argc {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = 0;
}

fn _onexit(emu: &mut emu::Emu) {
    let fptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!_onexit") as u64;

    log::info!(
        "{}** {} msvcrt!_onexit 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        fptr,
        emu.colors.nc
    );

    emu.regs.rax = fptr;
    //emu.stack_pop32(false);
}

fn _lock(emu: &mut emu::Emu) {
    let lock_num = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!_lock");

    log::info!(
        "{}** {} msvcrt!_lock {} {}",
        emu.colors.light_red,
        emu.pos,
        lock_num,
        emu.colors.nc
    );

    emu.regs.rax = 1;
    //emu.stack_pop32(false);
}

fn free(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!free error reading addr");

    log::info!(
        "{}** {} msvcrt!free 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        emu.colors.nc
    );
}

fn realloc(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!realloc error reading addr") as u64;
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!realloc error reading size") as u64;

    if addr == 0 {
        if size == 0 {
            emu.regs.rax = 0;
            return;
        } else {
            let base = emu.maps.alloc(size).expect("msvcrt!malloc out of memory");

            emu.maps
                .create_map(&format!("alloc_{:x}", base), base, size)
                .expect("msvcrt!malloc cannot create map");

            log::info!(
                "{}** {} msvcrt!realloc 0x{:x} {} =0x{:x} {}",
                emu.colors.light_red,
                emu.pos,
                addr,
                size,
                base,
                emu.colors.nc
            );

            emu.regs.rax = base;
            return;
        }
    }

    if size == 0 {
        log::info!(
            "{}** {} msvcrt!realloc 0x{:x} {} =0x1337 {}",
            emu.colors.light_red,
            emu.pos,
            addr,
            size,
            emu.colors.nc
        );

        emu.regs.rax = 0x1337; // weird msvcrt has to return a random unallocated pointer, and the program has to do free() on it
        return;
    }

    let mem = emu
        .maps
        .get_mem_by_addr(addr)
        .expect("msvcrt!realloc error getting mem");
    let prev_size = mem.size();

    let new_addr = emu.maps.alloc(size).expect("msvcrt!realloc out of memory");

    emu.maps
        .create_map(&format!("alloc_{:x}", new_addr), new_addr, size)
        .expect("msvcrt!realloc cannot create map");

    emu.maps.memcpy(new_addr, addr, prev_size);
    emu.maps.dealloc(addr);

    log::info!(
        "{}** {} msvcrt!realloc 0x{:x} {} =0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        size,
        new_addr,
        emu.colors.nc
    );

    emu.regs.rax = new_addr;
}

fn strtok(emu: &mut emu::Emu) {
    let str_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("msvcrt!strtok error reading str_ptr");

    let delim_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("msvcrt!strtok error reading delim");

    let str = emu.maps.read_string(str_ptr as u64);
    let delim = emu.maps.read_string(delim_ptr as u64);

    log::info!(
        "{}** {} msvcrt!strtok `{}` `{}` {}",
        emu.colors.light_red,
        emu.pos,
        str,
        delim,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}
