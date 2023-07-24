use crate::emu;
use crate::emu::constants;
use crate::emu::context64::Context64;
use crate::emu::structures;
use crate::emu::winapi32::helper;
use crate::emu::winapi64::kernel32;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    match addr {
        0x77021760 => ZwQueueApcThread(emu),
        0x77021490 => NtAllocateVirtualMemory(emu),
        0x77021fe0 => NtGetContextThread(emu),
        0x770b3ad0 => RtlAddVectoredExceptionHandler(emu),
        0x7709c2d0 => RtlRemoveVectoredExceptionHandler(emu),
        0x76ff7a90 => LdrLoadDll(emu),
        0x77021540 => NtQueryVirtualMemory(emu),
        0x7700c5ec => stricmp(emu),
        0x77016930 => RtlExitUserThread(emu),
        0x770233a0 => RtlAllocateHeap(emu),
        0x76ff1f70 => RtlQueueWorkItem(emu),
        0x77021350 => NtWaitForSingleObject(emu),
        0x7705a974 => sscanf(emu),
        0x770847b0 => NtGetTickCount(emu),
        0x77021620 => NtQueryPerformanceCounter(emu),
        0x77094c80 => RtlGetProcessHeaps(emu),
        0x7701b5c0 => RtlDosPathNameToNtPathName_U(emu),
        0x77021860 => NtCreateFile(emu),
        0x77023200 => RtlFreeHeap(emu),
        0x77021420 => NtQueryInformationFile(emu),
        0x77021370 => NtReadFile(emu),
        0x77021400 => NtClose(emu),
        0x76ff6c20 => RtlInitializeCriticalSectionAndSpinCount(emu),
        0x77021810 => NtProtectVirtualMemory(emu),
        0x77022fc0 => RtlEnterCriticalSection(emu),
        0x76ff9380 => RtlGetVersion(emu),
        0x7700b3f0 => RtlInitializeCriticalSectionEx(emu),
        0x77022ed0 => memset(emu),
        0x77011950 => RtlSetUnhandledExceptionFilter(emu),

        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented ntdll API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

fn NtAllocateVirtualMemory(emu: &mut emu::Emu) {
    /*
        __kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
            [in]      HANDLE    ProcessHandle,
            [in, out] PVOID     *BaseAddress,
            [in]      ULONG_PTR ZeroBits,
            [in, out] PSIZE_T   RegionSize,
            [in]      ULONG     AllocationType,
            [in]      ULONG     Protect
    */

    let addr_ptr = emu.regs.rcx;
    let size_ptr = emu.regs.rdx;

    let addr = emu
        .maps
        .read_qword(addr_ptr)
        .expect("bad NtAllocateVirtualMemory address parameter") as u64;
    let size = emu
        .maps
        .read_qword(size_ptr)
        .expect("bad NtAllocateVirtualMemory size parameter") as u64;
    let do_alloc: bool;
    let alloc_addr: u64;

    if addr == 0 {
        do_alloc = true;
    } else {
        do_alloc = emu.maps.is_mapped(addr);
    }

    if size == 0 {
        panic!("NtAllocateVirtualMemory mapping zero bytes.")
    }

    if do_alloc {
        alloc_addr = match emu.maps.alloc(size) {
            Some(a) => a,
            None => panic!("/!\\ out of memory cannot allocate ntdll!NtAllocateVirtualMemory "),
        };
    } else {
        alloc_addr = addr;
    }

    println!(
        "{}** {} ntdll!NtAllocateVirtualMemory  addr: 0x{:x} sz: {} alloc: 0x{:x} {}",
        emu.colors.light_red, emu.pos, addr, size, alloc_addr, emu.colors.nc
    );

    let alloc = emu
        .maps
        .create_map(format!("valloc_{:x}", alloc_addr).as_str());
    alloc.set_base(alloc_addr);
    alloc.set_size(size);
    //alloc.set_bottom(alloc_addr + size);

    if !emu.maps.write_qword(addr_ptr, alloc_addr) {
        panic!("NtAllocateVirtualMemory: cannot write on address pointer");
    }

    emu.regs.rax = emu::constants::STATUS_SUCCESS;

    for _ in 0..2 {
        emu.stack_pop64(false);
    }
}

fn stricmp(emu: &mut emu::Emu) {
    let str1ptr = emu.regs.rcx;
    let str2ptr = emu.regs.rdx;
    let str1 = emu.maps.read_string(str1ptr);
    let str2 = emu.maps.read_string(str2ptr);

    println!(
        "{}** {} ntdll!stricmp  '{}'=='{}'? {}",
        emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc
    );

    if str1 == str2 {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = 1;
    }
}

fn NtQueryVirtualMemory(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let addr = emu.regs.rdx;

    println!(
        "{}** {} ntdll!NtQueryVirtualMemory addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, addr, emu.colors.nc
    );

    if handle != 0xffffffff {
        println!("\tusing handle of remote process {:x}", handle);

        if !helper::handler_exist(handle) {
            println!("\nhandler doesnt exist.");
        }
    }

    let out_meminfo_ptr = emu.regs.r9;

    if !emu.maps.is_mapped(addr) {
        println!(
            "/!\\ ntdll!NtQueryVirtualMemory: querying non maped addr: 0x{:x}",
            addr
        );
        for _ in 0..2 {
            emu.stack_pop64(false);
        }
        emu.regs.rax = emu::constants::STATUS_INVALID_PARAMETER;
        return;
    }

    let base = emu.maps.get_addr_base(addr).unwrap_or(0);

    let mut mem_info = structures::MemoryBasicInformation::load(out_meminfo_ptr, &emu.maps);
    mem_info.base_address = base as u32; //addr & 0xfff;
    mem_info.allocation_base = base as u32; //  addr & 0xfff;
    mem_info.allocation_protect = constants::PAGE_EXECUTE | constants::PAGE_READWRITE;
    mem_info.state = constants::MEM_COMMIT;
    mem_info.typ = constants::MEM_PRIVATE;
    mem_info.save(out_meminfo_ptr, &mut emu.maps);

    for _ in 0..2 {
        emu.stack_pop64(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn LdrLoadDll(emu: &mut emu::Emu) {
    // NTSTATUS NTAPI DECLSPEC_HOTPATCH 	LdrLoadDll (
    //      IN PWSTR SearchPath OPTIONAL,
    //      IN PULONG DllCharacteristics OPTIONAL,
    //      IN PUNICODE_STRING DllName,
    //      OUT PVOID *BaseAddress)

    let libname_ptr = emu.regs.r8;
    let libaddr_ptr = emu.regs.r9;

    let libname = emu.maps.read_wide_string(libname_ptr);
    println!(
        "{}** {} ntdll!LdrLoadDll   lib: {} {}",
        emu.colors.light_red, emu.pos, libname, emu.colors.nc
    );

    if libname == "user32.dll" {
        let user32 = emu.maps.create_map("user32");
        user32.set_base(0x773b0000);
        user32.load("maps32/user32.bin");
        let user32_text = emu.maps.create_map("user32_text");
        user32_text.set_base(0x773b1000);
        user32_text.load("maps32/user32_text.bin");

        if !emu.maps.write_qword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll_LdrLoadDll: cannot write in addr param");
        }
    }

    emu.regs.rax = emu::constants::STATUS_SUCCESS;
}

fn RtlAddVectoredExceptionHandler(emu: &mut emu::Emu) {
    let p1 = emu.regs.rcx;
    let fptr = emu.regs.rdx;

    println!(
        "{}** {} ntdll!RtlAddVectoredExceptionHandler  {} callback: 0x{:x} {}",
        emu.colors.light_red, emu.pos, p1, fptr, emu.colors.nc
    );

    emu.veh = fptr;
    emu.regs.rax = 0x2c2878;
}

fn RtlRemoveVectoredExceptionHandler(emu: &mut emu::Emu) {
    let p1 = emu.regs.rcx;
    let fptr = emu.regs.rdx;

    println!(
        "{}** {} ntdll!RtlRemoveVectoredExceptionHandler  {} callback: 0x{:x} {}",
        emu.colors.light_red, emu.pos, p1, fptr, emu.colors.nc
    );

    emu.veh = 0;
    emu.regs.rax = 0;
}

fn NtGetContextThread(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let ctx_ptr = emu.regs.rdx;
    let ctx_ptr2 = emu
        .maps
        .read_qword(ctx_ptr)
        .expect("ntdll_NtGetContextThread: error reading context ptr");

    println!(
        "{}** {} ntdll_NtGetContextThread   ctx: {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    let ctx = Context64::new(&emu.regs);
    ctx.save(ctx_ptr2, &mut emu.maps);

    emu.regs.rax = 0;
}

fn RtlExitUserThread(emu: &mut emu::Emu) {
    println!(
        "{}** {} ntdll!RtlExitUserThread   {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.spawn_console();
    std::process::exit(1);
}

fn ZwQueueApcThread(emu: &mut emu::Emu) {
    let thread_handle = emu.regs.rcx;
    let apc_routine = emu.regs.rdx;
    let apc_ctx = emu.regs.r8;
    let arg1 = emu.regs.r9;
    let arg2 = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("kernel32!ZwQueueApcThread cannot read arg2");

    println!(
        "{}** {} ntdll!ZwQueueApcThread hndl: {} routine: {} ctx: {} arg1: {} arg2: {} {}",
        emu.colors.light_red,
        emu.pos,
        thread_handle,
        apc_routine,
        apc_ctx,
        arg1,
        arg2,
        emu.colors.nc
    );

    emu.stack_pop64(false);
    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlAllocateHeap(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let size = emu.regs.r8;

    let alloc_addr = match emu.maps.alloc(size) {
        Some(a) => a,
        None => panic!("/!\\ out of memory cannot allocate ntdll!RtlAllocateHeap"),
    };

    println!(
        "{}** {} ntdll!RtlAllocateHeap  sz: {}   =addr: 0x{:x} {}",
        emu.colors.light_red, emu.pos, size, alloc_addr, emu.colors.nc
    );

    let alloc = emu
        .maps
        .create_map(format!("valloc_{:x}", alloc_addr).as_str());
    alloc.set_base(alloc_addr);
    alloc.set_size(size);

    emu.regs.rax = alloc_addr;
}

fn RtlQueueWorkItem(emu: &mut emu::Emu) {
    let fptr = emu.regs.rcx;
    let ctx = emu.regs.rdx;
    let flags = emu.regs.r8;

    println!(
        "{}** {} ntdll!RtlQueueWorkItem  fptr: 0x{:x} ctx: 0x{:x} flags: {} {}",
        emu.colors.light_red, emu.pos, fptr, ctx, flags, emu.colors.nc
    );

    if fptr > constants::LIBS_BARRIER64 {
        let name = kernel32::guess_api_name(emu, fptr);
        println!("api: {} ", name);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn NtWaitForSingleObject(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let bAlert = emu.regs.rdx;
    let timeout = emu.regs.r8;

    println!(
        "{}** {} ntdll!NtWaitForSingleObject  hndl: 0x{:x} timeout: {} {}",
        emu.colors.light_red, emu.pos, handle, timeout, emu.colors.nc
    );

    emu.regs.rax = 0x102; //constants::STATUS_SUCCESS;
}

fn sscanf(emu: &mut emu::Emu) {
    let buffer_ptr = emu.regs.rcx;
    let fmt_ptr = emu.regs.rdx;
    let list = emu.regs.r8;

    let buffer = emu.maps.read_string(buffer_ptr);
    let fmt = emu.maps.read_string(fmt_ptr);

    println!(
        "{}** {} ntdll!sscanf out_buff: `{}` fmt: `{}` {}",
        emu.colors.light_red, emu.pos, buffer, fmt, emu.colors.nc
    );

    let rust_fmt = fmt
        .replace("%x", "{x}")
        .replace("%d", "{}")
        .replace("%s", "{}")
        .replace("%hu", "{u16}")
        .replace("%i", "{}")
        .replace("%o", "{o}")
        .replace("%f", "{}");
    let params = rust_fmt.matches("{").count();

    unimplemented!("sscanf is unimplemented for now.");
}

fn NtGetTickCount(emu: &mut emu::Emu) {
    println!(
        "{}** {} ntdll!NtGetTickCount {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    let tick = kernel32::TICK.lock().unwrap();
    emu.regs.rax = *tick as u64;
}

fn NtQueryPerformanceCounter(emu: &mut emu::Emu) {
    let perf_counter_ptr = emu.regs.rcx;
    let perf_freq_ptr = emu.regs.rdx;

    println!(
        "{}** {} ntdll!NtQueryPerformanceCounter {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.maps.write_dword(perf_counter_ptr, 0);
    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlGetProcessHeaps(emu: &mut emu::Emu) {
    let num_of_heaps = emu.regs.rcx;
    let out_process_heaps = emu.regs.rcx;

    println!(
        "{}** {} ntdll!RtlGetProcessHeaps num: {} out: 0x{:x} {}",
        emu.colors.light_red, emu.pos, num_of_heaps, out_process_heaps, emu.colors.nc
    );

    emu.regs.rax = 1;
}

struct CurDir {
    DosPath: String, // unicode
    Handle: u64,
}

fn RtlDosPathNameToNtPathName_U(emu: &mut emu::Emu) {
    let dos_path_name_ptr = emu.regs.rcx;
    let nt_path_name_ptr = emu.regs.rdx;
    let nt_file_name_part_ptr = emu.regs.r8;
    let curdir_ptr = emu.regs.r9;

    let dos_path_name = emu.maps.read_wide_string(dos_path_name_ptr);

    //TODO: si la variable destino apunta a pila no hacer memcpy, solo si es un alloc_

    if curdir_ptr > 0 {
        let dos_path_unicode_ptr = emu
            .maps
            .read_dword(curdir_ptr)
            .expect("ntdll!RtlDosPathNameToNtPathName_U error reading dos_path_unicode_ptr")
            as u64;

        let dst_map_name = emu
            .maps
            .get_addr_name(dos_path_unicode_ptr)
            .expect("ntdll!RtlDosPathNameToNtPathName_U writting on unmapped address");

        if dst_map_name.starts_with("alloc_") {
            emu.maps.memcpy(
                dos_path_unicode_ptr,
                dos_path_name_ptr,
                emu.maps.sizeof_wide(dos_path_name_ptr) * 2,
            );
        } else {
            if emu.cfg.verbose >= 1 {
                println!(
                    "/!\\ ntdll!RtlDosPathNameToNtPathName_U denied dest buffer on {} map",
                    dst_map_name
                );
                println!(
                    "memcpy1 0x{:x} <- 0x{:x}  sz: {}",
                    dos_path_unicode_ptr,
                    dos_path_name_ptr,
                    emu.maps.sizeof_wide(dos_path_name_ptr) * 2
                );
            }
        }
    }

    if nt_path_name_ptr > 0 {
        // its a stack dword where to write the address of a new buffer

        let dst_map_name = emu
            .maps
            .get_addr_name(nt_path_name_ptr)
            .expect("ntdll!RtlDosPathNameToNtPathName_U writting on unmapped address.");

        if dst_map_name.starts_with("alloc_") {
            emu.maps.memcpy(
                nt_path_name_ptr,
                dos_path_name_ptr,
                emu.maps.sizeof_wide(dos_path_name_ptr) * 2,
            );
        } else {
            let addr = match emu.maps.alloc(255) {
                Some(a) => {
                    let mem = emu.maps.create_map("nt_alloc");
                    mem.set_base(a);
                    mem.set_size(255);
                    emu.maps.write_dword(nt_path_name_ptr, a as u32);
                    emu.maps.memcpy(
                        a,
                        dos_path_name_ptr,
                        emu.maps.sizeof_wide(dos_path_name_ptr) * 2,
                    );
                }
                None => {
                    if emu.cfg.verbose >= 1 {
                        println!("/!\\ ntdll!RtlDosPathNameToNtPathName_U low memory");
                    }
                }
            };
        }
    }
}

fn NtCreateFile(emu: &mut emu::Emu) {
    let out_hndl_ptr = emu.regs.rcx;
    let access_mask = emu.regs.rdx;
    let oattrib = emu.regs.r8;
    let iostat = emu.regs.r9;
    let alloc_sz = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("ntdll!NtCreateFile error reading alloc_sz param");
    let fattrib = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("ntdll!NtCreateFile error reading fattrib param");
    let share_access = emu
        .maps
        .read_qword(emu.regs.rsp + 16)
        .expect("ntdll!NtCreateFile error reading share_access param");
    let create_disp = emu
        .maps
        .read_qword(emu.regs.rsp + 24)
        .expect("ntdll!NtCreateFile error reading create_disp param");
    let create_opt = emu
        .maps
        .read_qword(emu.regs.rsp + 32)
        .expect("ntdll!NtCreateFile error reading create_opt param");
    let ea_buff = emu
        .maps
        .read_qword(emu.regs.rsp + 40)
        .expect("ntdll!NtCreateFile error reading ea_buff param");
    let ea_len = emu
        .maps
        .read_qword(emu.regs.rsp + 48)
        .expect("ntdll!NtCreateFile error reading ea_len param");

    for _ in 0..7 {
        emu.stack_pop64(false);
    }

    let obj_name_ptr = emu
        .maps
        .read_dword(oattrib + 8)
        .expect("ntdll!NtCreateFile error reading oattrib +8") as u64;
    let filename = emu.maps.read_wide_string(obj_name_ptr);

    println!(
        "{}** {} ntdll!NtCreateFile {} {}",
        emu.colors.light_red, emu.pos, filename, emu.colors.nc
    );

    if out_hndl_ptr > 0 {
        emu.maps
            .write_dword(out_hndl_ptr, helper::handler_create(&filename) as u32);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlFreeHeap(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let base_addr = emu.regs.r8;

    println!(
        "{}** {} ntdll!RtlFreeHeap 0x{} {}",
        emu.colors.light_red, emu.pos, base_addr, emu.colors.nc
    );

    helper::handler_close(hndl);
    let name = emu
        .maps
        .get_addr_name(base_addr)
        .unwrap_or_else(|| String::new());
    if name == "" {
        if emu.cfg.verbose >= 1 {
            println!("map not allocated, so cannot free it.");
        }
        emu.regs.rax = 0;
        return;
    }

    if name.starts_with("alloc_") {
        emu.maps.free(&name);
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
        if emu.cfg.verbose >= 1 {
            println!("trying to free a systems map {}", name);
        }
    }
}

fn NtQueryInformationFile(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let stat = emu.regs.rdx;
    let fileinfo = emu.regs.r8;
    let len = emu.regs.r9;
    let fileinfoctls = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("ntdll!NtQueryInformationFile cannot read fileinfoctls param");

    println!(
        "{}** {} ntdll!NtQueryInformationFile {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop64(false);

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn NtReadFile(emu: &mut emu::Emu) {
    let file_hndl = emu.regs.rcx;
    let ev_hndl = emu.regs.rdx;
    let apc_rout = emu.regs.r8;
    let apc_ctx = emu.regs.r9;
    let stat = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("ntdll!NtReadFile error reading stat param");
    let buff = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("ntdll!NtReadFile error reading buff param");
    let len = emu
        .maps
        .read_qword(emu.regs.rsp + 16)
        .expect("ntdll!NtReadFile error reading len param") as usize;
    let off = emu
        .maps
        .read_qword(emu.regs.rsp + 24)
        .expect("ntdll!NtReadFile error reading off param");
    let key = emu
        .maps
        .read_qword(emu.regs.rsp + 32)
        .expect("ntdll!NtReadFile error reading key param");

    let file = helper::handler_get_uri(file_hndl);

    println!(
        "{}** {} ntdll!NtReadFile {} buff: 0x{:x} sz: {} off_var: 0x{:x} {}",
        emu.colors.light_red, emu.pos, file, buff, len, off, emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop64(false);
    }

    emu.maps.memset(buff, 0x90, len);
    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn NtClose(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    let uri = helper::handler_get_uri(hndl);

    println!(
        "{}** {} ntdll!NtClose hndl: 0x{:x} uri: {} {}",
        emu.colors.light_red, emu.pos, hndl, uri, emu.colors.nc
    );

    if uri == "" {
        emu.regs.rax = constants::STATUS_INVALID_HANDLE;
    } else {
        emu.regs.rax = constants::STATUS_SUCCESS;
    }
}

fn RtlInitializeCriticalSectionAndSpinCount(emu: &mut emu::Emu) {
    let crit_sect = emu.regs.rcx;
    let spin_count = emu.regs.rdx;

    println!(
        "{}** {} ntdll!RtlInitializeCriticalSectionAndSpinCount {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn NtProtectVirtualMemory(emu: &mut emu::Emu) {
    let sz = emu.regs.rcx;
    let status = emu.regs.rdx;
    let page_number = emu.regs.r8;
    let page = emu.regs.r9;
    let prot = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("ntdll!NtProtectVirtualMemory error reading old prot param");

    println!(
        "{}** {} ntdll!NtProtectVirtualMemory sz: {} {} {}",
        emu.colors.light_red, emu.pos, sz, prot, emu.colors.nc
    );

    emu.stack_pop64(false);

    emu.regs.rax = constants::STATUS_SUCCESS
}

fn RtlEnterCriticalSection(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    println!(
        "{}** {} ntdll!RtlEnterCriticalSection {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn RtlGetVersion(emu: &mut emu::Emu) {
    let versioninfo_ptr = emu.regs.rcx;

    println!(
        "{}** {} ntdll!RtlGetVersion {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    let versioninfo = emu::structures::OsVersionInfo::new();
    versioninfo.save(versioninfo_ptr, &mut emu.maps);

    emu.regs.rax = 1;
}

fn RtlInitializeCriticalSectionEx(emu: &mut emu::Emu) {
    let crit_sect_ptr = emu.regs.rcx;
    let spin_count = emu.regs.rdx;
    let flags = emu.regs.r8;

    println!(
        "{}** {} ntdll!RtlInitializeCriticalSectionEx {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn memset(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;
    let byte = emu.regs.rdx;
    let count = emu.regs.r8;

    println!(
        "{}** {} ntdll!memset ptr: 0x{:x} byte: {} count: {} {}",
        emu.colors.light_red, emu.pos, ptr, byte, count, emu.colors.nc
    );

    emu.maps.memset(ptr, byte as u8, count as usize);

    emu.regs.rax = ptr;
}

fn RtlSetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let filter = emu.regs.rcx;

    println!(
        "{}** {} ntdll!RtlSetUnhandledExceptionFilter filter: 0x{:x} {}",
        emu.colors.light_red, emu.pos, filter, emu.colors.nc
    );

    emu.feh = filter;
    emu.regs.rax = 1;
}
