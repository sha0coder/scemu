use crate::emu;
use crate::emu::constants;
use crate::emu::context64::Context64;
use crate::emu::structures;
use crate::emu::winapi32::helper;
use crate::emu::winapi64::kernel32;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let apiname = kernel32::guess_api_name(emu, addr);
    match apiname.as_str() {
        "ZwQueueApcThread" => ZwQueueApcThread(emu),
        "NtAllocateVirtualMemory" => NtAllocateVirtualMemory(emu),
        "NtGetContextThread" => NtGetContextThread(emu),
        "RtlAddVectoredExceptionHandler" => RtlAddVectoredExceptionHandler(emu),
        "RtlRemoveVectoredExceptionHandler" => RtlRemoveVectoredExceptionHandler(emu),
        "LdrLoadDll" => LdrLoadDll(emu),
        "NtQueryVirtualMemory" => NtQueryVirtualMemory(emu),
        "stricmp" => stricmp(emu),
        "RtlExitUserThread" => RtlExitUserThread(emu),
        "RtlAllocateHeap" => RtlAllocateHeap(emu),
        "RtlQueueWorkItem" => RtlQueueWorkItem(emu),
        "NtWaitForSingleObject" => NtWaitForSingleObject(emu),
        "sscanf" => sscanf(emu),
        "NtGetTickCount" => NtGetTickCount(emu),
        "NtQueryPerformanceCounter" => NtQueryPerformanceCounter(emu),
        "RtlGetProcessHeaps" => RtlGetProcessHeaps(emu),
        "RtlDosPathNameToNtPathName_U" => RtlDosPathNameToNtPathName_U(emu),
        "NtCreateFile" => NtCreateFile(emu),
        "RtlFreeHeap" => RtlFreeHeap(emu),
        "NtQueryInformationFile" => NtQueryInformationFile(emu),
        "NtReadFile" => NtReadFile(emu),
        "NtClose" => NtClose(emu),
        "RtlInitializeCriticalSectionAndSpinCount" => RtlInitializeCriticalSectionAndSpinCount(emu),
        "NtProtectVirtualMemory" => NtProtectVirtualMemory(emu),
        "RtlEnterCriticalSection" => RtlEnterCriticalSection(emu),
        "RtlGetVersion" => RtlGetVersion(emu),
        "RtlInitializeCriticalSectionEx" => RtlInitializeCriticalSectionEx(emu),
        "memset" => memset(emu),
        "RtlSetUnhandledExceptionFilter" => RtlSetUnhandledExceptionFilter(emu),
        "RtlCopyMemory" => RtlCopyMemory(emu),
        "RtlReAllocateHeap" => RtlReAllocateHeap(emu),
        "NtFlushInstructionCache" => NtFlushInstructionCache(emu),
        "LdrGetDllHandleEx" => LdrGetDllHandleEx(emu),
        "NtTerminateThread" => NtTerminateThread(emu),

        _ => {
            log::info!("calling unimplemented ntdll API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    String::new()
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
        .expect("bad NtAllocateVirtualMemory address parameter");
    let size = emu
        .maps
        .read_qword(size_ptr)
        .expect("bad NtAllocateVirtualMemory size parameter");

    let do_alloc: bool = if addr == 0 {
        true
    } else {
        emu.maps.is_mapped(addr)
    };

    if size == 0 {
        panic!("NtAllocateVirtualMemory mapping zero bytes.")
    }

    let alloc_addr: u64 = if do_alloc {
        match emu.maps.alloc(size) {
            Some(a) => a,
            None => panic!("/!\\ out of memory cannot allocate ntdll!NtAllocateVirtualMemory "),
        }
    } else {
        addr
    };

    log::info!(
        "{}** {} ntdll!NtAllocateVirtualMemory  addr: 0x{:x} sz: {} alloc: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        size,
        alloc_addr,
        emu.colors.nc
    );

    emu.maps
        .create_map(
            format!("valloc_{:x}", alloc_addr).as_str(),
            alloc_addr,
            size,
        )
        .expect("ntdll!NtAllocateVirtualMemory cannot create map");

    if !emu.maps.write_qword(addr_ptr, alloc_addr) {
        panic!("NtAllocateVirtualMemory: cannot write on address pointer");
    }

    emu.regs.rax = emu::constants::STATUS_SUCCESS;
}

fn stricmp(emu: &mut emu::Emu) {
    let str1ptr = emu.regs.rcx;
    let str2ptr = emu.regs.rdx;
    let str1 = emu.maps.read_string(str1ptr);
    let str2 = emu.maps.read_string(str2ptr);

    log::info!(
        "{}** {} ntdll!stricmp  '{}'=='{}'? {}",
        emu.colors.light_red,
        emu.pos,
        str1,
        str2,
        emu.colors.nc
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

    log::info!(
        "{}** {} ntdll!NtQueryVirtualMemory addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        addr,
        emu.colors.nc
    );

    if handle != 0xffffffff {
        log::info!("\tusing handle of remote process {:x}", handle);

        if !helper::handler_exist(handle) {
            log::info!("\nhandler doesnt exist.");
        }
    }

    let out_meminfo_ptr = emu.regs.r9;

    if !emu.maps.is_mapped(addr) {
        log::info!(
            "/!\\ ntdll!NtQueryVirtualMemory: querying non maped addr: 0x{:x}",
            addr
        );

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
    log::info!(
        "{}** {} ntdll!LdrLoadDll   lib: {} {}",
        emu.colors.light_red,
        emu.pos,
        libname,
        emu.colors.nc
    );

    if libname == "user32.dll" {
        let user32 = emu
            .maps
            .create_map("user32", 0x773b0000, 0x1000)
            .expect("ntdll!LdrLoadDll_gul cannot create map");
        user32.load("maps32/user32.bin");
        let user32_text = emu
            .maps
            .create_map("user32_text", 0x773b1000, 0x1000)
            .expect("ntdll!LdrLoadDll_gul cannot create map");
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

    log::info!(
        "{}** {} ntdll!RtlAddVectoredExceptionHandler  {} callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        p1,
        fptr,
        emu.colors.nc
    );

    emu.veh = fptr;
    emu.regs.rax = 0x2c2878;
}

fn RtlRemoveVectoredExceptionHandler(emu: &mut emu::Emu) {
    let p1 = emu.regs.rcx;
    let fptr = emu.regs.rdx;

    log::info!(
        "{}** {} ntdll!RtlRemoveVectoredExceptionHandler  {} callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        p1,
        fptr,
        emu.colors.nc
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

    log::info!(
        "{}** {} ntdll_NtGetContextThread   ctx: {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let ctx = Context64::new(&emu.regs);
    ctx.save(ctx_ptr2, &mut emu.maps);

    emu.regs.rax = 0;
}

fn RtlExitUserThread(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ntdll!RtlExitUserThread   {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
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

    log::info!(
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

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlAllocateHeap(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let mut size = emu.regs.r8;
    let alloc_addr: u64;

    /*
    if emu.maps.exists_mapname(&map_name) {
        let map = emu.maps.get_map_by_name_mut(&map_name).unwrap();
        alloc_addr = map.get_base();
        if size as usize > map.size() {
            map.set_size(size+1024);
        }
    } else {
    */

    if size < 1024 {
        size = 1024
    }
    let alloc_addr = match emu.maps.alloc(size) {
        Some(a) => a,
        None => panic!("/!\\ out of memory cannot allocate ntdll!RtlAllocateHeap"),
    };
    let map_name = format!("valloc_{:x}", alloc_addr);
    emu.maps
        .create_map(&map_name, alloc_addr, size)
        .expect("ntdll!RtlAllocateHeap cannot create map");
    //}

    log::info!(
        "{}** {} ntdll!RtlAllocateHeap  hndl: {:x} sz: {}   =addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        size,
        alloc_addr,
        emu.colors.nc
    );

    emu.regs.rax = alloc_addr;
}

fn RtlQueueWorkItem(emu: &mut emu::Emu) {
    let fptr = emu.regs.rcx;
    let ctx = emu.regs.rdx;
    let flags = emu.regs.r8;

    log::info!(
        "{}** {} ntdll!RtlQueueWorkItem  fptr: 0x{:x} ctx: 0x{:x} flags: {} {}",
        emu.colors.light_red,
        emu.pos,
        fptr,
        ctx,
        flags,
        emu.colors.nc
    );

    if fptr > constants::LIBS_BARRIER64 {
        let name = kernel32::guess_api_name(emu, fptr);
        log::info!("api: {} ", name);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn NtWaitForSingleObject(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let bAlert = emu.regs.rdx;
    let timeout = emu.regs.r8;

    log::info!(
        "{}** {} ntdll!NtWaitForSingleObject  hndl: 0x{:x} timeout: {} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        timeout,
        emu.colors.nc
    );

    emu.regs.rax = 0x102; //constants::STATUS_SUCCESS;
}

fn sscanf(emu: &mut emu::Emu) {
    let buffer_ptr = emu.regs.rcx;
    let fmt_ptr = emu.regs.rdx;
    let list = emu.regs.r8;

    let buffer = emu.maps.read_string(buffer_ptr);
    let fmt = emu.maps.read_string(fmt_ptr);

    log::info!(
        "{}** {} ntdll!sscanf out_buff: `{}` fmt: `{}` {}",
        emu.colors.light_red,
        emu.pos,
        buffer,
        fmt,
        emu.colors.nc
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
    log::info!(
        "{}** {} ntdll!NtGetTickCount {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    let tick = kernel32::TICK.lock().unwrap();
    emu.regs.rax = *tick;
}

fn NtQueryPerformanceCounter(emu: &mut emu::Emu) {
    let perf_counter_ptr = emu.regs.rcx;
    let perf_freq_ptr = emu.regs.rdx;

    log::info!(
        "{}** {} ntdll!NtQueryPerformanceCounter {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_dword(perf_counter_ptr, 0);
    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlGetProcessHeaps(emu: &mut emu::Emu) {
    let num_of_heaps = emu.regs.rcx;
    let out_process_heaps = emu.regs.rcx;

    log::info!(
        "{}** {} ntdll!RtlGetProcessHeaps num: {} out: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        num_of_heaps,
        out_process_heaps,
        emu.colors.nc
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
        } else if emu.cfg.verbose >= 1 {
            log::info!(
                "/!\\ ntdll!RtlDosPathNameToNtPathName_U denied dest buffer on {} map",
                dst_map_name
            );
            log::info!(
                "memcpy1 0x{:x} <- 0x{:x}  sz: {}",
                dos_path_unicode_ptr,
                dos_path_name_ptr,
                emu.maps.sizeof_wide(dos_path_name_ptr) * 2
            );
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
            match emu.maps.alloc(255) {
                Some(a) => {
                    let mem = emu
                        .maps
                        .create_map("nt_alloc", a, 255)
                        .expect("ntdll!RtlDosPathNameToNtPathName_U cannot create map");
                    emu.maps.write_dword(nt_path_name_ptr, a as u32);
                    emu.maps.memcpy(
                        a,
                        dos_path_name_ptr,
                        emu.maps.sizeof_wide(dos_path_name_ptr) * 2,
                    );
                }
                None => {
                    if emu.cfg.verbose >= 1 {
                        log::info!("/!\\ ntdll!RtlDosPathNameToNtPathName_U low memory");
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

    let obj_name_ptr = emu
        .maps
        .read_dword(oattrib + 8)
        .expect("ntdll!NtCreateFile error reading oattrib +8") as u64;
    let filename = emu.maps.read_wide_string(obj_name_ptr);

    log::info!(
        "{}** {} ntdll!NtCreateFile {} {}",
        emu.colors.light_red,
        emu.pos,
        filename,
        emu.colors.nc
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

    log::info!(
        "{}** {} ntdll!RtlFreeHeap 0x{} {}",
        emu.colors.light_red,
        emu.pos,
        base_addr,
        emu.colors.nc
    );

    helper::handler_close(hndl);
    let name = emu
        .maps
        .get_addr_name(base_addr)
        .unwrap_or_else(String::new);
    if name.is_empty() {
        if emu.cfg.verbose >= 1 {
            log::info!("map not allocated, so cannot free it.");
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
            log::info!("trying to free a systems map {}", name);
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

    log::info!(
        "{}** {} ntdll!NtQueryInformationFile {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

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

    log::info!(
        "{}** {} ntdll!NtReadFile {} buff: 0x{:x} sz: {} off_var: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        file,
        buff,
        len,
        off,
        emu.colors.nc
    );

    emu.maps.memset(buff, 0x90, len);
    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn NtClose(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    let uri = helper::handler_get_uri(hndl);

    log::info!(
        "{}** {} ntdll!NtClose hndl: 0x{:x} uri: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        uri,
        emu.colors.nc
    );

    if uri.is_empty() {
        emu.regs.rax = constants::STATUS_INVALID_HANDLE;
    } else {
        emu.regs.rax = constants::STATUS_SUCCESS;
    }
}

fn RtlInitializeCriticalSectionAndSpinCount(emu: &mut emu::Emu) {
    let crit_sect = emu.regs.rcx;
    let spin_count = emu.regs.rdx;

    log::info!(
        "{}** {} ntdll!RtlInitializeCriticalSectionAndSpinCount {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
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

    log::info!(
        "{}** {} ntdll!NtProtectVirtualMemory sz: {} {} {}",
        emu.colors.light_red,
        emu.pos,
        sz,
        prot,
        emu.colors.nc
    );

    emu.regs.rax = constants::STATUS_SUCCESS
}

fn RtlEnterCriticalSection(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    log::info!(
        "{}** {} ntdll!RtlEnterCriticalSection {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn RtlGetVersion(emu: &mut emu::Emu) {
    let versioninfo_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} ntdll!RtlGetVersion {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let versioninfo = emu::structures::OsVersionInfo::new();
    versioninfo.save(versioninfo_ptr, &mut emu.maps);

    emu.regs.rax = 1;
}

fn RtlInitializeCriticalSectionEx(emu: &mut emu::Emu) {
    let crit_sect_ptr = emu.regs.rcx;
    let spin_count = emu.regs.rdx;
    let flags = emu.regs.r8;

    log::info!(
        "{}** {} ntdll!RtlInitializeCriticalSectionEx {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

fn memset(emu: &mut emu::Emu) {
    let ptr = emu.regs.rcx;
    let byte = emu.regs.rdx;
    let count = emu.regs.r8;

    log::info!(
        "{}** {} ntdll!memset ptr: 0x{:x} byte: {} count: {} {}",
        emu.colors.light_red,
        emu.pos,
        ptr,
        byte,
        count,
        emu.colors.nc
    );

    emu.maps.memset(ptr, byte as u8, count as usize);

    emu.regs.rax = ptr;
}

fn RtlSetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let filter = emu.regs.rcx;

    log::info!(
        "{}** {} ntdll!RtlSetUnhandledExceptionFilter filter: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        filter,
        emu.colors.nc
    );

    emu.feh = filter;
    emu.regs.rax = 1;
}

fn RtlCopyMemory(emu: &mut emu::Emu) {
    let dst = emu.regs.rcx;
    let src = emu.regs.rdx;
    let sz = emu.regs.r8 as usize;

    emu.maps.memcpy(dst, src, sz);
    let s = emu.maps.read_string(src);

    log::info!(
        "{}** {} ntdll!RtlCopyMemory {} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        emu.colors.nc
    );
}

fn RtlReAllocateHeap(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let sz = emu.regs.r8;

    let mapname = format!("valloc_{:x}", hndl);
    emu.regs.rax = match emu.maps.get_map_by_name_mut(&mapname) {
        Some(mem) => {
            mem.set_size(sz + 1024);
            mem.get_base()
        }
        None => 0,
    };

    log::info!(
        "{}** {} ntdll!RtlReAllocateHeap hndl: {:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        sz,
        emu.colors.nc
    );
}

fn NtFlushInstructionCache(emu: &mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let sz = emu.regs.r8;

    log::info!(
        "{}** {} ntdll!NtFlushInstructionCache hndl: {:x} 0x{:x} sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        proc_hndl,
        addr,
        sz,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn LdrGetDllHandleEx(emu: &mut emu::Emu) {
    //LdrGetDllHandleEx (_In_ ULONG Flags, _In_opt_ PWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_opt_ PVOID *DllHandle)
    let flags = emu.regs.rcx;
    let path_ptr = emu.regs.rdx;
    let characteristics = emu.regs.r8;
    let dll_name_ptr = emu.regs.r9;
    let out_hndl = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("ntdll!LdrGetDllHandleEx error reading out_hdl");

    let dll_name = emu.maps.read_wide_string(dll_name_ptr);

    log::info!(
        "{}** {} ntdll!LdrGetDllHandleEx {} {}",
        emu.colors.light_red,
        emu.pos,
        dll_name,
        emu.colors.nc
    );

    emu.maps.memcpy(path_ptr, dll_name_ptr, dll_name.len());

    let handle = helper::handler_create(&dll_name);
    emu.maps.write_qword(out_hndl, handle);

    emu.regs.rax = 1;
}

fn NtTerminateThread(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let exit_status = emu.regs.rdx;

    log::info!(
        "{}** {} ntdll!NtTerminateThread {:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        exit_status,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}
