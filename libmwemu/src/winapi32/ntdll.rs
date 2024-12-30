use crate::emu;
use crate::constants;
use crate::context32::Context32;
use crate::structures;
use crate::serialization;
use crate::winapi32::helper;
use crate::winapi32::kernel32;
use crate::console::Console;

use scan_fmt::scan_fmt_some;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "NtAllocateVirtualMemory" => NtAllocateVirtualMemory(emu),
        "NtGetContextThread" => NtGetContextThread(emu),
        "RtlVectoredExceptionHandler" => RtlVectoredExceptionHandler(emu),
        "LdrLoadDll" => LdrLoadDll(emu),
        "NtQueryVirtualMemory" => NtQueryVirtualMemory(emu),
        "stricmp" => stricmp(emu),
        "RtlExitUserThread" => RtlExitUserThread(emu),
        "sscanf" => sscanf(emu),
        "NtGetTickCount" => NtGetTickCount(emu),
        "NtQueryPerformanceCounter" => NtQueryPerformanceCounter(emu),
        "RtlGetProcessHeaps" => RtlGetProcessHeaps(emu),
        "RtlDosPathNameToNtPathName_U" => RtlDosPathNameToNtPathName_U(emu),
        "NtCreateFile" => NtCreateFile(emu),
        "RtlFreeHeap" => RtlFreeHeap(emu),
        "NtQueryInformationFile" => NtQueryInformationFile(emu),
        "RtlAllocateHeap" => RtlAllocateHeap(emu),
        "NtReadFile" => NtReadFile(emu),
        "NtClose" => NtClose(emu),
        "RtlInitializeCriticalSectionAndSpinCount" => RtlInitializeCriticalSectionAndSpinCount(emu),
        "NtProtectVirtualMemory" => NtProtectVirtualMemory(emu),
        "RtlEnterCriticalSection" => RtlEnterCriticalSection(emu),
        "RtlLeaveCriticalSection" => RtlLeaveCriticalSection(emu),
        "RtlGetVersion" => RtlGetVersion(emu),
        "RtlInitializeCriticalSectionEx" => RtlInitializeCriticalSectionEx(emu),
        "memset" => memset(emu),
        "RtlSetUnhandledExceptionFilter" => RtlSetUnhandledExceptionFilter(emu),
        "strlen" => strlen(emu),
        "VerSetConditionMask" => VerSetConditionMask(emu),
        "strcat" => strcat(emu),
        "memcpy" => memcpy(emu),
        "LdrLoadDll_gul" => LdrLoadDll_gul(emu),

        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("atemmpt to call unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {} at 0x{:x}", addr, api, emu.regs.rip);
            return api;
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
            );
    */

    let addr_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("bad NtAllocateVirtualMemory address pointer parameter") as u64;
    let size_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("bad NtAllocateVirtualMemory size pointer parameter") as u64;
    let addr = emu
        .maps
        .read_dword(addr_ptr)
        .expect("bad NtAllocateVirtualMemory address parameter") as u64;
    let size = emu
        .maps
        .read_dword(size_ptr)
        .expect("bad NtAllocateVirtualMemory size parameter") as u64;

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
            None => {
                panic!("/!\\ out of memory   cannot allocate forntdll!NtAllocateVirtualMemory ")
            }
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

    if !emu.maps.write_dword(addr_ptr, alloc_addr as u32) {
        panic!("NtAllocateVirtualMemory: cannot write on address pointer");
    }

    emu.regs.rax = constants::STATUS_SUCCESS;

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}

fn stricmp(emu: &mut emu::Emu) {
    let str1ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!stricmp: error reading string1") as u64;
    let str2ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!stricmp: error reading string2") as u64;
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

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
}

fn NtQueryVirtualMemory(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!NtQueryVirtualMemory: error reading handle") as u64;
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!NtQueryVirtualMemory: error reading address") as u64;

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

    let out_meminfo_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ntdll_NtQueryVirtualMemory: error reading out pointer to meminfo")
        as u64;

    if !emu.maps.is_mapped(addr) {
        log::info!(
            "/!\\ ntdll!NtQueryVirtualMemory: querying non maped addr: 0x{:x}",
            addr
        );
        for _ in 0..6 {
            emu.stack_pop32(false);
        }
        emu.regs.rax = constants::STATUS_INVALID_PARAMETER;
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

    for _ in 0..6 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn LdrLoadDll(emu: &mut emu::Emu) {
    //let libaddr_ptr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("LdrLoadDll: error reading lib ptr") as u64;
    //let libname_ptr = emu.maps.read_dword(emu.regs.get_esp()+20).expect("LdrLoadDll: error reading lib param") as u64;

    let libname_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("LdrLoadDll: error reading lib name") as u64;
    let libaddr_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("LdrLoadDll: error reading lib base") as u64;

    let libname = emu.maps.read_wide_string(libname_ptr);
    log::info!(
        "{}** {} ntdll!LdrLoadDll   lib: {} {}",
        emu.colors.light_red,
        emu.pos,
        libname,
        emu.colors.nc
    );

    let base = kernel32::load_library(emu, &libname);
    emu.maps.write_dword(libname_ptr, base as u32);

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn LdrLoadDll_gul(emu: &mut emu::Emu) {
    let path_to_file_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("LdrLoadDll: error reading lib base") as u64;
    let libname_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("LdrLoadDll: error reading lib name") as u64;
    let libaddr_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("LdrLoadDll: error reading lib base") as u64;

    let libname = emu.maps.read_wide_string(libname_ptr);
    let path = emu.maps.read_wide_string(path_to_file_ptr);

    log::info!(
        "{}** {} ntdll!LdrLoadDll_gul   lib: {} {} ->{:x} {}",
        emu.colors.light_red,
        emu.pos,
        libname,
        path,
        libaddr_ptr,
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

        if !emu.maps.write_dword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll!LdrLoadDll: cannot write in addr param");
        }
    } /*else {
          emu.maps.write_dword(libaddr_ptr, 0x77570000); // ntdll by default
      }*/

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    /*
     undo prolog implemented on guloader
        mov   esp, ebp
        pop   ebp
    */

    emu.regs.set_esp(emu.regs.get_ebp());
    let ebp = emu.stack_pop32(false).unwrap() as u64;
    emu.regs.set_ebp(ebp);

    emu.regs.rax = constants::STATUS_SUCCESS;

    emu.maps.write_dword(emu.regs.get_ebp() + 0x168, 0x77570000);
    emu.regs.rip = 0x682e5e2;
}

fn RtlVectoredExceptionHandler(emu: &mut emu::Emu) {
    let p1 = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll_RtlVectoredExceptionHandler: error reading p1") as u64;
    let fptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll_RtlVectoredExceptionHandler: error reading fptr") as u64;

    log::info!(
        "{}** {} ntdll!RtlVectoredExceptionHandler  {} callback: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        p1,
        fptr,
        emu.colors.nc
    );

    emu.veh = fptr;

    emu.regs.rax = 0x2c2878;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn NtGetContextThread(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll_NtGetContextThread: error reading stack") as u64;
    let ctx_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll_NtGetContextThread: error reading context pointer") as u64;
    let ctx_ptr2 = emu
        .maps
        .read_dword(ctx_ptr)
        .expect("ntdll_NtGetContextThread: error reading context ptr") as u64;

    log::info!(
        "{}** {} ntdll_NtGetContextThread   ctx  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let ctx = Context32::new(&emu.regs);
    ctx.save(ctx_ptr2 as u32, &mut emu.maps);

    emu.regs.rax = 0;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn RtlExitUserThread(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ntdll!RtlExitUserThread   {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    Console::spawn_console(emu);
    std::process::exit(1);
}

fn sscanf(emu: &mut emu::Emu) {
    let buffer_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!sscanf error reading out buffer paramter") as u64;
    let fmt_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!sscanf error reading format parameter") as u64;
    let list = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!sscanf error reading list parameter");

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

    let b = buffer.as_str();
    let p1: String;

    let params = scan_fmt_some!(b, &rust_fmt, i32);

    //let params = scanf!(b, format!("{}", rust_fmt)).unwrap();

    unimplemented!("sscanf is unimplemented for now.");
    //log::info!("sscanf not implemented for now");
    //Console::spawn_console(emu);
}

fn NtGetTickCount(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ntdll!NtGetTickCount {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    emu.regs.rax = emu.tick as u64;
}

fn NtQueryPerformanceCounter(emu: &mut emu::Emu) {
    let perf_counter_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!NtQueryPerformanceCounter error reading perf_counter_ptr")
        as u64;
    let perf_freq_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp() + 4)
            .expect("ntdll!NtQueryPerformanceCounter error reading perf_freq_ptr") as u64;

    log::info!(
        "{}** {} ntdll!NtQueryPerformanceCounter {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_dword(perf_counter_ptr, 0);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlGetProcessHeaps(emu: &mut emu::Emu) {
    /*
    let count = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlGetProcessHeaps error reading count param");
    let hndl = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!RtlGetProcessHeaps error reading handle param");
    */
    log::info!(
        "{}** {} ntdll!RtlGetProcessHeaps {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1; // number of handlers
}

struct CurDir {
    DosPath: String, // unicode
    Handle: u64,
}

fn RtlDosPathNameToNtPathName_U(emu: &mut emu::Emu) {
    let dos_path_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlDosPathNameToNtPathName_U error reading dos_path_name_ptr param")
        as u64;
    let nt_path_name_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!RtlDosPathNameToNtPathName_U error reading nt_path_name_ptr param")
        as u64;
    let nt_file_name_part_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!RtlDosPathNameToNtPathName_U error reading nt_file_name_part_ptr param");
    let curdir_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ntdll!RtlDosPathNameToNtPathName_U error reading curdir_ptr param")
        as u64; // DirectoryInfo

    let dos_path_name = emu.maps.read_wide_string(dos_path_name_ptr);

    log::info!(
        "{}** {} ntdll!RtlDosPathNameToNtPathName_U {} {}",
        emu.colors.light_red,
        emu.pos,
        dos_path_name,
        emu.colors.nc
    );

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
                    emu.maps
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

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn NtCreateFile(emu: &mut emu::Emu) {
    let out_handle_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("ntdll!NtCreateFile error reading out_handle_ptr param") as u64;
    let access_mask = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!NtCreateFile error reading access_mask param");
    let oattrib = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!NtCreateFile error reading oattrib param") as u64;
    let iostat = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ntdll!NtCreateFile error reading iostat param");
    let alloc_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("ntdll!NtCrea   teFile error reading alloc_sz param");
    let fattrib = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("ntdll!NtCreateFile error reading fattrib param");
    let share_access = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("ntdll!NtCreateFile error reading share_access param");
    let create_disp = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
        .expect("ntdll!NtCreateFile error reading create_disp param");
    let create_opt = emu
        .maps
        .read_dword(emu.regs.get_esp() + 32)
        .expect("ntdll!NtCreateFile error reading create_opt param");
    let ea_buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 36)
        .expect("ntdll!NtCreateFile error reading ea_buff param");
    let ea_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 40)
        .expect("ntdll!NtCreateFile error reading ea_len param");

    /*
       [out]          PHANDLE            FileHandle,
       [in]           ACCESS_MASK        DesiredAccess,
       [in]           POBJECT_ATTRIBUTES ObjectAttributes,
       [out]          PIO_STATUS_BLOCK   IoStatusBlock,
       [in, optional] PLARGE_INTEGER     AllocationSize,
       [in]           ULONG              FileAttributes,
       [in]           ULONG              ShareAccess,
       [in]           ULONG              CreateDisposition,
       [in]           ULONG              CreateOptions,
       [in]           PVOID              EaBuffer,
       [in]           ULONG              EaLength


       typedef struct _OBJECT_ATTRIBUTES {
           ULONG           Length;
           HANDLE          RootDirectory;
           PUNICODE_STRING ObjectName;
           ULONG           Attributes;
           PVOID           SecurityDescriptor;
           PVOID           SecurityQualityOfService;
         } OBJECT_ATTRIBUTES;

    */

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

    if out_handle_ptr > 0 {
        emu.maps
            .write_dword(out_handle_ptr, helper::handler_create(&filename) as u32);
    }

    for _ in 0..11 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlFreeHeap(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlFreeHeap error reading handle param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!RtlFreeHeap error reading flags param");
    let base_addr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!RtlFreeHeap error reading base_addr param") as u64;

    log::info!(
        "{}** {} ntdll!RtlFreeHeap 0x{} {}",
        emu.colors.light_red,
        emu.pos,
        base_addr,
        emu.colors.nc
    );

    helper::handler_close(handle);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

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
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!NtQueryInformationFile error reading handle param") as u64;
    let stat = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!NtQueryInformationFile error reading stat param");
    let fileinfo = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!NtQueryInformationFile error reading fileinfo param");
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ntdll!NtQueryInformationFile error reading len param");
    let fileinfocls = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("ntdll!NtQueryInformationFile error reading fileinfocls param");

    log::info!(
        "{}** {} ntdll!NtQueryInformationFile {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlAllocateHeap(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlAllocateHeap error reading handle param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!RtlAllocateHeap error reading handle param");
    let size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!RtlAllocateHeap error reading handle param") as u64;

    let base = emu
        .maps
        .alloc(size)
        .expect("ntdll!RtlAllocateHeap out of memory");
    emu.maps
        .create_map(format!("alloc_{:x}", base).as_str(), base, size)
        .expect("ntdll!RtlAllocateHeap cannot create map");

    log::info!(
        "{}** {} ntdll!RtlAllocateHeap sz: {} addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        size,
        base,
        emu.colors.nc
    );

    emu.regs.rax = base;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}

fn NtReadFile(emu: &mut emu::Emu) {
    let file_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!NtReadFile error reading file_hndl param") as u64;
    let ev_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!NtReadFile error reading ev_hndl param") as u64;
    let apc_rout = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!NtReadFile error reading apc_rout param");
    let apc_ctx = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ntdll!NtReadFile error reading apc_ctx param");
    let stat = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("ntdll!NtReadFile error reading stat param");
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("ntdll!NtReadFile error reading buff param") as u64;
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("ntdll!NtReadFile error reading len param") as usize;
    let off = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
        .expect("ntdll!NtReadFile error reading off param");
    let key = emu
        .maps
        .read_dword(emu.regs.get_esp() + 32)
        .expect("ntdll!NtReadFile error reading key param");

    /*
          [in]           HANDLE           FileHandle,
          [in, optional] HANDLE           Event,
          [in, optional] PIO_APC_ROUTINE  ApcRoutine,
          [in, optional] PVOID            ApcContext,
          [out]          PIO_STATUS_BLOCK IoStatusBlock,
          [out]          PVOID            Buffer,
          [in]           ULONG            Length,
          [in, optional] PLARGE_INTEGER   ByteOffset,
          [in, optional] PULONG           Key
    */

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

    for _ in 0..9 {
        emu.stack_pop32(false);
    }

    emu.maps.memset(buff, 0x90, len);

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn NtClose(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!NtClose error reading hndl param") as u64;

    let uri = helper::handler_get_uri(hndl);

    log::info!(
        "{}** {} ntdll!NtClose hndl: 0x{:x} uri: {} {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        uri,
        emu.colors.nc
    );

    emu.stack_pop32(false);

    if uri.is_empty() {
        emu.regs.rax = constants::STATUS_INVALID_HANDLE;
    } else {
        emu.regs.rax = constants::STATUS_SUCCESS;
    }
}

fn RtlInitializeCriticalSectionAndSpinCount(emu: &mut emu::Emu) {
    let crit_sect = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlInitializeCriticalSectionAndSpinCount error reading crit_sect param");
    let spin_count = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!RtlInitializeCriticalSectionAndSpinCount error reading spin_count param");

    log::info!(
        "{}** {} ntdll!RtlInitializeCriticalSectionAndSpinCount {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn NtProtectVirtualMemory(emu: &mut emu::Emu) {
    let sz = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!NtProtectVirtualMemory error reading sz param") as u64;
    let status = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!NtProtectVirtualMemory error reading status param") as u64;
    let page_number =
        emu.maps
            .read_dword(emu.regs.get_esp() + 8)
            .expect("ntdll!NtProtectVirtualMemory error reading page_number param") as u64;
    let page = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("ntdll!NtProtectVirtualMemory error reading page param") as u64;
    let old_prot_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp() + 16)
            .expect("ntdll!NtProtectVirtualMemory error reading old prot param") as u64;

    log::info!(
        "{}** {} ntdll!NtProtectVirtualMemory sz: {} {}",
        emu.colors.light_red,
        emu.pos,
        sz,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn CheckRemoteDebuggerPresent(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll! CheckRemoteDebuggerPresenterror reading hndl param") as u64;
    let bool_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp() + 4)
            .expect("ntdll!CheckRemoteDebuggerPresent reading bool ptr param") as u64;

    log::info!(
        "{}** {} ntdll!CheckRemoteDebuggerPresent  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.maps.write_dword(bool_ptr, 0);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1;
}

fn RtlEnterCriticalSection(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlEnterCriticalSection error reading hndl param") as u64;

    log::info!(
        "{}** {} ntdll!RtlEnterCriticalSection {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn RtlLeaveCriticalSection(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlLeaveCriticalSection error reading hndl param") as u64;

    log::info!(
        "{}** {} ntdll!RtlLeaveCriticalSection {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn RtlGetVersion(emu: &mut emu::Emu) {
    let versioninfo_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlLeaveCriticalSection error reading versioninfo_ptr param")
        as u64;

    log::info!(
        "{}** {} ntdll!RtlGetVersion {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    let versioninfo = structures::OsVersionInfo::new();
    versioninfo.save(versioninfo_ptr, &mut emu.maps);

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn RtlInitializeCriticalSectionEx(emu: &mut emu::Emu) {
    let crit_sect_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlInitializeCriticalSectionEx error reading crit_sect_ptr")
        as u64;
    let spin_count = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!RtlInitializeCriticalSectionEx error reading spin_count");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!RtlInitializeCriticalSectionEx error reading flags");

    log::info!(
        "{}** {} ntdll!RtlInitializeCriticalSectionEx {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn memset(emu: &mut emu::Emu) {
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!memset error reading ptr") as u64;
    let byte = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!memset error reading byte");
    let count = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!memset error reading count");

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

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = ptr;
}

fn RtlSetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let filter =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("ntdll!RtlSetUnhandledExceptionFilter error reading filter") as u64;

    log::info!(
        "{}** {} ntdll!RtlSetUnhandledExceptionFilter filter: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        filter,
        emu.colors.nc
    );

    emu.feh = filter;
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn strlen(emu: &mut emu::Emu) {
    let s_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!strlen error reading string pointer") as u64;

    let s = emu.maps.read_string(s_ptr);
    let l = s.len();

    log::info!(
        "{}** {} ntdll!strlen: `{}` {} {}",
        emu.colors.light_red,
        emu.pos,
        s,
        l,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = l as u32 as u64;
}

fn VerSetConditionMask(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} ntdll!strlen: {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0xffff;
}

fn strcat(emu: &mut emu::Emu) {
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!strcat error reading dst") as u64;
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!strcat error reading src") as u64;

    let dst = emu.maps.read_string(dst_ptr);
    let src = emu.maps.read_string(src_ptr);

    log::info!(
        "{}** {} ntdll!strcat: `{}`+`{}` {}",
        emu.colors.light_red,
        emu.pos,
        src,
        dst,
        emu.colors.nc
    );

    let dst_cont_ptr = dst_ptr + dst.len() as u64;
    emu.maps.write_string(dst_cont_ptr, &src);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = dst_cont_ptr;
}

fn memcpy(emu: &mut emu::Emu) {
    let dst_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("ntdll!strcat error reading dst") as u64;
    let src_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("ntdll!strcat error reading src") as u64;
    let count = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("ntdll!strcat error reading src") as usize;

    log::info!(
        "{}** {} ntdll!memcpy: 0x{:x} <- 0x{:x} {} {}",
        emu.colors.light_red,
        emu.pos,
        dst_ptr,
        src_ptr,
        count,
        emu.colors.nc
    );

    emu.maps.memcpy(dst_ptr, src_ptr, count);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}
