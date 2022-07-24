use crate::emu;
use crate::emu::constants;
use crate::emu::structures;
use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;
use crate::emu::context32::Context32;

use scan_fmt::scan_fmt_some;

pub fn gateway(addr:u32, emu:&mut emu::Emu) {
    match addr {
        0x775b52d8 => NtAllocateVirtualMemory(emu),
        0x775b5a18 => NtGetContextThread(emu),
        0x7757f774 => RtlVectoredExceptionHandler(emu),
        0x775d22b8 => LdrLoadDll(emu),
        0x775b6258 => NtQueryVirtualMemory(emu),
        0x775d531f => stricmp(emu),
        0x7759f611 => RtlExitUserThread(emu),
        0x7763a4dd => sscanf(emu),
        0x7761b3de => NtGetTickCount(emu),
        0x775b6158 => NtQueryPerformanceCounter(emu),
        0x775eabd1 => RtlGetProcessHeaps(emu),
        0x775d27e0 => RtlDosPathNameToNtPathName_U(emu),
        0x775b55c8 => NtCreateFile(emu),
        0x775c2c6a => RtlFreeHeap(emu),
        0x775b6018 => NtQueryInformationFile(emu),
        0x775c2dd6 => RtlAllocateHeap(emu),
        _ => panic!("calling unimplemented ntdll API 0x{:x} {}", addr, kernel32::guess_api_name(emu, addr)),
    }
}


fn NtAllocateVirtualMemory(emu:&mut emu::Emu) {
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

    let addr_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("bad NtAllocateVirtualMemory address pointer parameter") as u64;
    let size_ptr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("bad NtAllocateVirtualMemory size pointer parameter") as u64;
    let addr = emu.maps.read_dword(addr_ptr).expect("bad NtAllocateVirtualMemory address parameter") as u64;
    let size = emu.maps.read_dword(size_ptr).expect("bad NtAllocateVirtualMemory size parameter") as u64;
    let do_alloc:bool;
    let alloc_addr:u64;

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
            None => panic!("/!\\ out of memory   cannot allocate forntdll!NtAllocateVirtualMemory "),
        };
    } else { 
        alloc_addr = addr;
    }

    println!("{}** {} ntdll!NtAllocateVirtualMemory  addr: 0x{:x} sz: {} alloc: 0x{:x} {}", emu.colors.light_red, emu.pos, addr, size, alloc_addr, emu.colors.nc);

    let alloc = emu.maps.create_map(format!("valloc_{:x}", alloc_addr).as_str());
    alloc.set_base(alloc_addr);
    alloc.set_size(size);
    //alloc.set_bottom(alloc_addr + size);

    if !emu.maps.write_dword(addr_ptr, alloc_addr as u32) {
        panic!("NtAllocateVirtualMemory: cannot write on address pointer");
    }

    emu.regs.rax = emu::constants::STATUS_SUCCESS;

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
}



fn stricmp(emu:&mut emu::Emu) {
    let str1ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("ntdll!stricmp: error reading string1") as u64;
    let str2ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("ntdll!stricmp: error reading string2") as u64;
    let str1 = emu.maps.read_string(str1ptr);
    let str2 = emu.maps.read_string(str2ptr);

    println!("{}** {} ntdll!stricmp  '{}'=='{}'? {}", emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc);

    if str1 == str2 {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = 1;
    }

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
}

fn NtQueryVirtualMemory(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp()).expect("ntdll!NtQueryVirtualMemory: error reading handle") as u64;
    let addr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("ntdll!NtQueryVirtualMemory: error reading address") as u64;

    println!("{}** {} ntdll!NtQueryVirtualMemory addr: 0x{:x} {}", emu.colors.light_red, emu.pos, addr, emu.colors.nc);

    if handle != 0xffffffff {
        println!("\tusing handle of remote process {:x}", handle);

        if !helper::handler_exist(handle) {
            println!("\nhandler doesnt exist.");
        }
    }

    let out_meminfo_ptr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("ntdll_NtQueryVirtualMemory: error reading out pointer to meminfo") as u64;

    if !emu.maps.is_mapped(addr) {
        println!("/!\\ ntdll!NtQueryVirtualMemory: querying non maped addr: 0x{:x}", addr);
        for _ in 0..6 {
            emu.stack_pop32(false);
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
   
    for _ in 0..6 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}


fn LdrLoadDll(emu:&mut emu::Emu) {
    //let libaddr_ptr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("LdrLoadDll: error reading lib ptr") as u64;
    //let libname_ptr = emu.maps.read_dword(emu.regs.get_esp()+20).expect("LdrLoadDll: error reading lib param") as u64;

    let libname_ptr = emu.maps.read_dword(emu.regs.get_esp()+8).expect("LdrLoadDll: error reading lib name") as u64;
    let libaddr_ptr = emu.maps.read_dword(emu.regs.get_esp()+12).expect("LdrLoadDll: error reading lib base") as u64;

    let libname = emu.maps.read_wide_string(libname_ptr);
    println!("{}** {} ntdll!LdrLoadDll   lib: {} {}", emu.colors.light_red, emu.pos, libname, emu.colors.nc);

    
    if libname == "user32.dll" {
        let user32 = emu.maps.create_map("user32");
        user32.set_base(0x773b0000);
        user32.load("maps32/user32.bin");
        let user32_text = emu.maps.create_map("user32_text");
        user32_text.set_base(0x773b1000);
        user32_text.load("maps32/user32_text.bin");

        if !emu.maps.write_dword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll_LdrLoadDll: cannot write in addr param");
        }
    }

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = emu::constants::STATUS_SUCCESS;
}

fn RtlVectoredExceptionHandler(emu:&mut emu::Emu) {
    let p1 = emu.maps.read_dword(emu.regs.get_esp()).expect("ntdll_RtlVectoredExceptionHandler: error reading p1") as u64;
    let fptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("ntdll_RtlVectoredExceptionHandler: error reading fptr") as u64;

    println!("{}** {} ntdll!RtlVectoredExceptionHandler  {} callback: 0x{:x} {}", emu.colors.light_red, emu.pos, p1, 
             fptr, emu.colors.nc);

    emu.veh = fptr;

    emu.regs.rax = 0x2c2878;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn NtGetContextThread(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp()).expect("ntdll_NtGetContextThread: error reading stack") as u64;
    let ctx_ptr = emu.maps.read_dword(emu.regs.get_esp()+4).expect("ntdll_NtGetContextThread: error reading context pointer") as u64;
    let ctx_ptr2 = emu.maps.read_dword(ctx_ptr).expect("ntdll_NtGetContextThread: error reading context ptr") as u64;
    
    println!("{}** {} ntdll_NtGetContextThread   ctx  {}", emu.colors.light_red, emu.pos, emu.colors.nc);


    let ctx = Context32::new(&emu.regs);
    ctx.save(ctx_ptr2 as u32, &mut emu.maps);

    emu.regs.rax = 0;
    emu.stack_pop32(false);
    emu.stack_pop32(false);
}

fn RtlExitUserThread(emu:&mut emu::Emu) {
    println!("{}** {} ntdll!RtlExitUserThread   {}", emu.colors.light_red, emu.pos, emu.colors.nc);   
    emu.spawn_console();
    std::process::exit(1);
}

fn sscanf(emu:&mut emu::Emu) {
    let buffer_ptr = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!sscanf error reading out buffer paramter") as u64;
    let fmt_ptr = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!sscanf error reading format parameter") as u64;
    let list = emu.maps.read_dword(emu.regs.get_esp()+8)
        .expect("ntdll!sscanf error reading list parameter");

    let buffer = emu.maps.read_string(buffer_ptr);
    let fmt = emu.maps.read_string(fmt_ptr);

    println!("{}** {} ntdll!sscanf out_buff: `{}` fmt: `{}` {}", emu.colors.light_red, emu.pos, buffer, fmt, emu.colors.nc);

    let rust_fmt = fmt.replace("%x","{x}").replace("%d","{}").replace("%s","{}").replace("%hu","{u16}").replace("%i","{}").replace("%o", "{o}").replace("%f","{}");

    let params = rust_fmt.matches("{").count();


    let b = buffer.as_str();
    let p1:String;


    let params = scan_fmt_some!(b, &rust_fmt, i32);

    //let params = scanf!(b, format!("{}", rust_fmt)).unwrap();

    unimplemented!("sscanf is unimplemented for now.");
    //println!("sscanf not implemented for now");
    //emu.spawn_console();
}

fn NtGetTickCount(emu:&mut emu::Emu) {
    println!("{}** {} ntdll!NtGetTickCount {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    let tick = kernel32::TICK.lock().unwrap();
    emu.regs.rax = *tick as u64;
}

fn NtQueryPerformanceCounter(emu:&mut emu::Emu) {
    let perf_counter_ptr = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!NtQueryPerformanceCounter error reading perf_counter_ptr") as u64;
    let perf_freq_ptr = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!NtQueryPerformanceCounter error reading perf_freq_ptr") as u64;
    
    println!("{}** {} ntdll!NtQueryPerformanceCounter {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.maps.write_dword(perf_counter_ptr, 0);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlGetProcessHeaps(emu:&mut emu::Emu) {
    let count = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlGetProcessHeaps error reading count param");
    let hndl = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!RtlGetProcessHeaps error reading handle param");

    println!("{}** {} ntdll!RtlGetProcessHeaps {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    emu.regs.rax = 1; // number of handlers
}

struct CurDir {
    DosPath: String, // unicode
    Handle: u64,
}

fn RtlDosPathNameToNtPathName_U(emu:&mut emu::Emu) {
   let dos_path_name_ptr = emu.maps.read_dword(emu.regs.get_esp())
       .expect("ntdll!RRtlDosPathNameToNtPathName_U error reading dos_path_name_ptr param") as u64;
   let nt_path_name_ptr = emu.maps.read_dword(emu.regs.get_esp()+4)
       .expect("ntdll!RRtlDosPathNameToNtPathName_U error reading nt_path_name_ptr param") as u64;
   let nt_file_name_part_ptr = emu.maps.read_dword(emu.regs.get_esp()+8)
       .expect("ntdll!RRtlDosPathNameToNtPathName_U error reading nt_file_name_part_ptr param");
   let curdir_ptr = emu.maps.read_dword(emu.regs.get_esp()+12)
       .expect("ntdll!RRtlDosPathNameToNtPathName_U error reading curdir_ptr param") as u64; // DirectoryInfo
    
   let dos_path_name = emu.maps.read_wide_string(dos_path_name_ptr);

   println!("{}** {} ntdll!RtlDosPathNameToNtPathName_U {} {}", emu.colors.light_red, emu.pos, dos_path_name, emu.colors.nc);

   if curdir_ptr > 0 {
       let dos_path_unicode_ptr = emu.maps.read_dword(curdir_ptr)
           .expect("ntdll!RRtlDosPathNameToNtPathName_U error reading dos_path_unicode_ptr") as u64;
        
       emu.maps.memcpy(dos_path_unicode_ptr, dos_path_name_ptr, emu.maps.sizeof_wide(dos_path_name_ptr)*2);
   }

   if nt_path_name_ptr > 0 {
       emu.maps.memcpy(nt_path_name_ptr, dos_path_name_ptr, emu.maps.sizeof_wide(dos_path_name_ptr)*2);
   }

   emu.stack_pop32(false);
   emu.stack_pop32(false);
   emu.stack_pop32(false);
   emu.stack_pop32(false);

}

fn NtCreateFile(emu:&mut emu::Emu) {
    let out_handle_ptr = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!NtCreateFile error reading out_handle_ptr param") as u64;
    let access_mask = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!NtCreateFile error reading access_mask param");
    let oattrib = emu.maps.read_dword(emu.regs.get_esp()+8)
        .expect("ntdll!NtCreateFile error reading oattrib param") as u64;
    let iostat = emu.maps.read_dword(emu.regs.get_esp()+12)
        .expect("ntdll!NtCreateFile error reading iostat param");
    let alloc_sz = emu.maps.read_dword(emu.regs.get_esp()+16)
        .expect("ntdll!NtCrea   teFile error reading alloc_sz param");
    let fattrib = emu.maps.read_dword(emu.regs.get_esp()+20)
        .expect("ntdll!NtCreateFile error reading fattrib param");
    let share_access = emu.maps.read_dword(emu.regs.get_esp()+24)
        .expect("ntdll!NtCreateFile error reading share_access param");
    let create_disp = emu.maps.read_dword(emu.regs.get_esp()+28)
        .expect("ntdll!NtCreateFile error reading create_disp param");
    let create_opt = emu.maps.read_dword(emu.regs.get_esp()+32)
        .expect("ntdll!NtCreateFile error reading create_opt param"); 
    let ea_buff = emu.maps.read_dword(emu.regs.get_esp()+36)
        .expect("ntdll!NtCreateFile error reading ea_buff param");
    let ea_len = emu.maps.read_dword(emu.regs.get_esp()+40)
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

    let obj_name_ptr = emu.maps.read_dword(oattrib + 8)
        .expect("ntdll!NtCreateFile error reading oattrib +8") as u64;
    let filename = emu.maps.read_wide_string(obj_name_ptr);

    println!("{}** {} ntdll!NtCreateFile {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);

    if out_handle_ptr > 0 {
       emu.maps.write_dword(out_handle_ptr, helper::handler_create(&filename) as u32);
    }

    for _ in 0..11 {
       emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlFreeHeap(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlFreeHeap error reading handle param") as u64;
    let flags = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!RtlFreeHeap error reading flags param");
    let base_addr = emu.maps.read_dword(emu.regs.get_esp()+8)
        .expect("ntdll!RtlFreeHeap error reading base_addr param") as u64;

    println!("{}** {} ntdll!RtlFreeHeap 0x{} {}", emu.colors.light_red, emu.pos, base_addr, emu.colors.nc);


    helper::handler_close(handle);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);


    let name = emu.maps.get_addr_name(base_addr).unwrap_or_else(|| String::new());
    if name == "" {
        println!("map not allocated, so cannot free it.");
        emu.regs.rax = 0;
        return;
    }

    emu.maps.free(&name);
    emu.regs.rax = 1;
}

fn NtQueryInformationFile(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!NtQueryInformationFile error reading handle param") as u64;
    let stat = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!NtQueryInformationFile error reading stat param");
    let fileinfo = emu.maps.read_dword(emu.regs.get_esp()+8)
        .expect("ntdll!NtQueryInformationFile error reading fileinfo param");
    let len = emu.maps.read_dword(emu.regs.get_esp()+12)
        .expect("ntdll!NtQueryInformationFile error reading len param");
    let fileinfocls = emu.maps.read_dword(emu.regs.get_esp()+16)
        .expect("ntdll!NtQueryInformationFile error reading fileinfocls param");
   
    println!("{}** {} ntdll!NtQueryInformationFile {}", emu.colors.light_red, emu.pos, emu.colors.nc);
        
    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = constants::STATUS_SUCCESS;
}

fn RtlAllocateHeap(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.get_esp())
        .expect("ntdll!RtlAllocateHeap error reading handle param") as u64;
    let flags = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("ntdll!RtlAllocateHeap error reading handle param");
    let size = emu.maps.read_dword(emu.regs.get_esp()+8)
        .expect("ntdll!RtlAllocateHeap error reading handle param") as u64;

    let base = emu.maps.alloc(size).expect("ntdll!RtlAllocateHeap out of memory");
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);

    println!("{}** {} ntdll!RtlAllocateHeap sz: {} addr: 0x{:x} {}", 
             emu.colors.light_red, emu.pos, size, base, emu.colors.nc);

    emu.regs.rax = base;

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
}



