use crate::emu;
use crate::emu::winapi32::helper;
use crate::emu::context64::Context64;
use crate::emu::structures;
use crate::emu::constants;


pub fn gateway(addr:u64, emu:&mut emu::Emu) {
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
        _ => panic!("calling unimplemented ntdll API 0x{:x}", addr),
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
    */

    let addr_ptr = emu.regs.rcx;
    let size_ptr = emu.regs.rdx;

    let addr = emu.maps.read_qword(addr_ptr).expect("bad NtAllocateVirtualMemory address parameter") as u64;
    let size = emu.maps.read_qword(size_ptr).expect("bad NtAllocateVirtualMemory size parameter") as u64;
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

    println!("{}** {} ntdll!NtAllocateVirtualMemory  addr: 0x{:x} sz: {} alloc: 0x{:x} {}", emu.colors.light_red, 
             emu.pos, addr, size, alloc_addr, emu.colors.nc);

    let alloc = emu.maps.create_map(format!("valloc_{:x}", alloc_addr).as_str());
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

fn stricmp(emu:&mut emu::Emu) {
    let str1ptr = emu.regs.rcx;
    let str2ptr = emu.regs.rdx;
    let str1 = emu.maps.read_string(str1ptr);
    let str2 = emu.maps.read_string(str2ptr);

    println!("{}** {} ntdll!stricmp  '{}'=='{}'? {}", emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc);

    if str1 == str2 {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = 1;
    }
}

fn NtQueryVirtualMemory(emu:&mut emu::Emu) {
    let handle = emu.regs.rcx;
    let addr = emu.regs.rdx;

    println!("{}** {} ntdll!NtQueryVirtualMemory addr: 0x{:x} {}", emu.colors.light_red, emu.pos, addr, emu.colors.nc);

    if handle != 0xffffffff {
        println!("\tusing handle of remote process {:x}", handle);

        if !helper::handler_exist(handle) {
            println!("\nhandler doesnt exist.");
        }
    }

    let out_meminfo_ptr = emu.regs.r9;

    if !emu.maps.is_mapped(addr) {
        println!("/!\\ ntdll!NtQueryVirtualMemory: querying non maped addr: 0x{:x}", addr);
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


fn LdrLoadDll(emu:&mut emu::Emu) {
    // NTSTATUS NTAPI DECLSPEC_HOTPATCH 	LdrLoadDll (
    //      IN PWSTR SearchPath OPTIONAL, 
    //      IN PULONG DllCharacteristics OPTIONAL, 
    //      IN PUNICODE_STRING DllName, 
    //      OUT PVOID *BaseAddress)
    
    let libname_ptr = emu.regs.r8;
    let libaddr_ptr = emu.regs.r9;

    let libname = emu.maps.read_wide_string(libname_ptr);
    println!("{}** {} ntdll!LdrLoadDll   lib: {} {}", emu.colors.light_red, emu.pos, libname, emu.colors.nc);

    
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

fn RtlAddVectoredExceptionHandler(emu:&mut emu::Emu) {
    let p1 = emu.regs.rcx;
    let fptr = emu.regs.rdx;

    println!("{}** {} ntdll!RtlAddVectoredExceptionHandler  {} callback: 0x{:x} {}", emu.colors.light_red, emu.pos, p1, 
             fptr, emu.colors.nc);

    emu.veh = fptr;
    emu.regs.rax = 0x2c2878;
}

fn RtlRemoveVectoredExceptionHandler(emu:&mut emu::Emu) {
    let p1 = emu.regs.rcx;
    let fptr = emu.regs.rdx;

    println!("{}** {} ntdll!RtlRemoveVectoredExceptionHandler  {} callback: 0x{:x} {}", emu.colors.light_red, emu.pos, p1, 
             fptr, emu.colors.nc);

    emu.veh = 0;
    emu.regs.rax = 0;
}

fn NtGetContextThread(emu:&mut emu::Emu) {
    let handle = emu.regs.rcx;
    let ctx_ptr = emu.regs.rdx;
    let ctx_ptr2 = emu.maps.read_qword(ctx_ptr).expect("ntdll_NtGetContextThread: error reading context ptr");
    
    println!("{}** {} ntdll_NtGetContextThread   ctx: {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    let ctx = Context64::new(&emu.regs);
    ctx.save(ctx_ptr2, &mut emu.maps);

    emu.regs.rax = 0;
}

fn RtlExitUserThread(emu:&mut emu::Emu) {
    println!("{}** {} ntdll!RtlExitUserThread   {}", emu.colors.light_red, emu.pos, emu.colors.nc);   
    std::process::exit(1);
}

fn ZwQueueApcThread(emu:&mut emu::Emu) {
    let thread_handle = emu.regs.rcx;
    let apc_routine = emu.regs.rdx;
    let apc_ctx = emu.regs.r8;
    let arg1 = emu.regs.r9;
    let arg2 = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!ZwQueueApcThread cannot read arg2");

    println!("{}** {} ntdll!ZwQueueApcThread hndl: {} routine: {} ctx: {} arg1: {} arg2: {} {}", emu.colors.light_red, emu.pos,
        thread_handle, apc_routine, apc_ctx, arg1, arg2, emu.colors.nc);

    emu.stack_pop64(false);
    emu.regs.rax = constants::STATUS_SUCCESS;
}


