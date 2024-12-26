# pymwemu

## initialization

```python
import pymwemu
emu = pymwemu.init32()
or
emu = pymwemu.init64()


    # It is necessary to load the 32bits or 64bits maps folder for having a realistic memory layout.
    # The maps can be downloaded from the https://github.com/sha0coder/mwemu
emu.load_maps(folder:str)

    # Load the binary to be emulated.
emu.load_binary(filename:str)
    # Load the bytes to be emulated.
emu.load_code_bytes(bytes:bytearray)
```

optionally is possible to change entry point and base address

```python

    # change the default entry point.
set_entry_point(addr:int)

    # rebase the program address.
set_base_address(addr:int)

```


## emulator configuration and info

```python

    # get pymwemu version.
version() -> str

    # get last emulated mnemonic with name and parameters.
get_prev_mnemonic() -> str

    # reset the instruction counter to zero.
reset_pos()

    # check if the emulator is in 64bits mode.
is_64bits() -> bool

    # check if the emulator is in 32bits mode.
is_32bits() -> bool

    # Set 64bits mode, it's necessary to load the 64bits maps with load_maps() method.
    # Or better can use: emu = pymwemu.init64()
set_64bits()

    # Set 32bits mode, it's necessary to load the 32bits maps with load_maps() method.
    # Or better can use: emu = pymwemu.init32()
set_32bits()

    # disable the colored mode for instructions, api calls and other logs.
disable_colors()

    # enable the colored mode.
enable_colors()

    # trace all memory reads and writes.
enable_trace_mem()

    # disable the memory tracer.
disable_trace_mem()

    # trace all the registers printing them in every step.
enable_trace_regs()

    # disable the register tracer.
disable_trace_regs()

    # trace a specific list of registers, provide array of strings with register names in lower case.
enable_trace_reg(regs:list)

    # disable the multi-register tracer.
disable_trace_reg()


    # inspect sequence like: inspect_seq('dword ptr [eax + 0x3c]')
inspect_seq(seq:str)

    # set the verbosity between 0 and 3.
    #     0: only show api calls.
    #     1: show api calls and some logs.
    #     2: show also instructions (slower).
    #     3: show every iteration of rep preffix.
set_verbose(verbose:int)

    # when the execution reached a specified amount of steps will spawn an interactive console.
spawn_console_at_pos(position:int)

    # when the execution reached a specified address will spawn an interactive console.
spawn_console_at_addr(addr:int)

    # disable the console spawning.
disable_spawn_console_at_pos()

    # allow to enable the console if its needed.
enable_console()

    # disable the console, to prevent to be spawned in some situations.  
disable_console()

    # enable the loops counter, this feature slows down the emulation but count the iteration number.
enable_count_loops()

    # disable the loops counting system.
disable_count_loops()

    # enable tracing a string on a specified memory address. 
enable_trace_string(addr:int)

    # disable the string tracer.
disable_trace_string()

    # inspect a memory area by providing a stirng like 'dword ptr [esp + 0x8]'
enable_inspect_sequence(seq:str)

    # disable the memory inspector.
disable_inspect_sequence()

    # give the binary the posibility of connecting remote hosts to get next stage, use it safelly.
enable_endpoint_mode()

    # disable the endpoint mode.
disable_endpoint_mode()

    # configure stack mapping address
set_stack_base(addr:int)

    # change the default entry point.
set_entry_point(addr:int)

    # rebase the program address.
set_base_address(addr:int)

    # enable the stack tracer.
enable_stack_trace()

    # disable the stack tracer.
disable_stack_trace()

    # test mode use inline assembly to contrast the result of emulation and detect bugs.
enable_test_mode()

    # disable the test mode.
disable_test_mode()

    # Enable banzai mode. This mode keep emulating after finding unimplemented instructions or apis.
enable_banzai_mode()

    # disable banzai mode.
disable_banzai_mode()

    # add unimplemented API to banzai.
banzai_add(apiname:str, nparams:int) {

    # enable the Control-C handling for spawning console.
enable_ctrlc()

    # disable the Control-C handling.
disable_ctrlc()

    # update base of an ldr entry
update_ldr_entry_base(modname:str, base:int)

    # address to api name, based on LDR lookup
api_addr_to_name(addr:int) -> str

```


### stack

```python
    # push a 32bits value to the stack.
stack_push32(value:int) -> bool

    # push a 64bits value to the stack.
stack_push64(value:int) -> bool

    # pop a 32bits value from the stack.
stack_pop32() -> int

    # pop a 64bits value from the stack.
stack_pop64() -> int
```

### registers
```python
    # read register value ie get_reg('rax')
get_reg(reg:str) -> int

    # set register value ie  set_reg('rax', 0x123), returns previous value.
set_reg(reg:str, value:int) -> int

    # get the value of a xmm register.
get_xmm(reg:str) -> int

    # set a value to a xmm register.
set_xmm(reg:str, value:int) -> int
```

### memory

```python
    # allocate a buffer on the emulated process address space. It returns an address.
alloc(map_name:str, size:int) -> int

    # allocate a buffer on the emulated process at specific space, check first to avoid collisions.
alloc_at(map_name:str, addr:int, size:int)

    # Link DLL library
link_library(filepath:str) -> int {

    # load an aditional blob to the memory layout, check first to avoid collisions.
load_map(name:str, filename:str, base_addr:int)

    # write a little endian qword on memory.
write_qword(addr:int, value:int) -> bool

    # write a little endian dword on memory.
write_dword(addr:int, value:int) -> bool

    # write a little endian word on memory.
write_word(addr:int, value:int) -> bool

    # write a byte on memory.
write_byte(addr:int, value:int) -> bool

    # write an ascii string
write_string(addr:int, s:str)

    # write a wide
write_wide_string(addr:int, s:str)

    # read 128bits big endian.
read_128bits_be(addr:int) -> int

    # read 128bits little endian.
read_128bits_le(addr:int) -> int

    # read little endian qword.
read_qword(addr:int) -> int

    # read little endian dword.
read_dword(addr:int) -> int

    # read little endian word.
read_word(addr:int) -> int

    # read a byte from a memory address.
read_byte(addr:int) -> int

    # fill a memory chunk starting at `address`, with a specified `amount` of bytes defined in `byte`.
memset(addr:int, byte:int, amount:int)

    # get the size of a wide string.
sizeof_wide(unicode_str_ptr:str) -> int

    # write a python bytes() or b'' to an emulator memory address.
write_buffer(to:addr, from:bytes)

    # read a buffer from the emulator memory to a python list of int bytes.
read_buffer(from:int, sz:int) -> list

    # print all the maps that match a substring of the keyword provided.
print_maps_by_keyword(kw:str)

    # print all the memory maps on the process address space.
print_maps()

    # get the base address of a given address. Will make an exception if it's invalid address.
get_addr_base(addr:int) -> int

    # this method checks if the given address is allocated or not.
is_mapped(addr:int) -> bool

    # get the memory map name where is the given address. 
    # Will cause an exception if the address is not allocated.
get_addr_name(addr:int) -> str

    # visualize the bytes on the given address.
dump(addr:int)

    # visualize the `amount` of bytes provided on `address`.
dump_n(addr:int, amount:int)

    # visualize a number of qwords on given address.
dump_qwords(addr:int, amount:int)

    # visualize a number of dwords on a given address.
dump_dwords(addr:int, amount:int)

    # read an amount of bytes from an address to a python object.
read_bytes(addr:int, sz:int) -> list

    # read an amount of bytes from an address to a string of spaced hexa bytes.
read_string_of_bytes(addr:int, sz:int) -> str

    # read an ascii string from a memory address, 
    # if the address point to a non allocated zone string will be empty.
read_string(addr:int) -> str

    # read a wide string from a memory address, 
    # if the address point to a non allocated zone string will be empty. 
read_wide_string(addr:int) -> str

    # search a substring on a specific memory map name, it will return a list of matched addresses.
    # if the string is not found, it will return an empty list.
search_string(kw:str, map_name:str) -> list

    # write on emulators memory a spaced hexa bytes
write_spaced_bytes(addr:int, spaced_hex_bytes:str) -> bool

    # search one occurence of a spaced hex bytes from a specific address, will return zero if it's not found.
search_spaced_bytes_from(saddr:int, sbs:str) -> int

    # search one occcurence of a spaced hex bytes from an especific address backward,
    # will return zero if it's not found.
search_spaced_bytes_from_bw(saddr:int, sbs:str) -> int

    # search spaced hex bytes string on specific map using its map name, 
    # will return a list with the addresses found if there are matches, 
    # otherwise the list will be empty.
search_spaced_bytes(sbs:str, map_name:str) -> list

    # search spaced hex bytes string on all the memory layout, 
    # will return a list with the addresses found if there are matches, 
    # otherwise the list will be empty.
search_spaced_bytes_in_all(sbs:str) -> list

    # Search a substring in all the memory layout except on libs, will print the results.
    # In the future will return a list with results instead of printing.
search_string_in_all(kw:str)

    # search a bytes object on specific map, will return a list with matched addresses if there are any.
search_bytes(bkw:list, map_name:str) -> list

    # show the total allocated memory.
allocated_size() -> int

    # show if there are memory blocks overlapping eachother.
memory_overlaps(addr:int, sz:int) -> bool

    # show all the memory blocks allocated during the emulation.
show_allocs()

    # free a memory map by its name
free(name:str)

    # basic allocator, it looks for a free block of given size,
    # it only returns the address if its possible, but dont really allocates,
    # just find the address, you have to load to that address something.
    # use alloc() method instead if possible.
memory_alloc(sz:int) -> int

    # Save all memory blocks allocated during emulation to disk.
    # Provide a folder where every alloc will be a file.
save_all_allocs(path:str)

    # save a chunk of memory to disk.
save(addr:int, size:int, filename:str)

    # perform a memory test to see overlapps or other possible problems.
mem_test() -> bool

```

### breakpoints

```python
    # show breakpoints
bp_show()

    # clear all the breakpoints
bp_clear_all()

    # set breakpoint on an address
bp_set_addr(addr:int)

    # get the current address breakpoint
bp_get_addr() -> int

    # set breakpoint on a instruction counter
bp_set_inst(ints:int)

    # get breakpoint on a instrunction counter
bp_get_inst() -> int

    # set a memory breakpoint on read
bp_set_mem_read(addr:int)

    # get the memory breakpoint on read
bp_get_mem_read() -> int

    # set a memory breakpoint on write
bp_set_mem_write(addr:int)

    # get the memory breakpoint on write
bp_get_mem_write() -> int
```


### emulation

```python
    # set rip register, if rip point to an api will be emulated.
set_rip(addr:int)

    # set eip register, if eip point to an api will be emulated.
set_eip(addr:int)

    # spawn an interactive console.  
spawn_console()

    # disassemble some instructions from an address.  
disassemble(addr:int, amount:int) -> str

    # start emulating the binary after finding the first return.
run_until_return() -> int

    # emulate a single step, this is slower than run(address) or run(0)
step() -> bool

    # start emulating the binary until reach the provided end_addr. 
    # Use run() with no params for emulating forever.
run(end_addr:int) -> int

    # read the number of instructions emulated since now.
get_position() -> int

    # call a 32bits function, internally pushes params in reverse order.
call32(addr:int, params:list) -> int

    # call a 64bits function, internally pushes params in reverse order.
call64(addr:int, params:list) -> int

    # emulate until a specific winapi is called.
run_until_winapi(winapi_name:str)

    # emulate until any winapi is called.
run_until_apicall() -> [addr, api_name]


```

### hooks 

libmwemu provide multipe hooks, but not pymwemu.
one opion is synchronous way:

```python
def GetUserNameA():
    retaddr = emu.stack_pop64()
    print('GetUserNameA')
    emu.write_string(emu.get_reg('rcx'), 'baremetal\x00')
    emu.write_qword(emu.get_reg('rdx'), 9)
    emu.set_reg('rax', emu.get_reg('rcx'))

def recv():
    retaddr = emu.stack_pop64()
    rip = emu.get_reg('rip')
    rcx = emu.get_reg('rcx')
    rdx = emu.get_reg('rdx')
    r8 = emu.get_reg('r8')
    print(f'{rip:x}: recv({rcx}, {rdx:x}, {r8})')
    emu.write_dword(rdx, 3)
    emu.set_reg('rax', 4)


emu.set_reg('rip', comm_protocol)
while True:
    addr, name = emu.run_until_apicall()
    if name == 'getusernamea':
        GetUserNameA()
    elif name =='recv':
        recv()
    else:
        emu.handle_winapi(addr)
```

