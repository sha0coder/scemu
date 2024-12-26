# TODO


- ldr update on LoadLibrary
- implement pe64
- optimize GetProcAddress storing in the handler the lib name

- support vmprotect 

- set all flags
- list breakpoints
- clear breakpoint bug
- md accept registers
- md memory check the string filter
- mr mw options can crash the console
- fix instruction breakpoint 
- more 64bits apis
- in self.execption() put a message self.exception(msg)
- improve seh command
- better api implementations
- winhttp
- implement a basic decompiler in rust.
- remove expect() on implemented instructions, just break;
- stack\_push and stack\_pop assumes the stack is in the memory map stack
- step over
- more fpu and xmm
- on WriteProcessMemory/recv save the payload written to disk
- remove non printable bytes from strings
- randomize initial register for avoid targeted anti-amulation
- support guloader
- scripting
- intead of panic spawn console
- set the code base addr
- on every set\_eip of a non branch dump stack to log file
- other rep instruction preffix
- check pf flag bug
- save state to disk and continue
- command to exit the bucle or to see  next instruction
- optimize loop counter


- the string change non printables for spaces instead of points:
```
=>r rax
        rax: 0x3c0037 3932215 'LoadLibraryA    ws2_32.dl' (code)
=>s
0x22dfdc: 0xc () ''
0x22dfe4: 0x3c0037 (code) 'LoadLibraryA....ws2_32.dll'
```

