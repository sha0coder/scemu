# scemu
x86 32bits emulator, for securely emulating shellcodes 

- rust safety, good for malware.
- rust speed, 18,750 instructions per second
- iteration detector
- colorized
- stop at sepcific moment and explore the state or modify it.
- 73 instructions implemented


Some use cases:

scemu emulates a simple shellcode detecting the execve() interrupt
![exploring basic shellcode](pics/basic_shellcode1.png)

We select the line to stop and inspect the memory
![inspecting basic shellcode](pics/basic_shellcode2.png)

After emulating near 2 million instructions of GuLoader win32 in linux, faking cpuid's and other tricks in the way, arrives to a sigtrap to confuse debuggers. 
![exception handlers](pics/guloader1.png)
