
# Arguments 


## Select shellcode 

The unique required parameter is the shellcode `-f` or `--file`.

```
target/release/scemu -f path/shellcode.bin
```

But it will try to locate the maps files in "maps/" if the maps are not there see "Memory maps" chapter.


## Memory maps

scemu looks for the memory maps folder in "maps/"  but also can be configured with `-M` or `--maps` 

The maps are TEB and PEB and other structures, and also memory headers and library code mapped in different memory maps.

Use the console m command to see the memory maps.

## Verbose

Without verbose only the Windows API and Linux syscalls are shown in red.

One level of verbosity `-v` shows messages, like "/!\ polymorfic code" or "/!\ poping a code address" etc.

Two level of verbosity `-vv` shows also the assembly code, this mode is cool but not showing the asm is even faster.

## Console

Every line start with an identificator of the emulation moment. We can stop in a specific moment and spawn a console to inspect or edit the emulator status using the flag `-c num` for example to stop in the emulation step 1000 `-c 1000`

It's like a debugger, but with the difference that the code is not executed, it's emulated which is safer, ideal for analyzing malware.

More information about the console in [CONSOLE.md](CONSOLE.md)

Also it's possible to spawn the console at specific address with `-C addr`

## 64bits

The 64bits engine is not 100% ready, but you can emulate some instructions, use the `-6` or `--64bits` to emulate 64bits shellcodes.

## Registers

Its possible to display all the registers in every step with `-r` or `--regs` often used together with `-vv`.

```
22325 0x3c0078: add       edi,eax
        eax: 0x72 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4536 edi: 0xc17800e2
22326 0x3c007a: cmp       al,ah
        cmp: 0x72 > 0x0
        eax: 0x72 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4536 edi: 0xc17800e2
22327 0x3c007c: jne       short 003C0072h taken 
        eax: 0x72 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4536 edi: 0xc17800e2
22328 0x3c0072: xor       eax,eax
        eax: 0x0 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4536 edi: 0xc17800e2
22329 0x3c0074: ror       edi,0Dh
        eax: 0x0 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4536 edi: 0x7160bc0
22330 0x3c0077: lodsb
        eax: 0x0 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4537 edi: 0x7160bc0
22331 0x3c0078: add       edi,eax
        eax: 0x0 ebx: 0x775a80d0 ecx: 0x6b7 edx: 0x77570000 esi: 0x775b4537 edi: 0x7160bc0
```


But more detail is provided if you specify a register ie `--reg esi`

This allow to do a tracing of what is going on or guessing for what is used every register.

```
54351 esi: 0x775b31cc 2002465228 'ZwCreatePor' (ntdll_text)
54352 esi: 0x775b31cc 2002465228 'ZwCreatePor' (ntdll_text)
54353 esi: 0x775b31cc 2002465228 'ZwCreatePor' (ntdll_text)
54354 esi: 0x431a3 274851
54355 esi: 0x775b31a3 2002465187 'ZwCreateNamedPipeFil' (ntdll_text)
54356 esi: 0x775b31a3 2002465187 'ZwCreateNamedPipeFil' (ntdll_text)
54357 esi: 0x775b31a3 2002465187 'ZwCreateNamedPipeFil' (ntdll_text)
54358 esi: 0x775b31a3 2002465187 'ZwCreateNamedPipeFil' (ntdll_text)
54359 esi: 0x775b31a4 2002465188 'wCreateNamedPipeFil' (ntdll_text)
54360 esi: 0x775b31a4 2002465188 'wCreateNamedPipeFil' (ntdll_text)
54361 esi: 0x775b31a4 2002465188 'wCreateNamedPipeFil' (ntdll_text)
54362 esi: 0x775b31a4 2002465188 'wCreateNamedPipeFil' (ntdll_text)
54363 esi: 0x775b31a4 2002465188 'wCreateNamedPipeFil' (ntdll_text)
54364 esi: 0x775b31a4 2002465188 'wCreateNamedPipeFil' (ntdll_text)
54365 esi: 0x775b31a5 2002465189 'CreateNamedPipeFil' (ntdll_text)
54366 esi: 0x775b31a5 2002465189 'CreateNamedPipeFil' (ntdll_text)
54367 esi: 0x775b31a5 2002465189 'CreateNamedPipeFil' (ntdll_text)
54368 esi: 0x775b31a5 2002465189 'CreateNamedPipeFil' (ntdll_text)
```


## Memory

Sometimes could be strategic to trace the memory usage. The argument `-m` will trace all memory operations both read and write, specifying if its a 32bits, 16 bits or 8 bits operation, address, content and the memory map. 

```
1677856 mem trace read 32 bits ->  0x22de44: 0xe0df0fea  map:'stack'
1677861 mem trace read 32 bits ->  0x775a971c: 0x42e14  map:'ntdll_text'
1678032 mem trace read 32 bits ->  0x22de18: 0x3e9a174f  map:'stack'
1678033 mem trace read 32 bits ->  0x22de44: 0xe0df0fea  map:'stack'
1678038 mem trace read 32 bits ->  0x775a9718: 0x42dfc  map:'ntdll_text'
1678185 mem trace read 32 bits ->  0x22de18: 0x3e9a174f  map:'stack'
1678186 mem trace read 32 bits ->  0x22de44: 0xe0df0fea  map:'stack'
1678191 mem trace read 32 bits ->  0x775a9714: 0x42de0  map:'ntdll_text'
1678362 mem trace read 32 bits ->  0x22de18: 0x3e9a174f  map:'stack'
1678363 mem trace read 32 bits ->  0x22de44: 0xe0df0fea  map:'stack'
1678368 mem trace read 32 bits ->  0x775a9710: 0x42dc8  map:'ntdll_text'
1678515 mem trace read 32 bits ->  0x22de18: 0x3e9a174f  map:'stack'
1678516 mem trace read 32 bits ->  0x22de44: 0xe0df0fea  map:'stack'
1678521 mem trace read 32 bits ->  0x775a970c: 0x42dac  map:'ntdll_text'
1678692 mem trace read 32 bits ->  0x22de18: 0x3e9a174f  map:'stack'
1678693 mem trace read 32 bits ->  0x22de44: 0xe0df0fea  map:'stack'
```

Its also possible to inspect memory with `-i` or `--inspect` providing a more complex argument like `-i 'dword ptr [esi + 0xa]'`

```
dword ptr [esi] (0x775b3339): 0x41677562 1097299298 'bugActiveProcess' {62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 }
dword ptr [esi] (0x775b3339): 0x41677562 1097299298 'bugActiveProcess' {62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 }
dword ptr [esi] (0x775b3339): 0x41677562 1097299298 'bugActiveProcess' {62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 }
dword ptr [esi] (0x775b3339): 0x41677562 1097299298 'bugActiveProcess' {62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 }
dword ptr [esi] (0x775b3339): 0x41677562 1097299298 'bugActiveProcess' {62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 }
dword ptr [esi] (0x775b3339): 0x41677562 1097299298 'bugActiveProcess' {62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 }
dword ptr [esi] (0x775b333a): 0x63416775 1665230709 'ugActiveProcess' {75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 00 }
dword ptr [esi] (0x775b333a): 0x63416775 1665230709 'ugActiveProcess' {75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 00 }
dword ptr [esi] (0x775b333a): 0x63416775 1665230709 'ugActiveProcess' {75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 00 }
dword ptr [esi] (0x775b333a): 0x63416775 1665230709 'ugActiveProcess' {75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 00 }
dword ptr [esi] (0x775b333a): 0x63416775 1665230709 'ugActiveProcess' {75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 00 }
dword ptr [esi] (0x775b333a): 0x63416775 1665230709 'ugActiveProcess' {75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 00 }
```

## No-Color

If your purpose is to log to file the output, is better disable the colorized mode with option `-n`

## Endpoint

Use this option only if you know what you are doing.
The option `-e` or `--endpoint` perform communications with the command & controls to retrieve data useful to continue the emulation.
Use VPN or Tor to protect your IP if the endpoing is not trusted.

The endpoint mode is like a Man In The Middle proxy between the API calls and the C&C, it support socket communications in windows and linux and also wininet.

## Entry Point and Base address

By default the entrypoint is the first instruction in the binary blob provided with `-f shellcode.bin` but its possible to specify a different entry point with `-a addr`

For avoiding having to rebase the IDA/Ghidra/Rdare to have a common base with this tool, its possible to set an address with `-b addr` but make sure this address is not already mapped.

If you select a base you have to select also the entry point for exmaple `-b 0x4c000000 -e 0x4c000000`

## Greppable output

The tool can be used with grep to filter the output, for example for see only the calls or the branches.

To analyze the logic of the algorithm you can use this filter:

```bash
target/release/scemu -f shellcode.bin -vv | egrep '(j|cmp|test)'
```

Or for correlating the ghidra/ida/radare functions with scemu use a call filter.

```bash
target/release/scemu -f shellcode.bin -vv | grep 'call'
```

