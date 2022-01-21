# Console

## Spawn the console

Every line printed  starts with a number that represent an emulation moment, its possible to spawn a console a specific moment doing for example this:

```bash
target/release/scemu -f shellcode.bin -vv -c 1000
```

This is going to step 1000 instructions and then spawn the console on that moment.

## Step, Continue and Quit

Pressing `enter` the emulator perform steps into, pressing `c` it continues the emulation until a breakpoint or an exception or the end of the emulation.

To quit the console just press q

## Registers

`r` command display all the registers, but if a register name is specified more information is provided ie: `r esi`

```
=>r esi
        esi: 0x775b1244 2002457156 'Zon' (ntdll_text)
```

The info displayed is register: value in hex, value in decimal, string pointed and memory map.

To change a register press `rc` and enter, then specify the register name, enter again, and then the new value.

For changing the EIP to redirect the emulator to another place press command `eip`

## CPU Flags

Press `f` to show all the flags, and `fc` for clearing all the flags. Its possible to enable and disable the flag zero with command `fz` and toggle enable/disable sign with `fs`

## Breakpoints

Its only possible to set one breakpoint of each type, but there are several types.

type `bc` to clear the breakpoing, `ba` to set a breakpoint on address and `bi` to set a breapoing on an emulation moment id.

Its also possible to set a memory breakpoint on read `bmr` and write `bmw` 

The command `b` list the breakponts:
```
=>b
break on address: 0x3c00e4
break on instruction: 0
break on memory read: 0x0
break on memory write: 0x0
```

## Stack and Variables

press `s` to see the stack values, and press `v` to se the local variables, both are stored on a memory map named `stack`

Its possible to push values to the stack for example for preparing parameter to call another function, use `push` command or `pop` command to extract a value from the stack.

For example push params to the stack and redirect the flow to a function with `eip` command.

## FPU

Press `fpu` command to view the FPU environment.

## Memory maps

Use `m` command to see all the mapped memory maps. Its possible to create a new memory map with `mc` command:

```
=>mc 
name =>testmap
base address =>0x5f000000
```

If we have an address and we want to figure-out in which map pertain that address, use memory name `mn` command.
For Loading files to the virtual memory system use `ml`

```
=>ml
map name=>testmap
filename=>/etc/passwd
=>
```

To see the maps allocated by the shellcode use `ma` for memory allocations.

Its possible to compute the md5sum of a memory map with command `md5`

## Memory read and write

Reading specific dword, word or byte can be done with command `mr` for example:

```
=>mr
memory argument=>dword ptr [esi]
0x775b1244: 0x656e6f5a
=>
```

In same way can be written a value to the memory with `mw`:

```
=>mw
memory argument=>dword ptr [esi]
value=>0x1234
done.
=>
```

## Memory dump

It's quite useful the memory dump command `md` to see the hex bytes and printable strings.

```
=>md
address=>0x775b1244 
34 12 00 00  00 52 74 6c  52 65 73 65  74 52 74 6c  4....RtlResetRtl
54 72 61 6e  73 6c 61 74  69 6f 6e 73  00 52 74 6c  Translations.Rtl
52 65 73 74  6f 72 65 4c  61 73 74 57  69 6e 33 32  RestoreLastWin32
45 72 72 6f  72 00 52 74  6c 52 65 74  72 69 65 76  Error.RtlRetriev
65 4e 74 55  73 65 72 50  66 6e 00 52  74 6c 52 65  eNtUserPfn.RtlRe
76 65 72 74  4d 65 6d 6f  72 79 53 74  72 65 61 6d  vertMemoryStream
00 52 74 6c  52 75 6e 44  65 63 6f 64  65 55 6e 69  .RtlRunDecodeUni
63 6f 64 65  53 74 72 69  6e 67 00 52  74 6c 52 75  codeString.RtlRu
```

Also it's possible to dump to disk with `mdd` command.

If you want to dump an ascii string `mds` and wide string with `mdw`

The command `mrd` for memory read dword dumps a list of dwords. And `mrq` for read a list of qwords.


## Search 

You can search in specific map or in all the memory, `ss` search string in a map, and `sb` search a bunch of bytes hexa separated by hex

```
=>sb
map name=>code
spaced bytes=>24 f4 5f 29
found at 0x3c0009
=>
```

If you need to do a search in all the memory `sba` search bytes and `ssa` search strings.

## Linked lists

There is a tool to walk the elements of a linked list which is command `ll` 

## Dissasemble

To dissasemble from specific addres use command `d`

## SEH and VEH pointers 

The command `seh` allow to see the stack pointer where is the SEH pointers.


```
=>seh
0x1b002d
=>mr
memory argument=>dword ptr [0x1b0028]
0x1b00a7
=>mr 
memory argument=>dword ptr [0x1b002c]
0x3c0012
```

The `veh` return the vectorized exception pointer.
