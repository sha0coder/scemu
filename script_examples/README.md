
# use pyscemu from pip instead of this plugin scripting


```
; target/release/scemu -f ~/samples/danabot/2023-02-20/unpacked/stage2_e0000.bin -b 0xe0000 -a 0xe115c -vv -x script_examples/test.scemu 


; most of addresses and values has to be numbers like 0x123 or registers or the result varible
; except for sizes or amounts


; print the result variable
pr

; print.
p <message>    
p this is a test

; quit.
q

; show all the registers.
r

; show a register, and set it value in result variable.
r <reg>
r rax

; register change, values always in hex.
rc <reg> <value>
rc rax 0x1

; memory read, and put value in result variable.
mr <operand>
mr dword ptr [eax + 0x3]

; memory write.
mw <value> <operand>
mw 0x123 drowd ptr [eax + 0x3]
mw rsi dword ptr [eax + 0x3]

; write spaced bytes.
mwb <addr> <bytes>
mwb 0x40000000 A1 B3 C0 FF 00
mwb rax A1 B3 C0 FF 00
mwb result A1 B3 C0 FF 00

; show breakpoints 
b

; set breakpoint on address.
ba <addr>
ba 0x40000000

; set breakpoint on instruction number.
bi <num>
bi 33

; set breakpoint on memory read.
bmr <addr>
bmr 0x200000

; set breakpoint on memory write.
bmw <addr>
bmw 0x200000

; clear breakpoints.
bc

; break on next cmp.
bcmp

; clear screen.
cls

; view stack.
s

; set verbose.
sv <num>
sv 3

; trace register.
tr <reg>

; clear register trace.
trc

; continue emulation.
c

; continue emulation until next return.
cr

; print flags.
f

; clear flags.
fc

; toggle zero flag.
fz

; toggle sign flag.
sf

; create a memory map, using the automatic allocator, the variable result get the address.
mc <mapname> <size>
mc mymap 1024

; create a memory map choosing the address.
mca <mapname> <addr> <size>
mca mymap 0x120000 1024

; load a file to a map
ml <mapname> <filename>
ml mymap /tmp/file

; guess in chich map is located an address
mn <address>
mn 0x112233

; show memory maps but only the ones allocated by the malware
ma

; memory dump to see the bytes.
md <addr>
md 0x112233

; dump a number of dwords
mrd <addr> <number>
mrd 0x112233 3

; dump a number of qwords
mrq <addr> <number>
mrq 0x112233 3

; memory dump string
mds <addr>
mds 0x112233

; memody dump wide string
mdw <addr>
mdw 0x112233

; memory dump to disk
mdd <addr> <sz> <filename>
mdd 0x112233 1024 /tmp/blob.bin

; save all the maps allocated by the malware to a folder
mdda <folder>
mdda /tmp/allocs/

; do a memory test
mt

; change eip, if eip is an api will jump to it.
eip <addr>
eip 0x112233


; change rip, if rip is an api will jump to it.
rip <addr>
rip 0x1122334455


; push a value to the stack decrementing esp/rsp.
push <hexvalue>
push 0x11223344

; pop value to the result variable and print it.
pop

; show fpu state
fpu

; perform the md5sum of a map
md5 <mapname>
md5 alloc_1

; search string
ss <mapname> <string>
ss mymap hello bro

; search spaced bytes
sb <mapname> <spaced bytes>
sb mymap A1 FF 00 C3

; search spaced bytes in all the maps
sba <spaced bytes>
sba FF C3 1A 00

; search string in all the maps
ssa <string>
ssa some string

; show the SEH
seh

; show the vectorized exception pointer
veh

; crawl linkedlist
ll <addr>
ll 0x112233

; emulate next instruction
n

; print all the maps
m

; primt all maps that match a keyword
ms <keyword>
ms my

; dissasemble a block
d <addr> <sz>
d 0x1100 20

; show linked modules on LDR
ldr

; search api details by keyword
iat <keyword>
iat CreateFile

; search api details by exact api name
iatx <apiname>
iatx CreateFileA

; dump module
iatd

; show structre 
dt <structure> <address>
dt peb64 0x11020

; start conditional blocks
if <condition>
if rax == result
if rax != 0x33
if rax < 0x33

; end conditional block
endif

; spawn console
console

; call function, pushing parameters in reverse order
call <address> <params>
call 0x11233 0x33 0x22 rax result

; call with no arguments
call <address>
call 0x112233

; set a number to the result variable
set <hexnum>
set 0x3

; loop until return is zero
loop 

; end loop
endloop

; neable script tracing
trace

```
