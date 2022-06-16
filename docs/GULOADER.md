# GuLoader PIC malware (shellcode)

ScEmu is emulating 78,574,913,778 instructions bypassing multiple tricks.

It start with typical api search algorithms with several loops inside eachother.

Then there is a huge loop 

## Vectored Exception Handler

It programs a veh and triggers multiple times with int3.
At the end of the veh routine, a cleanup is triggered that restores the contect which 
has been modified by the malware altering the execution flow in this way.

Thats not a problem for scemu.

## Cpuid

At the begining there is a loop from 1 to 0x6e as an input of Cpuid.
not all this inputs are implemented on the Cpuid instruction implementation, but it seems
it continues well the execution.

## Memory Scan

It scans memory with ntdll!NtQueryVirtualMemory in a huge loop and exit the loop on address 0x7fffe000
its about one day to emulate that loop arriving to the instruction number 78,574,913,778

But the loop can be bypassed, hit Ctrl-C to spawn console and modify a register.

```
Ctrl-C detected, spawning console
--- console ---
=>rc
register name=>esi
value=>0x7fffe000
=>c

** 8146980 ntdll_NtGetContextThread   ctx  
** 8147073 ntdll!NtQueryVirtualMemory addr: 0x2e000 
/!\ int 3 sigtrap!!!!
/!\ int 3 sigtrap!!!!
```

# Anti-emulation loop


And here an anti-emulation with many iterations.
```
  do
  {
    v2 = 0;
    *(_DWORD *)(a1 + 248) = 11100000;
    do
    {
      result = do_cpuid_1();
      v2 += v4;
      --*(_DWORD *)(a1 + 248);
    }
    while ( *(_DWORD *)(a1 + 248) );
    *(_DWORD *)(a1 + 440) = a2;
    a2 = *(_DWORD *)(a1 + 440);
  }
  while ( v2 >= 15000000 );
  return result;
}
```


for now we have to identify it and manually force to break the loops.



       cmp: 0x0 == 0x0
606735301156 0x3cd372: mov   edx,[ebp+22Eh]
606735301157 0x3cd378: jle   003CD288h taken 
606735301158 0x3cd288: call  003CD555h
606735301159 0x3cd555: lfence
606735301160 0x3cd558: rdtsc
606735301161 0x3cd55a: lfence
606735301162 0x3cd55d: shl   edx,20h
606735301163 0x3cd560: or    edx,eax
606735301164 0x3cd562: ret
606735301165 0x3cd28d: mov   esi,edx
606735301166 0x3cd28f: pushad
606735301167 0x3cd290: mov   eax,0B5F29654h
606735301168 0x3cd295: add   eax,606717A2h
606735301169 0x3cd29a: sub   eax,26B6051Ch
606735301170 0x3cd29f: xor   eax,0EFA3A8DBh
606735301171 0x3cd2a4: cpuid
        input value: 0x1
606735301172 0x3cd2a6: bt    ecx,1Fh
606735301173 0x3cd2aa: jb    003CDD9Fh not taken 
606735301174 0x3cd2b0: popad
606735301175 0x3cd2b1: call  003CD555h
606735301176 0x3cd555: lfence
606735301177 0x3cd558: rdtsc
606735301178 0x3cd55a: lfence
606735301179 0x3cd55d: shl   edx,20h
606735301180 0x3cd560: or    edx,eax
606735301181 0x3cd562: ret
606735301182 0x3cd2b6: sub   edx,esi
606735301183 0x3cd2b8: mov   [ebp+22Eh],edx
606735301184 0x3cd2be: mov   edx,0C82AF9F2h
606735301185 0x3cd2c3: jmp   short 003CD2F9h
606735301186 0x3cd2f9: test  bh,bh
606735301187 0x3cd2fb: xor   edx,61AD7248h
606735301188 0x3cd301: xor   edx,2A7FD332h
606735301189 0x3cd307: jmp   short 003CD361h
606735301190 0x3cd361: cmp   cx,bx
        cmp: 0x86a0 > 0xbb8
606735301191 0x3cd364: add   edx,7C07A778h
606735301192 0x3cd36a: test  bl,cl
606735301193 0x3cd36c: cmp   [ebp+22Eh],edx
        cmp: 0x0 == 0x0
606735301194 0x3cd372: mov   edx,[ebp+22Eh]
606735301195 0x3cd378: jle   003CD288h taken 
606735301196 0x3cd288: call  003CD555h
606735301197 0x3cd555: lfence
606735301198 0x3cd558: rdtsc
606735301199 0x3cd55a: lfence
606735301200 0x3cd55d: shl   edx,20h
606735301201 0x3cd560: or    edx,eax
606735301202 0x3cd562: ret
606735301203 0x3cd28d: mov   esi,edx
606735301204 0x3cd28f: pushad
606735301205 0x3cd290: mov   eax,0B5F29654h
606735301206 0x3cd295: add   eax,606717A2h
606735301207 0x3cd29a: sub   eax,26B6051Ch
606735301208 0x3cd29f: xor   eax,0EFA3A8DBh
606735301209 0x3cd2a4: cpuid
        input value: 0x1
606735301210 0x3cd2a6: bt    ecx,1Fh
606735301211 0x3cd2aa: jb    003CDD9Fh not taken 
606735301212 0x3cd2b0: popad
606735301213 0x3cd2b1: call  003CD555h
606735301214 0x3cd555: lfence
606735301215 0x3cd558: rdtsc
606735301216 0x3cd55a: lfence
606735301217 0x3cd55d: shl   edx,20h
606735301218 0x3cd560: or    edx,eax
606735301219 0x3cd562: ret
606735301220 0x3cd2b6: sub   edx,esi
606735301221 0x3cd2b8: mov   [ebp+22Eh],edx
606735301222 0x3cd2be: mov   edx,0C82AF9F2h
606735301223 0x3cd2c3: jmp   short 003CD2F9h
606735301224 0x3cd2f9: test  bh,bh
606735301225 0x3cd2fb: xor   edx,61AD7248h
606735301226 0x3cd301: xor   edx,2A7FD332h
606735301227 0x3cd307: jmp   short 003CD361h
606735301228 0x3cd361: cmp   cx,bx
        cmp: 0x86a0 > 0xbb8
606735301229 0x3cd364: add   edx,7C07A778h
606735301230 0x3cd36a: test  bl,cl
606735301231 0x3cd36c: cmp   [ebp+22Eh],edx
        cmp: 0x0 == 0x0
606735301232 0x3cd372: mov   edx,[ebp+22Eh]
606735301233 0x3cd378: jle   003CD288h taken 
606735301234 0x3cd288: call  003CD555h
606735301235 0x3cd555: lfence
606735301236 0x3cd558: rdtsc
606735301237 0x3cd55a: lfence
606735301238 0x3cd55d: shl   edx,20h
606735301239 0x3cd560: or    edx,eax
606735301240 0x3cd562: ret
606735301241 0x3cd28d: mov   esi,edx
606735301242 0x3cd28f: pushad
606735301243 0x3cd290: mov   eax,0B5F29654h
606735301244 0x3cd295: add   eax,606717A2h
606735301245 0x3cd29a: sub   eax,26B6051Ch
606735301246 0x3cd29f: xor   eax,0EFA3A8DBh
606735301247 0x3cd2a4: cpuid
        input value: 0x1
606735301248 0x3cd2a6: bt    ecx,1Fh
606735301249 0x3cd2aa: jb    003CDD9Fh not taken 
606735301250 0x3cd2b0: popad
606735301251 0x3cd2b1: call  003CD555h
606735301252 0x3cd555: lfence
606735301253 0x3cd558: rdtsc
606735301254 0x3cd55a: lfence
606735301255 0x3cd55d: shl   edx,20h
606735301256 0x3cd560: or    edx,eax
606735301257 0x3cd562: ret
606735301258 0x3cd2b6: sub   edx,esi
606735301259 0x3cd2b8: mov   [ebp+22Eh],edx
606735301260 0x3cd2be: mov   edx,0C82AF9F2h
^C606735301261 0x3cd2c3: jmp   short 003CD2F9h
606735301262 0x3cd2f9: test  bh,bh
606735301263 0x3cd2fb: xor   edx,61AD7248h
606735301264 0x3cd301: xor   edx,2A7FD332h
606735301265 0x3cd307: jmp   short 003CD361h
606735301266 0x3cd361: cmp   cx,bx
        cmp: 0x86a0 > 0xbb8
606735301267 0x3cd364: add   edx,7C07A778h
606735301268 0x3cd36a: test  bl,cl
606735301269 0x3cd36c: cmp   [ebp+22Eh],edx
        cmp: 0x0 == 0x0
606735301270 0x3cd372: mov   edx,[ebp+22Eh]
606735301271 0x3cd378: jle   003CD288h taken 
606735301272 0x3cd288: call  003CD555h
606735301273 0x3cd555: lfence
606735301274 0x3cd558: rdtsc
606735301275 0x3cd55a: lfence
606735301276 0x3cd55d: shl   edx,20h
606735301277 0x3cd560: or    edx,eax
Ctrl-C detected, spawning console
606735301278 0x3cd562: ret


