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





