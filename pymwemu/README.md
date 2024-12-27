# PYMWEMU

## Examples

https://github.com/sha0coder/mwemu/tree/main/pymwemu/examples

## Documentation

https://github.com/sha0coder/mwemu/blob/main/pymwemu/DOCUMENTATION.md

## Gpt Assistant

https://chat.openai.com/g/g-sfrh5tzEM-pymwemu-helper

## Install
```bash
pip install --upgrade pip
pip3 install --upgrade pip
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
pip install pymwemu
pip3 install pymwemu
```

## Mac Install
same procedure, if there is a problem with !tapi-tbd the solution is:
```bash
sudo xcode-select --switch /Library/Developer/CommandLineTools
```

## Download maps
download maps32 from releases or maps64 better from git:
https://github.com/sha0coder/mwemu



## Usage

### Fully emulation of a shellcode

```python
~ ❯❯❯ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pymwemu
>>> emu = pymwemu.init32()
>>> emu.load_maps('/home/sha0/src/mwemu/maps32/')
initializing regs
loading memory maps
Loaded nsi.dll
	4 sections  base addr 0x776c0000
	created pe32 map for section `.text` at 0x776c1000 size: 5624
	created pe32 map for section `.data` at 0x776c3000 size: 16
	created pe32 map for section `.rsrc` at 0x776c4000 size: 1008
/!\ warning: raw sz:8704 off:8192 sz:512  off+sz:8704
	created pe32 map for section `.reloc` at 0x776c5000 size: 88
>>> 
>>> emu.load_binary('/home/sha0/src/mwemu/shellcodes32/shikata.bin')
shellcode detected.
>>> emu.set_verbose(0)   # by default already 0
>>> emu.disable_console() # by default already disabled
>>> emu.run()   # 
 ----- emulation -----
** 333368 kernel32!LoadLibraryA  'ws2_32' =0x77480000 
** 1618021 ws2_32!WsaStartup 
** 2902832 ws2_32!WsaSocketA 
** 4180546 ws2_32!connect  family: 2 192.168.1.38:1337 
** 5456468 ws2_32!recv   buff: 0x22de64 sz: 4 
** 5736281 kernel32!VirtualAlloc sz: 256 addr: 0x164 
** 7012203 ws2_32!recv   buff: 0x164 sz: 256 
redirecting code flow to non maped address 0x264

>>> help(emu.run)
Help on built-in function run:

run(end_addr) method of builtins.Emu instance
    start emulating the binary until reach the provided end_addr. 
    Use run() with no param for emulating forever.
```


### Loading Danabot PE

```python
>>> emu.load_binary('/home/sha0/samples/danabot/2023-04-03-MainModule/unpacked2/dbmm_unpacked.dll')
PE32 header detected.
IAT binding started ...
Loaded /home/sha0/src/mwemu/maps32/version.dll
	5 sections  base addr 0x52180000
	created pe32 map for section `.text` at 0x52181000 size: 10431
	created pe32 map for section `.data` at 0x52184000 size: 872
	created pe32 map for section `.idata` at 0x52185000 size: 3176
	created pe32 map for section `.rsrc` at 0x52186000 size: 1064
	created pe32 map for section `.reloc` at 0x52187000 size: 820
Loaded /home/sha0/src/mwemu/maps32/mpr.dll
	6 sections  base addr 0x4b680000
	created pe32 map for section `.text` at 0x4b681000 size: 71344
	created pe32 map for section `.data` at 0x4b693000 size: 1260
	created pe32 map for section `.idata` at 0x4b694000 size: 4228
	created pe32 map for section `.didat` at 0x4b696000 size: 80
	created pe32 map for section `.rsrc` at 0x4b697000 size: 1296
	created pe32 map for section `.reloc` at 0x4b698000 size: 3856
Loaded /home/sha0/src/mwemu/maps32/netapi32.dll
	4 sections  base addr 0x40ac0000
	created pe32 map for section `.text` at 0x40ac1000 size: 51905
	created pe32 map for section `.data` at 0x40ace000 size: 992
	created pe32 map for section `.rsrc` at 0x40acf000 size: 1016
/!\ warning: raw sz:56832 off:55808 sz:1024  off+sz:56832
	created pe32 map for section `.reloc` at 0x40ad0000 size: 908
Loaded /home/sha0/src/mwemu/maps32/shell32.dll
	4 sections  base addr 0x73800000
	created pe32 map for section `.text` at 0x73801000 size: 3966180
	created pe32 map for section `.data` at 0x73bca000 size: 26872
	created pe32 map for section `.rsrc` at 0x73bd1000 size: 8670296
/!\ warning: raw sz:12872192 off:12660736 sz:211456  off+sz:12872192
	created pe32 map for section `.reloc` at 0x74416000 size: 211060
Loaded /home/sha0/src/mwemu/maps32/esent.dll
	7 sections  base addr 0x10000000
	created pe32 map for section `.text` at 0x10001000 size: 2573914
	created pe32 map for section `.data` at 0x10276000 size: 22056
	created pe32 map for section `.idata` at 0x1027c000 size: 7442
	created pe32 map for section `.didat` at 0x1027e000 size: 44
	created pe32 map for section `cachelin` at 0x1027f000 size: 1824
	created pe32 map for section `.rsrc` at 0x10280000 size: 1360
/!\ warning: raw sz:2712064 off:2597376 sz:114688  off+sz:2712064
	created pe32 map for section `.reloc` at 0x10281000 size: 114200
Loaded /home/sha0/src/mwemu/maps32/iphlpapi.dll
	4 sections  base addr 0x40c90000
	created pe32 map for section `.text` at 0x40c91000 size: 96173
	created pe32 map for section `.data` at 0x40ca9000 size: 1936
	created pe32 map for section `.rsrc` at 0x40caa000 size: 1288
/!\ warning: raw sz:103936 off:101376 sz:2560  off+sz:103936
	created pe32 map for section `.reloc` at 0x40cab000 size: 2372
Loaded /home/sha0/src/mwemu/maps32/winspool.drv.dll
	6 sections  base addr 0x4cc80000
	created pe32 map for section `.text` at 0x4cc81000 size: 328345
	created pe32 map for section `.data` at 0x4ccd2000 size: 4972
	created pe32 map for section `.idata` at 0x4ccd4000 size: 8628
	created pe32 map for section `.didat` at 0x4ccd7000 size: 548
	created pe32 map for section `.rsrc` at 0x4ccd8000 size: 88632
/!\ warning: raw sz:449536 off:430080 sz:19456  off+sz:449536
	created pe32 map for section `.reloc` at 0x4ccee000 size: 19448
Loaded /home/sha0/src/mwemu/maps32/netapi32.dll
	4 sections  base addr 0x40ac0000
	created pe32 map for section `.text` at 0x40ac1000 size: 51905
	created pe32 map for section `.data` at 0x40ace000 size: 992
	created pe32 map for section `.rsrc` at 0x40acf000 size: 1016
/!\ warning: raw sz:56832 off:55808 sz:1024  off+sz:56832
	created pe32 map for section `.reloc` at 0x40ad0000 size: 908
Loaded /home/sha0/src/mwemu/maps32/rasapi32.dll
	6 sections  base addr 0x10000000
	created pe32 map for section `.text` at 0x10001000 size: 812208
	created pe32 map for section `.data` at 0x100c8000 size: 5692
	created pe32 map for section `.idata` at 0x100ca000 size: 9484
	created pe32 map for section `.didat` at 0x100cd000 size: 524
	created pe32 map for section `.rsrc` at 0x100ce000 size: 1296
/!\ warning: raw sz:875008 off:826880 sz:48128  off+sz:875008
	created pe32 map for section `.reloc` at 0x100cf000 size: 47656
Loaded /home/sha0/src/mwemu/maps32/shell32.dll
	4 sections  base addr 0x73800000
	created pe32 map for section `.text` at 0x73801000 size: 3966180
	created pe32 map for section `.data` at 0x73bca000 size: 26872
	created pe32 map for section `.rsrc` at 0x73bd1000 size: 8670296
/!\ warning: raw sz:12872192 off:12660736 sz:211456  off+sz:12872192
	created pe32 map for section `.reloc` at 0x74416000 size: 211060
Loaded /home/sha0/src/mwemu/maps32/pstorec.dll
	5 sections  base addr 0x5a800000
	created pe32 map for section `.text` at 0x5a801000 size: 1105
	created pe32 map for section `.data` at 0x5a802000 size: 804
	created pe32 map for section `.idata` at 0x5a803000 size: 480
	created pe32 map for section `.rsrc` at 0x5a804000 size: 9936
/!\ warning: raw sz:14336 off:13824 sz:512  off+sz:14336
	created pe32 map for section `.reloc` at 0x5a807000 size: 44
Loaded /home/sha0/src/mwemu/maps32/rasapi32.dll
	6 sections  base addr 0x10000000
	created pe32 map for section `.text` at 0x10001000 size: 812208
	created pe32 map for section `.data` at 0x100c8000 size: 5692
	created pe32 map for section `.idata` at 0x100ca000 size: 9484
	created pe32 map for section `.didat` at 0x100cd000 size: 524
	created pe32 map for section `.rsrc` at 0x100ce000 size: 1296
/!\ warning: raw sz:875008 off:826880 sz:48128  off+sz:875008
	created pe32 map for section `.reloc` at 0x100cf000 size: 47656
IAT Bound.
Loaded /home/sha0/samples/danabot/2023-04-03-MainModule/unpacked2/dbmm_unpacked.dll
	10 sections  base addr 0x1e70000
	created pe32 map for section `.text` at 0x1e71000 size: 31920128
	entry point at 0x22f7968  0x487968 
	created pe32 map for section `.itext` at 0x22f6000 size: 36659200
	created pe32 map for section `.data` at 0x22f8000 size: 36667392
	created pe32 map for section `.bss` at 0x236f000 size: 37154816
	created pe32 map for section `.idata` at 0x2489000 size: 38309888
	created pe32 map for section `.didata` at 0x248e000 size: 38330368
	created pe32 map for section `.edata` at 0x248f000 size: 38334464
	created pe32 map for section `.rdata` at 0x2490000 size: 38338560
	created pe32 map for section `.reloc` at 0x2491000 size: 38342656
/!\ warning: raw sz:372658176 off:334061568 sz:38596608  off+sz:372658176
	created pe32 map for section `.rsrc` at 0x24cd000 size: 38596608

```

### calling xloader keygen function with 1 params.

```python

>>> hex(emu.get_reg('eip'))
'0x22f7968'

>>> struct_ptr = 0x03DB000   # somewhere, evrithing is writable.
>>> xloader_key1_keygen = 0x03DB687

>>> eax = emu.call32(xloader_key1_keygen, [struct_ptr])

>>> rc4_key = emu.read_string_of_bytes(struct_ptr+1980, 20)
>>> rc4_key
'03 00 00 6a 02 51 ff d2 80 3b 00 74 4e 8b 4d 14 6a 08 89 8e '

```

other way to do the call:

```python
>>> struct_ptr = 0x03DB000
>>> xloader_key1_keygen = 0x03DB687
>>> old_eip = emu.set_reg('eip', xloader_key1_keygen)
>>> ret_addr = old_eip
>>> emu.stack_push32(struct_ptr)
True
>>> emu.stack_push32(ret_addr)
True
>>> emu.run(ret_addr)  # point ret_addr to some mapped place and run until ret_addr
```


### Spawn console by address or by position.

```python
>>> emu.spawn_console_at_pos(6)
>>> emu.set_verbose(3)
>>> emu.run(0)
shellcode detected.
1 0x3c8b97: push  ebp ;0x22f000 
2 0x3c8b97: push  ebp ;0x22f000 
3 0x3c8b98: mov   ebp,esp
4 0x3c8b9a: mov   ecx,[ebp+0Ch]
5 0x3c8b9d: mov   eax,[ebp+8]
-------
6 0x3c8ba0: xor   [eax],ecx
--- console ---
=>r eax
	eax: 0x3c0000 3932160 (code)
=>r ecx
	ecx: 0x464 1124 'AAAABBBB' (struct_buff)
=>
```


