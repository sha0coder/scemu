'''
    pymwemu is synchronous, if you need to implement an unimplemented api 
    or override an implemented api can use emu.run_until_apicall() in a loop 
'''

import pymwemu
import sys

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('/home/sha0/src/mwemu/shellcodes32/shikata.bin')



while True:
    api = emu.run_until_apicall() # stop until next apicall try
    print(f'calling api 0x{api:x}')

    if api == 0x77486b0e:
        # override recv implementation here
        esp = emu.get_reg('esp')
        ret_addr = emu.read_dword(esp)
        socket = emu.read_dword(esp+4)
        buff = emu.read_dword(esp+8)
        sz = emu.read_dword(esp+12)
        flags = emu.read_dword(esp+16)
        print(f'recv {socket} 0x{buff:x} {sz} {flags}')
        emu.write_buffer(buff, b'\x11\x22\x33\x44')
        emu.set_reg('eax', 4)
        #emu.set_eip(api)       # triger emulators api implementation
        emu.set_eip(ret_addr)   # dont trigger emulation api inmplementation
        break

    else:
        emu.set_eip(api) # trigger api implementation on emulator


