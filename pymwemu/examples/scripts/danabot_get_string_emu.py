import pymwemu
import sys

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('/home/sha0/samples/danabot/2023-04-03-Botnet3-MainModule/unpacked2/dbmm_unpacked.dll')


danabot_get_string = 0x01E7AF08

i = 0
while True:
    i += 1
    emu.set_reg('eax', i)
    s_ptr = emu.call32( danabot_get_string, [] )
    try:
        derref = emu.read_wide_string(s_ptr)
        if len(derref) > 2:
            print(f'{i} {len(derref)} {derref}')
            i += (len(derref)*2)
    except:
        pass
    

