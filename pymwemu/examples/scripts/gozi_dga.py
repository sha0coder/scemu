import pymwemu
import random 

emu = pymwemu.init64()
emu.load_maps('/home/sha0/src/mwemu/maps64/')
emu.set_base_address(0x280000000)
emu.load_binary('gozi10008.bin')
emu.set_verbose(0)

gozi_dga = 0x2800046A8 # function
size = 10
seed = 0x246640bb

# write seed global
emu.write_dword(0x280052D40, seed)


for i in range(0,100):
    rax = emu.call64(gozi_dga, [size])
    print(emu.read_string(rax))



