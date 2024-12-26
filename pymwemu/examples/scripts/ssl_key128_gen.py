'''
    ssl 1024*4 harcoded blob xored with 4 bytes generating 128 bytes.
'''


import pymwemu

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32')
emu.load_binary('mw/dbmm_unpacked.dll')
emu.set_verbose(0)
#emu.enable_banzai_mode()

gen = emu.alloc("generated", 128)
seed = emu.alloc("seed", 100)


ssl_key128_gen = 0x020EDE54

emu.write_spaced_bytes(seed, "00 00 00 00")
for try_seed in range(0xffffffff):
    emu.reset_pos()
    print(f'seed: {hex(try_seed)}')
    emu.write_dword(seed, try_seed)
    emu.call32(ssl_key128_gen, [seed, gen])
    emu.dump_n(gen, 128)
    #key = emu.read_bytes(gen, 128)
    #print(key.hex())
    pos = emu.get_position()
    print(f'{pos} instructions emulated.')
    print('---')

