import pymwemu
import sys

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('mw/xl_unpacked.bin')

buff = emu.alloc("struct_buff", 1024)
try:
    emu.memset(buff, 0, 1024)  # non necessary allocator fill with zeros
    emu.write_spaced_bytes(buff, "41 41 41 41 42 42 42 42 A1 A1 A1 A1 B2 B2 B2 B2")
except:
    sys.exit(1)


xloader_dexor = 0x3C8B97
key = 0x11223344

emu.set_verbose(3)
#emu.spawn_console_at_pos(6)
ptr = emu.call32(xloader_dexor, [buff, key])

emu.dump_n(buff, 100)


