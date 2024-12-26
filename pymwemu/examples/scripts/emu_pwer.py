import pymwemu
import sys


emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')

# dont load the pe, its tricked to crash the loader
# instead read it to an buffer inside the emulator:
x = open('pwer','rb').read()
code_buffer = emu.alloc("code", len(x))
emu.write_bytes(code_buffer, x)

# starting point
pattern = b'\xd9\xcc\xd9\x74\x24\xf4\x58' # fpu

# locating starting point
off = x.find(pattern)
if off < 0:
    print('pattern not found')
    sys.exit(1)

# go go go
emu.set_reg('eip', code_buffer + off)
emu.run()




