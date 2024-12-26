import pymwemu
emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32')
emu.load_binary('mw/vidar_557_unpacked.bin')

emu.call32(0x00B01253,[])
emu.show_allocs()
emu.save_all_allocs("vidar/")



pos = emu.get_position()
print(f"emulated instructions: {pos}")



