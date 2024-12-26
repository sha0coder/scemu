import pymwemu

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('mw/rundll32_danabotX.dll_1650000_x86.dll')
emu.set_verbose(3)

danabot_int_obfuscation = 0x0184ED18

emu.set_reg('eax', 65833)
calc = emu.call32( danabot_int_obfuscation, [] )

print(calc)

