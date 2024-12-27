import pymwemu

emu = pymwemu.init64()
emu.load_maps('/Users/jesus/src/mwemu/maps64/')
emu.load_binary('surprise.dll')

emu.set_verbose(0)
emu.set_reg('rdx', 1)
emu.spawn_console_at_pos(227871000)
try:
    emu.run()
except:
    emu.spawn_console()

emu.spawn_console()
