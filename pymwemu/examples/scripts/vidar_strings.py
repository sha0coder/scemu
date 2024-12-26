import pymwemu
emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32')
emu.load_binary('mw/vidar_557_unpacked.bin')

#emu.call32(0x00B01253,[])

decrypted = []
emu.set_reg('eip', 0x00B01253)
while emu.step():
    if emu.get_prev_mnemonic().startswith('ret'):
        ptr = emu.get_reg('eax')
        dec = emu.read_string(ptr)
        decrypted.append(dec)
    if emu.get_reg('eip') == 0x0B0408E:
        break



print('\n'.join(decrypted))


pos = emu.get_position()
print(f"emulated instructions: {pos}")



