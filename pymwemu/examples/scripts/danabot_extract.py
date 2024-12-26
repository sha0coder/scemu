import pymwemu

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('mw/dbmm_unpacked.dll')
emu.disable_ctrlc()
emu.set_verbose(3)



def dword2ip(dword):
    byte1 = (dword >> 24) & 0xff
    byte2 = (dword >> 16) & 0xff
    byte3 = (dword >> 8) & 0xff
    byte4 = dword & 0xff
    ip_address = "{}.{}.{}.{}".format(byte1, byte2, byte3, byte4)
    return ip_address


cfg = emu.alloc("static_config", 1024)


emu.set_reg('ebx', cfg)
for addr in emu.search_spaced_bytes_in_all("C7 43 18 40 7E 05 00"):
    #emu.disassemble(addr, 10)
    emu.set_reg('eip', addr)
    for i in range(9):
        emu.step()
    print('command and control hosts:')
    print(dword2ip(emu.read_dword(cfg+0x6a)))
    print(dword2ip(emu.read_dword(cfg+0x72)))
    print(dword2ip(emu.read_dword(cfg+0x7a)))
    print(dword2ip(emu.read_dword(cfg+0x82)))

