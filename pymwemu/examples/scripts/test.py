import pymwemu

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('mw/dbmm_unpacked.dll')
emu.set_verbose(0)
emu.set_base_address(0x1E70000)
emu.enable_banzai_mode()
danabot_init = 0x022EBBC0 


emu.disable_ctrlc()


'''
public_key_ptr = emu.alloc("pubkey", 1024)
private_key_ptr = emu.alloc("privkey", 1024)
pub_ptr = emu.alloc("pub_ptr", 4)
priv_ptr = emu.alloc("priv_ptr", 4)

emu.write_dword(pub_ptr, public_key_ptr)
emu.write_dword(priv_ptr, private_key_ptr)

emu.enable_trace_reg(['eax'])

emu.set_reg('eax', pub_ptr)
emu.set_reg('edx', priv_ptr)
'''

emu.set_reg('eax', 1)
emu.set_reg('esi', 1)
ret_addr = emu.set_reg('eip', danabot_init)
emu.run(ret_addr)


