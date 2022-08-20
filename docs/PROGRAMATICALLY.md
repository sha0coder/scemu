# Using SCEMU programatically

just modify the main and implement your custom emulation.

# normal usage

The main instatiates emu module, set the config, loads the binary and run.


```rust
    let mut emu = Emu::new();
    
    emu.set_config(cfg);
    emu.init();
    emu.load_code(&filename.to_string());

    emu.run(0);
```

in run method we can specify a stop address, when emulator reach this address will end the run function.
So we can do multiple runs.

but run(0) means forever.

# calling a specific function

```rust

    let mut emu = Emu::new();
    
    emu.set_config(cfg);
    emu.init();
    emu.load_code(&filename.to_string());
    emu.disable_ctrlc();
    
    // alloc a buffer needed to generate the key
    let buff = emu.alloc("key_buffer", 1024);

    // set eip
    emu.regs.set_eip(my_crypto_function_address);  // or emu.regs.rip = my_function_address   in 64bits

    // params pushed in reverse order
    emu.stack_push32(length);
    emu.stack_push32(buff);
    emu.stack_push32(seed);
    emu.stack_push32(0); // return address 

    emu.run(ret_address); // stop on latest ret, dont emulate it that will jump to zero.

    // show the buffer in the screen
    emu.maps.dump(buff);

    // you can spawn the console if needed
    emu.spawn_console();
```

you can build a program that decrypt stuff by emulating malwares's decryption functions.

