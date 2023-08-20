# Introducing the ROP ROCKET
This new, advanced ROP framwork made it debute at at DEF CON 31 with some unprecedented capabilities. ROCKET generates several types of chains, and it provides new patterns or techniques.

Please note that this is still a work in progress, with some updated and enhanced capabilities to be added. Updates should be frequent in the next couple months. If you encounter issues, please put them on issues or email me with them, and I will get them sorted. Additional, alternate ways of generating certain types of gadgets will also be added in the coming weeks.

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot1.jpg?raw=true)

# Powerful ROP Capabilities
ROP ROCKET is very powerful with some unique capabilities, which includes the following:
- It can generate Windows syscalls for NtAllocateVirtualMemory and NtAllocateVirtualProtect - this is the first known usage of direct Windows syscalls in WoW64 ROP.
- It can generate a novel Heaven's Gate attack to transition from x86 to x64 via ROP. To work with this, you will need to use WinDbg x64 and attach to a currently running process (do not open it directly in the debugger).
- It can generate a novel Heaven's Gate attack to transition from x64 to x86 via ROP. This is 64-bit code.
- It can generate shellcodeless ROP attacks for LoadLibrary / GetProcAddress / System and LoadLibrary/ GetProcAddress. Several others are under development for future release. The idea with "shellcodeless" ROP is to avoid bypassing DEP and to just invoke shellcode-like functionality directly. 
- It internally utilizes emulation of ROP chains - which it may also do recursively - to determine distances to certain pointers used as parameters, such as a pointer to a string or structure. Without this, automatic chain generation likely would be infeasible.
- It utilizes emulation of individual ROP gadgets to widen the attack surface. (This is not fully deployed on all yet.) This can evaluate each ROP gadget to see what may or may not be cloberred, etc. Expect a lot more to happen with this.
- This allows for gadgets to be used regardless of bad bytes in the gadget address. For instance, if you need a pushad but there are bad bytes in the address, we can encode it and decode it at runtime, executing it via push r32 /ret. (See obfuscation options.) Several types of obfuscation are provided, including a very robust integer overflow that likely will not fail, assuming there are gadgets available. (If you exclude all \x00 and every gadget has those, there is nothing that can be done.) Registers can be excluded as well, preventing "clobbering."
- Alternative mov dereference "sniper" approach to VirtualProtect - for those of you that need to avoid pushad.
- Very Robust exclusion criteria - exclude based off of CFG, ASLR, Windows dlls, bad bytes, etc.
- Persistence - ROP ROCKET will extract x86 gadgets upon launch. These are saved in an .obj file, so they will remain each time you open it, allowing previously found gadgets to be instantly available. Generating new attacks should be more or less instantaneous at this point. Note: if you extract up to 0x22 bytes and then decide you want to decrease it, you will need to clear those and re-capture; saving your results is automatic.
- Config.cfg file for useful settings for some personal preferences.
- Some other new and unique features are planned as well.

# Install Instructions

## Setup
This should be installed as a local package. There is a setup.py file. In order to do this, just go to the directory and enter the following command:
`py -m pip install -e ./` Depending on your Python installation, you may need to vary that slightly. If you go view installed packages, you should see ROP-ROCKET appear: `py -m pip list` It is belelived that all required dependencies are included, but if you encounter any issues - due to the newness of this release, just open an issue, and we will look into it.

## Running the First Time
Just simply run it from the command line:`py rop2.py rop_tester_syscall.exe` A fully exploitable rop_tester_syscall.exe is included as a zip file as well. This was developed just to help make sure that all gadgets are being found and not missed.

# History
This tool was inspired by the much older [JOP ROCKET](https://github.com/Bw3ll/JOP_ROCKET/), which I wrote for part of my Ph.D. dissertation and released at DEF CON 27 in 2019. That led to a lot of further development on JOP and many new JOP capabilities, as well as providing extensive documentation on the mechancis and usage of JOP in different papers. That tool is a little outdated at the moment - it is an older style of Python. With this new research, part of this inspiration is to try and do something novel and different in the area of ROP. We have fulfilled that mandate so far. So in a way this tool is inspired by a JOP tool, allowing us to maybe try and think outside the box and in less conventional ways than we normally would with ROP.  ROP ROCKET does not have any JOP capabilities - it is strictly devoted to ROP. The only fully dedicated JOP tool is JOP ROCKET, as everything else just kind of has a placeholder for future work on JOP. Anyway, I wanted to clarify this historical information, so that the similarity in names does not confuse anyone, as these are two very different and unrelated tools.

# Screenshots
