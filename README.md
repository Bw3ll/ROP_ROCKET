This new, advanced ROP framwork made it debute at at DEF CON 31 with some unprecedented capabilities. ROCKET generates several types of chains, and it provides new patterns or techniques.

Please note that this is still a work in progress, with some updated and enhanced capabilities to be added. Updates should be frequent in the next couple months. If you encounter issues, please put them on issues or email me with them, and I will get them sorted. Additional, alternate ways of generating certain types of gadgets will also be added in the coming weeks.

# Capabilities
ROP ROCKET is very powerful with some unique capabilities, which includes the following:
- It can generate Windows syscalls for NtAllocateVirtualMemory and NtAllocateVirtualProtect - this is the first known usage of direct Windows syscalls in WoW64 ROP.
- It can generate a novel Heaven's Gate attack to transition from x86 to x64 via ROP. To work with this, you will need to use WinDbg x64 and attach to a currently running process (do not open it directly in the debugger).
- It can generate a novel Heaven's Gate attack to transition from x64 to x86 via ROP. This is 64-bit code.
- It can generate shellcodeless ROP attacks for LoadLibrary / GetProcAddress / System and LoadLibrary/ GetProcAddress. Several others are under development for future release. The idea with "shellcodeless" ROP is to avoid bypassing DEP and to just invoke shellcode-like functionality directly. 
- It internally utilizes emulation of ROP chains - which it may also do recursively - to determine distances to certain pointers used as parameters, such as a pointer to a string or structure. Without this, automatic chain generation likely would be infeasible.
- It utilizes emulation of individual ROP gadgets to widen the attack surface. (This is not fully deployed on all yet.)
- This allows for gadgets to be used regardless of bad bytes in the gadget address. For instance, if you need a pushad but there are bad bytes in the address, we can encode it and decode it at runtime, executing it via push r32 /ret. (See obfuscation options.) Several types of obfuscation are provided, including a very robust integer overflow that likely will not fail, assuming there are gadgets available. (If you exclude all \x00 and every gadget has those, there is nothing that can be done.) Registers can be excluded as well, preventing "clobbering."
- Very Robust exclusion criteria - exclude based off of CFG, ASLR, Windows dlls, bad bytes, etc.
- Some other new and unique features are planned as well.

# Install Instructions

## Setup
This should be installed as a local package. There is a setup.py file. In order to do this, just go to the directory and enter the following command:
`py -m pip install -e ./` Depending on your Python installation, you may need to vary that slightly. If you go view installed packages, you should see ROP-ROCKET appear: `py -m pip list` It is belelived that all required dependencies are included, but if you encounter any issues - due to the newness of this release, just open an issue, and we will look into it.


