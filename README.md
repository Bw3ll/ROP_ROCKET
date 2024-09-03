# Introducing the ROP ROCKET
This new, advanced ROP framework made it debute at at DEF CON 31 with some unprecedented capabilities. ROCKET generates several types of chains, and it provides new patterns or techniques.

Please note that this is still a work in progress, with some updated and enhanced capabilities to be added. Updates should be regular. If you encounter issues, please put them on issues or email me with them, and I will get them sorted. Additional, alternate ways of generating certain types of gadgets will also be added.

Work is ongoing with new capabilities regularly added at present. Please check back on a regular basis.

![image](https://raw.githubusercontent.com/Bw3ll/ROP_ROCKET/main/rop%20rocket_screenshots/logo2024_90324.png?raw=true)

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

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot2.png?raw=true)

*ROCKET has generated a **Heaven's Gate x86-to-x64 attack**, printing it to screen and saving it.*

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot3.png?raw=true)

*ROCKET has generated a **Windows Syscall for NtProtectVirtualMemory** for Win 10/11, printing it to screen and saving it.*


![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/captureESP.png?raw=true)

*Thanks to its internal emulation capabilities, ROCKET can consider many unusual combinations of gadgets. The above is intended to capture a stack pointer (ESP), and move it to ECX. It is able to find alternative means of doing so, rather than just using a single ROP gadget, which may not be available. First it moves esp to edi; edi is then moved to ebx; and ebx is then moved to esi. ECX is set to zero, via integer overflow, and then the value of esi (containing our stack pointer) is added to ecx. The result is that the stack pointer is in ecx. An equivalent, shorter gadget would be **mov ecx, esp # ret** - though such is not always possible. ROCKET also correctly handles the extra pop instructions, producing the correct filler. Note that ROP ROCKET carefully considers registers that must be protected ("excluded registers"), which can change from gadget to gadget. In the above example, no registers are "clobbered" that we are attempting to protect.*


![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot4.png?raw=true)

*ROCKET provides many options for what and how you capture gadgets. Defaults can be set in the **config.cfg** file of course. Here the user decides the only want to examine chunks of memory with a maximum of 0xa (15) bytes.*

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot5.png?raw=true)

*Not only can you print individual ROP chains, but you can print all gadgets found, organized by category, such as **mov edx**. There are hundreds of possibilities. You can also refine results by changing number of lines per gadget.*

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot6.png?raw=true)

*When printing results, there are many options for different types of filters to apply to exclude gadgets, such as ASLR, CFG, Windows system DLLs, or just simple bad bytes. This is all **highly customizable**.*

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot7.png?raw=true)

*Sometimes you need to **obfuscate a certain gadget** that might prove unavailable otherwise, due to bad bytes in the gadget address. We have many options for this, and you can exclude based on registers used or bad bytes as well.*

![image](https://github.com/Bw3ll/ROP_ROCKET/blob/main/rop%20rocket_screenshots/screenshot8.png?raw=true)
*Here the user used obfuscation to dynamically decode at runtime the address for a **xor eax, edi # ret**, which hypothetically he could not use otherwise. Once decoded, the **push r32 / ret** causes this to be immediately executed. This is a great way to use gadgets otherwise unavailable due to bad bytes. ROCKET completes this in seconds. Its ability to do this with integer overflow is all but guaranteed to work, assuming no issues with bad bytes or lack of availble registers (i.e. the user excluded too many registers).*

# Acknowledgement

Shiva Shashank Kusuma works for Dr. Bramwell Brizendine as a graduate student to develop patterns for shellcodeless attacks. He has done great work, and he was also a co-speaker at DEFCON.

# Updates
09/18/2023 - Various enhancements; further support for variant ways of leaking the far jump that leads to the Windows syscall.

3/2024 - Many important updates on a somewhat regular basis - please try to keep the most current copy if possible, if you intend to actively use ROP ROCKET. Individual changes will not be listed. Minor changes and updates are likely to be ongoing. Only major new features will be described. (Some minor new featurs have already been added.)
Late March -April 3, 2024 - Extensive updates to emulation to improve and enhance efficiency; support for many more possibility options for individual gadgets to be generated; correction of bugs; **new release of VirtualAlloc and VirtualProtect** via pushad. While other tools have provided support for VirtualProtect and VirtualAlloc before, which is why we did not, we now feel it would be remiss not to include these, especially as these can be enhanced by the tool's capabilities. Created full templates for VirtualAlloc and VirtualProtect via pushad, that also includes shellcode (pop a calc).

5/2024 - Massive revamping of Windows syscalls to greatly expand what can be found with real-world binaries. Even lengthy, undesirable gadgets that leak the FS register (needed for doing Windows syscalls in SysWow64, i.e. 32-bit) can be worked with in automated fashion. Numerous other minor enhancements.
