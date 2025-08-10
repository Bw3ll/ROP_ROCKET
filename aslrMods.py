aslrMod = {
    "InInitalizationModuleListNTDLL": {
        "targetModList": "InInitalizationModuleList",
        "targetDLL": "NTDLL",
        "pebLDROffset": 0x18,
        "reachModList": 0x30,
        "getBaseAddress": 0x10,
        "numDereferences": 1,
    },
    "InInitalizationModuleListKernel32": {
        "targetModList": "InInitalizationModuleList",
        "targetDLL": "Kernel32",
        "pebLDROffset": 0x18,
        "reachModList": 0x30,
        "getBaseAddress": 0x10,
        "numDereferences": 3,
    },
    "InInitalizationModuleListKernelbase": {
        "targetModList": "InInitalizationModuleList",
        "targetDLL": "Kernelbase",
        "pebLDROffset": 0x18,
        "reachModList": 0x30,
        "getBaseAddress": 0x10,
        "numDereferences": 2,
    },
    "InLoadOrderModuleListNTDLL": {
        "targetModList": "InLoadOrderModuleList",
        "targetDLL": "NTDLL",
        "pebLDROffset": 0x18,
        "reachModList": 0x10,
        "getBaseAddress": 0x30,
        "numDereferences": 2,
    },
    "InLoadOrderModuleListKernel32": {
        "targetModList": "InLoadOrderModuleList",
        "targetDLL": "Kernel32",
        "pebLDROffset": 0x18,
        "reachModList": 0x10,
        "getBaseAddress": 0x30,
        "numDereferences": 3,
    },
    "InLoadOrderModuleListKernelbase": {
        "targetModList": "InLoadOrderModuleList",
        "targetDLL": "Kernelbase",
        "pebLDROffset": 0x18,
        "reachModList": 0x10,
        "getBaseAddress": 0x30,
        "numDereferences": 4,
    },
    "InMemoryOrderModuleListNTDLL": {
        "targetModList": "InMemoryOrderModuleList",
        "targetDLL": "NTDLL",
        "pebLDROffset": 0x18,
        "reachModList": 0x20,
        "getBaseAddress": 0x20,
        "numDereferences": 2,
    },
    "InMemoryOrderModuleListKernel32": {
        "targetModList": "InMemoryOrderModuleList",
        "targetDLL": "Kernel32",
        "pebLDROffset": 0x18,
        "reachModList": 0x20,
        "getBaseAddress": 0x20,
        "numDereferences": 3,
    },
    "InMemoryOrderModuleListKernelbase": {
        "targetModList": "InMemoryOrderModuleList",
        "targetDLL": "Kernelbase",
        "pebLDROffset": 0x18,
        "reachModList": 0x20,
        "getBaseAddress": 0x20,
        "numDereferences": 4,
    },
}


inMem="InMemoryOrderModuleListKernelbase"
inLoad="InLoadOrderModuleListKernel32"
inInit= "InInitalizationModuleListKernel32"
modLists=[inMem,inLoad, inInit]

entry = aslrMod[inMem]
base_offset = entry["getBaseAddress"]
print (hex(base_offset))
