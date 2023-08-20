from capstone import *
import re
import pefile
import sys
import binascii
import copy
#import prog
global MyBytes
global objs

OP_JMP_EAX = b"\xff\xe0"
OP_JMP_EBX = b"\xff\xe3"
OP_JMP_ECX = b"\xff\xe1"
OP_JMP_EDX = b"\xff\xe2"
OP_JMP_ESI = b"\xff\xe6"
OP_JMP_EDI = b"\xff\xe7"
OP_JMP_ESP = b"\xff\xe4"
OP_JMP_EBP = b"\xff\xe5"
OP_JMP_R8 = b"\x41\xff\xe0"
OP_JMP_R9 = b"\x41\xff\xe1"
OP_JMP_R10 = b"\x41\xff\xe2"
OP_JMP_R11 = b"\x41\xff\xe3"
OP_JMP_R12 = b"\x41\xff\xe4"
OP_JMP_R13 = b"\x41\xff\xe5"
OP_JMP_R14 = b"\x41\xff\xe6"
OP_JMP_R15 = b"\x41\xff\xe7"


dJmp = {
	"JMP_EAX": b"\xff\xe0",
	"JMP_EBX": b"\xff\xe3",
	"JMP_ECX": b"\xff\xe1",
	"JMP_EDX": b"\xff\xe2",
	"JMP_ESI": b"\xff\xe6",
	"JMP_EDI": b"\xff\xe7",
	"JMP_ESP": b"\xff\xe4",
	"JMP_EBP": b"\xff\xe5"
}

dJmpPtr = {
	"JMP_PTR_EAX": b"\xff\x20",
	"JMP_PTR_EBX": b"\xff\x23",
	"JMP_PTR_ECX": b"\xff\x21",
	"JMP_PTR_EDX": b"\xff\x22",
	"JMP_PTR_EDI": b"\xff\x27",
	"JMP_PTR_ESI": b"\xff\x26",
	"JMP_PTR_EBP": b"\xff\x65\x00",
	"JMP_PTR_ESP": b"\xff\x24\x24"
}

dCall = {
	"CALL_EAX": b"\xff\xd0",
	"CALL_EBX": b"\xff\xd3",
	"CALL_ECX": b"\xff\xd1",
	"CALL_EDX": b"\xff\xd2",
	"CALL_EDI": b"\xff\xd7",
	"CALL_ESI": b"\xff\xd6",
	"CALL_EBP": b"\xff\xd5",
	"CALL_ESP": b"\xff\xd4"
}


dCallPtr = {
	"CALL_PTR_EAX":  b"\xff\x10",
	"CALL_PTR_EBX":  b"\xff\x13",
	"CALL_PTR_ECX":  b"\xff\x11",
	"CALL_PTR_EDX":  b"\xff\x12",
	"CALL_PTR_EDI":  b"\xff\x17",
	"CALL_PTR_ESI":  b"\xff\x16",
	"CALL_PTR_EBP":  b"\xff\x55\x00",
	"CALL_PTR_ESP":  b"\xff\x14\x24"
}

#these just contain vanilla basic, 32-bit jmp and call
setOpsCall = {b"\xff\xd0",b"\xff\xd3",b"\xff\xd1",b"\xff\xd2",b"\xff\xd7",b"\xff\xd6",b"\xff\xd5",b"\xff\xd4",b"\xff\x10",b"\xff\x13",b"\xff\x11",b"\xff\x12",b"\xff\x17",b"\xff\x16",b"\xff\x55\x00",b"\xff\x14\x24"}
setOpsJmp = {b"\xff\x20",b"\xff\x23",b"\xff\x21",b"\xff\x22",b"\xff\x27",b"\xff\x26",b"\xff\x65\x00",b"\xff\x24\x24",b"\xff\xe0",b"\xff\xe3",b"\xff\xe1",b"\xff\xe2",b"\xff\xe6",b"\xff\xe7",b"\xff\xe4",b"\xff\xe5"}

#these ones are 2 ditgits only
setOpsCall2 = {b"\xff\xd0",b"\xff\xd3",b"\xff\xd1",b"\xff\xd2",b"\xff\xd7",b"\xff\xd6",b"\xff\xd5",b"\xff\xd4",b"\xff\x10",b"\xff\x13",b"\xff\x11",b"\xff\x12",b"\xff\x17",b"\xff\x16",b"\xff\x55",b"\xff\x14"}
setOpsJmp2 = {b"\xff\x20",b"\xff\x23",b"\xff\x21",b"\xff\x22",b"\xff\x27",b"\xff\x26",b"\xff\x65",b"\xff\x24",b"\xff\xe0",b"\xff\xe3",b"\xff\xe1",b"\xff\xe2",b"\xff\xe6",b"\xff\xe7",b"\xff\xe4",b"\xff\xe5"}

setOpsCF2 = {b"\xff\xd0",b"\xff\xd3",b"\xff\xd1",b"\xff\xd2",b"\xff\xd7",b"\xff\xd6",b"\xff\xd5",b"\xff\xd4",b"\xff\x10",b"\xff\x13",b"\xff\x11",b"\xff\x12",b"\xff\x17",b"\xff\x16",b"\xff\x55",b"\xff\x14",b"\xff\x20",b"\xff\x23",b"\xff\x21",b"\xff\x22",b"\xff\x27",b"\xff\x26",b"\xff\x65",b"\xff\x24",b"\xff\xe0",b"\xff\xe3",b"\xff\xe1",b"\xff\xe2",b"\xff\xe6",b"\xff\xe7",b"\xff\xe4",b"\xff\xe5"}

# setOpsJmp=set()
# setOpsCall=set()

# for p in dJmp:
# 	setOpsJmp.add(dJmp[p])
# for p in dJmpPtr:
# 	setOpsJmp.add(dJmpPtr[p])

PEB_WALK = {
	'MOV_OFFSET_NONE': b"\x64\xA1",
	'MOV_OFFSET':   b"\x64\x8B",
	'ADD_ALL':		b"\x64\x03",
	'ADC_ALL':		b"\x64\x13",
	'XOR_ALL':		b"\x64\x33",
	'OR_ALL':		b"\x64\x0B",
	'XCHG_ALL':		b"\x64\x87",
	'PUSH_ALL':		b"\x64\xFF"
}

OP_JMP_PTR_EAX = b"\xff\x20"
OP_JMP_PTR_EBX = b"\xff\x23"
OP_JMP_PTR_ECX = b"\xff\x21"
OP_JMP_PTR_EDX = b"\xff\x22"
OP_JMP_PTR_EDI = b"\xff\x27"
OP_JMP_PTR_ESI = b"\xff\x26"
OP_JMP_PTR_EBP = b"\xff\x65\x00"
OP_JMP_PTR_ESP = b"\xff\x24\x24"

OP_CALL_EAX = b"\xff\xd0"
OP_CALL_EBX = b"\xff\xd3"
OP_CALL_ECX = b"\xff\xd1"
OP_CALL_EDX = b"\xff\xd2"
OP_CALL_EDI = b"\xff\xd7"
OP_CALL_ESI = b"\xff\xd6"
OP_CALL_EBP = b"\xff\xd5"
OP_CALL_ESP = b"\xff\xd4"

OP_CALL_PTR_EAX =  b"\xff\x10"
OP_CALL_PTR_EBX =  b"\xff\x13"
OP_CALL_PTR_ECX =  b"\xff\x11"
OP_CALL_PTR_EDX =  b"\xff\x12"
OP_CALL_PTR_EDI =  b"\xff\x17"
OP_CALL_PTR_ESI =  b"\xff\x16"
OP_CALL_PTR_EBP =  b"\xff\x55\x00"
OP_CALL_PTR_ESP =  b"\xff\x14\x24"

OP_CALL_FAR_EAX =  b"\xff\x18"
OP_CALL_FAR_EBX =  b"\xff\x1b"
OP_CALL_FAR_ECX =  b"\xff\x19"
OP_CALL_FAR_EDX =  b"\xff\x1a"
OP_CALL_FAR_EDI =  b"\xff\x1f"
OP_CALL_FAR_ESI =  b"\xff\x1e"
OP_CALL_FAR_EBP =  b"\xff\x1c\x24"
OP_CALL_FAR_ESP =  b"\xff\x5d\x00"


OTHER_JMP_PTR_EAX_SHORT =  b"\xff\x60"
OTHER_JMP_PTR_EAX_LONG =  b"\xff\xa0"  #  ff a0 00 01 00 00       jmp    DWORD PTR [eax+0x100]   # should be 00 00 on last two, or too unrealistic

OTHER_JMP_PTR_EBX_SHORT =  b"\xff\x63"
OTHER_JMP_PTR_ECX_SHORT =  b"\xff\x61"
OTHER_JMP_PTR_EDX_SHORT =  b"\xff\x62"
OTHER_JMP_PTR_EDI_SHORT =  b"\xff\x67"
OTHER_JMP_PTR_ESI_SHORT =  b"\xff\x66"
OTHER_JMP_PTR_ESP_SHORT =  b"\xff\x64"
OTHER_JMP_PTR_EBP_SHORT =  b"\xff\x65"

OP_RET = b"\xc3"
OP_RET2 = b"\xc2"
OP_CALL_JMP_FS_START=b"\x64\xff"
OP_RETF = b"\xcb"


listOP_Base = []
listOP_Base_CNT = []
listOP_Base_NumOps = []
listOP_Base_Module = []

listOP_BaseDG = []
listOP_BaseDG_CNT = []
listOP_BaseDG_NumOps = []
listOP_BaseDG_Module = []

