import timeit
# from rop2 import binaryToStr, checkPlease
from helpers import *
from capstone import *
cs64 = Cs(CS_ARCH_X86, CS_MODE_64)
cs = Cs(CS_ARCH_X86, CS_MODE_32)

# fg=None
# dp ("loading gadgets module")

eax="eax"
ebx="ebx"
ecx="ecx"
edx="edx"
esi="esi"
edi="edi"
ebp="ebp"
esp="esp"

mod = {}
pe = {}
curArch=32


	# for item in myPE.DIRECTORY_ENTRY_IMPORT:
	# 	dllDict[item.dll.lower().decode()]={}
	# 	for i in item.imports:
	# 		dllDict[item.dll.lower().decode()][i.name.decode()]=i.address
	# dp (dllDict)


def newGadget(address, pe,n,offset, op_strL,raw, mod, length, myDict2, c2,opOffset=None,myArch=32):
	# dp ("newGadget", address)
	offsetEmBase=offset+pe[n].emBase

	if mod not in fg.ropLookup:
		fg.ropLookup[mod]={}
	fg.ropLookup[mod][offset]=offsetEmBase


	obj = gadgets(address, offsetEmBase, offset,op_strL, raw, mod, length,c2,opOffset,myArch)


	myDict2[offsetEmBase]=obj
	fg.rop[offsetEmBase]=obj
	# dp ("***", hex(address),"off", hex(offset), "offsetEmBase", hex(offsetEmBase))

	dp ("\nnewGadget ropLookup mod", mod, hex(offset), hex(offsetEmBase))
	dp("outsky", fg.ropLookup[mod][offset])
	return obj

def disTiny64(raw):
	returnVal = ""
	

	for i in cs64.disasm(raw, 0):
		val =  i.mnemonic + " " + i.op_str + " # "
		returnVal +=val
	returnVal=returnVal[:-3]
	return returnVal

def disTinyCnt(raw,arch,length):
	myCs=cs
	if arch==64:
		myCs=cs64
	returnVal = ""
	
	# for i in myCs.disasm(raw, 0):
	# 	val =  i.mnemonic + " " + i.op_str + " # "
	# 	returnVal +=val
	t=0
	for i in myCs.disasm(raw, 0):
		t=t+1

	f=t-1		
	if f==0:
		f=1
	return f


def disTinyOpStr(raw, arch):
	myCs=cs

	if arch==32:
		myCs = cs
	elif arch==64:
		myCs = cs64
	op1=None
	op2=None
	# decode just the first instruction
	for i in myCs.disasm(raw, 0):
		# full text, exactly as before
		returnVal = f"{i.mnemonic} {i.op_str}"

		# drop only the first word (the mnemonic)
		#	"mov eax, ebx"  →  "eax, ebx"
		#	"pop rax"	   →  "rax"
		if " " in returnVal:
			operands_str = returnVal.split(" ", 1)[1]
		else:
			operands_str = ""
		break
	# split into up to two pieces, trimming whitespace
	parts = [p.strip() for p in operands_str.split(",", 1)]
	op1 = parts[0] if len(parts) >= 1 else None
	op2 = parts[1] if len(parts) >= 2 else None

	return returnVal, op1, op2

def disTinyOpStrOld(raw,arch):
	myCs=cs
	if arch==64:
		myCs=cs64
	returnVal = ""
	for i in myCs.disasm(raw, 0):
		returnVal=i.mnemonic + " " + i.op_str
		break
	returnValL = returnVal.split(", ")

	
	print ("(******",returnVal,returnValL, ")", arch)
	return returnVal,returnValL

def addGadget64(address,pe, n,offset, op_str,raw, mod, c2=False, reg=None, myDict2=None):
	addGadget(address,pe, n,offset, op_str,raw, mod, c2, reg, myDict2,64)


def addGadget(address,pe, n,offset, op_str,raw, mod, c2=False, reg=None, myDict2=None,myArch=32):
	# dp ("addGadget",op_str)
	opOffset=None
	
	safe,length, op_str=checkPlease(raw,c2,myArch)

	test=(disTiny64(raw))


	# dp ("**************************************************** >", op_str)
	if safe:
		if ", " in op_str:
			# dp ("got comma")
			# dp (op_str)
			op_strL=op_str.split(", ")
			# dp (op_strL)
			# dp ("oplen",len(op_strL))
		op_strL=op_str.split(", ")
		# dp ("op_strL",op_strL)
		if "add rbx" in test:
			# print("addGadget",  hex(offset), "-", op_str, "-", op_strL,test)
			pass
		obj=newGadget(address,pe,n, offset, op_strL,raw, mod, length, myDict2, c2,opOffset, myArch)
		return obj
	return False

def addGadgetJmp(address, pe,n,offset, op_str,raw, mod, c2=False, reg=None, myDict2=None, opOffset=None):
	# safe,length, op_str=checkPlease(raw,c2)
	# dp("addGadgetJmp bytes", len(raw))
	safe=True
	length=1
	# dp ("**************************************************** >", op_str)
	if safe:
		if ", " in op_str:
			# dp ("got comma")
			# dp (op_str)
			op_strL=op_str.split(", ")
			# dp (op_strL)
			# dp ("oplen",len(op_strL))
		op_strL=op_str.split(", ")
		obj=newGadget(address, pe,n, offset, op_strL,raw, mod, length, myDict2, c2,opOffset)


def addGadgetNoCheck(address,pe, n,offset, op_str,raw, mod, c2=False, reg=None, myDict2=None):
	dp ("addGadgetNoCheck", op_str)
	safe,length, op_str=checkPlease(raw,c2)
	op_strL=op_str.split(", ")
	# dp ("op_strL",op_strL)
	newGadget(address,pe,n, offset, op_strL,raw, mod, length, myDict2, c2)

def addChainObj(obj,tlist):
	tlist.append(obj)
def addChainList(listObj,targetList):
	for obj in listObj:
		targetList.append(obj)
def insertChainObj(obj,myList,index):
	myList.insert(index, obj)

def insertChainList(insertList,targetList,index):
	for obj in insertList:
		targetList.insert(index, obj)
		index=index+1
def delChainObj(item,ropList):
	ropList.remove(item)

def delChainIndex(index,ropList):
	ropList.pop(index)

def delChainMulti(deleteList,ropList):   # This sorts in ascending. Deletes all in list - updates values to be deleted, and indexes to be deleted.
	deleteList.sort()
	# dp ("deleteList", deleteList)
	t=0
	for index in deleteList:
		# dp ("before pop deleteList", deleteList,"index",index, "t",t)
		ropList.pop(index)
		# dp ("\tafter pop deleteList", deleteList,"index",index,"t",t)
		index=index-1
		z=0
		for each in deleteList:
			deleteList[z]=deleteList[z]-1
			z+=1
		# dp ("\tindexList", deleteList,"index",index)
		# dp ("\n\n")
		t+=1

def replaceChain(index,tlist,obj):  # at specified index, replace object with one or more objects
	if type(obj) != list:
		tlist[index]=obj
	else:
		tlist[index]=obj[0]
		index=index+1

		t=0
		for o in obj:   # it is a list of objects to replace with
			if t>0:
				tlist.insert(index,o)
				index=index+1
			t+=1


def makeChain(name, myDict):
	myDict[name]=obj
	# dp ("***", hex(address),"off", hex(offset))

class fChainObj:
	def __init__(self,pk,txt,txtC):
		self.pk=pk
		self.txt=None
		self.txtC=None
class gadgetChains:
	def __init__(self):
		self.hg32to64=None
		self.hg64to32=None
		self.sysNtAllocateVirtualMemory=None
		self.sysNtProtectVirtualMemory=None
		self.sr_system=None
		self.sr_getProcAddress=None
		self.md_virtualProtect=None
	def addHg32to64(self,val):
		self.hg32to64=val
	def addHg64to32(self,val):
		self.hg64to32=val
	def addNtAllocate(self,val):
		self.sysNtAllocateVirtualMemory=val
	def addNtProtect(self,val):
		self.sysNtProtectVirtualMemory=val
	def addsrSystem(self,val):
		self.sr_system=val
	def addsrGetProcAddress(self,val):
		self.sr_getProcAddress=val
	def addmdVirtualProtect(self,val):
		self.md_virtualProtect=val


class ropChainObj: 			
	def __init__(self, gadget,comment,stack,index):
		#rop cahin object
		self.g =gadget   # gadget object 
		self.comment=comment
		self.stack = stack # = []   # May consist of filler for stack addresstment and values to be popped into registers
		self.id=index  # index - i prefer dict
		self.obfStatus=None
	def setObf(self,obf,obj=None):
		if type(obj)==list:
			for o in obj:
				o.obfStatus=obf
		else:
			self.obfStatus=obf
	def showObf(self):
		return self.obfStatus
	def show():
		pass
	def modStack(self,new):
		self.stack=new
	def modStackAddFirst(self,new):
		old=self.stack
		nList=new
		nList.extend(old)
		self.stack=nList

	# def copy(self):
	# 	__init__(self, self.gadget,self.comment,self.stack,self.index)
	# 	#rop cahin object
	# 	self.gadget =gadget   # gadget object 
	# 	self.comment=comment
	# 	self.stack = stack # = []   # May consist of filler for stack adjustment and values to be popped into registers
	# 	self.id=index  # index - i prefer dict
	# 	self.obfStatus=None
		
	def modCom(self,new):
		self.comment=new
	def mod(self,*args):
		for each in args:
			if type(each)==list:
				stack=each
				self.stack=stack
			if type(each)==str:
				comment=each
				self.comment=comment
	def app(self,*args):
		for each in args:
			if type(each)==list:
				stack=each
				self.stack=stack
			if type(each)==str:
				comment=each
				self.comment=self.comment + " # " + comment

	def appCom(self,new):
		self.comment=self.comment + " # " + new

	
# frc[name].virtualProtect[obf].gadget.
class foundRopChains:

	def __init__(self):
		#containers for rop chains (i.e. more than one rop chain)
		self.hg33={}
		self.hg23={}
		self.intOverflow={}
		self.virtualProtect = {}
	def addHg33(chain,name):
		self.hg33[name]=chain  ## add complete rop chain object
	def show(self,myDict):
		if myDict=="hg33":
			myDict=self.hg33




class hgRopChainOld: 								# hypothetical - not using - doing a different direction
	def __init__(self, address,offset,op_strL,raw,mod, length,c2): #, name):
		self.doublePush=doublePush
		self.dPushStackAdjust=dPushStackAdjust
		self.p1=p1
		self.p2=p2
		self.p1StackAdjust=p1StackAdjust
		self.p2StackAdjust=p1StackAdjust

class gadgets:
	def __init__(self, address, offsetEmBase, offset,op_strL,raw,mod, length,c2,opOffset=None,myArch=32): #, name):
		# print ("myArch",myArch)
		try:
			self.offset=offset
			self.offsetEmBase=offsetEmBase
			self.addressRet=address
			self.raw=raw
			self.length=length
			self.mod=mod
			self.mnemonic=""
			self.emulated=False
			self.op1=None
			self.op2=None
			self.opOffset=opOffset
			self.FSIndex=None
			self.arch=myArch  #not all x64 is initialized as 64, e.g. JMP, call, TODO
			
			# print (1,myArch, self.arch,2)
			# test0=(disTiny64(raw))
			
			try:
				returnValStr, op1, op2=disTinyOpStr(raw,self.arch)
			except:
				print ("opps!!!!")
				pass
			# print("ops", returnValStr, op1, op2)
			if myArch==64:
				t=disTinyCnt(raw,self.arch,length)
				self.length=t

			
			try:
				self.op1=op1
			except:
				# print ("in except1")

				pass
			try:
				self.op2=op2
			except:
				# print ("in except2")
				pass
			# print ("self.ops", self.op1, self.op2)
			if not c2:
				self.opcode="c3"
			else:
				self.opcode="c2"
			self.c2Adjust=None
			self.stC2=[]
		except Exception as e:
			print (e)
			print("class gadgets\n",traceback.format_exc())
		# print (1)

	def setFSIndex(self,val):
		self.FSIndex=val
	def setC2Adjust(self,val):
		self.c2Adjust=val
	def addHg1(self,val):
		self.hg1=val			
	def addHg2(self,val):
		self.hg2=val
	def setRegsObj(self,obj,special=None):
		if special==None:
			self.regs=obj
			self.emulated=True
		elif special=="hg":
			self.hgRegs=obj
			self.hgEmulated=True
	def setHgDiff(self,val):
		self.hgDiff=val

class retC2Pivots:
	def __init__(self):
		self.g04=None
		self.b04=False
		self.g08=None
		self.b08=False
		self.g0c=None
		self.b0c=False
		self.g10=None
		self.b10=False
		self.g14=None
		self.b14=False
		self.g18=None
		self.b18=False
		self.g1c=None
		self.b1c=False
		self.g20=None
		self.b20=False
		self.g24=None
		self.b24=False
		self.g28=None
		self.b28=False
		self.g2c=None
		self.b2c=False
		self.g30=None
		self.b30=False
		self.g34=None
		self.b34=False
		self.g38=None
		self.b38=False
		self.g3c=None
		self.b3c=False
		self.g40=None
		self.b40=False
		self.g44=None
		self.b44=False
		self.g48=None
		self.b48=False
		self.g4c=None
		self.b4c=False
		self.g50=None
		self.b50=False

	def setG0x4(self,val):
		# dp ("setG04",val)
		if self.g04 ==None:
			self.g04=val
			self.b04=True
	def setG0x8(self,val):
		if self.g08 ==None:
			self.g08=val
			self.b08=True
	def setG0xc(self,val):
		if self.g0c ==None:
			self.g0c=val
			self.b0c=True
	def setG0x10(self,val):
		if self.g10 ==None:
			self.g10=val
			self.b10=True
	def setG0x14(self,val):
		if self.g14 ==None:
			self.g14=val
			self.b14=True
	def setG0x18(self,val):
		if self.g18 ==None:
			self.g18=val
			self.b18=True
	def setG0x1c(self,val):
		if self.g1c ==None:
			self.g1c=val
			self.b1c=True
	def setG0x20(self,val):
		if self.g20 ==None:
			self.g20=val
			self.b20=True
	def setG0x24(self,val):
		if self.g24 ==None:
			self.g24=val
			self.b24=True
	def setG0x28(self,val):
		if self.g28 ==None:
			self.g28=val
			self.b28=True
	def setG0x2c(self,val):
		if self.g2c ==None:
			self.g2c=val
			self.b2c=True
	def setG0x30(self,val):
		if self.g30 ==None:
			self.g30=val
			self.b30=True
	def setG0x34(self,val):
		if self.g34 ==None:
			self.g34=val
			self.b34=True
	def setG0x38(self,val):
		if self.g38 ==None:
			self.g38=val
			self.b38=True
	def setG0x3c(self,val):
		if self.g3c ==None:
			self.g3c=val
			self.b3c=True
	def setG0x40(self,val):
		if self.g40 ==None:
			self.g40=val
			self.b40=True
	def setG0x44(self,val):
		if self.g44 ==None:
			self.g44=val
			self.b44=True
	def setG0x48(self,val):
		if self.g48 ==None:
			self.g48=val
			self.b48=True
	def setG0x4c(self,val):
		if self.g4c ==None:
			self.g4c=val
			self.b4c=True
	def setG0x50(self,val):
		if self.g50 ==None:
			self.g50=val
			self.b50=True

	def sort(self,myDict):
		for p in myDict:
			try:
				val=int(myDict[p].op1)
				# dp (val, hex(val))
			except:
				try:
					val=int(myDict[p].op1,16)
					# dp (p,hex(p),"val",val, hex(val))
				except:
					# dp ("weird one", myDict[p])
					# dp(myDict[p].op1)
					pass
			do = f"setG{hex(val)}"

			if hasattr(self, do) and callable(func := getattr(self, do)):
				func(p)
			
rc2=retC2Pivots()


class foundGadgets:
	def __init__(self):
		self.settings ={}
		self.x64=False
		self.x86=False	
		self.rop = {}
		self.hgGadgets = {}
		self.ropLookup = {}
		self.junkBox=set()
		self.pops = {}
		self.ret ={}
		self.retC2 ={}
		self.popEAX = {}
		self.popEBX = {}
		self.popECX = {}
		self.popEDX = {}
		self.popESI = {}
		self.popEDI = {}
		self.popEBP = {}
		self.popESP = {}
		self.popOther = {}
		self.popDwordEAX = {}
		self.popDwordEBX = {}
		self.popDwordECX = {}
		self.popDwordEDX = {}
		self.popDwordESI = {}
		self.popDwordEDI = {}
		self.popDwordEBP = {}
		self.popDwordESP = {}
		self.popDword = {}
		self.jmpEAX = {}
		self.jmpEBX = {}
		self.jmpECX = {}
		self.jmpEDX = {}
		self.jmpEDI = {}
		self.jmpESI = {}
		self.jmpESP = {}
		self.jmpEBP = {}
		self.jmpDwordEAX = {}
		self.jmpDwordEBX = {}
		self.jmpDwordECX = {}
		self.jmpDwordEDX = {}
		self.jmpDwordEDI = {}
		self.jmpDwordESI = {}
		self.jmpDwordESP = {}
		self.jmpDwordEBP = {}
		self.callDwordEAX = {}
		self.callDwordEBX = {}
		self.callDwordECX = {}
		self.callDwordEDX = {}
		self.callDwordEDI = {}
		self.callDwordESI = {}
		self.callDwordESP = {}
		self.callDwordEBP = {}
		self.jmpDwordOffsetEAX = {}
		self.jmpDwordOffsetEBX = {}
		self.jmpDwordOffsetECX = {}
		self.jmpDwordOffsetEDX = {}
		self.jmpDwordOffsetEDI = {}
		self.jmpDwordOffsetESI = {}
		self.jmpDwordOffsetESP = {}
		self.jmpDwordOffsetEBP = {}
		self.callDwordOffsetEAX = {}
		self.callDwordOffsetEBX = {}
		self.callDwordOffsetECX = {}
		self.callDwordOffsetEDX = {}
		self.callDwordOffsetEDI = {}
		self.callDwordOffsetESI = {}
		self.callDwordOffsetESP = {}
		self.callDwordOffsetEBP = {}
		self.callEAX = {}
		self.callEBX = {}
		self.callECX = {}
		self.callEDX = {}
		self.callEDI = {}
		self.callESI = {}
		self.callESP = {}
		self.callEBP = {}
		self.popDwordOther = {}
		self.push = {}
		self.pushEAX = {}
		self.pushEBX = {}
		self.pushECX = {}
		self.pushEDX = {}
		self.pushESI = {}
		self.pushEDI = {}
		self.pushEBP = {}
		self.pushESP = {}
		self.pushDwordFS = {}
		self.pushDwordFSEAX = {}
		self.pushDwordFSEBX = {}
		self.pushDwordFSECX = {}
		self.pushDwordFSEDX = {}
		self.pushDwordFSEDI = {}
		self.pushDwordFSESI = {}
		self.pushDwordFSEBP = {}
		self.pushDwordEAX = {}
		self.pushDwordEBX = {}
		self.pushDwordECX = {}
		self.pushDwordEDX = {}
		self.pushDwordESI = {}
		self.pushDwordEDI = {}
		self.pushDwordEBP = {}
		self.pushDwordESP = {}
		self.pushDword = {}
		self.pushDwordOther = {}
		self.pushConstant = {}
		self.pushDword = {}
		self.pushOther = {}
		self.hgPush = {}
		self.hgPushEAX = {}
		self.hgPushEBX = {}
		self.hgPushECX = {}
		self.hgPushEDX = {}
		self.hgPushESI = {}	
		self.hgPushEDI = {}
		self.hgPushEBP = {}
		self.hgPushESP = {}
		self.hgPushDwordFS = {}
		self.hgPushDwordEAX = {}
		self.hgPushDwordEBX = {}
		self.hgPushDwordECX = {}
		self.hgPushDwordEDX = {}
		self.hgPushDwordESI = {}
		self.hgPushDwordEDI = {}
		self.hgPushDwordEBP = {}
		self.hgPushDwordESP = {}
		self.hgPushDword = {}
		self.hgPushDwordOther = {}
		self.hgPushConstant = {}
		self.hgPushDword = {}
		self.hgPushOther = {}
		self.inc = {}
		self.incEAX = {}
		self.incEBX = {}
		self.incECX = {}
		self.incEDX = {}
		self.incESI = {}
		self.incEDI = {}
		self.incEBP = {}
		self.incESP = {}
		self.dec = {}
		self.decEAX = {}
		self.decEBX = {}
		self.decECX = {}
		self.decEDX = {}
		self.decESI = {}
		self.decEDI = {}
		self.decEBP = {}
		self.decESP = {}
		self.addEAX = {}
		self.addEBX = {}
		self.addECX = {}
		self.addEDX = {}
		self.addESI = {}
		self.addEDI = {}
		self.addEBP = {}
		self.addESP = {}
		self.addESPVal = {}
		self.addFS = {}
		self.subFS = {}
		self.xorFS = {}
		self.xchgFS = {}
		self.add = {}
		self.addDword = {}
		self.addDwordEAX = {}
		self.addDwordEBX = {}
		self.addDwordECX = {}
		self.addDwordEDX = {}
		self.addDwordESI = {}
		self.addDwordEDI = {}
		self.addDwordEBP = {}
		self.addDwordESP = {}
		self.subEAX = {}
		self.subEBX = {}
		self.subECX = {}
		self.subEDX = {}
		self.subESI = {}
		self.subEDI = {}
		self.subEBP = {}
		self.subESP = {}
		self.sub = {}
		self.subDword = {}
		self.subDwordEAX = {}
		self.subDwordEBX = {}
		self.subDwordECX = {}
		self.subDwordEDX = {}
		self.subDwordESI = {}
		self.subDwordEDI = {}
		self.subDwordEBP = {}
		self.subDwordESP = {}
		self.mulEAX = {}
		self.mulEBX = {}
		self.mulECX = {}
		self.mulEDX = {}
		self.mulESI = {}
		self.mulEDI = {}
		self.mulEBP = {}
		self.mulESP = {}
		self.mul = {}
		self.divEAX = {}
		self.divEBX = {}
		self.divECX = {}
		self.divEDX = {}
		self.divESI = {}
		self.divEDI = {}
		self.divEBP = {}
		self.divESP = {}
		self.div = {}
		self.leaEAX = {}
		self.leaEBX = {}
		self.leaECX = {}
		self.leaEDX = {}
		self.leaESI = {}
		self.leaEDI = {}
		self.leaEBP = {}
		self.leaESP = {}
		self.lea = {}	
		self.movEAX = {}
		self.movEBX = {}
		self.movECX = {}
		self.movEDX = {}
		self.movESI = {}
		self.movEDI = {}
		self.movEBP = {}
		self.movESP = {}
		self.movFS = {}
		self.movFSEAX = {}
		self.movFSEBX = {}
		self.movFSECX = {}
		self.movFSEDX = {}
		self.movFSEDI = {}
		self.movFSESI = {}
		self.movFSEBP = {}
		self.movFSESP = {}
		self.addFSEAX = {}
		self.addFSEBX = {}
		self.addFSECX = {}
		self.addFSEDX = {}
		self.addFSEDI = {}
		self.addFSESI = {}
		self.addFSEBP = {}
		self.addFSESP = {}
		self.subFSEAX = {}
		self.subFSEBX = {}
		self.subFSECX = {}
		self.subFSEDX = {}
		self.subFSEDI = {}
		self.subFSESI = {}
		self.subFSEBP = {}
		self.subFSESP = {}
		self.xorFSEAX = {}
		self.xorFSEBX = {}
		self.xorFSECX = {}
		self.xorFSEDX = {}
		self.xorFSEDI = {}
		self.xorFSESI = {}
		self.xorFSEBP = {}
		self.xorFSESP = {}
		self.xchgFSEAX = {}
		self.xchgFSEBX = {}
		self.xchgFSECX = {}
		self.xchgFSEDX = {}
		self.xchgFSEDI = {}
		self.xchgFSESI = {}
		self.xchgFSEBP = {}
		self.xchgFSESP = {}
		self.mov = {}
		self.movDwordEAX = {}
		self.movDwordEBX = {}
		self.movDwordECX = {}
		self.movDwordEDX = {}
		self.movDwordESI = {}
		self.movDwordEDI = {}
		self.movDwordEBP = {}
		self.movDwordESP = {}
		self.movDword = {}
		self.movDword2EAX = {}
		self.movDword2EBX = {}
		self.movDword2ECX = {}
		self.movDword2EDX = {}
		self.movDword2ESI = {}
		self.movDword2EDI = {}
		self.movDword2EBP = {}
		self.movDword2ESP = {}
		self.movDword2 = {}
		self.xchgEAX = {}
		self.xchgEBX = {}
		self.xchgECX = {}
		self.xchgEDX = {}
		self.xchgESI = {}
		self.xchgEDI = {}
		self.xchgEBP = {}
		self.xchgESP = {}
		self.xchg = {}
		self.movConstantEAX = {}
		self.movConstantEBX = {}
		self.movConstantECX = {}
		self.movConstantEDX = {}
		self.movConstantESI = {}
		self.movConstantEDI = {}
		self.movConstantEBP = {}
		self.movConstantESP = {}
		self.movConstant = {}
		self.negEAX = {}
		self.negEBX = {}
		self.negECX = {}
		self.negEDX = {}
		self.negESI = {}
		self.negEDI = {}
		self.negEBP = {}
		self.negESP = {}
		self.neg = {}
		self.xorEAX = {}
		self.xorEBX = {}
		self.xorECX = {}
		self.xorEDX = {}
		self.xorESI = {}
		self.xorEDI = {}
		self.xorEBP = {}
		self.xorESP = {}
		self.xor = {}
		self.xorDwordEAX = {}
		self.xorDwordEBX = {}
		self.xorDwordECX = {}
		self.xorDwordEDX = {}
		self.xorDwordESI = {}
		self.xorDwordEDI = {}
		self.xorDwordEBP = {}
		self.xorDwordESP = {}
		self.xorDword = {}
		self.xorZeroEAX = {}
		self.xorZeroEBX = {}
		self.xorZeroECX = {}
		self.xorZeroEDX = {}
		self.xorZeroESI = {}
		self.xorZeroEDI = {}
		self.xorZeroEBP = {}
		self.xorZeroESP = {}
		self.xorZero = {}
		self.pushad = {}
		self.popal = {}
		self.syscall64={}
		self.shl = {}
		self.shr = {}
		self.shlDword = {}
		self.shrDword = {}
		self.rcl = {}
		self.rcr = {}
		self.rclDword = {}
		self.rcrDword = {}
		self.unusual = {}
		self.andInstEAX = {}
		self.andInstEBX = {}
		self.andInstECX = {}
		self.andInstEDX = {}
		self.andInstESI = {}
		self.andInstEDI = {}
		self.andInstEBP = {}
		self.andInstESP = {}
		self.andInst = {}
		self.andInstOther = {}
		self.notInstEAX = {}
		self.notInstEBX = {}
		self.notInstECX = {}
		self.notInstEDX = {}
		self.notInstESI = {}
		self.notInstEDI = {}
		self.notInstEBP = {}
		self.notInstESP = {}
		self.notInst = {}
		self.notInstOther = {}
		self.fs = {}
		self.fsSpecial = {}
		self.retfSingle={}

		#####64 bit follows!!!
		self.jmpRSI = {}
		self.jmpRBP = {}
		self.jmpRDI = {}
		self.jmpRAX = {}
		self.jmpRBX = {}
		self.jmpRSP = {}
		self.jmpRCX = {}
		self.jmpRDX = {}
		self.jmpR8 = {}
		self.jmpR9 = {}
		self.jmpR10 = {}
		self.jmpR11 = {}
		self.jmpR12 = {}
		self.jmpR13 = {}
		self.jmpR14 = {}
		self.jmpR15 = {}
		self.jmpQwordRBP = {}
		self.jmpQwordOffsetRBP = {}
		self.jmpQwordRSP = {}
		self.jmpQwordOffsetRSP = {}
		self.jmpQwordRDI = {}
		self.jmpQwordOffsetRDI = {}
		self.jmpQwordRSI = {}
		self.jmpQwordOffsetRSI = {}
		self.jmpQwordRAX = {}
		self.jmpQwordOffsetRAX = {}
		self.jmpQwordRBX = {}
		self.jmpQwordOffsetRBX = {}
		self.jmpQwordRCX = {}
		self.jmpQwordOffsetRCX = {}
		self.jmpQwordRDX = {}
		self.jmpQwordOffsetRDX = {}
		self.jmpQwordR8 = {}
		self.jmpQwordOffsetR8 = {}
		self.jmpQwordR9 = {}
		self.jmpQwordOffsetR9 = {}
		self.jmpQwordR10 = {}
		self.jmpQwordOffsetR10 = {}
		self.jmpQwordR11 = {}
		self.jmpQwordOffsetR11 = {}
		self.jmpQwordR12 = {}
		self.jmpQwordOffsetR12 = {}
		self.jmpQwordR13 = {}
		self.jmpQwordOffsetR13 = {}
		self.jmpQwordR14 = {}
		self.jmpQwordOffsetR14 = {}
		self.jmpQwordR15 = {}
		self.jmpQwordOffsetR15 = {}
		self.callRSI = {}
		self.callRBP = {}
		self.callRDI = {}
		self.callRAX = {}
		self.callRBX = {}
		self.callRSP = {}
		self.callRCX = {}
		self.callRDX = {}
		self.callR8 = {}
		self.callR9 = {}
		self.callR10 = {}
		self.callR11 = {}
		self.callR12 = {}
		self.callR13 = {}
		self.callR14 = {}
		self.callR15 = {}
		self.callQwordRBP = {}
		self.callQwordOffsetRBP = {}
		self.callQwordRSP = {}
		self.callQwordOffsetRSP = {}
		self.callQwordRDI = {}
		self.callQwordOffsetRDI = {}
		self.callQwordRSI = {}
		self.callQwordOffsetRSI = {}
		self.callQwordRAX = {}
		self.callQwordOffsetRAX = {}
		self.callQwordRBX = {}
		self.callQwordOffsetRBX = {}
		self.callQwordRCX = {}
		self.callQwordOffsetRCX = {}
		self.callQwordRDX = {}
		self.callQwordOffsetRDX = {}
		self.callQwordR8 = {}
		self.callQwordOffsetR8 = {}
		self.callQwordR9 = {}
		self.callQwordOffsetR9 = {}
		self.callQwordR10 = {}
		self.callQwordOffsetR10 = {}
		self.callQwordR11 = {}
		self.callQwordOffsetR11 = {}
		self.callQwordR12 = {}
		self.callQwordOffsetR12 = {}
		self.callQwordR13 = {}
		self.callQwordOffsetR13 = {}
		self.callQwordR14 = {}
		self.callQwordOffsetR14 = {}
		self.callQwordR15 = {}
		self.callQwordOffsetR15 = {}
		self.retfSingle64 = {}
		self.pops64 = {}
		self.popRSI = {}
		self.popRBX = {}
		self.popRCX = {}
		self.popRAX = {}
		self.popRDI = {}
		self.popRBP = {}
		self.popRSP = {}
		self.popRDX = {}
		self.popR8 = {}
		self.popR9 = {}
		self.popR10 = {}
		self.popR11 = {}
		self.popR12 = {}
		self.popR13 = {}
		self.popR14 = {}
		self.popR15 = {}
		self.popOther64 = {}
		self.popQword = {}
		self.popQwordRAX = {}
		self.popQwordRBX = {}
		self.popQwordRCX = {}
		self.popQwordRDX = {}
		self.popQwordRSI = {}
		self.popQwordRDI = {}
		self.popQwordRSP = {}
		self.popQwordRBP = {}
		self.popQwordR8 = {}
		self.popQwordR9 = {}
		self.popQwordR10 = {}
		self.popQwordR11 = {}
		self.popQwordR12 = {}
		self.popQwordR13 = {}
		self.popQwordR14 = {}
		self.popQwordR15 = {}
		self.popQwordOther = {}
		self.hgPush64 = {}
		self.hgPushRAX = {}
		self.hgPushRBX = {}
		self.hgPushRCX = {}
		self.hgPushRBP = {}
		self.hgPushRSP = {}
		self.hgPushRDX = {}
		self.hgPushRDI = {}
		self.hgPushRSI = {}
		self.hgPushConstant64 = {}
		self.hgPushR8 = {}
		self.hgPushR9 = {}
		self.hgPushR10 = {}
		self.hgPushR11 = {}
		self.hgPushR12 = {}
		self.hgPushR13 = {}
		self.hgPushR14 = {}
		self.hgPushR15 = {}
		self.hgPushOther64 = {}
		self.hgPushQword = {}
		self.hgPushQwordRAX = {}
		self.hgPushQwordRBX = {}
		self.hgPushQwordRCX = {}
		self.hgPushQwordRDX = {}
		self.hgPushQwordRSI = {}
		self.hgPushQwordRDI = {}
		self.hgPushQwordRSP = {}
		self.hgPushQwordRBP = {}
		self.hgPushQwordR8 = {}
		self.hgPushQwordR9 = {}
		self.hgPushQwordR10 = {}
		self.hgPushQwordR11 = {}
		self.hgPushQwordR12 = {}
		self.hgPushQwordR13 = {}
		self.hgPushQwordR14 = {}
		self.hgPushQwordR15 = {}
		self.hgPushQwordOther = {}
		self.ret64 = {}
		self.retC264 = {}
		self.push64 = {}
		self.pushRAX = {}
		self.pushRBX = {}
		self.pushRCX = {}
		self.pushRBP = {}
		self.pushRSP = {}
		self.pushRDX = {}
		self.pushRDI = {}
		self.pushRSI = {}
		self.pushR8 = {}
		self.pushR9 = {}
		self.pushR10 = {}
		self.pushR11 = {}
		self.pushR12 = {}
		self.pushR13 = {}
		self.pushR14 = {}
		self.pushR15 = {}
		self.pushConstant64 = {}
		self.pushOther64 = {}
		self.pushQwordGS = {}
		self.pushQwordGSRAX = {}
		self.pushQwordGSRBX = {}
		self.pushQwordGSRCX = {}
		self.pushQwordGSRDX = {}
		self.pushQwordGSRDI = {}
		self.pushQwordGSRSI = {}
		self.pushQwordGSRBP = {}
		self.pushQwordGSR8 = {}
		self.pushQwordGSR9 = {}
		self.pushQwordGSR10 = {}
		self.pushQwordGSR11 = {}
		self.pushQwordGSR12 = {}
		self.pushQwordGSR13 = {}
		self.pushQwordGSR14 = {}
		self.pushQwordGSR15 = {}
		self.pushQword64 = {}
		self.pushQwordRAX = {}
		self.pushQwordRBX = {}
		self.pushQwordRCX = {}
		self.pushQwordRDX = {}
		self.pushQwordRSI = {}
		self.pushQwordRDI = {}
		self.pushQwordRSP = {}
		self.pushQwordRBP = {}
		self.pushQwordR8 = {}
		self.pushQwordR9 = {}
		self.pushQwordR10 = {}
		self.pushQwordR11 = {}
		self.pushQwordR12 = {}
		self.pushQwordR13 = {}
		self.pushQwordR14 = {}
		self.pushQwordR15 = {}
		self.pushQwordGS = {}
		self.pushQwordOther = {}
		self.inc64 = {}
		self.incRSI = {}
		self.incRBP = {}
		self.incRDI = {}
		self.incRAX = {}
		self.incRBX = {}
		self.incRSP = {}
		self.incRCX = {}
		self.incRDX = {}
		self.incR8 = {}
		self.incR9 = {}
		self.incR10 = {}
		self.incR11 = {}
		self.incR12 = {}
		self.incR13 = {}
		self.incR14 = {}
		self.incR15 = {}
		self.dec64 = {}
		self.decRSI = {}
		self.decRBP = {}
		self.decRDI = {}
		self.decRAX = {}
		self.decRBX = {}
		self.decRSP = {}
		self.decRCX = {}
		self.decRDX = {}
		self.decR8 = {}
		self.decR9 = {}
		self.decR10 = {}
		self.decR11 = {}
		self.decR12 = {}
		self.decR13 = {}
		self.decR14 = {}
		self.decR15 = {}
		self.add64 = {}
		self.addRAX = {}
		self.addRBX = {}
		self.addRCX = {}
		self.addRSP = {}
		self.addRSPVal = {}
		self.addRBP = {}
		self.addRDX = {}
		self.addRDI = {}
		self.addRSI = {}
		self.addR8 = {}
		self.addR9 = {}
		self.addR10 = {}
		self.addR11 = {}
		self.addR12 = {}
		self.addR13 = {}
		self.addR14 = {}
		self.addR15 = {}
		self.addQwordRAX = {}
		self.addQwordRBX = {}
		self.addQwordRCX = {}
		self.addQwordRSP = {}
		self.addQwordRBP = {}
		self.addQwordRDX = {}
		self.addQwordRDI = {}
		self.addQwordRSI = {}
		self.addQwordR8 = {}
		self.addQwordR9 = {}
		self.addQwordR10 = {}
		self.addQwordR11 = {}
		self.addQwordR12 = {}
		self.addQwordR13 = {}
		self.addQwordR14 = {}
		self.addQwordR15 = {}
		self.addGS = {}
		self.sub64 = {}
		self.subRAX = {}
		self.subRBX = {}
		self.subRCX = {}
		self.subRDX = {}
		self.subRSI = {}
		self.subRDI = {}
		self.subRSP = {}
		self.subRBP = {}
		self.subR8 = {}
		self.subR9 = {}
		self.subR10 = {}
		self.subR11 = {}
		self.subR12 = {}
		self.subR13 = {}
		self.subR14 = {}
		self.subR15 = {}
		self.subQwordRAX = {}
		self.subQwordRBX = {}
		self.subQwordRCX = {}
		self.subQwordRDX = {}
		self.subQwordRSI = {}
		self.subQwordRDI = {}
		self.subQwordRSP = {}
		self.subQwordRBP = {}
		self.subQwordR8 = {}
		self.subQwordR9 = {}
		self.subQwordR10 = {}
		self.subQwordR11 = {}
		self.subQwordR12 = {}
		self.subQwordR13 = {}
		self.subQwordR14 = {}
		self.subQwordR15 = {}
		self.subGS = {}
		self.mul = {}
		self.mulRAX = {}
		self.mulRDX = {}
		self.mulRAX = {}
		self.mulRBX = {}
		self.mulRCX = {}
		self.mulRDX = {}
		self.mulRSI = {}
		self.mulRDI = {}
		self.mulRSP = {}
		self.mulRBP = {}
		self.mulR8 = {}
		self.mulR9 = {}
		self.mulR10 = {}
		self.mulR11 = {}
		self.mulR12 = {}
		self.mulR13 = {}
		self.mulR14 = {}
		self.mulR15 = {}
		self.div = {}
		self.divRAX = {}
		self.divRDX = {}
		self.lea = {}
		self.leaRAX = {}
		self.leaRBX = {}
		self.leaRCX = {}
		self.leaRDX = {}
		self.leaRSI = {}
		self.leaRDI = {}
		self.leaRBP = {}
		self.leaRSP = {}
		self.leaR8 = {}
		self.leaR9 = {}
		self.leaR10 = {}
		self.leaR11 = {}
		self.leaR12 = {}
		self.leaR13 = {}
		self.leaR14 = {}
		self.leaR15 = {}
		self.xchg64 = {}
		self.xchgRAX = {}
		self.xchgRBX = {}
		self.xchgRCX = {}
		self.xchgRDX = {}
		self.xchgRSI = {}
		self.xchgRDI = {}
		self.xchgRBP = {}
		self.xchgRSP = {}
		self.xchgGS = {}
		self.xchgR8 = {}
		self.xchgR9 = {}
		self.xchgR10 = {}
		self.xchgR11 = {}
		self.xchgR12 = {}
		self.xchgR13 = {}
		self.xchgR14 = {}
		self.xchgR15 = {}
		self.neg = {}
		self.negRAX = {}
		self.junkBox64 = set()
		self.negRBX = {}
		self.negRCX = {}
		self.negRDX = {}
		self.negRSI = {}
		self.negRDI = {}
		self.negRSP = {}
		self.negRBP = {}
		self.negR8 = {}
		self.negR9 = {}
		self.negR10 = {}
		self.negR11 = {}
		self.negR12 = {}
		self.negR13 = {}
		self.negR14 = {}
		self.negR15 = {}
		self.xor = {}
		self.xorZeroRAX = {}
		self.xorRAX = {}
		self.xorZeroRBX = {}
		self.xorRBX = {}
		self.xorZeroRCX = {}
		self.xorRCX = {}
		self.xorZeroRDX = {}
		self.xorRDX = {}
		self.xorZeroRSI = {}
		self.xorRSI = {}
		self.xorZeroRDI = {}
		self.xorRDI = {}
		self.xorZeroRSP = {}
		self.xorRSP = {}
		self.xorZeroRBP = {}
		self.xorRBP = {}
		self.xorZeroR8 = {}
		self.xorR8 = {}
		self.xorZeroR9 = {}
		self.xorR9 = {}
		self.xorZeroR10 = {}
		self.xorR10 = {}
		self.xorZeroR11 = {}
		self.xorR11 = {}
		self.xorZeroR12 = {}
		self.xorR12 = {}
		self.xorZeroR13 = {}
		self.xorR13 = {}
		self.xorZeroR14 = {}
		self.xorR14 = {}
		self.xorZeroR15 = {}
		self.xorR15 = {}
		self.xorQwordRAX = {}
		self.xorQwordRBX = {}
		self.xorQwordRCX = {}
		self.xorQwordRDX = {}
		self.xorQwordRSI = {}
		self.xorQwordRDI = {}
		self.xorQwordRSP = {}
		self.xorQwordRBP = {}
		self.xorR8 = {}
		self.xorR9 = {}
		self.xorR10 = {}
		self.xorR11 = {}
		self.xorR12 = {}
		self.xorR13 = {}
		self.xorR14 = {}
		self.xorR15 = {}
		self.xorGS = {}
		self.mov64 = {}
		self.movRAX = {}
		self.movRBX = {}
		self.movRCX = {}
		self.movRDX = {}
		self.movRSI = {}
		self.movRDI = {}
		self.movRSP = {}
		self.movRBP = {}
		self.movR8 = {}
		self.movR9 = {}
		self.movR10 = {}
		self.movR11 = {}
		self.movR12 = {}
		self.movR13 = {}
		self.movR14 = {}
		self.movR15 = {}
		self.movQword2 = {}
		self.movQword2RAX = {}
		self.movQword2RBX = {}
		self.movQword2RCX = {}
		self.movQword2RDX = {}
		self.movQword2RSI = {}
		self.movQword2RDI = {}
		self.movQword2RSP = {}
		self.movQword2RBP = {}
		self.movQword2R8 = {}
		self.movQword2R9 = {}
		self.movQword2R10 = {}
		self.movQword2R11 = {}
		self.movQword2R12 = {}
		self.movQword2R13 = {}
		self.movQword2R14 = {}
		self.movQword2R15 = {}
		self.movConstant64 = {}
		self.movConstantRAX = {}
		self.movConstantRBX = {}
		self.movConstantRCX = {}
		self.movConstantRDX = {}
		self.movConstantRSI = {}
		self.movConstantRDI = {}
		self.movConstantRSP = {}
		self.movConstantRBP = {}
		self.movConstantR8 = {}
		self.movConstantR9 = {}
		self.movConstantR10 = {}
		self.movConstantR11 = {}
		self.movConstantR12 = {}
		self.movConstantR13 = {}
		self.movConstantR14 = {}
		self.movConstantR15 = {}
		self.movQword = {}
		self.movQwordRAX = {}
		self.movQwordRBX = {}
		self.movQwordRCX = {}
		self.movQwordRDX = {}
		self.movQwordRDI = {}
		self.movQwordRSI = {}
		self.movQwordRBP = {}
		self.movQwordRSP = {}
		self.movR8 = {}
		self.movR9 = {}
		self.movR10 = {}
		self.movR11 = {}
		self.movR12 = {}
		self.movR13 = {}
		self.movR14 = {}
		self.movR15 = {}
		self.movGSSpecial = {}
		self.popal64 = {}
		self.syscall64 = {}
		self.rdgsbase64 = {}
		self.pushad64 = {}
		self.shlQword = {}
		self.shl64 = {}
		self.shrQword = {}
		self.shr64 = {}
		self.rcrQword = {}
		self.rcr64 = {}
		self.rclQword = {}
		self.rcl64 = {}
		self.notInst64 = {}
		self.notInstRAX = {}
		self.notInstRBX = {}
		self.notInstRCX = {}
		self.notInstRDX = {}
		self.notInstRSI = {}
		self.notInstRDI = {}
		self.notInstRSP = {}
		self.notInstRBP = {}
		self.notInstR8 = {}
		self.notInstR9 = {}
		self.notInstR10 = {}
		self.notInstR11 = {}
		self.notInstR12 = {}
		self.notInstR13 = {}
		self.notInstR14 = {}
		self.notInstR15 = {}
		self.andInst64 = {}
		self.andInstRAX = {}
		self.andInstRBX = {}
		self.andInstRCX = {}
		self.andInstRDX = {}
		self.andInstRSI = {}
		self.andInstRDI = {}
		self.andInstRSP = {}
		self.andInstRBP = {}
		self.andInstR8 = {}
		self.andInstR9 = {}
		self.andInstR10 = {}
		self.andInstR11 = {}
		self.andInstR12 = {}
		self.andInstR13 = {}
		self.andInstR14 = {}
		self.andInstR15 = {}
		self.unusual64 = {}
		self.fs64 = {}
		self.fsSpecial64 = {}


	def getFg(self,mystr,reg=""):
		# print ("getfFg", reg, len(reg))
		try:
			reg=reg.upper()
			mystr=mystr+reg
			# dp ("mystr", mystr)
		except:
			pass
		# dp ("getFg", mystr)
		if hasattr(self,mystr):
			# print ("mystr", mystr)
			myDict=getattr(self,mystr)
			if len(myDict) > 0:
				dp ("\t\tgetfFg: it exists2", mystr, len(myDict))
				return True, myDict
			else:
				return False, 0
		else:
			dp ("getFg: does not exist2",mystr)
			empty={}
			return False, empty
	def get2FG(self, mystr, mystr2):
		emtpy={}
		if hasattr(self,mystr) and hasattr(self,mystr2):
			# dp ("it has both fg!",mystr,mystr2)
			myDict=getattr(self,mystr)
			myDict2=getattr(self,mystr2)
			if len(myDict) > 0 and len(myDict2) > 0:
				return True, myDict, myDict2
			else:
				return False, empty, empty
		else:
			# dp ("nope3!")
			return False, empty,empty

	def __del__ (self):
		dp("foundGadgets object destroyed")
	def merge(self,old):
		dp("merge")
		# dp ("types", type(self), type(old))

		# mergeT = timeit.default_timer()
		if old is None:
			dp ("Nonetype object for merge -  rejected.")
			return

		self.rop = {**self.rop, **old.rop}
		self.pops = {**self.pops, **old.pops}
		self.popEAX = {**self.popEAX, **old.popEAX}
		self.ret ={**self.ret, **old.ret}
		self.retC2 ={**self.retC2, **old.retC2}
		self.ropLookup = {**self.ropLookup, **old.ropLookup}
		self.popEBX = {**self.popEBX, **old.popEBX}
		self.popECX = {**self.popECX, **old.popECX}
		self.popEDX = {**self.popEDX, **old.popEDX}
		self.popESI = {**self.popESI, **old.popESI}
		self.popEDI = {**self.popEDI, **old.popEDI}
		self.popEBP = {**self.popEBP, **old.popEBP}
		self.popESP = {**self.popESP, **old.popESP}
		self.popOther = {**self.popOther, **old.popOther}
		self.popDwordEAX = {**self.popDwordEAX, **old.popDwordEAX}
		self.popDwordEBX = {**self.popDwordEBX, **old.popDwordEBX}
		self.popDwordECX = {**self.popDwordECX, **old.popDwordECX}
		self.popDwordEDX = {**self.popDwordEDX, **old.popDwordEDX}
		self.popDwordESI = {**self.popDwordESI, **old.popDwordESI}
		self.popDwordEDI = {**self.popDwordEDI, **old.popDwordEDI}
		self.popDwordEBP = {**self.popDwordEBP, **old.popDwordEBP}
		self.popDwordESP = {**self.popDwordESP, **old.popDwordESP}
		self.jmpEAX = {**self.jmpEAX, **old.jmpEAX}
		self.jmpEBX = {**self.jmpEBX, **old.jmpEBX}
		self.jmpECX = {**self.jmpECX, **old.jmpECX}
		self.jmpEDX = {**self.jmpEDX, **old.jmpEDX}
		self.jmpESI = {**self.jmpESI, **old.jmpESI}
		self.jmpEDI = {**self.jmpEDI, **old.jmpEDI}
		self.jmpEBP = {**self.jmpEBP, **old.jmpEBP}
		self.jmpESP = {**self.jmpESP, **old.jmpESP}
		self.callEAX = {**self.callEAX, **old.callEAX}
		self.callEBX = {**self.callEBX, **old.callEBX}
		self.callECX = {**self.callECX, **old.callECX}
		self.callEDX = {**self.callEDX, **old.callEDX}
		self.callESI = {**self.callESI, **old.callESI}
		self.callEDI = {**self.callEDI, **old.callEDI}
		self.callEBP = {**self.callEBP, **old.callEBP}
		self.callESP = {**self.callESP, **old.callESP}
		self.jmpDwordEAX = {**self.jmpDwordEAX, **old.jmpDwordEAX}
		self.jmpDwordEBX = {**self.jmpDwordEBX, **old.jmpDwordEBX}
		self.jmpDwordECX = {**self.jmpDwordECX, **old.jmpDwordECX}
		self.jmpDwordEDX = {**self.jmpDwordEDX, **old.jmpDwordEDX}
		self.jmpDwordESI = {**self.jmpDwordESI, **old.jmpDwordESI}
		self.jmpDwordEDI = {**self.jmpDwordEDI, **old.jmpDwordEDI}
		self.jmpDwordEBP = {**self.jmpDwordEBP, **old.jmpDwordEBP}
		self.jmpDwordESP = {**self.jmpDwordESP, **old.jmpDwordESP}
		self.callDwordEAX = {**self.callDwordEAX, **old.callDwordEAX}
		self.callDwordEBX = {**self.callDwordEBX, **old.callDwordEBX}
		self.callDwordECX = {**self.callDwordECX, **old.callDwordECX}
		self.callDwordEDX = {**self.callDwordEDX, **old.callDwordEDX}
		self.callDwordESI = {**self.callDwordESI, **old.callDwordESI}
		self.callDwordEDI = {**self.callDwordEDI, **old.callDwordEDI}
		self.callDwordEBP = {**self.callDwordEBP, **old.callDwordEBP}
		self.callDwordESP = {**self.callDwordESP, **old.callDwordESP}
		self.jmpDwordOffsetEAX = {**self.jmpDwordOffsetEAX, **old.jmpDwordOffsetEAX}
		self.jmpDwordOffsetEBX = {**self.jmpDwordOffsetEBX, **old.jmpDwordOffsetEBX}
		self.jmpDwordOffsetECX = {**self.jmpDwordOffsetECX, **old.jmpDwordOffsetECX}
		self.jmpDwordOffsetEDX = {**self.jmpDwordOffsetEDX, **old.jmpDwordOffsetEDX}
		self.jmpDwordOffsetESI = {**self.jmpDwordOffsetESI, **old.jmpDwordOffsetESI}
		self.jmpDwordOffsetEDI = {**self.jmpDwordOffsetEDI, **old.jmpDwordOffsetEDI}
		self.jmpDwordOffsetEBP = {**self.jmpDwordOffsetEBP, **old.jmpDwordOffsetEBP}
		self.jmpDwordOffsetESP = {**self.jmpDwordOffsetESP, **old.jmpDwordOffsetESP}
		self.callDwordOffsetEAX = {**self.callDwordOffsetEAX, **old.callDwordOffsetEAX}
		self.callDwordOffsetEBX = {**self.callDwordOffsetEBX, **old.callDwordOffsetEBX}
		self.callDwordOffsetECX = {**self.callDwordOffsetECX, **old.callDwordOffsetECX}
		self.callDwordOffsetEDX = {**self.callDwordOffsetEDX, **old.callDwordOffsetEDX}
		self.callDwordOffsetESI = {**self.callDwordOffsetESI, **old.callDwordOffsetESI}
		self.callDwordOffsetEDI = {**self.callDwordOffsetEDI, **old.callDwordOffsetEDI}
		self.callDwordOffsetEBP = {**self.callDwordOffsetEBP, **old.callDwordOffsetEBP}
		self.callDwordOffsetESP = {**self.callDwordOffsetESP, **old.callDwordOffsetESP}
		self.popDword = {**self.popDword, **old.popDword}
		self.popDwordOther = {**self.popDwordOther, **old.popDwordOther}
		self.push = {**self.push, **old.push}
		self.pushEAX = {**self.pushEAX, **old.pushEAX}
		self.pushEBX = {**self.pushEBX, **old.pushEBX}
		self.pushECX = {**self.pushECX, **old.pushECX}
		self.pushEDX = {**self.pushEDX, **old.pushEDX}
		self.pushESI = {**self.pushESI, **old.pushESI}
		self.pushEDI = {**self.pushEDI, **old.pushEDI}
		self.pushEBP = {**self.pushEBP, **old.pushEBP}
		self.pushESP = {**self.pushESP, **old.pushESP}
		self.pushDwordFS = {**self.pushDwordFS, **old.pushDwordFS}
		self.pushDwordFSEAX = {**self.pushDwordFSEAX, **old.pushDwordFSEAX}
		self.pushDwordFSEBX = {**self.pushDwordFSEBX, **old.pushDwordFSEBX}
		self.pushDwordFSECX = {**self.pushDwordFSECX, **old.pushDwordFSECX}
		self.pushDwordFSEDX = {**self.pushDwordFSEDX, **old.pushDwordFSEDX}
		self.pushDwordFSEDI = {**self.pushDwordFSEDI, **old.pushDwordFSEDI}
		self.pushDwordFSESI = {**self.pushDwordFSESI, **old.pushDwordFSESI}
		self.pushDwordFSEBP = {**self.pushDwordFSEBP, **old.pushDwordFSEBP}
		self.pushDwordEAX = {**self.pushDwordEAX, **old.pushDwordEAX}
		self.pushDwordEBX = {**self.pushDwordEBX, **old.pushDwordEBX}
		self.pushDwordECX = {**self.pushDwordECX, **old.pushDwordECX}
		self.pushDwordEDX = {**self.pushDwordEDX, **old.pushDwordEDX}
		self.pushDwordESI = {**self.pushDwordESI, **old.pushDwordESI}
		self.pushDwordEDI = {**self.pushDwordEDI, **old.pushDwordEDI}
		self.pushDwordEBP = {**self.pushDwordEBP, **old.pushDwordEBP}
		self.pushDwordESP = {**self.pushDwordESP, **old.pushDwordESP}
		self.pushDword = {**self.pushDword, **old.pushDword}
		self.pushDwordOther = {**self.pushDwordOther, **old.pushDwordOther}
		self.pushConstant = {**self.pushConstant, **old.pushConstant}
		self.pushDword = {**self.pushDword, **old.pushDword}
		self.pushOther = {**self.pushOther, **old.pushOther}
		self.inc = {**self.inc, **old.inc}
		self.incEAX = {**self.incEAX, **old.incEAX}
		self.incEBX = {**self.incEBX, **old.incEBX}
		self.incECX = {**self.incECX, **old.incECX}
		self.incEDX = {**self.incEDX, **old.incEDX}
		self.incESI = {**self.incESI, **old.incESI}
		self.incEDI = {**self.incEDI, **old.incEDI}
		self.incEBP = {**self.incEBP, **old.incEBP}
		self.incESP = {**self.incESP, **old.incESP}
		self.dec = {**self.dec, **old.dec}
		self.decEAX = {**self.decEAX, **old.decEAX}
		self.decEBX = {**self.decEBX, **old.decEBX}
		self.decECX = {**self.decECX, **old.decECX}
		self.decEDX = {**self.decEDX, **old.decEDX}
		self.decESI = {**self.decESI, **old.decESI}
		self.decEDI = {**self.decEDI, **old.decEDI}
		self.decEBP = {**self.decEBP, **old.decEBP}
		self.decESP = {**self.decESP, **old.decESP}
		self.addEAX = {**self.addEAX, **old.addEAX}
		self.addEBX = {**self.addEBX, **old.addEBX}
		self.addECX = {**self.addECX, **old.addECX}
		self.addEDX = {**self.addEDX, **old.addEDX}
		self.addESI = {**self.addESI, **old.addESI}
		self.addEDI = {**self.addEDI, **old.addEDI}
		self.addEBP = {**self.addEBP, **old.addEBP}
		self.addESP = {**self.addESP, **old.addESP}
		self.addESPVal = {**self.addESPVal, **old.addESPVal}
		self.addFS = {**self.addFS, **old.addFS}
		self.subFS = {**self.subFS, **old.subFS}
		self.xorFS = {**self.xorFS, **old.xorFS}
		self.xchgFS = {**self.xchgFS, **old.xchgFS}
		self.add = {**self.add, **old.add}
		self.addDword = {**self.addDword, **old.addDword}
		self.addDwordEAX = {**self.addDwordEAX, **old.addDwordEAX}
		self.addDwordEBX = {**self.addDwordEBX, **old.addDwordEBX}
		self.addDwordECX = {**self.addDwordECX, **old.addDwordECX}
		self.addDwordEDX = {**self.addDwordEDX, **old.addDwordEDX}
		self.addDwordESI = {**self.addDwordESI, **old.addDwordESI}
		self.addDwordEDI = {**self.addDwordEDI, **old.addDwordEDI}
		self.addDwordEBP = {**self.addDwordEBP, **old.addDwordEBP}
		self.addDwordESP = {**self.addDwordESP, **old.addDwordESP}
		self.subEAX = {**self.subEAX, **old.subEAX}
		self.subEBX = {**self.subEBX, **old.subEBX}
		self.subECX = {**self.subECX, **old.subECX}
		self.subEDX = {**self.subEDX, **old.subEDX}
		self.subESI = {**self.subESI, **old.subESI}
		self.subEDI = {**self.subEDI, **old.subEDI}
		self.subEBP = {**self.subEBP, **old.subEBP}
		self.subESP = {**self.subESP, **old.subESP}
		self.sub = {**self.sub, **old.sub}
		self.subDword = {**self.subDword, **old.subDword}
		self.subDwordEAX = {**self.subDwordEAX, **old.subDwordEAX}
		self.subDwordEBX = {**self.subDwordEBX, **old.subDwordEBX}
		self.subDwordECX = {**self.subDwordECX, **old.subDwordECX}
		self.subDwordEDX = {**self.subDwordEDX, **old.subDwordEDX}
		self.subDwordESI = {**self.subDwordESI, **old.subDwordESI}
		self.subDwordEDI = {**self.subDwordEDI, **old.subDwordEDI}
		self.subDwordEBP = {**self.subDwordEBP, **old.subDwordEBP}
		self.subDwordESP = {**self.subDwordESP, **old.subDwordESP}
		self.mulEAX = {**self.mulEAX, **old.mulEAX}
		self.mulEBX = {**self.mulEBX, **old.mulEBX}
		self.mulECX = {**self.mulECX, **old.mulECX}
		self.mulEDX = {**self.mulEDX, **old.mulEDX}
		self.mulESI = {**self.mulESI, **old.mulESI}
		self.mulEDI = {**self.mulEDI, **old.mulEDI}
		self.mulEBP = {**self.mulEBP, **old.mulEBP}
		self.mulESP = {**self.mulESP, **old.mulESP}
		self.mul = {**self.mul, **old.mul}
		self.divEAX = {**self.divEAX, **old.divEAX}
		self.divEBX = {**self.divEBX, **old.divEBX}
		self.divECX = {**self.divECX, **old.divECX}
		self.divEDX = {**self.divEDX, **old.divEDX}
		self.divESI = {**self.divESI, **old.divESI}
		self.divEDI = {**self.divEDI, **old.divEDI}
		self.divEBP = {**self.divEBP, **old.divEBP}
		self.divESP = {**self.divESP, **old.divESP}
		self.div = {**self.div, **old.div}
		self.leaEAX = {**self.leaEAX, **old.leaEAX}
		self.leaEBX = {**self.leaEBX, **old.leaEBX}
		self.leaECX = {**self.leaECX, **old.leaECX}
		self.leaEDX = {**self.leaEDX, **old.leaEDX}
		self.leaESI = {**self.leaESI, **old.leaESI}
		self.leaEDI = {**self.leaEDI, **old.leaEDI}
		self.leaEBP = {**self.leaEBP, **old.leaEBP}
		self.leaESP = {**self.leaESP, **old.leaESP}
		self.lea  = {**self.lea , **old.lea }
		self.movEAX = {**self.movEAX, **old.movEAX}
		self.movEBX = {**self.movEBX, **old.movEBX}
		self.movECX = {**self.movECX, **old.movECX}
		self.movEDX = {**self.movEDX, **old.movEDX}
		self.movESI = {**self.movESI, **old.movESI}
		self.movEDI = {**self.movEDI, **old.movEDI}
		self.movEBP = {**self.movEBP, **old.movEBP}
		self.movESP = {**self.movESP, **old.movESP}
		self.movFS = {**self.movFS, **old.movFS}
		self.movFSEAX = {**self.movFSEAX, **old.movFSEAX}
		self.movFSEBX = {**self.movFSEBX, **old.movFSEBX}
		self.movFSECX = {**self.movFSECX, **old.movFSECX}
		self.movFSEDX = {**self.movFSEDX, **old.movFSEDX}
		self.movFSEDI = {**self.movFSEDI, **old.movFSEDI}
		self.movFSESI = {**self.movFSESI, **old.movFSESI}
		self.movFSEBP = {**self.movFSEBP, **old.movFSEBP}
		self.movFSESP = {**self.movFSESP, **old.movFSESP}
		self.addFSEAX = {**self.addFSEAX,**old.addFSEAX}
		self.addFSEBX = {**self.addFSEBX,**old.addFSEBX}
		self.addFSECX = {**self.addFSECX,**old.addFSECX}
		self.addFSEDX = {**self.addFSEDX,**old.addFSEDX}
		self.addFSEDI = {**self.addFSEDI,**old.addFSEDI}
		self.addFSESI = {**self.addFSESI,**old.addFSESI}
		self.addFSEBP = {**self.addFSEBP,**old.addFSEBP}
		self.addFSESP = {**self.addFSESP,**old.addFSESP}
		self.subFSEAX = {**self.subFSEAX,**old.subFSEAX}
		self.subFSEBX = {**self.subFSEBX,**old.subFSEBX}
		self.subFSECX = {**self.subFSECX,**old.subFSECX}
		self.subFSEDX = {**self.subFSEDX,**old.subFSEDX}
		self.subFSEDI = {**self.subFSEDI,**old.subFSEDI}
		self.subFSESI = {**self.subFSESI,**old.subFSESI}
		self.subFSEBP = {**self.subFSEBP,**old.subFSEBP}
		self.subFSESP = {**self.subFSESP,**old.subFSESP}
		self.xorFSEAX = {**self.xorFSEAX,**old.xorFSEAX}
		self.xorFSEBX = {**self.xorFSEBX,**old.xorFSEBX}
		self.xorFSECX = {**self.xorFSECX,**old.xorFSECX}
		self.xorFSEDX = {**self.xorFSEDX,**old.xorFSEDX}
		self.xorFSEDI = {**self.xorFSEDI,**old.xorFSEDI}
		self.xorFSESI = {**self.xorFSESI,**old.xorFSESI}
		self.xorFSEBP = {**self.xorFSEBP,**old.xorFSEBP}
		self.xorFSESP = {**self.xorFSESP,**old.xorFSESP}
		self.xchgFSEAX = {**self.xchgFSEAX,**old.xchgFSEAX}
		self.xchgFSEBX = {**self.xchgFSEBX,**old.xchgFSEBX}
		self.xchgFSECX = {**self.xchgFSECX,**old.xchgFSECX}
		self.xchgFSEDX = {**self.xchgFSEDX,**old.xchgFSEDX}
		self.xchgFSEDI = {**self.xchgFSEDI,**old.xchgFSEDI}
		self.xchgFSESI = {**self.xchgFSESI,**old.xchgFSESI}
		self.xchgFSEBP = {**self.xchgFSEBP,**old.xchgFSEBP}
		self.xchgFSESP = {**self.xchgFSESP,**old.xchgFSESP}
		self.mov = {**self.mov, **old.mov}
		self.movDwordEAX = {**self.movDwordEAX, **old.movDwordEAX}
		self.movDwordEBX = {**self.movDwordEBX, **old.movDwordEBX}
		self.movDwordECX = {**self.movDwordECX, **old.movDwordECX}
		self.movDwordEDX = {**self.movDwordEDX, **old.movDwordEDX}
		self.movDwordESI = {**self.movDwordESI, **old.movDwordESI}
		self.movDwordEDI = {**self.movDwordEDI, **old.movDwordEDI}
		self.movDwordEBP = {**self.movDwordEBP, **old.movDwordEBP}
		self.movDwordESP = {**self.movDwordESP, **old.movDwordESP}
		self.movDword = {**self.movDword, **old.movDword}
		self.movDword2EAX = {**self.movDword2EAX, **old.movDword2EAX}
		self.movDword2EBX = {**self.movDword2EBX, **old.movDword2EBX}
		self.movDword2ECX = {**self.movDword2ECX, **old.movDword2ECX}
		self.movDword2EDX = {**self.movDword2EDX, **old.movDword2EDX}
		self.movDword2ESI = {**self.movDword2ESI, **old.movDword2ESI}
		self.movDword2EDI = {**self.movDword2EDI, **old.movDword2EDI}
		self.movDword2EBP = {**self.movDword2EBP, **old.movDword2EBP}
		self.movDword2ESP = {**self.movDword2ESP, **old.movDword2ESP}
		self.movDword2 = {**self.movDword2, **old.movDword2}
		self.xchgEAX = {**self.xchgEAX, **old.xchgEAX}
		self.xchgEBX = {**self.xchgEBX, **old.xchgEBX}
		self.xchgECX = {**self.xchgECX, **old.xchgECX}
		self.xchgEDX = {**self.xchgEDX, **old.xchgEDX}
		self.xchgESI = {**self.xchgESI, **old.xchgESI}
		self.xchgEDI = {**self.xchgEDI, **old.xchgEDI}
		self.xchgEBP = {**self.xchgEBP, **old.xchgEBP}
		self.xchgESP = {**self.xchgESP, **old.xchgESP}
		self.xchg = {**self.xchg, **old.xchg}
		self.movConstantEAX = {**self.movConstantEAX, **old.movConstantEAX}
		self.movConstantEBX = {**self.movConstantEBX, **old.movConstantEBX}
		self.movConstantECX = {**self.movConstantECX, **old.movConstantECX}
		self.movConstantEDX = {**self.movConstantEDX, **old.movConstantEDX}
		self.movConstantESI = {**self.movConstantESI, **old.movConstantESI}
		self.movConstantEDI = {**self.movConstantEDI, **old.movConstantEDI}
		self.movConstantEBP = {**self.movConstantEBP, **old.movConstantEBP}
		self.movConstantESP = {**self.movConstantESP, **old.movConstantESP}
		self.movConstant = {**self.movConstant, **old.movConstant}
		self.negEAX = {**self.negEAX, **old.negEAX}
		self.negEBX = {**self.negEBX, **old.negEBX}
		self.negECX = {**self.negECX, **old.negECX}
		self.negEDX = {**self.negEDX, **old.negEDX}
		self.negESI = {**self.negESI, **old.negESI}
		self.negEDI = {**self.negEDI, **old.negEDI}
		self.negEBP = {**self.negEBP, **old.negEBP}
		self.negESP = {**self.negESP, **old.negESP}
		self.neg = {**self.neg, **old.neg}
		self.xorEAX = {**self.xorEAX, **old.xorEAX}
		self.xorEBX = {**self.xorEBX, **old.xorEBX}
		self.xorECX = {**self.xorECX, **old.xorECX}
		self.xorEDX = {**self.xorEDX, **old.xorEDX}
		self.xorESI = {**self.xorESI, **old.xorESI}
		self.xorEDI = {**self.xorEDI, **old.xorEDI}
		self.xorEBP = {**self.xorEBP, **old.xorEBP}
		self.xorESP = {**self.xorESP, **old.xorESP}
		self.xor = {**self.xor, **old.xor}
		self.xorDwordEAX = {**self.xorDwordEAX, **old.xorDwordEAX}
		self.xorDwordEBX = {**self.xorDwordEBX, **old.xorDwordEBX}
		self.xorDwordECX = {**self.xorDwordECX, **old.xorDwordECX}
		self.xorDwordEDX = {**self.xorDwordEDX, **old.xorDwordEDX}
		self.xorDwordESI = {**self.xorDwordESI, **old.xorDwordESI}
		self.xorDwordEDI = {**self.xorDwordEDI, **old.xorDwordEDI}
		self.xorDwordEBP = {**self.xorDwordEBP, **old.xorDwordEBP}
		self.xorDwordESP = {**self.xorDwordESP, **old.xorDwordESP}
		self.xorDword = {**self.xorDword, **old.xorDword}
		self.xorZeroEAX = {**self.xorZeroEAX, **old.xorZeroEAX}
		self.xorZeroEBX = {**self.xorZeroEBX, **old.xorZeroEBX}
		self.xorZeroECX = {**self.xorZeroECX, **old.xorZeroECX}
		self.xorZeroEDX = {**self.xorZeroEDX, **old.xorZeroEDX}
		self.xorZeroESI = {**self.xorZeroESI, **old.xorZeroESI}
		self.xorZeroEDI = {**self.xorZeroEDI, **old.xorZeroEDI}
		self.xorZeroEBP = {**self.xorZeroEBP, **old.xorZeroEBP}
		self.xorZeroESP = {**self.xorZeroESP, **old.xorZeroESP}
		self.xorZero = {**self.xorZero, **old.xorZero}
		self.pushad = {**self.pushad, **old.pushad}
		self.popal = {**self.popal, **old.popal}
		self.syscall64 = {**self.syscall64, **old.syscall64}
		self.rdgsbase64 = {**self.rdgsbase64, **old.rdgsbase64}
		self.shl = {**self.shl, **old.shl}
		self.shr = {**self.shr, **old.shr}
		self.shlDword = {**self.shlDword, **old.shlDword}
		self.shrDword = {**self.shrDword, **old.shrDword}
		self.rcl = {**self.rcl, **old.rcl}
		self.rcr = {**self.rcr, **old.rcr}
		self.rclDword = {**self.rclDword, **old.rclDword}
		self.rcrDword = {**self.rcrDword, **old.rcrDword}
		self.unusual = {**self.unusual, **old.unusual}
		self.andInstEAX = {**self.andInstEAX, **old.andInstEAX}
		self.andInstEBX = {**self.andInstEBX, **old.andInstEBX}
		self.andInstECX = {**self.andInstECX, **old.andInstECX}
		self.andInstEDX = {**self.andInstEDX, **old.andInstEDX}
		self.andInstESI = {**self.andInstESI, **old.andInstESI}
		self.andInstEDI = {**self.andInstEDI, **old.andInstEDI}
		self.andInstEBP = {**self.andInstEBP, **old.andInstEBP}
		self.andInstESP = {**self.andInstESP, **old.andInstESP}
		self.andInst = {**self.andInst, **old.andInst}
		self.andInstOther = {**self.andInstOther, **old.andInstOther}
		self.notInstEAX = {**self.notInstEAX, **old.notInstEAX}
		self.notInstEBX = {**self.notInstEBX, **old.notInstEBX}
		self.notInstECX = {**self.notInstECX, **old.notInstECX}
		self.notInstEDX = {**self.notInstEDX, **old.notInstEDX}
		self.notInstESI = {**self.notInstESI, **old.notInstESI}
		self.notInstEDI = {**self.notInstEDI, **old.notInstEDI}
		self.notInstEBP = {**self.notInstEBP, **old.notInstEBP}
		self.notInstESP = {**self.notInstESP, **old.notInstESP}
		self.notInst = {**self.notInst, **old.notInst}
		self.notInstOther = {**self.notInstOther, **old.notInstOther}
		self.fs = {**self.fs, **old.fs}
		self.fsSpecial = {**self.fsSpecial, **old.fsSpecial}
		self.retfSingle = {**self.retfSingle, **old.retfSingle}
		self.hgGadgets = {**self.hgGadgets, **old.hgGadgets}
		self.hgPush = {**self.hgPush, **old.hgPush}
		self.hgPushEAX = {**self.hgPushEAX, **old.hgPushEAX}
		self.hgPushEBX = {**self.hgPushEBX, **old.hgPushEBX}
		self.hgPushECX = {**self.hgPushECX, **old.hgPushECX}
		self.hgPushEDX = {**self.hgPushEDX, **old.hgPushEDX}
		self.hgPushESI = {**self.hgPushESI, **old.hgPushESI}
		self.hgPushEDI = {**self.hgPushEDI, **old.hgPushEDI}
		self.hgPushEBP = {**self.hgPushEBP, **old.hgPushEBP}
		self.hgPushESP = {**self.hgPushESP, **old.hgPushESP}
		self.hgPushDwordFS = {**self.hgPushDwordFS, **old.hgPushDwordFS}
		self.hgPushDwordEAX = {**self.hgPushDwordEAX, **old.hgPushDwordEAX}
		self.hgPushDwordEBX = {**self.hgPushDwordEBX, **old.hgPushDwordEBX}
		self.hgPushDwordECX = {**self.hgPushDwordECX, **old.hgPushDwordECX}
		self.hgPushDwordEDX = {**self.hgPushDwordEDX, **old.hgPushDwordEDX}
		self.hgPushDwordESI = {**self.hgPushDwordESI, **old.hgPushDwordESI}
		self.hgPushDwordEDI = {**self.hgPushDwordEDI, **old.hgPushDwordEDI}
		self.hgPushDwordEBP = {**self.hgPushDwordEBP, **old.hgPushDwordEBP}
		self.hgPushDwordESP = {**self.hgPushDwordESP, **old.hgPushDwordESP}
		self.hgPushDword = {**self.hgPushDword, **old.hgPushDword}
		self.hgPushDwordOther = {**self.hgPushDwordOther, **old.hgPushDwordOther}
		self.hgPushConstant = {**self.hgPushConstant, **old.hgPushConstant}
		self.hgPushDword = {**self.hgPushDword, **old.hgPushDword}
		self.hgPushOther = {**self.hgPushOther, **old.hgPushOther}
		self.retfSingle = {**self.retfSingle, **old.retfSingle}

		###64 bit
		self.jmpRSI = {**self.jmpRSI, **old.jmpRSI}
		self.jmpRBP = {**self.jmpRBP, **old.jmpRBP}
		self.jmpRDI = {**self.jmpRDI, **old.jmpRDI}
		self.jmpRAX = {**self.jmpRAX, **old.jmpRAX}
		self.jmpRBX = {**self.jmpRBX, **old.jmpRBX}
		self.jmpRSP = {**self.jmpRSP, **old.jmpRSP}
		self.jmpRCX = {**self.jmpRCX, **old.jmpRCX}
		self.jmpRDX = {**self.jmpRDX, **old.jmpRDX}
		self.jmpR8 = {**self.jmpR8, **old.jmpR8}
		self.jmpR9 = {**self.jmpR9, **old.jmpR9}
		self.jmpR10 = {**self.jmpR10, **old.jmpR10}
		self.jmpR11 = {**self.jmpR11, **old.jmpR11}
		self.jmpR12 = {**self.jmpR12, **old.jmpR12}
		self.jmpR13 = {**self.jmpR13, **old.jmpR13}
		self.jmpR14 = {**self.jmpR14, **old.jmpR14}
		self.jmpR15 = {**self.jmpR15, **old.jmpR15}
		self.jmpQwordRBP = {**self.jmpQwordRBP, **old.jmpQwordRBP}
		self.jmpQwordOffsetRBP = {**self.jmpQwordOffsetRBP, **old.jmpQwordOffsetRBP}
		self.jmpQwordRSP = {**self.jmpQwordRSP, **old.jmpQwordRSP}
		self.jmpQwordOffsetRSP = {**self.jmpQwordOffsetRSP, **old.jmpQwordOffsetRSP}
		self.jmpQwordRDI = {**self.jmpQwordRDI, **old.jmpQwordRDI}
		self.jmpQwordOffsetRDI = {**self.jmpQwordOffsetRDI, **old.jmpQwordOffsetRDI}
		self.jmpQwordRSI = {**self.jmpQwordRSI, **old.jmpQwordRSI}
		self.jmpQwordOffsetRSI = {**self.jmpQwordOffsetRSI, **old.jmpQwordOffsetRSI}
		self.jmpQwordRAX = {**self.jmpQwordRAX, **old.jmpQwordRAX}
		self.jmpQwordOffsetRAX = {**self.jmpQwordOffsetRAX, **old.jmpQwordOffsetRAX}
		self.jmpQwordRBX = {**self.jmpQwordRBX, **old.jmpQwordRBX}
		self.jmpQwordOffsetRBX = {**self.jmpQwordOffsetRBX, **old.jmpQwordOffsetRBX}
		self.jmpQwordRCX = {**self.jmpQwordRCX, **old.jmpQwordRCX}
		self.jmpQwordOffsetRCX = {**self.jmpQwordOffsetRCX, **old.jmpQwordOffsetRCX}
		self.jmpQwordRDX = {**self.jmpQwordRDX, **old.jmpQwordRDX}
		self.jmpQwordOffsetRDX = {**self.jmpQwordOffsetRDX, **old.jmpQwordOffsetRDX}
		self.jmpQwordR8 = {**self.jmpQwordR8, **old.jmpQwordR8}
		self.jmpQwordOffsetR8 = {**self.jmpQwordOffsetR8, **old.jmpQwordOffsetR8}
		self.jmpQwordR9 = {**self.jmpQwordR9, **old.jmpQwordR9}
		self.jmpQwordOffsetR9 = {**self.jmpQwordOffsetR9, **old.jmpQwordOffsetR9}
		self.jmpQwordR10 = {**self.jmpQwordR10, **old.jmpQwordR10}
		self.jmpQwordOffsetR10 = {**self.jmpQwordOffsetR10, **old.jmpQwordOffsetR10}
		self.jmpQwordR11 = {**self.jmpQwordR11, **old.jmpQwordR11}
		self.jmpQwordOffsetR11 = {**self.jmpQwordOffsetR11, **old.jmpQwordOffsetR11}
		self.jmpQwordR12 = {**self.jmpQwordR12, **old.jmpQwordR12}
		self.jmpQwordOffsetR12 = {**self.jmpQwordOffsetR12, **old.jmpQwordOffsetR12}
		self.jmpQwordR13 = {**self.jmpQwordR13, **old.jmpQwordR13}
		self.jmpQwordOffsetR13 = {**self.jmpQwordOffsetR13, **old.jmpQwordOffsetR13}
		self.jmpQwordR14 = {**self.jmpQwordR14, **old.jmpQwordR14}
		self.jmpQwordOffsetR14 = {**self.jmpQwordOffsetR14, **old.jmpQwordOffsetR14}
		self.jmpQwordR15 = {**self.jmpQwordR15, **old.jmpQwordR15}
		self.jmpQwordOffsetR15 = {**self.jmpQwordOffsetR15, **old.jmpQwordOffsetR15}
		self.callRSI = {**self.callRSI, **old.callRSI}
		self.callRBP = {**self.callRBP, **old.callRBP}
		self.callRDI = {**self.callRDI, **old.callRDI}
		self.callRAX = {**self.callRAX, **old.callRAX}
		self.callRBX = {**self.callRBX, **old.callRBX}
		self.callRSP = {**self.callRSP, **old.callRSP}
		self.callRCX = {**self.callRCX, **old.callRCX}
		self.callRDX = {**self.callRDX, **old.callRDX}
		self.callR8 = {**self.callR8, **old.callR8}
		self.callR9 = {**self.callR9, **old.callR9}
		self.callR10 = {**self.callR10, **old.callR10}
		self.callR11 = {**self.callR11, **old.callR11}
		self.callR12 = {**self.callR12, **old.callR12}
		self.callR13 = {**self.callR13, **old.callR13}
		self.callR14 = {**self.callR14, **old.callR14}
		self.callR15 = {**self.callR15, **old.callR15}
		self.callQwordRBP = {**self.callQwordRBP, **old.callQwordRBP}
		self.callQwordOffsetRBP = {**self.callQwordOffsetRBP, **old.callQwordOffsetRBP}
		self.callQwordRSP = {**self.callQwordRSP, **old.callQwordRSP}
		self.callQwordOffsetRSP = {**self.callQwordOffsetRSP, **old.callQwordOffsetRSP}
		self.callQwordRDI = {**self.callQwordRDI, **old.callQwordRDI}
		self.callQwordOffsetRDI = {**self.callQwordOffsetRDI, **old.callQwordOffsetRDI}
		self.callQwordRSI = {**self.callQwordRSI, **old.callQwordRSI}
		self.callQwordOffsetRSI = {**self.callQwordOffsetRSI, **old.callQwordOffsetRSI}
		self.callQwordRAX = {**self.callQwordRAX, **old.callQwordRAX}
		self.callQwordOffsetRAX = {**self.callQwordOffsetRAX, **old.callQwordOffsetRAX}
		self.callQwordRBX = {**self.callQwordRBX, **old.callQwordRBX}
		self.callQwordOffsetRBX = {**self.callQwordOffsetRBX, **old.callQwordOffsetRBX}
		self.callQwordRCX = {**self.callQwordRCX, **old.callQwordRCX}
		self.callQwordOffsetRCX = {**self.callQwordOffsetRCX, **old.callQwordOffsetRCX}
		self.callQwordRDX = {**self.callQwordRDX, **old.callQwordRDX}
		self.callQwordOffsetRDX = {**self.callQwordOffsetRDX, **old.callQwordOffsetRDX}
		self.callQwordR8 = {**self.callQwordR8, **old.callQwordR8}
		self.callQwordOffsetR8 = {**self.callQwordOffsetR8, **old.callQwordOffsetR8}
		self.callQwordR9 = {**self.callQwordR9, **old.callQwordR9}
		self.callQwordOffsetR9 = {**self.callQwordOffsetR9, **old.callQwordOffsetR9}
		self.callQwordR10 = {**self.callQwordR10, **old.callQwordR10}
		self.callQwordOffsetR10 = {**self.callQwordOffsetR10, **old.callQwordOffsetR10}
		self.callQwordR11 = {**self.callQwordR11, **old.callQwordR11}
		self.callQwordOffsetR11 = {**self.callQwordOffsetR11, **old.callQwordOffsetR11}
		self.callQwordR12 = {**self.callQwordR12, **old.callQwordR12}
		self.callQwordOffsetR12 = {**self.callQwordOffsetR12, **old.callQwordOffsetR12}
		self.callQwordR13 = {**self.callQwordR13, **old.callQwordR13}
		self.callQwordOffsetR13 = {**self.callQwordOffsetR13, **old.callQwordOffsetR13}
		self.callQwordR14 = {**self.callQwordR14, **old.callQwordR14}
		self.callQwordOffsetR14 = {**self.callQwordOffsetR14, **old.callQwordOffsetR14}
		self.callQwordR15 = {**self.callQwordR15, **old.callQwordR15}
		self.callQwordOffsetR15 = {**self.callQwordOffsetR15, **old.callQwordOffsetR15}
		self.retfSingle64 = {**self.retfSingle64, **old.retfSingle64}
		self.pops64 = {**self.pops64, **old.pops64}
		self.popRSI = {**self.popRSI, **old.popRSI}
		self.popRBX = {**self.popRBX, **old.popRBX}
		self.popRCX = {**self.popRCX, **old.popRCX}
		self.popRAX = {**self.popRAX, **old.popRAX}
		self.popRDI = {**self.popRDI, **old.popRDI}
		self.popRBP = {**self.popRBP, **old.popRBP}
		self.popRSP = {**self.popRSP, **old.popRSP}
		self.popRDX = {**self.popRDX, **old.popRDX}
		self.popR8 = {**self.popR8, **old.popR8}
		self.popR9 = {**self.popR9, **old.popR9}
		self.popR10 = {**self.popR10, **old.popR10}
		self.popR11 = {**self.popR11, **old.popR11}
		self.popR12 = {**self.popR12, **old.popR12}
		self.popR13 = {**self.popR13, **old.popR13}
		self.popR14 = {**self.popR14, **old.popR14}
		self.popR15 = {**self.popR15, **old.popR15}
		self.popOther64 = {**self.popOther64, **old.popOther64}
		self.popQword = {**self.popQword, **old.popQword}
		self.popQwordRAX = {**self.popQwordRAX, **old.popQwordRAX}
		self.popQwordRBX = {**self.popQwordRBX, **old.popQwordRBX}
		self.popQwordRCX = {**self.popQwordRCX, **old.popQwordRCX}
		self.popQwordRDX = {**self.popQwordRDX, **old.popQwordRDX}
		self.popQwordRSI = {**self.popQwordRSI, **old.popQwordRSI}
		self.popQwordRDI = {**self.popQwordRDI, **old.popQwordRDI}
		self.popQwordRSP = {**self.popQwordRSP, **old.popQwordRSP}
		self.popQwordRBP = {**self.popQwordRBP, **old.popQwordRBP}
		self.popQwordR8 = {**self.popQwordR8, **old.popQwordR8}
		self.popQwordR9 = {**self.popQwordR9, **old.popQwordR9}
		self.popQwordR10 = {**self.popQwordR10, **old.popQwordR10}
		self.popQwordR11 = {**self.popQwordR11, **old.popQwordR11}
		self.popQwordR12 = {**self.popQwordR12, **old.popQwordR12}
		self.popQwordR13 = {**self.popQwordR13, **old.popQwordR13}
		self.popQwordR14 = {**self.popQwordR14, **old.popQwordR14}
		self.popQwordR15 = {**self.popQwordR15, **old.popQwordR15}
		self.popQwordOther = {**self.popQwordOther, **old.popQwordOther}
		self.hgPush64 = {**self.hgPush64, **old.hgPush64}
		self.hgPushRAX = {**self.hgPushRAX, **old.hgPushRAX}
		self.hgPushRBX = {**self.hgPushRBX, **old.hgPushRBX}
		self.hgPushRCX = {**self.hgPushRCX, **old.hgPushRCX}
		self.hgPushRBP = {**self.hgPushRBP, **old.hgPushRBP}
		self.hgPushRSP = {**self.hgPushRSP, **old.hgPushRSP}
		self.hgPushRDX = {**self.hgPushRDX, **old.hgPushRDX}
		self.hgPushRDI = {**self.hgPushRDI, **old.hgPushRDI}
		self.hgPushRSI = {**self.hgPushRSI, **old.hgPushRSI}
		self.hgPushConstant64 = {**self.hgPushConstant64, **old.hgPushConstant64}
		self.hgPushR8 = {**self.hgPushR8, **old.hgPushR8}
		self.hgPushR9 = {**self.hgPushR9, **old.hgPushR9}
		self.hgPushR10 = {**self.hgPushR10, **old.hgPushR10}
		self.hgPushR11 = {**self.hgPushR11, **old.hgPushR11}
		self.hgPushR12 = {**self.hgPushR12, **old.hgPushR12}
		self.hgPushR13 = {**self.hgPushR13, **old.hgPushR13}
		self.hgPushR14 = {**self.hgPushR14, **old.hgPushR14}
		self.hgPushR15 = {**self.hgPushR15, **old.hgPushR15}
		self.hgPushOther64 = {**self.hgPushOther64, **old.hgPushOther64}
		self.hgPushQword = {**self.hgPushQword, **old.hgPushQword}
		self.hgPushQwordRAX = {**self.hgPushQwordRAX, **old.hgPushQwordRAX}
		self.hgPushQwordRBX = {**self.hgPushQwordRBX, **old.hgPushQwordRBX}
		self.hgPushQwordRCX = {**self.hgPushQwordRCX, **old.hgPushQwordRCX}
		self.hgPushQwordRDX = {**self.hgPushQwordRDX, **old.hgPushQwordRDX}
		self.hgPushQwordRSI = {**self.hgPushQwordRSI, **old.hgPushQwordRSI}
		self.hgPushQwordRDI = {**self.hgPushQwordRDI, **old.hgPushQwordRDI}
		self.hgPushQwordRSP = {**self.hgPushQwordRSP, **old.hgPushQwordRSP}
		self.hgPushQwordRBP = {**self.hgPushQwordRBP, **old.hgPushQwordRBP}
		self.hgPushQwordR8 = {**self.hgPushQwordR8, **old.hgPushQwordR8}
		self.hgPushQwordR9 = {**self.hgPushQwordR9, **old.hgPushQwordR9}
		self.hgPushQwordR10 = {**self.hgPushQwordR10, **old.hgPushQwordR10}
		self.hgPushQwordR11 = {**self.hgPushQwordR11, **old.hgPushQwordR11}
		self.hgPushQwordR12 = {**self.hgPushQwordR12, **old.hgPushQwordR12}
		self.hgPushQwordR13 = {**self.hgPushQwordR13, **old.hgPushQwordR13}
		self.hgPushQwordR14 = {**self.hgPushQwordR14, **old.hgPushQwordR14}
		self.hgPushQwordR15 = {**self.hgPushQwordR15, **old.hgPushQwordR15}
		self.hgPushQwordOther = {**self.hgPushQwordOther, **old.hgPushQwordOther}
		self.ret64 = {**self.ret64, **old.ret64}
		self.retC264 = {**self.retC264, **old.retC264}
		self.push64 = {**self.push64, **old.push64}
		self.pushRAX = {**self.pushRAX, **old.pushRAX}
		self.pushRBX = {**self.pushRBX, **old.pushRBX}
		self.pushRCX = {**self.pushRCX, **old.pushRCX}
		self.pushRBP = {**self.pushRBP, **old.pushRBP}
		self.pushRSP = {**self.pushRSP, **old.pushRSP}
		self.pushRDX = {**self.pushRDX, **old.pushRDX}
		self.pushRDI = {**self.pushRDI, **old.pushRDI}
		self.pushRSI = {**self.pushRSI, **old.pushRSI}
		self.pushR8 = {**self.pushR8, **old.pushR8}
		self.pushR9 = {**self.pushR9, **old.pushR9}
		self.pushR10 = {**self.pushR10, **old.pushR10}
		self.pushR11 = {**self.pushR11, **old.pushR11}
		self.pushR12 = {**self.pushR12, **old.pushR12}
		self.pushR13 = {**self.pushR13, **old.pushR13}
		self.pushR14 = {**self.pushR14, **old.pushR14}
		self.pushR15 = {**self.pushR15, **old.pushR15}
		self.pushConstant64 = {**self.pushConstant64, **old.pushConstant64}
		self.pushOther64 = {**self.pushOther64, **old.pushOther64}
		self.pushQwordGS = {**self.pushQwordGS, **old.pushQwordGS}
		self.pushQwordGSRAX = {**self.pushQwordGSRAX, **old.pushQwordGSRAX}
		self.pushQwordGSRBX = {**self.pushQwordGSRBX, **old.pushQwordGSRBX}
		self.pushQwordGSRCX = {**self.pushQwordGSRCX, **old.pushQwordGSRCX}
		self.pushQwordGSRDX = {**self.pushQwordGSRDX, **old.pushQwordGSRDX}
		self.pushQwordGSRDI = {**self.pushQwordGSRDI, **old.pushQwordGSRDI}
		self.pushQwordGSRSI = {**self.pushQwordGSRSI, **old.pushQwordGSRSI}
		self.pushQwordGSRBP = {**self.pushQwordGSRBP, **old.pushQwordGSRBP}
		self.pushQwordGSR8 = {**self.pushQwordGSR8, **old.pushQwordGSR8}
		self.pushQwordGSR9 = {**self.pushQwordGSR9, **old.pushQwordGSR9}
		self.pushQwordGSR10 = {**self.pushQwordGSR10, **old.pushQwordGSR10}
		self.pushQwordGSR11 = {**self.pushQwordGSR11, **old.pushQwordGSR11}
		self.pushQwordGSR12 = {**self.pushQwordGSR12, **old.pushQwordGSR12}
		self.pushQwordGSR13 = {**self.pushQwordGSR13, **old.pushQwordGSR13}
		self.pushQwordGSR14 = {**self.pushQwordGSR14, **old.pushQwordGSR14}
		self.pushQwordGSR15 = {**self.pushQwordGSR15, **old.pushQwordGSR15}
		self.pushQword64 = {**self.pushQword64, **old.pushQword64}
		self.pushQwordRAX = {**self.pushQwordRAX, **old.pushQwordRAX}
		self.pushQwordRBX = {**self.pushQwordRBX, **old.pushQwordRBX}
		self.pushQwordRCX = {**self.pushQwordRCX, **old.pushQwordRCX}
		self.pushQwordRDX = {**self.pushQwordRDX, **old.pushQwordRDX}
		self.pushQwordRSI = {**self.pushQwordRSI, **old.pushQwordRSI}
		self.pushQwordRDI = {**self.pushQwordRDI, **old.pushQwordRDI}
		self.pushQwordRSP = {**self.pushQwordRSP, **old.pushQwordRSP}
		self.pushQwordRBP = {**self.pushQwordRBP, **old.pushQwordRBP}
		self.pushQwordR8 = {**self.pushQwordR8, **old.pushQwordR8}
		self.pushQwordR9 = {**self.pushQwordR9, **old.pushQwordR9}
		self.pushQwordR10 = {**self.pushQwordR10, **old.pushQwordR10}
		self.pushQwordR11 = {**self.pushQwordR11, **old.pushQwordR11}
		self.pushQwordR12 = {**self.pushQwordR12, **old.pushQwordR12}
		self.pushQwordR13 = {**self.pushQwordR13, **old.pushQwordR13}
		self.pushQwordR14 = {**self.pushQwordR14, **old.pushQwordR14}
		self.pushQwordR15 = {**self.pushQwordR15, **old.pushQwordR15}
		self.pushQwordGS = {**self.pushQwordGS, **old.pushQwordGS}
		self.pushQwordOther = {**self.pushQwordOther, **old.pushQwordOther}
		self.inc64 = {**self.inc64, **old.inc64}
		self.incRSI = {**self.incRSI, **old.incRSI}
		self.incRBP = {**self.incRBP, **old.incRBP}
		self.incRDI = {**self.incRDI, **old.incRDI}
		self.incRAX = {**self.incRAX, **old.incRAX}
		self.incRBX = {**self.incRBX, **old.incRBX}
		self.incRSP = {**self.incRSP, **old.incRSP}
		self.incRCX = {**self.incRCX, **old.incRCX}
		self.incRDX = {**self.incRDX, **old.incRDX}
		self.incR8 = {**self.incR8, **old.incR8}
		self.incR9 = {**self.incR9, **old.incR9}
		self.incR10 = {**self.incR10, **old.incR10}
		self.incR11 = {**self.incR11, **old.incR11}
		self.incR12 = {**self.incR12, **old.incR12}
		self.incR13 = {**self.incR13, **old.incR13}
		self.incR14 = {**self.incR14, **old.incR14}
		self.incR15 = {**self.incR15, **old.incR15}
		self.dec64 = {**self.dec64, **old.dec64}
		self.decRSI = {**self.decRSI, **old.decRSI}
		self.decRBP = {**self.decRBP, **old.decRBP}
		self.decRDI = {**self.decRDI, **old.decRDI}
		self.decRAX = {**self.decRAX, **old.decRAX}
		self.decRBX = {**self.decRBX, **old.decRBX}
		self.decRSP = {**self.decRSP, **old.decRSP}
		self.decRCX = {**self.decRCX, **old.decRCX}
		self.decRDX = {**self.decRDX, **old.decRDX}
		self.decR8 = {**self.decR8, **old.decR8}
		self.decR9 = {**self.decR9, **old.decR9}
		self.decR10 = {**self.decR10, **old.decR10}
		self.decR11 = {**self.decR11, **old.decR11}
		self.decR12 = {**self.decR12, **old.decR12}
		self.decR13 = {**self.decR13, **old.decR13}
		self.decR14 = {**self.decR14, **old.decR14}
		self.decR15 = {**self.decR15, **old.decR15}
		self.add64 = {**self.add64, **old.add64}
		self.addRAX = {**self.addRAX, **old.addRAX}
		self.addRBX = {**self.addRBX, **old.addRBX}
		self.addRCX = {**self.addRCX, **old.addRCX}
		self.addRSP = {**self.addRSP, **old.addRSP}
		self.addRSPVal = {**self.addRSPVal, **old.addRSPVal}
		self.addRBP = {**self.addRBP, **old.addRBP}
		self.addRDX = {**self.addRDX, **old.addRDX}
		self.addRDI = {**self.addRDI, **old.addRDI}
		self.addRSI = {**self.addRSI, **old.addRSI}
		self.addR8 = {**self.addR8, **old.addR8}
		self.addR9 = {**self.addR9, **old.addR9}
		self.addR10 = {**self.addR10, **old.addR10}
		self.addR11 = {**self.addR11, **old.addR11}
		self.addR12 = {**self.addR12, **old.addR12}
		self.addR13 = {**self.addR13, **old.addR13}
		self.addR14 = {**self.addR14, **old.addR14}
		self.addR15 = {**self.addR15, **old.addR15}
		self.addQwordRAX = {**self.addQwordRAX, **old.addQwordRAX}
		self.addQwordRBX = {**self.addQwordRBX, **old.addQwordRBX}
		self.addQwordRCX = {**self.addQwordRCX, **old.addQwordRCX}
		self.addQwordRSP = {**self.addQwordRSP, **old.addQwordRSP}
		self.addQwordRBP = {**self.addQwordRBP, **old.addQwordRBP}
		self.addQwordRDX = {**self.addQwordRDX, **old.addQwordRDX}
		self.addQwordRDI = {**self.addQwordRDI, **old.addQwordRDI}
		self.addQwordRSI = {**self.addQwordRSI, **old.addQwordRSI}
		self.addQwordR8 = {**self.addQwordR8, **old.addQwordR8}
		self.addQwordR9 = {**self.addQwordR9, **old.addQwordR9}
		self.addQwordR10 = {**self.addQwordR10, **old.addQwordR10}
		self.addQwordR11 = {**self.addQwordR11, **old.addQwordR11}
		self.addQwordR12 = {**self.addQwordR12, **old.addQwordR12}
		self.addQwordR13 = {**self.addQwordR13, **old.addQwordR13}
		self.addQwordR14 = {**self.addQwordR14, **old.addQwordR14}
		self.addQwordR15 = {**self.addQwordR15, **old.addQwordR15}
		self.addGS = {**self.addGS, **old.addGS}
		self.sub64 = {**self.sub64, **old.sub64}
		self.subRAX = {**self.subRAX, **old.subRAX}
		self.subRBX = {**self.subRBX, **old.subRBX}
		self.subRCX = {**self.subRCX, **old.subRCX}
		self.subRDX = {**self.subRDX, **old.subRDX}
		self.subRSI = {**self.subRSI, **old.subRSI}
		self.subRDI = {**self.subRDI, **old.subRDI}
		self.subRSP = {**self.subRSP, **old.subRSP}
		self.subRBP = {**self.subRBP, **old.subRBP}
		self.subR8 = {**self.subR8, **old.subR8}
		self.subR9 = {**self.subR9, **old.subR9}
		self.subR10 = {**self.subR10, **old.subR10}
		self.subR11 = {**self.subR11, **old.subR11}
		self.subR12 = {**self.subR12, **old.subR12}
		self.subR13 = {**self.subR13, **old.subR13}
		self.subR14 = {**self.subR14, **old.subR14}
		self.subR15 = {**self.subR15, **old.subR15}
		self.subQwordRAX = {**self.subQwordRAX, **old.subQwordRAX}
		self.subQwordRBX = {**self.subQwordRBX, **old.subQwordRBX}
		self.subQwordRCX = {**self.subQwordRCX, **old.subQwordRCX}
		self.subQwordRDX = {**self.subQwordRDX, **old.subQwordRDX}
		self.subQwordRSI = {**self.subQwordRSI, **old.subQwordRSI}
		self.subQwordRDI = {**self.subQwordRDI, **old.subQwordRDI}
		self.subQwordRSP = {**self.subQwordRSP, **old.subQwordRSP}
		self.subQwordRBP = {**self.subQwordRBP, **old.subQwordRBP}
		self.subQwordR8 = {**self.subQwordR8, **old.subQwordR8}
		self.subQwordR9 = {**self.subQwordR9, **old.subQwordR9}
		self.subQwordR10 = {**self.subQwordR10, **old.subQwordR10}
		self.subQwordR11 = {**self.subQwordR11, **old.subQwordR11}
		self.subQwordR12 = {**self.subQwordR12, **old.subQwordR12}
		self.subQwordR13 = {**self.subQwordR13, **old.subQwordR13}
		self.subQwordR14 = {**self.subQwordR14, **old.subQwordR14}
		self.subQwordR15 = {**self.subQwordR15, **old.subQwordR15}
		self.subGS = {**self.subGS, **old.subGS}
		self.mul = {**self.mul, **old.mul}
		self.mulRAX = {**self.mulRAX, **old.mulRAX}
		self.mulRDX = {**self.mulRDX, **old.mulRDX}
		self.mulRAX = {**self.mulRAX, **old.mulRAX}
		self.mulRBX = {**self.mulRBX, **old.mulRBX}
		self.mulRCX = {**self.mulRCX, **old.mulRCX}
		self.mulRDX = {**self.mulRDX, **old.mulRDX}
		self.mulRSI = {**self.mulRSI, **old.mulRSI}
		self.mulRDI = {**self.mulRDI, **old.mulRDI}
		self.mulRSP = {**self.mulRSP, **old.mulRSP}
		self.mulRBP = {**self.mulRBP, **old.mulRBP}
		self.mulR8 = {**self.mulR8, **old.mulR8}
		self.mulR9 = {**self.mulR9, **old.mulR9}
		self.mulR10 = {**self.mulR10, **old.mulR10}
		self.mulR11 = {**self.mulR11, **old.mulR11}
		self.mulR12 = {**self.mulR12, **old.mulR12}
		self.mulR13 = {**self.mulR13, **old.mulR13}
		self.mulR14 = {**self.mulR14, **old.mulR14}
		self.mulR15 = {**self.mulR15, **old.mulR15}
		self.div = {**self.div, **old.div}
		self.divRAX = {**self.divRAX, **old.divRAX}
		self.divRDX = {**self.divRDX, **old.divRDX}
		self.lea = {**self.lea, **old.lea}
		self.leaRAX = {**self.leaRAX, **old.leaRAX}
		self.leaRBX = {**self.leaRBX, **old.leaRBX}
		self.leaRCX = {**self.leaRCX, **old.leaRCX}
		self.leaRDX = {**self.leaRDX, **old.leaRDX}
		self.leaRSI = {**self.leaRSI, **old.leaRSI}
		self.leaRDI = {**self.leaRDI, **old.leaRDI}
		self.leaRBP = {**self.leaRBP, **old.leaRBP}
		self.leaRSP = {**self.leaRSP, **old.leaRSP}
		self.leaR8 = {**self.leaR8, **old.leaR8}
		self.leaR9 = {**self.leaR9, **old.leaR9}
		self.leaR10 = {**self.leaR10, **old.leaR10}
		self.leaR11 = {**self.leaR11, **old.leaR11}
		self.leaR12 = {**self.leaR12, **old.leaR12}
		self.leaR13 = {**self.leaR13, **old.leaR13}
		self.leaR14 = {**self.leaR14, **old.leaR14}
		self.leaR15 = {**self.leaR15, **old.leaR15}
		self.xchg64 = {**self.xchg64, **old.xchg64}
		self.xchgRAX = {**self.xchgRAX, **old.xchgRAX}
		self.xchgRBX = {**self.xchgRBX, **old.xchgRBX}
		self.xchgRCX = {**self.xchgRCX, **old.xchgRCX}
		self.xchgRDX = {**self.xchgRDX, **old.xchgRDX}
		self.xchgRSI = {**self.xchgRSI, **old.xchgRSI}
		self.xchgRDI = {**self.xchgRDI, **old.xchgRDI}
		self.xchgRBP = {**self.xchgRBP, **old.xchgRBP}
		self.xchgRSP = {**self.xchgRSP, **old.xchgRSP}
		self.xchgGS = {**self.xchgGS, **old.xchgGS}
		self.xchgR8 = {**self.xchgR8, **old.xchgR8}
		self.xchgR9 = {**self.xchgR9, **old.xchgR9}
		self.xchgR10 = {**self.xchgR10, **old.xchgR10}
		self.xchgR11 = {**self.xchgR11, **old.xchgR11}
		self.xchgR12 = {**self.xchgR12, **old.xchgR12}
		self.xchgR13 = {**self.xchgR13, **old.xchgR13}
		self.xchgR14 = {**self.xchgR14, **old.xchgR14}
		self.xchgR15 = {**self.xchgR15, **old.xchgR15}
		self.neg = {**self.neg, **old.neg}
		self.negRAX = {**self.negRAX, **old.negRAX}
		self.negRBX = {**self.negRBX, **old.negRBX}
		self.negRCX = {**self.negRCX, **old.negRCX}
		self.negRDX = {**self.negRDX, **old.negRDX}
		self.negRSI = {**self.negRSI, **old.negRSI}
		self.negRDI = {**self.negRDI, **old.negRDI}
		self.negRSP = {**self.negRSP, **old.negRSP}
		self.negRBP = {**self.negRBP, **old.negRBP}
		self.negR8 = {**self.negR8, **old.negR8}
		self.negR9 = {**self.negR9, **old.negR9}
		self.negR10 = {**self.negR10, **old.negR10}
		self.negR11 = {**self.negR11, **old.negR11}
		self.negR12 = {**self.negR12, **old.negR12}
		self.negR13 = {**self.negR13, **old.negR13}
		self.negR14 = {**self.negR14, **old.negR14}
		self.negR15 = {**self.negR15, **old.negR15}
		self.xor = {**self.xor, **old.xor}
		self.xorZeroRAX = {**self.xorZeroRAX, **old.xorZeroRAX}
		self.xorRAX = {**self.xorRAX, **old.xorRAX}
		self.xorZeroRBX = {**self.xorZeroRBX, **old.xorZeroRBX}
		self.xorRBX = {**self.xorRBX, **old.xorRBX}
		self.xorZeroRCX = {**self.xorZeroRCX, **old.xorZeroRCX}
		self.xorRCX = {**self.xorRCX, **old.xorRCX}
		self.xorZeroRDX = {**self.xorZeroRDX, **old.xorZeroRDX}
		self.xorRDX = {**self.xorRDX, **old.xorRDX}
		self.xorZeroRSI = {**self.xorZeroRSI, **old.xorZeroRSI}
		self.xorRSI = {**self.xorRSI, **old.xorRSI}
		self.xorZeroRDI = {**self.xorZeroRDI, **old.xorZeroRDI}
		self.xorRDI = {**self.xorRDI, **old.xorRDI}
		self.xorZeroRSP = {**self.xorZeroRSP, **old.xorZeroRSP}
		self.xorRSP = {**self.xorRSP, **old.xorRSP}
		self.xorZeroRBP = {**self.xorZeroRBP, **old.xorZeroRBP}
		self.xorRBP = {**self.xorRBP, **old.xorRBP}
		self.xorZeroR8 = {**self.xorZeroR8, **old.xorZeroR8}
		self.xorR8 = {**self.xorR8, **old.xorR8}
		self.xorZeroR9 = {**self.xorZeroR9, **old.xorZeroR9}
		self.xorR9 = {**self.xorR9, **old.xorR9}
		self.xorZeroR10 = {**self.xorZeroR10, **old.xorZeroR10}
		self.xorR10 = {**self.xorR10, **old.xorR10}
		self.xorZeroR11 = {**self.xorZeroR11, **old.xorZeroR11}
		self.xorR11 = {**self.xorR11, **old.xorR11}
		self.xorZeroR12 = {**self.xorZeroR12, **old.xorZeroR12}
		self.xorR12 = {**self.xorR12, **old.xorR12}
		self.xorZeroR13 = {**self.xorZeroR13, **old.xorZeroR13}
		self.xorR13 = {**self.xorR13, **old.xorR13}
		self.xorZeroR14 = {**self.xorZeroR14, **old.xorZeroR14}
		self.xorR14 = {**self.xorR14, **old.xorR14}
		self.xorZeroR15 = {**self.xorZeroR15, **old.xorZeroR15}
		self.xorR15 = {**self.xorR15, **old.xorR15}
		self.xorQwordRAX = {**self.xorQwordRAX, **old.xorQwordRAX}
		self.xorQwordRBX = {**self.xorQwordRBX, **old.xorQwordRBX}
		self.xorQwordRCX = {**self.xorQwordRCX, **old.xorQwordRCX}
		self.xorQwordRDX = {**self.xorQwordRDX, **old.xorQwordRDX}
		self.xorQwordRSI = {**self.xorQwordRSI, **old.xorQwordRSI}
		self.xorQwordRDI = {**self.xorQwordRDI, **old.xorQwordRDI}
		self.xorQwordRSP = {**self.xorQwordRSP, **old.xorQwordRSP}
		self.xorQwordRBP = {**self.xorQwordRBP, **old.xorQwordRBP}
		self.xorR8 = {**self.xorR8, **old.xorR8}
		self.xorR9 = {**self.xorR9, **old.xorR9}
		self.xorR10 = {**self.xorR10, **old.xorR10}
		self.xorR11 = {**self.xorR11, **old.xorR11}
		self.xorR12 = {**self.xorR12, **old.xorR12}
		self.xorR13 = {**self.xorR13, **old.xorR13}
		self.xorR14 = {**self.xorR14, **old.xorR14}
		self.xorR15 = {**self.xorR15, **old.xorR15}
		self.xorGS = {**self.xorGS, **old.xorGS}
		self.mov64 = {**self.mov64, **old.mov64}
		self.movRAX = {**self.movRAX, **old.movRAX}
		self.movRBX = {**self.movRBX, **old.movRBX}
		self.movRCX = {**self.movRCX, **old.movRCX}
		self.movRDX = {**self.movRDX, **old.movRDX}
		self.movRSI = {**self.movRSI, **old.movRSI}
		self.movRDI = {**self.movRDI, **old.movRDI}
		self.movRSP = {**self.movRSP, **old.movRSP}
		self.movRBP = {**self.movRBP, **old.movRBP}
		self.movR8 = {**self.movR8, **old.movR8}
		self.movR9 = {**self.movR9, **old.movR9}
		self.movR10 = {**self.movR10, **old.movR10}
		self.movR11 = {**self.movR11, **old.movR11}
		self.movR12 = {**self.movR12, **old.movR12}
		self.movR13 = {**self.movR13, **old.movR13}
		self.movR14 = {**self.movR14, **old.movR14}
		self.movR15 = {**self.movR15, **old.movR15}
		self.movQword2 = {**self.movQword2, **old.movQword2}
		self.movQword2RAX = {**self.movQword2RAX, **old.movQword2RAX}
		self.movQword2RBX = {**self.movQword2RBX, **old.movQword2RBX}
		self.movQword2RCX = {**self.movQword2RCX, **old.movQword2RCX}
		self.movQword2RDX = {**self.movQword2RDX, **old.movQword2RDX}
		self.movQword2RSI = {**self.movQword2RSI, **old.movQword2RSI}
		self.movQword2RDI = {**self.movQword2RDI, **old.movQword2RDI}
		self.movQword2RSP = {**self.movQword2RSP, **old.movQword2RSP}
		self.movQword2RBP = {**self.movQword2RBP, **old.movQword2RBP}
		self.movQword2R8 = {**self.movQword2R8, **old.movQword2R8}
		self.movQword2R9 = {**self.movQword2R9, **old.movQword2R9}
		self.movQword2R10 = {**self.movQword2R10, **old.movQword2R10}
		self.movQword2R11 = {**self.movQword2R11, **old.movQword2R11}
		self.movQword2R12 = {**self.movQword2R12, **old.movQword2R12}
		self.movQword2R13 = {**self.movQword2R13, **old.movQword2R13}
		self.movQword2R14 = {**self.movQword2R14, **old.movQword2R14}
		self.movQword2R15 = {**self.movQword2R15, **old.movQword2R15}
		self.movConstant64 = {**self.movConstant64, **old.movConstant64}
		self.movConstantRAX = {**self.movConstantRAX, **old.movConstantRAX}
		self.movConstantRBX = {**self.movConstantRBX, **old.movConstantRBX}
		self.movConstantRCX = {**self.movConstantRCX, **old.movConstantRCX}
		self.movConstantRDX = {**self.movConstantRDX, **old.movConstantRDX}
		self.movConstantRSI = {**self.movConstantRSI, **old.movConstantRSI}
		self.movConstantRDI = {**self.movConstantRDI, **old.movConstantRDI}
		self.movConstantRSP = {**self.movConstantRSP, **old.movConstantRSP}
		self.movConstantRBP = {**self.movConstantRBP, **old.movConstantRBP}
		self.movConstantR8 = {**self.movConstantR8, **old.movConstantR8}
		self.movConstantR9 = {**self.movConstantR9, **old.movConstantR9}
		self.movConstantR10 = {**self.movConstantR10, **old.movConstantR10}
		self.movConstantR11 = {**self.movConstantR11, **old.movConstantR11}
		self.movConstantR12 = {**self.movConstantR12, **old.movConstantR12}
		self.movConstantR13 = {**self.movConstantR13, **old.movConstantR13}
		self.movConstantR14 = {**self.movConstantR14, **old.movConstantR14}
		self.movConstantR15 = {**self.movConstantR15, **old.movConstantR15}
		self.movQword = {**self.movQword, **old.movQword}
		self.movQwordRAX = {**self.movQwordRAX, **old.movQwordRAX}
		self.movQwordRBX = {**self.movQwordRBX, **old.movQwordRBX}
		self.movQwordRCX = {**self.movQwordRCX, **old.movQwordRCX}
		self.movQwordRDX = {**self.movQwordRDX, **old.movQwordRDX}
		self.movQwordRDI = {**self.movQwordRDI, **old.movQwordRDI}
		self.movQwordRSI = {**self.movQwordRSI, **old.movQwordRSI}
		self.movQwordRBP = {**self.movQwordRBP, **old.movQwordRBP}
		self.movQwordRSP = {**self.movQwordRSP, **old.movQwordRSP}
		self.movR8 = {**self.movR8, **old.movR8}
		self.movR9 = {**self.movR9, **old.movR9}
		self.movR10 = {**self.movR10, **old.movR10}
		self.movR11 = {**self.movR11, **old.movR11}
		self.movR12 = {**self.movR12, **old.movR12}
		self.movR13 = {**self.movR13, **old.movR13}
		self.movR14 = {**self.movR14, **old.movR14}
		self.movR15 = {**self.movR15, **old.movR15}
		self.movGSSpecial = {**self.movGSSpecial, **old.movGSSpecial}
		self.popal64 = {**self.popal64, **old.popal64}
		self.syscall64 = {**self.syscall64, **old.syscall64}
		self.pushad64 = {**self.pushad64, **old.pushad64}
		self.shlQword = {**self.shlQword, **old.shlQword}
		self.shl64 = {**self.shl64, **old.shl64}
		self.shrQword = {**self.shrQword, **old.shrQword}
		self.shr64 = {**self.shr64, **old.shr64}
		self.rcrQword = {**self.rcrQword, **old.rcrQword}
		self.rcr64 = {**self.rcr64, **old.rcr64}
		self.rclQword = {**self.rclQword, **old.rclQword}
		self.rcl64 = {**self.rcl64, **old.rcl64}
		self.notInst64 = {**self.notInst64, **old.notInst64}
		self.notInstRAX = {**self.notInstRAX, **old.notInstRAX}
		self.notInstRBX = {**self.notInstRBX, **old.notInstRBX}
		self.notInstRCX = {**self.notInstRCX, **old.notInstRCX}
		self.notInstRDX = {**self.notInstRDX, **old.notInstRDX}
		self.notInstRSI = {**self.notInstRSI, **old.notInstRSI}
		self.notInstRDI = {**self.notInstRDI, **old.notInstRDI}
		self.notInstRSP = {**self.notInstRSP, **old.notInstRSP}
		self.notInstRBP = {**self.notInstRBP, **old.notInstRBP}
		self.notInstR8 = {**self.notInstR8, **old.notInstR8}
		self.notInstR9 = {**self.notInstR9, **old.notInstR9}
		self.notInstR10 = {**self.notInstR10, **old.notInstR10}
		self.notInstR11 = {**self.notInstR11, **old.notInstR11}
		self.notInstR12 = {**self.notInstR12, **old.notInstR12}
		self.notInstR13 = {**self.notInstR13, **old.notInstR13}
		self.notInstR14 = {**self.notInstR14, **old.notInstR14}
		self.notInstR15 = {**self.notInstR15, **old.notInstR15}
		self.andInst64 = {**self.andInst64, **old.andInst64}
		self.andInstRAX = {**self.andInstRAX, **old.andInstRAX}
		self.andInstRBX = {**self.andInstRBX, **old.andInstRBX}
		self.andInstRCX = {**self.andInstRCX, **old.andInstRCX}
		self.andInstRDX = {**self.andInstRDX, **old.andInstRDX}
		self.andInstRSI = {**self.andInstRSI, **old.andInstRSI}
		self.andInstRDI = {**self.andInstRDI, **old.andInstRDI}
		self.andInstRSP = {**self.andInstRSP, **old.andInstRSP}
		self.andInstRBP = {**self.andInstRBP, **old.andInstRBP}
		self.andInstR8 = {**self.andInstR8, **old.andInstR8}
		self.andInstR9 = {**self.andInstR9, **old.andInstR9}
		self.andInstR10 = {**self.andInstR10, **old.andInstR10}
		self.andInstR11 = {**self.andInstR11, **old.andInstR11}
		self.andInstR12 = {**self.andInstR12, **old.andInstR12}
		self.andInstR13 = {**self.andInstR13, **old.andInstR13}
		self.andInstR14 = {**self.andInstR14, **old.andInstR14}
		self.andInstR15 = {**self.andInstR15, **old.andInstR15}
		self.unusual64 = {**self.unusual64, **old.unusual64}
		self.fs64 = {**self.fs64, **old.fs64}
		self.fsSpecial64 = {**self.fsSpecial64, **old.fsSpecial64}


		# mergeStop = timeit.default_timer()
		# dp("merge_time: " + str(mergeStop - mergeT))

class PEInfo:
	def __init__(self): #, name):
		"""Initializes the data."""
		self.peName = "PeName"
		self.modName = "modName"
		self.pe = "pe" #pefile.PE(self.peName)
		self.data = b'\x00'
		self.VirtualAdd = 0
		self.imageBase = 0
		self.vSize = 0
		self.SizeOfRawData = 0
		self.isDLL=True
		self.startLoc = 0
		self.endAddy = 0
		self.entryPoint = 0
		self.sectionName = 'sectionName'
		self.protect =""
		self.depStatus=None
		self.aslrStatus=None
		self.sehStatus=None
		self.CFGStatus=None
		self.magic=0
		self.Hash_sha256_section=0
		self.Hash_md5_section=0
		self.dlls=[]
		self.subdirectories = []
		self.subdirectoriesSet = set()
		self.files = []
		self.filesSet =set()
		self.path=""
		self.systemWin=False
		self.skipDll=False
		self.extracted=False
		self.dllDict={}
		self.emBase=0  # emulated base - nothing to do with actual bases used - these are allocated in emulation to avoid conflicts
		self.emBaseOld=0  # emulated base - nothing to do with actual bases used - these are allocated in emulation to avoid conflicts


	def setExtracted(self,val):
		self.extracted=True
	def setSkip(self, val):
		self.setSkip=val
	def setMagic(self,val):
		self.magic=val
	def setIsDLL(self,val):
		self.isDLL=val
	def setPath(self,val):
		self.path=val
	def setSystem(self,val):
		self.systemWin=val
	def setData(self, val):
		self.data=val
	def setHash_sha256(self,val):
		self.Hash_sha256_section=val
	def setHash_md5(self,val):
		self.Hash_md5_section=val
	def setPeName(self, val):
		self.peName =val
	def setModName(self, val):		
		self.modName =val
	def setPe(self, val):		
		self.pe = val
	def setVirtualAdd(self, val):		
		self.VirtualAdd = val
	def setVSize(self, val):		
		self.vSize = val
	def setSizeOfRawData(self, val):		
		self.SizeOfRawData = val
	def setStartLoc(self, val):		
		self.startLoc = val
	def setImageBase(self,val):
		self.imageBase=val
	def setEndAddy(self, val):		
		self.endAddy = val
	def setEntryPoint(self, val):		
		self.entryPoint = val
	def setSectionName(self, val):		
		self.sectionName = val
	def setDEPStatus(self, val):		
		self.depStatus= val
	def setASLRStatus(self, val):		
		self.aslrStatus=val
	def setSEHStatus(self, val):		
		self.sehStatus= val
	def setCFGStatus(self, val):		
		self.CFGStatus= val

def calculateTotalGadgets(fg):
	totalGadgets=len(fg.pops) + len(fg.popEAX) + len(fg.popEBX) + len(fg.popECX) + len(fg.popEDX) + len(fg.popESI) + len(fg.popEDI) + len(fg.popEBP) + len(fg.popESP) + len(fg.popOther) + len(fg.popDwordEAX) + len(fg.popDwordEBX) + len(fg.popDwordECX) + len(fg.popDwordEDX) + len(fg.popDwordESI) + len(fg.popDwordEDI) + len(fg.popDwordEBP) + len(fg.popDwordESP) + len(fg.popDword) + len(fg.popDwordOther) + len(fg.push) + len(fg.pushEAX) + len(fg.pushEBX) + len(fg.pushECX) + len(fg.pushEDX) + len(fg.pushESI) + len(fg.pushEDI) + len(fg.pushEBP) + len(fg.pushESP) + len(fg.pushDwordFS) + len(fg.pushDwordEAX) + len(fg.pushDwordEBX) + len(fg.pushDwordECX) + len(fg.pushDwordEDX) + len(fg.pushDwordESI) + len(fg.pushDwordEDI) + len(fg.pushDwordEBP) + len(fg.pushDwordESP) + len(fg.pushDword) + len(fg.pushDwordOther) + len(fg.pushConstant) + len(fg.pushDword) + len(fg.pushOther) + len(fg.inc) + len(fg.incEAX) + len(fg.incEBX) + len(fg.incECX) + len(fg.incEDX) + len(fg.incESI) + len(fg.incEDI) + len(fg.incEBP) + len(fg.incESP) + len(fg.dec) + len(fg.decEAX) + len(fg.decEBX) + len(fg.decECX) + len(fg.decEDX) + len(fg.decESI) + len(fg.decEDI) + len(fg.decEBP) + len(fg.decESP) + len(fg.addEAX) + len(fg.addEBX) + len(fg.addECX) + len(fg.addEDX) + len(fg.addESI) + len(fg.addEDI) + len(fg.addEBP) + len(fg.addESP) + len(fg.addFS) + len(fg.subFS) + len(fg.xorFS) + len(fg.xchgFS) + len(fg.add) + len(fg.addDword) + len(fg.addDwordEAX) + len(fg.addDwordEBX) + len(fg.addDwordECX) + len(fg.addDwordEDX) + len(fg.addDwordESI) + len(fg.addDwordEDI) + len(fg.addDwordEBP) + len(fg.addDwordESP) + len(fg.subEAX) + len(fg.subEBX) + len(fg.subECX) + len(fg.subEDX) + len(fg.subESI) + len(fg.subEDI) + len(fg.subEBP) + len(fg.subESP) + len(fg.sub) + len(fg.subDword) + len(fg.subDwordEAX) + len(fg.subDwordEBX) + len(fg.subDwordECX) + len(fg.subDwordEDX) + len(fg.subDwordESI) + len(fg.subDwordEDI) + len(fg.subDwordEBP) + len(fg.subDwordESP) + len(fg.mulEAX) + len(fg.mulEBX) + len(fg.mulECX) + len(fg.mulEDX) + len(fg.mulESI) + len(fg.mulEDI) + len(fg.mulEBP) + len(fg.mulESP) + len(fg.mul) + len(fg.divEAX) + len(fg.divEBX) + len(fg.divECX) + len(fg.divEDX) + len(fg.divESI) + len(fg.divEDI) + len(fg.divEBP) + len(fg.divESP) + len(fg.div) + len(fg.leaEAX) + len(fg.leaEBX) + len(fg.leaECX) + len(fg.leaEDX) + len(fg.leaESI) + len(fg.leaEDI) + len(fg.leaEBP) + len(fg.leaESP) + len(fg.lea ) + len(fg.movEAX) + len(fg.movEBX) + len(fg.movECX) + len(fg.movEDX) + len(fg.movESI) + len(fg.movEDI) + len(fg.movEBP) + len(fg.movESP) + len(fg.movFS) + len(fg.mov) + len(fg.movDwordEAX) + len(fg.movDwordEBX) + len(fg.movDwordECX) + len(fg.movDwordEDX) + len(fg.movDwordESI) + len(fg.movDwordEDI) + len(fg.movDwordEBP) + len(fg.movDwordESP) + len(fg.movDword) + len(fg.movDword2EAX) + len(fg.movDword2EBX) + len(fg.movDword2ECX) + len(fg.movDword2EDX) + len(fg.movDword2ESI) + len(fg.movDword2EDI) + len(fg.movDword2EBP) + len(fg.movDword2ESP) + len(fg.movDword2) + len(fg.xchgEAX) + len(fg.xchgEBX) + len(fg.xchgECX) + len(fg.xchgEDX) + len(fg.xchgESI) + len(fg.xchgEDI) + len(fg.xchgEBP) + len(fg.xchgESP) + len(fg.xchg) + len(fg.movConstantEAX) + len(fg.movConstantEBX) + len(fg.movConstantECX) + len(fg.movConstantEDX) + len(fg.movConstantESI) + len(fg.movConstantEDI) + len(fg.movConstantEBP) + len(fg.movConstantESP) + len(fg.movConstant) + len(fg.negEAX) + len(fg.negEBX) + len(fg.negECX) + len(fg.negEDX) + len(fg.negESI) + len(fg.negEDI) + len(fg.negEBP) + len(fg.negESP) + len(fg.neg) + len(fg.xorEAX) + len(fg.xorEBX) + len(fg.xorECX) + len(fg.xorEDX) + len(fg.xorESI) + len(fg.xorEDI) + len(fg.xorEBP) + len(fg.xorESP) + len(fg.xor) + len(fg.xorDwordEAX) + len(fg.xorDwordEBX) + len(fg.xorDwordECX) + len(fg.xorDwordEDX) + len(fg.xorDwordESI) + len(fg.xorDwordEDI) + len(fg.xorDwordEBP) + len(fg.xorDwordESP) + len(fg.xorDword) + len(fg.xorZeroEAX) + len(fg.xorZeroEBX) + len(fg.xorZeroECX) + len(fg.xorZeroEDX) + len(fg.xorZeroESI) + len(fg.xorZeroEDI) + len(fg.xorZeroEBP) + len(fg.xorZeroESP) + len(fg.xorZero) + len(fg.pushad) + len(fg.popal) + len(fg.shl) + len(fg.shr) + len(fg.shlDword) + len(fg.shrDword) + len(fg.rcl) + len(fg.rcr) + len(fg.rclDword) + len(fg.rcrDword) + len(fg.unusual) + len(fg.andInstEAX) + len(fg.andInstEBX) + len(fg.andInstECX) + len(fg.andInstEDX) + len(fg.andInstESI) + len(fg.andInstEDI) + len(fg.andInstEBP) + len(fg.andInstESP) + len(fg.andInst) + len(fg.andInstOther) + len(fg.notInstEAX) + len(fg.notInstEBX) + len(fg.notInstECX) + len(fg.notInstEDX) + len(fg.notInstESI) + len(fg.notInstEDI) + len(fg.notInstEBP) + len(fg.notInstESP) + len(fg.notInst) + len(fg.notInstOther) + len(fg.fs) + len(fg.fsSpecial) + len(fg.retfSingle) + len(fg.hgGadgets) + len(fg.hgPush) + len(fg.hgPushEAX) + len(fg.hgPushEBX) + len(fg.hgPushECX) + len(fg.hgPushEDX) + len(fg.hgPushESI) + len(fg.hgPushEDI) + len(fg.hgPushEBP) + len(fg.hgPushESP) + len(fg.hgPushDwordFS) + len(fg.hgPushDwordEAX) + len(fg.hgPushDwordEBX) + len(fg.hgPushDwordECX) + len(fg.hgPushDwordEDX) + len(fg.hgPushDwordESI) + len(fg.hgPushDwordEDI) + len(fg.hgPushDwordEBP) + len(fg.hgPushDwordESP) + len(fg.hgPushDword) + len(fg.hgPushDwordOther) + len(fg.hgPushConstant) + len(fg.hgPushDword) + len(fg.hgPushOther) + len(fg.retfSingle) 
	return totalGadgets
rg={}
def createFg():
	global fg
	global rg
	
	# # try:
	# # 	del fg
	# # except:
	# # 	dp ("could not destroy fg object")
	# fg=None
	# dp (type(fg))
	# dp ("createFg")
	fg = foundGadgets()
	# dp (type(fg))
	# dp ("fg pops count at start", len(fg.pops))

createFg()