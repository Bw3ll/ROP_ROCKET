


#!/usr/bin/env python
# Sample code for X86 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import pickle
import capstone as Cs
from capstone import *
import traceback
import binascii
import math
from badBytes import *
from helpers import *
import copy

import gc
import os
import sys
import struct
import signal

# memory address where emulation starts
ADDRESS = 0x1000000

new=b'\x5d\xc3'

shellList=[]

red ='\u001b[31;1m'
gre = '\u001b[32;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'
res2 = '\u001b[0m'

# callback for tracing basic blocks
# def hook_block(uc, address, size, user_data):
#     dp(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    
    dp ("eip:", hex(address), size)
    global maxAddress
    r_eip = int(uc.reg_read(UC_X86_REG_EIP))
    if r_eip >= maxAddress:
        dp ("magic stop")
        uc.emu_stop()

    # dp(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    # dp(">>> --- EFLAGS is 0x%x" %eflags)

    shells = b''
    try:
        shells = uc.mem_read(address, size)
        # dp (shells.hex())
        if shells[0]==0xc2:
            dp ("got c2")
            uc.emu_stop()
    except Exception as e:
        dp ("Error2: ", e)
        dp(traceback.format_exc())
    giveRegOuts(uc)

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    t=0
    for i in cs.disasm(shells, address):

        val = i.mnemonic + " " + i.op_str  # + " " + shells.hex()
        if t == 0:
            mnemonic = i.mnemonic
            op_str = i.op_str
            dp (val)
        t+=1
syscallValAtESP=False
snapshotESP=0xffffffff
def hook_codeFS(uc, address, size, user_data):
    global syscallValAtESP
    global bad_instruct_count
    global snapshotESP
    showOnScreen=False
    # showOnScreen=True
    finalCall=False
    dp ("eip:", hex(address), size)
    global maxAddress
    r_eip = int(uc.reg_read(UC_X86_REG_EIP))
    r_esp = int(uc.reg_read(UC_X86_REG_ESP))
    saved1=False

    if r_eip >= maxAddress:
        # print ("here is current r_esp", hex(r_esp))
        if not saved1:
            snapshotESP=r_esp
            saved1=True


    if r_eip >= maxAddress+0x2000      :
        # print ("magic stop", maxAddress, hex(maxAddress), "r_eip",hex(r_eip))
        if r_eip != 0xaaaaaa:
            finalCall=True
            uc.emu_stop()

    # dp(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    # dp(">>> --- EFLAGS is 0x%x" %eflags)

    shells = b''
    try:
        shells = uc.mem_read(address, size)
        # dp (shells.hex())
        if shells[0]==0xc2:
            # print ("got c2")
            uc.emu_stop()
    except Exception as e:
        dp ("Error2: ", e)
        dp(traceback.format_exc())
    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    valInstruction=""
    for i in cs.disasm(shells, address):
        valInstruction = i.mnemonic + " " + i.op_str  # + " " + shells.hex()

    # if "idiv" in valInstruction:   ##skip instrucitons
    #     print (gre,"we have idiv - can create problems - let's skip",res)
    #     uc.reg_write(UC_X86_REG_EIP, address+size)

    regOut=giveRegOuts(uc)

    t=0
    for i in cs.disasm(shells, address):

        val = i.mnemonic + " " + i.op_str  # + " " + shells.hex()
        if t == 0:
            mnemonic = i.mnemonic
            op_str = i.op_str
            dp (val)
        t+=1
    bad_instruct=False
    if shells == b'\x00\x00':
        # print ("increment bad instruction by 1")
        bad_instruct_count += 1
        # print (instructLine)
        if bad_instruct_count > 5:
            
            uc.emu_stop()

    if finalCall:
        if "0xaaaaab" in hex(address):
            # print (red, "yes!",res)
            syscallValAtESP=True

    try:
        shells = uc.mem_read(address, size)
    except Exception as e:
        # dp ("Error: ", e)
        # dp(traceback.format_exc())
        instructLine += " size: 0x%x" % size + '\t'  # size is overflow - why so big?
        outFile.write("abrupt end:  " + instructLine)
    instructLine=""
    verbose=True
    if verbose:
        instructLine += giveRegs(uc,32)
        instructLine +=  " 0x%x" % address + "\t"
        if showOnScreen:
            print (red,instructLine,res)
    t=0
    # print(giveRegs(uc,32))
    # instructLine=""
    for i in cs.disasm(shells, address):
        valInstruction = i.mnemonic + " " + i.op_str  # + " " + shells.hex()
        if showOnScreen:
            print (valInstruction+"\n")

        instructLine += valInstruction + '\n'
        # shells = uc.mem_read(sbase, size)
        # print (yel,instructLine,res)
        if verbose:
            outFile.write(instructLine)
        if t == 0:
            mnemonic = i.mnemonic
            op_str = i.op_str
            # dp ("mnemonic op_str", mnemonic, op_str)
            break
        t += 1
def handle_exit(signum,frame):
    global stopProcess
    stopProcess=True
    # print ("graceful handle_exit")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
def giveRegOuts(mu):
    r_eip = int(mu.reg_read(UC_X86_REG_EIP))
    r_eax = int(mu.reg_read(UC_X86_REG_EAX))
    r_ebx = int(mu.reg_read(UC_X86_REG_EBX))
    r_ecx = int(mu.reg_read(UC_X86_REG_ECX))
    r_edx = int(mu.reg_read(UC_X86_REG_EDX))
    r_esi = int(mu.reg_read(UC_X86_REG_ESI))
    r_edi = int(mu.reg_read(UC_X86_REG_EDI))
    r_ebp = int(mu.reg_read(UC_X86_REG_EBP))
    r_esp = int(mu.reg_read(UC_X86_REG_ESP))

        
    # dp ("\touts",r_eax, r_ebx, r_ecx, r_edx, r_esi, r_edi, r_ebp, r_esp)
    dp ("\teip:",hex(r_eip), "eax", hex(r_eax),"ebx", hex(r_ebx), "ecx",hex(r_ecx), "edx",hex(r_edx), "esi",hex(r_esi), "edi",hex(r_edi),"ebp", hex(r_ebp), "esp", hex(r_esp))
    if 1==2:
        try:
            tmp = mu.mem_read(r_esp, 4)
            dp("\t\t>>> Read 4 bytes from [0x%x] = 0x" %(r_esp), end="")

            for i in reversed(tmp):
                dp("%x" %(i), end="")
            dp("")
            dp ("tmp", type(bytes(tmp)), bytes(tmp).hex())
            esp = mu.reg_read(UC_X86_REG_ESP)


            # regVal = uc.mem_read(esp,4)
            # regVal= int.from_bytes(regVal, "little")
            # dp ("regVal", regVal)

        except:
            dp ("cannot print stack")

maxAddress=0

def errorESP(mu):
    r_esp = int(mu.reg_read(UC_X86_REG_ESP))

    tmp = mu.mem_read(r_esp, 4)
    dp("\t\t>>> Read 4 bytes from [0x%x] = 0x" %(r_esp), end="")

    for i in reversed(tmp):
        dp("%x" %(i), end="")
    dp("")
    dp ("tmp", bytes(tmp).hex())
    esp = mu.reg_read(UC_X86_REG_ESP)


    regVal = mu.mem_read(esp,4)
    regVal= int.from_bytes(regVal, "little")
    dp ("deref", regVal)

class gadgetRegs:
    def __init__(self):  
        pass
        # self.eax = 0
        # self.ebx = 0
        # self.ecx = 0
        # self.edx = 0
        # self.esi = 0
        # self.edi = 0
        # self.ebp = 0
        # self.esp = 0
        # self.diffEax = 0
        # self.diffEbx = 0
        # self.diffEcx = 0
        # self.diffEdx = 0
        # self.diffEsi = 0
        # self.diffEdi = 0
        # self.diffEbp = 0
        # self.diffEsp = 0

    def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp, changed=False):
        if changed:
            self.diffEax = eax - self.eax
            self.diffEbx = ebx - self.ebx
            self.diffEcx = ecx - self.ecx
            self.diffEdx = edx - self.edx
            self.diffEsi = esi - self.esi
            self.diffEdi = edi - self.edi

            self.diffs = {}

            self.diffs["eax"]=self.diffEax
            self.diffs["ebx"]=self.diffEbx
            self.diffs["ecx"]=self.diffEcx
            self.diffs["edx"]=self.diffEdx
            self.diffs["edi"]=self.diffEdi
            self.diffs["esi"]=self.diffEsi


            try:
                self.diffEbp = ebp -self.ebp
                self.diffs["ebp"]=self.diffEbp

            except:
                self.diffEbp=0xdeaddead
                self.diffs["ebp"]=0xdeaddead

            try:
                self.diffEsp = esp -self.esp
                self.diffs["esp"]=self.diffEsp

                dp ("diffesp", hex(self.diffEsp), "Esp", hex(esp), "self.esp", hex(self.esp))
            except:
                self.diffEsp=0xdeaddead
                self.diffs["esp"]=0xdeadead

            if self.diffEax + self.diffEbx + self.diffEcx + self.diffEdx + self.diffEbp + self.diffEdi + self.diffEsi == 0:
                self.clobberFree=True
            else:
                self.clobberFree=False
        self.eax = eax
        self.ebx = ebx
        self.ecx = ecx
        self.edx = edx
        self.esi = esi
        self.edi = edi
        self.ebp = ebp
        self.esp = esp
        self.esp2=esp
        self.reg = {}
        self.reg["eax"]=eax
        self.reg["ebx"]=ebx
        self.reg["ecx"]=ecx
        self.reg["edx"]=edx
        self.reg["edi"]=edi
        self.reg["esi"]=esi
        self.reg["ebp"]=ebp
        self.reg["esp"]=esp
        self.error=False
        # dp ("set ebp", (self.ebp))
        # dp ("set esp", (self.esp))
    def setStackPivot(self,esp2):
        # print ("esp2", hex(esp2))
        # print(hex(self.esp2))
        self.diffEspSP=esp2-self.esp2
    def giveSP(self):
        return self.diffEspSP
    def setRegWrit(self,regSet,newVal):
        # print ("setRegWrit", regSet, newVal)
        if regSet=="eax":
            self.eax = newVal
        elif regSet=="ebx":
            self.ebx = newVal
        elif regSet=="ecx":
            self.ecx = newVal
        elif regSet=="edx":
            self.edx = newVal
        elif regSet=="esi":
            self.esi = newVal
        elif regSet=="edi":
            self.edi = newVal
        else:
            pass
        
    def giveRegLoc(self,r):
        rLookup={"eax":self.eax, "ebx":self.ebx, "ecx":self.ecx, "edx":self.edx, "edi":self.edi, "esi":self.esi, "ebp":self.ebp, "esp":self.esp}
        returnVal=rLookup[r]   
        return returnVal

    def CalculateRemainingRegs(self,first,second):
        regs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
        regs.remove(first)
        regs.remove(second)
        dp(regs)
        dict_look_up={"eax": self.diffEax, "ebx": self.diffEbx, "ecx":self.diffEcx, "edx":self.diffEdx,"edi":self.diffEdi,"esi":self.diffEsi,"ebp":self.diffEbp,"esp":self.diffEsp}
    
        val=0
        for r in regs:
            val+=dict_look_up[r]
        dp ("difference", val)
        self.hgDiff=val
    def setError(self,val):
        dp ("setError", val)
        self.error=True
        self.errorType=val
    def show(self):
        print ("Final results:")
        if not self.error:
            print ("\teax", hex(self.eax),"ebx", hex(self.ebx), "ecx",hex(self.ecx), "edx",hex(self.edx), "esi",hex(self.esi), "edi",hex(self.edi),"ebp", hex(self.ebp), "esp", hex(self.esp))
            print ("\tdiff eax", hex(self.diffEax),"diff ebx", hex(self.diffEbx), "diff ecx",hex(self.diffEcx), "diff edx",hex(self.diffEdx), "diff esi",hex(self.diffEsi), "diff edi",hex(self.diffEdi),"diff ebp", hex(self.diffEbp), "diff esp", hex(self.diffEsp))
        else:
            print ("*Error:", self.errorType)
    def giveChanged(self,skipEsp=True):
        availableRegs=["eax", "ebx","ecx","edx", "esi","edi","ebp","esp"]
        try:
            dict_look_up={"eax": self.diffEax, "ebx": self.diffEbx, "ecx":self.diffEcx, "edx":self.diffEdx,"edi":self.diffEdi,"esi":self.diffEsi,"ebp":self.diffEbp,"esp":self.diffEsp}
            dict_look_up2={"eax": self.eax, "ebx": self.ebx, "ecx":self.ecx, "edx":self.edx,"edi":self.edi,"esi":self.esi,"ebp":self.ebp,"esp":self.esp}
        except:
            pass
        changedDiff={}
        changedVal={}
        if skipEsp:
            availableRegs.remove("esp")
        try:
            for r in availableRegs:
                if dict_look_up[r] !=0:
                    changedDiff[r]=dict_look_up[r]
                    changedVal[r]=dict_look_up2[r]
        except:
            pass
        if len(changedDiff) ==0:
            return False,{},{}
        else:
            return True, changedDiff,changedVal
    def checkFree(self,regs, remExc=None, espGuard=0x100):
        # print ("checkFree", regs, remExc)
        if remExc=="ds" or remExc=="fs" or remExc=="es" :
            return False,0
        try:
            regs=set(regs)
        except:
            pass
        if remExc!=None:
            try:
                for r1 in remExc:
                    regs.remove(r1)
            except:
                pass
        try:
            for r in regs:
                try:
                    if self.diffs[r]!=0:
                        # print (yel,"bads",r, hex(self.diffs[r]),res)
                        return False,0
                except:
                    # print (yel,"checkfree except",res)
                    return False,0
                    break
                    pass
            try:       
                if self.diffEsp <= espGuard:
                    return True, self.diffEsp
                # print ("returning false")
            except:
                pass
            return False,0
        except Exception as e:
            dp("cfree ERROR: %s" % e)
            dp(traceback.format_exc())
            return False,0
    def checkFreeTester(self,regs, remExc=None, espGuard=0x100):
        # print ("checkFree", regs, remExc)
        if remExc=="ds" or remExc=="fs" or remExc=="es" :
            return False,0
        try:
            regs=set(regs)
        except:
            pass
        if remExc!=None:
            try:
                if type(remExc)==list:
                    for r1 in remExc:
                        # print ("r1",r1, type(regs))
                        try:
                            regs.remove(r1)
                        except:
                            regs.pop(r1)
                elif type(remExc)==str:
                    try:
                        regs.remove(remExc)
                    except:
                        regs.pop(remExc)
            except Exception as e:
                # print("cfree ERROR: %s" % e)
                print(traceback.format_exc())
                
        try:
            for r in regs:
                try:
                    if self.diffs[r]!=0:
                        print (yel,"bads",r, hex(self.diffs[r]),res)
                        return False,0
                except:
                    # print (yel,"checkfree except",res)
                    return False,0
                    break
                    pass
            try:       
                if self.diffEsp <= espGuard:
                    # print ("check-->GOOD")
                    return True, self.diffEspSP
                # print ("returning false")
            except:
                pass
            return True,self.diffEspSP
        except Exception as e:
            dp("cfree ERROR: %s" % e)
            dp(traceback.format_exc())
            return False,0
    def verifyValSame(self,reg1,reg2):
        # print ("verifyValSame",reg1, reg2)
        if reg1=="ds" or reg1=="fs" or reg1=="es" or reg2=="ds" or reg2=="fs" or reg2=="es" :
            return False,0
        if rVal[reg1] ==self.reg[reg2]:
            # print ("it is the same")
            return True
        else:
            # print ("it is not the same", hex(self.reg[reg1]),hex(rVal[reg2]), reg1, reg2)
            return False

    def verifyRegUnchanged(self,reg):
        # print ("verifyValSame",reg1, reg2)

        dict_look_up={"eax": self.diffEax, "ebx": self.diffEbx, "ecx":self.diffEcx, "edx":self.diffEdx,"edi":self.diffEdi,"esi":self.diffEsi,"ebp":self.diffEbp,"esp":self.diffEsp}
        if dict_look_up[reg]==0:
            # print ("it is the same")
            return True
        else:
            # print ("it is not the same", hex(self.reg[reg1]),hex(rVal[reg2]), reg1, reg2)
            return False
    def start(self,gRegsObj):
        self.eax = gRegsObj.eax
        self.ebx = gRegsObj.ebx
        self.ecx = gRegsObj.ecx
        self.edx = gRegsObj.edx
        self.esi = gRegsObj.esi
        self.edi = gRegsObj.edi
        self.ebp = gRegsObj.ebp
        self.esp = gRegsObj.esp
        self.esp2 = gRegsObj.esp

    def setEbp(self,ebpVal):
        self.ebp=ebpVal
        rVal["ebp"]=ebpVal
    def setEsp(self,espVal):
        self.esp=espVal
        self.esp2=espVal

        rVal["esp"]=espVal
    def setEspold(self,espVal):
        self.esp=espVal
        # regs=["eax", "ebx","ecx","edx", "esi","edi","ebp"]
    def setEaxTemp(self, val):
        self.eax=val
    def setEbxTemp(self, val):
        self.ebx=val
    def setEcxTemp(self, val):
        self.ecx=val
    def setEdxTemp(self, val):
        self.edx=val
    def setEsiTemp(self, val):
        self.esi=val
    def setEdiTemp(self, val):
        self.edi=val
    def setEbpTemp(self, val):
        self.ebp=val



    def checkForPops(self,findEspPops):
        dp("checkForPops findEspPops",findEspPops)
        try:
            dict_look_up={"eax": self.eax, "ebx": self.ebx, "ecx":self.ecx, "edx":self.edx,"edi":self.edi,"esi":self.esi,"ebp":self.ebp,"esp":self.esp}
            numDict_look_up={0:0x41414141,1:0x42424242,2:0x43434343, 3:0x44444444,4:0x45454545,5:0x46464646}

            t=0
            for r in findEspPops:
                curVal=dict_look_up[r]
                desiredVal=[t]
                dp ("cur", hex(curVal), "desiredVal", hex(numDict_look_up[t]))
                if curVal==numDict_look_up[t]:
                    dp ("cur=desired")
                else:
                    return False
                t=t+1
            return True



            # for r in excludeRegs:
            #     val=dict_look_up[r]
            #     if val != 0 or self.diffEsp != espDesiredMovement:
            #         dp ("checkForBad FALSE")
            #         dp ("val", val, espDesiredMovement)
            #         return False
            #     else:
            #         dp ("checkForBad TRUE")

            #         return True  # free of clobbering for selected regs
        
        except Exception as e:
            dp("cfB ERROR: %s" % e)
            dp(traceback.format_exc())
            dp ("except: returning false")
            return False # some kind of exception, e.g. memory error
    def checkForBad(self,excludeRegs, espDesiredMovement):
        dp("checkForBad excludeRegs", excludeRegs, "espDesiredMovement", espDesiredMovement)
        espDList=False
        if type(espDesiredMovement)==list:
            espDList=True
        if self.error:
            return False
        try:
            dict_look_up={"eax": self.diffEax, "ebx": self.diffEbx, "ecx":self.diffEcx, "edx":self.diffEdx,"edi":self.diffEdi,"esi":self.diffEsi,"ebp":self.diffEbp,"esp":self.diffEsp}
            if not espDList:
                for r in excludeRegs:
                    val=dict_look_up[r]
                    if val != 0 or self.diffEsp != espDesiredMovement:
                        dp ("checkForBad FALSE")
                        dp ("val", val, espDesiredMovement)
                        return False
                    else:
                        dp ("checkForBad TRUE")

                        return True  # free of clobbering for selected regs
            else:   # it is a list  
                espMin=espDesiredMovement[0]
                espMax=espDesiredMovement[1]
                for r in excludeRegs:
                    val=dict_look_up[r]
                    if val !=0 or self.diffEsp <espMin or self.diffEsp>espMax:
                        dp ("checkForBad FALSE")
                        dp ("val", val, espDesiredMovement)
                        return False
                    else:
                        dp ("checkForBad TRUE")

                        return True  # free of clobbering for selected regs
        except Exception as e:
            dp("cfB ERROR: %s" % e)
            dp(traceback.format_exc())
            dp ("except: returning false")
            return False # some kind of exception, e.g. memory error
            
def disMini(CODED2, offset):

    # dp ("disHereClean6", n)
    returnVal = ""
    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    
    for i in cs.disasm(CODED2, offset):
        val =  i.mnemonic + " " + i.op_str + " # "
        returnVal +=val
    return returnVal



gRegs=gadgetRegs()
# gRegs.set(1,2,3,4,5,6,None,None)
# def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp, changed=False):

rVal={}
rVal["eax"]=0x1111222
rVal["ebx"]=0x2222442
rVal["ecx"]=0x3331112
rVal["edx"]=0x444dddd
rVal["edi"]=0x555eeee
rVal["esi"]=0x666eeee
rVal["ebp"]=0xdeadcad
rVal["esp"]=0xdeadcad



gRegs.set(rVal["eax"], rVal["ebx"], rVal["ecx"], rVal["edx"], rVal["edi"], rVal["esi"], None,None)



def doGC():
    # Returns the number of
    # objects it has collected
    # and deallocated
    collected = gc.collect()

     
    # dps Garbage collector
    # as 0 object
    dp("Garbage collector: collected",
              "%d objects." % collected)

# def roundup1000(x):
#     return int(math.ceil(x / 1000.0)) * 1000
def rg(val):
    # dp ("val", val, type(val))
    rg=struct.pack("<I", val)
    return rg
def giveStackSys(uc, arch):
    global ApiSyscall
    global sysTarget2
    if ApiSyscall!="syscall":
        return False, 0x696969699
    # print (gre,"giveStackSys",res, hex(sysTarget2))
    # 0x55667799
    pattern=rg(sysTarget2)
    # print ("pattern:",binaryToStr(pattern), hex(sysTarget2))
    goBackDistance=0x2800
    goForwardDistance=0x3000
    # mem=(uc.mem_read(uc.reg_read(UC_X86_REG_ESP-goBackDistance), 0x150))
    mem1=uc.mem_read(uc.reg_read(UC_X86_REG_ESP), goForwardDistance)
    mem2=uc.mem_read(uc.reg_read(UC_X86_REG_ESP-goBackDistance), goBackDistance)
    mem3=uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 20)
    # mem=mem1+mem2
    mem=mem2+mem1
    # print (cya,binaryToStr(mem),res)
    if pattern not in mem:
        # print(gre,"Emulating Windows syscall exploit - searching for target pattern",res)#, hex(sysTarget2))
        pass
    elif pattern in mem:
        # print (cya,binaryToStr(mem),res)
        # print (gre,"Emulating Windows syscall exploit - calculating a needed distance to target",res)#, hex(sysTarget2),red,"YES!",res)

        start=0
        start = mem.find(pattern , start)
        # print (hex(start))
        # print (hex(start -goBackDistance))
        # print (gre,hex(start-goBackDistance),res)
        if start-goBackDistance==0:
            # print(yel,binaryToStr(mem3),res)
            pass
        return True,start-goBackDistance
    return False,0xdeadc0de

def giveStack(uc, arch):
    global ApiSyscall
    if ApiSyscall=="syscall":
        return False, 0x696969699
    # print (gre,"giveStack",res)
    # 0x55667799
    global  fakeWinAPIInner
    goBackDistance=0x2800
    goForwardDistance=0x3000
    # mem=(uc.mem_read(uc.reg_read(UC_X86_REG_ESP-goBackDistance), 0x150))
    mem1=uc.mem_read(uc.reg_read(UC_X86_REG_ESP), goForwardDistance)
    mem2=uc.mem_read(uc.reg_read(UC_X86_REG_ESP-goBackDistance), goBackDistance)
    mem3=uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 20)


    # mem=mem1+mem2
    mem=mem2+mem1
    # print (cya,binaryToStr(mem),res)
    if fakeWinAPIInner not in mem:
        # print(gre,"Emulating exploit - searching for target pattern",res)#, hex(sysTarget2))
        pass
    
    elif fakeWinAPIInner in mem:
        # print (cya,binaryToStr(mem),res)

        # print (red,"yes",res)
        # print (gre,"Emulating exploit - calculating a needed distance to target",res)#, hex(sysTarget2),red,"YES!",res)

        start=0

        start = mem.find(fakeWinAPIInner , start)
        # print (hex(start))
        # print (hex(start -goBackDistance))
        # print (gre,hex(start-goBackDistance),res)
        if start-goBackDistance==0:
            # print(yel,binaryToStr(mem3),res)
            pass
        return True,start-goBackDistance
    return False,0xdeadc0de
    # stacky1=binaryToStr(uc.mem_read(uc.reg_read(UC_X86_REG_ESP-0x50), 0x50))

    # stacky=binaryToStr(uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 0x100))


    # print (cya,stacky1,res)
    # print (stacky)

topEsp=0xffffffff
def giveRegs(uc, arch):
    global topEsp
    instructLine = "\n\t>>> "
    if arch == 32:
        regs32 = {"EAX": UC_X86_REG_EAX, "EBX": UC_X86_REG_EBX, "ECX": UC_X86_REG_ECX, "EDX": UC_X86_REG_EDX, "ESI": UC_X86_REG_ESI, "EDI": UC_X86_REG_EDI, "EBP": UC_X86_REG_EBP, "ESP": UC_X86_REG_ESP}
        for regName, regConst in regs32.items():
            regVal = uc.reg_read(regConst)
            instructLine += f"{regName}: {hex(regVal)} "
        stacky=binaryToStr(uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 0x100))
        someBy=uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4)
        unpacked = struct.unpack("<I", someBy)
        topEsp=unpacked[0]
        
        instructLine += "\n\t top esp: "+ hex(topEsp)+ " stack: " + stacky + "\n"
        return instructLine
    elif arch == 64:
        regs64 = {"RAX": UC_X86_REG_RAX, "RBX": UC_X86_REG_RBX, "RCX": UC_X86_REG_RCX, "RDX": UC_X86_REG_RDX, "RSI": UC_X86_REG_RSI, "RDI": UC_X86_REG_RDI, "R8": UC_X86_REG_R8, "R9": UC_X86_REG_R9, "R10": UC_X86_REG_R10, "R11": UC_X86_REG_R11, "R12": UC_X86_REG_R12, "R13": UC_X86_REG_R13, "R14": UC_X86_REG_R14, "R15": UC_X86_REG_R15, "RBP": UC_X86_REG_RBP, "RSP": UC_X86_REG_RSP}
        for regName, regConst in regs64.items():
            regVal = uc.reg_read(regConst)
            instructLine += f"{regName}: {hex(regVal)} "
        instructLine += "\n"
        return instructLine
    
bad_instruct_count = 0
stopProcess=False
outFile = open(os.path.join(os.path.dirname(__file__), 'emulationLog.txt'), 'w')
oldEsp=0x0
winApiSyscallReached=False
finalPivotGadgetG=0xbadddddd
doAfterPivot=False
givStDistance=0xdeadc0de

def hook_code2(uc, address, size, user_data):
    # print ("hook_code2")
    global winApiSyscallReached
    global maxCount
    global stopProcess
    global oldEsp
    global ApiSyscall
    global sysTarget2
    if stopProcess:
        # print ("** StopProces --> stopping")
        uc.emu_stop()
    
    global outFile
    global bad_instruct_count
    shells = b''
    instructLine=""
    global RP
    global targetP
    global doAfterPivot
    global finalPivotGadgetG
    global bGiveStack
    global givStDistance
    global ApiSyscall

    r_esp = uc.reg_read(UC_X86_REG_ESP)
    r_eip = uc.reg_read(UC_X86_REG_EIP)
    oldEsp=r_esp

    try:
        # locParam=RP.giveParamLocOnStack(targetP, ApiSyscall)
        if ApiSyscall=="syscall":
            locParam=RP.giveParamLocOnStack(targetP,"syscall")
        else:
            locParam=RP.giveParamLocOnStack(targetP,"winApi")
        locParam2=uc.mem_read(locParam,4)

    except:
        pass
   
    if ApiSyscall!="syscall":
        # print ("finalPivotGadgetG",hex(finalPivotGadgetG))

        if doAfterPivot:
            # print (red,"doAfterPivot address:", hex(address))
            bGiveStack, givStDistance= giveStack(uc,32)
            doAfterPivot=False
        if address==finalPivotGadgetG:
            # print (red, "this is it!!!!",res)
            doAfterPivot=True
    elif ApiSyscall=="syscall":
        if doAfterPivot:
            # print ("address:", hex(address))
            bGiveStack, givStDistance= giveStackSys(uc,32)
            doAfterPivot=False
        if address==finalPivotGadgetG:
            # print (red, "reached final pivot gadget",res,hex(finalPivotGadgetG))
            doAfterPivot=True


    # dp ("locParam2", binaryToStr(bytes(locParam2)))
    maxCount+=1
    if maxCount > 20000:
        # print ("Emulation max exceeded. Stopping.")
        stopProcess=True
    try:

        stopPoint = int.from_bytes(locParam2, 'little')

    except:
        stopPoint=0x9999999
    if stopPoint==r_eip and stopPoint !=0:
        # print ("special stopping process: EIP is at ", hex(r_eip))
        outFile.write("special stopping process: EIP is at " + hex(r_eip))
        
        dp (hex(stopPoint),hex(r_eip))

        stopProcess=True
        if stopPoint !=0:
            winApiSyscallReached=True
            # print (gre, "winApiSyscallReached=True!!!!!!!!!!!!!!!!!!!",res)
    elif (sysTarget2==r_eip and ApiSyscall=="syscall"):
        # print ("special stopping process: EIP is at WinAPI (simulated at 0x55667799) or gadget to invoke Syscall")
        outFile.write("special stopping process: EIP is at WinAPI (simulated at 0x55667799) or gadget to invoke Syscall - EIP at " + hex(r_eip))
        
        dp (hex(sysTarget2),hex(r_eip))
        stopProcess=True
        winApiSyscallReached=True
    elif r_eip == 0x55667799:
        # print ("special stopping process: EIP is at WinAPI (simulated at 0x55667799) or gadget to invoke Syscall!!")
        outFile.write("special stopping process: EIP is at WinAPI (simulated at 0x55667799) or gadget to invoke Syscall - EIP at " + hex(r_eip))
        
        dp (hex(sysTarget2),hex(r_eip))
        stopProcess=True
        winApiSyscallReached=True


    try:
        shells = uc.mem_read(address, size)
    except Exception as e:
        # dp ("Error: ", e)
        # dp(traceback.format_exc())
        instructLine += " size: 0x%x" % size + '\t'  # size is overflow - why so big?
        outFile.write("abrupt end:  " + instructLine)
        # print("abrupt end: error reading line of shellcode")
        stopProcess = True
        # return # terminate func early   --don't comment - we want to see the earlyrror
    programCounter=0  # just temp 0
    bad_instruct = False

 
    verbose=True
    if verbose:
        instructLine += giveRegs(uc,32)
        instructLine += str(programCounter) + ": 0x%x" % address + "\t"

    t=0
    
    for i in cs.disasm(shells, address):
        valInstruction = i.mnemonic + " " + i.op_str  # + " " + shells.hex()
        instructLine += valInstruction + '\n'
        # shells = uc.mem_read(sbase, size)
        # dp (instrssuctLine)
        if verbose:
            outFile.write(instructLine)
        if t == 0:
            mnemonic = i.mnemonic
            op_str = i.op_str
            # dp ("mnemonic op_str", mnemonic, op_str)
            break
        t += 1

    if shells == b'\x00\x00':
        # print ("increment bad instruction by 1")
        bad_instruct_count += 1
        # print (instructLine)
        if bad_instruct_count > 5:
            bad_instruct = True

    if bad_instruct:
        # print ("bad instruction-stopping")
        stopProcess = True

def checkRetStart(pe):
    highest=0x1005000
    start=0x1005000
    startRet=0x900000
    itIsCaught=False
    for q in pe:
        if pe[q].emBase !=0:     
            topSizeForMod=pe[q].emBase + len(pe[q].data)+0x40000
            # print (q, hex(pe[q].emBase),    "topSizeForMod", hex(topSizeForMod))
            if startRet >= pe[q].emBase and startRet <= topSizeForMod:
                # print (red,"it is caught here!!",res)
                itIsCaught=True
            if topSizeForMod > highest:
                highest=topSizeForMod
    # print ("highest", hex(highest))
    if itIsCaught:
        highestTxt=hex(highest)
        highestTxt=highestTxt[:-3]
        highestTxt+="000"
        highest=int(highestTxt,16)
        # print (hex(highest), highestTxt)
        newRet=highest-0x2000
        return True, newRet
    else:
        return False, 0
def checkNeeds(pe):
    highest=0x1005000
    start=0x1005000

    startRet=0x900000

    for q in pe:
        if pe[q].emBase !=0:     
            topSizeForMod=pe[q].emBase + len(pe[q].data)+0x40000
            # print (q, hex(pe[q].emBase),    "topSizeForMod", hex(topSizeForMod))
            
            if topSizeForMod > highest:
                highest=topSizeForMod
    # print ("highest", hex(highest))
    if highest!=start:
        highestTxt=hex(highest)
        highestTxt=highestTxt[:-3]
        highestTxt+="000"
        highest=int(highestTxt,16)
        # print (hex(highest), highestTxt)
        return True, highest
    else:
        return False, 0

saveForLater=""
def addImgsToEmulation(pe,mu):   
    # lowest=None
    global saveForLater
    saveForLater=""
    dp("addImgsToEmulation") 
    for q in pe:
        if pe[q].emBase !=0:     
            # print (red,q,  "trying    ", res,hex(pe[q].emBase), "size", hex(len(pe[q].data)))   

            try:
                # print(mag,q, hex(pe[q].emBase),res)

                mu.mem_write(pe[q].emBase, pe[q].data)
                # print ("   ===>    succeded\n\t",hex(pe[q].emBase, + hex(pe[q].emBase+len(pe[q].data))))
                saveForLater+= q + ": succeded --> \t" + hex(pe[q].emBase) + " " + hex(pe[q].emBase+len(pe[q].data))+"\n"
            except:
                # end=pe[q].emBase+len(pe[q].data)
                # print (q,"********memory loading error1*********\n\t",hex(pe[q].emBase), hex(end))
                
                topSizeForMod=len(pe[q].data)+0x40000
                highestTxt=hex(topSizeForMod)
                highestTxt=highestTxt[:-3]
                highestTxt+="000"
                maxSize=int(highestTxt,16)
                try:
                    mu.mem_map(pe[q].emBase, maxSize)
                    mu.mem_write(pe[q].emBase, pe[q].data)
                    # print ("Mapped and wrote")
                    saveForLater+= q +":  TRY AGAIN --> \t" + hex(pe[q].emBase) + " " + hex(pe[q].emBase+len(pe[q].data))

                except Exception as e:
                    dp (red,q, "********memory loading error2*********",res)
                    qS=pe[q].emBase+len(pe[q].data)
                    dp ("\n\t",hex(pe[q].emBase), hex(qS))

                    dp(yel,"ERROR: %s" % e)
                    dp(traceback.format_exc(),res)


    # print ("press any key")
    # input()
distanceDict={ 
    'targetDllString':{'distanceToPayload':0x400, 'numLoc':2,
        'loc1':{'distanceFromPayload':0,'isText':True, 'String':'msvcrt.dll','size':12,'NullAfterString':True,'isStruct':False},
        'loc2':{'distanceFromPayload':12,'isText':True, 'String':'system','size':8,'NullAfterString':True,'isStruct':False},
        'loc3':{'distanceFromPayload':20,'isText':True, 'String':'calc','size':6,'NullAfterString':True,'isStruct':False},
    },

    'System':{'distanceToPayload':0x400, 'numLoc':3,
        'loc1':{'distanceFromPayload':0,'isText':True, 'String':'msvcrt.dll','size':12,'NullAfterString':True,'isStruct':False},
        'loc2':{'distanceFromPayload':12,'isText':True, 'String':'system','size':8,'NullAfterString':True,'isStruct':False},
        'loc3':{'distanceFromPayload':20,'isText':True, 'String':'calc','size':6,'NullAfterString':True,'isStruct':False},
    },
    'lpProcName':{'distanceToPayload':0x700, 'numLoc':1,
        'loc1':{'distanceFromPayload':0,'isText':True, 'String':'kernel32.dll','size':15,'NullAfterString':True,'isStruct':False},
    },

    'WinExec':{'distanceToPayload':0x400, 'numLoc':1,
        'loc1':{'distanceFromPayload':0,'isText':True, 'String':'calc','size':6,'NullAfterString':True,'isStruct':False},
    },


    'DeleteFileA':{'distanceToPayload':0x400, 'numLoc':1,
        'loc1':{'distanceFromPayload':0,'isText':True, 'String':'C:\\My Files\\delete.txt','size':35,'NullAfterString':True,'isStruct':False},
    },



    'empty':{'distanceToPayload':0x700, 'numLoc':5,
        'loc1':{'distanceFromPayload':0,'isText':False, 'String':None,'size':10,'NullAfterString':False,'isStruct':False},
        'loc2':{'distanceFromPayload':0,'isText':False, 'String':None,'size':10,'NullAfterString':False,'isStruct':False}
    },
}


class ropParms:                  
    def __init__(self, ApiSyscall,  direction, distEsp, startEsp, numP,winApi=None,retAddress=None,param1=None, param2=None,param3=None,param4=None, param5=None,param6=None,param7=None,param8=None,param9=None):
        #address in memory,e.g. esp, where these params are.
        if ApiSyscall=="winApi":
            self.startEsp=startEsp
            self.distEsp=distEsp
            self.direction=direction # e.g. Inc or Dec 
            self.numP=numP
            self.shellcode=None
            self.param1=None
            self.param2=None
            self.param3=None
            self.param4=None
            self.param5=None
            self.param6=None
            self.param7=None
            self.param8=None
            self.param9=None
            self.shellcode=None
            self.hasDistance=None
            self.loc1=0
            self.loc2=0
            self.loc3=0
            self.loc4=0
            self.loc5=0
            self.loc6=0
            self.loc7=0
            self.locString1=None
            self.locString2=None
            self.locString3=None
            self.locString4=None
            self.locString5=None
            self.locString6=None
            self.locString7=None


            if direction=="inc":
                distEsp=distEsp+startEsp + 4 # (+4 compensation for initial ret to start things in emulation)
                self.winApi=distEsp + 0x0
                self.RA=distEsp + 0x4
                self.param1=distEsp + 0x8
                self.param2=distEsp + 0xc
                self.param3=distEsp + 0x10
                self.param4=distEsp + 0x14
                self.param5=distEsp + 0x18
                self.param6=distEsp + 0x1c
                self.param7=distEsp + 0x20
                self.param8=distEsp + 0x24
                self.param9=distEsp + 0x28

            elif direction=="dec":

                #  DIRECTIONALITY:  Go to first param and neg until we initialize them all
                #               p1p2p3p4p5p6     <- (dec)           payload   rop gadgets   
                # dp ("startEsp", hex(startEsp), "distEsp", hex(distEsp))
                distEsp=distEsp+startEsp  + 4 # (+4 compensation for initial ret to start things in emulation)
                pDist=0
                keepGoing=False
                if numP==9 or keepGoing:
                    self.param9=distEsp + pDist  + 4 # (+4 compensation for initial ret to start things in emulation)
                    pDist=pDist-4
                    keepGoing=True
                if numP==8 or keepGoing:
                    self.param8=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==7 or keepGoing:
                    self.param7=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==6 or keepGoing:
                    self.param6=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==5 or keepGoing:
                    self.param5=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==4 or keepGoing:
                    self.param4=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==3 or keepGoing:
                    self.param3=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==2 or keepGoing:
                    self.param2=distEsp + pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==1 or keepGoing:
                    self.param1=distEsp + pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==0 or keepGoing:
                    self.RA=distEsp + pDist
                    pDist=pDist-4
                    self.winApi=distEsp + pDist
                    pDist=pDist-4
        elif ApiSyscall=="syscall":
            self.startEsp=startEsp
            self.distEsp=distEsp
            self.direction=direction # e.g. Inc or Dec 
            self.numP=numP
            self.shellcode=None
            self.RA2=None
            self.RA1=None
            self.param1=None
            self.param2=None
            self.param3=None
            self.param4=None
            self.param5=None
            self.param6=None
            self.param7=None
            self.param8=None
            self.param9=None
            self.shellcode=None
            self.sysInvoke = None
            self.hasDistance=None
            

            if direction=="inc":
                distEsp=distEsp+startEsp + 4   # (+4 compensation for initial ret to start things in emulation)  
                self.sysInvoke = distEsp -4
                self.RA2=distEsp + 0x0
                self.RA1=distEsp + 0x4
                self.param1=distEsp + 0x8
                self.param2=distEsp + 0xc
                self.param3=distEsp + 0x10
                self.param4=distEsp + 0x14
                self.param5=distEsp + 0x18
                self.param6=distEsp + 0x1c
                self.param7=distEsp + 0x20
                self.param8=distEsp + 0x24
                self.param9=distEsp + 0x28

            elif direction=="dec":

                #  DIRECTIONALITY:  Go to first param and neg until we initialize them all
                #               p1p2p3p4p5p6     <- (dec)           payload   rop gadgets   
                # dp ("startEsp", hex(startEsp), "distEsp", hex(distEsp))
                distEsp=distEsp+startEsp   # (+4 compensation for initial ret to start things in emulation)
                pDist=0
                keepGoing=False
                if numP==9 or keepGoing:
                    self.param9=distEsp + pDist  + 4 # (+4 compensation for initial ret to start things in emulation)
                    pDist=pDist-4
                    keepGoing=True
                if numP==8 or keepGoing:
                    self.param8=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==7 or keepGoing:
                    self.param7=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==6 or keepGoing:
                    self.param6=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==5 or keepGoing:
                    self.param5=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==4 or keepGoing:
                    self.param4=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==3 or keepGoing:
                    self.param3=distEsp +  pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==2 or keepGoing:
                    self.param2=distEsp + pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==1 or keepGoing:
                    self.param1=distEsp + pDist
                    pDist=pDist-4
                    keepGoing=True
                if numP==0 or keepGoing:
                    self.RA1=distEsp + pDist
                    pDist=pDist-4
                    self.RA2=distEsp + pDist
                    pDist=pDist-4
                    self.sysInvoke =distEsp + pDist
                    pDist=pDist-4
                    
    def setShellcode(self,distToShell,ApiSyscall):
        # proximity to shellcode - it is relative to WinApi - whether backwards or forward
        # use positive to go after - use negative to go before
        if ApiSyscall=="winApi":
            if distToShell=="after":
                self.shellcode=self.winApi+(self.numP*4)+4+4
            elif type(distToShell)==int:
                self.shellcode=self.winApi+distToShell
        else:
            if distToShell=="after":
                self.shellcode=self.sysInvoke +(self.numP*4)+4+4+4
            elif type(distToShell)==int:
                self.shellcode=self.sysInvoke +distToShell


    def setDistanceLoc(self,patternType,stack,pivot):
        dp ("setDistanceLoc")
        numLoc=distanceDict[patternType]["numLoc"]

        if numLoc>=7:
            self.loc7=distanceDict[patternType]["loc7"]["distanceFromPayload"] +stack + pivot
            if distanceDict[patternType]["loc7"]["isText"]:
              self.locString7=  distanceDict[patternType]["loc7"]["String"]
        if numLoc>=6:
            self.loc6=distanceDict[patternType]["loc6"]["distanceFromPayload"] +stack + pivot
            if distanceDict[patternType]["loc6"]["isText"]:
              self.locString6=  distanceDict[patternType]["loc6"]["String"]
        if numLoc>=5:
            self.loc5=distanceDict[patternType]["loc5"]["distanceFromPayload"] +stack + pivot
            if distanceDict[patternType]["loc5"]["isText"]:
              self.locString5=  distanceDict[patternType]["loc5"]["String"]
        if numLoc>=4:
            self.loc4=distanceDict[patternType]["loc4"]["distanceFromPayload"] +stack + pivot
            if distanceDict[patternType]["loc4"]["isText"]:
              self.locString4=  distanceDict[patternType]["loc4"]["String"]
        if numLoc>=3:
            dp ("in loc3a")
            self.loc3=distanceDict[patternType]["loc3"]["distanceFromPayload"] +stack + pivot
            if distanceDict[patternType]["loc3"]["isText"]:
              self.locString3=  distanceDict[patternType]["loc3"]["String"]
            dp ("in loc3b")

        if numLoc>=2:
            self.loc2=distanceDict[patternType]["loc2"]["distanceFromPayload"] +stack + pivot
            if distanceDict[patternType]["loc2"]["isText"]:
              self.locString2=  distanceDict[patternType]["loc2"]["String"]       
        if numLoc >=1:
            self.loc1=distanceDict[patternType]["loc1"]["distanceFromPayload"] + stack + pivot
            if distanceDict[patternType]["loc1"]["isText"]:
              self.locString1=  distanceDict[patternType]["loc1"]["String"]
        self.hasDistance=True

    def showShellLoc(self):
        dp ("shellcode location: ", hex (self.shellcode))
    def show(self,mu,ApiSyscall):
        if ApiSyscall=="winApi":
            dp("winApi:", hex(self.winApi),binaryToStr(mu.mem_read(self.winApi, 4)))
            dp("Return address:", hex(self.RA), binaryToStr(mu.mem_read(self.RA, 4)))
        if self.hasDistance:
            dp("loc1:", hex(self.loc1),binaryToStr(mu.mem_read(self.loc1, 4)))
            try:
                dp("loc2:", hex(self.loc2),binaryToStr(mu.mem_read(self.loc2, 4)))
            except:
                pass
            try:
                dp("loc3:", hex(self.loc3),binaryToStr(mu.mem_read(self.loc3, 4)))
            except:
                pass
            try:
                dp("loc4:", hex(self.loc4),binaryToStr(mu.mem_read(self.loc4, 4)))
            except:
                pass
            try:
                dp("loc5:", hex(self.loc5),binaryToStr(mu.mem_read(self.loc5, 4)))
            except:
                pass                
            try:
                dp("loc6:", hex(self.loc6),binaryToStr(mu.mem_read(self.loc6, 4)))
            except:
                pass
            try:
                dp("loc7:", hex(self.loc7),binaryToStr(mu.mem_read(self.loc7, 4)))
            except:
                pass                
            dp ("###3", self.loc3)
            # dp("loc2:", hex(self.loc2),binaryToStr(mu.mem_read(self.loc2, 4)))
            # dp("loc3:", hex(self.loc3),binaryToStr(mu.mem_read(self.loc3, 4)))
            # dp("loc4:", hex(self.loc4),binaryToStr(mu.mem_read(self.loc4, 4)))

        if ApiSyscall=="syscall":
            dp ("nump", self.numP)
            dp("sysInvoke:", hex(self.sysInvoke),binaryToStr(mu.mem_read(self.sysInvoke, 4)))
            dp("Return address 1:", hex(self.RA1), binaryToStr(mu.mem_read(self.RA1, 4)))
            dp("Return address 2:", hex(self.RA2), binaryToStr(mu.mem_read(self.RA2, 4)))

            if self.numP >=1:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param1, 4), 'little'), 4), 'little')
                    dp("param 1:",hex(self.param1),binaryToStr(mu.mem_read(self.param1, 4)),hex(int.from_bytes(mu.mem_read(self.param1, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 1:",hex(self.param1),binaryToStr(mu.mem_read(self.param1, 4)),hex(int.from_bytes(mu.mem_read(self.param1, 4), 'little')))
            if self.numP >=2:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param2, 4), 'little'), 4), 'little')
                    dp("param 2:",hex(self.param2) ,binaryToStr(mu.mem_read(self.param2, 4)),hex(int.from_bytes(mu.mem_read(self.param2, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 2:",hex(self.param2) ,binaryToStr(mu.mem_read(self.param2, 4)),hex(int.from_bytes(mu.mem_read(self.param2, 4), 'little')))
            if self.numP >=3:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param3, 4), 'little'), 4), 'little')
                    dp("param 3:",hex(self.param3),binaryToStr(mu.mem_read(self.param3, 4)),hex(int.from_bytes(mu.mem_read(self.param3, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 3:",hex(self.param3),binaryToStr(mu.mem_read(self.param3, 4)),hex(int.from_bytes(mu.mem_read(self.param3, 4), 'little')))
            if self.numP >=4:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param4, 4), 'little'), 4), 'little')
                    dp("param 4:",hex(self.param4),binaryToStr(mu.mem_read(self.param4, 4)),hex(int.from_bytes(mu.mem_read(self.param4, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 4:",hex(self.param4),binaryToStr(mu.mem_read(self.param4, 4)),hex(int.from_bytes(mu.mem_read(self.param4, 4), 'little')))
            if self.numP >=5:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param5, 4), 'little'), 4), 'little')
                    dp("param 5:",hex(self.param5),binaryToStr(mu.mem_read(self.param5, 4)),hex(int.from_bytes(mu.mem_read(self.param5, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 5:",hex(self.param5),binaryToStr(mu.mem_read(self.param5, 4)),hex(int.from_bytes(mu.mem_read(self.param5, 4), 'little')))
            if self.numP >=6:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param6, 4), 'little'), 4), 'little')
                    dp("param 6:",hex(self.param6),binaryToStr(mu.mem_read(self.param6, 4)),hex(int.from_bytes(mu.mem_read(self.param6, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 6:",hex(self.param6),binaryToStr(mu.mem_read(self.param6, 4)),hex(int.from_bytes(mu.mem_read(self.param6, 4), 'little')))
            if self.numP >=7:            
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param7, 4), 'little'), 4), 'little')
                    dp("param 7:",hex(self.param7),binaryToStr(mu.mem_read(self.param7, 4)),hex(int.from_bytes(mu.mem_read(self.param7, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 7:",hex(self.param7),binaryToStr(mu.mem_read(self.param7, 4)),hex(int.from_bytes(mu.mem_read(self.param7, 4), 'little')))
            if self.numP >=8:            
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param8, 4), 'little'), 4), 'little')
                    dp("param 8:",hex(self.param8),binaryToStr(mu.mem_read(self.param8, 4)),hex(int.from_bytes(mu.mem_read(self.param8, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 8:",hex(self.param8),binaryToStr(mu.mem_read(self.param8, 4)),hex(int.from_bytes(mu.mem_read(self.param8, 4), 'little')))
            if self.numP >=9:
                
                try:
                    test2=int.from_bytes(mu.mem_read(int.from_bytes(mu.mem_read(self.param9, 4), 'little'), 4), 'little')
                    dp("param 9:",hex(self.param9),binaryToStr(mu.mem_read(self.param9, 4)),hex(int.from_bytes(mu.mem_read(self.param9, 4), 'little')),"\t-->", hex(test2))
                except:
                    dp("param 9:",hex(self.param9),binaryToStr(mu.mem_read(self.param9, 4)),hex(int.from_bytes(mu.mem_read(self.param9, 4), 'little')))
        


    def giveParamLocOnStack(self,paramNum,ApiSyscall):
        # dp ("giveParamLocOnStack", paramNum, ApiSyscall)
        if ApiSyscall=="winApi":
            paramLookup={1: self.param1,2: self.param2,3: self.param3,4: self.param4,5: self.param5,6: self.param6,7: self.param7,8: self.param8 ,9: self.param9, "winApi":self.winApi, "RA": self.RA, "shellcode":self.shellcode,"loc1":self.loc1,"loc2":self.loc2,"loc3":self.loc3,"loc4":self.loc4,"loc5":self.loc5,"loc6":self.loc6}
        else:
            paramLookup={1: self.param1,2: self.param2,3: self.param3,4: self.param4,5: self.param5,6: self.param6,7: self.param7,8: self.param8 ,9: self.param9, "sysInvoke":self.sysInvoke, "RA1": self.RA1, "RA2": self.RA2,"shellcode":self.shellcode}

        returnVal=paramLookup[paramNum]   

        return returnVal
RP=None
targetP=None
fakeWinAPIInner=b'\x99\x77\x66\x55'
ApiSyscall="winApi"
sysTarget2=0


def rop_testerRunROP(pe,n,gadgets, distEsp,IncDec,numP,targetP2,targetR, PWinApi,sysTarget,finalPivotGadget1, rValStr=None):
    # print(blu,"rop_testerRunROP", rValStr,res)
    global maxCount
    global winApiSyscallReached
    global oldEsp
    global ApiSyscall
    global fakeWinAPIInner
    global sysTarget2
    global RP
    global targetP
    global finalPivotGadgetG
    maxCount=0
    targetP=targetP2
    sysTarget2=sysTarget
    RP=None
    #target parameter = parameter that we wish to get to - find it on stack
    #target register - the register we are comparing targetP with - how far apart are they? for instnace, 8 bytes apart.
    global stopProcess
    global outFile
    global stack2
    global doAfterPivot
    global bGiveStack
    global givStDistance
    global bad_instruct_count
    global ApiSyscall
    outFile.write(saveForLater)

    bad_instruct_count=0

    
    bGiveStack=False
    givStDistance=0xdeadc0de
    finalPivotGadgetG=finalPivotGadget1
    doAfterPivot=False

    winApiSyscallReached=False
    stopProcess=False
    sizeG=len(gadgets)
    outFile.write("New Emulation\n\n\n*************************************************************************************************    "+     "         length gadgets: " +  str(sizeG) + "      " +hex(sizeG))
    # outFile.write("finalPivotGadgetG:  "+hex(finalPivotGadgetG))
    # print("finalPivotGadgetG:", hex(finalPivotGadgetG))

    dp ("rop_testerRunROP", targetP, targetR)
    dp("*************************************************************************************************")
    doGC()
    try:
        outFile.write(rValStr)
    except:
        pass
    gOutput=gadgetRegs()
    gOutput.start(gRegs)
    try:
        # Initialize emulator in X86-32bit mode
        global maxAddress
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        maxCode=0x5005000
                # 0x900000
        # bChkNeeds,highest= checkNeeds(pe)
        # if bChkNeeds and 2==3:
        #     maxCode=highest
        try:
            mu.mem_unmap(0x00000000, maxCode)
        except:
            # print ("no need to unmap")
            pass
        try:
            mu.mem_map(0x00000000, maxCode)
        except:
            print (red,"********memory loading erorr: emulation will fail*********",res)
        # mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        stack=0x150000
        stack2=stack
        if targetP=="sysInvoke":
            ApiSyscall="syscall"
        else:
            ApiSyscall="winApi"
        RP=ropParms(ApiSyscall,IncDec,distEsp,stack,numP)   # inc/dec, direction, distEsp, startEsp, numP

        if rValStr!=None:
            RP.setDistanceLoc(rValStr,stack,distanceDict[rValStr]["distanceToPayload"])

        RP.show(mu,ApiSyscall)
        RP.setShellcode("after",ApiSyscall)
        # RP.setShellcode(0x200)
        RP.showShellLoc()

        stackT=stack-0x1000
        EXTRA_ADDR=0x50000
        startB=b"\x68\x00\x00\x05\x00"
        beginTesting=b"\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3"

        # mu.mem_map(stackT, 2 * 1024 * 5024)
        # mu.mem_map(EXTRA_ADDR, 2 * 1024 * 1024)
        mu.mem_write(EXTRA_ADDR, b'\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc')
        # mu.mem_write(stack,b'\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44\x45\x45\x45\x45\x46\x46\x46\x46')
        mu.mem_write(stack,gadgets)

        # try:
        #     mu.mem_map(0x99999000, 0x1000)
        # except:
        #     print (red,"********memory loading erorr: emulation will fail*********",res)
        # try:
        #     mu.mem_write(0x99999990,b"\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3")
        # except:
        #     print ("ERROR")

        try:

            mu.mem_write(PWinApi,fakeWinAPIInner)

        
        except UcError as e:
            dp("ERROR: %s" % e)
            dp(traceback.format_exc())
            dp ("memory writing error!")
            dp ("winApi", hex(PWinApi))
            tempWin=hex(PWinApi)[:-4]+"0000"
            try:
                tempWin=int(tempWin,16)
            except:
                tempWin=int(tempWin)

            dp ("tempWin", hex(tempWin))
            mu.mem_map(tempWin, 0x10000)
            mu.mem_write(PWinApi,fakeWinAPIInner)

        fakeInner2=0x55667799
        try:

            mu.mem_write(fakeInner2,b'\x00\x00\x00\x00\x00')

        
        except UcError as e:
            try:
                dp ("winApi", hex(PWinApi))
                tempF=hex(fakeInner2)[:-4]+"0000"
                try:
                    tempF=int(tempF,16)
                except:
                    tempF=int(tempF)

                # dp ("tempF", hex(tempF))
                mu.mem_map(tempF, 0x10000)
                mu.mem_write(fakeInner2,b'\x00\x00\x00\x00\x00')
                dp ("succeeded")
            except:
                dp("memory writing error2!")
        


        image2=0x900000
        bCheckRetStart,newRet= checkRetStart(pe)
        if bCheckRetStart:
            image2=newRet
        try:
            mu.mem_write(image2,beginTesting)
        except:
            mu.mem_map(image2, 0x10000)
            mu.mem_write(image2,beginTesting)

        try:
            #### this is is what will be at 0xc0 - just verification for the emulation logs - not used by the tool currently.
            mu.mem_write(0xc0, b"\x99\x99\x99\x99")
            # print("fs",binaryToStr(mu.mem_read(0xc0, 0x4)))

            

        except:
            print (red,"  Writing to fs:[0xc0] fails.",res)
            # input()

        addImgsToEmulation(pe,mu)
        # print("press any key 2")
        # input()
        testCode=b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3\xc3'
        # mu.mem_write(stack,EXTRA_ADDR.to_bytes(4, "little"))
        maxSize=len(testCode)
        maxAddress =  ADDRESS + maxSize-1
    
        mu.mem_write(ADDRESS, testCode)

        # initialize machine registers
        # dp ("stack2A",binaryToStr(mu.mem_read(stack, 0x10)))

        mu.reg_write(UC_X86_REG_EAX, gRegs.eax)
        mu.reg_write(UC_X86_REG_EBX, gRegs.ebx)
        mu.reg_write(UC_X86_REG_ECX, gRegs.ecx)
        mu.reg_write(UC_X86_REG_EDX, gRegs.edx)
        mu.reg_write(UC_X86_REG_ESI, gRegs.esi)
        mu.reg_write(UC_X86_REG_EDI, gRegs.edi)
        # mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x440000)
        mu.reg_write(UC_X86_REG_ESP, stack)
        mu.reg_write(UC_X86_REG_EBP, stack-600)
        gOutput.setEsp(stack)
        # dp ("stack2B",binaryToStr(mu.mem_read(stack, 0x10)))

        gOutput.setEbp(stack-600)
        gOutput.setEsp(stack)

        giveRegOuts(mu)
        # tracing all basic blocks with customized callback
        # mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        hook2=mu.hook_add(UC_HOOK_CODE, hook_code2)


        # emulate machine code in infinite time
        
        # mu.emu_start(ADDRESS2, ADDRESS2 + len(testCode))
        # dp ("stack2",binaryToStr(mu.mem_read(stack, 0x10s0)))
        # mu.emu_start(image2, image2 + len(testCode))
        
        dp ("second rp.show()")
        RP.show(mu,ApiSyscall)
        

        # dp ("loc 1 mem",binaryToStr(mu.mem_read(stack+0x700, 0x100)))
        # mu.emu_start(image2, 0xFFFFF)
        # mu.emu_start(image2, image2+200)
        mu.emu_start(image2, image2+0xFFFFF)



        # now dp out some registers
        dp(">>> Emulation done. Below is the CPU context")

        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_edi = mu.reg_read(UC_X86_REG_EDI)
        r_esi = mu.reg_read(UC_X86_REG_ESI)
        r_ebp = mu.reg_read(UC_X86_REG_EBP)
        r_esp = mu.reg_read(UC_X86_REG_ESP)

        # def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp):
        gOutput.set(r_eax,r_ebx,r_ecx,r_edx,r_edi,r_esi,r_ebp,r_esp,True)
        # dp ("targetP",targetP)
        # dp("param loc on stack", hex(RP.giveParamLocOnStack(targetP)), "param ", targetP)
        # dp(targetR," loc", hex(gOutput.giveRegLoc(targetR)))

        # dp(hex(gOutput.diffEsp), hex(gOutput.esp))
        if targetR != None:
            locReg=gOutput.giveRegLoc(targetR)
            if ApiSyscall=="syscall":
                locParam=RP.giveParamLocOnStack(targetP,"syscall")
            else:
                locParam=RP.giveParamLocOnStack(targetP,"winApi")
        else:
            locParam=0
            locReg=0
            # locShell=RP.giveParamLocOnStack("shellcode")

        # outFile.close()
        outFile.write("finalPivotGadgetG: " + hex(finalPivotGadgetG)+"\n" )

        diffPR=0
        if targetR != None:
            diffPR=locParam-locReg
            dp ("API or Syscall Reached?", winApiSyscallReached)
            dp ("\n\n***********locParam", targetP, hex(locParam), "locReg", targetR, hex(locReg))
            dp ("diff", hex(diffPR),"\n")
            RP.show(mu,ApiSyscall)

        
        # dp ("locShell", hex(locShell))
        # giveStack(mu,32)

        try:

            mu.emu_stop()
            # dp ("stopped1")
            # mu.emu_start(image2, 0xFFFFFFFF)

        
        except:
            pass

        # m = unicorn.Uc.mem_unmap(self, addr, size)
        try:
            mu.mem_unmap(0x00000000, maxCode)
        except:
            # print ("no need to unmap")
            pass
        # dp ("unmapped")
        # mu.mem_write(stack,gadgets)
        uc_err = mu.hook_del(hook2)
        # mu.hook_add(UC_HOOK_CODE, hook_code2)
        dp ("uc_err", uc_err)
        stopProcess = False


        return gOutput, locParam, locReg, winApiSyscallReached, givStDistance

    except UcError as e:
        doGC()
        # print("ERROR rop_testerRunROP: %s" % e)
        errorMsg=(traceback.format_exc())
        # print(errorMsg)
        giveRegOuts(mu)
        outFile.write(errorMsg)
        gOutput.setError(e)
        # errorESP(mu)
        giveRegOuts(mu)
        try:
            locReg=gOutput.giveRegLoc(targetR)
        except:
            pass
        if ApiSyscall=="syscall":
            locParam=RP.giveParamLocOnStack(targetP,"syscall")
        else:
            locParam=RP.giveParamLocOnStack(targetP,"winApi")
        return gOutput, locParam,oldEsp,winApiSyscallReached,givStDistance

rop_testerCalled=0
prevRop_testerCalled=0

def rop_tester(testCode, ID=False, regWritable=False):
    # print (mag,"rop_tester",res)
    dp("*************************************************************************************************")
    outFile.write("Roptester:\t")
    outFile.write(binaryToStr(testCode)+"\n")


    
    global rop_testerCalled
    global prevRop_testerCalled
    checkDoGC=prevRop_testerCalled-rop_testerCalled
    if checkDoGC==20:
        prevRop_testerCalled=rop_testerCalled
        doGC()  ## manual garbage collection - memory problems

    gOutput=gadgetRegs()
    gOutput.start(gRegs)
    try:
        # Initialize emulator in X86-32bit mode
        global maxAddress

        # testCode=shellList[0]
        try:
            mu = Uc(UC_ARCH_X86, UC_MODE_32)
        except Exception as e:
            print(yel,"ERROR: %s" % e)
            print(traceback.format_exc(),res)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        stack=0x440000
        stackT=stack-0x1000
        EXTRA_ADDR=0x50000
        startB=b"\x68\x00\x00\x05\x00"
        mu.mem_map(stackT, 2 * 1024 * 5024)
        mu.mem_map(EXTRA_ADDR, 2 * 1024 * 1024)
        mu.mem_write(EXTRA_ADDR, b'\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc')
        mu.mem_write(stack,b'\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44\x45\x45\x45\x45\x46\x46\x46\x46')
        

        # mu.mem_write(stack,EXTRA_ADDR.to_bytes(4, "little"))
        maxSize=len(testCode)
        maxAddress =  ADDRESS + maxSize-1

    
        mu.mem_write(ADDRESS, testCode)

        # initialize machine registers
        if regWritable != False:
            gOutput.setRegWrit(regWritable, stack-0x200)
        mu.reg_write(UC_X86_REG_EAX, gOutput.eax)
        mu.reg_write(UC_X86_REG_EBX, gOutput.ebx)
        mu.reg_write(UC_X86_REG_ECX, gOutput.ecx)
        mu.reg_write(UC_X86_REG_EDX, gOutput.edx)
        mu.reg_write(UC_X86_REG_ESI, gOutput.esi)
        mu.reg_write(UC_X86_REG_EDI, gOutput.edi)
        # mu.reg_write(UC_X86_REG_XMM0, 0x000102030405060708090a0b0c0d0e0f)
        # mu.reg_write(UC_X86_REG_XMM1, 0x00102030405060708090a0b0c0d0e0f0)

        # mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x440000)
        mu.reg_write(UC_X86_REG_ESP, stack)
        mu.reg_write(UC_X86_REG_EBP, stack-600)
        gOutput.setEsp(stack)
        gOutput.setEbp(stack-600)

        dp ("start")
        giveRegOuts(mu)
        dp (".")
        # tracing all basic blocks with customized callback
        # mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        
        mu.emu_start(ADDRESS, ADDRESS + len(testCode))

        # input()

        # now dp out some registers
        dp(">>> Emulation done. Below is the CPU context")

        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_edi = mu.reg_read(UC_X86_REG_EDI)
        r_esi = mu.reg_read(UC_X86_REG_ESI)
        r_ebp = mu.reg_read(UC_X86_REG_EBP)
        r_esp = mu.reg_read(UC_X86_REG_ESP)

        # def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp):
        gOutput.set(r_eax,r_ebx,r_ecx,r_edx,r_edi,r_esi,r_ebp,r_esp,True)

        try:
            mu.emu_stop()
            dp ("stopped")
            mu=""
            # mu.release_handle()
        except:
            pass
        return gOutput

    except UcError as e:
        dp(yel,"ERROR: %s" % e)
        dp(traceback.format_exc(),res)
        doGC()
        if ID!="special":
            gOutput=  rop_tester(testCode,"special")
            return gOutput
        giveRegOuts(mu)
        gOutput.setError(e)
        # errorESP(mu)
        giveRegOuts(mu)
        return gOutput


def findMemRegs(input_str):
    regs=[]
    lst=input_str.split("#")
    result = ''.join(lst[1:])
    # print (result)
    pattern = re.compile(r'\[(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*[\s\w\[\]]*[+\-]?\s*(0x[0-9a-fA-F]+|\d+)\]')
    pattern2 = re.compile(r'\[(eax|ebx|ecx|edx|esi|edi|ebp|esp)\]')

    matches = pattern.findall(result)
    matches2 = pattern2.findall(result)
    registers = set(match[0] for match in matches)
    registers2 = set(match for match in matches2)
    registers=registers.union(registers2)
    for r in registers:
        regs.append(r)
    return regs

def givDis(CODED2):
    offset=0
    returnVal = ""
    for i in cs.disasm(CODED2, offset):
        val =  i.mnemonic + " " + i.op_str + " # "
        returnVal +=val
    returnVal=returnVal[:-3]
    return returnVal

def adjustRegForMem(lst,gOutput):
    startVal= 0x1010
    for reg in lst:
        if reg=="eax":
            gOutput.setEaxTemp(startVal)
        elif reg=="ebx":
            gOutput.setEbxTemp(startVal)
        elif reg=="ecx":
            gOutput.setEcxTemp(startVal)
        elif reg=="edx":
            gOutput.setEdxTemp(startVal)
        elif reg=="edi":
            gOutput.setEdiTemp(startVal)
        elif reg=="esi":
            gOutput.setEsiTemp(startVal)
        elif reg=="ebp":
            gOutput.setEbpTemp(startVal)
        startVal+=0x222
def rop_testerFS(testCode, fsReg,fsAdjust, ID=False, regWritable=False):
    # print (mag,"rop_tester",res)
    dp("*************************************************************************************************")
    outFile.write("RoptesterFS:\t")
    testCode=testCode+b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"

    outFile.write(binaryToStr(testCode)+"\n")
  
    global rop_testerCalled
    global prevRop_testerCalled
    global bad_instruct_count
    global syscallValAtESP
    global snapshotESP


    bad_instruct_count=4
    checkDoGC=prevRop_testerCalled-rop_testerCalled
    if checkDoGC==20:
        prevRop_testerCalled=rop_testerCalled
        doGC()  ## manual garbage collection - memory problems

    gOutput=gadgetRegs()
    gRegs2= copy.deepcopy(gRegs)

    gOutput.start(gRegs2)
    try:
        # Initialize emulator in X86-32bit mode
        global maxAddress

        # testCode=shellList[0]
        try:
            mu = Uc(UC_ARCH_X86, UC_MODE_32)
        except Exception as e:
            print(yel,"ERROR: %s" % e)
            print(traceback.format_exc(),res)

        # map 2MB memory for this emulation
        # mu.mem_map(ADDRESS, 4 * 1024 * 1024)
        maxAd=0xbad0000

        ADDRESS=0
        
        mu.mem_map(ADDRESS, maxAd)

        stack=0x440000
        stackT=stack-0x10000
        EXTRA_ADDR=0x50000
        startB=b"\x68\x00\x00\x05\x00"
        mu.mem_write(stack,b'\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44\x45\x45\x45\x45\x46\x46\x46\x46')

        # mu.mem_write(stack,EXTRA_ADDR.to_bytes(4, "little"))
        maxSize=len(testCode)
        # testCode+=b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"+testCode+b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"

        maxAddress =  ADDRESS + maxSize + 0x20-1
        # print ("maxAddress", hex(maxAddress))

        fsStart=0x2000
        mu.mem_write(fsStart, testCode)
        # print("rop_testerFS",gre,givDis(testCode),res)
        memRegs=findMemRegs(givDis(testCode))
        # print("findMemRegs",gre,memRegs,res)
        adjustRegForMem(memRegs,gOutput)
                
        # initialize machine registers
        if regWritable != False:
            gOutput.setRegWrit(regWritable, stack-0x200)
        mu.reg_write(UC_X86_REG_EAX, gOutput.eax)
        mu.reg_write(UC_X86_REG_EBX, gOutput.ebx)
        mu.reg_write(UC_X86_REG_ECX, gOutput.ecx)
        mu.reg_write(UC_X86_REG_EDX, gOutput.edx)
        mu.reg_write(UC_X86_REG_ESI, gOutput.esi)
        mu.reg_write(UC_X86_REG_EDI, gOutput.edi)
        r_fs = mu.reg_read(UC_X86_REG_FS)
        mu.reg_write(UC_X86_REG_FS, 0x2)  ### larger numbers fail - i don't think it matters here to be accurate
        mu.mem_write(0xc0, b"\xaa\xaa\xaa\x00")
        mu.mem_write(0xaaaaaa, b"\x90\x90\x90\x90")


        # print (cya,"fsReg", fsReg, hex(fsAdjust),res)
        if fsReg=="eax":
            gOutput.setEaxTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_EAX, gOutput.eax)
        elif fsReg=="ebx":
            gOutput.setEbxTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_EBX, gOutput.ebx)
        elif fsReg=="ecx":
            gOutput.setEcxTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_ECX, fsAdjust)
        elif fsReg=="edx":
            gOutput.setEdxTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_EDX, gOutput.edx)
        elif fsReg=="edi":
            gOutput.setEdiTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_EDI, gOutput.edi)
        elif fsReg=="esi":
            gOutput.setEsiTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_ESI, gOutput.esi)
        elif fsReg=="ebp":
            gOutput.setEbpTemp(fsAdjust)
            mu.reg_write(UC_X86_REG_EBP, gOutput.ebp)
        mu.reg_write(UC_X86_REG_ESP, stack)
        mu.reg_write(UC_X86_REG_EBP, stack-600)
        gOutput.setEsp(stack)
        gOutput.setEbp(stack-600)


        giveRegOuts(mu)
        # tracing all basic blocks with customized callback
        # mu.hook_add(UC_HOOK_BLOCK, hook_block)
        mu.hook_add(UC_HOOK_CODE, hook_codeFS)
        mu.emu_start(fsStart, fsStart + len(testCode)+0x120)
        # now dp out some registers
        dp(">>> Emulation done. Below is the CPU context")
        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_edi = mu.reg_read(UC_X86_REG_EDI)
        r_esi = mu.reg_read(UC_X86_REG_ESI)
        r_ebp = mu.reg_read(UC_X86_REG_EBP)
        r_esp = mu.reg_read(UC_X86_REG_ESP)
        # someBy=mu.mem_read(mu.reg_read(UC_X86_REG_ESP), 0x4)
        # stacky=binaryToStr(mu.mem_read(mu.reg_read(UC_X86_REG_ESP-0xc), 0x100))

        # print (stacky)
        # unpacked = struct.unpack("<I", someBy)
        # topEsp=unpacked[0]
        # global topEsp      
        # print (red,"topEsp", hex(topEsp))
        # print (red,"topEsp", hex(topEsp))

        # def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp):
    
        gOutput.setStackPivot(snapshotESP)
        gOutput.set(r_eax,r_ebx,r_ecx,r_edx,r_edi,r_esi,r_ebp,r_esp,True)
        try:
            mu.emu_stop()
            dp ("stopped")
            mu=""
            # mu.release_handle()
        except:
            pass
        return gOutput, syscallValAtESP

    except UcError as e:
        dp(yel,"ERROR: %s" % e)
        dp(traceback.format_exc(),res)
        outFile.write("errror: " +  str(e) + "\t" +traceback.format_exc())

        doGC()
        if ID!="special":
            gOutput=  rop_tester(testCode,"special")
            return gOutput,syscallValAtESP
        giveRegOuts(mu)
        gOutput.setError(e)
        # errorESP(mu)
        giveRegOuts(mu)
        return gOutput,syscallValAtESP

def rop_testerDoublePush(testCode,first,second):
    dp("*************************************************************************************************")
    dp (testCode.hex())
    dp ("first", first, "second", second)
    gOutput=gadgetRegs()
    # gOutput.start(gRegs)
    try:
        # Initialize emulator in X86-32bit mode
        global maxAddress

        # testCode=shellList[0]


        stack=0x440000

        regsStart={"eax": 0x4, "ebx": 0x4, "ecx":0x4, "edx":0x4,"edi":0x4,"esi":0x4,"ebp":0x4,"esp":stack}
        regsStart[first]=0x66666666
        regsStart[second]=0x33333333

        skipEbpAssignment=False
        if first == "ebp" or second == "ebp":
            dp ("skipEbpAssignment")
            skipEbpAssignment=True

        dp ("ebp", regsStart["ebp"])
        gRegs.set(regsStart["eax"],regsStart["ebx"],regsStart["ecx"],regsStart["edx"],regsStart["edi"],regsStart["esi"],regsStart["ebp"],regsStart["esp"])  #  set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp, changed=False):
        gOutput.start(gRegs)
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        
        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        stackT=stack-0x1000
        EXTRA_ADDR=0x50000
        stackWeirdStart=0x440000
        startB=b"\x68\x00\x00\x05\x00"
        mu.mem_map(stackT, 2 * 1024 * 5024)
        mu.mem_map(EXTRA_ADDR, 2 * 1024 * 1024)
        mu.mem_write(EXTRA_ADDR, b'\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc')
        mu.mem_write(stackWeirdStart,EXTRA_ADDR.to_bytes(4, "little"))
        maxSize=len(testCode)
        maxAddress =  ADDRESS + maxSize-1

    
        mu.mem_write(ADDRESS, testCode)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_EAX, gRegs.eax)
        mu.reg_write(UC_X86_REG_EBX, gRegs.ebx)
        mu.reg_write(UC_X86_REG_ECX, gRegs.ecx)
        mu.reg_write(UC_X86_REG_EDX, gRegs.edx)
        mu.reg_write(UC_X86_REG_ESI, gRegs.esi)
        mu.reg_write(UC_X86_REG_EDI, gRegs.edi)
        if skipEbpAssignment:
            mu.reg_write(UC_X86_REG_EBP, gRegs.ebp)

        # mu.reg_write(UC_X86_REG_XMM0, 0x000102030405060708090a0b0c0d0e0f)
        # mu.reg_write(UC_X86_REG_XMM1, 0x00102030405060708090a0b0c0d0e0f0)

        # mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x440000)
        mu.reg_write(UC_X86_REG_ESP, stack)

        if not skipEbpAssignment:
            dp ("making ebp")
            mu.reg_write(UC_X86_REG_EBP, stack-600)
            gOutput.setEbp(stack-600)

        gOutput.setEsp(stack)

        dp ("start")
        giveRegOuts(mu)
        dp (".")
        # tracing all basic blocks with customized callback
        # mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        
        mu.emu_start(ADDRESS, ADDRESS + len(testCode))

        # input()

        # now dp out some registers
        dp(">>> Emulation done. Below is the CPU context")

        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_edi = mu.reg_read(UC_X86_REG_EDI)
        r_esi = mu.reg_read(UC_X86_REG_ESI)
        r_ebp = mu.reg_read(UC_X86_REG_EBP)
        r_esp = mu.reg_read(UC_X86_REG_ESP)

        # def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp):
        gOutput.set(r_eax,r_ebx,r_ecx,r_edx,r_edi,r_esi,r_ebp,r_esp,True)

        esp = mu.reg_read(UC_X86_REG_ESP)


        dp ("esp", hex(esp))
        firstOut = mu.mem_read(esp,4)
        firstOut= int.from_bytes(firstOut, "little")
        dp ("1", hex(firstOut))



        secondOut = mu.mem_read(esp+4,4)
        secondOut= int.from_bytes(secondOut, "little")
        dp ("2", hex(secondOut))
   
        gOutput.CalculateRemainingRegs(first,second)     
        hgGadgetStatus=False
        if firstOut ==0x33333333 and secondOut == 0x66666666:
            dp ("Good HG gadget")
            hgGadgetStatus=True

        return gOutput, hgGadgetStatus


    except UcError as e:
        dp("ERROR: %s" % e)
        dp(traceback.format_exc())
        giveRegOuts(mu)
        gOutput.setError(e)
        # errorESP(mu)
        giveRegOuts(mu)
        
        return gOutput, False

evil_look_up={"eax": 0x11111111, "ebx": 0x22224222, "ecx":0x33333333, "edx":0x44444444,"edi":0x55555555,"esi":0x66666666,"ebp":0x77777777,"esp":0x88888888}
rev_evil_look_up={0x11111111:"eax", 0x22224222:"ebx",0x33333333:"ecx",0x44444444:"edx",0x55555555:"edi",0x66666666:"esi",0x77777777:"ebp",0x88888888:"esp"}

def rop_testerDoublePop(testCode,first):
    dp("*************************************************************************************************")
    dp (testCode.hex())
    dp ("first", first, "second", second)
    gOutput=gadgetRegs()
    # gOutput.start(gRegs)
    try:
        # Initialize emulator in X86-32bit mode
        global maxAddress

        # testCode=shellList[0]
        eax =2
        ebx=2
        ecx=2
        edx=2
        esi=2
        edi=2
        ebp=2

             
        skipEbpAssignment=False
        if first == "ebp":
            dp ("skipEbpAssignment")
            skipEbpAssignment=True



        dp ("ebp", ebp)
        gRegs.set(eax,ebx,ecx,edx,edi,esi,ebp,None)  #  set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp, changed=False):
        gOutput.start(gRegs)

        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        
        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        stack=0x440000
        stackT=stack-0x1000
        EXTRA_ADDR=0x50000
        stackWeirdStart=0x440000
        startB=b"\x68\x00\x00\x05\x00"
        mu.mem_map(stackT, 2 * 1024 * 5024)
        mu.mem_map(EXTRA_ADDR, 2 * 1024 * 1024)
        mu.mem_write(EXTRA_ADDR, b'\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc\x90\x90\x90\xCc\xcc\xcc')
        mu.mem_write(stackWeirdStart,EXTRA_ADDR.to_bytes(4, "little"))
        maxSize=len(testCode)
        maxAddress =  ADDRESS + maxSize-1

    
        mu.mem_write(ADDRESS, testCode)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_EAX, gRegs.eax)
        mu.reg_write(UC_X86_REG_EBX, gRegs.ebx)
        mu.reg_write(UC_X86_REG_ECX, gRegs.ecx)
        mu.reg_write(UC_X86_REG_EDX, gRegs.edx)
        mu.reg_write(UC_X86_REG_ESI, gRegs.esi)
        mu.reg_write(UC_X86_REG_EDI, gRegs.edi)
        if skipEbpAssignment:
            mu.reg_write(UC_X86_REG_EBP, gRegs.ebp)

        # mu.reg_write(UC_X86_REG_XMM0, 0x000102030405060708090a0b0c0d0e0f)
        # mu.reg_write(UC_X86_REG_XMM1, 0x00102030405060708090a0b0c0d0e0f0)

        # mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x440000)
        mu.reg_write(UC_X86_REG_ESP, stack)

        if not skipEbpAssignment:
            dp ("making ebp")
            mu.reg_write(UC_X86_REG_EBP, stack-600)
            gOutput.setEbp(stack-600)

        gOutput.setEsp(stack)

        dp ("start")
        giveRegOuts(mu)
        dp (".")
        # tracing all basic blocks with customized callback
        # mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        
        mu.emu_start(ADDRESS, ADDRESS + len(testCode))

        # input()

        # now dp out some registers
        dp(">>> Emulation done. Below is the CPU context")

        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        r_edi = mu.reg_read(UC_X86_REG_EDI)
        r_esi = mu.reg_read(UC_X86_REG_ESI)
        r_ebp = mu.reg_read(UC_X86_REG_EBP)
        r_esp = mu.reg_read(UC_X86_REG_ESP)

        # def set(self,eax,ebx,ecx,edx,edi,esi,ebp,esp):
        gOutput.set(r_eax,r_ebx,r_ecx,r_edx,r_edi,r_esi,r_ebp,r_esp,True)

        esp = mu.reg_read(UC_X86_REG_ESP)


        dp ("esp", hex(esp))
        firstOut = mu.mem_read(esp,4)
        firstOut= int.from_bytes(firstOut, "little")
        dp ("1", hex(firstOut))



        secondOut = mu.mem_read(esp+4,4)
        secondOut= int.from_bytes(secondOut, "little")
        dp ("2", hex(secondOut))
   
        gOutput.CalculateRemainingRegs(first,second)     
        hgGadgetStatus=False
        if firstOut ==0x33333333 and secondOut == 0x66666666:
            dp ("Good HG gadget")
            hgGadgetStatus=True

        return gOutput, hgGadgetStatus


    except UcError as e:
        dp("ERROR: %s" % e)
        dp(traceback.format_exc())
        giveRegOuts(mu)
        gOutput.setError(e)
        # errorESP(mu)
        giveRegOuts(mu)
        
        return gOutput
if __name__ == '__main__':
    # test_x86_16()
    # test_i386()

    for each in shellList:
        out=rop_tester(each)
        out.show()

    # dp("=" * 35)
    # test_i386_map_ptr()
    # dp("=" * 35)
    # test_i386_inout()
    # dp("=" * 35)
    # # test_i386_context_save()
    # # dp("=" * 35)
    # test_i386_jump()
    # dp("=" * 35)
    # test_i386_loop()
    # dp("=" * 35)
    # test_i386_invalid_mem_read()

    # test_i386_invalid_mem_read()
    # dp("=" * 35)
    # test_i386_invalid_mem_write()
    # dp("=" * 35)
    # test_i386_jump_invalid()
    # test_i386_jump_invalid()

    # test_x86_64()
    # dp("=" * 35)
    # test_x86_64_syscall()
    # # dp("=" * 35)
    # # test_i386_mmio()
