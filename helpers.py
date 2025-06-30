from capstone import *
import re
import gc
import logging
import sys
import traceback

cs = Cs(CS_ARCH_X86, CS_MODE_32)
logging.basicConfig(filename='myLog.log', level=logging.DEBUG)


debugging=False
# debugging=True

def dp(*args):
	if debugging:
		# restorePoint = sys.stdout
		# sys.stdout = open("new_debug_output2.txt", 'a')
		print (*args)
		# sys.stdout.close()
		# sys.stdout = restorePoint
	else:
		# print (*args)
		return
	return
	# try:
	# 	logging.debug(*args)
	# except:
	# 	dp ("DP error")
	# 	dp (*args)


def hx(val, length=8):
	# print ("hx val", val)
	hex_str = format(val, 'x').zfill(length) 
	return hex_str
def toHex(val, length=8):
	hex_str = format(val, 'x').zfill(length) 
	return hex_str

def truncate(num, bits):
	v= hex((num + (1 << bits)) % (1 << bits))
	return int(v,16)


def checkFreeBadBytesTester(opt,fg,address, bad,myDict=None,pe=None,n=None, checkImg=False,isVal=False, tellWhy=False):
	# dp("checkFreeBadBytes helpers", address,hx(address) )
	# print("checkFreeBadBytes helpers", address,hx(address) )
	checkOffset=True
	mod=None
	acceptASLR=opt["acceptASLR"]
	try:
		if not acceptASLR:
			mod=fg.rop[address].mod
			pe[mod].aslrStatus
			if pe[mod].aslrStatus:
				print ("ASLR", mod, pe[mod].aslrStatus)
				# return True  ### we are ignofring for now
				return False
	except:
		pass
	if myDict!=None:
		try:
			mod=myDict[address].mod
			offset=myDict[address].offset + pe[n].VirtualAdd
			checkImg=True
			lenBad=len(bad)
			if lenBad < 5: # and not checkImg:
				if checkImg and  len(myDict) >0:
					address1 = offset+pe[mod].startLoc
					for soBad in bad:
						if hx(soBad,2) in hx(address1):
							dp ("bad", hx(soBad,2), "in", hx(address1))
							print ("baddd", hx(soBad,2), "in", hx(address1))
							return False
		except Exception as e:
			pass
			# come back and fix later
			# print ("weird error", hex(address),e)
			# print("\t",traceback.format_exc())

	if type(address)==int:
		lenBad=len(bad)
		dp ("lenBad", lenBad,bad)
		if lenBad < 5: # and not checkImg:
			if checkOffset:
				for soBad in bad:
					# do this one too
					if hx(soBad,2) in hx(address):
						dp ("bad", hx(soBad,2), "in", hx(address))
						print ("badd2", hx(soBad,2), "in", hx(address))
						return False
			return True
		else:
			checkBad=binaryToStr(bad)
			if checkOffset:
				start=hx(address)
				if start[0:2] in checkBad:
					print ("bad", start[0:2], "in", start)
					return False
				if start[2:4] in checkBad:
					print ("bad", start[2:4], "in", start)
					return False
				if start[4:6] in checkBad:
					print ("bad", start[4:6], "in", start)
					return False
				if start[6:8] in checkBad:
					print ("bad", start[6:8], "in", start)
					return False
				# if start[0:2] or start[2:4] or start[4:6] or start[6:8] in bad:
				dp ("No bads seen in ", start)
			if checkImg and len(myDict) >0 and not isVal:
				# print ("in checkImg")
				try:
					address = offset+pe[mod].startLoc
					start=hx(address)
					# print ("\t------------->", start)
					# dp ("bads", binaryToStr(bad))
					if start[0:2] in checkBad:
						print ("bad", start[0:2], "in", start)
						return False
					if start[2:4] in checkBad:
						print ("bad", start[2:4], "in", start)
						return False
					if start[4:6] in checkBad:
						print ("bad", start[4:6], "in", start)
						return False
					if start[6:8] in checkBad:
						print ("bad", start[6:8], "in", start)
						return False
					dp ("No bads seen in ", start)		
				except:
					print ("CheckImg address not found.")
					pass
			return True
	if type(address)==list:
		for addy in address:
			for soBad in bad:
				if hx(soBad,2) in hx(addy):
					dp ("bad", hx(soBad,2), "in", hx(addy))
					return False
			# dp ("good bytes")
			return True
	if bad == None:
		dp ("bad none, true")
		return True


def checkFreeBadBytes(opt,fg,address, bad,myDict=None,pe=None,n=None, checkImg=False,isVal=False,tellWhy=False):
	# dp("checkFreeBadBytes helpers", address,hx(address) )
	# print("checkFreeBadBytes helpers", address,hx(address) )
	checkOffset=True
	mod=None
	acceptASLR=opt["acceptASLR"]
	# acceptASLR=True
	try:
		if not acceptASLR and not isVal:
			mod=fg.rop[address].mod
			pe[mod].aslrStatus
			if pe[mod].aslrStatus:
				if tellWhy:
					print ("ASLR", mod, pe[mod].aslrStatus)
					pass
				return False
	except:
		pass
	if myDict!=None and not isVal:
		try:
			mod=myDict[address].mod
			offset=myDict[address].offset + pe[n].VirtualAdd
			checkImg=True
			lenBad=len(bad)
			if lenBad < 5: # and not checkImg:
				if checkImg and  len(myDict) >0:
					address1 = offset+pe[mod].startLoc
					for soBad in bad:
						if hx(soBad,2) in hx(address1):
							dp ("bad", hx(soBad,2), "in", hx(address1))
							if tellWhy:
								print ("baddd", hx(soBad,2), "in", hx(address1))
							return False
		except Exception as e:
			pass
			# come back and fix later
			# print ("weird error", hex(address),e)
			# print("\t",traceback.format_exc())

	if type(address)==int:
		lenBad=len(bad)
		dp ("lenBad", lenBad,bad)
		if lenBad < 5: # and not checkImg:
			if checkOffset:
				for soBad in bad:
					# do this one too
					if hx(soBad,2) in hx(address):
						dp ("bad", hx(soBad,2), "in", hx(address))
						if tellWhy:
							print ("badd2", hx(soBad,2), "in", hx(address))
						return False
			return True
		else:
			checkBad=binaryToStr(bad)
			if checkOffset:
				start=hx(address)
				if start[0:2] in checkBad:
					if tellWhy:
						print ("bad", start[0:2], "in", start)
					return False
				if start[2:4] in checkBad:
					if tellWhy:
						print ("bad", start[2:4], "in", start)
					return False
				if start[4:6] in checkBad:
					if tellWhy:
						print ("bad", start[4:6], "in", start)
					return False
				if start[6:8] in checkBad:
					if tellWhy:
						print ("bad", start[6:8], "in", start)
					return False
				# if start[0:2] or start[2:4] or start[4:6] or start[6:8] in bad:
				dp ("No bads seen in ", start)
			if checkImg and len(myDict) >0 and not isVal:
				# print ("in checkImg")
				try:
					address = offset+pe[mod].startLoc
					start=hx(address)
					# print ("\t------------->", start)
					# dp ("bads", binaryToStr(bad))
					if start[0:2] in checkBad:
						if tellWhy:
							print ("bad", start[0:2], "in", start)
						return False
					if start[2:4] in checkBad:
						if tellWhy:
							print ("bad", start[2:4], "in", start)
						return False
					if start[4:6] in checkBad:
						if tellWhy:
							print ("bad", start[4:6], "in", start)
						return False
					if start[6:8] in checkBad:
						if tellWhy:
							print ("bad", start[6:8], "in", start)
						return False
					# print ("No bads seen in ", start)		
				except:
					# print ("CheckImg address not found.")
					pass
			return True
	if type(address)==list:
		for addy in address:
			for soBad in bad:
				if hx(soBad,2) in hx(addy):
					if tellWhy:
						print ("bad", hx(soBad,2), "in", hx(addy))
					return False
			# dp ("good bytes")
			return True
	if bad == None:
		dp ("bad none, true")
		return True
def checkFreeBadBytes2(address, bad,myDict=None,pe=None,n=None, checkImg=False,isVal=False):
	dp("checkFreeBadBytes helpers", address,hx(address) )
	# print("checkFreeBadBytes helpers", address,hx(address) )
	checkOffset=True
	mod=None
	if myDict!=None:
		try:
			mod=myDict[address].mod
			offset=myDict[address].offset + pe[n].VirtualAdd
			checkImg=True
			lenBad=len(bad)
			if lenBad < 5: # and not checkImg:
				if checkImg and  len(myDict) >0:
					address1 = offset+pe[mod].startLoc
					for soBad in bad:
						if hx(soBad,2) in hx(address1):
							dp ("bad", hx(soBad,2), "in", hx(address1))
							# print ("baddd", hx(soBad,2), "in", hx(address1))
							return False
		except Exception as e:
			pass
			# come back and fix later
			# print ("weird error", hex(address),e)
			# print("\t",traceback.format_exc())

	if type(address)==int:
		lenBad=len(bad)
		dp ("lenBad", lenBad,bad)
		if lenBad < 5: # and not checkImg:
			if checkOffset:
				for soBad in bad:
					# do this one too
					if hx(soBad,2) in hx(address):
						dp ("bad", hx(soBad,2), "in", hx(address))
						# print ("badd2", hx(soBad,2), "in", hx(address))
						return False
			return True
		else:
			checkBad=binaryToStr(bad)
			if checkOffset:
				start=hx(address)
				if start[0:2] in checkBad:
					dp ("bad", start[0:2], "in", start)
					return False
				if start[2:4] in checkBad:
					dp ("bad", start[2:4], "in", start)
					return False
				if start[4:6] in checkBad:
					dp ("bad", start[4:6], "in", start)
					return False
				if start[6:8] in checkBad:
					dp ("bad", start[6:8], "in", start)
					return False
				# if start[0:2] or start[2:4] or start[4:6] or start[6:8] in bad:
				dp ("No bads seen in ", start)
			if checkImg and len(myDict) >0 and not isVal:
				# print ("in checkImg")
				try:
					address = offset+pe[mod].startLoc
					start=hx(address)
					# print ("\t------------->", start)
					# dp ("bads", binaryToStr(bad))
					if start[0:2] in checkBad:
						dp ("bad", start[0:2], "in", start)
						return False
					if start[2:4] in checkBad:
						dp ("bad", start[2:4], "in", start)
						return False
					if start[4:6] in checkBad:
						dp ("bad", start[4:6], "in", start)
						return False
					if start[6:8] in checkBad:
						dp ("bad", start[6:8], "in", start)
						return False
					dp ("No bads seen in ", start)		
				except:
					print ("CheckImg address not found.")
					pass
			return True
	if type(address)==list:
		for addy in address:
			for soBad in bad:
				if hx(soBad,2) in hx(addy):
					dp ("bad", hx(soBad,2), "in", hx(addy))
					return False
			# dp ("good bytes")
			return True
	if bad == None:
		dp ("bad none, true")
		return True
def doGC():
    # Returns the number of
    # objects it has collected
    # and deallocated
    collected = gc.collect()
     
    # dps Garbage collector
    # as 0 object
    dp("Garbage collector: collected",
              "%d objects." % collected)

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


def checkPlease (raw1, c2=False):
	returnVal = ""
	t=0  #ret
	op_str=""
	for i in cs.disasm(raw1, 0):
		val =  i.mnemonic + " " + i.op_str + " "
		bad = re.match( r'^call|^jmp|^jo|^jno|^jsn|^js|^je|^jz|^jne|^jnz|^jb|^jnae|^jc|^jnb|^jae|^jnc|^jbe|^jna|^ja|^jnben|^jl|^jnge|^jge|^jnl|^jle|^jng|^jg|^jnle|^jp|^jpe|^jnp|^jpo|^jczz|^jecxz|^jmp|^int|^retf|^db|^hlt|lcall|ljmp|loop', val, re.M|re.I)
		bad = re.match( r'^call|^jmp|^jo|^jno|^jsn|^js|^je|^jz|^jne|^jnz|^jb|^jnae|^jc|^jnb|^jae|^jnc|^jbe|^jna|^ja|^jnben|^jl|^jnge|^jge|^jnl|^jle|^jng|^jg|^jnle|^jp|^jpe|^jnp|^jpo|^jczz|^jecxz|^jmp|^int|^db|^hlt|lcall|ljmp|loop', val, re.M|re.I)

		if bad:
			return False,0,""
		returnVal+=val
		if t==0:
			op_str=i.op_str
		t+=1
	retS = re.findall( r'ret', returnVal, re.M|re.I)
	if len(retS)>1 or len(retS)==0:
		# dp ("extra ret")
		return False,0,""
	if c2:
		retS = re.findall( r'ret [0-9]+|ret 0x', returnVal, re.M|re.I)
		if len(retS) ==0:
			# dp ("not a c2")
			return False,0,""
		else:
			# dp ("ret-true0")
			return True,t-1,op_str
	return True,t-1,op_str
	
def stupidPreJ(val2, num):
	global cutting
	res = []
	bad = 0
	# dp "***********PRESTUPIDJ"

	start = re.match( r'\bjmp\b|\bcall\b', val2[0], re.M|re.I)
	if not start:
		# dp "opps2!"
		val2.reverse()
	t=0

	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# dp "jrev"
		val2.reverse()
	else:
		# dp "no rev"
		pass


	limit=num#len(val2)-(num)
	# dp "limit "  + str(limit) + " num: " + str(num) + " size: " + str(len(val2))
	for x in val2:
	# for i in val2: #   #was +1
	#	dp i
		# dp "t: " + str(t) + " x: " + x
		# matchObj3 = re.compile( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\bptr\b')


		# if matchObj3.search(x):
		matchObj3 = re.search( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b', x, re.M|re.I)

		if matchObj3:
			bad = bad + 1
			if bad < 2:
				# dp "bad2 " + str(t) + " x: " + x
				res.append(str(x))
			if bad > 1:   ###### WAS 1 - missing small ones - fixed it - 2 - not sure original logic behind this
				# dp "bad3 "  + str(t) + " x: " + x
				# dp  matchObj3.search(x)
				return False
		else:	
			if bad < 2 : 
				res.append(x)
		t+=1
		if limit == t:
			# dp "return True" 
			return True
	# dp "res: " + str(len(res))
	# for x in res:
	# 	dp x
	# dp "return True2" 
	return True

def stupidPreJJ(val2, num, addy):
	global cutting
	res = []
	bad = 0
	# dp "***********PRESTUPIDJ"
	saveJ=0
	saveC =0

	val2r = val2[:]

	start = re.match( r'\bjmp\b|\bcall\b', val2[0], re.M|re.I)
	if not start:
		# dp "opps2!"
		val2.reverse()
	t=0

	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# dp "jrev"
		val2.reverse()
	else:
		# dp "no rev"
		pass


	limit=num#len(val2)-(num)
	# dp "limit "  + str(limit) + " num: " + str(num) + " size: " + str(len(val2))
	
	for xx in val2:
		dp ("\t**" + xx)
	for x in val2:
	# for i in val2: #   #was +1
	#	dp i
		# dp "t: " + str(t) + " x: " + x
		# matchObj3 = re.compile( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\bptr\b')


		# if matchObj3.search(x):
		matchObj3 = re.search( r'\bcall\b|\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b', x, re.M|re.I)

		if matchObj3:
			myCall = re.search( r'\bcall\b', x, re.M|re.I)
			myJmp = re.search( r'\bjmp\b', x, re.M|re.I)
			if bad == 0:
				if myCall:
					saveC=t
				if myJmp:
					saveJ=t
					dp ("j here ")
					dp (t)




			bad = bad + 1
			if bad < 2:
				# dp "bad2 " + str(t) + " x: " + x
				res.append(str(x))
			if bad > 1:   ###### WAS 1 - missing small ones - fixed it - 2 - not sure original logic behind this
				# dp "bad3 "  + str(t) + " x: " + x
				# dp  matchObj3.search(x)



				matchObj3 = re.search( r'\bcall\b|\bjmp\b', x, re.M|re.I)
				if matchObj3 and bad == 2:
					dp ("STOP! " +  "")
					dp (x)
					dp ("j", saveJ)
					k=0
					for d in val2r:
						dp ("\t# " + d)

						matchObj3 = re.search( r'\bcall\b|\bjmp\b', d, re.M|re.I)
						if matchObj3:
							dp ("found true end " + d)
							dp ("need " + str((addy)))
						k+=1

				return False
		else:	
			if bad < 2 : 
				res.append(x)
		t+=1
		if limit == t:
			# dp "return True" 
			return True
	# dp "res: " + str(len(res))
	# for x in res:
	# 	dp x
	# dp "return True2" 
	return True

def stupidPreJJ2(val2, num, addy, saveq, transfer, listAddy, Reg):
	try:
		res = []
		bad = 0
		saveJ=0
		saveC =0
		val2r = val2[:]
		strAddy=str(addy)
		t=0
		w=0
		gotIt=False
		val2r.reverse()
		listAddy.reverse
		for line in val2r:
			findNumLines = re.search( strAddy, line, re.M|re.I)
			if findNumLines:
				dp ("got one!!! " + str(t))
				dp (line)
				dp ("saveq", hex(saveq))
				gotIt = True
				# w+=1
			if gotIt:
				w+=1
			if transfer=="call":
				test = re.search( r'call e', line, re.M|re.I)
				bad = re.search( r'\bjmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b', line, re.M|re.I)
			if transfer=="jmp":
				test = re.search( r'jmp e', line, re.M|re.I)
				bad = re.search( r'\bcall\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b', line, re.M|re.I)
			if bad:
				dp( "BAD: " + str(listAddy[t]))
				dp (line)
				dp ("t",t, "total lines", w)
			if bad:
				dp ("I is quitting")
				break
			if test: # and gotIt:
				dp( "END, got other: " + str(listAddy[t]) + " " +  Reg)
				dp (line)
				dp ("total lines " + str(w) + " t: " + str(t))
				dp ("retVal",)

			t+=1

	except Exception as e:
		dp (e)
		# dp ("badd address", address, "i", i)
		# for each in val2:
		# 	dp "\t\t"+each
		dp(traceback.format_exc())


def reverseOffsets(val2):
	arrOffsets = []
	for each in myTest:
		array = each.split("(offset ")
		offset = array[1]
		offset = offset[:-2]
		hexOffset = int(offset, 16)
		dp (offset)
		dp (hex(hexOffset))
		arrOffsets.append(offset)
	dp (arrOffsets)
	if arrOffsets[len(arrOffsets)-1] > arrOffsets[len(arrOffsets)-2]:
		dp ("bigger")
	else:
		dp ("smaller" )
	arrOffsets.reverse()
	dp (arrOffsets)

def reverseChecker(lines):
	try: 
		dp ("reverseChecker")
		firstOff=0
		secondOff=0
		t=0
		for line in lines:
			array = line.split("offset")
			val= array[1].strip()
			val= val[:-1]
			val = int(val,16)
			if t==0:
				firstOff=val
			if t==(len(lines)-1):
				secondOff=val
			t+=1

		dp ("rcheck: 1", hex(firstOff), "2", hex(secondOff))
		if firstOff > secondOff:
			dp ("reversing")
			lines.reverse()
			return lines
		else:
			return lines

	except Exception as e:
		# pass
		dp ("rcheck trace")
		dp (e)
		dp(traceback.format_exc())


def stupidPreJJ3(val5, addy,addyV, transfer, listAddy, listTReg):
	dp ("\n\n\n\n********************************\nnew start " + str((addy)) + "\n\n")
	dp (val5, addy, addyV, transfer, listAddy, listTReg)

	# return False, 0,0
	try:
		bad = 0
		val5r = val5[:]
		combined = hex(int(addy,16)+addyV)
		strAddy=str(combined)
		t=0
		w=0
		gotIt=False
		badCt=0
		savMy=""
		doubleChecking=False
		val5r=reverseChecker(val5r)
		dp ("mySize", len(val5))
		for e in val5r:
			dp( "\t" + e)
		for line in val5r:
			dp (line)
			findNumLines = re.search( strAddy, line, re.M|re.I)
			if not gotIt:
				dp( "searching for " + strAddy)
			if findNumLines:
				gotIt = True
				dp ("gots one!!! " + str(t) + "transfer: " +  transfer + " gotIt: " + str(gotIt))
				dp (line)
				dp ("transfer: " +  transfer + " gotIt: " + str(gotIt))
				savMy=line
				
			if gotIt:
				w+=1  
			if transfer=="call":
				test = re.search( r'call e', line, re.M|re.I)
				test2 = re.search( r'call|call [dword]*', line, re.M|re.I)
				bad = re.search( r'\bjmp\b|\bljmp|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bjmp\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\benter\b|\bjns\b', line, re.M|re.I)
				if test2 and gotIt:
					badCt +=1
			if transfer=="jmp":
				test = re.search( r'jmp e', line, re.M|re.I)
				test2 = re.search( r'jmp|jmp [dword]*', line, re.M|re.I)
				bad = re.search( r'\bcall\b|\bljmp\b|\bjo\b|\bjno\b|\bjsn\b|\bjs\b|\bje\b|\bjz\b|\bjne\b|\bjnz\b|\bjb\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjbe\b|\bjna\b|\bja\b|\bjnben\b|\bjl\b|\bjnge\b|\bjge\b|\bjnl\b|\bjle\b|\bjng\b|\bjg\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b|\bjczz\b|\bjecxz\b|\bint\b|\bretf\b|\bdb\b|\bhlt\b|\bloop\b|\bret\b|\bleave\b|\bint3\b|\binsd\b|\benter\b|\bjns\b', line, re.M|re.I)
				if test2 and gotIt:
					badCt +=1
			if (bad) or (badCt > 1):
				dp ("BAD: " + str(listAddy[t]))
				dp ("start was: " + strAddy)
				dp (line)
				# dp ("t",t, "total lines", w)
				return False, 0,0,0
				break
			if test and gotIt: 
				dp( "END, got final transfer: " + str(listAddy[t])  )
				dp (line)

				if doubleChecking:
					answer = splitterSpace(savMy,1)
					answer = splitterTab(answer,0)
					answer=answer.encode()
					dp ("answer", answer)
					dp ("listTReg", listTReg, "savMy", savMy)		
					if answer == listTReg:
						dp ("i got a match")
					else:
						if listTReg != "all":
							xc = re.match( r'xchg', savMy, re.M|re.I)
							if not xc:
								dp ("BAD match")


				dp ("total lines " + str(w) + " t: " + str(t))
				dp ("New retVal",str(listAddy[t]), int(listAddy[t],0),  w, listTReg )
				return True, int(listAddy[t],0), w, listTReg
			t+=1
		return False, 0,0,0
	except Exception as e:
		# pass
		dp ("jj3 trace")
		dp (e)
		dp(traceback.format_exc())
def giveLineNum(val2, line):
	# dp "details"
	# for x in val2:
	# 	dp x
	# 	dp "\t\t"+splitter(x)
	# dp "l: " + line

	
	val2.reverse()
	### WTF! not sure why they keep getting reversed wrong -- sometimes Ret at beginning, others at end--no rhyme or reason i can discern
	start = re.match( r'\bret\b', val2[0], re.M|re.I)
	if not start:
		# dp "opps!"
		val2.reverse()

	
	if splitter(val2[0]) < splitter(val2[len(val2)-1]):
		# dp "giveLine rev"
		val2.reverse()
	else:
		# dp "glno rev"
		pass
	t=0
	TEXTO=splitter(line)
	# dp "texto " + TEXTO
	my_regex = r"\b(?=\w)" + re.escape(TEXTO) + r"\b(?!\w)"

	# my_regex = r"\b" + re.escape(TEXTO) + r"\b"
	for x in val2:
		t+=1 # dp "ok"
		check= re.match( TEXTO, splitter(x), re.M|re.I)
		# m = re.search('offset(.+?)\)', x)
		# dp "c: " + splitter(x) + " ? " + splitter(TEXTO) +  " desired: " + line
		if check:
			# dp "ok2"
			# dp "returning: " + str(t)
			return t
		# if m:
		# 	found = m.group(1)
		# 	dp "found: " + found
		# t+=1
# dp "ans " + str(giveLineNum(val5, line))

# dp splitter(test)
