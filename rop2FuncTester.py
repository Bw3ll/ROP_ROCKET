

from helpers import *


def disOffset2(offset,fg):
	obj=fg.rop[offset]
	CODED2=obj.raw
	offset=obj.offset
	returnVal = ""
	for i in cs.disasm(CODED2, offset):
		val =  i.mnemonic + " " + i.op_str + " # "
		returnVal +=val
	return returnVal
def twos_complement_hex(n):
	if n >= 0:
		return (n)  # positive numbers are represented as-is
	else:
		return ((1 << 32) + n)  # compute two's complement

def not_(val):
	bad=(~val)
	bad2=twos_complement_hex(bad)
	print (hex(bad2))


def hx(val, length=8):
	hex_str = format(val, 'x').zfill(length) 
	return hex_str


def twos_complement_neg(n):
    # compute the absolute value of n
    abs_n = (~n & 0xFFFFFFFF) + 1
    # compute the two's complement negation of n
    neg_n = -abs_n
    # return the result as a signed 2's complement number
    return abs(neg_n & 0xFFFFFFFF) if neg_n >= 0 else (abs((~(-neg_n & 0xFFFFFFFF)) + 1))

def foundIntOverflows(myDict, desired,bad):
	for g in myDict:
		# print (g, type(g))
		# print (myDict[g].op2, "    ---------       ",disOffset2(g,fg) )
		try:
			if myDict[g].length ==1 and len(myDict[g].op2) > 4:
				if checkFreeBadBytes(g,bad):

					# print ("\n\n************", myDict[g].op2)
					twos_complement_neg(desired)
					# foundOverflow,target=	foundIntOverflows2(myDict[g].op2, desired,bad)
					# if foundOverflow:
					# 	return foundOverflow,target,g
					# 	break
		except:
			pass
		# if myDict[g].length ==1 and len(myDict[g].op2) > 3 and len(myDict[g].op2) <6:
		# 	print ("\n\toooooh yeah", myDict[g].op2)
		# 	mathStuff2(myDict[g].op2, desired)
	return False,0,0
def ropfunctester(fg):
	myDict=fg.addEAX

	desired=0x5401234
	# desired=0x234
	desired=0xad401234
	foundIntOverflows(myDict,desired,fg)

	exit()
	# Example usage
	n = -3
	print(hex(twos_complement_neg(0x401234)))
	print(hex(twos_complement_neg(-0x401234)))

	# print(33,hex(neg_n))  # Output: 'fffffffd'


	# Example usage
	# print(twos_complement_hex(-3))  # Output: 'fffffffd'

	not_(0x401234)
	not_(-0x401234)
