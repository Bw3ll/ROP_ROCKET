def hx(val, length=8):
	hex_str = format(val, 'x').zfill(length) 
	return hex_str

def genCode1_64():
	chunk="""import struct

def rq(val):
	rq = struct.pack("<Q", val)
	return rq

def binaryToStr(binary):
	new = ""
	for v in binary:
		new += "\\\\x"+"{0:02x}".format(v)
	return new
		
def genChQ(gList):
	ch=b""
	for g in gList:
		ch+=rq(g)
	return ch

"""
	return chunk

def genCode1():
	chunk="""import struct

def rg(val):
	rg=struct.pack("<I", val)
	return rg

def binaryToStr(binary):
	new = ""
	for v in binary:
		new += "\\\\x"+"{0:02x}".format(v)
	return new
		
def genCh(gList):
	ch=b""
	for g in gList:
		ch+=rg(g)
	return ch

"""
	return chunk


def genCode2(showAll):
	if showAll:
		chunk="""
ch=genCh(gList)

filler=b"\\x41"
	
"""
	if not showAll:
		chunk="""
ch=genCh(gList)
"""	
	return chunk

def genCode2_64(showAll):
	chunk="""
ch=genChQ(gListQ)

"""
	return chunk

def genCode3(showAll):
	if showAll:
		chunk="""
payload+= params

print ("Generating payload...\\n")
print (binaryToStr(payload))
print (len(payload), "bytes")
	
"""
	if not showAll:
		chunk="""
print ("Generating payload...\\n")
print (binaryToStr(payload))
print (len(payload), "bytes")
"""		
	return chunk

def genClose():
	chunk="""
evil = open("test.bin", "wb")
evil.write(payload)
evil.close()

"""
	return chunk