from helpers import *
bad = b'\x00\x0a\x0d\xaa'

class badBytes:
	def __init__(self,bad): #, name):
		"""Initializes the data."""
		self.bads =bad
		self.allChars=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]
		self.available=[]
		self.generateGoods()
		self.i=0
		self.d=0
		self.start='0xff'
		self.startXor='0xff'

	def setBad(self,bad):
		self.bads=bad
	def giveI(self):
		if self.i > len(self.available)-1:
			self.i=0
		return self.i
	def giveI_Xor(self):
		if self.d > len(self.available)-1:
			self.d=0
		return self.i
	def incI(self):
		self.i=self.i+1
		if self.i > len(self.available)-1:
			self.i=0
			self.changeStart()
	def incI_Xor(self):
		self.d=self.d+1
		if self.d > len(self.available)-1:
			self.d=0
			self.changeStartXor()
	def changeFF(num):
		self.start=num
		self.start = hex(self.start)
	def changeStart(self):
		# dp ("changeStart", self.start)
		self.start=(int(self.start,16)-1)
		while self.start not in self.available:
			self.start=self.start-1
			if self.start<0xdd:
				self.start=0xff
		if (self.start) <0xdd:
			self.start=0xff
		self.start=hex(self.start)
	def changeStartXor(self):
		# dp ("changeStartXor", self.startXor)
		self.startXor=(int(self.startXor,16)-1)
		while self.startXor not in self.available:
			if self.startXor<0x1:
				self.startXor=0xff
			self.startXor=self.startXor-1
		if (self.startXor) <0x1:
			self.startXor=0xff
		self.startXor=hex(self.startXor)
	def generateGoods(self):
		self.available = self.allChars.copy()
		listBads=list(self.bads)
		listBads.sort()
		listBads=list(set(listBads))
		self.bads=bytes(listBads)
		for val in self.bads:
			dp ("val", hex(val), val)
			self.available.remove(int(val))	
			dp ("popped")
		if 0 in self.available:
			self.available.remove(00)
		if 0x0d in self.available:
			self.available.remove(0x0d)
		if 0x0a in self.available:
			self.available.remove(0x0a)

		dp("end")
	def resetI(self):
		self.i=0
	def reset(self):
		self.bads=b''
		self.available=[]
		self.i=0
	def add(selfbad):
		for val in bad:
			self.available.pop(int(val))	
	def show(self):
		dp (self.available)
	def give(self,need=3):
		val=self.start
		try:
			for opc in range(need):
				val2=hx(int(self.available[self.giveI()]),2)
				val=val+val2
				self.incI()
			return int(val,16)
		except IndexError as e:
			self.i=0
			return 0
	def giveXor(self,need=3):
		val=self.startXor
		try:
			for opc in range(need):
				val2=hx(int(self.available[self.giveI_Xor()]),2)
				val=val+val2
				self.incI_Xor()
			return int(val,16)
		except IndexError as e:
			self.i=0
			return 0

def buildObfValuesIntOverflowInner(evil,evil2):
	evil3=0x11514556
	out=hex(evil+evil2)
	dp (out)
	dp (hex(truncate(evil+evil2,32)))
	dp (hex(truncate(evil+evil3,32)))

def buildObfValuesIntOverflow(goal,bad,bb, maxL=10000):   ### only works with a 0x00 in front!!!!
	start=0x00400000
	# evil=0xeeeeeeee
	evil2=0x11511112  # evil + evil 2 = 400000
	evil1L= [0xeeeeeeee,0xdddddddd,	0xcccccccc,	0xbbbbbbbb,	0xaaaaaaaa,	0x99999999,	0x88888888,	0x77777777,	0x66666666,	0x55555555,	0x44444444,	0x33333333,	0x22222222,	0x11111111,	0x09414243]
	evil2L=[0x11511112,0x22622223,0x33733334,0x44844445,0x55955556, 0x66a66667,0x77b77778,0x88c88889,0x99d9999a,0xaaeaaaab,0xbbfbbbbc,0xcd0ccccd,0xde1dddde,0xef2eeeef,0xf6febdbd]
	evil1LC= [0xeeeeeeee,0xdddddddd,	0xcccccccc,	0xbbbbbbbb,	0xaaaaaaaa,	0x99999999,	0x88888888,	0x77777777,	0x66666666,	0x55555555,	0x44444444,	0x33333333,	0x22222222,	0x11111111,	0x09414243]
	evil2LC=[0x11511112,0x22622223,0x33733334,0x44844445,0x55955556, 0x66a66667,0x77b77778,0x88c88889,0x99d9999a,0xaaeaaaab,0xbbfbbbbc,0xcd0ccccd,0xde1dddde,0xef2eeeef,0xf6febdbd]
	evil=0x09414243
	# to help calculate future values
	# need=0xeeeeeeee -evil
	# need=0x11511112+need
	# dp("need",hex(need))
	diff = goal-start
	evil4=diff + evil2
	t=0
	
	for x in evil1L:
		# dp ("t",t)
		diff = goal-start
		evil4=diff + evil2L[t]
		dp ("\tevil1 and 4 new:",hex(evil1L[t]),"+",hex(evil4),"----len:", len(hex(evil1L[t]))-2, len(hex(evil4))-2)
		dp(" \t\ttrunc:",hex(truncate(evil1L[t]+evil4,32)), hex(evil1L[t]+evil4)) 
		if (hex(truncate(evil1L[t]+evil4,32))) == hex(goal):
			if hex(evil4) == hex(truncate(evil4,32)):
				dp ("\t\t\t\t\t\tit is a match - preset:", hex(truncate(evil1L[t]+evil4,32)))
				dp("evil1 and evil 4",hex(evil1L[t]), "+", hex(evil4))			
				if len(hex(evil1L[t])) >8  and len(hex(evil1L[t])) <11:
					if len(hex(evil4)) >8  and len(hex(evil4)) <11:
						if checkFreeBadBytes2(evil4,bad) and checkFreeBadBytes2(evil1L[t],bad):
							# dp ("     *****         no bad chars")
							return True, evil1L[t],evil4
						# else:
						# 	pass
							# dp ("     ^^^^^^^^^   bad chars")
		t+=1
	t=0

	for x in range (maxL):
		# dp ("t",t)
		diff = goal-start
		evil4=diff + evil2L[t]
		# dp ("evil4, diff", evil4, diff)
		# dp ("evil 4 too big")
		dp("    ->evil1",hex(evil1L[t]),"evil4",hex(evil4), hex(evil2L[t]))
		# special=0xffffffff
		special=bb.give()
		extra=evil4-special
		evil1L[t]=evil1L[t]+extra
		evil4=evil4-extra
		dp ("\tcalculating evil1 and 4 new:",hex(evil1L[t]),"+",hex(evil4),"        ----len:", len(hex(evil1L[t]))-2, len(hex(evil4))-2)
		dp(" \t\ttrunc:",hex(truncate(evil1L[t]+evil4,32)), hex(evil1L[t]+evil4))		
		if (hex(truncate(evil1L[t]+evil4,32))) == hex(goal):
			if len(hex(evil1L[t])) >8  and len(hex(evil1L[t])) <11:
				if len(hex(evil4)) >8  and len(hex(evil4)) <11:
					dp ("\t\t\t\t!!!            it is a match3", hex(truncate(evil1L[t]+evil4,32)))
					# dp("\t\t-> evil1 and evil 4",hex(evil1L[t]), "+", hex(evil4))
					if checkFreeBadBytes2(evil1L[t],bad):
						# dp ("yes, free bad bytes!")
						return True, evil1L[t], evil4
		t=t+1
		if t>14:
			t=0
			evil1L=evil1LC.copy()
			evil2L=evil2LC.copy()
	return False,0,0


def buildXORStart(goal,bad,bb, maxL=10000):   ### only works with a 0x00 in front!!!!
	t=0
	for x in range (maxL):
		special=bb.giveXor()
		result=special ^ goal
		if len(hex(result)) >8  and len(hex(result)) <11:	
			if checkFreeBadBytes2(result,bad):
				dp("got xor", hex(goal), hex(special), hex(result), hex(special^result))
				return True, special, result
			# else:
				# dp ("GOT BAD BYTE*****************************************")
		# else:
		# 	dp ("tooooo lng^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", hex(result),hex(special), hex(result ^ special))
		# 	input()
	return False,0xbadf00d2,0xbadf00d2