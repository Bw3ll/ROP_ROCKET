import colorama

colorama.init()

red ='\u001b[31;1m'
red2 ='\u001b[91;1m'

gre = '\u001b[32;1m'
gre2= '\u001b[92;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'
res2 = '\u001b[0m'

class gadgetTracker:

    def __init__(self,researcher=False):
        self.sets = {}   
        self.nextId = 1  
        self.researcher=True

    def setResearcher(self, val):
        if val==True:
            self.researcher=True
        elif val==False:
            self.researcher=False

    def newGadgetSet(self):
        id = self.nextId
        self.sets[id] = set()
        self.nextId += 1
        return id

    def setG(self, id, addresses):
        # print ("setG",id, addresses)
        if id not in self.sets:
            self.sets[id] = set()
            if id >= self.nextId:
                self.nextId = id + 1

        for addr in addresses:
            self.sets[id].add(addr)

    def hasBeenUsed(self, id, addresses,callerID=None,researcher=True):
        # print (yel,"hasBeenUsed", id, hex(addresses),res, callerID)
        if not researcher:
            return False
        if self.researcher:
            used = self.sets.get(id, set())
            if isinstance(addresses, int):
                boolOut=addresses in used
                # print (red,"boolOut1", boolOut,res)
                return boolOut
            try:
                boolOut=bool(used & set(addresses))
                # print (red,"boolOut", boolOut,res)
                return boolOut
            except TypeError:
                raise TypeError("addresses must be an int or an iterable of ints.")
        return False
    def getAddresses(self, id):
        return set(self.sets.get(id, set()))

    def show(self, title="",ourColor=None):
        if not self.sets:
            # print("(no gadget sets recorded)")
            return

        for id in sorted(self.sets):
            addrs = sorted(self.sets[id])
            addrsStr = ", ".join(hex(a) for a in addrs)
            if ourColor==None:
                print(f"{title} Set {id}: [{addrsStr}]",res)
            else:
                print(ourColor, f"{title} Set {id}: [{addrsStr}]",res)

    def reset(self):
        self.sets.clear()
        self.nextId = 1
    def clone(self):
        new = gadgetTracker()
        # copy nextId
        new.nextId = self.nextId
        # copy each gadget‐set’s addresses
        new.sets = {sid: set(addrs) for sid, addrs in self.sets.items()}
        return new

    def mergeFrom(self, other):
        """
        Merge all gadget‐sets from `other` into self.
        Existing sets are unioned; new IDs get added.
        Also advances nextId to avoid collisions.
        """
        for sid, addrs in other.sets.items():
            if sid not in self.sets:
                self.sets[sid] = set()
            self.sets[sid].update(addrs)
        # make sure future auto‐IDs don’t collide
        self.nextId = max(self.nextId, other.nextId)        

gTrackTesting = gadgetTracker()
gTrackEmpty = gadgetTracker()


testing=False
# testing=True

if testing:
    g1 = gTrackTesting.newGadgetSet()  

    gTrackTesting.setG(g1, [0x100, 0x200, 0x300])
    gTrackTesting.setG(g1, [444])
    gTrackTesting.setG(1, [23444])
    print ("ADDED 23444")
    print ("checking 1: gTrackTesting.hasBeenUsed(1, 23444)   -   ",gTrackTesting.hasBeenUsed(1, 23444))
    print ("checking 2: gTrackTesting.hasBeenUsed(1, 23445)   -   ",gTrackTesting.hasBeenUsed(1, 23445))
    print ("checking 3: gTrackTesting.hasBeenUsed(1, 23444,False)   -   ",gTrackTesting.hasBeenUsed(1, 23444,False))
    print ("checking 4: gTrackTesting.hasBeenUsed(1, 23445,False)   -   ",gTrackTesting.hasBeenUsed(1, 23445,False))


    print ("checking 5: gTrackTesting.hasBeenUsed(24242, 424242,False)   -   ",gTrackTesting.hasBeenUsed(24242, 424242,False))

    print ("\n\n")
    gTrackTesting.setG(4242, [242423444])

    gTrackTesting.show()

    gTrackTesting.setG(g1, [0x111, 0x222, 0x344])
    print ("final show")
    gTrackTesting.show()

    temp = gTrackTesting.clone()
    print ("temp show")
    temp.setG(g1, [44324242424242424])
    temp.show()

    success=True
    success=False
    if success:
        gTrackTesting.mergeFrom(temp)
        print ("merged:")
        gTrackTesting.show()
    else:
        # just throw temp away, tracker stays as it was
        pass
        gTrackTesting.show()




