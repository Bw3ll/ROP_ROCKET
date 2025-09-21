pat2 = {
		'LoLi1':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebx",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'LoLi2':{ 
		'1': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None} 
		},

		'LoLi3':{ 
		'1': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], 'r2':'','com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[], 'r2':'','com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'ebp', 'val': 'pop', 'excluded':['esi'], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], 'r2':'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], 'r2':'esi','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'pop', 'excluded':['esi'], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'LoLi4':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'}, 
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		},

		'LoLi5':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None} 
		},

		'LoLi6':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None} 
		},

		'LoLi7':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'targetDllString', 'excluded':[], "r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}		 
		},

		'LoLi8':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'LoLi9':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'targetDllString', 'excluded':[],"r2":"",'com':'Target DLL string','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'loadLibraryPtr', 'excluded':[], "r2":"",'com':'Ptr to LoadLibrary','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'GPA1':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ropNop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'GPA2':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["ecx", "esi"], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'pop', 'excluded':["ecx","esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	 'GPA3':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["ecx","esi"], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'addESP', 'excluded':["ecx","esi"], "r2":'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'GPA4':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	 'GPA5':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'GPA6':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	 'GPA7':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'GPA8':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':["ecx"], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":4,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

	 'GPA9':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":4,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'GPA10':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'pop', 'excluded':["ecx","ebp"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

	 'GPA11':{ 
		'1': {'r': 'ecx', 'val': 'hModule', 'excluded':[], "r2":"",'com':'hModule','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpProcName', 'excluded':[],"r2":"",'com':'lpProcName','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'GetProcAddressPTR', 'excluded':[], "r2":"",'com':'Ptr to GetProcAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'pop', 'excluded':["ecx","esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		},
	   'SYS1':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR', 'val2':'System_RT','excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'val2': 'jmp','excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS2':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'val2':'System_RT','excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword', 'val2': 'jmp','excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS3':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR', 'val2':'System_RT','excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword','val2': 'jmp', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS4':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR','val2':'System_RT', 'excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'Command', 'excluded':[], "r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'JmpDword','val2': 'jmp', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS5':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR','val2':'System_RT', 'excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0x8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'val2': 'jmp','excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS6':{ 
		'1': {'r': 'ebx', 'val': 'SystemPTR', 'val2':'System_RT','excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'val2': 'jmp','excluded':[], "r2":"ebx",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS7':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'val2':'System_RT','excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'val2': 'jmp','excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS8':{ 
		'1': {'r': 'ebp', 'val': 'SystemPTR','val2':'System_RT', 'excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword','val2': 'jmp', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'SYS9':{ 
		'1': {'r': 'esi', 'val': 'SystemPTR', 'val2':'System_RT', 'excluded':[], "r2":"",'com':'Ptr to System','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'Command', 'excluded':[],"r2":"",'com':'Command','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'},
		'3': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'val2': 'jmp', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   'HG321':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'cs0x33', 'excluded':[], "r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG322':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'cs0x33', 'excluded':[], "r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG323':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'cs0x33', 'excluded':[], "r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG324':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"esi",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG325':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG326':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0x10','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebx",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG327':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0xc,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebx",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG328':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0xc,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"ebp",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'HG329':{ 
		'1': {'r': 'edi', 'val': 'popLoad', 'excluded':[], "r2":'edi','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':['edi'], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'jmp', 'excluded':[], "r2":"edi",'com':'Jmp to retf','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG3210':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":0xc,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'HG3211':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'cs0x33', 'excluded':[],"r2":"",'com':'CS 0x33 selector for 64-bit','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'retf', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'destination0x33', 'excluded':[], "r2":"",'com':'Destination address','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'VP1':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'VPPtr', 'excluded':[],"r2":"",'com':'VirtualProtect ptr','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		
		'3': {'r': 'esi', 'val': 'JmpDword', 'excluded':[], "r2":"eax",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},

		'6': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'LpAddress - automatic - skip','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'dwSize', 'excluded':[], "r2":"",'com':'dwSize','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'edx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':'flNewProtect - 0x40','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'flOldProtect', 'excluded':[], "r2":"",'com':'flOldProtect - any writable memory address!','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'VP2':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'esi','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'nop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		
		'3': {'r': 'esi', 'val': 'VPPtr2', 'excluded':[], "r2":"eax",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},

		'4': {'r': 'ebp', 'val': 'JmpESP', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'LpAddress - automatic - skip','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ebx', 'val': 'dwSize', 'excluded':[], "r2":"",'com':'dwSize','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'edx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':'flNewProtect - 0x40','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ecx', 'val': 'flOldProtect', 'excluded':[], "r2":"",'com':'flOldProtect - any writable memory address!','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'VA1':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'nop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'VAPtr2', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'JmpESP', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':' LpAddress - automatic skip ','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'dwSize2', 'excluded':[], "r2":"",'com':' - The dwSize will round up! ','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'flAllocationType', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':' flNewProtect ','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		
		'VA2':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'VAPtr', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'JmpDword', 'excluded':[], "r2":"eax",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':' LpAddress - automatic skip ','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'dwSize2', 'excluded':[], "r2":"",'com':' - The dwSize will round up! ','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'flAllocationType', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'flNewProtect', 'excluded':[], "r2":"",'com':' flNewProtect ','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'WE1':{ 
		'4': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'winPTR', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},		
		'WE2':{ 
		'1': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'pop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'winPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE3':{ 
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":8,'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'winPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE4':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'winPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE5':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'addESP', 'excluded':[],"r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'winPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE6':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'winPTR', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE7':{ 
		'1': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'addESP', 'excluded':[],"r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'winPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE8':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'winPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE9':{ 
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'pop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'winPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'WE10':{ 
		'1': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'winPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'cmdLine', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uCmdShow', 'excluded':[], "r2":"",'com':'1 for SW_SHOWNORMAL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'DF1':{ 
		'4': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'dfPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'DF2':{ 
		'1': {'r': 'edi', 'val': 'dfPTR_RT', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'lpFileName', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
				
		'DF3':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'dfPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
				
		'DF4':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'dfPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'DF5':{ 
		'4': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'dfPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'DF6':{ 
		'4': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'dfPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
				
		'DF7':{ 
		'8': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'dfPTR_RT', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
				
		'DF8':{ 
		'4': {'r': 'edi', 'val': 'pop', 'excluded':["esi"], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'dfPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},		
		'DF9':{ 
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"8",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'dfPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebx",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'DF10':{ 
		'4': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'pop', 'excluded':["edi","esi"],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'dfPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
				
		'DF11':{ 
		'4': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'pop', 'excluded':["edi","esi"],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'dfPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
				
		'DF12':{ 
		'8': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'dfPTR', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"EBP",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},	
		'DF13':{ 
		'4': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'dfPTR', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'DF14':{ 
		'4': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'dfPTR', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
			
		'DF15':{ 
		'4': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'dfPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		
		'DF16':{ 
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'dfPTR', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'DF17':{ 
		'4': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'dfPTR', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpFileName', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		},		

	   	'CT32S1':{
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[],"r2":"",'com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'CT32SPtr_RT', 'excluded':[], "r2":"",'com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], "r2":"",'com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
	   	'CT32S2':{
		'1': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], "r2":"",'com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'CT32SPtr', 'excluded':[], "r2":"",'com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[],"r2":"",'com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None} 
		},
   		'CT32S3':{
		'1': {'r': 'esi', 'val': 'CT32SPtr', 'excluded':[], 'r2':'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'addESP', 'excluded':["edi","esi"], "r2":'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'esi','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'pop', 'excluded':['esi'], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
   		'CT32S4':{
		'1': {'r': 'esi', 'val': 'ropNop', 'excluded':[], 'r2':'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'CT32SPtr', 'excluded':[], "r2":'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'ebp','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S5':{
		'1': {'r': 'esi', 'val': 'CT32SPtr', 'excluded':[], 'r2':'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'esi','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S6':{
		'1': {'r': 'esi', 'val': 'CT32SPtr', 'excluded':[], 'r2':'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'addESP', 'excluded':[], "r2":'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'esi','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S7':{
		'1': {'r': 'esi', 'val': 'addESP', 'excluded':[], 'r2':'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'CT32SPtr', 'excluded':[], "r2":'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'ebp','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S8':{
		'1': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], 'r2':'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'CT32SPtr', 'excluded':[], "r2":'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'ebp','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S9':{
		'3': {'r': 'esi', 'val': 'addESP', 'excluded':[], 'r2':'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ebp', 'val': 'CT32SPtr', 'excluded':[], "r2":'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'ebp','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], 'r2':'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S10':{
		'1': {'r': 'esi', 'val': 'pop', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'CT32SPtr', 'excluded':[], "r2":'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'ebp','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'0xc','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},
		'CT32S11':{
		'1': {'r': 'esi', 'val': 'CT32SPtr', 'excluded':[], 'r2':'','com':'Ptr to CreateToolhelp32Snapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'th32ProcessID', 'excluded':[], 'r2':'','com':'th32ProcessID','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'ebp', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'esp', 'val': 'skip', 'excluded':[], 'r2':'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], 'r2':'ebp','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], 'r2':'','com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'dwFlags', 'excluded':[], 'r2':'','com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], 'r2':'4','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'UDTF1':{
		'2': {'r': 'edi', 'val': 'UDTF_RT', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'pop', 'excluded':["ebx","ecx","edx", "esi","edi","ebp"],"r2":"eax",'com':'pop eax','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pCaller', 'excluded':[], "r2":"",'com':'pCaller - set to NULL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'szURL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc2"},
		'1': {'r': 'ebx', 'val': 'szFileName', 'excluded':[], "r2":"",'com':'szFileName','specHan':True, 'hasStr':True, 'parStr': True, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc1"},
		'6': {'r': 'edx', 'val': 'dwReserved', 'excluded':[], "r2":"",'com':'dwReserved - set to NULL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'ecx', 'val': 'lpfnCB', 'excluded':[], "r2":"",'com':'lpfnCB - set to NULL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'UDTF2':{
		'2': {'r': 'edi', 'val': 'UDTF_RT', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'addESP', 'excluded':[],"r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pCaller', 'excluded':[], "r2":"",'com':'pCaller','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'szURL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc2"},
		'1': {'r': 'ebx', 'val': 'szFileName', 'excluded':[], "r2":"",'com':'szFileName','specHan':True, 'hasStr':True, 'parStr': True, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc1"},
		'7': {'r': 'edx', 'val': 'dwReserved', 'excluded':[], "r2":"",'com':'dwReserved','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ecx', 'val': 'lpfnCB', 'excluded':[], "r2":"",'com':'lpfnCB','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'OP1':{
		'9': {'valStr': 'dwProcessId', 'val': 0x0dee, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwProcessId - placeholder for PID'}, # TODO: point to the PID; which comes from Process32First/Next
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'bInheritHandle', 'excluded':[],"r2":"",'com':'bInheritHandle','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'OP_RT', 'excluded':[], "r2":"",'com':'OpenProcessStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'dwDesiredAccess', 'excluded':[], "r2":"",'com':'dwDesiredAccess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'OP2':{
		'9': {'valStr': 'dwProcessId', 'val': 0x0dee, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwProcessId - placeholder for PID'}, # TODO: point to the PID; which comes from Process32First/Next
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'bInheritHandle', 'excluded':[],"r2":"",'com':'bInheritHandle','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'OP_RT', 'excluded':[], "r2":"",'com':'OpenProcessStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'dwDesiredAccess', 'excluded':[], "r2":"",'com':'dwDesiredAccess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'OP3':{
		'9': {'valStr': 'dwProcessId', 'val': 0x0dee, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwProcessId - placeholder for PID'}, # TODO: point to the PID; which comes from Process32First/Next
		'1': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'bInheritHandle', 'excluded':[],"r2":"",'com':'bInheritHandle','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'OP_RT', 'excluded':[], "r2":"",'com':'OpenProcessStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'jmp', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'dwDesiredAccess', 'excluded':[], "r2":"",'com':'dwDesiredAccess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'OP4':{
		'9': {'valStr': 'dwProcessId', 'val': 0x0dee, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwProcessId - placeholder for PID'}, # TODO: point to the PID; which comes from Process32First/Next
		'1': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'bInheritHandle', 'excluded':[],"r2":"",'com':'bInheritHandle','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'OP_PTR', 'excluded':[], "r2":"",'com':'Ptr to OpenProcess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"esi",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'dwDesiredAccess', 'excluded':[], "r2":"",'com':'dwDesiredAccess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'OP5':{
		'9': {'valStr': 'dwProcessId', 'val': 0x0dee, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwProcessId - placeholder for PID'}, # TODO: point to the PID; which comes from Process32First/Next
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'bInheritHandle', 'excluded':[],"r2":"",'com':'bInheritHandle','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'OP_PTR', 'excluded':[], "r2":"",'com':'Ptr to OpenProcess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'JmpDword', 'excluded':[], "r2":"ebp",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'dwDesiredAccess', 'excluded':[], "r2":"",'com':'dwDesiredAccess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'P32F1':{
		'2': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

	 	'P32F2':{
	  	'8': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F3':{
	  	'8': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'addESP', 'excluded':["edi", "esi"], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F4':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F5':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F6':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F7':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F8':{
	  	'8': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},
		
		'P32F9':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'pop', 'excluded':["edi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32F10':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32F_RT', 'excluded':[], "r2":"",'com':'Process32FirstStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'}
		},
		
		'P32N1':{
		'2': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":'8','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

	 	'P32N2':{
	  	'8': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N3':{
	  	'8': {'r': 'edi', 'val': 'pop', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'addESP', 'excluded':["edi", "esi"], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N4':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N5':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N6':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N7':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N8':{
	  	'8': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},
		
		'P32N9':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"0xc",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'pop', 'excluded':["edi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'} 
		},

		'P32N10':{
	  	'8': {'r': 'edi', 'val': 'addESP', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'hSnapshot', 'excluded':[], "r2":"",'com':'hSnapshot','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'P32N_RT', 'excluded':[], "r2":"",'com':'Process32NextStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lppe', 'excluded':[],"r2":"",'com':'lppe','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': True, 'strucT':'PROCESSENTRY32', 'struSize':40, 'loc':'loc1'}
		},

		"RSKV1":{
		'5': {'r': 'edi', 'val': 'RegSetKeyValueA_RT', 'excluded':[], "r2":"",'com':'RegSetKeyValueAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ecx', 'val': 'lpData', 'val2': 'lpData2', 'excluded':[], "r2":"",'com':'lpData','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':True, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'locb':'loc8'},   #todo may not be corect - this is a string
		'4': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		# val2 comes from the RegCreateKeyA, which will be written to stack using mov deref.
		# stackLoc1
		'6': {'r': 'ebp', 'val': 'hKey_RSKV', 'val2': 'getStack', 'excluded':[], "r2":"",'com':'hKey','specHan':False, 'hasStr':False, 'parStr': False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'locb':'loc1'},
		'3': {'r': 'esp', 'val': 'skip', 'val2': 'lpSubKey2_RSKV','excluded':[], "r2":"",'com':'lpSubKey = \"SYSTEM\\CurrentControlSet\\Control\\Terminal Server','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc2", 'locb': 'loc6'},
		'1': {'r': 'ebx', 'val': 'lpValueName', 'val2': 'lpValueName2', 'excluded':[], "r2":"",'com':'lpValueName = \"fDenyTSConnections\'','specHan':True, 'hasStr':True, 'parStr': 'fDenyTSConnections', 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1', 'locb':'loc7'},
		'7': {'r': 'edx', 'val': 'dwType2', 'val2': 'dwType2', 'excluded':[], "r2":"",'com':'dwType','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'cbData2', 'val2': 'cbData2', 'excluded':[],"r2":"",'com':'cbData','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		"RSKV2_SKIP":{	#not a unique pattern, just different values.
		'1': {'r': 'edi', 'val': 'RegSetKeyValueA_RT', 'excluded':[], "r2":"",'com':'RegSetKeyValueAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},  # Duplicate pattern, different values
		'2': {'r': 'ecx', 'val': 'lpData2', 'excluded':[], "r2":"",'com':'lpData','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'hKey2_RSKV', 'excluded':[], "r2":"",'com':'hKey','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'lpSubKey2_RSKV', 'excluded':[], "r2":"",'com':'lpSubKey','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'lpValueName2', 'excluded':[], "r2":"",'com':'lpValueName','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'dwType2', 'excluded':[], "r2":"",'com':'dwType','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'cbData2', 'excluded':[],"r2":"",'com':'cbData','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		"RCKV1":{
		'2': {'r': 'edi', 'val': 'RCKV_RT', 'excluded':[], "r2":"",'com':'RegCreateKeyAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},   ### return address was add esp, 0x44 - big value - to connect to next regsetkeyvaluea
		'4': {'r': 'ebp', 'val': 'hKey_RCKV', 'excluded':[], "r2":"",'com':'hKey','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'lpSubKey','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},  # lpSubKey_RCKV
		'1': {'r': 'ebx', 'val': 'phkResult', 'excluded':[], "r2":"",'com':'phkResult','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

 		"RCKV2_skip":{  #not a unique pattern, just different values.
		'1': {'r': 'edi', 'val': 'RCKV_RT', 'excluded':[], "r2":"",'com':'RegCreateKeyAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},		   # Duplicate pattern, different values
		'2': {'r': 'ecx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'hKey_RCKV', 'excluded':[], "r2":"",'com':'hKey','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'lpSubKey2_RCKV', 'excluded':[], "r2":"",'com':'lpSubKey2','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'phkResult', 'excluded':[], "r2":"",'com':'phkResult'},
		'7': {'r': 'edx', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop'},
		'8': {'r': 'eax', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'Test1':{ 
		'9': {'valStr': 'Test_Str_Name 1', 'val': 5, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'Test_Str_Name 1'},
		'10': {'valStr': 'Test_Str_Name 2', 'val': 23, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None,'com':'Test_Str_Name 2'},
		'11': {'valStr': 'Test_Str_Name 3', 'val': 4, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'Test_Str_Name 3'},
		'12': {'valStr': 'Test_Str_Name 4', 'val': 0x44, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None,'com':'Test_Str_Name 4'},
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'x', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'SYSxx':{ 
		'1': {'r': 'edi', 'val': 'x', 'excluded':[], "r2":'','com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'x', 'excluded':[],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'x', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'WPM1':{
		'9': {'valStr': 'lpBuffer', 'val': 0xbaddffff, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'Placeholder - supply lpBuffer here'}, # TODO: specHan
		'10': {'valStr': 'nSize', 'val': 0x800, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None,'com':'nSize'},
		'11': {'valStr': 'lpNumberOfBytesWritten', 'val': 0x0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':True, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc1", 'com':'lpNumberOfBytesWritten'},
		'2': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":'','com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"],"r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'hProcess', 'excluded':[], "r2":"",'com':'hProcess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'WPM_RT', 'excluded':[], "r2":"",'com':'WriteProcessMemoryStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		# val2 comes from the HeapCreate, which will be written to stack using mov deref.
		# stackLoc1
		'1': {'r': 'eax', 'val': 'lpBaseAddress', 'val2': 'getStack','excluded':[], "r2":"",'com':'Placeholder - supply lpBaseAddress here','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'HC1':{
		'9': {'valStr': 'dwMaximumSize', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwMaximumSize'},
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'flOptions', 'excluded':[], "r2":"",'com':'flOptions','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'HC_RT', 'excluded':[], "r2":"",'com':'HeapCreateStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'dwInitialSize', 'excluded':[], "r2":"",'com':'dwInitialSize','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'OSCM1':{
		'9': {'valStr': 'dwDesiredAccess', 'val': 0x2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwDesiredAccess'},
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'lpMachineName', 'excluded':[], "r2":"",'com':'lpMachineName','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'OSCM_RT', 'excluded':[], "r2":"",'com':'OpenSCManagerAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'lpDatabaseName', 'excluded':[], "r2":"",'com':'lpDatabaseName','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'CSA1':{
		'9': {'valStr': 'lpDisplayName', 'val': 0, 'specHan':False, 'hasStr':True, 'parStr': 'My EvilService', 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc1", 'com':'lpDisplayName'},  # TODO: varStr = 'My EvilService'
		'10': {'valStr': 'dwDesiredAccess', 'val': 0x2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwDesiredAccess - SC_MANAGER_CREATE_SERVICE'},
		'11': {'valStr': 'dwServiceType', 'val': 0x10, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwServiceType - SERVICE_WIN32_OWN_PROCESS'},
		'12': {'valStr': 'dwStartType', 'val': 0x2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwStartType - SERVICE_AUTO_START'},
		'13': {'valStr': 'dwErrorControl', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwErrorControl - SERVICE_ERROR_IGNORE'},
		'14': {'valStr': 'lpBinaryPathName', 'val': 0, 'specHan':False, 'hasStr':True, 'parStr': True, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2', 'com':'lpBinaryPathName , \"C:\\Program Files\\VMware\\VMware Tools\\demo.exe"'}, # TODO: varStr = 'C:\Program Files\VMware\VMware Tools\demo.exe'
		'15': {'valStr': 'lpLoadOrderGroup', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpLoadOrderGroup'},
		'16': {'valStr': 'lpdwTagId', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpdwTagId'},
		'17': {'valStr': 'lpDependencies', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpDependencies'},
		'18': {'valStr': 'lpServiceStartName', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpServiceStartName'},
		'19': {'valStr': 'lpPassword', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpPassword'},
		
		'4': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":"8",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		# val2 comes from the OpenSCManagerA eax, which will be written to stack using mov deref.
		# stackLoc1
		'1': {'r': 'ecx', 'val': 'hSCManager', 'val2':'getStack', 'excluded':[], "r2":"",'com':'hSCManager','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'CSA_RT', 'excluded':[], "r2":"",'com':'CreateServiceAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'eax', 'val': 'lpServiceName', 'excluded':[], "r2":"",'com':'lpServiceName','specHan':False, 'hasStr':True, 'parStr': True, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc3'}
		},

		'SEA1_incomplete':{
		'4': {'r': 'edi', 'val': 'SEA_RT', 'excluded':[], "r2":"",'com':'ShellExecuteAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'hwnd', 'excluded':[], "r2":"",'com':'hwnd','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'ecx', 'val': 'lpDirectory', 'excluded':[], "r2":"",'com':'lpDirectory','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'lpOperation', 'excluded':[], "r2":"",'com':'lpOperation','specHan':True, 'hasStr':True, 'parStr': True, 'hasPtr':True, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2'},
		'6': {'r': 'ebx', 'val': 'lpFile', 'excluded':[], "r2":"",'com':'lpFile','specHan':True, 'hasStr':True, 'parStr': True, 'hasPtr':True, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'7': {'r': 'edx', 'val': 'lpParameters', 'excluded':[], "r2":"",'com':'lpParameters','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'nShowCmd', 'excluded':[], "r2":"",'com':'nShowCmd','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

	 	'SEA1':{
		'9': {'valStr': 'lpFile', 'val': 0, 'specHan':True, 'hasStr':True, 'parStr': 'calc', 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc2', 'com':'lpFile'}, # TODO: varStr = 'calc'
		'10': {'valStr': 'lpParameters', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None,'com':'lpParameters'},
		'11': {'valStr': 'lpDirectory', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpDirectory'},
		'12': {'valStr': 'nShowCmd', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None,'com':'nShowCmd - SW_HIDE'},
		'4': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":"8",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'ecx', 'val': 'hwnd', 'excluded':[], "r2":"",'com':'hwnd','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'SEA_RT', 'excluded':[], "r2":"",'com':'ShellExecuteAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpOperation', 'excluded':[], "r2":"",'com':'lpOperation','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'}
		},

		'CRT1':{ # CreateRemoteThreadA
		'9': {'valStr': 'dwStackSize', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwStackSize - set to NULL'}, 
		'10': {'valStr': 'lpStartAddress', 'val': 0xddddffff, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'placeholder for lpStartAddress'}, # TODO: special handling
		'11': {'valStr': 'lpParameter', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpParameter - set to NULL'},
		'12': {'valStr': 'dwCreationFlags', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwCreationFlags - set to null'},
		'13': {'valStr': 'lpThreadId', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpThreadId - set to NULL'},
		'1': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'pop', 'excluded':["edi", "esi"], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'hProcess_CRT', 'excluded':[], "r2":"",'com':'hProcess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'CRT_RT', 'excluded':[], "r2":"",'com':'CreateRemoteThreadStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'lpThreadAttributes', 'excluded':[], "r2":"",'com':'lpThreadAttributes - set to NULL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

	   'VAE1':{ #VirtualAllocEx
		'9': {'valStr': 'dwSize', 'val': 0x999, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwSize','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'10': {'valStr': 'flAllocationType', 'val': 0x3000, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'flAllocationType - MEM_RESERVE | MEM_COMMIT'},
		'11': {'valStr': 'flProtect', 'val': 0x40, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'flProtect - PAGE_EXECUTE_READWRITE'},
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":"8",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'hProcess_VAE', 'excluded':[], "r2":"",'com':'hProcess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'VAE_RT', 'excluded':[], "r2":"",'com':'VirtualAllocExStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'lpAddress', 'excluded':[], "r2":"",'com':'lpAddress','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'TP1':{ #TerminateProcess
		'1': {'r': 'edi', 'val': 'ret_c2', 'excluded':[], "r2":"8",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'hProcess_TP', 'excluded':[], "r2":"",'com':'hProcess','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'TP_RT', 'excluded':[], "r2":"",'com':'TerminateProcessStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'uExitCode', 'excluded':[], "r2":"",'com':'uExitCode - set to NULL','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		},

		'CPA1':{ #CreateProcessA
		'9': {'valStr': 'lpProcessAttributes', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpProcessAttributes '},
		'10': {'valStr': 'lpThreadAttributes', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpThreadAttributes'},
		'11': {'valStr': 'bInheritHandles', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'bInheritHandles'},
		'12': {'valStr': 'dwCreationFlags', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwCreationFlags'},
		'13': {'valStr': 'lpEnvironment', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpEnvironment'},
		'14': {'valStr': 'lpCurrentDirectory', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpCurrentDirectory'},
		'15': {'valStr': 'lpStartupInfo', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':True, 'hasStru': True, 'strucT':"AllNull", 'struSize':68, 'loc':'loc2', 'com':'lpStartupInfo struct'}, # TODO: pointer to struct of 17 dwords- 0's
		'16': {'valStr': 'lpProcessInformation', 'val': 0, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':True, 'hasStru':False, 'strucT':None, 'struSize':68, 'loc':'loc2', 'com':'lpProcessInformation struct'}, # TODO: pointer to struct of 17 dwords- 0's  - this one is resusing the previous one - this is not really set up to do that, so jsut doing struct size 1  - will be equivalent
		'8': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'ebp', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'3': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ecx', 'val': 'lpApplicationName', 'excluded':[], "r2":"",'com':'lpApplicationName','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'CPA_RT', 'excluded':[], "r2":"",'com':'CreateProcessAStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1': {'r': 'eax', 'val': 'lpCommandLine', 'excluded':[], "r2":"",'com':'lpCommandLine - calc is supplied - ','specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc1"}
		},

		'HA1':{
		'9': {'valStr': 'dwBytes', 'val': 0x1000, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwBytes'},
		'3': {'r': 'edi', 'val': 'ropNop', 'excluded':[], "r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4': {'r': 'ebp', 'val': 'ropNop', 'excluded':[],"r2":"",'com':'ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'2': {'r': 'esi', 'val': 'ret_c2', 'excluded':[], "r2":"4",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		# val2 comes from the HeapCreate, which will be written to stack using mov deref.
		# stackLoc1
		'1': {'r': 'ecx', 'val': 'hHeap', 'val2': 'getStack', 'excluded':[], "r2":"",'com':'hHeap','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5': {'r': 'esp', 'val': 'skip', 'excluded':[], "r2":"",'com':'','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'6': {'r': 'ebx', 'val': 'HA_RT', 'excluded':[], "r2":"",'com':'HeapAllocStub','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'7': {'r': 'edx', 'val': 'returnAddress', 'excluded':[], "r2":"",'com':'Return address, ROP nop','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'8': {'r': 'eax', 'val': 'dwFlags_HA', 'excluded':[], "r2":"",'com':'dwFlags','specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None}
		}
	}


pat3 = {

		'OPT':{
		'1': {'valStr': 'OPT_RT', 'val': 0x0af0bd07, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'OpenProcessToken - not found. 0x0af0bd07 used as placeholder.'},
		'2': {'valStr': 'returnAddress', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'returnAddress'},
		'3': {'valStr': 'ProcessHandle', 'val': 0xffffffff, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'ProcessHandle'},
		'4': {'valStr': 'DesiredAccess', 'val': 0x20, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'DesiredAccess - TOKEN_ADJUST_PRIVILEGES'},
		'5': {'valStr': 'TokenHandle', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':True, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'TokenHandle'},
		},

		'ATP':{
		'1': {'valStr': 'ATP_RT', 'val': 0x0af0bd26, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'AdjustTokenPrivileges - not found. 0x0af0bd26 used as placeholder.'},
		'2': {'valStr': 'returnAddress', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'returnAddress'},
		'3': {'valStr': 'TokenHandle', 'val': 0xd82, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'0xd82 - used as placeholder value'},
		'4': {'valStr': 'DisableAllPrivileges', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'DisableAllPrivileges'},
		# 5 -> TODO: create pointer to struct - this has struct inside struct - real values inside struct
		'5': {'valStr': 'NewState', 'val': 0, 'specHan':False, 'hasStr':True, 'parStr': None, 'hasPtr':True, 'strucT':None, 'struSize':None, 'loc':None, 'com':'NewState'},
		'6': {'valStr': 'BufferLength', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'BufferLength'},
		'7': {'valStr': 'PreviousState', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'PreviousState'},
		'8': {'valStr': 'ReturnLength', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'ReturnLength'},
		},

		'CFA':{
		'1': {'valStr': 'CFA_RT', 'val': 0x0af0bd22, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'CreateFileA - not found. 0x0af0bd22 used as placeholder.'},
		'2': {'valStr': 'returnAddress', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'returnAddress'},
		# 3 -> TODO: point to "\\??\\c:\\Windows\\SysWOW64\\urlmon.dll"
		'3': {'valStr': 'lpFileName', 'val': 0, 'specHan':True, 'hasStr':False, 'parStr': '\\??\\c:\\Windows\\SysWOW64\\urlmon.dll', 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpFileName'},
		'4': {'valStr': 'dwDesiredAccess', 'val': 0x00120089, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwDesiredAccess - GENERIC_READ'},
		'5': {'valStr': 'dwShareMode', 'val': 0x1, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwShareMode - FILE_SHARE_READ'},
		'6': {'valStr': 'lpSecurityAttributes ', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'lpSecurityAttributes'},
		'7': {'valStr': 'dwCreationDisposition', 'val': 0x3, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwCreationDisposition - OPEN_EXISTING'},
		'8': {'valStr': 'dwFlagsAndAttributes', 'val': 0x860, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'dwFlagsAndAttributes'},
		'9': {'valStr': 'hTemplateFile', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'hTemplateFile'},
		},

		'NtCS':{
		'1': {'valStr': 'NtCS_RT', 'val': 0x0af0bd21, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'NtCreateSection - not found. 0x0af0bd21 used as placeholder.'},
		'2': {'valStr': 'returnAddress', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'returnAddress'},
		'3': {'valStr': 'SectionHandle', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'SectionHandle'},
		'4': {'valStr': 'DesiredAccess', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'DesiredAccess'},
		'5': {'valStr': 'ObjectAttributes', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'ObjectAttributes'},
		'6': {'valStr': 'MaximumSize ', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'MaximumSize'},
		'7': {'valStr': 'SectionPageProtection', 'val': 0x2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'SectionPageProtection - PAGE_READONLY'},
		'8': {'valStr': 'AllocationAttributes', 'val': 0x01000000, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'AllocationAttributes'},
		'9': {'valStr': 'FileHandle', 'val': 0xd88, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'FileHandle - placeholder handle from CreateFileA'},
		},

		'NtMVS':{
		'1': {'valStr': 'NtMVS_RT', 'val': 0x0af0bd29, 'specHan':True, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'NtMapViewOfSection - not found. 0x0af0bd29 used as placeholder.'},
		'2': {'valStr': 'returnAddress', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'returnAddress'},
		'3': {'valStr': 'SectionHandle', 'val': 0xe1, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':' - placeholder SectionHandle from the NtCreateSection'},
		'4': {'valStr': 'ProcessHandle', 'val': 0xc2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'ProcessHandle - placeholder Process handle from the OpenProcess '},
		# 5 -> TODO: pointer to NULL
		'5': {'valStr': 'BaseAddress', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':True, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'BaseAddress'},
		'6': {'valStr': 'ZeroBits ', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'ZeroBits'},
		'7': {'valStr': 'CommitSize', 'val': 0x2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'CommitSize'},
		'8': {'valStr': 'SectionOffset', 'val': 0x01000000, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'SectionOffset'},
		# 9 -> TODO: pointer which points to 3 NULLs
		'9': {'valStr': 'ViewSize', 'val': 0xd88, 'specHan':False, 'hasStr':False, 'parStr': True, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'ViewSize'},
		'10': {'valStr': 'InheritDisposition', 'val': 0x1, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'InheritDisposition'},
		'11': {'valStr': 'AllocationType', 'val': 0, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'AllocationType'},
		'12': {'valStr': 'Protect', 'val': 0x2, 'specHan':False, 'hasStr':False, 'parStr': None, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None, 'com':'Protect'}
		}
		}

patSys64={


		'NtQueryInformationThread':{
		'2':{'r':'rdx', 'val':0, 'com':'ThreadBasicInformation', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1':{'r':'r8', 'val':0, 'com':'buffer for THREAD_BASIC_INFORMATION', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':"loc1"},
		'3':{'r':'r9', 'val':0x30, 'com':'sizeof(THREAD_BASIC_INFORMATION) ', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4':{'r':'rax', 'val':0x25, 'com':'NtQueryInformationThread SSN (all Win. 10-11)', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5':{'r':'r10', 'val':0xFFFFFFFFFFFFFFFE, 'com':'first parm from rcx ', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'retrieve':{'loc':'loc2', 'com':'retrieving TEB'}
		},
			'NtQueryInformationProcess':{
		'2':{'r':'rdx', 'val':0, 'com':'ProcessInformationClass = 0 (BasicInfo)', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'1':{'r':'r8', 'val':0, 'com':'ProcessInformation buffer', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':'loc1'},
		'3':{'r':'r9', 'val':0x30, 'com':'Buffer size ', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'4':{'r':'rax', 'val':0x19, 'com':'NtQueryInformationProcess SSN (all Win. 10-11)', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'5':{'r':'r10', 'val':0xFFFFFFFFFFFFFFFF, 'com':'first parm from rcx - current process  ', 'hasStr':False, 'hasPtr':False, 'hasStru': False, 'strucT':None, 'struSize':None, 'loc':None},
		'retrieve':{'loc':'loc1', 'com':'PEB'}
		}	
}