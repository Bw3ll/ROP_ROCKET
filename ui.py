import colorama

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


def splash():


	splash=yel+"""

     " ,  ,
        ", ,
           ""     _---.    ..;%%%;, .
             "" .",  ,  .==% %%%%%%% ' .
               "", %%%   =%% %%%%%%;  ; ;-_
               %; %%%%%  .;%;%%%"%p ---; _  '-_
               %; %%%%% __;%%;p/; O        --_ "-,_
                q; %%% /v \;%p ;%%%%%;--__    "'-__'-.__					
                //\\" // \  % ;%%%%%%%;',/%\_  __  "'-_'\__						
                \  / //   \/   ;%% %; %;/\%%%%;;;;\    "- _\					
                   ,"             %;  %%;  %%;;'  ';%       -\-__				
              -=\="             __%    %%;_ |;;    %%%\          \ 				
                              _/ _=      \==_;;,_ %%%; % -_      / 				
                             / /-          =%- ;%%%%; %%;  "--__/	
                            //=             ==%-%%;  %; %				
                            /             _=_-  d  ;%; ;%;  :F_P:		
                            \            =,-"    d%%; ;%%;				
                                        //        %  ;%%;				
                                       //          d%%%"				
                                        \           %%						
                                                    v							"""+res
	splash2=cya+"""   _____ _          _ ___          __             
  / ____| |        | | \ \        / /             
 | (___ | |__   ___| | |\ \  /\  / /_ _ ___ _ __  
  \___ \| '_ \ / _ \ | | \ \/  \/ / _` / __| '_ \ 
  ____) | | | |  __/ | |  \  /\  / (_| \__ \ |_) |
 |_____/|_| |_|\___|_|_|   \/  \/ \__,_|___/ .__/ 
                                           | |    
  Syscall Shellcode for WoW64, 32-bit    |_|    

"""+res
	author=yel+"                   v.2.0:  Bramwell Brizendine, 2022-2023"+res
	# print (splash)
	# print (splash2)
	# print (author)


	banner=gre+"""

   ___  ____  ___    ___  ____  _______ ____________
  / _ \/ __ \/ _ \  / _ \/ __ \/ ___/ //_/ __/_  __/
 / , _/ /_/ / ___/ / , _/ /_/ / /__/ ,< / _/  / /   
/_/|_|\____/_/    /_/|_|\____/\___/_/|_/___/ /_/    
                                                    
"""+res
	author=yel+"                   v.1.2:  Bramwell Brizendine, 2023-2025"+res

	print (banner)
	print (author)

def uiShowOptionsMainMenu(x86,x64):
	if x86:
		togx86Ex=res+""+cya+"FOUND"+res+""
	else:
		togx86Ex=res+""+cya+"NOT FOUND"+res+""
	
	if x64:
		togx64Ex=res+""+cya+"FOUND"+res+""
	else:
		togx64Ex=res+""+cya+"NOT FOUND"+res+""

	# if useSaved:
	# 	togE=res+"["+mag+"Using Previously Saved"+res+"]"
	# else:
	# 	togE=res+"["+mag+"Not Usings Previously Saved "+res+"]"
	
	text = "\n"
	text += "  {}   x86:{}\tx64:{}\n".format(cya + "r" + res + " -" + gre + "  Capture ROP Gadgets. " + yel, togx86Ex + yel, togx64Ex)
	text += "  {}        \n".format(cya + "as" + res + " -" + gre + " Generate x64, High Entropy ASLR bypasses for" +mag+" Kernel32, Kernelbase, NTDLL" + res)
	text += "  {}        \n".format(cya + "g" + res + " -" + gre + "  Generate Heaven's Gate x32 to x64." + res)
	text += "  {}        \n".format(cya + "t" + res + " -" + gre + "  Generate Heaven's Gate x64 to x32." + res)

	text += "  {}        \n".format(cya + "a" + res + " -" + gre + "  Generate Windows Syscall: " + yel +
	    "NtAllocateVirtualMemory" + res)
	text += "  {}        \n".format(cya + "v" + res + " -" + gre + "  Generate Windows Syscall: " + yel + "NtProtectVirtualMemory" + res)
	text += "  {}        \n".format(cya + "s" + res + " -" + gre + "  Generate Shellcodeless ROP: " + yel + "System" + res)
	text += "  {}        \n".format(cya + "d" + res + " -" + gre + "  Generate Shellcodeless ROP: " + yel + "GetProcAddress" + res)

	text += "  {}        \n".format(cya + "m" + res + " -" + gre + "  Generate Mov Dereference:" + yel + " VirtualProtect" + res)



	text += "  {}        \n".format(cya + "!" + res + " -" + gre + "  Generate pushad:" + yel + " VirtualProtect" + res)
	text += "  {}        \n".format(cya + "@" + res + " -" + gre + "  Generate pushad:" + yel + " VirtualAlloc" + res)
	text += "  {}        \n".format(cya + "va" + res + " -" + gre + " Generate pushad:" + yel + " VirtualAllocEx" + res)
	text += "  {}        \n".format(cya + "wp" + res + " -" + gre + " Generate pushad:" + yel + " WriteProcessMemory" + res)
	text += "  {}        \n".format(cya + "hc" + res + " -" + gre + " Generate pushad:" + yel + " HeapCreate" + res)
	text += "  {}        \n".format(cya + "ha" + res + " -" + gre + " Generate pushad:" + yel + " HeapAlloc" + res)
	text += "  {}        \n".format(cya + "we" + res + " -" + gre + " Generate pushad:" + yel + " WinExec" + res)
	text += "  {}        \n".format(cya + "se" + res + " -" + gre + " Generate pushad:" + yel + " ShellExecuteA" + res)
	text += "  {}        \n".format(cya + "cp" + res + " -" + gre + " Generate pushad:" + yel + " CreateProcessA" + res)
	text += "  {}        \n".format(cya + "cr" + res + " -" + gre + " Generate pushad:" + yel + " CreateRemoteThread" + res)
	text += "  {}        \n".format(cya + "tp" + res + " -" + gre + " Generate pushad:" + yel + " TerminateProcess" + res)
	text += "  {}        \n".format(cya + "ct" + res + " -" + gre + " Generate pushad:" + yel + " CreateToolhelp32Snapshot" + res)
	text += "  {}        \n".format(cya + "op" + res + " -" + gre + " Generate pushad:" + yel + " OpenProcess" + res)
	text += "  {}        \n".format(cya + "pf" + res + " -" + gre + " Generate pushad:" + yel + " Process32First" + res)
	text += "  {}        \n".format(cya + "pn" + res + " -" + gre + " Generate pushad:" + yel + " Process32Next" + res)
	text += "  {}        \n".format(cya + "rs" + res + " -" + gre + " Generate pushad:" + yel + " RegSetKeyValueA" + res)
	text += "  {}        \n".format(cya + "rc" + res + " -" + gre + " Generate pushad:" + yel + " RegCreateKeyA" + res)
	text += "  {}        \n".format(cya + "df" + res + " -" + gre + " Generate pushad:" + yel + " DeleteFileA" + res)
	text += "  {}        \n".format(cya + "u" + res + " -" + gre + "  Generate pushad:" + yel + " URLDownloadToFileA" + res)
	text += "  {}        \n".format(cya + "os" + res + " -" + gre + " Generate pushad:" + yel + " OpenSCManagerA" + res)
	text += "  {}        \n".format(cya + "cs" + res + " -" + gre + " Generate pushad:" + yel + " CreateServiceA" + res)
	text += "  {}        \n".format(cya + "set" + res + " -" + gre + "  Set initial overflow value (if applicable)" + res)
	text += "  {}        \n".format(cya + "o" + res + " -" + gre + "  Obfuscate gadget/value" + res)
	text += "  {}        \n".format(cya + "b" + res + " -" + gre + "  Set Bad bytes / Bad chars and ImageBase" + res)
	text += "  {}        \n".format(cya + "p" + res + " -" + gre + "  Print gadgets found" + res)
	text += "  {}        \n".format(cya + "f" + res + " -" + gre + "  PE file submenu" + res)
	text += "  {}        \n".format(cya + "w" + res + " -" + gre + "  Find individual gadgets / wildcard" + res)
	text += "  {}        \n".format(cya + "c" + res + " -" + gre + "  Save config file [" + res + "config.cfg" + gre + "] with current selections" + res)
	text += "  {}        \n".format(cya + "res" + res + " -" + gre + "  Researcher Mode (special setttings)" + res)

	text += "  {}        \n".format(cya + "h" + res + " -" + gre + "  Display options" + res)

	print (text)