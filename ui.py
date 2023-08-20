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
	author=yel+"                   v.0.9:  Bramwell Brizendine, 2023"+res

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
	text="\n"
	text += "  {}   x86:{}\tx64:{}\n".format(cya + "r"+res+" -"+gre+"  Capture ROP Gadgets. "+yel, togx86Ex+yel,togx64Ex)
	text += "  {}        \n".format(cya + "g"+res+" -"+gre+"  Generate Heaven's Gate x32 to x64."+ res)
	text += "  {}        \n".format(cya + "t"+res+" -"+gre+"  Generate Heaven's Gate x64 to x32."+ res)

	text += "  {}        \n".format(cya + "a"+res+" -"+gre+"  Generate Windows Syscall - "+yel+
		"NtAllocateVirtualMemory."+ res)
	text += "  {}        \n".format(cya + "v"+res+" -"+gre+"  Generate Windows Syscall - "+yel+"NtProtectVirtualMemory."+ res)
	text += "  {}        \n".format(cya + "s"+res+" -"+gre+"  Generate Shellcodeless ROP: "+yel+"System."+ res)
	text += "  {}        \n".format(cya + "d"+res+" -"+gre+"  Generate Shellcodeless ROP: "+yel+"GetProcAddress."+ res)

	text += "  {}        \n".format(cya + "m"+res+" -"+gre+"  Generate Mov Dereference:"+yel+" VirtualProtect."+ res)
	text += "  {}        \n".format(cya + "o"+res+" -"+gre+"  Obfuscate gadget/value."+ res)
	text += "  {}        \n".format(cya + "p"+res+" -"+gre+"  Print gadgets found."+ res)

	text += "  {}        \n".format(cya + "f"+res+" -"+gre+"  PE file submenu."+ res)

	text += "  {}        \n".format(cya + "c"+res+" -"+gre+"  Save config file ["+res+"config.cfg"+gre+"] with current selections."+ res)
	text += "  {}        \n".format(cya + "h"+res+" -"+gre+"  Display options."+ res)

	print (text)
