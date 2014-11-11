cryptdoor
=========

AES encrypted python backdoor that communicates AES encrypted data.
Shell has the ability to spawn a meterpreter reverse_tcp into memory using VirtualAlloc (taken from Veil-Evasion).
We can also download and upload files over the secure AES encrypted connection.
Keylogging is also implemented for windows using pyHook and the keystrokes are transmitted over the secure AES encrypted connection.
All communications apart from ones meterpreter makes are encrypted with AES.
On top of this the script itself is encrypted with AES and decrypts itself in memory (taken from pyherion).

Usage
=========

cryptdoor.py will make the backdoor and server.
The syntax is:

	./cryptdoor.py host port

You can add a -p to attempt automatic persistence like:

	./cryptdoor.py host port -p

host and port refer to the host and port of the listening server.

	AES-shell options:
    	 download file       -  Download a file from remote pwd to localhost.
    	 upload filepath     -  Upload a filepath to remote pwd.
    	 run commands        -  Run a command in the background.

	Windows Only:
    	 persistence         -  Install exe as a system service backdoor.
    	 meterpreter ip:port -  Execute a reverse_tcp meterpreter to ip:port.
    	 keyscan             -  Start recording keystrokes.
    	 keydump             -  Dump recorded keystrokes.
    	 keyclear            -  Clear the keystroke buffer.
    	 chromepass          -  Retrieve chrome stored passwords.
    	 bypassuac cmds      -  Run commands as admin.


