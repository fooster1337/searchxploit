# SearchXploit
Searchxploit is tools for find vulnerability based on exploit-db database.<br>
This tool is inspired by <a href="https://gitlab.com/exploit-database/exploitdb">Searchsploit</a>

## Usage Example
```
[cilia@cilia searchxploit]$ python3 searchxploit.py
===
Exploit-Searching By github.com/fooster1337
inspired by searchsploit [https://gitlab.com/exploit-database/exploitdb]
===

Usage : searchxploit.py [options]

>> Options      Argument        Description
----------      --------        -----------
-h, --help                      Help Menu
-s, --search    [Keyword]       Search like ordinary e.g -s afd windows local
-cve, --cve     [YYYY-NNNN]     Search cve e.g -cve 2021-44228 
-w, --www                       Show URLs to Exploit-DB.com.
-j, --json                      Show result in JSON.
--save                          Save all report to file.
--update                        Update files exploit and shellcode
[cilia@cilia searchxploit]$
[cilia@cilia searchxploit]$ python3 searchxploit.py -s afd windows local
[-] Shellcodes : Not Found..
+----------------------------------------------------------------------------------------+------------------------------------+
| Exploit Title                                                                          | Path                               |
+========================================================================================+====================================+
| Microsoft Windows - 'afd.sys' Local Kernel (PoC) (MS11-046)                            | exploits/windows/dos/18755.c       |
+----------------------------------------------------------------------------------------+------------------------------------+
| Microsoft Windows XP - 'afd.sys' Local Kernel Denial of Service                        | exploits/windows/dos/17133.c       |
+----------------------------------------------------------------------------------------+------------------------------------+
| Microsoft Windows - 'AfdJoinLeaf' Local Privilege Escalation (MS11-080) (Metasploit)   | exploits/windows/local/21844.rb    |
+----------------------------------------------------------------------------------------+------------------------------------+
| Microsoft Windows XP/2003 - 'afd.sys' Local Privilege Escalation (K-plugin) (MS08-066) | exploits/windows/local/6757.txt    |
+----------------------------------------------------------------------------------------+------------------------------------+
| Microsoft Windows XP/2003 - 'afd.sys' Local Privilege Escalation (MS11-080)            | exploits/windows/local/18176.py    |
+----------------------------------------------------------------------------------------+------------------------------------+
| Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)              | exploits/windows_x86/local/40564.c |
+----------------------------------------------------------------------------------------+------------------------------------+
[cilia@cilia searchxploit]$
[cilia@cilia searchxploit]$ python3 searchxploit.py -cve 2021-44228
---------------------------------------
Information About CVE-2021-44228
- Exploit Title : Apache Log4j2 2.14.1 - Information Disclosure
- Path          : exploits/java/remote/50590.py
- Exploit-DB    : exploit-db.com/exploit/50590
- Type          : remote
- Platform      : java
---------------------------------------
[cilia@cilia searchxploit]$ exit
```
## Installation
1. make sure you have python3+ installed
2. Follow this command :
```
git clone https://github.com/fooster1337/searchxploit
cd searchxploit
pip3 install -r requirements.txt
python3 searchxploit.py
```

## Author
This tool made by <a href="https://github.com/fooster1337">fooster1337 github</a><br>
Website : <a href="https://www.fooster1337.net/">Click me</a>
