import sys
import os
import argparse
import re
import requests
import datetime
import pandas as pd
from tabulate import tabulate

# default path.
csv_exploit = "files/files_exploits.csv"
csv_shellcode = "files/files_shellcodes.csv"

banner = """
  __                 _            _ _______________ 
 / _| ___   ___  ___| |_ ___ _ __/ |___ /___ /___  |
| |_ / _ \ / _ \/ __| __/ _ \ '__| | |_ \ |_ \  / / 
|  _| (_) | (_) \__ \ ||  __/ |  | |___) |__) |/ /  
|_|  \___/ \___/|___/\__\___|_|  |_|____/____//_/   
                                                    
"""

class Search:
    
    def __init__(self, search, cve, www, json, save):
        self.search = search
        self.cve = cve
        self.www = www
        self.json = json
        self.save = save
        self.exploit_found = True
        self.shellcodes_found = True
        self.headers = ["Exploit Title", "Path"]
        self.exploit = open_files_exploit()
        self.csv_shellcode_files = open_files_shellcode()
        self.exploit_data = self.exploit["description"].to_list()
        self.shellcode_data = self.csv_shellcode_files["description"].to_list()
    
    @property
    def time_now(self):
        date = datetime.datetime.now()
        return date.strftime('%Y-%m-%d')
    
    def write_file(self, content):
        time = self.time_now
        name_file = f"{time}.txt"
        if os.path.exists("save") != True:
            os.makedirs("save")
        # write file
        i = 0
        if os.path.exists("save/"+name_file):
            while (os.path.exists("save/"+name_file) == True):
                i += 1
                name_file = f"{time}_{i}.txt"
            #name_file = f"{time}_{i}.txt"
                
            
        try:
            open(f"save/{name_file}", "w+", encoding="utf8").write(content)
            print(f"\n[+] File saved on save/{name_file}")
        except Exception as e:
            print(f"[-] Error when save file : {e}")



    def searchexp(self):
        # if len(self.search) >= 2:
        #     self.search = ""
        #     for s in self.search:
        #         self.search += s
        # else:
        #     self.search = self.search[0]
        if self.cve != None:
            indx = 0
            self.cve = "CVE-"+self.cve
            self.search = None
            self.www = False
            for index, codes in enumerate(self.exploit["codes"].to_list()):
               #print(str(codes))
               if self.cve in str(codes):
                   indx = index
            
            if indx != 0:
                if self.json != False:
                    data = {
                        "info": {
                            "CVE": f'{self.cve}',
                            "title": f'{self.exploit["description"][indx]}',
                            "path": f'{self.exploit["file"][indx]}',
                            "exploit-db": f'exploit-db.com/exploit/{self.exploit["id"][indx]}',
                            "type": f'{self.exploit["type"][indx]}',
                            "platform": f'{self.exploit["platform"][indx]}'
                        }
                    }
                    
                    print(data["info"])
                    content = data["info"]
                else:

                    information = f"""---------------------------------------
Information About {self.cve}
- Exploit Title : {self.exploit["description"][indx]}
- Path          : {self.exploit["file"][indx]}
- Exploit-DB    : exploit-db.com/exploit/{self.exploit["id"][indx]}
- Type          : {self.exploit["type"][indx]}
- Platform      : {self.exploit["platform"][indx]}
---------------------------------------"""
                    print(information)
                    content = information
            else:
                print("[-] CVE not found in database. Try search online...")
        if self.search != None:
            exploit_title = []
            path = []
            shellcodes_link = []
            shellcodes = []
            shellcodes_file = []
            data_json = {
                "exploit": {
                    "exploit_title": [],
                    "file": [],
                    "exploit-db": []
                },
                "shellcodes": {
                    "shellcodes_title": [],
                    "file": [],
                    "exploit-db": []
                }
            }
            indexes_found = [index for index, desc in enumerate(self.exploit_data) if all(search.lower() in desc.lower() for search in self.search)]
            if indexes_found:
                for idx in indexes_found:
                    if self.json != False:
                        data_json["exploit"]["exploit_title"].append(self.exploit_data[idx])
                    else:
                        exploit_title.append(self.exploit_data[idx])
               
            if exploit_title or data_json["exploit"]["exploit_title"]:
                for i in indexes_found:
                    if self.json != False:
                        data_json["exploit"]["file"].append(self.exploit["file"][i])
                    else:
                        path.append(self.exploit["file"][i])

                if self.www != False:
                    exploit_link = []
                    self.headers.append("Exploit-DB")
                    for i in indexes_found:
                        if self.json != False:
                            data_json["exploit"]["exploit-db"].append(f'exploit-db.com/exploits/{self.exploit["id"][i]}')
                        else:
                            exploit_link.append(f'exploit-db.com/exploits/{self.exploit["id"][i]}')

            else:
                self.exploit_found = False
                #print("[-] Exploit : Not Found.")

            
            indexes_found = [index for index, desc in enumerate(self.shellcode_data) if all(search.lower() in desc.lower() for search in self.search)]
            if indexes_found:
                for idx in indexes_found:
                    if self.json != False:
                        data_json["shellcodes"]["shellcodes_title"].append(self.shellcode_data[idx])
                    else:
                        shellcodes.append(self.shellcode_data[idx])

                    for i in indexes_found:
                        shellcodes_file.append(self.shellcode_data["file"][i])
                    if self.www != False:
                        for i in indexes_found:
                            shellcodes_link.append(f'exploit-db.com/shellcodes/{self.shellcode_data["id"][i]}')

            else:
                # print("[-] Shellcodes : not found.\n")
                self.shellcodes_found = False

            
            if self.exploit_found != True:
                print("[-] Exploit : Not Found...")
            if self.shellcodes_found != True:
                print("[-] Shellcodes : Not Found..")
            if self.exploit_found != True and self.shellcodes_found != True:
                print("[-] Looks like we found nothing..."); sys.exit(0)
            if self.json != False:
                print(data_json)
                content = data_json
            else:
                if self.www != False:
                    print(tabulate(zip(exploit_title, path, exploit_link), headers=self.headers, tablefmt="grid"))
                    if shellcodes:
                        self.headers[0] = "Shellcodes"
                        print(tabulate(zip(shellcodes, shellcodes_file, shellcodes_link), headers=self.headers, tablefmt="grid"))
                else:
                    print(tabulate(zip(exploit_title, path), headers=self.headers, tablefmt="grid"))
                    if shellcodes:
                        self.headers[0] = "Shellcodes"
                        print(tabulate(zip(shellcodes, shellcodes_file), headers=self.headers, tablefmt="grid"))

                content = ""

                content += "== Exploit Title ==\n"

                if self.json != False:
                    exploit_title = data_json["exploit"]["exploit_title"]
                    file_path_exploit = data_json["exploit"]["file"]
                    shellcodes_title = data_json["shellcodes"]["shellcodes_title"]
                    file_path_shellcodes = data_json["shellcodes"]["file"]

                    content += "\n".join(exploit_title) + "\n== Path ==\n"
                    content += "\n".join(file_path_exploit) + "\n== Shellcodes ==\n"
                    content += "\n".join(shellcodes_title) + "\n== Path ==\n"
                    content += "\n".join(file_path_shellcodes)

                    if self.www != False:
                        exploit_db_link = data_json["exploit"]["exploit-db"]
                        shellcodes_db_link = data_json["shellcodes"]["exploit-db"]

                        content += "\n== Exploit Link ==\n"
                        content += "\n".join(exploit_db_link) + "\n== Shellcodes Link ==\n"
                        content += "\n".join(shellcodes_db_link)
                else:
                    content += "\n".join(exploit_title) + "\n== Path ==\n"
                    content += "\n".join(path) + "\n== Shellcodes ==\n"
                    content += "\n".join(shellcodes) + "\n== Path ==\n"
                    content += "\n".join(shellcodes_file)

                    if self.www != False:
                        content += "\n== Exploit Link ==\n"
                        content += "\n".join(exploit_link) + "\n== Shellcodes Link ==\n"
                        content += "\n".join(shellcodes_link)

            if self.save != False:
                self.write_file(str(content))
                
def open_files_exploit():
    try:
        op = pd.read_csv(csv_exploit)
        return op
    except FileNotFoundError:
        print(f"[-] {csv_exploit} File not found.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error {e}")
        sys.exit(0)

def open_files_shellcode():
    try:
        op = pd.read_csv(csv_shellcode)
        return op
    except FileNotFoundError:
        print(f"[-] {csv_shellcode} File not found.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error {e}")
        sys.exit(0)



def read_config():
    try:

        conf = open("config.txt", "r").read()
       
        csv_exploit = re.search(r'files_csv_exploit="(.*?)"', conf)
        csv_shellcode = re.search(r'files_csv_shellcode="(.*?)"', conf)
        if csv_exploit and csv_shellcode:
            csv_exploit = csv_exploit.group(1)
            csv_shellcode = csv_shellcode.group(1)
        else:
            print("[-] Syntax Failed/the contents of the file form are missing on config.txt. Use default path...")
        #print(csv_exploit, csv_shellcode)
    except FileNotFoundError:
        print("[-] Looks like config.txt not found. Use default path...")
    except Exception as e:
        print(f"[-] {e}. Use default path...")

def clear():
    os.system("cls") if os.name == "nt" else os.system("clear")

def update():
    try:
        req = requests.head("https://www.google.com", timeout=3)
    except:
        raise Exception("[-] You are offline. Skipping update...")
    
    print("[*] Downloading and replace file...")
    try:
        exploit = requests.get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads&inline=false")
        shellcode = requests.get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv?ref_type=heads&inline=false")
    except Exception as e:
        raise Exception(f"[-] Something error {e}")
    
    try:

        s = open(csv_exploit, "w").write(str(exploit.text))
        s2 = open(csv_shellcode, "w").write(str(shellcode.text))
        print("[*] Success update!")
    except Exception as e:
        print(f"[-] Error when update {e}")
    


def usage():
    usage = f"""===
Exploit-Searching By github.com/fooster1337
inspired by searchsploit [https://gitlab.com/exploit-database/exploitdb]
===

Usage : {sys.argv[0]} [options]

>> Options      Argument        Description
----------      --------        -----------
-h, --help                      Help Menu
-s, --search    [Keyword]       Search like ordinary e.g -s afd windows local
-cve, --cve     [YYYY-NNNN]     Search cve e.g -cve 2021-44228 
-w, --www                       Show URLs to Exploit-DB.com.
-j, --json                      Show result in JSON.
--save                          Save all report to file.
--update                        Update files exploit and shellcode
"""
    print(usage)

def main():
    if len(sys.argv) <= 1:
        usage()
        sys.exit(0)

    if '--help' in sys.argv or '-h' in sys.argv:
        usage()
        sys.exit(0)

    if '--update' in sys.argv:
        print("[*] Updating ...")
        update()
        sys.exit(0)

    parser= argparse.ArgumentParser(add_help=False)
    parser.add_argument('-s', '--search', type=str, default=None, nargs='+')
    parser.add_argument('-cve', '--cve', type=str, default=None)
    parser.add_argument('-w', '--www', action='store_true')
    parser.add_argument('-j', '--json', action='store_true')
    parser.add_argument('--save', action='store_true')
    args = parser.parse_args()
    exp = Search(args.search, args.cve, args.www, args.json, args.save)
    exp.searchexp()


    

if __name__ == '__main__':
    clear()
    read_config()
    main()