#!/usr/bin/python3
import argparse
import subprocess
import re

def sslsubjectcheck(ip):
    hostname = ""
    command = f"/usr/bin/curl --insecure -vvI https://{ip} 2>&1 | /usr/bin/awk 'BEGIN {{ cert=0 }} /^\* SSL connection/ {{ cert=1 }} /^\*/ {{ if (cert) print }}'"
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    cn_pattern =  r"CN=([^;\n]+)"
    match = re.search(cn_pattern, result.stdout)    
    if match:
        hostname = match.group(1)
    return hostname
    
def redirectcheck(ip):      
    print("doing redirect check")
    command = f"/usr/bin/curl --insecure -I https://{ip} | grep location"
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    
    pattern = r"(?<=http:\/\/)[^\/\?]+"
    match = re.search(pattern, result.stdout)
    if match:
        hostname = match.group()
        return hostname
    pattern = r"(?<=https:\/\/)[^\/\?]+"
    match = re.search(pattern, result.stdout)
    if match:
        hostname = match.group()
        return hostname
    else:
        return None
        
def nslookupcheck(ip,hostname):
    command = f"/usr/bin/nslookup {hostname}"
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    address_pattern = r"Address: ([\d\.:a-f]+)"
    addresses = re.findall(address_pattern, result.stdout)
    for address in addresses:
        if address == ip:
            return (f"{address} {hostname}")
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--ip', help="Check one IP")
    parser.add_argument('-f','--file', help="Input file, one line at a time")
    args = parser.parse_args()

    ips = []
    results = []

    if args.ip != None:
        ips.append(args.ip)
    elif args.file != None:
        with open(args.file, 'r') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
        ips = lines
    
     
    for ip in ips:
        print("doing ssl subject check")
        hostname = sslsubjectcheck(ip)
        print(hostname)

        ns = nslookupcheck(ip,hostname)
        if ns != None:
            results.append(ns)
            continue

        hostname = redirectcheck(ip)
        ns = nslookupcheck(ip,hostname)
        if ns != None:
            results.append(ns)
            continue
    
    print(results)       




if __name__ == "__main__":
    main()