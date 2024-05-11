#!/usr/bin/python3
import argparse
import subprocess
import re

def sslsubjectcheck(ip,v):
    hostname = None
    command = f"/usr/bin/curl --insecure -vvI https://{ip} --max-time 2 2>&1 | /usr/bin/awk 'BEGIN {{ cert=0 }} /^\* SSL connection/ {{ cert=1 }} /^\*/ {{ if (cert) print }}'"
    if v:
        print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    if v:
        print(result.stdout)
    cn_pattern =  r"CN=([^;\n]+)"
    match = re.search(cn_pattern, result.stdout)    
    if match:
        hostname = match.group(1)
    return hostname
    
def redirectcheck(ip,v):      
    command = f"/usr/bin/curl --insecure -I https://{ip} --max-time 2 | grep location"
    if v:
        print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    if v:
        print(result.stdout)
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
        
def nslookupcheck(ip,hostname,v):
    command = f"/usr/bin/nslookup {hostname}"
    if v:
        print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    if v:
        print(result.stdout)
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
    parser.add_argument('-v','--verbose', action="store_true", help="Show commands and responses.")
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
        hostname = sslsubjectcheck(ip, args.verbose)
        print(f"{hostname} {ip}")

        if hostname != None:
            ns = nslookupcheck(ip,hostname, args.verbose)
            if ns != None:
                print(f"Match found: {hostname} {ip}")
                results.append(ns)
                continue

        print("doing redirect check")
        hostname = redirectcheck(ip, args.verbose)
        print(f"{hostname} {ip}")
        if hostname != None:
            ns = nslookupcheck(ip,hostname, args.verbose)
            if ns != None:
                print(f"Match found: {hostname} {ip}")
                results.append(ns)
                continue
    
    print("===========")
    print("All Matches")
    print("===========")
    for result in results:
        print(result)    




if __name__ == "__main__":
    main()