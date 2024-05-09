#!/usr/bin/python3
import sys
import argparse
import subprocess
import re

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--ip', help="Check one IP")
    parser.add_argument('-f','--file', help="Input file, one line at a time")
    args = parser.parse_args()

    command = f"/usr/bin/curl --insecure -vvI https://{args.ip} 2>&1 | /usr/bin/awk 'BEGIN {{ cert=0 }} /^\* SSL connection/ {{ cert=1 }} /^\*/ {{ if (cert) print }}'"
    
    print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')

    output = result.stdout

    cn_pattern =  r"CN=([^;\n]+)"
    match = re.search(cn_pattern, output)

    if match:
        hostname = match.group(1)
        print(hostname)

        command = f"/usr/bin/nslookup {hostname}"
        result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
        print(result.stdout)
        # Regular expression to extract Address
        address_pattern = r"Address: ([\d\.:a-f]+)"

        # Find all matches in the string
        addresses = re.findall(address_pattern, result.stdout)

        # Print each found address
        for address in addresses:
            if address == args.ip:
                print("match found")
                print(f"{hostname} {address}")

if __name__ == "__main__":
    main()

#curl --insecure -vvI https://93.184.215.14 2>&1 | awk 'BEGIN { cert=0 } /^\* SSL connection/ { cert=1 } /^\*/ { if (cert) print }'| grep subject

