#!/usr/bin/python3
import argparse
import subprocess
import re

def getServerResponseHeader(url,v):      
    command = f"/usr/bin/curl --insecure -I {url} --max-time 2"
    if v:
        print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    if v:
        print(result.stdout)
    lines = result.stdout.split('\n')
    for line in lines:
        if "server" in line or "Server" in line:
            return line
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', help="Check one URL")
    parser.add_argument('-f','--file', help="Input file, one line at a time")
    parser.add_argument('-v','--verbose', action="store_true", help="Show commands and responses.")
    args = parser.parse_args()

    urls = []
    results = []

    if args.url != None:
        urls.append(args.url)
    elif args.file != None:
        with open(args.file, 'r') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
        urls = lines
    
     
    for url in urls:
        print("doing server header check")
        serverHeader = getServerResponseHeader(url, args.verbose)
        if serverHeader != None:
            results.append(f"{url} {serverHeader}")
            print(f"{url} {serverHeader}")
        else:
            print(f"{url} Server header not found")

    print("===========")
    print("All Results")
    print("===========")
    for result in results:
        print(result)   


if __name__ == "__main__":
    main()