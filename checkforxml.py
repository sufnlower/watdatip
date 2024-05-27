#!/usr/bin/python3
import argparse
import subprocess
import re


def doGetRequest(url,v):
    command = f"/usr/bin/curl --insecure {url} --max-time 2"
    if v:
        print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    if v:
        print(result.stdout)
    if result != None:
        return result.stdout

def doPostRequest(url,v):
    body = """<?xml version="1.0" encoding="UTF-8"?><root></root>"""
    command = f"/usr/bin/curl -H \"Content-Type: application/xml\" -X POST -d \"{body}\" --insecure {url} --max-time 3"
    if v:
        print(command)
    result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
    if v:
        print(result.stdout)
    if result != None:
        return result.stdout

def checkForXML(urls, verbose=False):
        results = []
        for url in urls:
            print("doing get request check looking for xml")
            response = doGetRequest(url, verbose)
            if response != None:
                if "xml" in response and "<html xmlns" not in response:
                    results.append(f"{url} had \"xml\" in the response body or headers")
                    print(f"{url} had \"xml\" in the response body or headers")
            else:
                print(f"{url} no response")
            print("doing post request check looking for xml")
            response = doPostRequest(url, verbose)
            if response != None:
                if "xml" in response and "<html xmlns" not in response:
                    results.append(f"{url} had \"xml\" in the response body or headers")
                    print(f"{url} had \"xml\" in the response body or headers")
            else:
                print(f"{url} no response")
        return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', help="Check one URL")
    parser.add_argument('-f','--file', help="Input file, one line at a time")
    parser.add_argument('-v','--verbose', action="store_true", help="Show commands and responses.")
    args = parser.parse_args()

    urls = []
    

    if args.url != None:
        urls.append(args.url)
    elif args.file != None:
        with open(args.file, 'r') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
        urls = lines
    
    results = checkForXML(urls, args.verbose)     

    print("===========")
    print("All Results")
    print("===========")
    if results != None:
        for result in results:
            print(result)   


if __name__ == "__main__":
    main()
