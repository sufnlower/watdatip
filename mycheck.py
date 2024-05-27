#!/usr/bin/python3
import sys
import argparse
import subprocess
import re

from watdatip import *
from checkforxml import *
from grabserverheaders import *

def doNmap(port,file):
    
    cmd = "/usr/bin/nmap "
    if file != None:
        cmd += f"-iL {file} "
    cmd += f"-p {port} "
    cmd += "-vv"
    
    stdoutStr = ""
    nmap_out = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    while True:
        output = nmap_out.stdout.readline()
        if output == b'' and nmap_out.poll() is not None:
            break
        if output:
            stdoutStr += output.decode()
            print(output.decode().strip(), end='\n', flush=True)
    nmap_out.wait()
    return stdoutStr

def processNmap(stdoutStr):
    targets = stdoutStr.split("Nmap scan report for ")
    count=0
    
    print("=================")
    print("Concise Output")
    print("=================")
    
    for target in targets[1:]:
        ip = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',target)[0]
        results = target[target.index("REASON\n")+6:]
        result_lines = results.split("\n")
        openPorts = []
        ipsForOut = []
        for line in result_lines:
            port = re.search(r'\d+', line)
            if "open" in line and port is not None:
                openPorts.append(port.group())
        if len(openPorts) != 0:
            print(f"{ip} appears up due to the following: Open {openPorts}.")
            ipsForOut.append(ip)
        else:
            print("No open ports found exiting.")
            exit()
        return ipsForOut

def main():
    parser = argparse.ArgumentParser()
    #parser.add_argument('-p','--ports', default="80,139,443,22,445,88", help="Ports like nmap takes them. Defaults to 80,443,22,445,88")
    parser.add_argument('-f','--file', help='Input file for IPs')
    args = parser.parse_args()
    
    nmapout443 = doNmap(443,args.file)
    upIPs443 = processNmap(nmapout443)

    nmapout80 = doNmap(80,args.file)
    upIPs80 = processNmap(nmapout80)

    ns_results, watDatHostnames, watDatWildcards = checkIPs(upIPs443)

    #443 check for xml with hostnames
    prepend = "https://"
    httpsurls = [f'{prepend}{ip}' for ip in watDatHostnames]
    xml443urls = checkForXML(httpsurls)

    #80 check for xml with IPs
    prepend = "http://"
    httpurls = [f'{prepend}{ip}' for ip in upIPs80]
    xml80urls = checkForXML(httpurls)
    
    xmlUrls = xml443urls + xml80urls
    allUrls = httpsurls + httpurls

    serverHeaders = getServerHeaders(allUrls)
    for header in serverHeaders:
            file.write(header + "\n")

    with open("https_wildcards.txt", 'w') as file:
        for result in watDatWildcards:
            file.write(result + "\n")

    with open("https_urls_ips.txt", 'w') as file:
        for result in ns_results:
            file.write(result + "\n")

    with open("xmlhosts.txt", 'w') as file:
        for xmlUrl in xmlUrls:
            file.write(xmlUrl + "\n")

    with open("httpshosts.txt", 'w') as file:
        for httpsurl in httpsurls:
            file.write(httpsurl + "\n")

    with open("httphosts.txt", 'w') as file:
        for httpurl in httpurls:
            file.write(httpurl + "\n")

if __name__ == "__main__":
    main()
