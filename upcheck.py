#!/usr/bin/python3
import sys
import argparse
import subprocess
import re

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n','--network', help="Network to scan in CIDR or something nmap likes")
    parser.add_argument('-p','--ports', default="80,139,443,22,445,88", help="Ports like nmap takes them. Defaults to 80,443,22,445,88")
    parser.add_argument('-s','--showmisses', action="store_true", help="Use if you want to see hosts where nothing suggesting up was detected")
    parser.add_argument('-f','--file', help='Input file for IPs')
    parser.add_argument('-sT','--useconnectscan', action="store_true", help="Use a connect scan, good for SOCKS proxy")
    parser.add_argument('-oA','--outputresults', help="save output as")
    args = parser.parse_args()
      
    cmd = "/usr/bin/nmap "
    if args.network != None:
        cmd += f"{args.network} "
    elif args.file != None:
        cmd += f"-iL {args.file} "
    cmd += f"-p {args.ports} "
    if args.useconnectscan:
        cmd += "-sT "
    if args.outputresults != None:
        cmd += f"-oA {args.outputresults} "
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
        closedPorts = []
        unfilteredPorts = []
        for line in result_lines:
            port = re.search(r'\d+', line)
            if "open" in line and port is not None:
                openPorts.append(port.group())
            if "closed" in line and port is not None:
                closedPorts.append(port.group())
            if "unfiltered" in line and port is not None:
                unfilteredPorts.append(port.group())
        if len(openPorts) + len(closedPorts) + len(unfilteredPorts) != 0:
            print(f"{ip} appears up due to the following: Open {openPorts}. Closed {closedPorts}. Unfiltered {unfilteredPorts}")
            count = count + 1
        else:
            if(args.showmisses):
                print(f"Nothing detected for {ip}")
       
    print(f"Total of {count} target machines found up.")

if __name__ == "__main__":
    main()
