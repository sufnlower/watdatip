#!/usr/bin/python3
import argparse
import subprocess
import re
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

# Function to get the server certificate
def get_server_certificate(ip, port):
    cert_pem = ssl.get_server_certificate((ip, port))
    return cert_pem

# Function to extract the CN from the certificate
def extract_cn_from_cert(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
    subject = cert.subject
    cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return cn

def extract_sans_from_cert(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None
    return sans

def sslcheck(ip,v):
    results = []
    cert = get_server_certificate(ip,443)
    results.append(extract_cn_from_cert(cert))
    results.extend(extract_sans_from_cert(cert))
    return results

# def sslsubjectcheck(ip,v):
#     hostname = None
#     command = f"/usr/bin/curl --insecure -vvI https://{ip} --max-time 2 2>&1 | /usr/bin/awk 'BEGIN {{ cert=0 }} /^\* SSL connection/ {{ cert=1 }} /^\*/ {{ if (cert) print }}'"
#     if v:
#         print(command)
#     result = subprocess.run(command,capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
#     if v:
#         print(result.stdout)
#     cn_pattern =  r"CN=([^;\n]+)"
#     match = re.search(cn_pattern, result.stdout)    
#     if match:
#         hostname = match.group(1)
#     return hostname
    
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


def checkIPs(ips, verbose=False):
    results = []
    wildcards = []
    ns_results = []
    for ip in ips:
        print("doing ssl subject check")
        try:
            hostnames = sslcheck(ip, verbose)
        except:
            continue
        for hostname in hostnames:        
            print(f"{hostname} {ip}")
            if hostname != None:
                if "*" in hostname:
                    wildcards.append(f"{ip} {hostname}")
                else:
                    ns = nslookupcheck(ip,hostname,verbose)
                    if ns != None:
                        print(f"Match found: {hostname} {ip}")
                        ns_results.append(ns)
                        results.append(hostname)
                        continue
            print("doing redirect check")
            hostname = redirectcheck(ip, verbose)
            print(f"{hostname} {ip}")
            if hostname != None:
                ns = nslookupcheck(ip,hostname, verbose)
                if ns != None:
                    print(f"Match found: {hostname} {ip}")
                    ns_results.append(ns)
                    results.append(hostname)
                    continue
    
        print("===========")
    print("All Matches")
    print("===========")
    if ns_results != None:
        for result in ns_results:
            print(result)    
    print("===========")
    print("All Wildcards")
    print("===========")
    if wildcards != None:
        for wildcard in wildcards:
            print(wildcard) 
    
    return ns_results, results, wildcards

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--ip', help="Check one IP")
    parser.add_argument('-f','--file', help="Input file, one line at a time")
    parser.add_argument('-v','--verbose', action="store_true", help="Show commands and responses.")
    args = parser.parse_args()

    ips = []

    if args.ip != None:
        ips.append(args.ip)
    elif args.file != None:
        with open(args.file, 'r') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
        ips = lines
    
    checkIPsResult = checkIPs(ips,args.verbose)
    ns_results, results, wildcards = (checkIPsResult if checkIPsResult is not None else ([], [], []))
    




if __name__ == "__main__":
    main()
