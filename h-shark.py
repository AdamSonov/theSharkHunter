#!/bin/python
import io
import os
import sys
import argparse
import json
from colorama import init
from termcolor import colored
from terminaltables import AsciiTable
from scapy.all import sr1, IP, ICMP
import time
import ipaddress
import subprocess
from rich.console import Console
from rich.table import Table
from rich.console import Console
from rich.syntax import Syntax
from tabulate import tabulate
import main

##############################
#theSharkHunter libraries
from checkInternet import *
from extractDFP import *
from virTotal import *
from unixTime import *
from config import *
from reassemble import *
from checkValidDomain import *
######################"########

import platform

init()
banner = """
            ░▀█▀░█░█░█▀▀░░░█▀▀░█░█░█▀█░█▀▄░█░█░░░█░█░█░█░█▀█░▀█▀░█▀▀░█▀▄
            ░░█░░█▀█░█▀▀░░░▀▀█░█▀█░█▀█░█▀▄░█▀▄░░░█▀█░█░█░█░█░░█░░█▀▀░█▀▄
            ░░▀░░▀░▀░▀▀▀░░░▀▀▀░▀░▀░▀░▀░▀░▀░▀░▀░░░▀░▀░▀▀▀░▀░▀░░▀░░▀▀▀░▀░▀

                       By @Rafik_Hadjal (The Shark Hunter v1.0)
                                 join me in Telegram
                                 t.me/Raf0x90
"""


def get_os_type():
    if sys.platform.startswith('win'):
        return "Windows"
    elif sys.platform.startswith('darwin'):
        return "macOS"
    elif sys.platform.startswith('linux'):
        return "Linux"
    else:
        return "Unknown"


if platform.system() == "Windows":
    os.system("color 02")


print(colored(banner,"white"))

parser = argparse.ArgumentParser(
    prog="h-shark",
    description = "Automation Tool to Find Suspecious and Malicious Network Traffic from (cap ,pcap ,pcapng,...etc) Files",
    epilog = "hunt malware Traffic")
    
parser.add_argument('-r' ,'--read')#*
parser.add_argument('--extract-ips',action='store_true')#*
parser.add_argument('--extract-dns',action='store_true')#*
parser.add_argument('-s','--scan',action='store_true')

args = parser.parse_args()

conn_status = Connection("8.8.8.8",53)
conn_status = conn_status.check_internet_connection()


if(conn_status):
    print(colored("\n\n\n [Connection-status] ","white")+colored("ON\n\n","green"))
else:
    print(colored("\n\n\n [Connection-status] ","white")+colored("OFF\n\n","red"))


if not args.read:
    parser.print_help()
    parser.exit(1)
else:
   extractor = ExtractDFP(args.read)


def print_pretty_json(json_data):
   
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data
    formatted_json = json.dumps(data, indent=2)

    console = Console()


    json_syntax = Syntax(formatted_json, "json", theme="monokai", line_numbers=False)
    console.print(json_syntax)


    
def print_indented_table(data, indent=4):
    table = AsciiTable(data)
    table_string = '\n'.join((' ' * indent + line) for line in table.table.split('\n'))
    print(colored("\n"+table_string,"white"))   
    
def extIP(extractor,output = False):

    filename2storeIPS = output
    list_IPs = extractor.extract_ips_from_pcap()
    print(colored(" [Running]","white")+colored(" Extracting IPs From "+args.read+" ...","light_grey"))
    print(" ","*"*60)
    if output: f = open("output/IPS/"+filename2storeIPS,"w")
    for ip in list_IPs:
        if output: f.write(ip+"\n")
        print(colored("   [+] ","light_green")+colored(ip,"light_cyan"))
    if output: f.close()
    return list_IPs
    
def extDNS(extractor,output = False):

    filename2storeDNS = output
    list_DNS = extractor.extract_hostnames_from_pcap()
    print(colored(" [Running]","white")+colored(" Extracting HOSTNAMES/DNS From "+args.read+" ...","light_grey"))
    print(" ","*"*60)
    if output: f = open("output/DNS/"+filename2storeDNS,"w")
    for dns in list_DNS:
        if output: f.write(dns+"\n")
        print(colored("   [+] ","light_green")+colored(dns,"light_cyan"))
    if output: f.close()
    return list_DNS


def run_IPS_VirusTotal_Scan(target,api_Key):
    virusTotal = VtScan(target,api_Key)
    result = virusTotal.scan_IPs()
    return result

def run_DNS_VirusTotal_Scan(target,api_Key):
    virusTotal = VtScan(target,api_Key)
    result = virusTotal.scan_domain()
    return result
def run_Hash_VirusTotal_Scan(target,api_Key):
    virusTotal = VtScan(target,api_Key)
    result = virusTotal.scan_hash()
    return result
    
def Is_Target_Live(target):
    system = platform.system()    
    if system == "Windows":
        command = ['ping', '-n', '1', target]
    else:  
        command = ['ping', '-c', '1', target]
    
    try:
        stderr_option = subprocess.PIPE if platform.system() == 'Windows' else subprocess.DEVNULL
        command_reponse = subprocess.check_output(command, stderr=stderr_option)
        return True
    except subprocess.CalledProcessError:
        return False



def is_ip_live(ip, timeout=1):
    try:
        packet = IP(dst=ip)/ICMP()
        start_time = time.time()
        response = sr1(packet, timeout=timeout, verbose=0)
        end_time = time.time()

        if response:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred while pinging {ip}: {e}")
        return False

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False




def retData(targets,type,virusTotal_api_Key):
    result_vt_table = []
    suspecious_hash = False
    list_suspecious_Hash = []
    print(colored(" [Running]","white")+colored(" "+type+" Scan Is Running Please Wait ...\n","light_grey"))
    try:
        for target in targets:
            data_to_table = []
            if(type ==  "DNS"):
                try:
                    result_dns = run_DNS_VirusTotal_Scan(target,virusTotal_api_Key)
                    result = result_dns
                except:
                    print(colored(" [-] Failed to scan this Target "+target,"red"))
                    print(colored("     [!] Please Make sure That your Connection is ON !!!","red"))
                    
            elif(type == "IPs"):
                try:
                    result_ips = run_IPS_VirusTotal_Scan(target,virusTotal_api_Key)
                    result = result_ips
                except:
                    print(colored("[-] Failed to scan this Target "+target,"red"))
                    print(colored("     [!] Please Make sure That your Connection is ON !!!","red"))
            elif(type =="HASH"):
                result_hash = run_Hash_VirusTotal_Scan(target,virusTotal_api_Key)
                result = result_hash
                
            if("data" in result.keys()):
                utime = UnixTime(result["data"]["attributes"]["last_analysis_date"])
                utime2date = utime.retDate()
                if(int(result["data"]["attributes"]["last_analysis_stats"]["malicious"]) > 0):
                    if type == "HASH":
                        suspecious_hash = True
                        list_suspecious_Hash.append(target)
                    print(colored(" [WARNING] "+target,"light_red"))
                    print(colored("   [LINK] https://www.virustotal.com/gui/domain/"+target,"light_yellow"))
                    print(colored("   [*] (Suspecious "+type+") ,Threats Found : "+str(result["data"]["attributes"]["last_analysis_stats"]["malicious"]),"red"))
                    print(colored("   [*] Total Votes : {harmless : "+str(result["data"]["attributes"]["total_votes"]["harmless"])+"} , {malicious : "+str(result["data"]["attributes"]["total_votes"]["malicious"])+"}","light_yellow"))
                    if("crowdsourced_context" in result["data"]["attributes"].keys()):
                       print(colored("   [*] Crowd Sourced Context :\n","light_yellow"))
                       print_pretty_json(result["data"]["attributes"]["crowdsourced_context"])
                       print("\n")
                    print(colored("   [*] Last Analysis Date : "+str(utime2date),"light_grey"))

                else:
                    print(colored(" [SAFE] ","light_green")+colored(target,"light_cyan"))


            
            if("data" in result.keys() and type == "IPs"):
                utime = UnixTime(result["data"]["attributes"]["last_analysis_date"])
                utime2date = utime.retDate()
                data_to_table.append(target)
                data_to_table.append(result["data"]["attributes"]["last_analysis_stats"]["malicious"])
                data_to_table.append(result["data"]["attributes"].get("country","none"))
                data_to_table.append(str(result["data"]["attributes"].get("asn","none")))
                data_to_table.append(result["data"]["attributes"].get("as_owner","none"))
                data_to_table.append(result["data"]["attributes"].get("network","none"))
                data_to_table.append(str(utime2date))
                result_vt_table.append(data_to_table)
                #
                table = Table(title="IPs Scan Result",style="cyan")
                table.add_column("IP_address", justify="right", style="cyan", no_wrap=True)
                table.add_column("Threat", justify="right", style="magenta", no_wrap=True)
                table.add_column("country", justify="right", style="green")
                table.add_column("asn", justify="right", style="green")
                table.add_column("asn_owner", justify="right", style="green")
                table.add_column("network", justify="right", style="green")
                table.add_column("last_analysis_date", style="white")
                
        if(type =="HASH" and suspecious_hash):
            return suspecious_hash, list_suspecious_Hash
        
        if(type == "IPs"):   
            for row in result_vt_table: 
                table.add_row(str(row[0]), str(row[1]), row[2],str(row[3]),row[4],row[5],row[6])
            console = Console()
            console.print(table)
    except:
        print(colored(" [WARNING] ","yellow"),colored("Please Make sure that you're putting the Correct VirusTotal Api_key in conf.py!","light_yellow"))
        exit()

    
def sharkHunter():
    
    if args.extract_dns or args.scan:
        listDNS = extDNS(extractor,args.output)
        if args.scan:
            isValidDomain_Instance = IsValidDomain(listDNS)
            TargetsIsValid = isValidDomain_Instance.fillterValidDomain()
            
            dns_table_data = [['Valid DNS/Hostname', 'Live']]
            for TargetIsValid in TargetsIsValid:
                dnsTargetToTable = []
                dnsTargetToTable.append(TargetIsValid)
                
                if Is_Target_Live(TargetIsValid):
                   dnsTargetToTable.append("YES")
                else:
                    dnsTargetToTable.append("NO")
                dns_table_data.append(dnsTargetToTable)


            print_indented_table(dns_table_data, indent=3)
   
   
    if args.extract_ips or args.scan:
        listIPs = extIP(extractor,args.output)
        if args.scan:
            ip_table_data = [['IP_Address', 'Type', 'Live']]
            for ip in listIPs:
                ipTargetToTable = []
                ipTargetToTable.append(ip)
                if is_private_ip(ip):
                    ipTargetToTable.append("Private")
                else:
                    ipTargetToTable.append("Public")
                if is_ip_live(ip):
                   ipTargetToTable.append("YES")
                else:
                    ipTargetToTable.append("NO")
                ip_table_data.append(ipTargetToTable)


            print_indented_table(ip_table_data, indent=3)



    if args.scan:

        print("\n","#","-"*60)
        retData(listDNS,"DNS",virusTotal_api_Key)


        print("\n","#","-"*60)
        listPublicIP = []
        for ip in listIPs:
            if not is_private_ip(ip):
                listPublicIP.append(ip)
        retData(listPublicIP,"IPs",virusTotal_api_Key)
       
        
        instance = HttpPcap(args.read)
        hashes = instance.execute("hash")
        print("\n","#","-"*60)
        if hashes:
            print(colored(" [Running]","white")+colored(" Extracting Hashes From "+args.read+"HTTP Objects Please Wait ...\n","light_grey"))
            print(colored(json.dumps(hashes, indent=4),"cyan"))
            
        
            print("\n","#","-"*60)
            suspecious_hash, list_suspecious_Hash = retData(hashes,"HASH",virusTotal_api_Key)

            if suspecious_hash:
                answer = input("Do you want to Extract the Suspecious HTTP Objects Files?(yes/no): ")
                if answer.lower() =="yes" or answer.lower() == "y":
                    for suspecious in list_suspecious_Hash:
                        instance.extFilebyHash(suspecious)
        else:
            print(" [-] No Hash File Found From HTTP Object")

            


if __name__ == "__main__":
    try:
        while True:
            sharkHunter()
            exit()
    except KeyboardInterrupt:
        print("Script Is Stoped")
        



