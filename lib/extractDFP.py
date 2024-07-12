from scapy.all import *
import re
#Extract Data From Packets
class ExtractDFP:

    def __init__(self,pcap_file):
        self.file = pcap_file
        
        
    def extract_ips_from_pcap(self):
        ips = set()
        packets = rdpcap(self.file)
        for packet in packets:
            if IP in packet:
                ips.add(packet[IP].src)
                ips.add(packet[IP].dst)
        return list(ips)


    def extract_domains_from_pcap(self):
        domains = set()
        packets = rdpcap(self.file)
        for packet in packets:
            if DNSRR in packet:
                for rr in packet[DNSRR]:
                    domain = rr.rrname.decode('utf-8')
                    domain = re.sub(r'\.$', '', domain)
                    domains.add(domain)
        return list(domains)

    def extract_hostnames_from_pcap(self):
        hostnames = set()
        packets = rdpcap(self.file)
        for packet in packets:
            if DNSQR in packet:
                query = packet[DNSQR].qname.decode('utf-8')
                hostnames.add(query[:-1])
        return list(hostnames)