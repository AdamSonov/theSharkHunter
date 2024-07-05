from scapy.all import *
import re
#Extract Data From Packets
class ExtractDFP:

    def __init__(self,pcap_file):
        self.file = pcap_file
        
        
    def extract_ips_from_pcap(self):
        """
        Extract IP addresses from a pcap file,
        and return a List of unique IP addresses found in the pcap file.
        """
        ips = set()
        packets = rdpcap(self.file)
        for packet in packets:
            if IP in packet:
                ips.add(packet[IP].src)
                ips.add(packet[IP].dst)
        return list(ips)


    def extract_domains_from_pcap(self):
        """
        Extract domains from a pcap file,
        and return a List of unique domain names found in the pcap file.
        """
        domains = set()
        packets = rdpcap(self.file)
        for packet in packets:
            if DNSRR in packet:
                for rr in packet[DNSRR]:
                    domain = rr.rrname.decode('utf-8')
                    # Extract domain name from DNS response
                    domain = re.sub(r'\.$', '', domain)  # Remove trailing dot if present
                    domains.add(domain)
        return list(domains)

    def extract_hostnames_from_pcap(self):
        """
        Extract hostnames from a pcap file.
        and return a List of unique hostnames found in the pcap file.
        """
        hostnames = set()
        packets = rdpcap(self.file)
        for packet in packets:
            if DNSQR in packet:
                query = packet[DNSQR].qname.decode('utf-8')
                # Add the hostname to the set
                hostnames.add(query[:-1])
        return list(hostnames)