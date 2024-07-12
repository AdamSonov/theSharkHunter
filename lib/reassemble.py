from scapy.all import *
import os
from termcolor import colored
from hash import *
class HttpPcap:
    def __init__(self,file):
        self.tcp_streams = {}
        self.file = file
        self.packets = rdpcap(file)
        self.output_dir = 'output'
        self.count = 0
        self.md5Hasher = Hasher("md5")
        self.ret_list = []
    
           
    def add_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            seq = packet[TCP].seq
            payload = packet[Raw].load
            if sport not in {80, 81, 82, 83, 8080, 8081, 8082, 8880, 7000, 8090, 8181} and dport not in {80, 81, 82, 83, 8080, 8081, 8082, 8880, 7000, 8090, 8181}:
                return

            stream_id = (ip_src, ip_dst, sport, dport)

            if stream_id not in self.tcp_streams:
                self.tcp_streams[stream_id] = {}
            self.tcp_streams[stream_id][seq] = payload

    def reassemble_streams(self):
        reassembled_streams = {}
        for stream_id, segments in self.tcp_streams.items():
            sorted_segments = sorted(segments.items())
            reassembled_payload = b''.join(payload for _, payload in sorted_segments)
            reassembled_streams[stream_id] = reassembled_payload
        return reassembled_streams
    

    def extractData2File(self,body,output_dir = "output"):
        filename = os.path.join(output_dir, f"{self.file}_HTTPstream_{self.count}.bin")
        if body:
            with open(filename, "wb") as f:
                f.write(body)
        print(colored(f" [SAVE] Extracted payload saved to {filename}","light_green"))
        self.count += 1
    
    def execute(self,option):
        
        if option == "read":
            for packet in self.packets:
                self.add_packet(packet)
                
            reassembled_streams = self.reassemble_streams()
            for stream_id, data in reassembled_streams.items():
                print(f"Stream {stream_id} has {len(data)} bytes")
                try:
                    data_str = data.decode('utf-8', errors='replace')
                    header_end = data_str.find('\r\n\r\n')
                    if header_end != -1:
                        body = data[header_end + 4:]
                        print(body.decode('utf-8', errors='replace'))

                except UnicodeDecodeError as e:
                    print("No HTTP headers found.")
        
        elif(option == "hash"):
        
            for packet in self.packets:
                self.add_packet(packet)
                
            reassembled_streams = self.reassemble_streams()
            for stream_id, data in reassembled_streams.items():

                try:
                    data_str = data.decode('utf-8', errors='replace')
                    header_end = data_str.find('\r\n\r\n')
                    if header_end != -1:
                        body = data[header_end + 4:]
                        if(body):
                            
                            self.ret_list.append(self.md5Hasher.calculate_file_hash(body))                

                except UnicodeDecodeError as e:
                    print("No HTTP headers found.")
            return self.ret_list        
                    
        elif(option == "extract"):
            for packet in self.packets:
                self.add_packet(packet)
                
            reassembled_streams = self.reassemble_streams()

            for stream_id, data in reassembled_streams.items():
                print(f"Stream {stream_id} has {len(data)} bytes")

                try:
                    data_str = data.decode('utf-8', errors='replace')
                    header_end = data_str.find('\r\n\r\n')
                    if header_end != -1:
                        body = data[header_end + 4:]
                        if body:
                            self.extractData2File(body)

                except UnicodeDecodeError as e:
                    print("No HTTP headers found.")
            
    
    def extFilebyHash(self,hash):
        for packet in self.packets:
            self.add_packet(packet)
                
        reassembled_streams = self.reassemble_streams()
        for stream_id, data in reassembled_streams.items():

            try:
                data_str = data.decode('utf-8', errors='replace')
                header_end = data_str.find('\r\n\r\n')
                if header_end != -1:
                    body = data[header_end + 4:]
                    if(body):
                        contentHash = self.md5Hasher.calculate_file_hash(body)
                        if contentHash == hash:
                            self.extractData2File(body,"output/suspeciousFile/http")
            except UnicodeDecodeError as e:
                return False
        return False