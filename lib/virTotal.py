import requests
 
class VtScan:

    def __init__(self,target,api_key):
        self.target = target
        self.api_key = api_key
    def vtRequest(self):
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        response = requests.get(self.url, headers=self.headers)
        return response.json()

    def scan_domain(self):

        self.url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
        return self.vtRequest()

    def scan_IPs(self):

        self.url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.target}"
        return self.vtRequest()

    def scan_hash(self):

        self.url = f"https://www.virustotal.com/api/v3/files/{self.target}"
        return self.vtRequest()
