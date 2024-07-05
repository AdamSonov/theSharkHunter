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
        """
        Scan a target using the VirusTotal v3 API.
        :param : Domain to scan.
        :param api_key: Your VirusTotal API key.
        :return: JSON response from the VirusTotal API.
        """

        self.url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
        return self.vtRequest()

    def scan_IPs(self):
        """
        Scan a target using the VirusTotal v3 API.
        :param : Domain to scan.
        :param api_key: Your VirusTotal API key.
        :return: JSON response from the VirusTotal API.
        """
        self.url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.target}"
        return self.vtRequest()

    def scan_hash(self):
        """
        Scan a target using the VirusTotal v3 API.
        :param : Hash to scan.
        :param api_key: Your VirusTotal API key.
        :return: JSON response from the VirusTotal API.
        """
        self.url = f"https://www.virustotal.com/api/v3/files/{self.target}"
        return self.vtRequest()
