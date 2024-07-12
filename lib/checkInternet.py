import requests,socket

class Connection:

    def __init__(self,ip,port):
        self.host = ip 
        self.port = port
        self.timeout = 3

    def check_internet_connection(self):
        try:
            socket.setdefaulttimeout(self.timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            s.close()
            return True
        except OSError:
            pass
        return False
