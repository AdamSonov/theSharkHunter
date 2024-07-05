import requests,socket

class Connection:

    def __init__(self,ip,port):
        self.host = ip   #"8.8.8.8"
        self.port = port #53
        self.timeout = 3

    def check_internet_connection(self):
        """
        Check internet connection by attempting to create a socket connection.
        :param host: Host to connect to. Default is Google's public DNS server (8.8.8.8).
        :param port: Port to connect to. Default is DNS port (53).
        :param timeout: Timeout for the connection attempt (in seconds). Default is 3 seconds.
        return True if connection succeeds, False otherwise.
        """
        try:
            # Create a socket object
            socket.setdefaulttimeout(self.timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Attempt to connect to the host and port
            s.connect((self.host, self.port))
            # If connection succeeds, return True
            s.close()
            return True
        except OSError:
            pass
        return False
