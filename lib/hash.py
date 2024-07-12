import hashlib

class Hasher:
    def __init__(self,alg):
        self.algorithm = alg 
    
    def calculate_file_hash(self,data):

        try:
            hasher = hashlib.new(self.algorithm)
        except ValueError:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        hasher.update(data)
        return hasher.hexdigest()