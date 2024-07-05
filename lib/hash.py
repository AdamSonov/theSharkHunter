import hashlib

class Hasher:
    def __init__(self,alg):
        self.algorithm = alg 
    
    def calculate_file_hash(self,data):

        try:
            # Initialize the hasher
            hasher = hashlib.new(self.algorithm)
        except ValueError:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        # Update the hasher with the text
        hasher.update(data)
        
        # Return the hexadecimal digest of the hash
        return hasher.hexdigest()