#!/bin/python
import re
class IsValidDomain:
    
    def __init__(self,targetList):
        self.targetList = targetList

    def is_valid_domain_syntax(self,domain):
        # Define a regex for a valid domain name
        # The regex is divided into several parts to handle each requirement:
        # - The domain can have multiple parts separated by dots.
        # - Each part (label) can contain letters, numbers, and hyphens but must not start or end with a hyphen.
        # - The last part (TLD) must contain only letters and be at least two characters long.
        regex = re.compile(
            r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.'         # Subdomain(s)
            r'((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*'       # Domain name (optional middle subdomains)
            r'[A-Za-z]{2,63}$'                           # Top-level domain
        )
        
        # Check overall length
        if len(domain) > 253:
            return False
        if  domain == "localhost":
            return True
        # Match the domain against the regex
        return bool(regex.match(domain))
    
    
    def fillterValidDomain(self):
        validTarget = []
        for target in self.targetList:
            if self.is_valid_domain_syntax(target):
                validTarget.append(target)
        return validTarget