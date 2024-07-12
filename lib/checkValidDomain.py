#!/bin/python
import re
class IsValidDomain:
    
    def __init__(self,targetList):
        self.targetList = targetList

    def is_valid_domain_syntax(self,domain):
        regex = re.compile(
            r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.'         # Subdomain(s)
            r'((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*'       # Domain name (optional middle subdomains)
            r'[A-Za-z]{2,63}$'                           # Top-level domain
        )
        

        if len(domain) > 253:
            return False
        if  domain == "localhost":
            return True

        return bool(regex.match(domain))
    
    
    def fillterValidDomain(self):
        validTarget = []
        for target in self.targetList:
            if self.is_valid_domain_syntax(target):
                validTarget.append(target)
        return validTarget