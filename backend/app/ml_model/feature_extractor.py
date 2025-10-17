import re
import socket
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime

class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'qty_dot_url', 'qty_hyphen_url', ..., 'url_shortened'  # Your 111 features
        ]
    
    def extract_all(self, url):
        """Extract all 111 features from a URL"""
        features = {}
        parsed = urlparse(url)
        
        # 1. URL Structure Features
        features['length_url'] = len(url)
        features['qty_dot_url'] = url.count('.')
        # ... [all your counting features]
        
        # 2. Domain Features
        domain = parsed.netloc
        features['domain_length'] = len(domain)
        features['qty_vowels_domain'] = self._count_vowels(domain)
        features['domain_in_ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0
        
        # 3. Security Features (requires API calls)
        features['tls_ssl_certificate'] = self._check_ssl(domain)
        features['time_domain_activation'] = self._get_domain_age(domain)
        features['qty_mx_servers'] = self._check_mx_records(domain)
        
        return {k: features.get(k, 0) for k in self.feature_names}

    # Helper methods
    def _check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    return 1
            return 0
        except:
            return 0

    def _get_domain_age(self, domain):
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    created = domain_info.creation_date[0]
                else:
                    created = domain_info.creation_date
                return (datetime.now() - created).days
        except:
            return 365  # Default to 1 year if unknown

    def _check_mx_records(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return len(answers)
        except:
            return 0