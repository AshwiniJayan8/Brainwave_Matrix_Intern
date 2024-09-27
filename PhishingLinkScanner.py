import requests
from urllib.parse import urlparse
import tldextract

def is_phishing(url):
    try:
        parsed_url = urlparse(url)
        domain_parts = tldextract.extract(url)
        domain = domain_parts.domain + '.' + domain_parts.suffix
        suspicious_keywords = ['secure', 'login', 'account', 'verify', 'bank', 'paypal', 'signin']
        for keyword in suspicious_keywords:
            if keyword in parsed_url.path.lower() or keyword in parsed_url.query.lower():
                return True
        
        if is_blacklisted(domain):
            return True
        
        response = requests.head(url, allow_redirects=True)
        if response.status_code == 200 and \
        domain != tldextract.extract(response.url).domain + '.' + tldextract.extract(response.url).suffix:
            return True
        return False
    
    except Exception as e:
        print(f"Error occurred: {e}")
        return False


def is_blacklisted(domain):
    blacklisted_domains = ['example.com', 'maliciousdomain.com']
    return domain in blacklisted_domains
    
urls_to_scan = [
    'http://example.com',
    'https://www.google.com',
    'http://securelogin.com/login.php',
    'https://notphishing.com',
    'http://maliciousdomain.com'
]

for url in urls_to_scan:
    if is_phishing(url):
        print(f"Phishing was detected in the: {url}")
    else:
        print(f"URL is safe: {url}")
