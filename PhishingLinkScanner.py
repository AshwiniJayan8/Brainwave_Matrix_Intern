import re
import tldextract
import requests

# Common phishing-related keywords in URLs
PHISHING_KEYWORDS = ['login', 'secure', 'account', 'update', 'free', 'bank', 'verify', 'password', 'signin']

# Suspicious TLDs often used by attackers
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.club', '.top']

# Regular expression for detecting IP-based URLs
IP_URL_PATTERN = re.compile(r'^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/\S*)?$')

# Function to extract domain and check against phishing rules
def check_url_safety(url):
    try:
        # Check if URL matches IP-based pattern
        if re.match(IP_URL_PATTERN, url):
            return "Phishing (IP-based URL detected)"

        # Extract domain parts
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        subdomain = domain_info.subdomain

        # Check for suspicious TLDs
        if f".{domain_info.suffix}" in SUSPICIOUS_TLDS:
            return "Phishing (Suspicious TLD detected)"

        # Check for phishing-related keywords in the domain or subdomain
        for keyword in PHISHING_KEYWORDS:
            if keyword in domain.lower() or keyword in subdomain.lower():
                return f"Phishing (Keyword '{keyword}' detected in URL)"

        # Perform an HTTP request to check the response
        response = requests.get(url)
        if response.status_code == 200:
            return "Safe (URL returned a valid response)"
        else:
            return "Phishing (Non-200 response code)"

    except Exception as e:
        return f"Error processing URL: {e}"

# Main function to get user input and check URLs
def main():
    while True:
        url = input("Enter the URL to check if it's safe: ")
        print("Checking the URL...")
        result = check_url_safety(url)
        print(f"Result: {result}")

        # Ask the user if they want to check another URL
        check_more = input("Do you want to check another URL? (yes/no): ").strip().lower()
        if check_more != 'yes':
            print("Exiting the program.")
            break

if __name__ == "__main__":
    main()
