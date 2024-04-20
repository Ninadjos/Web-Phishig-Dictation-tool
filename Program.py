#without UI
import requests
from urllib.parse import urlparse
import ssl
import socket
import dns.resolver
import datetime
import re
import whois
import ipaddress
import PySimpleGUI as sg


def get_ssl_certificate(domain_name):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain_name, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                certificate = ssock.getpeercert()
        return certificate
    except socket.gaierror:
        print(f"Error resolving domain name: {domain_name}")
        return None
    except ssl.SSLError:
        print(f"Error connecting to SSL server: {domain_name}")
        return None


def get_domain_name(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc


def check_ssl_certificate(certificate):
    if certificate is None:
        return False
    if 'notAfter' not in certificate:
        return False
    expiration_date = ssl.cert_time_to_seconds(certificate['notAfter'])
    current_date = int(datetime.datetime.now().timestamp())
    return expiration_date > current_date


def check_domain_ip(domain_name):
    try:
        ip_addresses = dns.resolver.resolve(domain_name, 'A')
        return len(ip_addresses) > 1
    except dns.resolver.NoNameservers:
        return False


def is_phishing_url(url):
    domain_name = get_domain_name(url)
    ssl_certificate = get_ssl_certificate(domain_name)
    if not check_ssl_certificate(ssl_certificate):
        return True
    if check_domain_ip(domain_name):
        return True
    return False


def extract_url_features(url):
    features = {}

    # 1. Length of the URL
    features['url_length'] = len(url)

    # 2. Presence of special characters in the URL
    special_characters = re.compile(r'[!@#$%^&*()<>?\\|}{~:]')  # Exclude ':', '/', '/'
    features['has_special_characters'] = bool(re.search(special_characters, url))
    features['special_characters'] = re.findall(special_characters, url)

    # 3. Number of subdomains and their lengths
    subdomains = urlparse(url).hostname.split('.')
    features['num_subdomains'] = len(subdomains) - 1 if subdomains[0] else 0
    features['subdomains'] = subdomains[:-1] if subdomains[0] else []

    # 4. Presence of HTTPS
    features['has_https'] = url.startswith("https://")

    return features


def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        return f"Unable to resolve IP address: {e}"


def is_https(url):
    return url.startswith("https://")


def has_excessive_dots(url):
    domain = urlparse(url).netloc
    dot_count = domain.count('.')
    return dot_count >= 4  # Customize as needed


def has_http_instead_of_https(url):
    return 'http://' in url


def contains_ip_address(url):
    domain = urlparse(url).netloc
    try:
        ip_address = ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def check_phishing_indicators(url):
    indicators = []

    if not is_https(url):
        indicators.append("1. The website does not use HTTPS.")

    if has_excessive_dots(url):
        indicators.append("2. The domain has an excessive number of dots, which may be indicative of phishing.")

    if has_http_instead_of_https(url):
        indicators.append("3. The URL contains 'http://' instead of 'https://', which may pose a security risk.")

    if contains_ip_address(url):
        indicators.append(
            "4. The URL contains an IP address instead of a domain name, which is uncommon for legitimate sites.")

    return indicators


def fetch_html_content(url):
    try:
        if not urlparse(url).scheme:
            url = 'http://' + url

        response = requests.get(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        response.raise_for_status()

        if 'text/html' in response.headers.get('content-type', '').lower():
            return response.text, response.headers
        else:
            print(f"The content is not HTML. Content-Type: {response.headers.get('content-type')}")
            return None, response.headers
    except requests.RequestException as e:
        print(f"Error fetching HTML content: {e}")
        return None, None


def is_secure(url):
    return urlparse(url).scheme == 'https'


def get_ssl_certificate_info(url):
    context = ssl.create_default_context()
    with requests.get(url, context=context, timeout=5) as req:
        cert = req.ssl_cert
        return {
            'issuer': cert.issuer,
            'subject': cert.subject,
            'not_before': cert.not_before,
            'not_after': cert.not_after
        }

def get_whois_info(domain):
    w = whois.Whois(domain)
    return w

def analyze_url(url):
    try:
        # Parse the URL using urlparse
        parsed_url = urlparse(url)

        # Extract components
        protocol = parsed_url.scheme
        domain = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else "N/A"

        # Display the parsed components
        print("\nParsed URL Components:")
        print(f"  Protocol: {protocol}")
        print(f"  Domain: {domain}")
        ip_address = get_ip_address(domain)
        print(f"  IP Address: {ip_address if ip_address != 'Unable to resolve IP address' else 'N/A'}")

        # Extract and display URL features
        url_features = extract_url_features(url)
        print("\nURL Features:")
        for feature, value in url_features.items():
            if feature == 'subdomains':
                print(f"{feature}: {value}")
                for i, subdomain in enumerate(value):
                    print(f"  Subdomain {i + 1}: Length - {len(subdomain)}, Name - {subdomain}")
            elif feature == 'special_characters':
                print(f"{feature}: {value}")
            else:
                print(f"{feature}: {value}")

        # Check for phishing indicators
        phishing_indicators = check_phishing_indicators(url)
        if phishing_indicators:
            print("\nPhishing Indicators Found:")
            for indicator in phishing_indicators:
                print(f"- {indicator}")
            print("\nIt is advisable to exercise caution when accessing this website.")
        else:
            print("\nNo phishing indicators found. The website appears to be secure.")

        # Fetch HTML content and analyze
        html_content, headers = fetch_html_content(url)
        if html_content:
            if is_secure(url):
                print("The website is secure (HTTPS).")
            else:
                print("The website is not served over a secure connection (HTTP).")

            print("\nAdditional Details:")
            print(f"Content Type: {headers.get('content-type', 'N/A')}")
            print(f"Server: {headers.get('server', 'N/A')}")
            print(f"X-Powered-By: {headers.get('x-powered-by', 'N/A')}")
        else:
            print("Unable to fetch HTML content for analysis. This could be a phishing attempt.")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    user_url = input("Enter the URL to analyze: ").strip()
    analyze_url(user_url)
