from urllib.parse import urlparse, parse_qs
import requests
import whois
import time
import tldextract
from ipwhois import IPWhois
import joblib
from datetime import datetime
import socket
import numpy as np
import dns.resolver
import ipwhois
from ipwhois import IPWhois
import certifi
import ssl
import xgboost as xgb
import pickle

def get_number_of_mx_servers(domain_name):
    try:
        mx_records = dns.resolver.resolve(domain_name, 'MX')
        return len(mx_records)
    except dns.resolver.NoAnswer:
        return 0
    except Exception as e:
        return 0
    except dns.resolver.Timeout:
        return 0

def get_asn(url):
    try:
        # Parse the domain from the URL
        domain = urlparse(url).hostname

        # Resolve the domain to its IP address
        ip_address = socket.gethostbyname(domain)

        # Query the WHOIS database for the IP address
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()

        # Extract the ASN from the results
        asn = results['asn']

        return asn
    except Exception as e:
        
        return -1
    
def calculate_time_activation(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is not None:
            today = datetime.now()
            activation_days = (today - creation_date).days
            return activation_days
    except Exception as e:
        print(f"Error fetching WHOIS information: {e}")
    
    return -1

def calculate_response_time(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return end_time - start_time

def extract_qty_dot_params(query_params):
  
    qty_dot_params = 0
    for params_list in query_params.values():
        for param in params_list:
            qty_dot_params += param.count('.')
    
    return qty_dot_params

def count_ip_resolved(parsed_url):
    try:
        ip_addresses = socket.getaddrinfo(parsed_url.netloc, None)
        qty_ip_resolved = len(set(addr[4][0] for addr in ip_addresses))
    except Exception as e:
        qty_ip_resolved = 0 
    return  qty_ip_resolved

def get_ttl(url):
    try:
        # Parse the URL to extract the domain name
        domain = urlparse(url).netloc

        # Perform a DNS lookup for the domain
        answer = dns.resolver.resolve(domain, 'A')

        # Get the TTL from the DNS answer
        ttl = answer.rrset.ttl

        return ttl
    except Exception as e:
        return -1
    
def extract_spf(url):
    try:
        # Parse the URL to extract the domain name
        domain = urlparse(url).netloc

        # Perform a DNS lookup for the SPF record (type TXT) for the domain
        answer = dns.resolver.resolve(domain, 'TXT')

        # Extract the SPF record from the DNS response
        spf_record = None
        for rdata in answer:
            if 'v=spf1' in rdata.strings[0].decode():
                spf_record = rdata.strings[0].decode()
                break

        return 0
    except Exception as e:
        return -1  

def count_nameservers(url):
    try:
        # Parse the URL to extract the domain name
        domain = urlparse(url).hostname

        # Perform a DNS lookup for the domain's NS records
        ns_records = dns.resolver.resolve(domain, 'NS')

        # Count the number of NS records
        qty_nameservers = len(ns_records)

        return qty_nameservers
    except Exception as e:
        return -1 # No NS records found  
    
def extract_certificate(url):
    try:
        # Parse the URL to extract the domain name
        domain = urlparse(url).hostname

        # Create an SSL context and load the system's certificate store
        context = ssl.create_default_context(cafile=certifi.where())

        # Connect to the domain using SSL/TLS and get the certificate
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        return 1
    except Exception as e:
        print(f"Error extracting certificate: {e}")
        return None

def count_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True)
        return len(response.history)
    except Exception as e:
        print(f"Error fetching URL: {e}")
        return -1

def extract_featuresS(url):
    # Parse the URL
    dom = urlparse(url).hostname
    parsed_url = urlparse(url)
    print("Port: ",parsed_url.port)
    print("netloc: ",parsed_url.netloc)
    print("Path: ",parsed_url.path)
    print("Query: ", parsed_url.query)
    print("Hostname: ", parsed_url.hostname)
    # Extract domain components using tldextract
    domain_extract = tldextract.extract(url)

    # Initialize features dictionary
    features = {}

    # Feature 1: Directory Length
    features['directory_length'] = len(parsed_url.path)

    # Feature 2: Quantity of slashes in the URL
    features['qty_slash_url'] = parsed_url.path.count('/')

    # Feature 3: Quantity of plus symbols in parameters
    features['qty_plus_params'] = url.count('+')

    # Feature 4: Quantity of dots in the domain
    features['qty_dot_domain'] = parsed_url.netloc.count('.')

    # Feature 5: Time domain activation (not extracted from URL, fill with a default value)
    features['time_domain_activation'] = calculate_time_activation(parsed_url.netloc)

    # Feature 6: Quantity of dots in parameters
    params = parse_qs(parsed_url.query)
    qty_dot_params = sum(param.count('.') for param in params)
    features['qty_dot_params'] = qty_dot_params

    # Feature 7: Quantity of hyphens in the directory
    features['qty_hyphen_directory'] = parsed_url.path.count('-')

    # Feature 8: Domain in IP format (not extracted from URL, fill with a default value)
    features['domain_in_ip'] = 1 if parsed_url.netloc.replace('.', '').isdigit() else 0

    # Feature 9: URL shortened (not extracted from URL, fill with a default value)
    features['url_shortened'] =  1 if len(parsed_url.netloc) < 15 else 0

    # Feature 10: Quantity of TLDs in the URL
    features['qty_tld_url'] = len(domain_extract.suffix)

    # Feature 11: Quantity of percent symbols in the file
    features['qty_percent_file'] = parsed_url.path.count('%')

    # Feature 12: Quantity of equal symbols in the URL
    features['qty_equal_url'] = url.count('=')

    # Feature 13: Quantity of underline symbols in parameters
    features['qty_underline_params'] = url.count('_')

    # Feature 14: Quantity of underline symbols in the file
    features['qty_underline_file'] = parsed_url.path.count('_')

    # Feature 15: Length of the URL
    features['length_url'] = len(url)

    # Feature 16: Quantity of @ symbols in the URL
    features['qty_at_url'] = url.count('@')

    # Feature 17: Quantity of plus symbols in the URL
    features['qty_plus_url'] = url.count('+')

    # Feature 18: Quantity of resolved IPs in the URL (not extracted from URL, fill with a default value)
    features['qty_ip_resolved'] = count_ip_resolved(parsed_url)

    # Feature 19: Quantity of comma symbols in the directory
    features['qty_comma_directory'] = parsed_url.path.count(',')

    # Feature 20: Quantity of name servers (not extracted from URL, fill with a default value)
    features['qty_nameservers'] = count_nameservers(url)

    # Feature 21: Quantity of dots in the URL
    features['qty_dot_url'] = url.count('.')

    # Feature 22: Quantity of equal symbols in the directory
    features['qty_equal_directory'] = parsed_url.path.count('=')

    # Feature 23: Quantity of hyphens in the domain
    features['qty_hyphen_domain'] = domain_extract.domain.count('-')

    # Feature 24: ASN IP (not extracted from URL, fill with a default value)
    features['asn_ip'] = get_asn(url)

    # Feature 25: TLS/SSL certificate (not extracted from URL, fill with a default value)
    features['tls_ssl_certificate'] = extract_certificate(url)

    # Feature 26: Quantity of hyphens in the URL
    features['qty_hyphen_url'] = url.count('-')

    # Feature 27: Quantity of comma symbols in the file
    features['qty_comma_file'] = parsed_url.path.count(',')

    # Feature 28: TTL hostname (not extracted from URL, fill with a default value)
    features['ttl_hostname'] = get_ttl(url)

    # Feature 29: Length of parameters
    params_length = sum(len(param) for param in params)
    features['params_length'] = params_length

    # Feature 30: Domain SPF (not extracted from URL, fill with a default value)
    features['domain_spf'] = extract_spf(url)

    # Feature 31: Quantity of MX servers (not extracted from URL, fill with a default value)
    features['qty_mx_servers'] = get_number_of_mx_servers(dom)

    # Feature 32: Quantity of parameters
    features['qty_params'] = len(params)

    # Feature 33: Quantity of "&"
    features['qty_and_params'] = url.count('&')
    
    # Feature 1: qty_redirects (not possible to extract from URL directly)
    # You may need to use a library or technique to follow redirects and count them
    features['qty_redirects']= count_redirects(url)
    
    # Feature 2: time_response (not possible to extract from URL directly)
    # You can use the requests library to get the response time
    try:
        response = requests.head(url)
        features['time_response'] = response.elapsed.total_seconds()
    except requests.exceptions.RequestException:
        features['time_response'] = -1
    
    # Feature 3: qty_underline_url
    features['qty_underline_url'] = url.count('_')
    
    # Feature 4: qty_slash_directory
    features['qty_slash_directory'] = parsed_url.path.count('/')
    
    # Feature 5: qty_percent_directory
    features['qty_percent_directory'] = parsed_url.path.count('%')
    
    # Feature 6: file_length
    features['file_length'] = len(parsed_url.path.split('/')[-1])
    
    # Feature 7: qty_comma_url
    features['qty_comma_url'] = url.count(',')
    
    # Feature 8: qty_hyphen_file
    features['qty_hyphen_file'] = parsed_url.path.count('-')
    
    # Feature 9: qty_percent_url
    features['qty_percent_url'] = url.count('%')
    
    # Feature 10: time_domain_expiration (not possible to extract from URL directly)
    # You may need to use a WHOIS lookup to get domain expiration information
    try:
        domain = tldextract.extract(parsed_url.netloc)
        whois_info = whois.whois(domain.registered_domain)
        features['time_domain_expiration'] = (whois_info.expiration_date - whois_info.creation_date).days if whois_info.expiration_date is not None else None
    except Exception:
        features['time_domain_expiration'] = -1
    
    # Feature 11: qty_dot_directory
    features['qty_dot_directory'] = parsed_url.path.count('.')
    
    # Feature 12: qty_tilde_url
    features['qty_tilde_url'] = url.count('~')
    
    # Feature 13: domain_length
    features['domain_length'] = len(parsed_url.netloc)
    
    # Feature 14: qty_underline_directory
    features['qty_underline_directory'] = parsed_url.path.count('_')
    
    # Feature 15: qty_vowels_domain
    vowels = 'aeiouAEIOU'
    features['qty_vowels_domain'] = sum(parsed_url.netloc.count(vowel) for vowel in vowels)
    
    # Feature 16: qty_dot_file
    features['qty_dot_file'] = parsed_url.path.count('.')
    
    # Feature 17: qty_equal_params
    features['qty_equal_params'] = url.count('=')
    
    return features

# vals = extract_featuresS('https://eugq.xyz')
# x = [vals[key] for key in vals.keys()]
# print(vals)
# print(x)

# print("IP resolved: ",count_ip_resolved(urlparse('https://www.geeksforgeeks.org')))
# print("Extracted spf: ",extract_spf('https://www.geeksforgeeks.org'))
# print("TTL: ",get_ttl('https://www.geeksforgeeks.org'))

# small_d = joblib.load('FinalPredictor.pkl')
# model = pickle.load(open('FinalPred.pkl','rb'))
# model_input = (np.array(x, dtype=object)).reshape(1, -1)
# #print(model_input)
# print(model.predict(model_input))
# print(small_d.predict(model_input))

# print("IP resolved: ",count_ip_resolved(urlparse('https://qlmedhfg.weebly.com/')))
# print("Extracted spf: ",extract_spf('https://www.geeksforgeeks.org'))
# print("TTL: ",get_ttl('https://www.geeksforgeeks.org'))
'''
Phishing URL:
	https://ghghfjrfng.weebly.com/
    https://green-btc.pages.dev/next/walletpage.php
    http://tcxtjssh.buzz/index.php?m=User&a=login
    https://qlmedhfg.weebly.com/
    
Extracted Features:
    [1, 1, 0, 2, 1, 0, 0, 0, 0, 3, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 2.400445, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 21, 0, 3, 0, 0]
    [20, 2, 0, 2, 1, 0, 0, 0, 0, 3, 0, 0, 0, 0, 47, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 2.938621, 0, 2, 0, 14, 0, 0, 0, -1, 1, 0, 19, 0, 5, 1, 0]
    [10, 1, 0, 1, 1, 0, 0, 0, 0, 4, 0, 2, 0, 0, 45, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 1, -1, 3.670627, 0, 1, 0, 9, 0, 0, 0, -1, 1, 0, 13, 0, 1, 1, 2]
    [1, 1, 0, 2, 1, 0, 0, 0, 0, 3, 0, 0, 0, 0, 28, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 19, 0, 4, 0, 0]
    
'''
#print(mod.predict([[0, 0, 0, 2, 1, 0, 0, 0, 0, 3, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1.52933, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 14, 0, 4, 0, 0]]))