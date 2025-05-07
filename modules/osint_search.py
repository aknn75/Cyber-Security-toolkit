import re
import socket
import whois
import requests
from urllib.parse import urlparse

# Helper Functions
def is_valid_email(email):
    """Check if the email has valid format"""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def is_valid_domain(domain):
    """Check if the domain has valid format"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_valid_ip(ip):
    """Check if the IP has valid format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    # Validate octet values
    octets = ip.split('.')
    for octet in octets:
        if int(octet) > 255:
            return False
    
    return True

# Search Functions
def search_email(email):
    """Search for information related to an email address"""
    if not is_valid_email(email):
        return {'error': 'Invalid email format'}

    domain = email.split('@')[1]
    result = {
        'email': email,
        'domain': domain,
        'domain_info': search_domain(domain),
        'possible_services': []
    }

    # Common services associated with email addresses
    common_services = [
        {'name': 'LinkedIn', 'url': f'https://www.linkedin.com/sales/gmail/profile/viewByEmail/{email}'},
        {'name': 'GitHub', 'url': f'https://api.github.com/search/users?q={email}'},
        {'name': 'Facebook', 'url': f'https://www.facebook.com/search/top/?q={email}'},
        {'name': 'Twitter', 'url': f'https://twitter.com/search?q={email}'}
    ]

    result['possible_services'] = [
        f"{service['name']}: {service['url']}" for service in common_services
    ]
    
    return result

def search_domain(domain):
    """Search for information related to a domain"""
    if not is_valid_domain(domain):
        return {'error': 'Invalid domain format'}

    result = {
        'domain': domain,
        'whois': {},
        'ip': None,
        'dns_records': [],
        'additional_resources': []
    }

    # Get WHOIS information
    try:
        w = whois.whois(domain)
        result['whois'] = {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers
        }
    except Exception as e:
        print(f"WHOIS Error: {e}")
        result['whois'] = 'WHOIS information unavailable'

    # Get IP address
    try:
        result['ip'] = socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"DNS Lookup Error: {e}")
        result['ip'] = 'Could not resolve IP'

    # Suggest additional resources
    result['additional_resources'] = [
        f"DNS Records: https://dnsdumpster.com/",
        f"SSL Information: https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
        f"Historical Data: https://web.archive.org/web/*/{domain}"
    ]
    
    return result

def search_ip(ip):
    """Search for information related to an IP address"""
    if not is_valid_ip(ip):
        return {'error': 'Invalid IP address format'}

    result = {
        'ip': ip,
        'reverse_dns': None,
        'geolocation': {},
        'additional_resources': []
    }

    # Get reverse DNS
    try:
        result['reverse_dns'] = socket.getfqdn(ip)
    except Exception as e:
        print(f"Reverse DNS Lookup Error: {e}")
        result['reverse_dns'] = 'Reverse DNS lookup failed'

    # Dummy geolocation data (In production, use an IP geolocation API)
    result['geolocation'] = {
        'note': 'This is placeholder data. In a real app, this would use an IP geolocation API.'
    }

    # Suggest additional resources
    result['additional_resources'] = [
        f"IP Reputation: https://www.abuseipdb.com/check/{ip}",
        f"Shodan Search: https://www.shodan.io/host/{ip}",
        f"VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}"
    ]
    
    return result

# Main Search Function
def search(query, query_type=None):
    """Search for information based on query type"""
    if not query:
        return {'error': 'Empty query'}

    # Automatically determine query type if not specified
    if not query_type:
        if is_valid_email(query):
            query_type = 'email'
        elif is_valid_ip(query):
            query_type = 'ip'
        elif is_valid_domain(query):
            query_type = 'domain'
        else:
            query_type = 'general'

    # Perform search based on query type
    if query_type == 'email':
        return search_email(query)
    elif query_type == 'domain':
        return search_domain(query)
    elif query_type == 'ip':
        return search_ip(query)
    else:
        # General search fallback
        return {
            'query': query,
            'note': 'For better results, specify a query type (email, domain, or IP).',
            'suggestions': [
                f"Web Search: https://www.google.com/search?q={query}",
                f"Username Search: https://whatsmyname.app/",
                f"Document Search: https://www.scribd.com/search?query={query}"
            ]
        }