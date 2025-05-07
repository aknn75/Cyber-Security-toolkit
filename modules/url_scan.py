import requests
import socket
import whois
import re
from urllib.parse import urlparse

def is_valid_url(url):
    """Check if the URL has valid format"""
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http://, https://, ftp://, ftps://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def scan_url(url):
    """Scan a URL for basic security information"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    if not is_valid_url(url):
        return {'error': 'Invalid URL format'}
    
    try:
        result = {
            'url': url,
            'status': 'Unknown',
            'ssl': False,
            'headers': {},
            'whois': {},
            'ip': None
        }
        
        # Parse the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check if SSL/TLS is used
        result['ssl'] = url.startswith('https://')
        
        # Get HTTP response info
        try:
            response = requests.get(url, timeout=5, verify=True)
            result['status'] = response.status_code
            result['headers'] = dict(response.headers)
        except requests.exceptions.SSLError:
            result['status'] = 'SSL Error'
        except requests.exceptions.RequestException as e:
            result['status'] = str(e)
        
        # Get IP address
        try:
            result['ip'] = socket.gethostbyname(domain)
        except socket.gaierror:
            result['ip'] = 'Could not resolve IP'
        
        # Get WHOIS information
        try:
            w = whois.whois(domain)
            result['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
        except Exception:
            result['whois'] = 'WHOIS information unavailable'
        
        return result
    
    except Exception as e:
        return {'error': str(e)}