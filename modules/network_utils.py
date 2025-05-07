import subprocess
import socket
import platform
import re
import time

def is_valid_hostname(hostname):
    """Check if hostname/domain has valid format"""
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def is_valid_ip(ip):
    """Check if IP has valid format"""
    pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
    if not pattern.match(ip):
        return False
    
    # Check octet values
    octets = ip.split('.')
    for octet in octets:
        if int(octet) > 255:
            return False
    
    return True

def sanitize_input(target):
    """Sanitize target input to prevent command injection"""
    # Remove any potentially dangerous characters
    return re.sub(r'[;&|<>]', '', target)

def ping(target):
    """Ping a target host and return results"""
    # Sanitize input
    target = sanitize_input(target)
    
    if not (is_valid_hostname(target) or is_valid_ip(target)):
        return {'error': 'Invalid hostname or IP address'}
    
    try:
        # Determine ping command based on operating system
        ping_param = '-n' if platform.system().lower() == 'windows' else '-c'
        count_param = '4'  # Number of packets to send
        
        # Execute ping command
        ping_command = ['ping', ping_param, count_param, target]
        process = subprocess.Popen(ping_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        if error:
            return {'error': error.decode('utf-8')}
        
        return {
            'target': target,
            'command': ' '.join(ping_command),
            'result': output.decode('utf-8')
        }
    except Exception as e:
        return {'error': str(e)}

def traceroute(target):
    """Perform a traceroute to target host and return results"""
    # Sanitize input
    target = sanitize_input(target)
    
    if not (is_valid_hostname(target) or is_valid_ip(target)):
        return {'error': 'Invalid hostname or IP address'}
    
    try:
        # Determine traceroute command based on operating system
        if platform.system().lower() == 'windows':
            command = ['tracert', target]
        else:
            command = ['traceroute', '-m', '30', target]
        
        # Execute traceroute command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        if error:
            return {'error': error.decode('utf-8')}
        
        return {
            'target': target,
            'command': ' '.join(command),
            'result': output.decode('utf-8')
        }
    except Exception as e:
        return {'error': str(e)}

def port_scan(target, ports='80,443,22,21,25'):
    """Scan common ports on a target host"""
    # Sanitize input
    target = sanitize_input(target)
    
    if not (is_valid_hostname(target) or is_valid_ip(target)):
        return {'error': 'Invalid hostname or IP address'}
    
    # Parse ports from string
    try:
        if isinstance(ports, str):
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip()]
        else:
            port_list = [int(p) for p in ports]
    except ValueError:
        return {'error': 'Invalid port specification'}
    
    if not port_list:
        port_list = [80, 443, 22, 21, 25]  # Default ports if none specified
    
    # Limit number of ports to scan
    if len(port_list) > 25:
        return {'error': 'Too many ports specified (maximum 25)'}
    
    results = {
        'target': target,
        'scanned_ports': len(port_list),
        'open_ports': [],
        'closed_ports': []
    }
    
    # Resolve hostname to IP if needed
    try:
        ip = socket.gethostbyname(target)
        results['ip'] = ip
    except socket.gaierror:
        return {'error': 'Could not resolve hostname'}
    
    # Scan ports
    for port in port_list:
        if port < 1 or port > 65535:
            continue  # Skip invalid ports
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Port is open
                service = get_common_service(port)
                results['open_ports'].append({
                    'port': port,
                    'service': service
                })
            else:
                # Port is closed
                results['closed_ports'].append(port)
        except Exception:
            results['closed_ports'].append(port)
        finally:
            sock.close()
    
    return results

def get_common_service(port):
    """Return common service name for well-known ports"""
    common_ports = {
        20: 'FTP (Data)',
        21: 'FTP (Control)',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP (Submission)',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP Alternate',
        8443: 'HTTPS Alternate'
    }
    
    return common_ports.get(port, 'Unknown')