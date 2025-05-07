from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import os
from werkzeug.utils import secure_filename
import secrets
from modules import url_scan, malware_scan, hashing_tools, osint_search, network_utils

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'doc', 'docx', 'exe', 'dll', 'zip'}

# Ensure the uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

# URL/Domain Scanning
@app.route('/url_scan', methods=['GET', 'POST'])
def url_scanner():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            result = url_scan.scan_url(url)
        else:
            flash('Please enter a valid URL', 'danger')
    return render_template('url_scan.html', result=result)

# Malware File Analysis
@app.route('/malware_scan', methods=['GET', 'POST'])
def malware_scanner():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                result = malware_scan.scan_file(filepath)
                # Delete the file after scanning for security
                os.remove(filepath)
            except Exception as e:
                flash(f'Error scanning file: {str(e)}', 'danger')
                if os.path.exists(filepath):
                    os.remove(filepath)
        else:
            flash('File type not allowed', 'danger')
            
    return render_template('malware_scan.html', result=result)

# Hashing Tools
@app.route('/hashing', methods=['GET', 'POST'])
def hashing():
    result = None
    if request.method == 'POST':
        # Check if it's a text hash request
        if 'text' in request.form:
            text = request.form.get('text')
            if text:
                result = hashing_tools.hash_text(text)
            else:
                flash('Please enter text to hash', 'danger')
        
        # Check if it's a file hash request
        elif 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(request.url)
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                try:
                    result = hashing_tools.hash_file(filepath)
                    # Delete the file after hashing
                    os.remove(filepath)
                except Exception as e:
                    flash(f'Error hashing file: {str(e)}', 'danger')
                    if os.path.exists(filepath):
                        os.remove(filepath)
            else:
                flash('File type not allowed', 'danger')
                
    return render_template('hashing.html', result=result)

# OSINT Search
@app.route('/osint', methods=['GET', 'POST'])
def osint():
    results = None
    search_type = None

    if request.method == 'POST':
        query = request.form.get('search_term')  
        search_type = request.form.get('search_type')
        
        if query:
            results = osint_search.search(query, search_type)
            print("OSINT Results:", results)  # Debugging step
        else:
            flash('Please enter a search query', 'danger')

    return render_template('osint.html', results=results, search_type=search_type)

# Network Utilities
# Main Network Utilities Route
@app.route('/network_utils', methods=['GET'])
def network_utilities():
    return render_template('network_util.html')

# Individual Network Tool Routes
@app.route('/network_utils/ping', methods=['POST'])
def network_ping():
    target = request.form.get('host')
    count = request.form.get('count', 4)
    
    if not target:
        flash('Please enter a target hostname or IP address', 'danger')
        return render_template('network_util.html', error='No target specified')
    
    result = network_utils.ping(target)
    
    return render_template('network_util.html', 
                          result_type="ping",
                          results=result.get('result', ''),
                          target=result.get('target', ''),
                          error=result.get('error'))

@app.route('/network_utils/traceroute', methods=['POST'])
def network_traceroute():
    target = request.form.get('host')
    max_hops = request.form.get('max_hops', 15)
    
    if not target:
        flash('Please enter a target hostname or IP address', 'danger')
        return render_template('network_util.html', error='No target specified')
    
    result = network_utils.traceroute(target)
    
    return render_template('network_util.html', 
                          result_type="traceroute",
                          results=result.get('result', ''),
                          target=result.get('target', ''),
                          error=result.get('error'))

@app.route('/network_utils/port_scan', methods=['POST'])
def network_port_scan():
    target = request.form.get('host')
    port_range = request.form.get('port_range', 'common')
    
    if not target:
        flash('Please enter a target hostname or IP address', 'danger')
        return render_template('network_util.html', error='No target specified')
    
    # Determine ports to scan based on selected range
    ports = ''
    if port_range == 'common':
        ports = '21,22,23,25,53,80,110,143,443,3306,3389,8080,8443'
    elif port_range == '1-1024':
        ports = ','.join(str(p) for p in range(1, 1025))
    elif port_range == '1-65535':
        # This would be a very extensive scan, limit it in practice
        ports = ','.join(str(p) for p in range(1, 101))  # Limited to first 100 for safety
    elif port_range == 'custom':
        custom_ports = request.form.get('custom_ports', '')
        if custom_ports:
            # Handle ranges like 1000-2000
            if '-' in custom_ports and ',' not in custom_ports:
                try:
                    start, end = map(int, custom_ports.split('-'))
                    ports = ','.join(str(p) for p in range(start, end + 1))
                except ValueError:
                    ports = custom_ports  # Use as is if parsing fails
            else:
                ports = custom_ports
        else:
            ports = '21,22,23,25,53,80,110,143,443,3306,3389,8080,8443'  # Default if empty
    
    result = network_utils.port_scan(target, ports)
    
    # Format open ports for display
    open_ports = []
    if 'open_ports' in result:
        for port_info in result['open_ports']:
            open_ports.append({
                'number': port_info['port'],
                'service': port_info['service'],
                'status': 'Open'
            })
    
    return render_template('network_util.html', 
                          result_type="port_scan",
                          results=f"Scan completed for {target}\nOpen ports: {len(open_ports)}\nClosed ports: {len(result.get('closed_ports', []))}",
                          target=result.get('target', ''),
                          open_ports=open_ports,
                          error=result.get('error'))

@app.route('/network_utils/dns_lookup', methods=['POST'])
def network_dns_lookup():
    domain = request.form.get('domain')
    record_types = request.form.getlist('record_types')
    
    if not domain:
        flash('Please enter a domain name', 'danger')
        return render_template('network_util.html', error='No domain specified')
    
    # Since DNS lookup is not implemented in your network_utils.py, we'll create a basic version here
    try:
        import dns.resolver
        
        results = {}
        dns_records = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    if record_type == 'MX':
                        records.append({
                            'name': domain,
                            'value': f"{rdata.preference} {rdata.exchange}",
                            'ttl': answers.ttl
                        })
                    elif record_type == 'SOA':
                        records.append({
                            'name': domain,
                            'value': f"{rdata.mname} {rdata.rname} (Serial: {rdata.serial})",
                            'ttl': answers.ttl
                        })
                    else:
                        records.append({
                            'name': domain,
                            'value': str(rdata),
                            'ttl': answers.ttl
                        })
                
                dns_records[record_type] = records
                
            except Exception as e:
                dns_records[record_type] = [{
                    'name': domain,
                    'value': f"Error: {str(e)}",
                    'ttl': 0
                }]
        
        results = f"DNS lookup completed for {domain}"
        
        return render_template('network_util.html',
                              result_type="dns_lookup",
                              results=results,
                              dns_records=dns_records,
                              domain=domain)
    
    except ImportError:
        # If dnspython is not installed
        return render_template('network_util.html',
                              result_type="dns_lookup",
                              error="DNS lookup requires the 'dnspython' package. Please install it with 'pip install dnspython'.",
                              domain=domain)
    except Exception as e:
        return render_template('network_util.html',
                              result_type="dns_lookup",
                              error=f"DNS lookup error: {str(e)}",
                              domain=domain)

# Educational Resources
@app.route('/education')
def education():
    return render_template('education.html')

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)