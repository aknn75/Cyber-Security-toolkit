"""
Configuration settings for the Cybersecurity Toolkit.
This file contains various configuration parameters used throughout the application.
"""

import os
from datetime import timedelta

# Application configuration
DEBUG = True
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_key_for_testing_only')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'exe', 'dll', 'zip'}

# Session configuration
PERMANENT_SESSION_LIFETIME = timedelta(days=1)
SESSION_TYPE = 'filesystem'

# Security-related configurations
CSRF_ENABLED = True
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
SESSION_COOKIE_HTTPONLY = True

# API Keys (for production, store these in environment variables)
# These are placeholders - replace with actual API keys in production
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

# Malware scan settings
MALWARE_SCAN_TIMEOUT = 60  # Seconds
SIGNATURE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules', 'data', 'signatures.json')

# OSINT search settings
OSINT_SEARCH_TIMEOUT = 30  # Seconds
OSINT_MAX_RESULTS = 20

# Network utility settings
NETWORK_TIMEOUT = 10  # Seconds
MAX_TTL = 30  # Maximum hops for traceroute
PORT_SCAN_TIMEOUT = 1  # Seconds per port
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]  # Common ports to scan

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)