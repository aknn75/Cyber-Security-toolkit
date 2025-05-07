# Cybersecurity Toolkit: Setup and Running Guide

This guide provides detailed, step-by-step instructions for setting up and running the Cybersecurity Toolkit web application.

## Prerequisites

Before starting, ensure you have the following installed:

1. **Python 3.8+**: Required to run the application
   - Verify with: `python --version` or `python3 --version`
   - Download from [python.org](https://www.python.org/downloads/) if needed

2. **pip**: Python package manager
   - Typically installed with Python
   - Verify with: `pip --version` or `pip3 --version`

3. **Git** (optional): For cloning the repository
   - Verify with: `git --version`
   - Download from [git-scm.com](https://git-scm.com/downloads) if needed

## Step 1: Get the Code

### Option A: Download the Code
Download the project as a ZIP file and extract it to your preferred location.

### Option B: Clone with Git
```bash
git clone [repository-url]
cd cybersec_toolkit
```

## Step 2: Create a Virtual Environment (Recommended)

Creating a virtual environment helps keep dependencies isolated:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

You should see your command prompt change to indicate the active virtual environment.

## Step 3: Install Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
```

This will install Flask and other necessary libraries listed in the requirements.txt file.

## Step 4: Set Up Configuration (Optional)

For enhanced security or to use external APIs:

1. Create environment variables for sensitive keys:
   ```bash
   # Windows
   set SECRET_KEY=your_secret_key_here
   set VIRUSTOTAL_API_KEY=your_api_key_here
   
   # macOS/Linux
   export SECRET_KEY=your_secret_key_here
   export VIRUSTOTAL_API_KEY=your_api_key_here
   ```

2. Alternatively, edit `config.py` directly for testing purposes

## Step 5: Run the Application

Start the Flask development server:

```bash
# Windows
python app.py
# macOS/Linux
python3 app.py
```

You should see output similar to:
```
* Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
* Restarting with stat
* Debugger is active!
* Debugger PIN: 123-456-789
```

## Step 6: Access the Application

Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

You should see the Cybersecurity Toolkit dashboard with all available tools.

## Step 7: Using the Tools

- **URL/Domain Scanning**: Enter a URL to check its security details
- **Malware File Analysis**: Upload a file (max 16MB) to scan for malware signatures
- **Hashing Tools**: Enter text or upload a file to generate cryptographic hashes
- **OSINT Search**: Search for information about domains, IPs, or usernames
- **Network Utilities**: Use ping, traceroute, or port scanning (local environment only)
- **Educational Resources**: Browse cybersecurity learning materials

## Troubleshooting

### Common Issues and Solutions

1. **"Port already in use" error**:
   ```bash
   # Change the port in app.py
   app.run(debug=True, port=5001)
   ```

2. **Missing dependencies**:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **File upload issues**:
   - Ensure the 'uploads' directory exists and is writable
   - Check that your file doesn't exceed the 16MB limit

4. **Network utilities not working**:
   - Some network functions may require administrator/root privileges
   - Certain environments may block network operations

## Development and Customization

To modify or extend the application:

1. **Adding new tool modules**:
   - Create a new Python file in the `modules/` directory
   - Add corresponding routes in `app.py`
   - Create a template in `templates/`

2. **Changing the appearance**:
   - Edit `static/css/style.css` for styling changes
   - Modify base template in `templates/base.html`

3. **Adding API integrations**:
   - Add new API keys to `config.py`
   - Create helper functions in the appropriate module file

## Production Deployment Notes

For production environments:

1. Use a production WSGI server like Gunicorn or uWSGI
2. Set `DEBUG = False` in config.py
3. Generate a strong SECRET_KEY
4. Consider adding a reverse proxy like Nginx
5. Set appropriate file permissions and ownership
6. Implement proper logging

**Note**: This application is primarily designed for educational purposes and local use. Additional security measures should be implemented before deploying to production environments.