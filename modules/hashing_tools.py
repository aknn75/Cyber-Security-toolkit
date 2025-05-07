import hashlib
import base64

def hash_text(text):
    """Generate multiple hash types for text input"""
    if not text:
        return None
    
    # Convert text to bytes if needed
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')
    else:
        text_bytes = text
    
    # Calculate various hashes
    md5 = hashlib.md5(text_bytes).hexdigest()
    sha1 = hashlib.sha1(text_bytes).hexdigest()
    sha256 = hashlib.sha256(text_bytes).hexdigest()
    sha512 = hashlib.sha512(text_bytes).hexdigest()
    
    # Base64 encoding
    base64_encoded = base64.b64encode(text_bytes).decode('utf-8')
    
    return {
        'input_text': text,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
        'sha512': sha512,
        'base64': base64_encoded
    }

def hash_file(filepath):
    """Generate multiple hash types for a file"""
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        
        with open(filepath, 'rb') as f:
            # Read and update hash in chunks for memory efficiency
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
        
        return {
            'filename': filepath.split('/')[-1],
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
            'sha512': sha512.hexdigest()
        }
        
    except Exception as e:
        return {'error': str(e)}