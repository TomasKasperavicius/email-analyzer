"""
Utilities to fetch EML files from various sources.
"""
import requests
import tempfile
import os
from typing import Optional

def fetch_eml_from_url(url: str) -> str:
    """Fetch EML file from URL and save to temporary file."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    
    # Create temporary file
    fd, temp_path = tempfile.mkstemp(suffix='.eml')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(response.text)
    except Exception:
        os.unlink(temp_path)
        raise
    
    return temp_path

def fetch_eml_from_imap(server: str, username: str, password: str, 
                       mailbox: str = 'INBOX', message_id: Optional[str] = None) -> str:
    """Fetch EML from IMAP server (basic implementation)."""
    # This would require imaplib implementation
    # Placeholder for IMAP functionality
    raise NotImplementedError("IMAP fetching not yet implemented")