"""
Utilities to fetch EML files from various sources.
"""
import requests
import tempfile
import os
import imaplib
from typing import Optional
from urllib.parse import urlparse, unquote

def fetch_eml_from_url(url: str) -> str:
    """Fetch EML file from URL and save to temporary file."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    
    # Create temporary file
    file_descriptor, temp_path = tempfile.mkstemp(suffix='.eml')
    try:
        with os.fdopen(file_descriptor, 'w', encoding='utf-8') as file:
            file.write(response.text)
    except Exception:
        os.unlink(temp_path)
        raise
    
    return temp_path

def fetch_eml_from_imap(server: str, username: str, password: str, 
                       mailbox: str = 'INBOX', message_id: Optional[str] = None,
                       use_ssl: bool = True) -> str:
    """
    Fetch EML from IMAP server and save to temporary file.
    
    Args:
        server: IMAP server address (e.g., 'imap.gmail.com')
        username: Email account username
        password: Email account password
        mailbox: Mailbox folder name (default: 'INBOX')
        message_id: Specific message ID to fetch (optional, fetches latest if None)
        use_ssl: Use SSL connection (default: True)
    
    Returns:
        Path to temporary EML file
    """
    # Connect to IMAP server
    if use_ssl:
        imap_connection = imaplib.IMAP4_SSL(server)
    else:
        imap_connection = imaplib.IMAP4(server)
    
    try:
        # Login
        imap_connection.login(username, password)
        
        # Select mailbox
        imap_connection.select(mailbox)
        
        # Search for messages
        if message_id:
            # Search by specific message ID
            status, message_numbers = imap_connection.search(None, f'HEADER Message-ID "{message_id}"')
        else:
            # Get the latest message
            status, message_numbers = imap_connection.search(None, 'ALL')
        
        if status != 'OK' or not message_numbers[0]:
            raise ValueError(f"No messages found in mailbox '{mailbox}'")
        
        # Get message number (latest if multiple)
        message_num_list = message_numbers[0].split()
        target_message_num = message_num_list[-1]  # Get the last (most recent) message
        
        # Fetch the email message
        status, message_data = imap_connection.fetch(target_message_num, '(RFC822)')
        
        if status != 'OK':
            raise ValueError(f"Failed to fetch message {target_message_num}")
        
        # Extract raw email content
        raw_email = message_data[0][1]
        
        # Create temporary file
        file_descriptor, temp_path = tempfile.mkstemp(suffix='.eml')
        try:
            with os.fdopen(file_descriptor, 'wb') as file:
                file.write(raw_email)
        except Exception:
            os.unlink(temp_path)
            raise
        
        return temp_path
    
    finally:
        # Clean up connection
        try:
            imap_connection.close()
            imap_connection.logout()
        except:
            pass


def fetch_eml(url_or_path: str) -> str:
    """
    Smart fetcher that handles HTTP/HTTPS URLs and IMAP URLs.
    
    Supports:
    - HTTP/HTTPS URLs: http://example.com/email.eml
    - IMAP URLs: imap://username:password@imap.gmail.com/INBOX
    - IMAP with message ID: imap://username:password@imap.gmail.com/INBOX?message_id=<id@example.com>
    
    Args:
        url_or_path: URL string (http/https/imap)
    
    Returns:
        Path to temporary EML file
    """
    parsed_url = urlparse(url_or_path)
    
    if parsed_url.scheme in ('http', 'https'):
        return fetch_eml_from_url(url_or_path)
    
    elif parsed_url.scheme == 'imap':
        # Parse IMAP URL: imap://username:password@server:port/mailbox?message_id=<id>
        username = unquote(parsed_url.username) if parsed_url.username else None
        password = unquote(parsed_url.password) if parsed_url.password else None
        server = parsed_url.hostname
        port = parsed_url.port
        
        if not username or not password or not server:
            raise ValueError("IMAP URL must include username, password, and server: imap://user:pass@server/mailbox")
        
        # Extract mailbox from path (remove leading slash)
        mailbox = parsed_url.path.lstrip('/') if parsed_url.path else 'INBOX'
        if not mailbox:
            mailbox = 'INBOX'
        
        # Parse query parameters for message_id
        message_id = None
        if parsed_url.query:
            query_params = {}
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = unquote(value)
            message_id = query_params.get('message_id')
        
        # Connect using custom port if specified
        if port:
            server = f"{server}:{port}"
        
        return fetch_eml_from_imap(
            server=server,
            username=username,
            password=password,
            mailbox=mailbox,
            message_id=message_id,
            use_ssl=True
        )
    
    else:
        raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme}. Supported: http, https, imap")