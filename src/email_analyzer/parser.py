"""
Parser utilities for email headers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from datetime import datetime
from email import policy
from email.parser import BytesParser
from typing import List, Optional, Sequence
from dateutil import parser as dtparser
from email.header import decode_header

# ============================================================================
# IP ADDRESS PATTERNS
# ============================================================================

# IPv4 Components
IPV4_SEGMENT = r"(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
IPV4_ADDRESS = rf"(?<![0-9.])(?:{IPV4_SEGMENT}\.){{3,3}}{IPV4_SEGMENT}(?![0-9.])"

# IPv6 Components
IPV6_SEGMENT = r"[0-9a-fA-F]{1,4}"
IPV6_ADDRESS = rf"""\b(?:
    (?:{IPV6_SEGMENT}:){{7,7}}{IPV6_SEGMENT}|
    (?:{IPV6_SEGMENT}:){{1,7}}:|
    (?:{IPV6_SEGMENT}:){{1,6}}:{IPV6_SEGMENT}|
    (?:{IPV6_SEGMENT}:){{1,5}}(?::{IPV6_SEGMENT}){{1,2}}|
    (?:{IPV6_SEGMENT}:){{1,4}}(?::{IPV6_SEGMENT}){{1,3}}|
    (?:{IPV6_SEGMENT}:){{1,3}}(?::{IPV6_SEGMENT}){{1,4}}|
    (?:{IPV6_SEGMENT}:){{1,2}}(?::{IPV6_SEGMENT}){{1,5}}|
    {IPV6_SEGMENT}:(?:(?::{IPV6_SEGMENT}){{1,6}})|
    :(?:(?::{IPV6_SEGMENT}){{1,7}}|:)|
    fe80:(?::{IPV6_SEGMENT}){{0,4}}%[0-9a-zA-Z]{{1,}}|
    ::(?:ffff(?::0{{1,4}}){{0,1}}:){{0,1}}{IPV4_ADDRESS}|
    (?:{IPV6_SEGMENT}:){{1,4}}:{IPV4_ADDRESS}
)\b"""

# 1:2:3:4:5:6:7:8
# 1::                                 1:2:3:4:5:6:7::
# 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
# 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
# 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
# 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
# 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
# 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
# ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
# fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
# ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
# 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)

IPV4_PATTERN = re.compile(IPV4_ADDRESS)
IPV6_PATTERN = re.compile(IPV6_ADDRESS, re.VERBOSE)

# ============================================================================
# TLS/ENCRYPTION DETECTION
# ============================================================================

TLS_INDICATOR_TOKENS = [
    "esmtps", "esmtpsa", "smtps", "with tls", "starttls", "tls", "ssl", "encrypted"
]

PLAINTEXT_PROTOCOL_PATTERN = re.compile(r"\bwith\s+(smtp|esmtp|lmtp)\b", re.IGNORECASE)

@dataclass
class Hop:
    index: int
    raw: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_proto: Optional[str] = None
    id: Optional[str] = None
    for_addr: Optional[str] = None
    timestamp: Optional[datetime] = None
    ips: List[str] = None
    tls: Optional[bool] = None
    geo: Optional[dict] = None

    def __post_init__(self):
        if self.ips is None:
            self.ips = []

    def to_dict(self) -> dict:
        hop_dictionary = asdict(self)
        if isinstance(self.timestamp, datetime):
            hop_dictionary['timestamp'] = self.timestamp.isoformat()
        return hop_dictionary

def load_email(path: str):
    with open(path, 'rb') as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)
    return message

def _extract_timestamp_from_received_header(raw_header: str) -> Optional[datetime]:
    if ';' not in raw_header:
        return None
    
    timestamp_part = raw_header.rsplit(';', 1)[1].strip()
    try:
        return dtparser.parse(timestamp_part)
    except Exception:
        return None


def _extract_ip_addresses_from_header(raw_header: str) -> List[str]:
    ipv4_addresses = IPV4_PATTERN.findall(raw_header)
    if ipv4_addresses:
        return ipv4_addresses
    
    ipv6_addresses = IPV6_PATTERN.findall(raw_header)
    return ipv6_addresses


def _detect_tls_encryption(raw_header: str) -> Optional[bool]:
    lower_header = raw_header.lower()
    
    # Check for TLS indicators
    for tls_indicator in TLS_INDICATOR_TOKENS:
        if tls_indicator in lower_header:
            return True
    
    # Check for plaintext protocols
    if PLAINTEXT_PROTOCOL_PATTERN.search(lower_header):
        return False
    
    return None


def _parse_received_single(raw: str, index: int) -> Hop:
    # Normalize whitespace for easier pattern matching
    normalized_header = ' '.join(raw.split())
    
    # Initialize hop with basic info
    hop = Hop(index=index, raw=raw, ips=[], tls=None)
    
    # Extract timestamp
    hop.timestamp = _extract_timestamp_from_received_header(raw)
    
    # Extract from_host
    from_host_match = re.search(r"\bfrom\s+(?P<from_host>.+?)\s+(?:by|with|id|for|;)", normalized_header, re.IGNORECASE)
    if from_host_match:
        hop.from_host = from_host_match.group('from_host').strip()
    
    # Extract by_host
    by_host_match = re.search(r"\bby\s+(?P<by_host>.+?)\s+(?:with|id|for|;)", normalized_header, re.IGNORECASE)
    if by_host_match:
        hop.by_host = by_host_match.group('by_host').strip()
    
    # Extract with_proto
    with_proto_match = re.search(r"\bwith\s+(?P<with_proto>.+?)\s+(?:id|for|;)", normalized_header, re.IGNORECASE)
    if with_proto_match:
        hop.with_proto = with_proto_match.group('with_proto').strip()
    
    # Extract id
    id_match = re.search(r"\bid\s+(?P<id>\S+)", normalized_header, re.IGNORECASE)
    if id_match:
        hop.id = id_match.group('id').strip()
    
    # Extract for_addr
    for_addr_match = re.search(r"\bfor\s+(?P<for_addr>.+?)\s*(?:;|$)", normalized_header, re.IGNORECASE)
    if for_addr_match:
        hop.for_addr = for_addr_match.group('for_addr').strip()
    
    # Extract IP addresses
    hop.ips = _extract_ip_addresses_from_header(raw)
    
    # Detect TLS encryption
    hop.tls = _detect_tls_encryption(raw)
    
    return hop

def parse_received_hops(message) -> List[Hop]:
    received_headers: Sequence[str] = message.get_all('Received') or []
    
    # Reverse to get chronological order (oldest first)
    received_headers = list(reversed(received_headers))
    
    # Parse each header into a structured Hop
    hops: List[Hop] = []
    for index, received_header in enumerate(received_headers):
        hop = _parse_received_single(received_header, index)
        hops.append(hop)
    
    return hops

def _parse_single_authentication_header(auth_header: str) -> dict:
    entry = {}
    
    # Extract SPF
    spf_match = re.search(r"\bspf=(?P<spf>pass|fail|neutral|none|softfail|temperror)\b", auth_header, re.IGNORECASE)
    if spf_match:
        entry['spf'] = spf_match.group('spf').lower()
    
    # Extract DKIM
    dkim_match = re.search(r"\bdkim=(?P<dkim>pass|fail|none|neutral)\b", auth_header, re.IGNORECASE)
    if dkim_match:
        entry['dkim'] = dkim_match.group('dkim').lower()
    
    # Extract DMARC
    dmarc_match = re.search(r"\bdmarc=(?P<dmarc>pass|fail|none|bestguesspass)\b", auth_header, re.IGNORECASE)
    if dmarc_match:
        entry['dmarc'] = dmarc_match.group('dmarc').lower()
    
    return entry


def parse_authentication_results(message) -> dict:
    auth_headers = message.get_all('Authentication-Results') or []
    
    # Parse each Authentication-Results header
    parsed_results = []
    for auth_header in auth_headers:
        parsed_result = _parse_single_authentication_header(auth_header)
        parsed_results.append(parsed_result)
    
    return {
        'raw': auth_headers,
        'parsed': parsed_results,
        'dkim_signature': message.get_all('DKIM-Signature') or [],
        'received_spf': message.get_all('Received-SPF') or []
    }

def extract_additional_headers(message) -> dict:
    headers = {}
    
    # Decode subject properly
    subject = message.get('Subject', '')
    if subject:
        decoded_parts = decode_header(subject)
        decoded_subject = ''
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                if encoding:
                    decoded_subject += part.decode(encoding)
                else:
                    decoded_subject += part.decode('utf-8', errors='ignore')
            else:
                decoded_subject += part
        headers['subject_decoded'] = decoded_subject
    
    # Message ID
    headers['message_id'] = message.get('Message-ID', '')
    
    # Content type
    headers['content_type'] = message.get_content_type()
    
    # Return-Path
    headers['return_path'] = message.get('Return-Path', '')
    
    # User-Agent/X-Mailer
    headers['user_agent'] = message.get('User-Agent') or message.get('X-Mailer', '')
    
    # MIME-Version
    headers['mime_version'] = message.get('MIME-Version', '')
    
    # X-Headers (common anti-spam headers)
    x_headers = {}
    for key, value in message.items():
        if key.startswith('X-'):
            x_headers[key] = value
    headers['x_headers'] = x_headers
    
    return headers