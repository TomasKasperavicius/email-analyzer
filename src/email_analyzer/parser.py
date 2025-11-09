"""
Parser utilities for email headers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime
from email import policy
from email.parser import BytesParser
from typing import List, Optional, Sequence, Any
from dateutil import parser as dtparser
from email.header import decode_header

# IPv4 components - strict validation (0-255 per octet)
IPV4_SEGMENT = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_ADDRESS = rf"\b(?:{IPV4_SEGMENT}\.){{3}}{IPV4_SEGMENT}\b"

# IPv6 components  
IPV6_SEGMENT = r"[0-9a-fA-F]{1,4}"
IPV6_ADDRESS = rf"""\b(?:
    (?:{IPV6_SEGMENT}:){{7}}{IPV6_SEGMENT}|
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

# Compile the patterns
IPV4_RE = re.compile(IPV4_ADDRESS)
IPV6_RE = re.compile(IPV6_ADDRESS, re.VERBOSE)

TLS_TOKENS = ["esmtps", "esmtpsa", "smtps", "with tls", "starttls", "tls", "ssl", "encrypted"]

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
        d = asdict(self)
        if isinstance(self.timestamp, datetime):
            d['timestamp'] = self.timestamp.isoformat()
        return d

def load_email(path: str):
    with open(path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def _parse_received_single(raw: str, idx: int) -> Hop:
    normalized_header = ' '.join(raw.split())
    hop = Hop(index=idx, raw=raw, ips=[], tls=None)

    # timestamp (after last semicolon)
    if ';' in raw:
        timestamp_part = raw.rsplit(';', 1)[1].strip()
        try:
            hop.timestamp = dtparser.parse(timestamp_part)
        except Exception:
            hop.timestamp = None

    # from
    match = re.search(r"\bfrom\s+(?P<from>.+?)\s+(?:by|with|id|for|;)", normalized_header, re.I)
    if match:
        hop.from_host = match.group('from').strip()

    match = re.search(r"\bby\s+(?P<by>.+?)\s+(?:with|id|for|;)", normalized_header, re.I)
    if match:
        hop.by_host = match.group('by').strip()

    match = re.search(r"\bwith\s+(?P<with>.+?)\s+(?:id|for|;)", normalized_header, re.I)
    if match:
        hop.with_proto = match.group('with').strip()

    match = re.search(r"\bid\s+(?P<id>\S+)", normalized_header, re.I)
    if match:
        hop.id = match.group('id').strip()

    match = re.search(r"\bfor\s+(?P<for>.+?)\s*(?:;|$)", normalized_header, re.I)
    if match:
        hop.for_addr = match.group('for').strip()

    # ips
    ipv4_addresses = IPV4_RE.findall(raw)
    if not ipv4_addresses:
        ipv6_addresses = IPV6_RE.findall(raw)
        hop.ips = ipv6_addresses
    else:
        hop.ips = ipv4_addresses

    # tls heuristics
    lower_raw = raw.lower()
    for tls_token in TLS_TOKENS:
        if tls_token in lower_raw:
            hop.tls = True
            break
    else:
        if re.search(r"\bwith\s+(smtp|esmtp|lmtp)\b", lower_raw):
            hop.tls = False
        else:
            hop.tls = None

    return hop

def parse_received_hops(msg) -> List[Hop]:
    received_headers: Sequence[str] = msg.get_all('Received') or []
    received_headers = list(reversed(received_headers))
    hops: List[Hop] = []
    for index, received_header in enumerate(received_headers):
        hops.append(_parse_received_single(received_header, index))
    return hops

def parse_authentication_results(msg) -> dict:
    auth_headers = msg.get_all('Authentication-Results') or []
    results = []
    for auth_header in auth_headers:
        entry = {}
        match = re.search(r"\bspf=(pass|fail|neutral|none|softfail|temperror)\b", auth_header, re.I)
        if match:
            entry['spf'] = match.group(1).lower()
        match = re.search(r"\bdkim=(pass|fail|none|neutral)\b", auth_header, re.I)
        if match:
            entry['dkim'] = match.group(1).lower()
        match = re.search(r"\bdmarc=(pass|fail|none|bestguesspass)\b", auth_header, re.I)
        if match:
            entry['dmarc'] = match.group(1).lower()
        results.append(entry)

    return {
        'raw': auth_headers,
        'parsed': results,
        'dkim_signature': msg.get_all('DKIM-Signature') or [],
        'received_spf': msg.get_all('Received-SPF') or []
    }

def extract_additional_headers(msg) -> dict:
    """Extract additional interesting headers from email."""
    headers = {}
    
    # Decode subject properly
    subject = msg.get('Subject', '')
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
    headers['message_id'] = msg.get('Message-ID', '')
    
    # Content type
    headers['content_type'] = msg.get_content_type()
    
    # Return-Path
    headers['return_path'] = msg.get('Return-Path', '')
    
    # User-Agent/X-Mailer
    headers['user_agent'] = msg.get('User-Agent') or msg.get('X-Mailer', '')
    
    # MIME-Version
    headers['mime_version'] = msg.get('MIME-Version', '')
    
    # X-Headers (common anti-spam headers)
    x_headers = {}
    for key, value in msg.items():
        if key.startswith('X-'):
            x_headers[key] = value
    headers['x_headers'] = x_headers
    
    return headers