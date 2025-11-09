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
IPV4SEG = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4ADDR = rf"\b(?:{IPV4SEG}\.){{3}}{IPV4SEG}\b"

# IPv6 components  
IPV6SEG = r"[0-9a-fA-F]{1,4}"
IPV6ADDR = rf"""\b(?:
    (?:{IPV6SEG}:){{7}}{IPV6SEG}|
    (?:{IPV6SEG}:){{1,7}}:|
    (?:{IPV6SEG}:){{1,6}}:{IPV6SEG}|
    (?:{IPV6SEG}:){{1,5}}(?::{IPV6SEG}){{1,2}}|
    (?:{IPV6SEG}:){{1,4}}(?::{IPV6SEG}){{1,3}}|
    (?:{IPV6SEG}:){{1,3}}(?::{IPV6SEG}){{1,4}}|
    (?:{IPV6SEG}:){{1,2}}(?::{IPV6SEG}){{1,5}}|
    {IPV6SEG}:(?:(?::{IPV6SEG}){{1,6}})|
    :(?:(?::{IPV6SEG}){{1,7}}|:)|
    fe80:(?::{IPV6SEG}){{0,4}}%[0-9a-zA-Z]{{1,}}|
    ::(?:ffff(?::0{{1,4}}){{0,1}}:){{0,1}}{IPV4ADDR}|
    (?:{IPV6SEG}:){{1,4}}:{IPV4ADDR}
)\b"""

# Compile the patterns
IPV4_RE = re.compile(rf"\b{IPV4ADDR}\b")
IPV6_RE = re.compile(rf"\b{IPV6ADDR}\b", re.VERBOSE)

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
    s = ' '.join(raw.split())
    hop = Hop(index=idx, raw=raw, ips=[], tls=None)

    # timestamp (after last semicolon)
    if ';' in raw:
        right = raw.rsplit(';', 1)[1].strip()
        try:
            hop.timestamp = dtparser.parse(right)
        except Exception:
            hop.timestamp = None

    # from
    m = re.search(r"\bfrom\s+(?P<from>.+?)\s+(?:by|with|id|for|;)", s, re.I)
    if m:
        hop.from_host = m.group('from').strip()

    m = re.search(r"\bby\s+(?P<by>.+?)\s+(?:with|id|for|;)", s, re.I)
    if m:
        hop.by_host = m.group('by').strip()

    m = re.search(r"\bwith\s+(?P<with>.+?)\s+(?:id|for|;)", s, re.I)
    if m:
        hop.with_proto = m.group('with').strip()

    m = re.search(r"\bid\s+(?P<id>\S+)", s, re.I)
    if m:
        hop.id = m.group('id').strip()

    m = re.search(r"\bfor\s+(?P<for>.+?)\s*(?:;|$)", s, re.I)
    if m:
        hop.for_addr = m.group('for').strip()

    # ips
    ips = IPV4_RE.findall(raw)
    if not ips:
        ipv6s = IPV6_RE.findall(raw)
        ips = ipv6s
    hop.ips = ips

    # tls heuristics
    lower = raw.lower()
    for t in TLS_TOKENS:
        if t in lower:
            hop.tls = True
            break
    else:
        if re.search(r"\bwith\s+(smtp|esmtp|lmtp)\b", lower):
            hop.tls = False
        else:
            hop.tls = None

    return hop

def parse_received_hops(msg) -> List[Hop]:
    recs: Sequence[str] = msg.get_all('Received') or []
    recs = list(reversed(recs))
    hops: List[Hop] = []
    for i, r in enumerate(recs):
        hops.append(_parse_received_single(r, i))
    return hops

def parse_authentication_results(msg) -> dict:
    auths = msg.get_all('Authentication-Results') or []
    results = []
    for a in auths:
        entry = {}
        m = re.search(r"\bspf=(pass|fail|neutral|none|softfail|temperror)\b", a, re.I)
        if m:
            entry['spf'] = m.group(1).lower()
        m = re.search(r"\bdkim=(pass|fail|none|neutral)\b", a, re.I)
        if m:
            entry['dkim'] = m.group(1).lower()
        m = re.search(r"\bdmarc=(pass|fail|none|bestguesspass)\b", a, re.I)
        if m:
            entry['dmarc'] = m.group(1).lower()
        results.append(entry)

    return {
        'raw': auths,
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