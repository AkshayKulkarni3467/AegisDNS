import requests
import hashlib
import re
import json
import os
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
import time

class WebsiteAnalyzer:
    """Comprehensive website security analyzer with static and dynamic analysis"""
    
    def __init__(self):
        self.virustotal_api_key = self._load_api_key("virustotal")
        self.urlscan_api_key = self._load_api_key("urlscan")
        self.analysis_cache = {}
        self.cache_file = "website_analysis_cache.json"
        self._load_cache()
    
    def _load_api_key(self, service):
        """Load API key from environment or config file"""
        # Try environment variable first
        env_var = f"{service.upper()}_API_KEY"
        if env_var in os.environ:
            return os.environ[env_var]
        
        # Try config file
        config_file = "configs/api_keys.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    return config.get(service, None)
            except:
                pass
        return None
    
    def _load_cache(self):
        """Load analysis cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    self.analysis_cache = json.load(f)
            except:
                self.analysis_cache = {}
    
    def _save_cache(self):
        """Save analysis cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.analysis_cache, f, indent=2)
        except:
            pass
    
    def analyze_website(self, domain, full_analysis=True):
        """
        Main analysis function that coordinates all checks
        
        Returns:
            dict: Analysis results with threat score and details
        """
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        # Check cache (valid for 24 hours)
        cache_key = domain.lower()
        if cache_key in self.analysis_cache:
            cached = self.analysis_cache[cache_key]
            cache_age = time.time() - cached.get('timestamp', 0)
            if cache_age < 86400:  # 24 hours
                return cached['result']
        
        result = {
            'domain': domain,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'static_analysis': {},
            'dynamic_analysis': {},
            'threat_score': 0.0,
            'is_malicious': False,
            'warnings': [],
            'details': []
        }
        
        try:
            # Static Analysis
            result['static_analysis'] = self._static_analysis(url, domain)
            
            # Dynamic Analysis (if enabled)
            if full_analysis:
                result['dynamic_analysis'] = self._dynamic_analysis(url, domain)
            
            # Calculate overall threat score
            result['threat_score'] = self._calculate_threat_score(result)
            result['is_malicious'] = result['threat_score'] >= 0.7
            
            # Cache the result
            self.analysis_cache[cache_key] = {
                'timestamp': time.time(),
                'result': result
            }
            self._save_cache()
            
        except Exception as e:
            result['error'] = str(e)
            result['details'].append(f"Analysis error: {e}")
        
        return result
    
    def _static_analysis(self, url, domain):
        """Perform static analysis on website content"""
        analysis = {
            'content_hash': None,
            'ssl_info': {},
            'content_analysis': {},
            'threat_indicators': [],
            'external_checks': {}
        }
        
        try:
            # 1. Fetch website content
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            content = response.text
            
            # 2. Calculate content hash
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            analysis['content_hash'] = content_hash
            
            # 3. SSL/TLS Analysis
            analysis['ssl_info'] = self._check_ssl(domain)
            
            # 4. Content Analysis
            analysis['content_analysis'] = self._analyze_content(content, url)
            
            # 5. Check against threat databases
            if self.virustotal_api_key:
                analysis['external_checks']['virustotal'] = self._check_virustotal(url, content_hash)
            
            # 6. Identify threat indicators
            analysis['threat_indicators'] = self._identify_threats(content, response)
            
        except requests.exceptions.SSLError:
            analysis['threat_indicators'].append({
                'type': 'SSL_ERROR',
                'severity': 'HIGH',
                'description': 'Invalid or untrusted SSL certificate'
            })
        except requests.exceptions.Timeout:
            analysis['threat_indicators'].append({
                'type': 'TIMEOUT',
                'severity': 'MEDIUM',
                'description': 'Website took too long to respond'
            })
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _dynamic_analysis(self, url, domain):
        """Perform dynamic analysis (sandbox-style checks)"""
        analysis = {
            'redirects': [],
            'external_resources': [],
            'javascript_analysis': {},
            'behavior_analysis': {},
            'urlscan_results': {}
        }
        
        try:
            # 1. Track redirects
            response = requests.get(url, timeout=10, allow_redirects=True)
            if response.history:
                for redirect in response.history:
                    analysis['redirects'].append({
                        'from': redirect.url,
                        'to': redirect.headers.get('Location', 'N/A'),
                        'status_code': redirect.status_code
                    })
            
            # 2. Analyze external resources
            soup = BeautifulSoup(response.text, 'html.parser')
            analysis['external_resources'] = self._analyze_external_resources(soup, url)
            
            # 3. JavaScript analysis
            analysis['javascript_analysis'] = self._analyze_javascript(soup)
            
            # 4. Behavioral indicators
            analysis['behavior_analysis'] = self._analyze_behavior(soup, response)
            
            # 5. URLScan.io analysis (if API key available)
            if self.urlscan_api_key:
                analysis['urlscan_results'] = self._check_urlscan(url)
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _check_ssl(self, domain):
        """Check SSL certificate information"""
        ssl_info = {
            'valid': False,
            'issuer': None,
            'expiry': None,
            'version': None,
            'warnings': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    ssl_info['expiry'] = cert['notAfter']
                    ssl_info['version'] = ssock.version()
                    
                    # Check for self-signed
                    if ssl_info['issuer'] == dict(x[0] for x in cert.get('subject', [])):
                        ssl_info['warnings'].append('Self-signed certificate')
        
        except ssl.SSLError as e:
            ssl_info['warnings'].append(f'SSL Error: {str(e)}')
        except Exception as e:
            ssl_info['warnings'].append(f'Connection error: {str(e)}')
        
        return ssl_info
    
    def _analyze_content(self, content, url):
        """Analyze HTML content for suspicious patterns"""
        soup = BeautifulSoup(content, 'html.parser')
        
        analysis = {
            'forms': [],
            'iframes': [],
            'scripts': [],
            'suspicious_patterns': [],
            'obfuscation_detected': False
        }
        
        # Check forms (phishing indicator)
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get'),
                'has_password': bool(form.find('input', {'type': 'password'})),
                'inputs': len(form.find_all('input'))
            }
            analysis['forms'].append(form_data)
            
            # Check for forms posting to external domains
            if form_data['action'] and not form_data['action'].startswith('/'):
                parsed_action = urlparse(form_data['action'])
                parsed_url = urlparse(url)
                if parsed_action.netloc and parsed_action.netloc != parsed_url.netloc:
                    analysis['suspicious_patterns'].append(
                        f"Form posts to external domain: {parsed_action.netloc}"
                    )
        
        # Check iframes (malware distribution)
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            if src:
                analysis['iframes'].append(src)
                # Hidden iframes are suspicious
                if 'display:none' in iframe.get('style', '') or 'visibility:hidden' in iframe.get('style', ''):
                    analysis['suspicious_patterns'].append(f"Hidden iframe: {src}")
        
        # Check scripts
        for script in soup.find_all('script'):
            script_src = script.get('src', '')
            if script_src:
                analysis['scripts'].append(script_src)
            
            # Check for obfuscation
            script_content = script.string or ''
            if self._is_obfuscated(script_content):
                analysis['obfuscation_detected'] = True
                analysis['suspicious_patterns'].append("Obfuscated JavaScript detected")
        
        return analysis
    
    def _is_obfuscated(self, script_content):
        """Detect obfuscated JavaScript"""
        if not script_content or len(script_content) < 100:
            return False
        
        # Common obfuscation indicators
        indicators = [
            r'eval\s*\(',  # eval usage
            r'\\x[0-9a-f]{2}',  # hex encoding
            r'String\.fromCharCode',  # character code obfuscation
            r'unescape\s*\(',  # unescape
            r'atob\s*\(',  # base64 decode
        ]
        
        matches = sum(1 for pattern in indicators if re.search(pattern, script_content, re.IGNORECASE))
        return matches >= 2
    
    def _analyze_external_resources(self, soup, base_url):
        """Analyze external resources loaded by the page"""
        resources = {
            'external_scripts': [],
            'external_links': [],
            'external_images': [],
            'suspicious_domains': []
        }
        
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc
        
        # Known suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw']
        
        # Check external scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            parsed = urlparse(full_url)
            
            if parsed.netloc and parsed.netloc != base_domain:
                resources['external_scripts'].append(full_url)
                
                if any(parsed.netloc.endswith(tld) for tld in suspicious_tlds):
                    resources['suspicious_domains'].append(parsed.netloc)
        
        # Check external links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http'):
                parsed = urlparse(href)
                if parsed.netloc and parsed.netloc != base_domain:
                    resources['external_links'].append(href)
        
        return resources
    
    def _analyze_javascript(self, soup):
        """Analyze JavaScript for malicious patterns"""
        analysis = {
            'inline_scripts': 0,
            'external_scripts': 0,
            'suspicious_functions': [],
            'dynamic_loading': False
        }
        
        suspicious_functions = [
            'eval', 'Function', 'setTimeout', 'setInterval',
            'document.write', 'innerHTML', 'createElement'
        ]
        
        for script in soup.find_all('script'):
            if script.get('src'):
                analysis['external_scripts'] += 1
            else:
                analysis['inline_scripts'] += 1
                content = script.string or ''
                
                for func in suspicious_functions:
                    if func in content:
                        analysis['suspicious_functions'].append(func)
                
                # Check for dynamic script loading
                if 'createElement' in content and 'script' in content:
                    analysis['dynamic_loading'] = True
        
        return analysis
    
    def _analyze_behavior(self, soup, response):
        """Analyze behavioral indicators"""
        analysis = {
            'auto_redirect': False,
            'popup_indicators': False,
            'download_triggers': False,
            'fingerprinting': False
        }
        
        content = response.text.lower()
        
        # Check for auto-redirect
        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
        if meta_refresh:
            analysis['auto_redirect'] = True
        
        # Check for popup/new window
        if 'window.open' in content or 'popup' in content:
            analysis['popup_indicators'] = True
        
        # Check for automatic downloads
        if 'download' in content and ('click' in content or 'automatic' in content):
            analysis['download_triggers'] = True
        
        # Check for fingerprinting
        fingerprint_apis = ['canvas', 'webgl', 'audicontext', 'battery', 'geolocation']
        if sum(1 for api in fingerprint_apis if api in content) >= 2:
            analysis['fingerprinting'] = True
        
        return analysis
    
    def _identify_threats(self, content, response):
        """Identify common threat indicators"""
        threats = []
        content_lower = content.lower()
        
        # Phishing keywords
        phishing_keywords = [
            'verify your account', 'confirm your identity', 'suspended account',
            'unusual activity', 'click here immediately', 'urgent action required',
            'account will be closed', 'update payment information'
        ]
        
        for keyword in phishing_keywords:
            if keyword in content_lower:
                threats.append({
                    'type': 'PHISHING_KEYWORD',
                    'severity': 'HIGH',
                    'description': f'Phishing keyword detected: {keyword}'
                })
        
        # Check for base64 encoded content (potential payload)
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        if len(re.findall(base64_pattern, content)) > 5:
            threats.append({
                'type': 'BASE64_ENCODING',
                'severity': 'MEDIUM',
                'description': 'Multiple base64 encoded strings detected'
            })
        
        # Check response headers for security issues
        headers = response.headers
        if 'X-Frame-Options' not in headers:
            threats.append({
                'type': 'MISSING_SECURITY_HEADER',
                'severity': 'LOW',
                'description': 'Missing X-Frame-Options header (clickjacking risk)'
            })
        
        if 'Content-Security-Policy' not in headers:
            threats.append({
                'type': 'MISSING_SECURITY_HEADER',
                'severity': 'LOW',
                'description': 'Missing Content-Security-Policy header'
            })
        
        return threats
    
    def _check_virustotal(self, url, content_hash):
        """Check URL and hash against VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'API key not configured'}
        
        results = {
            'url_checked': False,
            'hash_checked': False,
            'detections': 0,
            'total_engines': 0,
            'malicious': False
        }
        
        try:
            # Check URL
            vt_url = 'https://www.virustotal.com/api/v3/urls'
            headers = {'x-apikey': self.virustotal_api_key}
            
            # Submit URL for scanning
            response = requests.post(vt_url, headers=headers, data={'url': url}, timeout=10)
            
            if response.status_code == 200:
                results['url_checked'] = True
                # Note: Full results require a separate GET request after analysis completes
                # For real-time use, you'd need to implement polling
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_urlscan(self, url):
        """Submit URL to URLScan.io for sandbox analysis"""
        if not self.urlscan_api_key:
            return {'error': 'API key not configured'}
        
        results = {
            'submitted': False,
            'scan_id': None,
            'result_url': None
        }
        
        try:
            headers = {
                'API-Key': self.urlscan_api_key,
                'Content-Type': 'application/json'
            }
            data = {'url': url, 'visibility': 'private'}
            
            response = requests.post(
                'https://urlscan.io/api/v1/scan/',
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                results['submitted'] = True
                results['scan_id'] = result.get('uuid')
                results['result_url'] = result.get('result')
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _calculate_threat_score(self, result):
        """Calculate overall threat score from analysis results"""
        score = 0.0
        
        static = result.get('static_analysis', {})
        dynamic = result.get('dynamic_analysis', {})
        
        # SSL issues
        ssl_info = static.get('ssl_info', {})
        if not ssl_info.get('valid', False):
            score += 0.3
        if 'Self-signed' in str(ssl_info.get('warnings', [])):
            score += 0.2
        
        # Content analysis
        content = static.get('content_analysis', {})
        if content.get('obfuscation_detected', False):
            score += 0.25
        
        suspicious_patterns = len(content.get('suspicious_patterns', []))
        score += min(suspicious_patterns * 0.1, 0.3)
        
        # Threat indicators
        threats = static.get('threat_indicators', [])
        high_severity = sum(1 for t in threats if t.get('severity') == 'HIGH')
        medium_severity = sum(1 for t in threats if t.get('severity') == 'MEDIUM')
        
        score += high_severity * 0.2
        score += medium_severity * 0.1
        
        # Dynamic analysis
        behavior = dynamic.get('behavior_analysis', {})
        if behavior.get('auto_redirect', False):
            score += 0.15
        if behavior.get('download_triggers', False):
            score += 0.2
        
        # External resources from suspicious domains
        resources = dynamic.get('external_resources', {})
        suspicious_domains = len(resources.get('suspicious_domains', []))
        score += min(suspicious_domains * 0.15, 0.3)
        
        return min(score, 1.0)


# Convenience function for integration
def analyze_website(domain, full_analysis=True):
    """Quick access function for website analysis"""
    analyzer = WebsiteAnalyzer()
    return analyzer.analyze_website(domain, full_analysis)