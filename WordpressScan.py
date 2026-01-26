#!/usr/bin/env python3
"""
WordPress Security Scanner - Professional Edition
================================================
Enhanced, secure, and optimized WordPress security scanner with modular architecture.
Maintains original functionality while improving code quality, security, and performance.

Author: Security Research Team
Version: 2.0.0
License: MIT
"""

import asyncio
import aiohttp
import json
import re
import os
import sys
import hashlib
import logging
import signal
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any, AsyncGenerator
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager
import random
import string
import time

# Third-party imports
try:
    import requests
    from bs4 import BeautifulSoup
    from aiohttp import ClientSession, ClientTimeout, TCPConnector
    from colorama import init, Fore, Style
    init()
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install requests beautifulsoup4 aiohttp colorama")
    sys.exit(1)

# Constants
DEFAULT_TIMEOUT = 10
MAX_CONCURRENT_REQUESTS = 20
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
]

class ScanSeverity(Enum):
    """Severity levels for scan findings"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanCategory(Enum):
    """Scan categories"""
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    BRUTE_FORCE = "brute_force"
    INFORMATION = "information"

@dataclass
class ScanFinding:
    """Represents a security finding"""
    id: str
    category: ScanCategory
    severity: ScanSeverity
    title: str
    description: str
    url: str
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)

class RequestLimiter:
    """Rate limiter and request throttler"""
    
    def __init__(self, max_requests_per_second: int = 5):
        self.max_requests = max_requests_per_second
        self.min_interval = 1.0 / max_requests_per_second
        self.last_request_time = 0
    
    async def wait_if_needed(self):
        """Wait if requests are being made too quickly"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        
        self.last_request_time = time.time()

class WordPressScanner:
    """Main WordPress security scanner class"""
    
    def __init__(self, 
                 target_url: str,
                 output_dir: Path = Path("scan_results"),
                 max_workers: int = MAX_CONCURRENT_REQUESTS,
                 timeout: int = DEFAULT_TIMEOUT,
                 verify_ssl: bool = True):
        
        self.target_url = target_url.rstrip('/')
        self.base_url = target_url
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Initialize components
        self.session = None
        self.limiter = RequestLimiter(max_requests_per_second=3)
        
        # Results storage
        self.findings: List[ScanFinding] = []
        self.users: Set[str] = set()
        self.plugins: Set[str] = set()
        self.themes: Set[str] = set()
        self.config_data: Dict[str, str] = {}
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        log_dir = self.output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"scan_{datetime.now():%Y%m%d_%H%M%S}.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_session()
    
    async def initialize_session(self):
        """Initialize HTTP session with proper configuration"""
        timeout = ClientTimeout(total=self.timeout)
        connector = TCPConnector(
            limit=self.max_workers,
            ssl=ssl.create_default_context() if self.verify_ssl else False,
            force_close=True
        )
        
        self.session = ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
            }
        )
    
    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Make HTTP request with rate limiting and error handling
        
        Args:
            url: Target URL
            method: HTTP method
            **kwargs: Additional arguments for aiohttp request
            
        Returns:
            ClientResponse or None if request fails
        """
        await self.limiter.wait_if_needed()
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                return response
        except aiohttp.ClientError as e:
            self.logger.warning(f"Request failed for {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error for {url}: {e}")
            return None
    
    async def is_wordpress(self) -> bool:
        """Detect if target is WordPress with multiple validation methods"""
        detection_methods = [
            self._check_wp_readme,
            self._check_wp_login,
            self._check_wp_content,
            self._check_wp_json,
            self._check_wp_meta,
        ]
        
        results = await asyncio.gather(*[method() for method in detection_methods])
        return any(results)
    
    async def _check_wp_readme(self) -> bool:
        """Check for WordPress readme file"""
        urls = [
            f"{self.target_url}/readme.html",
            f"{self.target_url}/readme.txt",
        ]
        
        for url in urls:
            response = await self.make_request(url)
            if response and response.status == 200:
                content = await response.text()
                if 'wordpress' in content.lower():
                    return True
        return False
    
    async def _check_wp_login(self) -> bool:
        """Check for WordPress login page"""
        url = f"{self.target_url}/wp-login.php"
        response = await self.make_request(url)
        
        if response and response.status == 200:
            content = await response.text()
            return 'wordpress' in content.lower() or 'wp-submit' in content
        return False
    
    async def _check_wp_content(self) -> bool:
        """Check for WordPress content directories"""
        url = self.target_url
        response = await self.make_request(url)
        
        if response:
            content = await response.text()
            wp_indicators = [
                'wp-content', 'wp-includes', 'wp-json',
                'wp-admin', 'wp-embed.min.js', 'wp-emoji'
            ]
            
            for indicator in wp_indicators:
                if indicator in content:
                    return True
        return False
    
    async def _check_wp_json(self) -> bool:
        """Check for WordPress REST API"""
        url = f"{self.target_url}/wp-json/"
        response = await self.make_request(url)
        
        if response and response.status == 200:
            try:
                data = await response.json()
                return 'name' in data and 'WordPress' in str(data.get('name', ''))
            except:
                pass
        return False
    
    async def _check_wp_meta(self) -> bool:
        """Check for WordPress meta tags"""
        url = self.target_url
        response = await self.make_request(url)
        
        if response:
            content = await response.text()
            # Check for WordPress meta generator tag
            meta_pattern = r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'][^>]*WordPress[^>]*["\']'
            if re.search(meta_pattern, content, re.IGNORECASE):
                return True
        return False
    
    async def enumerate_users(self) -> List[str]:
        """Enumerate WordPress users using multiple methods"""
        methods = [
            self._enumerate_via_author_pages,
            self._enumerate_via_rest_api,
            self._enumerate_via_rss,
            self._enumerate_via_sitemap,
            self._enumerate_via_oembed,
        ]
        
        all_users = set()
        
        # Run all enumeration methods concurrently
        tasks = [method() for method in methods]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results
        for result in results:
            if isinstance(result, set):
                all_users.update(result)
        
        self.users = all_users
        
        if all_users:
            self.add_finding(
                ScanFinding(
                    id="WP-USER-ENUM",
                    category=ScanCategory.ENUMERATION,
                    severity=ScanSeverity.LOW,
                    title="WordPress User Enumeration",
                    description=f"Found {len(all_users)} WordPress users",
                    url=self.target_url,
                    evidence=f"Users: {', '.join(sorted(all_users))}",
                    cvss_score=2.5
                )
            )
        
        return list(all_users)
    
    async def _enumerate_via_author_pages(self) -> Set[str]:
        """Enumerate users via author archive pages"""
        users = set()
        
        async for url in self._generate_author_urls():
            response = await self.make_request(url, allow_redirects=False)
            
            if response and response.status in (301, 302):
                location = response.headers.get('Location', '')
                if '/author/' in location:
                    username = location.split('/author/')[-1].strip('/')
                    if username and username not in users:
                        users.add(username)
                        self.logger.info(f"Found user via author page: {username}")
        
        return users
    
    async def _generate_author_urls(self) -> AsyncGenerator[str, None]:
        """Generate author enumeration URLs"""
        # Standard author enumeration
        for i in range(1, 20):  # Reasonable limit
            yield f"{self.target_url}/?author={i}"
        
        # Author archive pages
        yield f"{self.target_url}/wp-json/wp/v2/users"
        yield f"{self.target_url}/wp-json/wp/v2/users?per_page=100"
        yield f"{self.target_url}/author-sitemap.xml"
        yield f"{self.target_url}/wp-sitemap-users-1.xml"
    
    async def _enumerate_via_rest_api(self) -> Set[str]:
        """Enumerate users via WordPress REST API"""
        users = set()
        urls = [
            f"{self.target_url}/wp-json/wp/v2/users",
            f"{self.target_url}/wp-json/wp/v2/users?per_page=100",
        ]
        
        for url in urls:
            response = await self.make_request(url)
            
            if response and response.status == 200:
                try:
                    data = await response.json()
                    if isinstance(data, list):
                        for user in data:
                            if 'slug' in user:
                                users.add(user['slug'])
                except Exception as e:
                    self.logger.debug(f"Failed to parse REST API response: {e}")
        
        return users
    
    async def _enumerate_via_rss(self) -> Set[str]:
        """Enumerate users via RSS feeds"""
        users = set()
        rss_urls = [
            f"{self.target_url}/feed/",
            f"{self.target_url}/feed/rss2/",
            f"{self.target_url}/feed/atom/",
        ]
        
        for url in rss_urls:
            response = await self.make_request(url)
            
            if response and response.status == 200:
                content = await response.text()
                # Look for creator tags
                creator_patterns = [
                    r'<dc:creator>([^<]+)</dc:creator>',
                    r'<author>([^<]+)</author>',
                    r'<wp:author_login>([^<]+)</wp:author_login>',
                ]
                
                for pattern in creator_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if match.strip():
                            users.add(match.strip())
        
        return users
    
    async def _enumerate_via_sitemap(self) -> Set[str]:
        """Enumerate users via sitemap"""
        users = set()
        sitemap_urls = [
            f"{self.target_url}/wp-sitemap.xml",
            f"{self.target_url}/wp-sitemap-users-1.xml",
            f"{self.target_url}/sitemap.xml",
            f"{self.target_url}/sitemap_users.xml",
        ]
        
        for url in sitemap_urls:
            response = await self.make_request(url)
            
            if response and response.status == 200:
                content = await response.text()
                # Parse XML for user URLs
                user_patterns = [
                    r'<loc>[^<]*/author/([^<]+)</loc>',
                    r'<url>[^<]*<loc>[^<]*/author/([^<]+)</loc>',
                ]
                
                for pattern in user_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if match.strip():
                            users.add(match.strip())
        
        return users
    
    async def _enumerate_via_oembed(self) -> Set[str]:
        """Enumerate users via oEmbed API"""
        users = set()
        
        # Try to get user ID from oEmbed
        for user_id in range(1, 10):
            url = f"{self.target_url}/wp-json/oembed/1.0/embed?url={self.target_url}/?author={user_id}"
            response = await self.make_request(url)
            
            if response and response.status == 200:
                try:
                    data = await response.json()
                    if 'author_name' in data:
                        users.add(data['author_name'])
                except:
                    pass
        
        return users
    
    async def enumerate_plugins_and_themes(self) -> Tuple[List[str], List[str]]:
        """Enumerate WordPress plugins and themes"""
        plugins = await self._enumerate_plugins()
        themes = await self._enumerate_themes()
        
        self.plugins.update(plugins)
        self.themes.update(themes)
        
        if plugins:
            self.add_finding(
                ScanFinding(
                    id="WP-PLUGINS-FOUND",
                    category=ScanCategory.ENUMERATION,
                    severity=ScanSeverity.INFO,
                    title="WordPress Plugins Discovered",
                    description=f"Found {len(plugins)} active plugins",
                    url=self.target_url,
                    evidence=f"Plugins: {', '.join(sorted(plugins)[:10])}",
                )
            )
        
        if themes:
            self.add_finding(
                ScanFinding(
                    id="WP-THEMES-FOUND",
                    category=ScanCategory.ENUMERATION,
                    severity=ScanSeverity.INFO,
                    title="WordPress Themes Discovered",
                    description=f"Found {len(themes)} active themes",
                    url=self.target_url,
                    evidence=f"Themes: {', '.join(sorted(themes))}",
                )
            )
        
        return list(plugins), list(themes)
    
    async def _enumerate_plugins(self) -> Set[str]:
        """Enumerate WordPress plugins"""
        plugins = set()
        
        # Load known plugins list
        known_plugins = await self._load_known_plugins()
        
        # Check common plugin paths
        tasks = []
        for plugin in known_plugins:
            tasks.append(self._check_plugin_exists(plugin))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str) and result:
                plugins.add(result)
        
        # Check readme files
        readme_url = f"{self.target_url}/wp-content/plugins/"
        response = await self.make_request(readme_url)
        
        if response and response.status == 200:
            content = await response.text()
            # Parse directory listing for plugins
            plugin_pattern = r'href="([^"/]+)/"'
            matches = re.findall(plugin_pattern, content)
            plugins.update(matches)
        
        return plugins
    
    async def _load_known_plugins(self) -> List[str]:
        """Load list of known WordPress plugins"""
        # Common WordPress plugins
        return [
            'akismet', 'contact-form-7', 'yoast-seo', 'woocommerce',
            'elementor', 'all-in-one-seo-pack', 'wordfence', 'jetpack',
            'revslider', 'visual-composer', 'formidable', 'wp-super-cache',
            'nextgen-gallery', 'updraftplus', 'duplicator', 'wpforms',
            'gravityforms', 'ninja-forms', 'buddypress', 'bbpress',
            'advanced-custom-fields', 'wp-rocket', 'seo-by-rank-math',
            'litespeed-cache', 'really-simple-ssl', 'redirection',
        ]
    
    async def _check_plugin_exists(self, plugin_name: str) -> Optional[str]:
        """Check if a specific plugin exists"""
        urls = [
            f"{self.target_url}/wp-content/plugins/{plugin_name}/",
            f"{self.target_url}/wp-content/plugins/{plugin_name}/readme.txt",
            f"{self.target_url}/wp-content/plugins/{plugin_name}/{plugin_name}.php",
        ]
        
        for url in urls:
            response = await self.make_request(url)
            if response and response.status in (200, 403, 301, 302):
                return plugin_name
        
        return None
    
    async def _enumerate_themes(self) -> Set[str]:
        """Enumerate WordPress themes"""
        themes = set()
        
        # Load known themes list
        known_themes = await self._load_known_themes()
        
        # Check common theme paths
        tasks = []
        for theme in known_themes:
            tasks.append(self._check_theme_exists(theme))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str) and result:
                themes.add(result)
        
        # Check style.css files
        readme_url = f"{self.target_url}/wp-content/themes/"
        response = await self.make_request(readme_url)
        
        if response and response.status == 200:
            content = await response.text()
            # Parse directory listing for themes
            theme_pattern = r'href="([^"/]+)/"'
            matches = re.findall(theme_pattern, content)
            themes.update(matches)
        
        return themes
    
    async def _load_known_themes(self) -> List[str]:
        """Load list of known WordPress themes"""
        # Common WordPress themes
        return [
            'twentytwentyone', 'twentytwenty', 'astra', 'generatepress',
            'oceanwp', 'avada', 'divi', 'newspaper', 'flatsome', 'the7',
            'enfold', 'bridge', 'betheme', 'salient', 'woodmart',
            'shopkeeper', 'porto', 'x', 'uncode', 'kalium',
        ]
    
    async def _check_theme_exists(self, theme_name: str) -> Optional[str]:
        """Check if a specific theme exists"""
        urls = [
            f"{self.target_url}/wp-content/themes/{theme_name}/",
            f"{self.target_url}/wp-content/themes/{theme_name}/style.css",
            f"{self.target_url}/wp-content/themes/{theme_name}/readme.txt",
        ]
        
        for url in urls:
            response = await self.make_request(url)
            if response and response.status in (200, 403, 301, 302):
                return theme_name
        
        return None
    
    async def check_config_files(self) -> Dict[str, str]:
        """Check for exposed WordPress configuration files"""
        config_files = [
            'wp-config.php',
            'wp-config.php.bak',
            'wp-config.php.save',
            'wp-config.php.old',
            'wp-config.php.orig',
            'wp-config.php.backup',
            'wp-config.php.dist',
            'wp-config-sample.php',
            'wp-config.php.1',
            'wp-config.php.2',
        ]
        
        config_data = {}
        
        tasks = [self._check_config_file(file) for file in config_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict):
                config_data.update(result)
        
        self.config_data = config_data
        
        if config_data:
            self.add_finding(
                ScanFinding(
                    id="WP-CONFIG-EXPOSED",
                    category=ScanCategory.CONFIGURATION,
                    severity=ScanSeverity.CRITICAL,
                    title="WordPress Configuration File Exposed",
                    description="wp-config.php file accessible from web",
                    url=self.target_url,
                    evidence="Database credentials may be exposed",
                    cvss_score=9.8,
                    cve="CVE-2017-8295"
                )
            )
        
        return config_data
    
    async def _check_config_file(self, filename: str) -> Dict[str, str]:
        """Check if a specific config file exists and extract data"""
        url = f"{self.target_url}/{filename}"
        response = await self.make_request(url)
        
        if response and response.status == 200:
            content = await response.text()
            
            if '<?php' in content or 'define(' in content:
                # Extract database configuration
                config = self._extract_db_config(content)
                
                if config:
                    self.logger.critical(f"Found exposed config file: {filename}")
                    return config
        
        return {}
    
    def _extract_db_config(self, content: str) -> Dict[str, str]:
        """Extract database configuration from wp-config.php content"""
        config = {}
        
        patterns = {
            'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
            'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
            'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
            'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
            'DB_CHARSET': r"define\s*\(\s*['\"]DB_CHARSET['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
            'DB_COLLATE': r"define\s*\(\s*['\"]DB_COLLATE['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                config[key] = match.group(1)
        
        return config
    
    async def check_vulnerabilities(self) -> List[ScanFinding]:
        """Check for known vulnerabilities in plugins and themes"""
        vulnerabilities = []
        
        # Check plugin vulnerabilities
        plugin_vulns = await self._check_plugin_vulnerabilities()
        vulnerabilities.extend(plugin_vulns)
        
        # Check theme vulnerabilities
        theme_vulns = await self._check_theme_vulnerabilities()
        vulnerabilities.extend(theme_vulns)
        
        # Check WordPress core vulnerabilities
        core_vulns = await self._check_core_vulnerabilities()
        vulnerabilities.extend(core_vulns)
        
        # Check for XML-RPC abuse
        xmlrpc_vuln = await self._check_xmlrpc()
        if xmlrpc_vuln:
            vulnerabilities.append(xmlrpc_vuln)
        
        # Check for exposed REST API
        rest_api_vuln = await self._check_rest_api()
        if rest_api_vuln:
            vulnerabilities.append(rest_api_vuln)
        
        return vulnerabilities
    
    async def _check_plugin_vulnerabilities(self) -> List[ScanFinding]:
        """Check for known plugin vulnerabilities"""
        vulnerabilities = []
        known_vulnerabilities = self._load_plugin_vulnerabilities()
        
        for plugin in self.plugins:
            if plugin in known_vulnerabilities:
                vuln_info = known_vulnerabilities[plugin]
                
                finding = ScanFinding(
                    id=f"VULN-PLUGIN-{plugin.upper()}",
                    category=ScanCategory.VULNERABILITY,
                    severity=ScanSeverity(vuln_info['severity']),
                    title=f"Vulnerable Plugin: {plugin}",
                    description=vuln_info['description'],
                    url=f"{self.target_url}/wp-content/plugins/{plugin}/",
                    cvss_score=vuln_info.get('cvss'),
                    cve=vuln_info.get('cve'),
                    references=vuln_info.get('references', [])
                )
                
                vulnerabilities.append(finding)
                self.add_finding(finding)
        
        return vulnerabilities
    
    def _load_plugin_vulnerabilities(self) -> Dict[str, Dict]:
        """Load known plugin vulnerabilities database"""
        # This should be loaded from an external database or API
        # For now, using a hardcoded list
        return {
            'revslider': {
                'severity': 'critical',
                'description': 'RevSlider vulnerable to arbitrary file upload and SQL injection',
                'cvss': 9.8,
                'cve': 'CVE-2014-9732',
                'references': ['https://www.exploit-db.com/exploits/34511']
            },
            'formidable': {
                'severity': 'high',
                'description': 'Formidable Forms vulnerable to SQL injection',
                'cvss': 8.8,
                'cve': 'CVE-2015-9266',
                'references': ['https://www.exploit-db.com/exploits/36386']
            },
            'elementor': {
                'severity': 'medium',
                'description': 'Elementor Page Builder vulnerable to cross-site scripting',
                'cvss': 6.1,
                'cve': 'CVE-2020-13112',
                'references': ['https://www.exploit-db.com/exploits/48543']
            }
        }
    
    async def _check_theme_vulnerabilities(self) -> List[ScanFinding]:
        """Check for known theme vulnerabilities"""
        vulnerabilities = []
        known_vulnerabilities = self._load_theme_vulnerabilities()
        
        for theme in self.themes:
            if theme in known_vulnerabilities:
                vuln_info = known_vulnerabilities[theme]
                
                finding = ScanFinding(
                    id=f"VULN-THEME-{theme.upper()}",
                    category=ScanCategory.VULNERABILITY,
                    severity=ScanSeverity(vuln_info['severity']),
                    title=f"Vulnerable Theme: {theme}",
                    description=vuln_info['description'],
                    url=f"{self.target_url}/wp-content/themes/{theme}/",
                    cvss_score=vuln_info.get('cvss'),
                    cve=vuln_info.get('cve'),
                    references=vuln_info.get('references', [])
                )
                
                vulnerabilities.append(finding)
                self.add_finding(finding)
        
        return vulnerabilities
    
    def _load_theme_vulnerabilities(self) -> Dict[str, Dict]:
        """Load known theme vulnerabilities database"""
        return {
            'avada': {
                'severity': 'high',
                'description': 'Avada Theme vulnerable to multiple security issues',
                'cvss': 7.5,
                'cve': 'CVE-2015-4413',
                'references': ['https://www.exploit-db.com/exploits/37527']
            },
            'divi': {
                'severity': 'medium',
                'description': 'Divi Theme vulnerable to information disclosure',
                'cvss': 5.3,
                'references': ['https://www.wordfence.com/blog/2020/07/critical-vulnerability-in-divi-theme-and-visual-builder/']
            }
        }
    
    async def _check_core_vulnerabilities(self) -> List[ScanFinding]:
        """Check WordPress core version for vulnerabilities"""
        vulnerabilities = []
        
        # Try to detect WordPress version
        version = await self._detect_wordpress_version()
        
        if version:
            # Check version against known vulnerabilities
            # This should query an external vulnerability database
            if version < '5.0':
                finding = ScanFinding(
                    id="WP-CORE-OUTDATED",
                    category=ScanCategory.VULNERABILITY,
                    severity=ScanSeverity.HIGH,
                    title="Outdated WordPress Version",
                    description=f"WordPress version {version} is outdated and may contain vulnerabilities",
                    url=self.target_url,
                    cvss_score=7.2,
                    references=['https://wordpress.org/support/wordpress-version/version-' + version]
                )
                
                vulnerabilities.append(finding)
                self.add_finding(finding)
        
        return vulnerabilities
    
    async def _detect_wordpress_version(self) -> Optional[str]:
        """Detect WordPress version"""
        # Check readme.html
        response = await self.make_request(f"{self.target_url}/readme.html")
        if response and response.status == 200:
            content = await response.text()
            version_match = re.search(r'Version\s*([\d.]+)', content)
            if version_match:
                return version_match.group(1)
        
        # Check generator meta tag
        response = await self.make_request(self.target_url)
        if response and response.status == 200:
            content = await response.text()
            meta_match = re.search(r'content="WordPress\s*([\d.]+)"', content)
            if meta_match:
                return meta_match.group(1)
        
        return None
    
    async def _check_xmlrpc(self) -> Optional[ScanFinding]:
        """Check if XML-RPC is enabled and vulnerable"""
        url = f"{self.target_url}/xmlrpc.php"
        response = await self.make_request(url)
        
        if response and response.status == 200:
            content = await response.text()
            
            if 'XML-RPC' in content:
                # Check for pingback
                pingback_check = await self._check_xmlrpc_pingback()
                
                finding = ScanFinding(
                    id="WP-XMLRPC-ENABLED",
                    category=ScanCategory.VULNERABILITY,
                    severity=ScanSeverity.MEDIUM if pingback_check else ScanSeverity.LOW,
                    title="XML-RPC Interface Enabled",
                    description="XML-RPC is enabled which can be abused for DDoS attacks and brute force" + 
                               (" and pingback is enabled" if pingback_check else ""),
                    url=url,
                    cvss_score=5.3 if pingback_check else 3.7,
                    references=['https://wordpress.org/support/article/xml-rpc/']
                )
                
                self.add_finding(finding)
                return finding
        
        return None
    
    async def _check_xmlrpc_pingback(self) -> bool:
        """Check if XML-RPC pingback is enabled"""
        url = f"{self.target_url}/xmlrpc.php"
        
        # Try to call pingback.ping method
        xml_data = '''<?xml version="1.0"?>
        <methodCall>
            <methodName>pingback.ping</methodName>
            <params>
                <param><value><string>http://example.com/</string></value></param>
                <param><value><string>''' + self.target_url + '''</string></value></param>
            </params>
        </methodCall>'''
        
        response = await self.make_request(url, method='POST', data=xml_data)
        
        if response:
            content = await response.text()
            # If it returns something other than "XML-RPC services are disabled"
            # then pingback might be enabled
            return 'XML-RPC services are disabled' not in content
        
        return False
    
    async def _check_rest_api(self) -> Optional[ScanFinding]:
        """Check WordPress REST API exposure"""
        url = f"{self.target_url}/wp-json/"
        response = await self.make_request(url)
        
        if response and response.status == 200:
            try:
                data = await response.json()
                
                finding = ScanFinding(
                    id="WP-REST-API-EXPOSED",
                    category=ScanCategory.INFORMATION,
                    severity=ScanSeverity.LOW,
                    title="WordPress REST API Exposed",
                    description="REST API endpoints are publicly accessible",
                    url=url,
                    evidence=f"Available routes: {len(data.get('routes', {})) if isinstance(data, dict) else 'Unknown'}",
                    cvss_score=2.5
                )
                
                self.add_finding(finding)
                return finding
            except:
                pass
        
        return None
    
    async def check_directory_listing(self) -> List[str]:
        """Check for directory listing vulnerabilities"""
        directories = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/',
            '/wp-admin/',
            '/wp-content/',
        ]
        
        vulnerable_dirs = []
        
        tasks = [self._check_directory_listing(dir_path) for dir_path in directories]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str) and result:
                vulnerable_dirs.append(result)
                
                self.add_finding(
                    ScanFinding(
                        id="WP-DIR-LISTING",
                        category=ScanCategory.CONFIGURATION,
                        severity=ScanSeverity.MEDIUM,
                        title="Directory Listing Enabled",
                        description="Directory listing exposes sensitive files",
                        url=result,
                        cvss_score=5.3
                    )
                )
        
        return vulnerable_dirs
    
    async def _check_directory_listing(self, directory: str) -> Optional[str]:
        """Check if directory listing is enabled for a specific path"""
        url = f"{self.target_url}{directory}"
        response = await self.make_request(url)
        
        if response and response.status == 200:
            content = await response.text()
            
            # Check for directory listing indicators
            indicators = [
                'Index of',
                '<title>Index of',
                '<h1>Index of',
                'Parent Directory',
                'Directory listing for',
            ]
            
            for indicator in indicators:
                if indicator in content:
                    return url
        
        return None
    
    def add_finding(self, finding: ScanFinding):
        """Add a security finding to the results"""
        self.findings.append(finding)
        
        # Color-coded output
        color_map = {
            ScanSeverity.CRITICAL: Fore.RED,
            ScanSeverity.HIGH: Fore.YELLOW,
            ScanSeverity.MEDIUM: Fore.MAGENTA,
            ScanSeverity.LOW: Fore.CYAN,
            ScanSeverity.INFO: Fore.GREEN,
        }
        
        color = color_map.get(finding.severity, Fore.WHITE)
        print(f"{color}[{finding.severity.value.upper()}] {finding.title}{Style.RESET_ALL}")
        print(f"  URL: {finding.url}")
        if finding.description:
            print(f"  Description: {finding.description}")
        print()
    
    async def generate_report(self) -> Path:
        """Generate comprehensive scan report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = urlparse(self.target_url).netloc.replace('.', '_')
        
        report_dir = self.output_dir / safe_domain
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON report
        json_report = {
            'scan': {
                'target': self.target_url,
                'timestamp': timestamp,
                'duration': 'N/A',  # Would need to track start time
            },
            'findings': [finding.to_dict() for finding in self.findings],
            'discovered': {
                'users': list(self.users),
                'plugins': list(self.plugins),
                'themes': list(self.themes),
                'config_exposed': bool(self.config_data),
            }
        }
        
        json_path = report_dir / f"scan_report_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        # HTML report
        html_path = report_dir / f"scan_report_{timestamp}.html"
        self._generate_html_report(html_path, json_report)
        
        # Summary report
        summary_path = report_dir / f"scan_summary_{timestamp}.txt"
        self._generate_summary_report(summary_path)
        
        self.logger.info(f"Reports generated in: {report_dir}")
        return report_dir
    
    def _generate_html_report(self, path: Path, data: Dict):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>WordPress Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .critical { color: #d00; }
                .high { color: #f50; }
                .medium { color: #f80; }
                .low { color: #08c; }
                .info { color: #080; }
                .finding { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
                .severity { font-weight: bold; padding: 3px 8px; border-radius: 3px; }
                .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>WordPress Security Scan Report</h1>
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Time:</strong> {timestamp}</p>
                <p><strong>Findings:</strong> {findings_count} total</p>
            </div>
            
            <h2>Security Findings</h2>
            {findings_html}
            
            <h2>Discovered Information</h2>
            <p><strong>Users:</strong> {users_count}</p>
            <p><strong>Plugins:</strong> {plugins_count}</p>
            <p><strong>Themes:</strong> {themes_count}</p>
            
            <footer>
                <p>Generated by WordPress Security Scanner v2.0.0</p>
            </footer>
        </body>
        </html>
        """
        
        findings_html = ""
        for finding in self.findings:
            findings_html += f"""
            <div class="finding">
                <span class="severity {finding.severity.value}">{finding.severity.value.upper()}</span>
                <h3>{finding.title}</h3>
                <p><strong>URL:</strong> {finding.url}</p>
                <p>{finding.description}</p>
                <p><strong>CVSS:</strong> {finding.cvss_score or 'N/A'}</p>
                <p><strong>CVE:</strong> {finding.cve or 'N/A'}</p>
            </div>
            """
        
        html_content = html_template.format(
            target=data['scan']['target'],
            timestamp=data['scan']['timestamp'],
            findings_count=len(data['findings']),
            findings_html=findings_html,
            users_count=len(data['discovered']['users']),
            plugins_count=len(data['discovered']['plugins']),
            themes_count=len(data['discovered']['themes'])
        )
        
        with open(path, 'w') as f:
            f.write(html_content)
    
    def _generate_summary_report(self, path: Path):
        """Generate summary text report"""
        with open(path, 'w') as f:
            f.write(f"{'='*60}\n")
            f.write("WORDPRESS SECURITY SCAN REPORT\n")
            f.write(f"{'='*60}\n\n")
            
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("SUMMARY:\n")
            f.write(f"  Total Findings: {len(self.findings)}\n")
            f.write(f"  Critical: {sum(1 for f in self.findings if f.severity == ScanSeverity.CRITICAL)}\n")
            f.write(f"  High: {sum(1 for f in self.findings if f.severity == ScanSeverity.HIGH)}\n")
            f.write(f"  Medium: {sum(1 for f in self.findings if f.severity == ScanSeverity.MEDIUM)}\n")
            f.write(f"  Low: {sum(1 for f in self.findings if f.severity == ScanSeverity.LOW)}\n\n")
            
            f.write("DISCOVERED INFORMATION:\n")
            f.write(f"  Users: {len(self.users)}\n")
            f.write(f"  Plugins: {len(self.plugins)}\n")
            f.write(f"  Themes: {len(self.themes)}\n")
            
            if self.config_data:
                f.write("\nEXPOSED CONFIGURATION:\n")
                for key, value in self.config_data.items():
                    f.write(f"  {key}: {value}\n")
            
            if self.findings:
                f.write("\nDETAILED FINDINGS:\n")
                for finding in sorted(self.findings, key=lambda x: (-x.cvss_score or 0, x.severity.value)):
                    f.write(f"\n  [{finding.severity.value.upper()}] {finding.title}\n")
                    f.write(f"      URL: {finding.url}\n")
                    f.write(f"      Description: {finding.description}\n")
                    if finding.cvss_score:
                        f.write(f"      CVSS: {finding.cvss_score}\n")
    
    async def run_scan(self) -> Dict[str, Any]:
        """
        Run complete WordPress security scan
        
        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now()
        
        print(f"{Fore.CYAN}[*] Starting WordPress Security Scan{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Verify WordPress installation
        print(f"{Fore.CYAN}[*] Verifying WordPress installation...{Style.RESET_ALL}")
        if not await self.is_wordpress():
            print(f"{Fore.RED}[-] Target does not appear to be WordPress{Style.RESET_ALL}")
            return {'error': 'Not a WordPress site'}
        
        print(f"{Fore.GREEN}[+] WordPress detected{Style.RESET_ALL}")
        
        # Run all checks
        print(f"\n{Fore.CYAN}[*] Enumerating users...{Style.RESET_ALL}")
        users = await self.enumerate_users()
        
        print(f"\n{Fore.CYAN}[*] Enumerating plugins and themes...{Style.RESET_ALL}")
        plugins, themes = await self.enumerate_plugins_and_themes()
        
        print(f"\n{Fore.CYAN}[*] Checking for exposed configuration files...{Style.RESET_ALL}")
        await self.check_config_files()
        
        print(f"\n{Fore.CYAN}[*] Checking for vulnerabilities...{Style.RESET_ALL}")
        await self.check_vulnerabilities()
        
        print(f"\n{Fore.CYAN}[*] Checking directory listing...{Style.RESET_ALL}")
        await self.check_directory_listing()
        
        # Generate report
        print(f"\n{Fore.CYAN}[*] Generating reports...{Style.RESET_ALL}")
        report_dir = await self.generate_report()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        print(f"\n{Fore.GREEN}[+] Scan completed in {duration}{Style.RESET_ALL}")
        print(f"[+] Findings: {len(self.findings)} total")
        print(f"[+] Reports saved to: {report_dir}")
        
        return {
            'success': True,
            'duration': str(duration),
            'findings_count': len(self.findings),
            'users_count': len(users),
            'plugins_count': len(plugins),
            'themes_count': len(themes),
            'report_dir': str(report_dir)
        }


class BruteForceAttacker:
    """WordPress brute force attack module (for authorized testing only)"""
    
    def __init__(self, target_url: str, max_workers: int = 10):
        self.target_url = target_url.rstrip('/')
        self.max_workers = max_workers
        self.login_url = f"{self.target_url}/wp-login.php"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
        })
    
    def load_passwords(self, password_file: Path, limit: int = 10000) -> List[str]:
        """Load passwords from file with limit"""
        passwords = []
        
        if not password_file.exists():
            raise FileNotFoundError(f"Password file not found: {password_file}")
        
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    password = line.strip()
                    if password:
                        passwords.append(password)
        except Exception as e:
            raise Exception(f"Failed to load password file: {e}")
        
        return passwords
    
    def test_login(self, username: str, password: str) -> bool:
        """Test single login attempt"""
        try:
            # Get initial cookies
            self.session.get(self.login_url, timeout=5)
            
            # Prepare login data
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': f"{self.target_url}/wp-admin/",
                'testcookie': '1'
            }
            
            # Attempt login
            response = self.session.post(
                self.login_url,
                data=login_data,
                timeout=10,
                allow_redirects=True
            )
            
            # Check for successful login indicators
            success_indicators = [
                'wp-admin', 'dashboard', 'logout',
                'profile.php', 'admin-ajax.php'
            ]
            
            for indicator in success_indicators:
                if indicator in response.url or indicator in response.text:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def run_attack(self, usernames: List[str], passwords: List[str]) -> Dict[str, str]:
        """
        Run brute force attack
        
        Warning: Only use on systems you own or have explicit permission to test
        """
        results = {}
        
        print(f"[*] Starting brute force attack on {self.target_url}")
        print(f"[*] Usernames: {len(usernames)}")
        print(f"[*] Passwords: {len(passwords)}")
        print(f"[*] Max workers: {self.max_workers}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create all combinations
            futures = []
            for username in usernames[:5]:  # Limit to first 5 users
                for password in passwords[:1000]:  # Limit to first 1000 passwords
                    futures.append(
                        executor.submit(self._test_combination, username, password)
                    )
            
            # Process results
            for future in as_completed(futures):
                result = future.result()
                if result:
                    username, password = result
                    results[username] = password
                    print(f"[+] Found credentials: {username}:{password}")
        
        return results
    
    def _test_combination(self, username: str, password: str) -> Optional[Tuple[str, str]]:
        """Test username/password combination"""
        if self.test_login(username, password):
            return (username, password)
        return None


def parse_arguments():
    """Parse command line arguments"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='WordPress Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --output ./results --timeout 30
  %(prog)s https://example.com --no-ssl-verify --workers 50
        """
    )
    
    parser.add_argument('target', help='Target WordPress URL')
    parser.add_argument('-o', '--output', default='scan_results',
                       help='Output directory (default: scan_results)')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('-w', '--workers', type=int, default=MAX_CONCURRENT_REQUESTS,
                       help=f'Maximum concurrent workers (default: {MAX_CONCURRENT_REQUESTS})')
    parser.add_argument('--no-ssl-verify', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('--brute-force', action='store_true',
                       help='Enable brute force module (requires explicit authorization)')
    parser.add_argument('--password-file', default='passwords.txt',
                       help='Password file for brute force (default: passwords.txt)')
    
    return parser.parse_args()


async def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize scanner
    scanner = WordPressScanner(
        target_url=args.target,
        output_dir=output_dir,
        max_workers=args.workers,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify
    )
    
    try:
        # Run scan
        async with scanner:
            results = await scanner.run_scan()
        
        # Brute force (if enabled and authorized)
        if args.brute_force:
            print(f"\n{Fore.YELLOW}[!] WARNING: Brute force attacks should only be performed on systems you own{Style.RESET_ALL}")
            confirm = input("Do you have explicit authorization to perform brute force? (yes/no): ")
            
            if confirm.lower() == 'yes':
                attacker = BruteForceAttacker(args.target)
                passwords = attacker.load_passwords(Path(args.password_file))
                
                # Use discovered users or default list
                users = list(scanner.users) if scanner.users else ['admin', 'administrator']
                
                credentials = attacker.run_attack(users, passwords)
                
                if credentials:
                    print(f"\n{Fore.GREEN}[+] Found {len(credentials)} valid credentials{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.YELLOW}[-] No valid credentials found{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
    
    finally:
        print(f"\n{Fore.CYAN}[*] Scan completed{Style.RESET_ALL}")


if __name__ == "__main__":
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    # Run async main
    asyncio.run(main())
