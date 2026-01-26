#!/usr/bin/env python3
"""
Config.py - Configuración del sistema para LUMA SCANNER
"""

import os
import yaml
import logging
import random
from dataclasses import dataclass, field
from typing import List


@dataclass
class ScannerConfig:
    """Configuración completa del scanner - MODO ULTRA AGGRESIVO"""
    request_timeout: int = 30
    connection_timeout: int = 15
    max_connections: int = 500
    max_redirects: int = 20
    
    user_agents: List[str] = field(default_factory=lambda: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'Aggressive-Security-Scanner/v5.0'
    ])
    
    proxy_enabled: bool = False
    proxy_url: str = ""
    proxy_username: str = ""
    proxy_password: str = ""
    
    thread_pool_size: int = 100
    max_concurrent_scans: int = 50
    scan_delay: float = 0.01
    
    scan_depth: int = 10
    max_pages_to_crawl: int = 2000
    follow_robots_txt: bool = False
    aggressive_mode: bool = True
    
    web_scan_types: List[str] = field(default_factory=lambda: ['sqli', 'xss', 'lfi', 'ssrf', 'xxe', 'rce', 'idor', 'ssi', 'ssti', 'nosqli'])
    
    jadx_path: str = "jadx"
    apktool_path: str = "apktool"
    decompile_enabled: bool = True
    use_external_tools: bool = True
    
    output_directory: str = "SCAN_RESULTS"
    auto_save: bool = True
    save_logs: bool = True
    generate_reports: bool = True
    
    two_fa_scanning: bool = True
    two_fa_bypass_methods: List[str] = field(default_factory=lambda: [
        'otp_bypass',
        'response_manipulation', 
        'timeout_exploit',
        'code_reuse',
        'silver_ticket',
        'jwt_tampering',
        'session_hijacking'
    ])
    
    verify_ssl: bool = False
    randomize_user_agent: bool = True
    
    # NUEVO: Configuración para ataque masivo
    mass_scan_enabled: bool = True
    max_targets_per_scan: int = 100
    auto_find_targets: bool = True
    use_shodan: bool = False
    shodan_api_key: str = ""
    use_censys: bool = False
    censys_api_key: str = ""
    
    # Configuración para auto-exploit
    auto_exploit_databases: bool = True
    auto_exploit_firebase: bool = True
    auto_exploit_sql: bool = True
    save_full_files: bool = True
    
    @classmethod
    def from_file(cls, config_path: str = "scanner_config.yaml") -> 'ScannerConfig':
        """Cargar configuración desde archivo"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}
                
                # Filtrar solo los campos que existen en la clase
                valid_fields = cls.__dataclass_fields__.keys()
                filtered_data = {k: v for k, v in data.items() if k in valid_fields}
                
                return cls(**filtered_data)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
        return cls()
    
    def save(self, config_path: str = "scanner_config.yaml"):
        """Guardar configuración a archivo"""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.__dict__, f, default_flow_style=False)
        except Exception as e:
            logging.error(f"Error saving config: {e}")
    
    def get_random_user_agent(self) -> str:
        """Obtener user agent aleatorio"""
        if self.randomize_user_agent and self.user_agents:
            return random.choice(self.user_agents)
        return self.user_agents[0] if self.user_agents else 'Aggressive-Security-Scanner/v5.0'


# Configuración global
CONFIG = ScannerConfig.from_file()

# Configuración de logging
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('UltimateSecurityScanner')
logger.setLevel(logging.INFO)

# Configurar file handler si save_logs está habilitado
if CONFIG.save_logs:
    try:
        file_handler = logging.FileHandler('scanner_aggressive.log', encoding='utf-8')
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"⚠ No se pudo configurar file handler: {e}")

# Configurar console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)