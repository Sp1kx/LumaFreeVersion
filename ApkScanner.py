#!/usr/bin/env python3
"""
ApkScanner.py - Módulo de escaneo de APKs con auto-exploit para LUMA SCANNER
"""

import os
import re
import json
import zipfile
import tempfile
import subprocess
import sqlite3
from datetime import datetime
from typing import Dict, List
import traceback

from PySide6.QtCore import QThread, Signal, QTimer

from FileOrganizer import FileOrganizer
from Config import CONFIG
from WebScanner import DatabaseAutoExploiter


class UltraAPKScanner(QThread):
    """APK Scanner ULTRA mejorado con análisis profundo y auto-exploit"""
    
    progress_signal = Signal(int, str)
    result_signal = Signal(str, str, str, str)
    log_signal = Signal(str)
    
    def __init__(self, apk_path: str, options: Dict):
        super().__init__()
        self.apk_path = apk_path
        self.options = options
        self.extracted_dir = ""
        self.findings = []
        self.apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        self.credentials_found = {}
        self.database_exploiter = DatabaseAutoExploiter(log_callback=self.log_signal.emit)
        
    def run(self):
        """Ejecutar análisis APK ultra"""
        try:
            self.progress_signal.emit(5, "📦 Verificando archivo APK...")
            if not self.validate_apk():
                return
            
            self.progress_signal.emit(10, "📂 Extrayendo APK...")
            self.extracted_dir = self.extract_apk()
            if not self.extracted_dir:
                return
            
            self.progress_signal.emit(20, "🔍 Analizando AndroidManifest.xml...")
            self.analyze_manifest()
            
            self.progress_signal.emit(30, "🔐 Buscando claves y tokens COMPLETOS...")
            self.find_keys_and_tokens_complete()
            
            self.progress_signal.emit(40, "🌐 Buscando URLs y endpoints COMPLETOS...")
            self.find_urls_and_endpoints_complete()
            
            self.progress_signal.emit(50, "💾 Buscando bases de datos...")
            self.find_databases()
            
            self.progress_signal.emit(60, "📄 Analizando recursos COMPLETOS...")
            self.analyze_resources_complete()
            
            self.progress_signal.emit(70, "🔧 Descompilando código...")
            self.decompile_code()
            
            self.progress_signal.emit(75, "🔥 AUTO-EXPLOIT DE BASES DE DATOS...")
            self.auto_exploit_all_databases()
            
            self.progress_signal.emit(80, "⚠️ Buscando vulnerabilidades...")
            self.find_vulnerabilities()
            
            self.progress_signal.emit(90, "📊 Generando reporte COMPLETO...")
            self.generate_complete_report()
            
            self.progress_signal.emit(100, "✅ Análisis APK COMPLETO con AUTO-EXPLOIT")
            
        except Exception as e:
            self.log_signal.emit(f"❌ Error en análisis APK: {str(e)}")
            traceback.print_exc()
    
    def validate_apk(self) -> bool:
        """Validar que el archivo sea un APK válido"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                if 'AndroidManifest.xml' not in z.namelist():
                    self.log_signal.emit("❌ No es un APK válido")
                    return False
            return True
        except:
            self.log_signal.emit("❌ Error al abrir el APK")
            return False
    
    def extract_apk(self) -> str:
        """Extraer contenido del APK"""
        try:
            temp_dir = tempfile.mkdtemp(prefix="apk_scan_")
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                z.extractall(temp_dir)
            return temp_dir
        except Exception as e:
            self.log_signal.emit(f"❌ Error extrayendo APK: {e}")
            return ""
    
    def analyze_manifest(self):
        """Analizar AndroidManifest.xml para permisos y componentes"""
        manifest_path = os.path.join(self.extracted_dir, 'AndroidManifest.xml')
        if not os.path.exists(manifest_path):
            return
        
        try:
            # Leer y analizar el manifest COMPLETO
            with open(manifest_path, 'rb') as f:
                content = f.read()
            
            # Convertir a texto si es binario
            try:
                content_str = content.decode('utf-8')
            except:
                content_str = str(content)
            
            # Guardar archivo COMPLETO
            FileOrganizer.save_full_file_content(
                "APK", "INFO", "MANIFEST_COMPLETO",
                manifest_path, content_str, self.apk_name
            )
            
            # Buscar permisos peligrosos
            dangerous_perms = [
                'android.permission.INTERNET',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_CONTACTS',
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE',
            ]
            
            for perm in dangerous_perms:
                if perm.encode() in content or perm in content_str:
                    self.report_finding_complete(
                        'PERMISO_PELIGROSO',
                        'MEDIUM',
                        'AndroidManifest.xml',
                        f"Permiso peligroso encontrado: {perm}",
                        full_content=content_str
                    )
            
            # Buscar componentes exportados
            exported_patterns = [
                b'android:exported="true"',
                b'exported="true"'
            ]
            
            for pattern in exported_patterns:
                if pattern in content:
                    self.report_finding_complete(
                        'COMPONENTE_EXPORTADO',
                        'HIGH',
                        'AndroidManifest.xml',
                        "Componente exportado encontrado (posible vulnerabilidad)",
                        full_content=content_str
                    )
                    break
                    
        except Exception as e:
            self.log_signal.emit(f"⚠ Error analizando manifest: {e}")
    
    def find_keys_and_tokens_complete(self):
        """Buscar claves API, tokens y credenciales - COPIA COMPLETA"""
        patterns = {
            'API_KEY': r'[A-Za-z0-9]{32,}',
            'FIREBASE': r'AAAA[A-Za-z0-9_-]{100,}',
            'AWS_KEY': r'AKIA[0-9A-Z]{16}',
            'GOOGLE_API': r'AIza[0-9A-Za-z_-]{35}',
            'STRIPE_KEY': r'(sk|pk)_(live|test)_[0-9a-zA-Z]{24}',
            'TWILIO': r'AC[0-9a-fA-F]{32}',
            'EMAIL': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'PASSWORD': r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']',
            'DATABASE_URL': r'(mysql|postgresql|mongodb)://[^\s"\']+',
            'JWT_TOKEN': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'ACCESS_TOKEN': r'access_token["\']?\s*[:=]\s*["\'][^"\']{20,}["\']',
            'SECRET_KEY': r'secret["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
        }
        
        found_credentials = {}
        
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.java', '.kt', '.xml', '.json', '.gradle', '.properties', '.config', '.txt', '.yaml', '.yml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Guardar archivo completo si contiene credenciales
                        file_has_credentials = False
                        
                        for key_type, pattern in patterns.items():
                            matches = re.findall(pattern, content)
                            for match in matches:
                                if len(match) > 5:
                                    # GUARDAR VALOR COMPLETO
                                    self.report_finding_complete(
                                        f'{key_type}_ENCONTRADO',
                                        'CRITICAL' if key_type in ['API_KEY', 'AWS_KEY', 'FIREBASE', 'DATABASE_URL'] else 'HIGH',
                                        os.path.relpath(file_path, self.extracted_dir),
                                        f"{key_type}: {match}",
                                        full_content=content
                                    )
                                    
                                    file_has_credentials = True
                                    
                                    # Guardar en diccionario de credenciales
                                    if key_type not in found_credentials:
                                        found_credentials[key_type] = []
                                    found_credentials[key_type].append({
                                        'value': match,
                                        'file': os.path.relpath(file_path, self.extracted_dir),
                                        'context': self.extract_context(content, match)
                                    })
                                    
                                    # Si es Firebase o Database URL, marcar para auto-exploit
                                    if key_type in ['FIREBASE', 'DATABASE_URL']:
                                        self.log_signal.emit(f"🔥 {key_type} encontrado - Preparando AUTO-EXPLOIT")
                        
                        # Si el archivo es sensible, guardarlo completo
                        if file_has_credentials and CONFIG.save_full_files:
                            FileOrganizer.save_full_file_content(
                                "APK", "HIGH", "ARCHIVO_CON_CREDENCIALES",
                                file_path, content, self.apk_name
                            )
                    
                    except Exception as e:
                        continue
        
        # Guardar todas las credenciales encontradas
        if found_credentials:
            FileOrganizer.save_credentials_found("APK", found_credentials, self.apk_name)
            self.log_signal.emit(f"✅ Se encontraron {sum(len(v) for v in found_credentials.values())} credenciales")
    
    def extract_context(self, content: str, match: str, lines_before: int = 3, lines_after: int = 3) -> str:
        """Extraer contexto alrededor de un match"""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if match in line:
                start = max(0, i - lines_before)
                end = min(len(lines), i + lines_after + 1)
                context_lines = lines[start:end]
                return '\n'.join(context_lines)
        return ""
    
    def find_urls_and_endpoints_complete(self):
        """Buscar URLs y endpoints en el código - COPIA COMPLETA"""
        url_patterns = [
            r'https?://[^\s<>"\']+',
            r'www\.[^\s<>"\']+\.[a-z]{2,}',
            r'[a-z]+://[^\s<>"\']+',
            r'api\.[^\s<>"\']+\.[a-z]{2,}',
            r'[a-zA-Z0-9.-]+\.[a-z]{2,}/[^\s<>"\']*',
        ]
        
        endpoints_found = []
        
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.java', '.kt', '.xml', '.json', '.smali', '.txt', '.config')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        for pattern in url_patterns:
                            matches = re.findall(pattern, content)
                            for url in matches:
                                # Filtrar URLs comunes/falsos positivos
                                if any(common in url.lower() for common in 
                                      ['google.com', 'android.com', 'example.com', 'localhost', '127.0.0.1']):
                                    continue
                                
                                if url not in endpoints_found:
                                    endpoints_found.append(url)
                                    # COPIAR URL COMPLETA
                                    self.report_finding_complete(
                                        'URL_ENCONTRADA',
                                        'MEDIUM',
                                        file,
                                        f"URL: {url}",
                                        full_content=content
                                    )
                    except:
                        continue
        
        # Guardar todas las URLs encontradas
        if endpoints_found:
            urls_file = {
                'total_urls': len(endpoints_found),
                'urls': endpoints_found,
                'apk': self.apk_name,
                'timestamp': datetime.now().isoformat()
            }
            
            FileOrganizer.save_apk_finding(
                "APK", "INFO", "TODAS_URLS_ENCONTRADAS",
                "all_urls.json", 
                f"Total URLs encontradas: {len(endpoints_found)}\n\n" + '\n'.join(endpoints_found),
                self.apk_name,
                full_content=json.dumps(urls_file, indent=2)
            )
    
    def find_databases(self):
        """Buscar archivos de base de datos"""
        db_extensions = ['.db', '.sqlite', '.sqlite3', '.db3', '.sql']
        
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if any(file.endswith(ext) for ext in db_extensions):
                    db_path = os.path.join(root, file)
                    size = os.path.getsize(db_path)
                    
                    # COPIAR ARCHIVO DE BASE DE DATOS COMPLETO
                    try:
                        with open(db_path, 'rb') as f:
                            db_content = f.read()
                        
                        # Guardar como texto si es posible
                        try:
                            content_str = db_content.decode('utf-8')
                        except:
                            content_str = str(db_content[:10000]) + f"\n\n[Archivo binario, tamaño: {size} bytes]"
                        
                        self.report_finding_complete(
                            'BASE_DATOS_ENCONTRADA',
                            'HIGH',
                            file,
                            f"Base de datos encontrada: {file} ({size} bytes)",
                            full_content=content_str
                        )
                        
                        # Intentar extraer información de la base de datos
                        self.extract_db_info(db_path, file)
                        
                    except Exception as e:
                        self.log_signal.emit(f"⚠ Error leyendo base de datos {file}: {e}")
    
    def extract_db_info(self, db_path: str, filename: str):
        """Extraer información de base de datos SQLite"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Obtener tablas
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            db_info = {
                'path': db_path,
                'tables': [],
                'total_tables': len(tables),
                'apk': self.apk_name
            }
            
            if tables:
                table_list = []
                for table in tables[:20]:  # Limitar a 20 tablas
                    table_name = table[0]
                    table_list.append(table_name)
                    
                    # Obtener estructura de cada tabla
                    try:
                        cursor.execute(f"PRAGMA table_info({table_name})")
                        columns = cursor.fetchall()
                        
                        # Obtener conteo de filas
                        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                        row_count = cursor.fetchone()[0]
                        
                        db_info['tables'].append({
                            'name': table_name,
                            'columns': columns,
                            'row_count': row_count
                        })
                        
                        # Si tiene datos, obtener muestras
                        if row_count > 0 and row_count < 100:
                            cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
                            sample_data = cursor.fetchall()
                            db_info['tables'][-1]['sample_data'] = sample_data
                        
                        # Buscar columnas sensibles
                        sensitive_columns = []
                        for col in columns:
                            col_name = col[1].lower()
                            if any(keyword in col_name for keyword in ['pass', 'pwd', 'token', 'key', 'secret', 'email', 'phone', 'credit']):
                                sensitive_columns.append(col_name)
                        
                        if sensitive_columns:
                            db_info['tables'][-1]['sensitive_columns'] = sensitive_columns
                            self.log_signal.emit(f"🚨 Tabla {table_name} tiene columnas sensibles: {sensitive_columns}")
                            
                    except Exception as e:
                        continue
                
                if table_list:
                    self.report_finding_complete(
                        'TABLAS_DB',
                        'INFO',
                        filename,
                        f"Tablas encontradas: {', '.join(table_list[:10])}" + 
                        (f" y {len(table_list)-10} más" if len(table_list) > 10 else ""),
                        full_content=json.dumps(db_info, indent=2, default=str)
                    )
            
            conn.close()
            
            # Guardar información completa de la base de datos
            FileOrganizer.save_database_exploit_result("APK", "SQLITE_INFO", db_info)
            
        except Exception as e:
            self.log_signal.emit(f"⚠ Error extrayendo info SQLite {filename}: {e}")
    
    def analyze_resources_complete(self):
        """Analizar recursos y assets - COPIANDO ARCHIVOS COMPLETOS"""
        interesting_patterns = [
            'backup', 'password', 'secret', 'key', 'config', '.env',
            'settings', 'credential', 'auth', 'token', 'api',
            'firebase', 'database', 'mysql', 'postgres', 'mongodb',
            'admin', 'root', 'login', 'user'
        ]
        
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                file_lower = file.lower()
                
                # Archivos sensibles
                if any(pattern in file_lower for pattern in interesting_patterns):
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Leer contenido COMPLETO
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        rel_path = os.path.relpath(file_path, self.extracted_dir)
                        
                        # Guardar hallazgo CON CONTENIDO COMPLETO
                        self.report_finding_complete(
                            'ARCHIVO_SENSIBLE',
                            'MEDIUM',
                            rel_path,
                            f"Archivo sensible encontrado: {file}",
                            full_content=content
                        )
                        
                        # También guardar como archivo completo
                        FileOrganizer.save_full_file_content(
                            "APK", "MEDIUM", "ARCHIVO_SENSIBLE_COMPLETO",
                            file_path, content, self.apk_name
                        )
                        
                    except Exception as e:
                        # Si es binario, guardar información básica
                        try:
                            size = os.path.getsize(file_path)
                            self.report_finding_complete(
                                'ARCHIVO_SENSIBLE_BINARIO',
                                'MEDIUM',
                                os.path.relpath(file_path, self.extracted_dir),
                                f"Archivo binario sensible: {file} ({size} bytes)",
                                full_content=f"Archivo binario, tamaño: {size} bytes"
                            )
                        except:
                            continue
    
    def auto_exploit_all_databases(self):
        """Auto-exploit ULTRA agresivo para todas las bases de datos encontradas"""
        if not CONFIG.auto_exploit_databases:
            return
        
        self.log_signal.emit("🔥 INICIANDO AUTO-EXPLOIT ULTRA PARA TODAS LAS BASES DE DATOS")
        
        # Buscar configuraciones de Firebase
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.json', '.xml', '.java', '.kt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Buscar configuraciones de Firebase
                        firebase_patterns = [
                            r'"apiKey"\s*:\s*"[^"]+"',
                            r'AAAA[A-Za-z0-9_-]{100,}',
                            r'firebase',
                            r'Firebase'
                        ]
                        
                        has_firebase = any(re.search(pattern, content, re.IGNORECASE) for pattern in firebase_patterns)
                        
                        if has_firebase:
                            self.log_signal.emit(f"🔥 Firebase detectado en {file}")
                            
                            # Intentar extraer configuración completa
                            firebase_config = self.extract_firebase_config(content)
                            if firebase_config:
                                # Ejecutar auto-exploit
                                exploit_result = self.database_exploiter.exploit_firebase_ultra(
                                    firebase_config, 
                                    os.path.relpath(file_path, self.extracted_dir)
                                )
                                
                                if exploit_result:
                                    # Guardar resultado del exploit
                                    FileOrganizer.save_database_exploit_result(
                                        "APK", "FIREBASE_EXPLOIT", exploit_result
                                    )
                                    self.log_signal.emit(f"✅ Auto-exploit Firebase completado")
                    
                    except:
                        continue
        
        # Buscar y explotar archivos SQLite
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.db', '.sqlite', '.sqlite3')):
                    db_path = os.path.join(root, file)
                    self.log_signal.emit(f"🔥 SQLite detectado: {file}")
                    
                    db_info = {
                        "type": "SQLITE",
                        "path": db_path,
                        "apk": self.apk_name,
                        "source": os.path.relpath(db_path, self.extracted_dir)
                    }
                    
                    # Ejecutar auto-exploit
                    exploit_result = self.database_exploiter.exploit_sqlite(db_info, {})
                    
                    if exploit_result:
                        FileOrganizer.save_database_exploit_result(
                            "APK", "SQLITE_EXPLOIT", exploit_result
                        )
                        self.log_signal.emit(f"✅ Auto-exploit SQLite completado para {file}")
    
    def extract_firebase_config(self, content: str) -> str:
        """Extraer configuración de Firebase del contenido"""
        try:
            # Buscar objeto JSON de Firebase
            patterns = [
                r'\{[^{}]*?"apiKey"[^{}]*\}',
                r'FirebaseOptions\s*\.\s*fromJson\s*\([^)]+\)',
                r'firebaseConfig\s*=\s*\{[^}]+\}',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
                if match:
                    return match.group(0)
            
            return content[:2000]  # Devolver parte del contenido si no se encuentra patrón específico
            
        except:
            return ""
    
    def decompile_code(self):
        """Intentar descompilar el código si hay herramientas disponibles"""
        if not self.options.get('decompile', False):
            return
        
        tools = ['jadx', 'apktool']
        for tool in tools:
            try:
                subprocess.run([tool, '--version'], capture_output=True, check=True)
                
                if tool == 'jadx':
                    output_dir = os.path.join(self.extracted_dir, 'jadx_output')
                    os.makedirs(output_dir, exist_ok=True)
                    
                    cmd = [tool, self.apk_path, '-d', output_dir]
                    result = subprocess.run(cmd, capture_output=True, timeout=60)
                    
                    if result.returncode == 0:
                        self.log_signal.emit(f"✅ Descompilación con {tool} completada")
                elif tool == 'apktool':
                    output_dir = os.path.join(self.extracted_dir, 'apktool_output')
                    cmd = ['apktool', 'd', self.apk_path, '-o', output_dir]
                    result = subprocess.run(cmd, capture_output=True, timeout=60)
                    
                    if result.returncode == 0:
                        self.log_signal.emit(f"✅ Desensamblaje con {tool} completado")
                        
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
    
    def find_vulnerabilities(self):
        """Buscar vulnerabilidades específicas"""
        # 1. Buscar certificados débiles
        cert_dir = os.path.join(self.extracted_dir, 'META-INF')
        if os.path.exists(cert_dir):
            self.report_finding_complete(
                'CERTIFICADO_ENCONTRADO',
                'INFO',
                'META-INF/',
                "Certificados de firma encontrados",
                full_content=str(os.listdir(cert_dir))
            )
        
        # 2. Buscar código vulnerable
        vulnerable_patterns = [
            (r'Runtime\.getRuntime\(\)\.exec\(', 'RCE_POTENCIAL'),
            (r'loadUrl\s*\(\s*["\']javascript:', 'WEBVIEW_RCE'),
            (r'addJavascriptInterface', 'JS_INTERFACE'),
            (r'Cipher\.getInstance\s*\(\s*["\']DES', 'CRYPTO_WEAK'),
            (r'HttpURLConnection', 'HTTP_PLAIN'),
            (r'android:debuggable\s*=\s*["\']true["\']', 'DEBUGGABLE_APP'),
        ]
        
        for root, dirs, files in os.walk(self.extracted_dir):
            for file in files:
                if file.endswith(('.java', '.smali', '.xml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        for pattern, vuln_type in vulnerable_patterns:
                            if re.search(pattern, content):
                                self.report_finding_complete(
                                    vuln_type,
                                    'HIGH',
                                    file,
                                    f"Posible vulnerabilidad: {vuln_type}",
                                    full_content=self.extract_context(content, pattern)
                                )
                    except:
                        continue
    
    def generate_complete_report(self):
        """Generar reporte COMPLETO del análisis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = f"SCAN_RESULTS/SCANNER_APK/REPORTS"
        
        os.makedirs(report_dir, exist_ok=True)
        
        # Generar reporte JSON COMPLETO
        report_data = {
            'apk': self.apk_path,
            'apk_name': self.apk_name,
            'analysis_date': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'findings_by_severity': {
                'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'INFO': len([f for f in self.findings if f['severity'] == 'INFO']),
            },
            'findings': self.findings,
            'credentials_found': self.credentials_found,
        }
        
        report_path = os.path.join(report_dir, f'{self.apk_name}_REPORT_COMPLETO.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        # Generar reporte de texto EJECUTIVO
        text_report = f"""⚡ LUMA SCANNER v5.0 - APK ANALYSIS REPORT COMPLETO
═══════════════════════════════════════════════════════════════════════
APK: {os.path.basename(self.apk_path)}
APK Name: {self.apk_name}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Findings: {len(self.findings)}
═══════════════════════════════════════════════════════════════════════
RESUMEN POR SEVERIDAD:
• CRITICAL: {report_data['findings_by_severity']['CRITICAL']}
• HIGH: {report_data['findings_by_severity']['HIGH']}
• MEDIUM: {report_data['findings_by_severity']['MEDIUM']}
• INFO: {report_data['findings_by_severity']['INFO']}
═══════════════════════════════════════════════════════════════════════
HALLAZGOS CRÍTICOS:
"""
        
        critical_findings = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
        for i, finding in enumerate(critical_findings[:20], 1):
            text_report += f"\n{i}. [{finding['severity']}] {finding['type']}\n"
            text_report += f"   File: {finding['file']}\n"
            text_report += f"   Details: {finding['details'][:200]}...\n"
        
        text_report += "\n═══════════════════════════════════════════════════════════════════════\n"
        text_report += "NOTAS:\n"
        text_report += "• Todos los archivos sensibles fueron guardados COMPLETOS en SCAN_RESULTS/SCANNER_APK/FULL_FILES/\n"
        text_report += "• Credenciales encontradas guardadas en SCAN_RESULTS/SCANNER_APK/DATABASES/\n"
        text_report += "• Resultados de auto-exploit guardados en SCAN_RESULTS/SCANNER_APK/EXPLOITS/\n"
        text_report += "═══════════════════════════════════════════════════════════════════════\n"
        text_report += "Made By @sp1kz - ULTRA APK Scanner with AUTO-EXPLOIT\n"
        
        text_path = os.path.join(report_dir, f'{self.apk_name}_REPORT_EJECUTIVO.txt')
        with open(text_path, 'w', encoding='utf-8') as f:
            f.write(text_report)
        
        self.log_signal.emit(f"📄 Reporte APK COMPLETO guardado en: {report_dir}")
    
    def report_finding_complete(self, finding_type: str, severity: str, file: str, details: str, full_content: str = None):
        """Reportar un hallazgo CON CONTENIDO COMPLETO"""
        finding = {
            'type': finding_type,
            'severity': severity,
            'file': file,
            'details': details,
            'full_content_present': full_content is not None,
            'full_content_length': len(full_content) if full_content else 0,
            'timestamp': datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        self.result_signal.emit(finding_type, severity, file, details)
        
        # Guardar en archivo organizado CON CONTENIDO COMPLETO
        try:
            filepath = FileOrganizer.save_apk_finding(
                "APK", severity, finding_type, file, details, self.apk_name, full_content
            )
            self.log_signal.emit(f"📁 Guardado COMPLETO en: {filepath}")
        except Exception as e:
            self.log_signal.emit(f"⚠ Error guardando hallazgo completo: {e}")
        
        # Mostrar hallazgos críticos inmediatamente
        if severity in ['CRITICAL', 'HIGH']:
            self.log_signal.emit(f"🚨 {severity}: {finding_type} en {file}")
            if full_content and len(full_content) < 500:
                self.log_signal.emit(f"   📄 Contenido: {full_content[:200]}...")