#!/usr/bin/env python3
"""
FileOrganizer.py - Sistema de organización de archivos para LUMA SCANNER
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, Optional


class FileOrganizer:
    """Organizador de archivos para resultados de escaneo"""
    
    @staticmethod
    def setup_directory_structure(base_dir: str, scan_type: str):
        """Crear estructura de carpetas para los resultados"""
        scan_dir = os.path.join(base_dir, f"SCANNER_{scan_type.upper()}")
        
        folders = [
            "CRITICAL",
            "HIGH", 
            "MEDIUM",
            "INFO",
            "DATABASES",
            "SHELLS",
            "LOGS",
            "REPORTS",
            "FULL_FILES",
            "EXPLOITS"
        ]
        
        # Agregar carpetas específicas para WordPress
        if scan_type.upper() == "WORDPRESS":
            wordpress_folders = [
                "WP_CONFIGS",
                "ADMIN_CREDENTIALS", 
                "DATABASE_DUMPS",
                "DATABASE_BACKUPS",
                "DIRECTORY_LISTINGS",
                "PLUGIN_EXPLOITS",
                "THEME_EXPLOITS"
            ]
            folders.extend(wordpress_folders)
        
        for folder in folders:
            os.makedirs(os.path.join(scan_dir, folder), exist_ok=True)
        
        return scan_dir
    
    @staticmethod
    def save_vulnerability(scan_type: str, severity: str, vuln_type: str, 
                          target: str, details: str, extra_data: Dict = None):
        """Guardar vulnerabilidad en la carpeta correspondiente"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = "SCAN_RESULTS"
        
        # Crear estructura de carpetas
        scan_dir = FileOrganizer.setup_directory_structure(base_dir, scan_type)
        
        # Determinar carpeta basada en severidad
        if severity in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
            target_folder = severity
        else:
            target_folder = "INFO"
        
        # Crear nombre de archivo seguro
        safe_target = re.sub(r'[^\w\-_\. ]', '_', target[:50])
        safe_vuln = re.sub(r'[^\w\-_\. ]', '_', vuln_type[:30])
        filename = f"{timestamp}_{safe_vuln}_{safe_target}.txt"
        filepath = os.path.join(scan_dir, target_folder, filename)
        
        # Guardar archivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Scan Type: {scan_type}\n")
            f.write(f"Severity: {severity}\n")
            f.write(f"Vulnerability Type: {vuln_type}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
            f.write(f"Details:\n{details}\n")
            
            if extra_data:
                f.write("\nExtra Data:\n")
                for key, value in extra_data.items():
                    f.write(f"{key}: {value}\n")
        
        return filepath
    
    @staticmethod
    def save_full_file_content(scan_type: str, severity: str, finding_type: str,
                              file_path: str, content: str, apk_name: str = None):
        """Guardar contenido COMPLETO de un archivo encontrado"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = "SCAN_RESULTS"
        
        # Crear estructura de carpetas
        scan_dir = FileOrganizer.setup_directory_structure(base_dir, scan_type)
        
        # Nombre seguro del archivo
        file_name = os.path.basename(file_path)
        safe_name = re.sub(r'[^\w\-_\. ]', '_', file_name[:50])
        safe_type = re.sub(r'[^\w\-_\. ]', '_', finding_type[:20])
        filename = f"{timestamp}_{safe_type}_{safe_name}.txt"
        filepath = os.path.join(scan_dir, "FULL_FILES", filename)
        
        # Guardar contenido COMPLETO
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Scan Type: {scan_type}\n")
            if apk_name:
                f.write(f"APK: {apk_name}\n")
            f.write(f"Severity: {severity}\n")
            f.write(f"Finding Type: {finding_type}\n")
            f.write(f"Original File: {file_path}\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
            f.write(f"File Size: {len(content)} bytes\n")
            f.write(f"\n{'='*80}\n")
            f.write("CONTENIDO COMPLETO DEL ARCHIVO:\n")
            f.write(f"{'='*80}\n\n")
            f.write(content)
        
        return filepath
    
    @staticmethod
    def save_apk_finding(scan_type: str, severity: str, finding_type: str, 
                        file: str, details: str, apk_name: str, full_content: str = None):
        """Guardar hallazgo de APK en carpeta correspondiente - CON CONTENIDO COMPLETO"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = "SCAN_RESULTS"
        
        # Crear estructura de carpetas
        scan_dir = FileOrganizer.setup_directory_structure(base_dir, scan_type)
        
        # Determinar carpeta basada en severidad
        if severity in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
            target_folder = severity
        else:
            target_folder = "INFO"
        
        # Crear nombre de archivo seguro
        safe_file = re.sub(r'[^\w\-_\. ]', '_', file[:50])
        safe_type = re.sub(r'[^\w\-_\. ]', '_', finding_type[:30])
        filename = f"{timestamp}_{safe_type}_{safe_file}.txt"
        filepath = os.path.join(scan_dir, target_folder, filename)
        
        # Guardar archivo CON CONTENIDO COMPLETO
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Scan Type: {scan_type}\n")
            f.write(f"APK: {apk_name}\n")
            f.write(f"Severity: {severity}\n")
            f.write(f"Finding Type: {finding_type}\n")
            f.write(f"File: {file}\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
            f.write(f"Details:\n{details}\n")
            
            # Si hay contenido completo, agregarlo
            if full_content:
                f.write(f"\n{'='*80}\n")
                f.write("CONTENIDO COMPLETO DEL ARCHIVO:\n")
                f.write(f"{'='*80}\n")
                f.write(full_content)
        
        return filepath
    
    @staticmethod
    def save_database_exploit_result(scan_type: str, db_type: str, result_data: Dict):
        """Guardar resultado de exploit de base de datos"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = "SCAN_RESULTS"
        
        scan_dir = FileOrganizer.setup_directory_structure(base_dir, scan_type)
        
        filename = f"{timestamp}_{db_type}_EXPLOIT_RESULT.json"
        filepath = os.path.join(scan_dir, "EXPLOITS", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    @staticmethod
    def save_credentials_found(scan_type: str, credentials: Dict, source: str):
        """Guardar credenciales encontradas"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = "SCAN_RESULTS"
        
        scan_dir = FileOrganizer.setup_directory_structure(base_dir, scan_type)
        
        filename = f"{timestamp}_CREDENCIALES_{source}.json"
        filepath = os.path.join(scan_dir, "DATABASES", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(credentials, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    @staticmethod
    def create_wordpress_report(wp_url: str, found_users: list, found_plugins: list, 
                              found_themes: list, admin_credentials: list, wp_config: dict):
        """Crear reporte de WordPress"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = wp_url.replace('://', '_').replace('/', '_')
            
            # Usar estructura de carpetas de WordPress
            base_dir = "SCAN_RESULTS"
            scan_dir = FileOrganizer.setup_directory_structure(base_dir, "WORDPRESS")
            
            # Crear archivo de reporte
            filename = f"{timestamp}_{safe_url}_WP_REPORT.json"
            filepath = os.path.join(scan_dir, "REPORTS", filename)
            
            report_data = {
                'target': wp_url,
                'scan_date': datetime.now().isoformat(),
                'found_users': found_users,
                'found_plugins': found_plugins,
                'found_themes': found_themes,
                'admin_credentials': admin_credentials,
                'wp_config': wp_config,
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            # También crear un reporte de texto ejecutivo
            text_filename = f"{timestamp}_{safe_url}_WP_SUMMARY.txt"
            text_filepath = os.path.join(scan_dir, "REPORTS", text_filename)
            
            with open(text_filepath, 'w', encoding='utf-8') as f:
                f.write(f"WORDPRESS ULTRA EXPLOIT REPORT\n")
                f.write(f"="*60 + "\n")
                f.write(f"Target: {wp_url}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n📊 SUMMARY:\n")
                f.write(f"• Users found: {len(found_users)}\n")
                f.write(f"• Plugins found: {len(found_plugins)}\n")
                f.write(f"• Themes found: {len(found_themes)}\n")
                f.write(f"• Admin cracked: {len(admin_credentials)}\n")
                
                if admin_credentials:
                    f.write(f"\n🚨 CRACKED CREDENTIALS:\n")
                    for cred in admin_credentials:
                        f.write(f"  - {cred.get('username', 'N/A')}:{cred.get('password', 'N/A')}\n")
                
                if wp_config:
                    f.write(f"\n🗄️ DATABASE CONFIG:\n")
                    for key, value in wp_config.items():
                        f.write(f"  - {key}: {value}\n")
            
            return filepath
            
        except Exception as e:
            print(f"⚠ Error creando reporte WordPress: {e}")
            return None
    
    @staticmethod
    def cleanup_old_scans(max_age_days: int = 7):
        """Limpiar escaneos antiguos"""
        try:
            import shutil
            from datetime import datetime, timedelta
            
            base_dir = "SCAN_RESULTS"
            if not os.path.exists(base_dir):
                return
            
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            for root, dirs, files in os.walk(base_dir):
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        # Intentar extraer fecha del nombre del directorio
                        dir_time = os.path.getctime(dir_path)
                        dir_date = datetime.fromtimestamp(dir_time)
                        
                        if dir_date < cutoff_date:
                            shutil.rmtree(dir_path)
                            print(f"🗑️ Eliminado directorio antiguo: {dir_path}")
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"⚠ Error en cleanup: {e}")