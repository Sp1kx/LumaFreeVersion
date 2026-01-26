#!/usr/bin/env python3
"""
HWIDManager.py - Sistema de autenticación por HWID/UUID para LUMA SCANNER
"""

import os
import json
import hashlib
import uuid
import platform
import subprocess
import re
from datetime import datetime
from typing import Dict, Tuple

import requests
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *


class HWIDManager:
    """Gestor de HWID - VERSIÓN MEJORADA"""
    
    HWID_URL = "https://raw.githubusercontent.com/SRx9091/luma-hwids/refs/heads/main/hwids.json"
    HWID_FILE = "authorized_hwids.json"
    
    @staticmethod
    def format_uuid(uuid_str: str) -> str:
        """Formatear un UUID a formato estándar"""
        if not uuid_str:
            return str(uuid.uuid4()).upper()
        
        # Eliminar espacios, guiones y convertir a mayúsculas
        uuid_str = re.sub(r'[^A-Fa-f0-9]', '', uuid_str).upper()
        
        # Si no es una cadena hexadecimal válida o no tiene longitud suficiente, generar uno nuevo
        if len(uuid_str) < 32:
            # Generar un UUID a partir de un hash de la cadena
            hash_obj = hashlib.md5(uuid_str.encode())
            uuid_str = hash_obj.hexdigest().upper()
        
        # Asegurar que tenga 32 caracteres
        uuid_str = uuid_str[:32].ljust(32, '0')
        
        # Formatear en grupos: 8-4-4-4-12
        return f"{uuid_str[0:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:32]}"
    
    @staticmethod
    def get_system_uuid() -> str:
        """Obtener UUID del sistema - VERSIÓN MEJORADA"""
        uuid_value = ""
        
        try:
            if platform.system() == "Windows":
                # Método 1: wmic
                try:
                    output = subprocess.check_output("wmic csproduct get uuid", shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                    lines = [line.strip() for line in output.strip().split('\n') if line.strip()]
                    if len(lines) > 1:
                        # Encontrar la línea que contiene el UUID (puede que la primera sea el encabezado)
                        for line in lines:
                            if line and not line.lower().startswith('uuid'):
                                uuid_value = line
                                break
                except:
                    pass
                
                # Si no se obtuvo un valor, intentar con PowerShell
                if not uuid_value:
                    try:
                        ps_command = "powershell -Command \"(Get-WmiObject Win32_ComputerSystemProduct).UUID\""
                        output = subprocess.check_output(ps_command, shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore').strip()
                        if output:
                            uuid_value = output
                    except:
                        pass
            else:
                # Para Linux/Mac, usar un identificador basado en hardware
                # Combinar varios identificadores del sistema
                system_info = f"{platform.node()}{platform.machine()}{platform.processor()}"
                uuid_value = hashlib.md5(system_info.encode()).hexdigest().upper()
                
        except Exception:
            # Si hay error, continuar con el flujo
            pass
        
        # Si aún no tenemos un valor, usar la MAC address
        if not uuid_value:
            try:
                mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1])
                uuid_value = hashlib.md5(mac.encode()).hexdigest().upper()
            except:
                # Último recurso: aleatorio
                return str(uuid.uuid4()).upper()
        
        # Formatear el UUID
        return HWIDManager.format_uuid(uuid_value)
    
    @staticmethod
    def fix_json_content(content: str) -> str:
        """Arreglar problemas comunes en JSON"""
        if not content:
            return "{}"
        
        # Remover BOM si existe
        if content.startswith('\ufeff'):
            content = content[1:]
        
        # Remover comentarios (// y /* */)
        lines = content.split('\n')
        cleaned_lines = []
        in_multiline_comment = False
        
        for line in lines:
            # Manejar comentarios multilínea
            if in_multiline_comment:
                if '*/' in line:
                    in_multiline_comment = False
                    line = line[line.find('*/') + 2:]
                else:
                    continue
            
            # Remover comentarios de una línea
            if '//' in line:
                line = line.split('//')[0]
            
            # Buscar inicio de comentario multilínea
            if '/*' in line:
                in_multiline_comment = True
                line = line.split('/*')[0]
            
            cleaned_lines.append(line.strip())
        
        content = '\n'.join(cleaned_lines)
        
        # Remover comas finales antes de } o ]
        content = re.sub(r',\s*([}\]])', r'\1', content)
        
        return content
    
    @staticmethod
    def load_hwids() -> Dict:
        """Cargar HWIDs - Primero local, luego remoto"""
        hwids = {}
        
        # 1. Archivo local (si existe)
        if os.path.exists(HWIDManager.HWID_FILE):
            try:
                with open(HWIDManager.HWID_FILE, 'r', encoding='utf-8') as f:
                    content = f.read()
                    content = HWIDManager.fix_json_content(content)
                    local_data = json.loads(content)
                    
                    if isinstance(local_data, dict):
                        for hwid, data in local_data.items():
                            hwid_upper = hwid.upper()
                            hwids[hwid_upper] = {
                                "username": data.get("username", "Unknown"),
                                "role": data.get("role", "user"),
                                "expiry": data.get("expiry"),
                                "features": data.get("features", [])
                            }
                        print("✅ HWIDs locales cargados")
            except Exception as e:
                print(f"⚠ Error con archivo local: {e}")
        
        # 2. URL remota (GitHub)
        try:
            response = requests.get(HWIDManager.HWID_URL, timeout=5)
            if response.status_code == 200:
                content = response.text
                content = HWIDManager.fix_json_content(content)
                remote_data = json.loads(content)
                
                if isinstance(remote_data, dict):
                    for hwid, data in remote_data.items():
                        hwid_upper = hwid.upper()
                        hwids[hwid_upper] = {
                            "username": data.get("username", "Unknown"),
                            "role": data.get("role", "user"),
                            "expiry": data.get("expiry"),
                            "features": data.get("features", [])
                        }
                    print("✅ HWIDs remotos cargados de GitHub")
        except Exception as e:
            print(f"⚠ No se pudieron cargar HWIDs remotos: {e}")
        
        # Si no hay HWIDs, crear uno de emergencia
        if not hwids:
            print("⚠ Creando HWID de emergencia...")
            emergency_uuid = HWIDManager.get_system_uuid()
            hwids[emergency_uuid] = {
                "username": "EMERGENCY_USER",
                "role": "admin",
                "expiry": None,
                "features": ["full_access"]
            }
            
            # Guardar para uso futuro
            with open("emergency_hwids.json", 'w', encoding='utf-8') as f:
                json.dump(hwids, f, indent=2)
        
        return hwids
    
    @staticmethod
    def verify_hwid(uuid_to_check: str = None) -> Tuple[bool, str, Dict]:
        """Verificar HWID"""
        if uuid_to_check is None:
            uuid_to_check = HWIDManager.get_system_uuid()
        
        hwids = HWIDManager.load_hwids()
        uuid_to_check = uuid_to_check.upper()
        
        print(f"🔍 Verificando HWID: {uuid_to_check}")
        print(f"📊 HWIDs en base de datos: {len(hwids)}")
        
        if uuid_to_check in hwids:
            user_data = hwids[uuid_to_check]
            
            # Verificar expiración
            expiry = user_data.get("expiry")
            if expiry and expiry not in [None, "null", "NULL", "None"]:
                try:
                    expiry_date = datetime.strptime(str(expiry), "%Y-%m-%d")
                    if datetime.now() > expiry_date:
                        return False, "HWID expirado", None
                except:
                    pass
            
            return True, f"✅ Acceso concedido", user_data
        
        return False, "❌ HWID no autorizado", None


class LoginDialog(QDialog):
    """Diálogo de login - CON OPCIÓN MANUAL"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 LUMA SCANNER - Login")
        self.setFixedSize(500, 350)
        self.setStyleSheet("""
            QDialog { background-color: #1a1a1a; }
            QLabel { color: white; font-size: 14px; }
            QLineEdit {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #444;
                border-radius: 3px;
                padding: 8px;
                font-size: 16px;
                font-family: 'Courier New', monospace;
            }
            QPushButton {
                background-color: #0d7377;
                color: white;
                border: 1px solid #14ffec;
                border-radius: 5px;
                padding: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #14ffec; color: black; }
            QPushButton:disabled { background-color: #444; color: #888; }
        """)
        
        self.user_data = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("⚡ LUMA SCANNER v5.0")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #14ffec; padding: 10px;")
        layout.addWidget(title)
        
        # HWID detectado automáticamente
        self.auto_uuid = HWIDManager.get_system_uuid()
        uuid_label = QLabel(f"HWID detectado:\n{self.auto_uuid}")
        uuid_label.setAlignment(Qt.AlignCenter)
        uuid_label.setStyleSheet("""
            color: #00ff00;
            font-size: 12px;
            font-family: 'Courier New';
            background-color: #2a2a2a;
            padding: 10px;
            border: 1px solid #444;
            border-radius: 5px;
            margin: 10px;
        """)
        layout.addWidget(uuid_label)
        
        # Separador
        layout.addWidget(QLabel("Si el HWID no es correcto, ingrésalo manualmente:"))
        
        # Campo para HWID manual
        self.manual_uuid_input = QLineEdit()
        self.manual_uuid_input.setPlaceholderText("Ej: 3C5451A6-593C-EC5D-B7C1-F02F741A9B19")
        self.manual_uuid_input.setText(self.auto_uuid)
        layout.addWidget(self.manual_uuid_input)
        
        # Botón de verificación
        self.btn_verify = QPushButton("🔍 VERIFICAR ACCESO")
        self.btn_verify.clicked.connect(self.verify_access)
        layout.addWidget(self.btn_verify)
        
        # Estado
        self.status_label = QLabel("Presiona VERIFICAR para continuar...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #888; padding: 10px;")
        layout.addWidget(self.status_label)
        
        # Contador
        self.counter = 5
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_counter)
        
        self.setLayout(layout)
        
        # Auto-verificar después de 1 segundo
        QTimer.singleShot(1000, self.verify_access)
    
    def verify_access(self):
        """Verificar acceso"""
        self.btn_verify.setEnabled(False)
        self.status_label.setText("🔍 Verificando HWID...")
        self.status_label.setStyleSheet("color: #ffff00; font-weight: bold;")
        
        # Usar el HWID manual si se ingresó, de lo contrario el automático
        manual_uuid = self.manual_uuid_input.text().strip().upper()
        if manual_uuid and manual_uuid != self.auto_uuid:
            uuid_to_check = manual_uuid
            print(f"Usando HWID manual: {uuid_to_check}")
        else:
            uuid_to_check = self.auto_uuid
        
        QTimer.singleShot(500, lambda: self.do_verification(uuid_to_check))
    
    def do_verification(self, uuid_to_check: str):
        """Realizar la verificación"""
        valid, message, user_data = HWIDManager.verify_hwid(uuid_to_check)
        
        if valid:
            self.user_data = user_data
            username = user_data.get('username', 'Usuario')
            
            self.status_label.setText(f"✅ ACCESO CONCEDIDO\n👤 {username}")
            self.status_label.setStyleSheet("color: #00ff00; font-weight: bold;")
            
            # Contar y aceptar
            self.counter = 3
            self.timer.start(1000)
            
        else:
            self.status_label.setText(f"❌ ACCESO DENEGADO\n{message}")
            self.status_label.setStyleSheet("color: #ff0000; font-weight: bold;")
            self.btn_verify.setEnabled(True)
            
            QMessageBox.critical(
                self, 
                "Acceso Denegado",
                f"{message}\n\nHWID usado: {uuid_to_check}\n\nContacta a @sp1kz"
            )
    
    def update_counter(self):
        """Actualizar contador"""
        if self.counter > 1:
            self.counter -= 1
            self.status_label.setText(f"✅ ACCESO CONCEDIDO\nIniciando en {self.counter}...")
        else:
            self.timer.stop()
            self.accept()


if __name__ == "__main__":
    # Test rápido
    app = QApplication([])
    dialog = LoginDialog()
    result = dialog.exec()
    
    if result == QDialog.Accepted:
        print("✅ Login exitoso")
        print(f"Usuario: {dialog.user_data}")
    else:
        print("❌ Login fallido")
    
    app.quit()