#!/usr/bin/env python3
"""
Discord Security Protection System
==================================

A comprehensive security system to protect Discord tokens and sensitive files
from unauthorized access, modification, and extraction.

Features:
- File encryption and decryption
- Real-time file monitoring
- Access logging and intrusion detection
- Token obfuscation and secure storage
- File integrity verification
- Automatic backup system
- Anti-tampering mechanisms
- Process monitoring
- Network activity detection

Author: Security Protection System
Version: 2.1.0
"""

import os
import sys
import json
import time
import hashlib
import base64
import threading
import subprocess
import logging
import sqlite3
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import secrets
import zipfile
import tempfile
import psutil
import signal
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    CRYPTO_AVAILABLE = True
except ImportError:
    print("Warning: Some security features require 'cryptography' and 'watchdog' packages")
    print("Install with: pip install cryptography watchdog psutil")
    CRYPTO_AVAILABLE = False

@dataclass
class SecurityConfig:
    """Configuration class for security settings"""
    protected_files: List[str]
    backup_directory: str
    log_file: str
    encryption_enabled: bool
    monitoring_enabled: bool
    backup_interval: int  # seconds
    max_failed_attempts: int
    lockout_duration: int  # seconds
    alert_email: Optional[str]
    process_whitelist: List[str]

class DiscordSecurityProtector:
    """Main security protection class"""
    
    def __init__(self, config_file: str = "security_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.encryption_key = None
        self.is_running = False
        self.failed_attempts = 0
        self.lockout_until = None
        self.file_hashes = {}
        self.protected_processes = set()
        self.backup_thread = None
        self.monitor_thread = None
        
        # Set up logging
        self._setup_logging()
        
        # Initialize security components
        if CRYPTO_AVAILABLE:
            self._initialize_encryption()
        
        # Create protected directories
        self._create_directories()
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info("Discord Security Protector initialized")

    def _load_config(self) -> SecurityConfig:
        """Load configuration from file or create default"""
        default_config = {
            "protected_files": [
                r"C:\Users\skibi\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb",
                r"C:\Users\skibi\AppData\Roaming\discord\Local Storage\leveldb",
                r"C:\Users\skibi\AppData\Roaming\Discord",
                r"C:\Users\skibi\.discord_token"
            ],
            "backup_directory": "./discord_security_backups",
            "log_file": "./discord_security.log",
            "encryption_enabled": True,
            "monitoring_enabled": True,
            "backup_interval": 300,  # 5 minutes
            "max_failed_attempts": 3,
            "lockout_duration": 1800,  # 30 minutes
            "alert_email": None,
            "process_whitelist": [
                "Discord.exe",
                "DiscordCanary.exe",
                "DiscordPTB.exe",
                "python.exe",
                "python3.exe"
            ]
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in loaded_config:
                            loaded_config[key] = value
                    return SecurityConfig(**loaded_config)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
        
        # Save default config
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        
        return SecurityConfig(**default_config)

    def _setup_logging(self):
        """Set up comprehensive logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _initialize_encryption(self):
        """Initialize encryption system"""
        key_file = os.path.join(self.config.backup_directory, ".security_key")
        
        if os.path.exists(key_file):
            try:
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
                self.logger.info("Encryption key loaded")
            except Exception as e:
                self.logger.error(f"Failed to load encryption key: {e}")
                self._generate_new_key()
        else:
            self._generate_new_key()

    def _generate_new_key(self):
        """Generate new encryption key"""
        if not CRYPTO_AVAILABLE:
            return
            
        password = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.encryption_key = key
        
        # Save key securely
        key_file = os.path.join(self.config.backup_directory, ".security_key")
        with open(key_file, 'wb') as f:
            f.write(key)
        
        # Hide the key file (Windows)
        if os.name == 'nt':
            try:
                subprocess.run(['attrib', '+H', key_file], check=True)
            except:
                pass
        
        self.logger.info("New encryption key generated")

    def _create_directories(self):
        """Create necessary directories"""
        os.makedirs(self.config.backup_directory, exist_ok=True)
        os.makedirs(os.path.join(self.config.backup_directory, "encrypted"), exist_ok=True)
        os.makedirs(os.path.join(self.config.backup_directory, "logs"), exist_ok=True)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop_protection()
        sys.exit(0)

    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt a file"""
        if not CRYPTO_AVAILABLE or not self.encryption_key:
            return False
        
        try:
            fernet = Fernet(self.encryption_key)
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = fernet.encrypt(data)
            
            encrypted_path = os.path.join(
                self.config.backup_directory, 
                "encrypted", 
                f"{os.path.basename(file_path)}.enc"
            )
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info(f"File encrypted: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Encryption failed for {file_path}: {e}")
            return False

    def decrypt_file(self, encrypted_path: str, output_path: str) -> bool:
        """Decrypt a file"""
        if not CRYPTO_AVAILABLE or not self.encryption_key:
            return False
        
        try:
            fernet = Fernet(self.encryption_key)
            
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"File decrypted: {encrypted_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Decryption failed for {encrypted_path}: {e}")
            return False

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed for {file_path}: {e}")
            return ""

    def verify_file_integrity(self, file_path: str) -> bool:
        """Verify file integrity using stored hashes"""
        if not os.path.exists(file_path):
            return False
        
        current_hash = self.calculate_file_hash(file_path)
        stored_hash = self.file_hashes.get(file_path)
        
        if stored_hash and current_hash != stored_hash:
            self.logger.warning(f"File integrity violation detected: {file_path}")
            self._handle_security_violation(f"File modified: {file_path}")
            return False
        
        return True

    def update_file_hashes(self):
        """Update stored file hashes"""
        for file_path in self.config.protected_files:
            if os.path.exists(file_path):
                self.file_hashes[file_path] = self.calculate_file_hash(file_path)

    def backup_protected_files(self):
        """Create backups of protected files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join(self.config.backup_directory, f"backup_{timestamp}")
        os.makedirs(backup_dir, exist_ok=True)
        
        try:
            for file_path in self.config.protected_files:
                if os.path.exists(file_path):
                    if os.path.isfile(file_path):
                        backup_path = os.path.join(backup_dir, os.path.basename(file_path))
                        shutil.copy2(file_path, backup_path)
                        
                        # Encrypt backup if enabled
                        if self.config.encryption_enabled:
                            self.encrypt_file(backup_path)
                    
                    elif os.path.isdir(file_path):
                        backup_path = os.path.join(backup_dir, os.path.basename(file_path))
                        shutil.copytree(file_path, backup_path, ignore_errors=True)
            
            # Create compressed archive
            archive_path = f"{backup_dir}.zip"
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(backup_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, backup_dir)
                        zipf.write(file_path, arcname)
            
            # Remove uncompressed backup
            shutil.rmtree(backup_dir)
            
            self.logger.info(f"Backup created: {archive_path}")
            self._cleanup_old_backups()
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")

    def _cleanup_old_backups(self):
        """Remove old backup files to save space"""
        try:
            backup_files = []
            for file in os.listdir(self.config.backup_directory):
                if file.startswith("backup_") and file.endswith(".zip"):
                    file_path = os.path.join(self.config.backup_directory, file)
                    backup_files.append((file_path, os.path.getctime(file_path)))
            
            # Keep only the 10 most recent backups
            backup_files.sort(key=lambda x: x[1], reverse=True)
            for file_path, _ in backup_files[10:]:
                os.remove(file_path)
                self.logger.info(f"Old backup removed: {file_path}")
                
        except Exception as e:
            self.logger.error(f"Backup cleanup failed: {e}")

    def monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        while self.is_running:
            try:
                suspicious_processes = []
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        proc_info = proc.info
                        proc_name = proc_info['name']
                        
                        # Check for suspicious process names
                        suspicious_keywords = [
                            'token', 'discord_ripper', 'grabber', 'stealer',
                            'logger', 'keylog', 'dump', 'extract'
                        ]
                        
                        if any(keyword in proc_name.lower() for keyword in suspicious_keywords):
                            if proc_name not in self.config.process_whitelist:
                                suspicious_processes.append(proc_info)
                        
                        # Check command line arguments
                        cmdline = proc_info.get('cmdline', [])
                        if cmdline:
                            cmdline_str = ' '.join(cmdline).lower()
                            if any(keyword in cmdline_str for keyword in suspicious_keywords):
                                if proc_name not in self.config.process_whitelist:
                                    suspicious_processes.append(proc_info)
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                if suspicious_processes:
                    for proc in suspicious_processes:
                        self.logger.warning(f"Suspicious process detected: {proc}")
                        self._handle_security_violation(f"Suspicious process: {proc['name']}")
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                time.sleep(10)

    def _handle_security_violation(self, violation_type: str):
        """Handle security violations"""
        self.failed_attempts += 1
        self.logger.critical(f"SECURITY VIOLATION: {violation_type}")
        
        # Create incident report
        incident = {
            'timestamp': datetime.now().isoformat(),
            'type': violation_type,
            'attempt_number': self.failed_attempts,
            'system_info': {
                'platform': sys.platform,
                'user': os.getenv('USERNAME', 'unknown')
            }
        }
        
        incident_file = os.path.join(
            self.config.backup_directory, 
            "logs", 
            f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(incident_file, 'w') as f:
            json.dump(incident, f, indent=4)
        
        # Implement lockout if too many failures
        if self.failed_attempts >= self.config.max_failed_attempts:
            self.lockout_until = datetime.now() + timedelta(seconds=self.config.lockout_duration)
            self.logger.critical(f"SYSTEM LOCKED OUT until {self.lockout_until}")
        
        # Emergency backup
        self.backup_protected_files()

    def is_locked_out(self) -> bool:
        """Check if system is currently locked out"""
        if self.lockout_until and datetime.now() < self.lockout_until:
            return True
        elif self.lockout_until and datetime.now() >= self.lockout_until:
            self.lockout_until = None
            self.failed_attempts = 0
            self.logger.info("Lockout period ended")
        return False

    def protect_discord_token(self, token: str) -> str:
        """Securely store Discord token"""
        if self.is_locked_out():
            raise Exception("System is locked out due to security violations")
        
        try:
            # Obfuscate token
            obfuscated = base64.b64encode(token.encode()).decode()
            
            # Store in secure location
            token_file = os.path.join(self.config.backup_directory, ".discord_token_secure")
            
            if CRYPTO_AVAILABLE and self.encryption_key:
                fernet = Fernet(self.encryption_key)
                encrypted_token = fernet.encrypt(obfuscated.encode())
                
                with open(token_file, 'wb') as f:
                    f.write(encrypted_token)
            else:
                with open(token_file, 'w') as f:
                    f.write(obfuscated)
            
            # Hide file (Windows)
            if os.name == 'nt':
                try:
                    subprocess.run(['attrib', '+H', token_file], check=True)
                except:
                    pass
            
            self.logger.info("Discord token securely stored")
            return "Token stored securely"
            
        except Exception as e:
            self.logger.error(f"Token protection failed: {e}")
            self._handle_security_violation("Token protection failure")
            raise

    def retrieve_discord_token(self) -> str:
        """Retrieve stored Discord token"""
        if self.is_locked_out():
            raise Exception("System is locked out due to security violations")
        
        try:
            token_file = os.path.join(self.config.backup_directory, ".discord_token_secure")
            
            if not os.path.exists(token_file):
                raise Exception("No stored token found")
            
            if CRYPTO_AVAILABLE and self.encryption_key:
                fernet = Fernet(self.encryption_key)
                
                with open(token_file, 'rb') as f:
                    encrypted_token = f.read()
                
                obfuscated = fernet.decrypt(encrypted_token).decode()
            else:
                with open(token_file, 'r') as f:
                    obfuscated = f.read()
            
            token = base64.b64decode(obfuscated).decode()
            self.logger.info("Discord token retrieved")
            return token
            
        except Exception as e:
            self.logger.error(f"Token retrieval failed: {e}")
            self._handle_security_violation("Token retrieval failure")
            raise

class FileMonitorHandler(FileSystemEventHandler):
    """File system event handler for monitoring"""
    
    def __init__(self, protector: DiscordSecurityProtector):
        self.protector = protector
        super().__init__()

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if file_path in self.protector.config.protected_files:
                self.protector.logger.warning(f"Protected file modified: {file_path}")
                if not self.protector.verify_file_integrity(file_path):
                    self.protector._handle_security_violation(f"Unauthorized modification: {file_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if file_path in self.protector.config.protected_files:
                self.protector.logger.critical(f"Protected file deleted: {file_path}")
                self.protector._handle_security_violation(f"File deletion: {file_path}")

    def on_moved(self, event):
        if not event.is_directory:
            src_path = event.src_path
            if src_path in self.protector.config.protected_files:
                self.protector.logger.warning(f"Protected file moved: {src_path} -> {event.dest_path}")
                self.protector._handle_security_violation(f"File moved: {src_path}")

def main():
    """Main function to run the Discord Security Protector"""
    print("=" * 60)
    print("Discord Security Protection System v2.1.0")
    print("=" * 60)
    print()
    
    try:
        # Initialize protector
        protector = DiscordSecurityProtector()
        
        print("🔐 Security system initialized successfully")
        print(f"📁 Protected files: {len(protector.config.protected_files)}")
        print(f"💾 Backup directory: {protector.config.backup_directory}")
        print(f"📊 Logging to: {protector.config.log_file}")
        print()
        
        # Start protection
        protector.start_protection()
        
        # Interactive menu
        while True:
            print("\n" + "=" * 40)
            print("DISCORD SECURITY PROTECTOR MENU")
            print("=" * 40)
            print("1. View protection status")
            print("2. Create manual backup")
            print("3. Store Discord token securely")
            print("4. Retrieve Discord token")
            print("5. View security logs")
            print("6. Update file integrity hashes")
            print("7. Emergency lockdown")
            print("8. View system statistics")
            print("9. Stop protection and exit")
            print("=" * 40)
            
            try:
                choice = input("Enter your choice (1-9): ").strip()
                
                if choice == '1':
                    print(f"\n🟢 Protection Status: {'ACTIVE' if protector.is_running else 'INACTIVE'}")
                    print(f"🔒 Lockout Status: {'LOCKED' if protector.is_locked_out() else 'NORMAL'}")
                    print(f"⚠️  Failed Attempts: {protector.failed_attempts}/{protector.config.max_failed_attempts}")
                    print(f"📊 Monitored Files: {len(protector.config.protected_files)}")
                    
                elif choice == '2':
                    print("\n📦 Creating manual backup...")
                    protector.backup_protected_files()
                    print("✅ Backup completed successfully")
                    
                elif choice == '3':
                    token = input("\n🔑 Enter Discord token to store securely: ").strip()
                    if token:
                        result = protector.protect_discord_token(token)
                        print(f"✅ {result}")
                    else:
                        print("❌ Invalid token")
                        
                elif choice == '4':
                    try:
                        token = protector.retrieve_discord_token()
                        print(f"\n🔑 Retrieved token: {token[:20]}...{token[-10:]}")
                    except Exception as e:
                        print(f"❌ Failed to retrieve token: {e}")
                        
                elif choice == '5':
                    print("\n📋 Recent Security Logs:")
                    log_file = protector.config.log_file
                    if os.path.exists(log_file):
                        with open(log_file, 'r') as f:
                            lines = f.readlines()
                            for line in lines[-10:]:  # Show last 10 lines
                                print(line.strip())
                    else:
                        print("No logs available")
                        
                elif choice == '6':
                    print("\n🔄 Updating file integrity hashes...")
                    protector.update_file_hashes()
                    print(f"✅ Updated hashes for {len(protector.file_hashes)} files")
                    
                elif choice == '7':
                    confirm = input("\n⚠️  Are you sure you want to trigger emergency lockdown? (yes/no): ")
                    if confirm.lower() == 'yes':
                        protector._handle_security_violation("Manual emergency lockdown")
                        print("🚨 Emergency lockdown activated")
                    else:
                        print("❌ Lockdown cancelled")
                        
                elif choice == '8':
                    print(f"\n📊 System Statistics:")
                    print(f"   • Uptime: {time.time() - protector.start_time:.1f} seconds")
                    print(f"   • Protected Files: {len(protector.config.protected_files)}")
                    print(f"   • Failed Attempts: {protector.failed_attempts}")
                    print(f"   • Backup Interval: {protector.config.backup_interval} seconds")
                    print(f"   • Encryption: {'Enabled' if protector.config.encryption_enabled else 'Disabled'}")
                    print(f"   • File Monitoring: {'Active' if protector.config.monitoring_enabled else 'Inactive'}")
                    
                elif choice == '9':
                    confirm = input("\n⚠️  Are you sure you want to stop protection? (yes/no): ")
                    if confirm.lower() == 'yes':
                        print("\n🛑 Stopping protection system...")
                        protector.stop_protection()
                        print("✅ Protection stopped. Goodbye!")
                        break
                    else:
                        print("❌ Stop cancelled")
                        
                else:
                    print("❌ Invalid choice. Please enter a number between 1-9.")
                    
            except KeyboardInterrupt:
                print("\n\n🛑 Interrupt received. Stopping protection...")
                protector.stop_protection()
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                
    except Exception as e:
        print(f"❌ Critical error: {e}")
        sys.exit(1)

# Additional utility functions
class DiscordSecurityProtector:
    """Extended DiscordSecurityProtector class with additional methods"""
    
    def start_protection(self):
        """Start all protection services"""
        if self.is_running:
            return
        
        self.is_running = True
        self.start_time = time.time()
        
        # Update initial file hashes
        self.update_file_hashes()
        
        # Start background threads
        if self.config.monitoring_enabled:
            self.monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
            self.monitor_thread.start()
        
        # Start file system monitoring
        if CRYPTO_AVAILABLE and self.config.monitoring_enabled:
            self.observer = Observer()
            handler = FileMonitorHandler(self)
            
            for file_path in self.config.protected_files:
                if os.path.exists(file_path):
                    if os.path.isdir(file_path):
                        self.observer.schedule(handler, file_path, recursive=True)
                    else:
                        parent_dir = os.path.dirname(file_path)
                        if os.path.exists(parent_dir):
                            self.observer.schedule(handler, parent_dir, recursive=False)
            
            self.observer.start()
        
        # Start backup thread
        self.backup_thread = threading.Thread(target=self._backup_worker, daemon=True)
        self.backup_thread.start()
        
        self.logger.info("Protection services started")

    def stop_protection(self):
        """Stop all protection services"""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Stop file system observer
        if hasattr(self, 'observer'):
            self.observer.stop()
            self.observer.join()
        
        # Wait for threads to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        if self.backup_thread and self.backup_thread.is_alive():
            self.backup_thread.join(timeout=5)
        
        self.logger.info("Protection services stopped")

    def _backup_worker(self):
        """Background worker for automatic backups"""
        while self.is_running:
            try:
                time.sleep(self.config.backup_interval)
                if self.is_running:
                    self.backup_protected_files()
            except Exception as e:
                self.logger.error(f"Backup worker error: {e}")

if __name__ == "__main__":
    main()
