# state_manager.py - Persistent State Management and Key Backup for Double Ratchet
import json
import os
import time
import shutil
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import secrets
# Use absolute imports that work both standalone and as package
try:
    from utils.error_handler import ErrorHandler, ErrorCode, create_state_error
except ImportError:
    # Fallback for when run as script  
    from .error_handler import ErrorHandler, ErrorCode, create_state_error

class StateManager:
    """Enhanced state manager with encrypted persistence and key backup/restore"""
    
    def __init__(self, error_handler=None):
        self.error_handler = error_handler or ErrorHandler()
        self.state_dir = "ratchet_states"
        self.backup_dir = f"{self.state_dir}/backups"
        
        # Create directories if they don't exist
        os.makedirs(self.state_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def _derive_key(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            return kdf.derive(password.encode())
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_SERIALIZATION_FAILED,
                f"Key derivation failed: {e}"
            )
    
    def _serialize_x25519_key(self, key):
        """Serialize X25519 key for JSON storage"""
        if key is None:
            return None
        
        try:
            if hasattr(key, 'private_bytes'):  # Private key
                return {
                    'type': 'private',
                    'bytes': b64encode(key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode()
                }
            else:  # Public key
                return {
                    'type': 'public',
                    'bytes': b64encode(key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )).decode()
                }
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_SERIALIZATION_FAILED,
                f"Key serialization failed: {e}"
            )
    
    def _deserialize_x25519_key(self, key_data):
        """Deserialize X25519 key from JSON storage"""
        if key_data is None:
            return None
        
        try:
            key_bytes = b64decode(key_data['bytes'])
            if key_data['type'] == 'private':
                return x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            else:  # public
                return x25519.X25519PublicKey.from_public_bytes(key_bytes)
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_DESERIALIZATION_FAILED,
                f"Key deserialization failed: {e}"
            )
    
    def _serialize_state_data(self, state_data):
        """Serialize state data with proper key handling"""
        try:
            serialized = {}
            
            for key, value in state_data.items():
                if key in ['DHs', 'DHr'] and value is not None:
                    # Handle X25519 keys
                    serialized[key] = self._serialize_x25519_key(value)
                elif isinstance(value, bytes):
                    # Handle byte values
                    serialized[key] = b64encode(value).decode()
                elif isinstance(value, dict):
                    # Handle nested dictionaries (e.g., MKSKIPPED)
                    serialized[key] = {}
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, bytes):
                            serialized[key][sub_key] = b64encode(sub_value).decode()
                        else:
                            serialized[key][sub_key] = sub_value
                else:
                    serialized[key] = value
            
            return json.dumps(serialized)
            
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_SERIALIZATION_FAILED,
                f"State serialization failed: {e}"
            )
    
    def _deserialize_state_data(self, serialized_data):
        """Deserialize state data with proper key handling"""
        try:
            parsed = json.loads(serialized_data)
            deserialized = {}
            
            for key, value in parsed.items():
                if key in ['DHs', 'DHr'] and value is not None:
                    # Handle X25519 keys
                    deserialized[key] = self._deserialize_x25519_key(value)
                elif isinstance(value, str) and key in ['RK', 'CKs', 'CKr']:
                    # Handle byte values
                    try:
                        deserialized[key] = b64decode(value) if value else None
                    except:
                        deserialized[key] = None
                elif isinstance(value, dict) and key == 'MKSKIPPED':
                    # Handle nested dictionaries
                    deserialized[key] = {}
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, str):
                            try:
                                deserialized[key][sub_key] = b64decode(sub_value)
                            except:
                                deserialized[key][sub_key] = sub_value
                        else:
                            deserialized[key][sub_key] = sub_value
                else:
                    deserialized[key] = value
            
            return deserialized
            
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_DESERIALIZATION_FAILED,
                f"State deserialization failed: {e}"
            )
    
    def _encrypt_data(self, plaintext, password):
        """Encrypt data using AES-256-CBC with PBKDF2"""
        try:
            # Generate random salt and IV
            salt = secrets.token_bytes(16)
            iv = secrets.token_bytes(16)
            
            # Derive key
            key = self._derive_key(password, salt)
            
            # Pad plaintext
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            # Encrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Package encrypted data
            encrypted_package = {
                'salt': b64encode(salt).decode(),
                'iv': b64encode(iv).decode(),
                'ciphertext': b64encode(ciphertext).decode(),
                'version': '1.0'
            }
            
            return json.dumps(encrypted_package)
            
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_SERIALIZATION_FAILED,
                f"Data encryption failed: {e}"
            )
    
    def _decrypt_data(self, encrypted_data, password):
        """Decrypt data using AES-256-CBC with PBKDF2"""
        try:
            # Parse encrypted package
            package = json.loads(encrypted_data)
            salt = b64decode(package['salt'])
            iv = b64decode(package['iv'])
            ciphertext = b64decode(package['ciphertext'])
            
            # Derive key
            key = self._derive_key(password, salt)
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
            
        except Exception as e:
            raise create_state_error(
                ErrorCode.STATE_DESERIALIZATION_FAILED,
                f"Data decryption failed: {e}"
            )
    
    def state_exists(self, user_id):
        """Check if state file exists for user"""
        state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
        return os.path.exists(state_file)
    
    def save_state(self, user_id, state_data, password):
        """Save encrypted state to file"""
        try:
            state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
            
            # Add metadata
            full_state = {
                'user_id': user_id,
                'timestamp': int(time.time()),
                'data': state_data
            }
            
            # Serialize and encrypt
            serialized_data = self._serialize_state_data(full_state)
            encrypted_data = self._encrypt_data(serialized_data, password)
            
            # Write to file
            with open(state_file, 'w') as f:
                f.write(encrypted_data)
            
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, f"save_state for {user_id}")
            return False
    
    def load_state(self, user_id, password):
        """Load and decrypt state from file"""
        try:
            state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
            
            if not os.path.exists(state_file):
                raise create_state_error(
                    ErrorCode.STATE_CORRUPTION,
                    f"State file not found for user {user_id}"
                )
            
            # Read and decrypt
            with open(state_file, 'r') as f:
                encrypted_data = f.read()
            
            serialized_data = self._decrypt_data(encrypted_data, password)
            full_state = self._deserialize_state_data(serialized_data)
            
            return full_state['data']
            
        except Exception as e:
            self.error_handler.handle_error(e, f"load_state for {user_id}")
            raise e
    
    def create_backup(self, user_id, password, backup_name=None):
        """Create a backup of the current state"""
        try:
            if not self.state_exists(user_id):
                return None
            
            # Generate backup name if not provided
            if backup_name is None:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                backup_name = f"{user_id}_backup_{timestamp}.enc"
            
            # Copy state file to backup directory
            state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
            backup_file = os.path.join(self.backup_dir, backup_name)
            
            shutil.copy2(state_file, backup_file)
            
            return backup_file
            
        except Exception as e:
            self.error_handler.handle_error(e, f"create_backup for {user_id}")
            return None
    
    def restore_from_backup(self, user_id, backup_file, password):
        """Restore state from a backup file"""
        try:
            if not os.path.exists(backup_file):
                raise create_state_error(
                    ErrorCode.RESTORE_FAILED,
                    f"Backup file not found: {backup_file}"
                )
            
            # Verify backup can be decrypted
            with open(backup_file, 'r') as f:
                encrypted_data = f.read()
            
            # Test decryption
            serialized_data = self._decrypt_data(encrypted_data, password)
            
            # If successful, copy to main state file
            state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
            shutil.copy2(backup_file, state_file)
            
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, f"restore_from_backup for {user_id}")
            return False
    
    def list_backups(self, user_id):
        """List all backup files for a user"""
        try:
            backups = []
            for file in os.listdir(self.backup_dir):
                if file.startswith(f"{user_id}_backup_") and file.endswith('.enc'):
                    backup_path = os.path.join(self.backup_dir, file)
                    stat = os.stat(backup_path)
                    backups.append({
                        'name': file,
                        'path': backup_path,
                        'size': stat.st_size,
                        'created': time.ctime(stat.st_ctime)
                    })
            
            return sorted(backups, key=lambda x: x['created'], reverse=True)
            
        except Exception as e:
            self.error_handler.handle_error(e, f"list_backups for {user_id}")
            return []
    
    def delete_state(self, user_id):
        """Delete state file for user"""
        try:
            state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
            if os.path.exists(state_file):
                os.remove(state_file)
                return True
            return False
            
        except Exception as e:
            self.error_handler.handle_error(e, f"delete_state for {user_id}")
            return False
    
    def get_state_info(self, user_id):
        """Get information about a user's state file"""
        try:
            state_file = os.path.join(self.state_dir, f"{user_id}_state.enc")
            
            if not os.path.exists(state_file):
                return None
            
            stat = os.stat(state_file)
            return {
                'user_id': user_id,
                'file_path': state_file,
                'size': stat.st_size,
                'created': time.ctime(stat.st_ctime),
                'modified': time.ctime(stat.st_mtime)
            }
            
        except Exception as e:
            self.error_handler.handle_error(e, f"get_state_info for {user_id}")
            return None