# x3dh_integration.py - Basic X3DH (Extended Triple Diffie-Hellman) Integration
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Optional, Dict, List, Tuple
import os
import hashlib
from base64 import b64encode, b64decode
# Use absolute imports that work both standalone and as package
try:
    from utils.error_handler import ErrorHandler, ErrorCode, create_crypto_error
except ImportError:
    # Fallback for when run as script
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from utils.error_handler import ErrorHandler, ErrorCode, create_crypto_error

class X3DHPreKey:
    """X3DH Pre-key bundle"""
    def __init__(self, key_id: int, public_key: x25519.X25519PublicKey, private_key: x25519.X25519PrivateKey):
        self.key_id = key_id
        self.public_key = public_key
        self.private_key = private_key
        self.created_timestamp = int(os.urandom(4).hex(), 16)  # Simple timestamp simulation
    
    def serialize_public(self):
        """Serialize public key for transmission"""
        return {
            'key_id': self.key_id,
            'public_key': b64encode(self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),
            'timestamp': self.created_timestamp
        }
    
    @classmethod
    def from_serialized_public(cls, data):
        """Create prekey from serialized public data (without private key)"""
        public_key_bytes = b64decode(data['public_key'])
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        # Create dummy instance for public key operations
        instance = cls.__new__(cls)
        instance.key_id = data['key_id']
        instance.public_key = public_key
        instance.private_key = None
        instance.created_timestamp = data['timestamp']
        return instance

class X3DHKeyBundle:
    """Complete X3DH key bundle for a user"""
    def __init__(self, identity_key: x25519.X25519PrivateKey, signed_prekey: X3DHPreKey, 
                 one_time_prekeys: list, signature: Optional[bytes] = None):
        self.identity_key = identity_key
        self.signed_prekey = signed_prekey
        self.one_time_prekeys = one_time_prekeys
        self.signature = signature or b"dummy_signature"  # Simplified signature
    
    def serialize_bundle(self):
        """Serialize key bundle for server upload"""
        return {
            'identity_key': b64encode(self.identity_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),
            'signed_prekey': self.signed_prekey.serialize_public(),
            'signature': b64encode(self.signature).decode(),
            'one_time_prekeys': [pk.serialize_public() for pk in self.one_time_prekeys]
        }

class X3DHSession:
    """X3DH session manager for initial key agreement"""
    
    def __init__(self, error_handler: Optional[ErrorHandler] = None):
        self.error_handler = error_handler or ErrorHandler()
    
    def generate_identity_key(self) -> x25519.X25519PrivateKey:
        """Generate long-term identity key"""
        try:
            return x25519.X25519PrivateKey.generate()
        except Exception as e:
            raise create_crypto_error(
                ErrorCode.KEY_GENERATION_FAILED,
                f"Failed to generate identity key: {e}"
            )
    
    def generate_prekey(self, key_id: int) -> X3DHPreKey:
        """Generate a single pre-key"""
        try:
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            return X3DHPreKey(key_id, public_key, private_key)
        except Exception as e:
            raise create_crypto_error(
                ErrorCode.KEY_GENERATION_FAILED,
                f"Failed to generate prekey {key_id}: {e}"
            )
    
    def generate_prekey_bundle(self, num_one_time_keys: int = 10) -> X3DHKeyBundle:
        """Generate complete prekey bundle"""
        try:
            # Generate identity key
            identity_key = self.generate_identity_key()
            
            # Generate signed prekey
            signed_prekey = self.generate_prekey(1)
            
            # Generate one-time prekeys
            one_time_prekeys = []
            for i in range(num_one_time_keys):
                one_time_prekeys.append(self.generate_prekey(i + 2))  # Start from ID 2
            
            # Create simple signature (in real X3DH, this would be EdDSA signature)
            signature_data = signed_prekey.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            signature = hashlib.sha256(signature_data).digest()[:32]
            
            return X3DHKeyBundle(identity_key, signed_prekey, one_time_prekeys, signature)
            
        except Exception as e:
            raise create_crypto_error(
                ErrorCode.KEY_GENERATION_FAILED,
                f"Failed to generate prekey bundle: {e}"
            )
    
    def perform_x3dh_sender(self, sender_identity_key: x25519.X25519PrivateKey,
                           receiver_bundle: dict, sender_ephemeral_key: Optional[x25519.X25519PrivateKey] = None):
        """
        Perform X3DH key agreement as sender (Alice)
        Returns (shared_key, ephemeral_public_key, used_one_time_prekey_id)
        """
        try:
            # Generate ephemeral key if not provided
            if sender_ephemeral_key is None:
                sender_ephemeral_key = x25519.X25519PrivateKey.generate()
            
            # Parse receiver's bundle
            receiver_identity_public = x25519.X25519PublicKey.from_public_bytes(
                b64decode(receiver_bundle['identity_key'])
            )
            receiver_signed_prekey_data = receiver_bundle['signed_prekey']
            receiver_signed_prekey = x25519.X25519PublicKey.from_public_bytes(
                b64decode(receiver_signed_prekey_data['public_key'])
            )
            
            # Select one-time prekey if available
            receiver_one_time_prekey = None
            used_prekey_id = None
            if receiver_bundle['one_time_prekeys']:
                one_time_key_data = receiver_bundle['one_time_prekeys'][0]  # Use first available
                receiver_one_time_prekey = x25519.X25519PublicKey.from_public_bytes(
                    b64decode(one_time_key_data['public_key'])
                )
                used_prekey_id = one_time_key_data['key_id']
            
            # Perform the X3DH exchanges
            # DH1 = DH(IK_A, SPK_B)
            dh1 = sender_identity_key.exchange(receiver_signed_prekey)
            
            # DH2 = DH(EK_A, IK_B) 
            dh2 = sender_ephemeral_key.exchange(receiver_identity_public)
            
            # DH3 = DH(EK_A, SPK_B)
            dh3 = sender_ephemeral_key.exchange(receiver_signed_prekey)
            
            # DH4 = DH(EK_A, OPK_B) - if one-time prekey available
            dh4 = b""
            if receiver_one_time_prekey:
                dh4 = sender_ephemeral_key.exchange(receiver_one_time_prekey)
            
            # Concatenate all DH outputs
            if dh4:
                key_material = dh1 + dh2 + dh3 + dh4
            else:
                key_material = dh1 + dh2 + dh3
            
            # Derive shared secret using HKDF
            shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"X3DH-SharedSecret",
                info=b"DoubleRatchet-InitialKey",
                backend=default_backend()
            ).derive(key_material)
            
            ephemeral_public = sender_ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            return shared_key, ephemeral_public, used_prekey_id
            
        except Exception as e:
            raise create_crypto_error(
                ErrorCode.DH_EXCHANGE_FAILED,
                f"X3DH sender operation failed: {e}"
            )
    
    def perform_x3dh_receiver(self, receiver_identity_key: x25519.X25519PrivateKey,
                             receiver_signed_prekey: X3DHPreKey,
                             receiver_one_time_prekey: Optional[X3DHPreKey],
                             sender_identity_public_bytes: bytes,
                             sender_ephemeral_public_bytes: bytes):
        """
        Perform X3DH key agreement as receiver (Bob)
        Returns shared_key
        """
        try:
            # Parse sender's public keys
            sender_identity_public = x25519.X25519PublicKey.from_public_bytes(sender_identity_public_bytes)
            sender_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(sender_ephemeral_public_bytes)
            
            # Perform the X3DH exchanges (same as sender but with roles reversed)
            # DH1 = DH(SPK_B, IK_A)
            dh1 = receiver_signed_prekey.private_key.exchange(sender_identity_public)
            
            # DH2 = DH(IK_B, EK_A)
            dh2 = receiver_identity_key.exchange(sender_ephemeral_public)
            
            # DH3 = DH(SPK_B, EK_A) 
            dh3 = receiver_signed_prekey.private_key.exchange(sender_ephemeral_public)
            
            # DH4 = DH(OPK_B, EK_A) - if one-time prekey was used
            dh4 = b""
            if receiver_one_time_prekey and receiver_one_time_prekey.private_key:
                dh4 = receiver_one_time_prekey.private_key.exchange(sender_ephemeral_public)
            
            # Concatenate all DH outputs
            if dh4:
                key_material = dh1 + dh2 + dh3 + dh4
            else:
                key_material = dh1 + dh2 + dh3
            
            # Derive shared secret using HKDF
            shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"X3DH-SharedSecret", 
                info=b"DoubleRatchet-InitialKey",
                backend=default_backend()
            ).derive(key_material)
            
            return shared_key
            
        except Exception as e:
            raise create_crypto_error(
                ErrorCode.DH_EXCHANGE_FAILED,
                f"X3DH receiver operation failed: {e}"
            )
    
    def create_x3dh_initial_message(self, shared_key: bytes, sender_ephemeral_public: bytes,
                                   used_prekey_id: Optional[int] = None) -> dict:
        """Create initial X3DH message for Double Ratchet initialization"""
        return {
            'type': 'X3DH_INIT',
            'ephemeral_key': b64encode(sender_ephemeral_public).decode(),
            'used_prekey_id': used_prekey_id,
            'shared_key_hash': hashlib.sha256(shared_key).hexdigest()[:16]  # For verification
        }

# Simple prekey server simulation for demonstration
class PreKeyServer:
    """Simplified prekey server for X3DH demonstration"""
    
    def __init__(self):
        self.user_bundles = {}  # user_id -> key_bundle
        self.error_handler = ErrorHandler()
    
    def upload_bundle(self, user_id: str, bundle: dict) -> bool:
        """Upload user's prekey bundle to server"""
        try:
            self.user_bundles[user_id] = bundle
            return True
        except Exception as e:
            self.error_handler.handle_error(e, f"upload_bundle for {user_id}")
            return False
    
    def fetch_bundle(self, user_id: str) -> dict:
        """Fetch user's prekey bundle from server"""
        if user_id not in self.user_bundles:
            raise create_crypto_error(
                ErrorCode.KEY_NOT_FOUND,
                f"No prekey bundle found for user {user_id}"
            )
        
        bundle = self.user_bundles[user_id].copy()
        
        # Remove one-time prekey after use (simplified)
        if bundle['one_time_prekeys']:
            bundle['one_time_prekeys'] = [bundle['one_time_prekeys'].pop(0)]
        
        return bundle
    
    def has_bundle(self, user_id: str) -> bool:
        """Check if user has uploaded a bundle"""
        return user_id in self.user_bundles