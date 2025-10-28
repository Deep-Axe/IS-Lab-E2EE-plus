# message_handler.py - Enhanced Message Format with Versioning and Replay Protection
import json
import os
import time
from base64 import b64encode, b64decode
# Use absolute imports that work both standalone and as package
try:
    from core.double_ratchet import Header
except ImportError:
    # Fallback for when run as script
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from core.double_ratchet import Header
import hashlib
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessageHandler:
    PROTOCOL_VERSION = "1.0"
    MESSAGE_TYPES = {
        'TEXT': 1,
        'KEY_EXCHANGE': 2,
        'SYSTEM': 3,
        'ACK': 4
    }
    
    # Replay protection: store last N message IDs
    MAX_STORED_MESSAGE_IDS = 1000
    
    def __init__(self):
        self.received_message_ids = set()
        self.last_seen_timestamps = {}
        
    def create_message(self, from_user, to_user, message_type, header, ciphertext, mac, ad,
                       plaintext_content=None, sealed_sender: Optional[Dict[str, Any]] = None):
        """Create enhanced message format with versioning and replay protection"""
        
        # Generate unique message ID
        message_id = self._generate_message_id(from_user, to_user, header, ciphertext)
        
        # Create enhanced message
        enhanced_message = {
            'version': self.PROTOCOL_VERSION,
            'message_id': message_id,
            'timestamp': int(time.time() * 1000),  # milliseconds
            'from': None if sealed_sender else from_user,
            'to': to_user,
            'message_type': message_type,
            'sequence_number': header.n if header else 0,
            'header': header.serialize() if header else None,
            'ciphertext': ciphertext,
            'mac': mac,
            'ad': ad,
            'metadata': {
                'client_version': 'DoubleRatchetDemo-1.0',
                'encryption_algorithm': 'AES-256-CBC',
                'mac_algorithm': 'HMAC-SHA256',
                'dh_algorithm': 'X25519'
            }
        }

        if sealed_sender:
            enhanced_message['sealed_sender'] = sealed_sender
            enhanced_message['metadata']['sealed_sender_hint'] = sealed_sender.get('hint')
        
        # Add plaintext hash for integrity checking (optional for debugging)
        if plaintext_content:
            enhanced_message['content_hash'] = hashlib.sha256(plaintext_content.encode()).hexdigest()[:16]
        
        return enhanced_message
    
    def _generate_message_id(self, from_user, to_user, header, ciphertext):
        """Generate unique message ID from message components"""
        id_data = f"{from_user}:{to_user}:{time.time()}:{ciphertext[:32]}"
        if header:
            id_data += f":{header.n}:{b64encode(header.dh[:8]).decode()}"
        
        return hashlib.sha256(id_data.encode()).hexdigest()[:16]
    
    def validate_message(self, message):
        """Validate message format and check for replay attacks"""
        try:
            # Check required fields
            required_fields = ['version', 'message_id', 'timestamp', 'to', 'message_type']
            for field in required_fields:
                if field not in message:
                    return False, f"Missing required field: {field}"
            if not message.get('from') and 'sealed_sender' not in message:
                return False, "Missing sender information (no sealed envelope provided)"
            
            # Check protocol version
            if message['version'] != self.PROTOCOL_VERSION:
                return False, f"Unsupported protocol version: {message['version']}"
            
            # Check message type
            if message['message_type'] not in self.MESSAGE_TYPES.values():
                return False, f"Invalid message type: {message['message_type']}"
            
            # Replay protection: check message ID
            if message['message_id'] in self.received_message_ids:
                return False, f"Duplicate message ID (replay attack): {message['message_id']}"
            
            # Timestamp validation (allow 5 minute clock skew)
            current_time = int(time.time() * 1000)
            message_time = message['timestamp']
            
            if abs(current_time - message_time) > 5 * 60 * 1000:  # 5 minutes
                return False, f"Message timestamp too old or too far in future"
            
            # Check timestamp ordering (basic replay protection)
            # Allow equal timestamps but use sequence number as tiebreaker
            sender = message.get('from')
            if not sender and message.get('sealed_sender'):
                sender = message['sealed_sender'].get('hint')
            if sender:
                if sender in self.last_seen_timestamps:
                    last_timestamp = self.last_seen_timestamps[sender]
                    current_timestamp = message_time
                    
                    if current_timestamp < last_timestamp:
                        return False, f"Message timestamp too old for sender"
                    
            return True, "Message valid"
            
        except Exception as e:
            return False, f"Message validation error: {e}"
    
    def record_message(self, message):
        """Record message to prevent replay attacks"""
        message_id = message['message_id']
        sender = message.get('from')
        if not sender and message.get('sealed_sender'):
            sender = message['sealed_sender'].get('hint')
        timestamp = message['timestamp']
        
        # Add to received set
        self.received_message_ids.add(message_id)
        
        # Update last seen timestamp
        if sender:
            self.last_seen_timestamps[sender] = timestamp
        
        # Cleanup old message IDs if needed
        if len(self.received_message_ids) > self.MAX_STORED_MESSAGE_IDS:
            # Remove oldest 10% of message IDs (simple cleanup)
            old_ids = list(self.received_message_ids)[:int(self.MAX_STORED_MESSAGE_IDS * 0.1)]
            self.received_message_ids.difference_update(old_ids)
    
    def serialize_message(self, message):
        """Serialize message to JSON for network transmission"""
        return json.dumps(message)
    
    def deserialize_message(self, message_json):
        """Deserialize message from JSON"""
        try:
            return json.loads(message_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON message: {e}")
    
    def extract_double_ratchet_components(self, message):
        """Extract Double Ratchet components from enhanced message"""
        header = None
        if message['header']:
            header = Header.deserialize(message['header'])
        
        return {
            'header': header,
            'ciphertext': message['ciphertext'],
            'mac': message['mac'],
            'ad': message['ad'],
            'sealed_sender': message.get('sealed_sender')
        }
    
    def create_ack_message(self, from_user, to_user, original_message_id):
        """Create acknowledgment message"""
        return self.create_message(
            from_user=from_user,
            to_user=to_user,
            message_type=self.MESSAGE_TYPES['ACK'],
            header=None,
            ciphertext=b64encode(f"ACK:{original_message_id}".encode()).decode(),
            mac="",
            ad="",
            plaintext_content=f"ACK:{original_message_id}"
        )
    
    def create_system_message(self, from_user, to_user, system_msg):
        """Create system message (e.g., key rotation notification)"""
        return self.create_message(
            from_user=from_user,
            to_user=to_user,
            message_type=self.MESSAGE_TYPES['SYSTEM'],
            header=None,
            ciphertext=b64encode(system_msg.encode()).decode(),
            mac="",
            ad="",
            plaintext_content=system_msg
        )
    
    def get_message_age(self, message):
        """Get age of message in seconds"""
        current_time = int(time.time() * 1000)
        message_time = message['timestamp']
        return (current_time - message_time) / 1000

    # --- Sealed sender helpers -------------------------------------------------

    def create_sealed_sender_envelope(self, sender_id: str,
                                      sender_identity_key: x25519.X25519PrivateKey,
                                      recipient_identity_key: x25519.X25519PublicKey,
                                      binding: Optional[bytes] = None) -> Dict[str, Any]:
        """Produce a sealed sender envelope so the server cannot read the sender."""
        
        if not sender_identity_key or not recipient_identity_key:
            raise ValueError("Identity keys required for sealed sender envelope")

        ephemeral_key = x25519.X25519PrivateKey.generate()
        shared_secret = ephemeral_key.exchange(recipient_identity_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"sealed-sender",
            info=b"sender-envelope" + (binding or b""),
        )
        seal_key = hkdf.derive(shared_secret)

        payload = {
            'sender_id': sender_id,
            'sender_identity': b64encode(sender_identity_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),
            'timestamp': int(time.time()),
        }

        payload_bytes = json.dumps(payload).encode('utf-8')
        aesgcm = AESGCM(seal_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)

        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        hint = hashlib.sha256(ciphertext).hexdigest()[:16]

        return {
            'ephemeral': b64encode(ephemeral_public).decode(),
            'nonce': b64encode(nonce).decode(),
            'ciphertext': b64encode(ciphertext).decode(),
            'hint': hint
        }

    def open_sealed_sender_envelope(self, sealed_sender: Dict[str, Any],
                                    recipient_identity_key: x25519.X25519PrivateKey,
                                    binding: Optional[bytes] = None) -> Dict[str, Any]:
        """Recover sender information from a sealed sender envelope."""
        if not sealed_sender:
            raise ValueError("No sealed sender data supplied")
        if not recipient_identity_key:
            raise ValueError("Recipient identity key required for sealed sender")

        ephemeral_bytes = b64decode(sealed_sender['ephemeral'])
        nonce = b64decode(sealed_sender['nonce'])
        ciphertext = b64decode(sealed_sender['ciphertext'])

        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_bytes)
        shared_secret = recipient_identity_key.exchange(ephemeral_public)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"sealed-sender",
            info=b"sender-envelope" + (binding or b""),
        )
        seal_key = hkdf.derive(shared_secret)

        aesgcm = AESGCM(seal_key)
        payload_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        payload = json.loads(payload_bytes.decode('utf-8'))
        payload['hint'] = sealed_sender.get('hint')
        return payload