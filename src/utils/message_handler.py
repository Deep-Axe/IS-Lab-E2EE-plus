# message_handler.py - Enhanced Message Format with Versioning and Replay Protection
import json
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
        
    def create_message(self, from_user, to_user, message_type, header, ciphertext, mac, ad, plaintext_content=None):
        """Create enhanced message format with versioning and replay protection"""
        
        # Generate unique message ID
        message_id = self._generate_message_id(from_user, to_user, header, ciphertext)
        
        # Create enhanced message
        enhanced_message = {
            'version': self.PROTOCOL_VERSION,
            'message_id': message_id,
            'timestamp': int(time.time() * 1000),  # milliseconds
            'from': from_user,
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
            required_fields = ['version', 'message_id', 'timestamp', 'from', 'to', 'message_type']
            for field in required_fields:
                if field not in message:
                    return False, f"Missing required field: {field}"
            
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
            sender = message['from']
            if sender in self.last_seen_timestamps:
                last_timestamp = self.last_seen_timestamps[sender]
                current_timestamp = message_time
                
                # Allow messages with equal or later timestamps
                # In production, you'd use a more sophisticated ordering mechanism
                if current_timestamp < last_timestamp:
                    return False, f"Message timestamp too old for sender {sender}"
                elif current_timestamp == last_timestamp:
                    # For same timestamp, check sequence number if available
                    if 'sequence_number' in message:
                        # This is a simplified check - real systems need more complex ordering
                        pass  # Allow same timestamp with different sequence numbers
                    
            return True, "Message valid"
            
        except Exception as e:
            return False, f"Message validation error: {e}"
    
    def record_message(self, message):
        """Record message to prevent replay attacks"""
        message_id = message['message_id']
        sender = message['from']
        timestamp = message['timestamp']
        
        # Add to received set
        self.received_message_ids.add(message_id)
        
        # Update last seen timestamp
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
            'ad': message['ad']
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