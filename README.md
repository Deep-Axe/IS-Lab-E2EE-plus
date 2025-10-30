# Double Ratchet End-to-End Encryption Demo 
## Overview


### Core Cryptographic Implementation

- **Complete Double Ratchet Protocol**
- **X25519 Elliptic Curve Diffie-Hellman**
- **HKDF Root Key Derivation** - RFC 5869 compliant key derivation
- **HMAC-SHA256 Chain Keys** - Secure chain key advancement
- **AES-256-CBC Encryption** - Industry standard symmetric encryption
- **Message Ordering & Skipping** - Handles out-of-order and lost messages
- **Forward & Backward Secrecy** - Perfect secrecy properties
- **Persistent State Management** - Encrypted state storage with PBKDF2
- **Key Backup & Restore** - Secure session backup and recovery
- **Enhanced Message Format** - Versioned messages with replay protection
- **Comprehensive Error Handling** - Detailed error categorization and recovery
- **Basic X3DH Integration** - Initial key agreement protocol
- **Message Validation** - Timestamp and sequence validation
- **Replay Attack Protection** - Message ID tracking and timestamp verification
- **Retry & Recovery Logic** - Automatic error recovery and retry mechanisms
- **Logging & Monitoring** - Comprehensive error tracking and statistics

### Architecture Components

- **Message Relay Server**: Handles key exchange and message forwarding
- **State Manager**: Encrypted persistent storage with backup/restore
- **Error Handler**: Centralized error management with recovery suggestions
- **Message Handler**: Enhanced message format with versioning and validation
- **X3DH Integration**: Basic initial key agreement (simplified implementation)
- **Cryptanalysis Tool**: Enhanced Malory for security analysis

## Technical Implementation

### Cryptographic Primitives

- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Key Derivation**: HKDF-SHA256 with proper salt and info parameters
- **Symmetric Encryption**: AES-256-CBC with PKCS7 padding
- **Message Authentication**: HMAC-SHA256
- **State Encryption**: AES-256-CBC with PBKDF2 (100,000 iterations)

### Message Format

```json
{
  "version": "1.0",
  "message_id": "unique_identifier",
  "timestamp": 1640995200000,
  "from": "Alice",
  "to": "Bob",
  "message_type": 1,
  "sequence_number": 5,
  "header": "base64_encoded_ratchet_header",
  "ciphertext": "base64_encoded_encrypted_data",
  "mac": "base64_encoded_hmac",
  "ad": "base64_encoded_associated_data",
  "metadata": {
    "client_version": "DoubleRatchetDemo-1.0",
    "encryption_algorithm": "AES-256-CBC",
    "mac_algorithm": "HMAC-SHA256",
    "dh_algorithm": "X25519"
  }
}
```

### Security Features

- **Message Replay Protection**: Duplicate message ID detection
- **Timestamp Validation**: Clock skew tolerance with replay prevention
- **State Persistence**: Encrypted storage with password-based key derivation
- **Error Recovery**: Comprehensive exception handling with recovery suggestions
- **Key Rotation**: Automatic DH ratchet advancement per Double Ratchet spec

### Modules

- `state_manager.py` - Encrypted persistent state with backup/restore
- `message_handler.py` - Enhanced message format with replay protection
- `error_handler.py` - Comprehensive error handling and recovery
- `x3dh_integration.py` - Basic X3DH initial key agreement

## Usage Instructions

**Optional - Multi-Contact Client (single terminal):**

```bash
python run.py multi-client <reg_user>
```

Register each demo user with `python -m tools.register_user` before logging in. Launch one instance per user, set the active contact with `use <name>`, and exchange messages without restarting the client for each peer.

**Optional - Web Dashboard (Consolidated View):**

```bash
python -m tools.dashboard --port 8080
```

Then open `http://localhost:8080/` to watch intercepted traffic, sealed-sender hints, and session statistics update in real time while Alice, Bob, and Malory are running.

### 2. Key Features Demonstrated

#### Persistent State Management

- Session states are encrypted and stored locally
- Automatic backup creation with timestamp
- State restoration across client restarts
- Password-based key derivation (PBKDF2)

#### X3DH Key Exchange

- Initial key agreement before Double Ratchet
- Identity key and ephemeral key exchange
- Fallback to simple key exchange if X3DH fails
- Proper shared secret derivation

#### Error Handling

- Categorized error codes and recovery suggestions
- Automatic retry with exponential backoff
- Comprehensive error statistics and logging
- Graceful degradation on failures

#### Message Validation

- Protocol version checking
- Replay attack detection via message IDs
- Timestamp validation with clock skew tolerance
- Sequence number gap detection

- Secure messaging system development
- Cryptographic protocol implementation studies
- Post-quantum cryptography adaptation research
- Forward secrecy mechanism analysis
