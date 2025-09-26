from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64

MAX_SKIP = 10

def serialize(val):
    return base64.standard_b64encode(val).decode('utf-8')

def deserialize(val):
    return base64.standard_b64decode(val.encode('utf-8'))

def GENERATE_DH():
    sk = x25519.X25519PrivateKey.generate()
    return sk

def DH(dh_pair, dh_pub):
    dh_out = dh_pair.exchange(dh_pub)
    return dh_out

def KDF_RK(rk, dh_out):
    # rk is hkdf salt, dh_out is hkdf input key material
    if isinstance(rk, x25519.X25519PublicKey):
        rk_bytes = rk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        rk_bytes = rk

    info = b"kdf_rk_info"
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk_bytes,
        info=info,
    )
    
    h_out = hkdf.derive(dh_out)
    root_key = h_out[:32]
    chain_key = h_out[32:]

    return (root_key, chain_key)

def KDF_CK(ck):
    if ck is None:
        raise ValueError("Chain key cannot be None in KDF_CK")
        
    if isinstance(ck, x25519.X25519PublicKey):
        ck_bytes = ck.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        ck_bytes = ck

    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x01]))
    message_key = h.finalize()

    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x02]))
    next_ck = h.finalize()

    return (next_ck, message_key)

class Header:
    def __init__(self, dh, pn, n):
        self.dh = dh
        self.pn = pn
        self.n = n
    
    def serialize(self):
        # Fixed serialization to handle integers properly
        pn_bytes = self.pn.to_bytes((self.pn.bit_length() + 7) // 8, 'big') if self.pn > 0 else b'\x00'
        n_bytes = self.n.to_bytes((self.n.bit_length() + 7) // 8, 'big') if self.n > 0 else b'\x00'
        return {
            'dh': serialize(self.dh), 
            'pn': serialize(pn_bytes), 
            'n': serialize(n_bytes)
        }

    @staticmethod
    def deserialize(val):
        dh = deserialize(val['dh'])
        pn_bytes = deserialize(val['pn'])
        n_bytes = deserialize(val['n'])
        pn = int.from_bytes(pn_bytes, 'big') if pn_bytes else 0
        n = int.from_bytes(n_bytes, 'big') if n_bytes else 0
        return Header(dh, pn, n)

def HEADER(dh_pair, pn, n):
    pk = dh_pair.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return Header(pk_bytes, pn, n)

def CONCAT(ad, header):
    return (ad, header)

def RatchetEncrypt(state, plaintext, AD):
    state["CKs"], mk = KDF_CK(state["CKs"])
    header = HEADER(state["DHs"], state["PN"], state["Ns"])
    state["Ns"] += 1
    return header, ENCRYPT_DOUB_RATCH(mk, plaintext, CONCAT(AD, header))

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    
    # Compare DH keys properly
    current_dh = x25519.X25519PublicKey.from_public_bytes(header.dh)
    if state["DHr"] is None or not _compare_dh_keys(current_dh, state["DHr"]):
        SkipMessageKeys(state, header.pn)
        DHRatchet(state, header)
    
    SkipMessageKeys(state, header.n)             
    state["CKr"], mk = KDF_CK(state["CKr"])
    state["Nr"] += 1
    padded_plain_text = DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(padded_plain_text) + unpadder.finalize()

def _compare_dh_keys(key1, key2):
    """Helper function to compare two X25519 public keys"""
    if key1 is None or key2 is None:
        return False
    key1_bytes = key1.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    key2_bytes = key2.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return key1_bytes == key2_bytes

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    key = (header.dh, header.n)
    if key in state["MKSKIPPED"]:
        mk = state["MKSKIPPED"][key]
        del state["MKSKIPPED"][key]
        padded_plain_text = DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
        unpadder = padding.PKCS7(256).unpadder()
        return unpadder.update(padded_plain_text) + unpadder.finalize()
    else:
        return None

def SkipMessageKeys(state, until):
    if state["Nr"] + MAX_SKIP < until:
        raise Exception("Too many skipped messages")
    if state["CKr"] != None:
        while state["Nr"] < until:
            state["CKr"], mk = KDF_CK(state["CKr"])
            DHr_bytes = state["DHr"].public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            state["MKSKIPPED"][(DHr_bytes, state["Nr"])] = mk
            state["Nr"] += 1

def DHRatchet(state, header):
    state["PN"] = state["Ns"]                          
    state["Ns"] = 0
    state["Nr"] = 0
    state["DHr"] = x25519.X25519PublicKey.from_public_bytes(header.dh)
    state["RK"], state["CKr"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))
    state["DHs"] = GENERATE_DH()
    state["RK"], state["CKs"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))

def ENCRYPT_DOUB_RATCH(mk, plaintext, associated_data):
    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    ad, header = associated_data
    pk, pn_bytes, n_bytes = header.dh, header.pn, header.n
    
    # Convert integers to bytes for concatenation
    pn_bytes = pn_bytes.to_bytes((pn_bytes.bit_length() + 7) // 8, 'big') if pn_bytes > 0 else b'\x00'
    n_bytes = n_bytes.to_bytes((n_bytes.bit_length() + 7) // 8, 'big') if n_bytes > 0 else b'\x00'
    
    assoc_data = ad + pk + pn_bytes + n_bytes

    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()

    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)

def DECRYPT_DOUB_RATCH(mk, cipherout, associated_data):
    ciphertext = cipherout[0]
    mac = cipherout[1]

    info = b"encrypt_info_kdf"
    zero_filled = b"\x00"*80
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    # Verify MAC first
    h = hmac.HMAC(auth_key, hashes.SHA256())
    
    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    
    # Convert integers to bytes for concatenation
    pn_bytes = pn.to_bytes((pn.bit_length() + 7) // 8, 'big') if pn > 0 else b'\x00'
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b'\x00'
    
    assoc_data = ad + pk + pn_bytes + n_bytes
    
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()

    h.update(padded_assoc_data + ciphertext) 
    
    try:
        h.verify(mac)
    except:
        raise Exception("MAC verification failed")

    # Decrypt after MAC verification
    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

# Initialize Double Ratchet state for sending user
def RatchetInitSender(SK, bob_public_key):
    state = {
        "DHs": GENERATE_DH(),
        "DHr": bob_public_key,
        "RK": SK,
        "CKs": None,
        "CKr": None,
        "Ns": 0,
        "Nr": 0,
        "PN": 0,
        "MKSKIPPED": {}
    }
    state["RK"], state["CKs"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))
    return state

# Initialize Double Ratchet state for receiving user  
def RatchetInitReceiver(SK, alice_public_key):
    state = {
        "DHs": GENERATE_DH(),
        "DHr": alice_public_key,
        "RK": SK,
        "CKs": None,
        "CKr": None,
        "Ns": 0,
        "Nr": 0,
        "PN": 0,
        "MKSKIPPED": {}
    }
    return state

class DoubleRatchetSession:
    """Object-oriented wrapper for Double Ratchet state management"""
    
    def __init__(self):
        self.state = None
        self.initialized = False
    
    def init_alice(self, private_key, bob_public_key):
        """Initialize as Alice (sender)"""
        # Use a default shared secret for demo (in real use, this comes from X3DH)
        shared_secret = b"default_shared_secret_32_bytes!!"[:32]
        self.state = RatchetInitSender(shared_secret, bob_public_key)
        self.initialized = True
    
    def init_alice_with_shared_key(self, shared_key, bob_public_key):
        """Initialize as Alice with specific shared key"""
        self.state = RatchetInitSender(shared_key, bob_public_key)
        self.initialized = True
    
    def init_bob(self, shared_secret=None):
        """Initialize as Bob (receiver) - will be completed when first message arrives"""
        if shared_secret is None:
            shared_secret = b"default_shared_secret_32_bytes!!"[:32]
        self.state = {
            "DHs": GENERATE_DH(),
            "DHr": None,  # Will be set when first message arrives
            "RK": shared_secret,
            "CKs": None,
            "CKr": None,
            "Ns": 0,
            "Nr": 0,
            "PN": 0,
            "MKSKIPPED": {}
        }
        self.initialized = True
    
    def init_bob_with_shared_key(self, shared_key):
        """Initialize as Bob with specific shared key"""
        self.state = {
            "DHs": GENERATE_DH(),
            "DHr": None,  # Will be set when first message arrives
            "RK": shared_key,
            "CKs": None,
            "CKr": None,
            "Ns": 0,
            "Nr": 0,
            "PN": 0,
            "MKSKIPPED": {}
        }
        self.initialized = True
    
    def ratchet_encrypt(self, plaintext):
        """Encrypt a message"""
        if not self.initialized or self.state is None:
            raise ValueError("Session not initialized")
        
        ad = b"double_ratchet_message"  # Associated data
        header, ciphertext = RatchetEncrypt(self.state, plaintext.encode(), ad)
        
        # Return components needed for enhanced message format
        return header, serialize(ciphertext[0]), serialize(ciphertext[1]), serialize(ad)
    
    def ratchet_decrypt(self, header, ciphertext, mac, ad):
        """Decrypt a message"""
        if not self.initialized or self.state is None:
            raise ValueError("Session not initialized")
        
        # Reconstruct ciphertext tuple
        ciphertext_bytes = deserialize(ciphertext)
        mac_bytes = deserialize(mac)
        ad_bytes = deserialize(ad)
        
        ciphertext_tuple = (ciphertext_bytes, mac_bytes)
        
        plaintext = RatchetDecrypt(self.state, header, ciphertext_tuple, ad_bytes)
        return plaintext.decode()
    
    def get_state(self):
        """Get current state for serialization"""
        if self.state is None:
            return None
        
        # Convert X25519 keys to serializable format
        serializable_state = {}
        for key, value in self.state.items():
            if key == "DHs" and value:
                # Serialize private key
                private_bytes = value.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                serializable_state[key] = serialize(private_bytes)
            elif key == "DHr" and value:
                # Serialize public key
                public_bytes = value.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                serializable_state[key] = serialize(public_bytes)
            elif key == "MKSKIPPED" and isinstance(value, dict):
                # Handle MKSKIPPED dictionary with tuple keys
                serializable_mkskipped = {}
                for tuple_key, mk_val in value.items():
                    if isinstance(tuple_key, tuple) and len(tuple_key) == 2:
                        dh_key, n_val = tuple_key
                        # Convert tuple key to string
                        if hasattr(dh_key, 'public_bytes'):
                            # It's a public key object
                            dh_bytes = dh_key.public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw
                            )
                            key_str = f"{serialize(dh_bytes)}:{n_val}"
                        elif isinstance(dh_key, bytes):
                            key_str = f"{serialize(dh_key)}:{n_val}"
                        else:
                            key_str = f"{str(dh_key)}:{n_val}"
                        
                        # Serialize the message key if it's bytes
                        serializable_mkskipped[key_str] = serialize(mk_val) if isinstance(mk_val, bytes) else mk_val
                    else:
                        # Fallback for non-tuple keys
                        serializable_mkskipped[str(tuple_key)] = serialize(mk_val) if isinstance(mk_val, bytes) else mk_val
                        
                serializable_state[key] = serializable_mkskipped
            elif isinstance(value, bytes):
                serializable_state[key] = serialize(value)
            else:
                serializable_state[key] = value
        
        return serializable_state
    
    def restore_state(self, serializable_state):
        """Restore state from serialized format"""
        if serializable_state is None:
            return
        
        self.state = {}
        for key, value in serializable_state.items():
            if key == "DHs" and value:
                # Deserialize private key
                private_bytes = deserialize(value)
                self.state[key] = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
            elif key == "DHr" and value:
                # Deserialize public key
                public_bytes = deserialize(value)
                self.state[key] = x25519.X25519PublicKey.from_public_bytes(public_bytes)
            elif key == "MKSKIPPED" and isinstance(value, dict):
                # Restore MKSKIPPED dictionary with tuple keys
                mkskipped_dict = {}
                for key_str, mk_val in value.items():
                    if ':' in key_str:
                        # Split the string key back to tuple components
                        parts = key_str.split(':', 1)  # Split only on first colon
                        try:
                            dh_bytes = deserialize(parts[0])
                            n_val = int(parts[1])
                            # Reconstruct the public key
                            dh_key = x25519.X25519PublicKey.from_public_bytes(dh_bytes)
                            tuple_key = (dh_key, n_val)
                            # Deserialize the message key
                            mkskipped_dict[tuple_key] = deserialize(mk_val) if isinstance(mk_val, str) else mk_val
                        except:
                            # If deserialization fails, skip this entry
                            continue
                    else:
                        # Handle fallback cases
                        try:
                            mkskipped_dict[key_str] = deserialize(mk_val) if isinstance(mk_val, str) else mk_val
                        except:
                            mkskipped_dict[key_str] = mk_val
                self.state[key] = mkskipped_dict
            elif isinstance(value, str) and key in ["RK", "CKs", "CKr"]:
                # Deserialize byte values
                try:
                    self.state[key] = deserialize(value) if value else None
                except:
                    self.state[key] = value
            else:
                self.state[key] = value
        
        self.initialized = True