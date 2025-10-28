# double_ratchet.py (Modified for Demonstration)

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
    # ====================================================================
    # DEMO MODIFICATION 1: Return the message key (mk) as well.
    # ====================================================================
    return header, ENCRYPT_DOUB_RATCH(mk, plaintext, CONCAT(AD, header)), mk

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    
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
    # Ensure the key is constructed correctly for lookup
    dh_bytes = header.dh
    key = (dh_bytes, header.n)

    # Check against serialized keys if necessary
    if key not in state["MKSKIPPED"]:
        for k_tuple, v in state["MKSKIPPED"].items():
            if isinstance(k_tuple[0], x25519.X25519PublicKey):
                 k_bytes = k_tuple[0].public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                 if k_bytes == dh_bytes and k_tuple[1] == header.n:
                     key = k_tuple
                     break

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
            state["MKSKIPPED"][(state["DHr"], state["Nr"])] = mk
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
    # Use header attributes directly
    pk, pn_val, n_val = header.dh, header.pn, header.n
    
    pn_bytes = pn_val.to_bytes((pn_val.bit_length() + 7) // 8, 'big') if pn_val > 0 else b'\x00'
    n_bytes = n_val.to_bytes((n_val.bit_length() + 7) // 8, 'big') if n_val > 0 else b'\x00'
    
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

    h = hmac.HMAC(auth_key, hashes.SHA256())
    
    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    
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

    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

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
    def __init__(self):
        self.state = None
        self.initialized = False
    
    def init_alice(self, private_key, bob_public_key):
        shared_secret = b"default_shared_secret_32_bytes!!"[:32]
        self.state = RatchetInitSender(shared_secret, bob_public_key)
        self.initialized = True
    
    def init_alice_with_shared_key(self, shared_key, bob_public_key):
        self.state = RatchetInitSender(shared_key, bob_public_key)
        self.initialized = True
    
    def init_bob(self, shared_secret=None):
        if shared_secret is None:
            shared_secret = b"default_shared_secret_32_bytes!!"[:32]
        self.state = {
            "DHs": GENERATE_DH(), "DHr": None, "RK": shared_secret,
            "CKs": None, "CKr": None, "Ns": 0, "Nr": 0, "PN": 0, "MKSKIPPED": {}
        }
        self.initialized = True
    
    def init_bob_with_shared_key(self, shared_key):
        self.state = {
            "DHs": GENERATE_DH(), "DHr": None, "RK": shared_key,
            "CKs": None, "CKr": None, "Ns": 0, "Nr": 0, "PN": 0, "MKSKIPPED": {}
        }
        self.initialized = True
    
    def ratchet_encrypt(self, plaintext):
        if not self.initialized or self.state is None:
            raise ValueError("Session not initialized")
        
        ad = b"double_ratchet_message"
        
        # ====================================================================
        # DEMO MODIFICATION 2: Capture the returned message key.
        # ====================================================================
        header, ciphertext, message_key = RatchetEncrypt(self.state, plaintext.encode(), ad)
        
        # ====================================================================
        # DEMO MODIFICATION 3: Return the message key from this method.
        # ====================================================================
        return header, serialize(ciphertext[0]), serialize(ciphertext[1]), serialize(ad), message_key
    
    def ratchet_decrypt(self, header, ciphertext, mac, ad):
        if not self.initialized or self.state is None:
            raise ValueError("Session not initialized")
        
        ciphertext_bytes = deserialize(ciphertext)
        mac_bytes = deserialize(mac)
        ad_bytes = deserialize(ad)
        
        ciphertext_tuple = (ciphertext_bytes, mac_bytes)
        
        plaintext = RatchetDecrypt(self.state, header, ciphertext_tuple, ad_bytes)
        return plaintext.decode()
    
    def get_state(self):
        if self.state is None:
            return None
        
        serializable_state = {}
        for key, value in self.state.items():
            if key == "DHs" and value:
                private_bytes = value.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                serializable_state[key] = serialize(private_bytes)
            elif key == "DHr" and value:
                public_bytes = value.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                serializable_state[key] = serialize(public_bytes)
            elif key == "MKSKIPPED" and isinstance(value, dict):
                serializable_mkskipped = {}
                for tuple_key, mk_val in value.items():
                    if isinstance(tuple_key, tuple) and len(tuple_key) == 2:
                        dh_key_obj, n_val = tuple_key
                        dh_key_bytes = dh_key_obj.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        key_str = f"{serialize(dh_key_bytes)}:{n_val}"
                        serializable_mkskipped[key_str] = serialize(mk_val)
                serializable_state[key] = serializable_mkskipped
            elif isinstance(value, bytes):
                serializable_state[key] = serialize(value)
            else:
                serializable_state[key] = value
        
        return serializable_state
    
    def restore_state(self, serializable_state):
        if serializable_state is None:
            return
        
        self.state = {}
        for key, value in serializable_state.items():
            if key == "DHs" and value:
                private_bytes = deserialize(value)
                self.state[key] = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
            elif key == "DHr" and value:
                public_bytes = deserialize(value)
                self.state[key] = x25519.X25519PublicKey.from_public_bytes(public_bytes)
            elif key == "MKSKIPPED" and isinstance(value, dict):
                mkskipped_dict = {}
                for key_str, mk_val in value.items():
                    try:
                        dh_b64, n_str = key_str.split(':', 1)
                        dh_bytes = deserialize(dh_b64)
                        n_val = int(n_str)
                        dh_key = x25519.X25519PublicKey.from_public_bytes(dh_bytes)
                        mkskipped_dict[(dh_key, n_val)] = deserialize(mk_val)
                    except:
                        continue
                self.state[key] = mkskipped_dict
            elif isinstance(value, str) and key in ["RK", "CKs", "CKr"]:
                try:
                    self.state[key] = deserialize(value) if value else None
                except:
                    self.state[key] = value
            else:
                self.state[key] = value
        
        self.initialized = True