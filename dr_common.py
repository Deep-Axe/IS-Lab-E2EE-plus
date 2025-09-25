# dr_common.py
import os, base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Helpers
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

# Key generation and DH
def gen_x25519_keypair():
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def dh(sk: x25519.X25519PrivateKey, pk: x25519.X25519PublicKey) -> bytes:
    return sk.exchange(pk)

# HKDF
def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    ).derive(ikm)

# Ratchet derivations
def kdf_root(root_key: bytes, dh_out: bytes):
    derived = hkdf(root_key, dh_out, b"DoubleRatchetRoot", 64)
    return derived[:32], derived[32:64]  # new_root, chain_key

def kdf_chain(chain_key: bytes):
    derived = hkdf(chain_key, b"", b"DoubleRatchetChain", 64)
    return derived[:32], derived[32:64]  # next_chain_key, message_key

# AEAD helpers
def encrypt_message(key: bytes, plaintext: bytes, aad: bytes = b""):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct

def decrypt_message(key: bytes, data: bytes, aad: bytes = b""):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(nonce, ct, aad)

# Serialize/deserialize public keys
def pk_bytes(pk: x25519.X25519PublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def pk_from_bytes(b: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b)
