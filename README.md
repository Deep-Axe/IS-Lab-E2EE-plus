# Forward Secrecy Chat Demo: Alice ↔ Bob + Malory

A **Python demonstration** of **forward secrecy** in encrypted messaging. Alice and Bob can chat bidirectionally through a server while Malory intercepts all ciphertext and attempts decryption.

---

## 🚨 What This Code Actually Implements

**❌ NOT Double Ratchet** - This is **basic forward secrecy** using key chains.

**✅ What's Implemented:**

- **Forward Secrecy**: Each message uses a unique key from a pre-generated chain
- **Key Rotation**: Keys advance after each message (cannot reuse old keys)
- **Bidirectional Chat**: Alice ↔ Bob can both send and receive messages
- **Separate Key Chains**: Alice→Bob and Bob→Alice use different key sequences
- **Eavesdropping Demo**: Malory intercepts all ciphertext

**❌ Missing for True Double Ratchet:**

- No Diffie-Hellman key exchanges
- No asymmetric ratcheting with ephemeral keys
- No proper message ordering/skipping
- No root key updates after each DH exchange

---

## 🏗️ System Architecture

```
Alice ←→ Server ←→ Bob
         ↓
      Malory 🕵️
   (Intercepts All)
```

- **Alice**: Sends encrypted messages, can receive from Bob
- **Bob**: Receives encrypted messages, can send to Alice
- **Server**: Relays encrypted messages (plaintext never exposed)
- **Malory**: Intercepts all ciphertext, tries to decrypt with stolen keys

---

## 🚀 How to Run

### 1. Install Dependencies

```bash
pip install cryptography
```

### 2. Start the Demo (4 terminals)

**Terminal 1 - Server:**

```bash
python server.py
```

**Terminal 2 - Alice:**

```bash
python alice.py
# Commands: send <message>, fetch, key <index>, quit
```

**Terminal 3 - Bob:**

```bash
python bob.py
# Commands: send <message>, fetch, key <index>, quit
```

**Terminal 4 - Malory:**

```bash
python malory.py
# Commands: intercept, list, decrypt <msg_index> <key>, quit
```

---


### Step 1: Start Chat

1. Alice: `send Hello Bob!`
2. Bob: `fetch` → sees "Hello Bob!"
3. Bob: `send Hi Alice!`
4. Alice: `fetch` → sees "Hi Alice!"

### Step 2: Malory Intercepts

1. Malory: `intercept` → gets all ciphertext
2. Malory: `list` → shows intercepted messages
3. Malory tries to decrypt → **fails without keys**

### Step 3: Forward Secrecy Test

1. Alice: `key 0` → reveals key for her first message
2. Malory: `decrypt 1 <alice_key>` → **Success** (decrypts Alice's message)
3. Malory: `decrypt 2 <alice_key>` → **Fails** (different key needed!)
4. Malory cannot decrypt Bob's messages with Alice's key

### Key Insight: Forward Secrecy Works!

- Even with Alice's key, Malory cannot decrypt:
  - Alice's other messages (different keys in chain)
  - Bob's messages (completely separate key chain)

---

## Files

- **`server.py`** - Message relay server, stores ciphertext
- **`alice.py`** - Alice's chat client (can send & receive)
- **`bob.py`** - Bob's chat client (can send & receive)
- **`malory.py`** - Malory's interception tool

---

## 🔐 Cryptographic Details

### Key Generation

- **Alice→Bob**: Derived from seed `alice_to_bob_shared_secret...`
- **Bob→Alice**: Derived from seed `bob_to_alice_shared_secret...`
- **Chain Derivation**: `key[n+1] = HKDF(SHA256(key[n] + "next"))`

### Forward Secrecy Properties

✅ **Key Independence**: Each message key is unique  
✅ **Forward Security**: Past keys cannot decrypt future messages  
✅ **Chain Separation**: Alice/Bob use different key chains  
❌ **No Backward Security**: Future keys can derive past keys (not full Double Ratchet)

### Encryption

- **Algorithm**: AES-GCM (authenticated encryption)
- **Key Size**: 256-bit keys
- **Nonce**: 96-bit random nonce per message

---

## 🎓 Educational Value

This demo teaches:

1. **Forward secrecy concepts** without Double Ratchet complexity
2. **Key chain management** and rotation
3. **Man-in-the-middle attacks** (Malory's interception)
4. **Cryptographic key isolation** between communication directions

Perfect for understanding why messaging apps like Signal use Double Ratchet - this simpler approach still has vulnerabilities that full Double Ratchet addresses!

---

## ⚠️ Disclaimer

**For educational use only!** This is a simplified demonstration:

- Fixed shared secrets (insecure for real use)
- No proper key exchange protocol
- No message authentication beyond AEAD
- Server stores all ciphertext (metadata leakage)

Real secure messaging requires proper Double Ratchet implementation with DH key exchanges!
