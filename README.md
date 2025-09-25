# Double Ratchet Chat System

A simple **Python client-server chat system** using the **Double Ratchet Algorithm** for end-to-end encrypted messaging.

Messages are stored in a **server-side in-memory queue** per user (max 10 messages), and users authenticate with **username & password**.

---

## Features

- User registration with **username + password**  
- **X25519 keys** generated per user for Double Ratchet  
- Client login to send/receive messages  
- Interactive terminal interface:
  - `/send <recipient> <message>` → send message  
  - `/fetch` → fetch new messages  
  - `/users` → list all users  
  - `/exit` → quit client  
- **Server stores messages in-memory** (max 10 per user, oldest removed)  
- End-to-end encryption with **Double Ratchet**  

---

## Requirements

- Python 3.10+  
- `cryptography` library  

Install dependencies:

```bash
pip install cryptography
