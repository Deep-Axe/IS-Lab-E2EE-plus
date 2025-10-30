# enhanced_multi_client.py - Multi-contact E2EE client
import json
import os
import re
import socket
import threading
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Dict, Optional
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

try:
    from core.double_ratchet import DoubleRatchetSession
    from utils.error_handler import ErrorHandler
    from utils.message_handler import MessageHandler
    from utils.state_manager import StateManager
    from security.x3dh_integration import X3DHSession
except ImportError:  # pragma: no cover
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.double_ratchet import DoubleRatchetSession  # type: ignore
    from utils.error_handler import ErrorHandler  # type: ignore
    from utils.message_handler import MessageHandler  # type: ignore
    from utils.state_manager import StateManager  # type: ignore
    from security.x3dh_integration import X3DHPreKey, X3DHSession  # type: ignore


@dataclass
class ContactSession:
    contact_id: str
    session: Optional[DoubleRatchetSession] = None
    session_initialized: bool = False
    peer_identity_key: Optional[x25519.X25519PublicKey] = None
    pending_ephemeral: Optional[x25519.X25519PrivateKey] = None
    pending_shared_key: Optional[bytes] = None
    role: Optional[str] = None
    handshake_event: threading.Event = field(default_factory=threading.Event)
    handshake_in_progress: bool = False
    first_message_logged: bool = False


class EnhancedMultiClient:
    PASSWORD_PATTERN = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$")

    def __init__(self) -> None:
        self.error_handler = ErrorHandler()
        self.state_manager = StateManager(self.error_handler)
        self.message_handler = MessageHandler()
        self.x3dh_session = X3DHSession(self.error_handler)

        self.client_socket: Optional[socket.socket] = None
        self.socket_lock = threading.Lock()
        self.print_lock = threading.Lock()

        self.listener_thread: Optional[threading.Thread] = None
        self.running = False

        self.username: Optional[str] = None
        self.state_password: Optional[str] = None
        self.identity_key: Optional[x25519.X25519PrivateKey] = None

        self.contacts: Dict[str, dict] = {}
        self.contact_sessions: Dict[str, ContactSession] = {}
        self.active_contact: Optional[str] = None

        self.login_event = threading.Event()
        self.contacts_event = threading.Event()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def connect(self, host: str = "localhost", port: int = 9999) -> bool:
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            self.client_socket.connect((host, port))
            self.client_socket.settimeout(1)
            self.running = True
            self.listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
            self.listener_thread.start()
            self._print("Connected to server")
            return True
        except Exception as exc:
            self.error_handler.handle_error(exc, "connect")
            self._print(f"Failed to connect: {exc}")
            return False

    def disconnect(self) -> None:
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2)
        self._print("Disconnected")

    # ------------------------------------------------------------------
    # Identity and session persistence
    # ------------------------------------------------------------------
    def _identity_state_id(self) -> str:
        return f"{self.username}_identity"

    def _session_state_id(self, contact: str) -> str:
        safe_contact = contact.lower().replace(" ", "_")
        return f"{self.username}__{safe_contact}"

    def load_identity(self) -> None:
        assert self.username is not None
        if self.state_manager.state_exists(self._identity_state_id()):
            stored = self.state_manager.load_state(self._identity_state_id(), self.state_password or "")
            sealed = stored.get("sealed_sender", {})
            private_b64 = sealed.get("identity_private")
            if private_b64:
                private_bytes = b64decode(private_b64)
                self.identity_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
                self._print("Loaded identity key from disk")
        if not self.identity_key:
            self.identity_key = self.x3dh_session.generate_identity_key()
            self._print("Generated new identity key")
            self.save_identity()

    def save_identity(self) -> None:
        if not self.username or not self.identity_key:
            return
        data = {
            "sealed_sender": {
                "identity_private": b64encode(
                    self.identity_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                ).decode()
            }
        }
        self.state_manager.save_state(self._identity_state_id(), data, self.state_password or "")

    def load_contact_session(self, contact: str) -> bool:
        if not self.username:
            raise RuntimeError("Client not initialized")
        session_id = self._session_state_id(contact)
        if not self.state_manager.state_exists(session_id):
            return False
        stored = self.state_manager.load_state(session_id, self.state_password or "")
        context = self._get_or_create_context(contact)
        context.session = DoubleRatchetSession()
        context.session.restore_state(stored["ratchet_state"])
        sealed = stored.get("sealed_sender", {})
        peer_b64 = sealed.get("peer_identity_public")
        if peer_b64:
            peer_bytes = b64decode(peer_b64)
            context.peer_identity_key = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        context.role = stored.get("role")
        context.session_initialized = True
        context.handshake_event.set()
        context.first_message_logged = bool(stored.get("first_message_logged", False))
        self._print(f"Restored session with {contact}")
        return True

    def save_contact_session(self, contact: str) -> None:
        if not self.username:
            raise RuntimeError("Client not initialized")
        context = self.contact_sessions.get(contact)
        if not context or not context.session or not context.session_initialized:
            return
        state_data = {
            "client_id": self.username,
            "contact": contact,
            "ratchet_state": context.session.get_state(),
            "role": context.role,
            "last_updated": int(time.time()),
            "first_message_logged": context.first_message_logged,
        }
        if self.identity_key or context.peer_identity_key:
            sealed = {}
            if self.identity_key:
                sealed["identity_private"] = b64encode(
                    self.identity_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                ).decode()
            if context.peer_identity_key:
                sealed["peer_identity_public"] = b64encode(
                    context.peer_identity_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ).decode()
            state_data["sealed_sender"] = sealed
        self.state_manager.save_state(self._session_state_id(contact), state_data, self.state_password or "")

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------
    def _get_or_create_context(self, contact: str) -> ContactSession:
        if contact not in self.contact_sessions:
            self.contact_sessions[contact] = ContactSession(contact_id=contact)
        return self.contact_sessions[contact]

    def ensure_session(self, contact: str, timeout: float = 30.0) -> bool:
        if not self.username:
            raise RuntimeError("Client not initialized")
        context = self._get_or_create_context(contact)
        if context.session_initialized:
            return True
        if self.load_contact_session(contact):
            return True
        if context.handshake_in_progress:
            return context.handshake_event.wait(timeout)
        context.handshake_in_progress = True
        context.handshake_event.clear()
        if not self.identity_key:
            self.load_identity()
        if not self.identity_key:
            raise RuntimeError("Identity key unavailable")
        context.pending_ephemeral = x25519.X25519PrivateKey.generate()
        identity_public = self.identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        ephemeral_public = context.pending_ephemeral.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        bundle = {
            "identity_key": b64encode(identity_public).decode(),
            "ephemeral_key": b64encode(ephemeral_public).decode(),
        }
        payload = {
            "type": "x3dh_key_exchange",
            "from": self.username,
            "to": contact,
            "bundle": bundle,
        }
        self._print(f"Initiating X3DH handshake with {contact}")
        self._send_json(payload)
        context.role = "initiator"
        success = context.handshake_event.wait(timeout)
        context.handshake_in_progress = False
        if not success:
            self._print(f"Handshake with {contact} timed out")
        else:
            self._print(f"Handshake with {contact} completed")
        return success and context.session_initialized

    # ------------------------------------------------------------------
    # Networking helpers
    # ------------------------------------------------------------------
    def _send_json(self, payload: dict) -> None:
        if not self.client_socket:
            return
        message = json.dumps(payload).encode("utf-8")
        with self.socket_lock:
            try:
                self.client_socket.sendall(message)
            except Exception as exc:
                self.error_handler.handle_error(exc, "send_json")
                self._print(f"Failed to send payload: {exc}")

    def _listener_loop(self) -> None:
        buffer = ""
        decoder = json.JSONDecoder()
        while self.running and self.client_socket:
            try:
                chunk = self.client_socket.recv(16384)
                if not chunk:
                    time.sleep(0.05)
                    continue
                buffer += chunk.decode("utf-8")
                while buffer:
                    buffer = buffer.lstrip()
                    if not buffer:
                        break
                    try:
                        payload, index = decoder.raw_decode(buffer)
                    except json.JSONDecodeError:
                        break
                    buffer = buffer[index:]
                    self._process_incoming(payload)
            except socket.timeout:
                continue
            except Exception as exc:
                self.error_handler.handle_error(exc, "listener_loop")
                self._print(f"Listener error: {exc}")
                break
        self.running = False

    # ------------------------------------------------------------------
    # Incoming message routing
    # ------------------------------------------------------------------
    def _process_incoming(self, message: dict) -> None:
        msg_type = message.get("type")
        if msg_type == "login_ack":
            if message.get("status") == "ok":
                self._print(f"Logged in as {message.get('username')}")
                self.login_event.set()
            else:
                self._print(f"Login failed: {message.get('message')}")
        elif msg_type == "contact_list":
            contacts = message.get("contacts", [])
            self.contacts = {entry["username"]: entry for entry in contacts if entry.get("username")}
            self.contacts_event.set()
            self._print(f"Received {len(self.contacts)} contacts")
        elif msg_type == "x3dh_key_exchange":
            self._handle_x3dh(message)
        elif msg_type == "dh_public_key":
            self._handle_dh_public_key(message)
        elif msg_type == "simple_key_exchange":
            self._print("Received legacy key exchange request; not supported in multi-client mode")
        elif "ciphertext" in message:
            self._handle_encrypted_message(message)
        else:
            self._print(f"Unknown message type: {msg_type}")

    def _handle_x3dh(self, message: dict) -> None:
        from_user = message.get("from")
        if not from_user or from_user == self.username:
            return
        context = self._get_or_create_context(from_user)
        bundle = message.get("bundle") or {}
        if context.role == "initiator" and context.pending_ephemeral:
            try:
                if not self.identity_key:
                    raise RuntimeError("Identity key missing for X3DH")
                shared_key, _, _ = self.x3dh_session.perform_x3dh_sender(
                    self.identity_key,
                    bundle,
                    context.pending_ephemeral,
                )
                identity_bytes = b64decode(bundle["identity_key"])
                context.peer_identity_key = x25519.X25519PublicKey.from_public_bytes(identity_bytes)
                context.pending_shared_key = shared_key
                self._print(f"{from_user} provided X3DH bundle; waiting for DH public key")
            except Exception as exc:
                self.error_handler.handle_error(exc, "x3dh_sender")
                self._print(f"Failed to process X3DH response from {from_user}: {exc}")
                context.handshake_event.set()
        else:
            try:
                if not self.identity_key:
                    self.load_identity()
                if not self.identity_key:
                    raise RuntimeError("Identity key missing for responder")
                prekey = self.x3dh_session.generate_prekey(int(time.time()) & 0xFFFF)
                response_bundle = {
                    "identity_key": b64encode(
                        self.identity_key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw,
                        )
                    ).decode(),
                    "signed_prekey": prekey.serialize_public(),
                    "one_time_prekeys": [],
                }
                reply = {
                    "type": "x3dh_key_exchange",
                    "from": self.username,
                    "to": from_user,
                    "bundle": response_bundle,
                }
                self._send_json(reply)
                shared_key = self.x3dh_session.perform_x3dh_receiver(
                    self.identity_key,
                    prekey,
                    None,
                    b64decode(bundle["identity_key"]),
                    b64decode(bundle["ephemeral_key"]),
                )
                session = DoubleRatchetSession()
                session.init_bob_with_shared_key(shared_key)
                context.session = session
                context.session_initialized = True
                context.role = "responder"
                context.peer_identity_key = x25519.X25519PublicKey.from_public_bytes(b64decode(bundle["identity_key"]))
                if session.state is None or session.state.get("DHs") is None:
                    raise RuntimeError("Double Ratchet state incomplete")
                dh_public = session.state["DHs"].public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                self._send_json(
                    {
                        "type": "dh_public_key",
                        "from": self.username,
                        "to": from_user,
                        "dh_public_key": b64encode(dh_public).decode(),
                    }
                )
                context.handshake_event.set()
                self.save_contact_session(from_user)
                self._print(f"Session with {from_user} established in responder role")
            except Exception as exc:
                self.error_handler.handle_error(exc, "x3dh_receiver")
                self._print(f"Failed to respond to X3DH from {from_user}: {exc}")
                context.handshake_event.set()

    def _handle_dh_public_key(self, message: dict) -> None:
        from_user = message.get("from")
        if not from_user:
            return
        context = self._get_or_create_context(from_user)
        if not context.pending_shared_key:
            return
        try:
            public_bytes = b64decode(message["dh_public_key"])
            public_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
            session = DoubleRatchetSession()
            session.init_alice_with_shared_key(context.pending_shared_key, public_key)
            context.session = session
            context.session_initialized = True
            context.pending_shared_key = None
            context.pending_ephemeral = None
            context.handshake_event.set()
            self.save_contact_session(from_user)
            self._print(f"Session with {from_user} established in initiator role")
        except Exception as exc:
            self.error_handler.handle_error(exc, "dh_public_key")
            self._print(f"Failed to process DH public key from {from_user}: {exc}")
            context.handshake_event.set()

    def _handle_encrypted_message(self, message: dict) -> None:
        sender_label = message.get("from")
        # Resolve sealed sender before retrieving session context so we map to actual contact
        if (not sender_label or sender_label == "sealed") and message.get("sealed_sender") and self.identity_key:
            try:
                envelope = self.message_handler.open_sealed_sender_envelope(
                    message["sealed_sender"], self.identity_key
                )
                extracted_id = envelope.get("sender_id")
                if extracted_id:
                    sender_label = extracted_id
                    context = self._get_or_create_context(sender_label)
                    if context.peer_identity_key is None and envelope.get("sender_identity"):
                        try:
                            peer_bytes = b64decode(envelope["sender_identity"])
                            context.peer_identity_key = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
                        except Exception:
                            pass
            except Exception:
                sender_label = sender_label or "unknown"

        sender_label = sender_label or "unknown"
        context = self._get_or_create_context(sender_label)
        if not context.session_initialized or not context.session:
            if not self.load_contact_session(sender_label):
                self._print(f"Received message from {sender_label} but no session is available")
                return
            context = self._get_or_create_context(sender_label)
        if not context.session:
            self._print(f"Session with {sender_label} is unavailable")
            return
        try:
            valid, reason = self.message_handler.validate_message(message)
            if not valid:
                self._print(f"Rejected message from {sender_label}: {reason}")
                return
            self.message_handler.record_message(message)
            components = self.message_handler.extract_double_ratchet_components(message)
            session_obj = context.session
            if not session_obj:
                self._print(f"Session with {sender_label} vanished")
                return
            plaintext = session_obj.ratchet_decrypt(
                components["header"],
                components["ciphertext"],
                components["mac"],
                components["ad"],
            )
            self._print(
                f"[{sender_label}] #{components['header'].n if components['header'] else '?'} -> {plaintext}"
            )
            self.save_contact_session(sender_label)
        except Exception as exc:
            self.error_handler.handle_error(exc, "decrypt")
            self._print(f"Failed to decrypt message from {sender_label}: {exc}")

    # ------------------------------------------------------------------
    # User interaction
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            username = input("Username: ").strip()
            if not username:
                self._print("Username required")
                return
            self.username = username
            identity_exists = self.state_manager.state_exists(self._identity_state_id())
            default_password = self._default_password()
            while True:
                password = getpass("State password (leave blank for default): ").strip()
                if not password:
                    password = default_password
                if identity_exists or self._password_meets_requirements(password):
                    break
                self._print(
                    "Password must be at least 8 characters, include letters, digits, and a special character."
                )
            self.state_password = password
            if not self.connect():
                return
            login_message = {"type": "client_login", "username": self.username}
            self._send_json(login_message)
            if not self.login_event.wait(5):
                self._print("Login timed out")
                return
            registration = {"type": "client_registration", "from": self.username, "status": "ready"}
            self._send_json(registration)
            self.load_identity()
            contact_request = {"type": "contact_list_request", "from": self.username}
            self._send_json(contact_request)
            self.contacts_event.wait(2)
            self._print("Type 'help' for available commands")
            while True:
                try:
                    command = input("multi> ").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not command:
                    continue
                if command.lower() in {"quit", "exit"}:
                    break
                if command.lower() == "help":
                    self._print("Commands: contacts, use <name>, send <message>, sessions, quit")
                    continue
                if command.lower() == "contacts":
                    self._print_contacts()
                    continue
                if command.lower().startswith("use "):
                    target = command[4:].strip()
                    if target:
                        self.active_contact = target
                        self._print(f"Active contact set to {target}")
                    continue
                if command.lower() == "sessions":
                    self._print_sessions()
                    continue
                if command.lower().startswith("send "):
                    if not self.active_contact:
                        self._print("Select a contact first using 'use <name>'")
                        continue
                    message_text = command[5:].strip()
                    self.send_message(self.active_contact, message_text)
                    continue
                if self.active_contact:
                    self.send_message(self.active_contact, command)
                else:
                    self._print("Unrecognized command. Type 'help'.")
        finally:
            self.disconnect()

    def _print_contacts(self) -> None:
        if not self.contacts:
            self._print("No contacts available. Register additional users via tools.register_user.")
            return
        for name, info in self.contacts.items():
            label = info.get("display_name", name)
            self._print(f"- {name} ({label})")

    def _print_sessions(self) -> None:
        if not self.contact_sessions:
            self._print("No sessions yet")
            return
        for name, context in self.contact_sessions.items():
            state = "ready" if context.session_initialized else "pending"
            role = context.role or "unknown"
            self._print(f"- {name}: {state} ({role})")

    def send_message(self, contact: str, plaintext: str) -> None:
        if not plaintext:
            return
        if not self.username:
            self._print("Client is not logged in")
            return
        if not self.ensure_session(contact):
            self._print(f"Unable to establish session with {contact}")
            return
        context = self._get_or_create_context(contact)
        if not context.session:
            self._print(f"Session with {contact} is not ready")
            return
        session_state = context.session.state if context.session else None
        if not session_state or session_state.get("CKs") is None:
            self._print(
                f"Session with {contact} is waiting for their next message before you can send."
            )
            return
        try:
            header, ciphertext, mac, ad, message_key = context.session.ratchet_encrypt(plaintext)
            sealed = None
            if self.identity_key and context.peer_identity_key:
                try:
                    sealed = self.message_handler.create_sealed_sender_envelope(
                        sender_id=self.username or "",
                        sender_identity_key=self.identity_key,
                        recipient_identity_key=context.peer_identity_key,
                    )
                except Exception:
                    sealed = None
            enhanced = self.message_handler.create_message(
                from_user=self.username,
                to_user=contact,
                message_type=self.message_handler.MESSAGE_TYPES["TEXT"],
                header=header,
                ciphertext=ciphertext,
                mac=mac,
                ad=ad,
                plaintext_content=plaintext,
                sealed_sender=sealed,
            )
            if header and header.n == 0 and not context.first_message_logged:
                self._record_first_message_key(contact, header, ciphertext, mac, ad, message_key)
                context.first_message_logged = True
            self._send_json(enhanced)
            self.save_contact_session(contact)
            self._print(f"Sent to {contact}: {plaintext}")
        except Exception as exc:
            self.error_handler.handle_error(exc, "send_message")
            self._print(f"Failed to send message: {exc}")

    def _record_first_message_key(
        self,
        contact: str,
        header,
        ciphertext_b64: str,
        mac_b64: str,
        ad_b64: str,
        message_key: bytes,
    ) -> None:
        """Persist the very first outbound message key for Malory demos without console output."""
        try:
            os.makedirs("malory_logs", exist_ok=True)
            ciphertext_bytes = b64decode(ciphertext_b64)
            mac_bytes = b64decode(mac_b64)
            ad_bytes = b64decode(ad_b64)
            entry = {
                "timestamp": int(time.time()),
                "from": self.username,
                "to": contact,
                "sequence_number": header.n,
                "message_id": f"first:{self.username}->{contact}",
                "ciphertext_hex": ciphertext_bytes.hex(),
                "mac_hex": mac_bytes.hex(),
                "ad_hex": ad_bytes.hex(),
                "message_key_hex": message_key.hex(),
                "note": "Captured for forward secrecy demonstration. Subsequent ciphertext requires new keys.",
            }
            log_path = os.path.join("malory_logs", "first_message_keys.jsonl")
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except Exception as exc:
            self.error_handler.handle_error(exc, "record_first_message_key")

    # ------------------------------------------------------------------
    # Logging utility
    # ------------------------------------------------------------------
    def _print(self, message: str) -> None:
        with self.print_lock:
            print(message)

    def _default_password(self) -> str:
        assert self.username is not None
        return f"{self.username}_state_123!"

    @classmethod
    def _password_meets_requirements(cls, password: str) -> bool:
        return bool(cls.PASSWORD_PATTERN.match(password))


def main() -> None:
    client = EnhancedMultiClient()
    client.run()


if __name__ == "__main__":
    main()
