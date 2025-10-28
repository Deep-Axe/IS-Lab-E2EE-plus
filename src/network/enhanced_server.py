"""Multi-user messaging relay with sealed sender aware logging."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, cast

try:
    from utils.error_handler import ErrorHandler
    from utils import user_registry
except ImportError:  # pragma: no cover - script execution fallback
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from utils.error_handler import ErrorHandler  # type: ignore  # noqa: E402
    from utils import user_registry  # type: ignore  # noqa: E402


@dataclass
class ClientInfo:
    socket: socket.socket
    address: Tuple[str, int]
    status: str = "connected"
    profile: Optional[user_registry.UserProfile] = None
    last_seen: float = field(default_factory=time.time)


class EnhancedServer:
    """Relay server that routes messages between registered users."""

    def __init__(self, host: str = "localhost", port: int = 9999) -> None:
        self.host = host
        self.port = port
        self.error_handler = ErrorHandler()

        self.clients: Dict[str, ClientInfo] = {}
        self.message_queue: Dict[str, List[dict]] = {}
        self.key_bundles: Dict[str, Dict[str, dict]] = {}
        self.server_socket: Optional[socket.socket] = None

        self.running = False
        self.lock = threading.Lock()

    # ------------------------------------------------------------------
    # lifecycle management
    # ------------------------------------------------------------------
    def start_server(self) -> None:
        if self.running:
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(20)

            self.running = True
            print(f"Enhanced E2EE Server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                except OSError:
                    if not self.running:
                        break
                    continue

                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True,
                )
                thread.start()

        except Exception as exc:  # pragma: no cover - relies on socket stack
            self.error_handler.handle_error(exc, "start_server")
        finally:
            self.stop_server()

    def stop_server(self) -> None:
        if not self.running and not self.server_socket:
            return

        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        with self.lock:
            for username, info in list(self.clients.items()):
                try:
                    info.socket.close()
                except Exception:
                    pass
                print(f"Closed connection to {username}")
            self.clients.clear()

        print("Server stopped")

    # ------------------------------------------------------------------
    # per-client handling
    # ------------------------------------------------------------------
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        username: Optional[str] = None

        try:
            while self.running:
                client_socket.settimeout(30)
                raw = client_socket.recv(8192)
                if not raw:
                    break

                try:
                    message = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    continue

                msg_type = message.get("type")

                if msg_type == "client_login":
                    username = self._handle_login(message, client_socket, address)
                    continue

                if msg_type == "contact_list_request":
                    self._handle_contact_list(client_socket, username)
                    continue

                if msg_type == "client_registration":
                    username = message.get("from") or username
                    if username:
                        self._register_client(cast(str, username), client_socket, address)
                    self._handle_client_registration(message)
                    continue

                from_user = message.get("from")
                if from_user and from_user != username:
                    username = from_user
                    self._register_client(cast(str, from_user), client_socket, address)

                if msg_type == "x3dh_key_exchange":
                    self._handle_x3dh(message)
                elif msg_type == "simple_key_exchange":
                    self._handle_simple_key(message)
                elif msg_type == "dh_public_key":
                    self._handle_dh_public_key(message)
                else:
                    self._handle_encrypted_message(message)

        except socket.timeout:
            pass
        except Exception as exc:  # pragma: no cover - defensive logging
            self.error_handler.handle_error(exc, f"client_loop_{address}")
        finally:
            if username:
                with self.lock:
                    info = self.clients.pop(username, None)
                if info:
                    try:
                        info.socket.close()
                    except Exception:
                        pass
                    print(f"{username} disconnected")

            try:
                client_socket.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # message handlers
    # ------------------------------------------------------------------
    def _handle_login(
        self,
        message: dict,
        client_socket: socket.socket,
        address: Tuple[str, int],
    ) -> Optional[str]:
        username = message.get("username")
        if not username:
            self._send_json(
                client_socket,
                {
                    "type": "login_ack",
                    "status": "error",
                    "message": "Missing username.",
                },
            )
            return None

        profile = user_registry.get_user(username)
        if not profile:
            self._send_json(
                client_socket,
                {
                    "type": "login_ack",
                    "status": "error",
                    "message": f"Unknown user '{username}'. Register first via tools.register_user.",
                },
            )
            return None

        self._register_client(username, client_socket, address, profile)
        self._send_json(
            client_socket,
            {
                "type": "login_ack",
                "status": "ok",
                "username": username,
                "display_name": profile.display_name,
            },
        )
        print(f"{username} logged in from {address}")
        return username

    def _handle_contact_list(self, client_socket: socket.socket, username: Optional[str]) -> None:
        if not username:
            self._send_json(client_socket, {"type": "contact_list", "contacts": []})
            return

        contacts = [profile.to_dict() for profile in user_registry.contacts_for(username)]
        self._send_json(client_socket, {"type": "contact_list", "contacts": contacts})

    def _handle_client_registration(self, message: dict) -> None:
        username = message.get("from")
        if not username:
            return

        with self.lock:
            info = self.clients.get(username)
        if not info:
            return

        queued = self.message_queue.pop(username, [])
        if queued:
            print(f"Delivering {len(queued)} queued messages to {username}")
            for payload in queued:
                self._send_json(info.socket, payload)

    def _handle_x3dh(self, message: dict) -> None:
        from_user = message.get("from")
        bundle = message.get("bundle")
        if not from_user or not bundle:
            return

        to_user = self._resolve_recipient(message)
        if not to_user:
            self._store_bundle("pending", from_user, bundle)
            return

        self._store_bundle(to_user, from_user, bundle)
        payload = {
            "type": "x3dh_key_exchange",
            "from": from_user,
            "bundle": bundle,
        }
        self._send_or_queue(to_user, payload)

    def _handle_simple_key(self, message: dict) -> None:
        from_user = message.get("from")
        key_material = message.get("public_key")
        if not from_user or not key_material:
            return

        to_user = self._resolve_recipient(message)
        if not to_user:
            self._store_bundle("pending_simple", from_user, message)
            return

        payload = {
            "type": "simple_key_exchange",
            "from": from_user,
            "public_key": key_material,
        }
        self._send_or_queue(to_user, payload)

    def _handle_dh_public_key(self, message: dict) -> None:
        to_user = self._resolve_recipient(message)
        if not to_user:
            return
        self._send_or_queue(to_user, message)

    def _handle_encrypted_message(self, message: dict) -> None:
        routing = message.get("routing") or {}
        to_user = routing.get("to") or message.get("to")
        if not to_user:
            return

        self._send_or_queue(to_user, message)
        self._log_for_malory(message)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _register_client(
        self,
        username: str,
        client_socket: socket.socket,
        address: Tuple[str, int],
        profile: Optional[user_registry.UserProfile] = None,
    ) -> None:
        if not profile:
            profile = user_registry.get_user(username)

        with self.lock:
            existing = self.clients.get(username)
            if existing and existing.socket is not client_socket:
                try:
                    existing.socket.close()
                except Exception:
                    pass

            self.clients[username] = ClientInfo(
                socket=client_socket,
                address=address,
                status="ready",
                profile=profile,
            )

        queued = self.message_queue.pop(username, [])
        for payload in queued:
            self._send_json(client_socket, payload)

    def _store_bundle(self, bucket: str, sender: str, bundle: dict) -> None:
        with self.lock:
            self.key_bundles.setdefault(bucket, {})[sender] = bundle

    def _resolve_recipient(self, message: dict) -> Optional[str]:
        explicit = message.get("to")
        if explicit:
            return explicit

        routing = message.get("routing") or {}
        explicit = routing.get("to")
        if explicit:
            return explicit

        sender = message.get("from")
        if not sender:
            return None

        with self.lock:
            candidates = [name for name in self.clients.keys() if name != sender]

        if len(candidates) == 1:
            return candidates[0]

        if sender == "Alice" and "Bob" in self.clients:
            return "Bob"
        if sender == "Bob" and "Alice" in self.clients:
            return "Alice"
        return None

    def _send_json(self, client_socket: socket.socket, payload: dict) -> None:
        try:
            encoded = json.dumps(payload).encode("utf-8")
            client_socket.sendall(encoded)
        except Exception as exc:  # pragma: no cover - network write
            self.error_handler.handle_error(exc, "send_json")

    def _send_or_queue(self, username: str, payload: dict) -> None:
        with self.lock:
            info = self.clients.get(username)

        if info:
            try:
                self._send_json(info.socket, payload)
                return
            except Exception:
                pass

        with self.lock:
            self.message_queue.setdefault(username, []).append(payload)

    # ------------------------------------------------------------------
    # logging integration for Malory tooling
    # ------------------------------------------------------------------
    def _log_for_malory(self, message: dict) -> None:
        try:
            log_entry = {
                "timestamp": int(time.time()),
                "from": message.get("from"),
                "to": message.get("to"),
                "routing": message.get("routing"),
                "message_id": message.get("message_id"),
                "sequence_number": message.get("sequence_number"),
                "header": message.get("header"),
                "ciphertext": message.get("ciphertext"),
                "mac": message.get("mac"),
                "ad": message.get("ad"),
                "metadata": message.get("metadata", {}),
                "sealed_sender": message.get("sealed_sender"),
            }

            sender_label = message.get("from")
            sealed_hint = None
            if not sender_label and message.get("sealed_sender"):
                sender_label = "sealed"
                sealed_hint = message["sealed_sender"].get("hint")

            print("=" * 60)
            print("MALORY'S KEY INTERCEPTION LOG")
            print("=" * 60)
            if sealed_hint:
                print(f"From: {sender_label} ({sealed_hint}) -> To: {message.get('to')}")
            else:
                print(f"From: {sender_label} -> To: {message.get('to')}")
            print(f"Message ID: {message.get('message_id', 'unknown')}")
            print(f"Sequence: {message.get('sequence_number', 'unknown')}")
            print(f"Timestamp: {time.strftime('%H:%M:%S', time.localtime())}")
            print("Status: Message intercepted and logged for cryptanalysis")
            print("=" * 60)

            os.makedirs("malory_logs", exist_ok=True)
            with open("malory_logs/intercepted_messages.json", "a", encoding="utf-8") as handle:
                handle.write(json.dumps(log_entry) + "\n")
            with open("malory_logs/malory_analysis.txt", "a", encoding="utf-8") as handle:
                handle.write(f"\n{'='*60}\n")
                handle.write(f"MALORY'S INTERCEPTION LOG - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                handle.write(f"{'='*60}\n")
                handle.write(f"From: {sender_label} -> To: {message.get('to')}\n")
                handle.write(f"Header: {message.get('header')}\n")
                handle.write(f"Ciphertext: {message.get('ciphertext')}\n")
                handle.write(f"MAC: {message.get('mac')}\n")
                handle.write("Status: Intercepted for cryptanalysis attempt\n")
                handle.write("Note: Double Ratchet forward secrecy should prevent decryption of future messages\n")
                handle.write(f"{'='*60}\n")
        except Exception as exc:  # pragma: no cover - logging must be best-effort
            self.error_handler.handle_error(exc, "log_for_malory")


def main() -> None:
    server = EnhancedServer()

    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    finally:
        server.stop_server()


if __name__ == "__main__":
    main()