# interactive_malory.py (interactive post-compromise demo)

import json
import time
from pathlib import Path
from typing import List, Optional, Tuple

try:
    from core.double_ratchet import DECRYPT_DOUB_RATCH, CONCAT, Header, deserialize
    from cryptography.hazmat.primitives import padding
except ImportError:
    print("ERROR: Could not import core cryptography library.")
    print("Please ensure this script is run from the project root (python -m tools.interactive_malory).")
    raise


class RealMalory:
    """Interactive helper that demonstrates post-compromise security."""

    def __init__(self, log_path: Optional[Path] = None) -> None:
        project_root = Path(__file__).resolve().parent.parent
        default_path = project_root / "malory_logs" / "intercepted_messages.json"
        alt_path = project_root / "src" / "network" / "malory_logs" / "intercepted_messages.json"

        if log_path is not None:
            self.log_path = Path(log_path)
        elif default_path.exists():
            self.log_path = default_path
        else:
            self.log_path = alt_path

        self.messages: List[dict] = []

    @staticmethod
    def _sender_label(message: dict) -> str:
        sender = message.get("from")
        if sender:
            return sender
        sealed = message.get("sealed_sender") or {}
        hint = sealed.get("hint")
        return f"sealed:{hint}" if hint else "sealed"

    def load_intercepted_messages(self) -> bool:
        """Load Malory's intercepted traffic from disk."""
        if not self.log_path.exists():
            print(f"No intercepted log found at {self.log_path}")
            print("Start the demo server/clients to generate traffic first.")
            return False

        try:
            with self.log_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.messages.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            if not self.messages:
                print("The intercepted log is empty.")
                return False

            self.messages.sort(key=lambda entry: entry.get("timestamp", 0))
            return True
        except OSError as exc:
            print(f"Failed to read intercepted log: {exc}")
            return False

    def display_timeline(self) -> None:
        """Render a compact overview so the user can pick messages."""
        print("\nAvailable intercepted messages (chronological):")
        for index, message in enumerate(self.messages):
            timestamp = message.get("timestamp")
            when = "unknown"
            if isinstance(timestamp, (int, float)) and timestamp:
                when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp / 1000))

            direction = f"{self._sender_label(message)} -> {message.get('to', '?')}"
            sequence = message.get("sequence_number", "?")
            print(f" [{index:02d}] {when} | {direction:>15} | seq={sequence}")

    def prompt_index(self, prompt: str, default: Optional[int] = None) -> int:
        """Ask the user for a valid message index."""
        while True:
            raw = input(prompt).strip()
            if raw == "" and default is not None:
                return default
            try:
                index = int(raw)
            except ValueError:
                print("Please enter a numeric index.")
                continue

            if 0 <= index < len(self.messages):
                return index
            print(f"Index out of range (0-{len(self.messages) - 1}).")

    def attempt_real_decryption(self, key_hex: str, message: dict) -> Tuple[bool, str]:
        """Try to decrypt a single intercepted message with the provided key."""
        header_data = message.get("header")
        if not header_data:
            return False, "Message does not contain a header."

        try:
            message_key = bytes.fromhex(key_hex)
        except ValueError:
            return False, "Key must be a valid hex string."

        try:
            header = Header.deserialize(header_data)
        except Exception as exc:
            return False, f"Header decode failed: {exc}"

        ciphertext_b64 = message.get("ciphertext")
        mac_b64 = message.get("mac")
        if not ciphertext_b64 or not mac_b64:
            return False, "Ciphertext or MAC missing from log entry."

        try:
            ciphertext_bytes = deserialize(ciphertext_b64)
            mac_bytes = deserialize(mac_b64)
        except Exception as exc:
            return False, f"Ciphertext decode failed: {exc}"

        ad_b64 = message.get("ad") or ""
        if ad_b64:
            try:
                ad_bytes = deserialize(ad_b64)
            except Exception as exc:
                return False, f"Associated data decode failed: {exc}"
        else:
            ad_bytes = b""

        ciphertext_tuple = (ciphertext_bytes, mac_bytes)
        associated_data = CONCAT(ad_bytes, header)

        try:
            padded_plaintext = DECRYPT_DOUB_RATCH(message_key, ciphertext_tuple, associated_data)
            unpadder = padding.PKCS7(256).unpadder()
            plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
            return True, plaintext_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            return False, str(exc)

    def explain_attempt(self, label: str, key_hex: str, index: int) -> None:
        """Run a decryption attempt and print a friendly verdict."""
        message = self.messages[index]
        success, outcome = self.attempt_real_decryption(key_hex, message)
        direction = f"{self._sender_label(message)} -> {message.get('to', '?')}"
        sequence = message.get("sequence_number", "?")

        print(f"\n[{label}] Message index {index} | {direction} | seq={sequence}")
        if success:
            print("  Decryption succeeded (post-compromise window).")
            print(f"  Plaintext: {outcome}")
        else:
            print("  Decryption failed as expected.")
            print(f"  Cryptographic error: {outcome}")

    def run_secrecy_demo(self) -> None:
        """Load intercepted traffic and walk through the post-compromise story."""
        print("\n" + "=" * 80)
        print("          MALORY'S POST-COMPROMISE SECURITY DEMONSTRATOR")
        print("=" * 80)
        print("This walkthrough shows that a stolen Double Ratchet message key")
        print("only unlocks the exact ciphertext it belongs to.")

        if not self.load_intercepted_messages():
            return

        self.display_timeline()
        compromised_index = self.prompt_index("\nSelect the index of the compromised message: ")
        key_hex = input("Paste the stolen message key (hex as printed by Alice): ").strip()

        self.explain_attempt("COMPROMISED", key_hex, compromised_index)

        # Reuse the same compromised key on surrounding traffic to highlight PCS.
        neighbor_indices: List[Tuple[str, int]] = []
        if compromised_index - 1 >= 0:
            neighbor_indices.append(("PAST", compromised_index - 1))
        if compromised_index + 1 < len(self.messages):
            neighbor_indices.append(("FUTURE", compromised_index + 1))

        if not neighbor_indices:
            print("\nNo adjacent messages found to demonstrate post-compromise security.")
            return

        for label, index in neighbor_indices:
            self.explain_attempt(label, key_hex, index)

        print("\n" + "=" * 80)
        print("Demo complete: Double Ratchet rotated the key, so Malory's access")
        print("is limited to the compromised ciphertext only.")


def main() -> None:
    malory = RealMalory()
    try:
        malory.run_secrecy_demo()
    except KeyboardInterrupt:
        print("\nSession cancelled by user.")


if __name__ == "__main__":
    main()