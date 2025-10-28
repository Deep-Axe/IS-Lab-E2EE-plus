"""User registration helper for the IS-Lab E2EE demo.

Workflow:
  1. `python -m tools.register_user --register` to create a pending user and OTP code.
  2. The script prints the OTP file path; read the code from that file.
  3. `python -m tools.register_user --confirm --username alice --otp 123456` to activate.
Profiles are stored under `data/users/` (confirmed) and `data/pending/` (pending).
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Optional

from utils import user_registry

PROFILE_VERSION = "1.0"


@dataclass
class PendingProfile:
    username: str
    display_name: str
    created_at: str
    otp_code: str
    identity_key: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None

    def to_json(self) -> str:
        payload = asdict(self)
        payload["version"] = PROFILE_VERSION
        return json.dumps(payload, indent=2)


@dataclass
class ActiveProfile:
    username: str
    display_name: str
    created_at: str
    confirmed_at: str
    identity_key: Optional[str]
    metadata: Optional[Dict[str, str]]

    def to_json(self) -> str:
        payload = asdict(self)
        payload["version"] = PROFILE_VERSION
        return json.dumps(payload, indent=2)

def _safe(username: str) -> str:
    return username.lower().replace(" ", "_")


def _generate_otp(length: int = 6) -> str:
    alphabet = string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def register(username: str, display_name: str) -> None:
    safe = _safe(username)
    pending_path = user_registry.PENDING_DIR / f"{safe}.json"
    user_path = user_registry.USERS_DIR / f"{safe}.json"
    if user_path.exists():
        print(f" User '{username}' is already registered.")
        return
    if pending_path.exists():
        print(f" A pending registration for '{username}' already exists.")
        print("Use --confirm to finish the registration or remove the pending file manually.")
        return

    otp_code = _generate_otp()
    now = datetime.utcnow().isoformat() + "Z"
    profile = PendingProfile(
        username=username,
        display_name=display_name,
        created_at=now,
        otp_code=otp_code,
        metadata={"note": "Provide this code during confirmation."},
    )
    pending_path.write_text(profile.to_json(), encoding="utf-8")

    otp_file = user_registry.otp_path(username)
    otp_file.write_text(f"OTP for {username}: {otp_code}\n", encoding="utf-8")

    print(" Pending registration created.")
    print(f"   Pending profile: {pending_path}")
    print(f"   OTP file (open to view code): {otp_file}")


def confirm(username: str, otp_code: str) -> None:
    safe = _safe(username)
    pending_path = user_registry.PENDING_DIR / f"{safe}.json"
    if not pending_path.exists():
        print(f" No pending registration for '{username}'.")
        return

    pending_data = json.loads(pending_path.read_text(encoding="utf-8"))
    if pending_data.get("otp_code") != otp_code:
        print(" Incorrect OTP code.")
        return

    now = datetime.utcnow().isoformat() + "Z"
    profile = ActiveProfile(
        username=pending_data["username"],
        display_name=pending_data["display_name"],
        created_at=pending_data["created_at"],
        confirmed_at=now,
        identity_key=pending_data.get("identity_key"),
        metadata=pending_data.get("metadata"),
    )

    user_path = user_registry.USERS_DIR / f"{safe}.json"
    user_path.write_text(profile.to_json(), encoding="utf-8")

    pending_path.unlink()
    otp_file = user_registry.otp_path(username)
    if otp_file.exists():
        otp_file.unlink()

    print("✅ Registration confirmed. User profile created at:")
    print(f"   {user_path}")


def list_users() -> None:
    users = sorted(user_registry.USERS_DIR.glob("*.json"))
    if not users:
        print("No registered users yet.")
        return
    for path in users:
        data = json.loads(path.read_text(encoding="utf-8"))
        print(f"- {data.get('username')} ({data.get('display_name')}) confirmed {data.get('confirmed_at')}")


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Register or confirm demo users.")
    sub = parser.add_subparsers(dest="command", required=True)

    register_cmd = sub.add_parser("register", help="Create a pending registration")
    register_cmd.add_argument("username", help="Unique handle (e.g., alice)")
    register_cmd.add_argument("display_name", help="Friendly name")

    confirm_cmd = sub.add_parser("confirm", help="Confirm OTP and activate user")
    confirm_cmd.add_argument("username", help="Pending username")
    confirm_cmd.add_argument("otp_code", help="OTP code from tools/otp/<user>.otp")

    sub.add_parser("list", help="List active users")

    args = parser.parse_args(argv)

    if args.command == "register":
        register(args.username, args.display_name)
    elif args.command == "confirm":
        confirm(args.username, args.otp_code)
    elif args.command == "list":
        list_users()
    else:
        parser.print_help()


if __name__ == "__main__":
    main(sys.argv[1:])
