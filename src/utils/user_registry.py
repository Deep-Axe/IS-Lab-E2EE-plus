"""Lightweight file-backed user registry for the E2EE demo."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
USERS_DIR = DATA_DIR / "users"
PENDING_DIR = DATA_DIR / "pending"
OTPS_DIR = DATA_DIR / "otp"

for directory in (USERS_DIR, PENDING_DIR, OTPS_DIR):
    directory.mkdir(parents=True, exist_ok=True)


@dataclass
class UserProfile:
    username: str
    display_name: str
    created_at: str
    confirmed_at: str
    identity_key: Optional[str]
    metadata: Dict[str, str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserProfile":
        return cls(
            username=data.get("username", ""),
            display_name=data.get("display_name", data.get("username", "")),
            created_at=data.get("created_at", ""),
            confirmed_at=data.get("confirmed_at", ""),
            identity_key=data.get("identity_key"),
            metadata=data.get("metadata") or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "confirmed_at": self.confirmed_at,
            "identity_key": self.identity_key,
            "metadata": self.metadata,
        }


def _user_path(username: str) -> Path:
    safe = username.lower().replace(" ", "_")
    return USERS_DIR / f"{safe}.json"


def get_user(username: str) -> Optional[UserProfile]:
    path = _user_path(username)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return UserProfile.from_dict(data)


def list_users() -> List[UserProfile]:
    profiles: List[UserProfile] = []
    for file in USERS_DIR.glob("*.json"):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
            profiles.append(UserProfile.from_dict(data))
        except json.JSONDecodeError:
            continue
    profiles.sort(key=lambda profile: profile.username.lower())
    return profiles


def usernames(exclude: Optional[str] = None) -> List[str]:
    names = [profile.username for profile in list_users()]
    if exclude:
        names = [name for name in names if name.lower() != exclude.lower()]
    return names


def ensure_user(username: str) -> UserProfile:
    profile = get_user(username)
    if not profile:
        raise ValueError(f"User '{username}' is not registered.")
    return profile


def contacts_for(username: str) -> List[UserProfile]:
    return [profile for profile in list_users() if profile.username.lower() != username.lower()]


def pending_users() -> Iterable[str]:
    for file in PENDING_DIR.glob("*.json"):
        yield file.stem


def otp_path(username: str) -> Path:
    safe = username.lower().replace(" ", "_")
    return OTPS_DIR / f"{safe}.otp"
