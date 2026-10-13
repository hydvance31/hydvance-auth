from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import jwt

ROLE_ORDER = ("reader", "editor", "expert", "admin")
HEADER = "X-Hydvance-Identity"
_SLUG = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    user_id: str
    email: str
    name: str
    role: str                 # one of ROLE_ORDER, as declared in the app's hydvance-app.toml
    user_config: bool         # the app declared per-user configuration
    dev: bool = False         # local run without the portal (never on Cloud Run)

    def at_least(self, role: str) -> bool:
        return ROLE_ORDER.index(self.role) >= ROLE_ORDER.index(role)

    @property
    def can_edit(self) -> bool:
        return self.at_least("editor")


def app_slug(fallback: str | None = None) -> str:
    """The application's identifier on the portal. The portal sets
    HYDVANCE_APP_SLUG when it publishes the app, so the code doesn't have to
    repeat it; `fallback` (or [app] id in hydvance-app.toml) serves when the
    app runs on its own."""
    slug = os.environ.get("HYDVANCE_APP_SLUG") or fallback or _slug_from_manifest()
    if not slug or not _SLUG.match(slug):
        raise AuthError("Unknown application identifier: set [app] id in hydvance-app.toml.")
    return slug


def _slug_from_manifest() -> str | None:
    path = Path(os.environ.get("HYDVANCE_APP_MANIFEST", "hydvance-app.toml"))
    try:
        import tomllib
        return tomllib.loads(path.read_text(encoding="utf-8")).get("app", {}).get("id")
    except (OSError, ValueError):
        return None


def public_key() -> bytes:
    pem = os.environ.get("HYDVANCE_PORTAL_PUBLIC_KEY")
    if pem:
        return pem.replace("\\n", "\n").encode()
    path = os.environ.get("HYDVANCE_PORTAL_PUBLIC_KEY_FILE")
    if path:
        return Path(path).read_bytes()
    raise AuthError("HYDVANCE_PORTAL_PUBLIC_KEY is not set.")


def verify_token(token: str, app_slug: str, key: bytes | None = None, leeway: int = 10) -> Identity:
    """Signature (EdDSA only: no 'none', no HMAC confusion), issuer, audience
    = this application, and expiry are all mandatory."""
    if not token or len(token) > 4096:
        raise AuthError("Missing token.")
    try:
        claims = jwt.decode(token, key or public_key(), algorithms=["EdDSA"], audience=f"hydvance-app:{app_slug}",
                            issuer="hydvance-portal", leeway=leeway,
                            options={"require": ["exp", "iat", "sub", "aud", "iss"]})
    except jwt.PyJWTError as exc:
        raise AuthError(f"Token refused: {exc}") from exc
    if claims.get("role") not in ROLE_ORDER:
        raise AuthError("Unknown role.")
    return Identity(claims["sub"], claims.get("email", ""), claims.get("name", ""), claims["role"],
                    bool(claims.get("user_config")))
