import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hydvance_auth import AuthError, Identity, UserConfigStore, app_slug, verify_token

PRIV = Ed25519PrivateKey.generate()
PRIV_PEM = PRIV.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
PUB_PEM = PRIV.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def token(slug="demo", role="reader", ttl=300, key=PRIV_PEM, alg="EdDSA"):
    now = int(time.time())
    claims = {"iss": "hydvance-portal", "aud": f"hydvance-app:{slug}", "sub": "c" * 32, "email": "a@b.fr",
              "name": "A", "role": role, "user_config": True, "iat": now, "exp": now + ttl}
    return jwt.encode(claims, key, algorithm=alg)


def test_valid_token():
    me = verify_token(token(), "demo", PUB_PEM)
    assert me.role == "reader" and not me.can_edit and me.user_config


def test_other_app_expired_or_forged_refused():
    other = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption())
    for t in (token(slug="other"), token(ttl=-60), token(key=other), token(key="secret", alg="HS256"),
              token(key=None, alg="none"), token(role="superuser")):
        with pytest.raises(AuthError):
            verify_token(t, "demo", PUB_PEM)


def test_app_slug_order(monkeypatch, tmp_path):
    (tmp_path / "hydvance-app.toml").write_text('[app]\nid = "from-file"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HYDVANCE_APP_SLUG", raising=False)
    assert app_slug() == "from-file"
    assert app_slug("explicit") == "explicit"
    monkeypatch.setenv("HYDVANCE_APP_SLUG", "from-portal")
    assert app_slug("explicit") == "from-portal"      # the portal is authoritative
    monkeypatch.setenv("HYDVANCE_APP_SLUG", "../evil")
    with pytest.raises(AuthError):
        app_slug()


def test_user_config_isolation_and_paths(tmp_path):
    store = UserConfigStore("demo", tmp_path)
    a, b = Identity("a" * 32, "", "", "editor", True), Identity("b" * 32, "", "", "editor", True)
    store.save(a, {"x": 1})
    assert store.load(a) == {"x": 1} and store.load(b) == {}
    with pytest.raises(ValueError):
        store.save(Identity("../../etc/passwd", "", "", "editor", True), {})
