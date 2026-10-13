"""Streamlit side of the gate.

Streamlit keeps one WebSocket per browser tab, and st.context.headers are
the headers of that WebSocket's opening request: the token is verified once
when the session opens and the identity is kept in session_state for the
reruns that follow. The portal re-checks the user's access every 30 s and
closes the WebSocket when it is withdrawn; the reconnect then gets refused.
"""
from __future__ import annotations

import hashlib
import os

import streamlit as st

from .identity import HEADER, AuthError, Identity, app_slug, verify_token

_KEY = "_hydvance_identity"


def _dev_identity() -> Identity | None:
    """HYDVANCE_AUTH_DEV_ROLE=editor lets a developer run the app alone on
    their machine. Refused on Cloud Run (K_SERVICE is set there)."""
    role = os.environ.get("HYDVANCE_AUTH_DEV_ROLE")
    if not role:
        return None
    if os.environ.get("K_SERVICE"):
        st.error("Configuration refused: HYDVANCE_AUTH_DEV_ROLE cannot be used in production.")
        st.stop()
    return Identity("0" * 32, "dev@localhost", "Local developer", role, True, dev=True)


def require_identity(slug: str | None = None) -> Identity:
    """The portal user, or a stopped page. `slug` is only needed when the app
    has no [app] id in hydvance-app.toml and runs outside the portal."""
    token = st.context.headers.get(HEADER, "")
    fingerprint = hashlib.sha256(token.encode()).hexdigest() if token else ""
    cached = st.session_state.get(_KEY)
    if cached and cached[0] == fingerprint:
        return cached[1]
    if not token:
        dev = _dev_identity()
        if dev:
            st.session_state[_KEY] = ("", dev)
            return dev
    try:
        me = verify_token(token, app_slug(slug))
    except AuthError:
        st.session_state.pop(_KEY, None)
        st.error("Access denied. This application only opens from the Hydvance application portal.")
        st.stop()
    st.session_state[_KEY] = (fingerprint, me)
    return me
