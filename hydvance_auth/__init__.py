"""Identity of the portal user inside a Hydvance application.

The portal is the only way into an application: it authenticates the user,
checks their role for this application, then forwards each request with an
X-Hydvance-Identity header holding a short-lived token signed with the
portal's Ed25519 key. This package verifies that token and gives the
application the user and their role. It also stores each user's own
configuration for applications that declare [user_config] in
hydvance-app.toml.

    from hydvance_auth import require_identity, UserConfigStore
    me = require_identity()      # stops the page if not opened via the portal
    if me.can_edit: ...
"""
from .identity import ROLE_ORDER, AuthError, Identity, app_slug, verify_token
from .user_config import UserConfigStore

__version__ = "1.1.0"
__all__ = ["ROLE_ORDER", "AuthError", "Identity", "app_slug", "verify_token", "UserConfigStore", "require_identity"]


def require_identity(slug: str | None = None) -> Identity:
    from .streamlit_gate import require_identity as _req
    return _req(slug)
