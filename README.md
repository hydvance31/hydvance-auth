# hydvance-auth

Library for applications served by the **Hydvance application portal**.

The portal is the only way into an application. It signs the user in (password and one-time code), checks the user's
role for this application, then forwards every request with an `X-Hydvance-Identity` header: a token valid for
5 minutes, signed with the portal's Ed25519 private key. This library verifies that token and gives the application
the user and their role.

The private key never leaves the portal (Google Secret Manager). This code holds no secret: it only verifies
signatures with the portal's public key, which is why this repository can be public.

## Install

In the application's `requirements.txt`:

```
hydvance-auth[streamlit] @ https://github.com/hydvance31/hydvance-auth/archive/refs/tags/v1.1.0.tar.gz
```

## Use (Streamlit)

```python
from hydvance_auth import UserConfigStore, require_identity

me = require_identity()                 # stops the page unless opened through the portal
st.caption(f"{me.name} · {me.role}")
if me.can_edit:                         # "editor" or above
    ...
store = UserConfigStore()               # one JSON file per user, if [user_config] is enabled
saved = store.load(me)
store.save(me, {"param": 1.0})
```

`require_identity()` reads the application identifier from `HYDVANCE_APP_SLUG`, which the portal sets when it
publishes the app, or else from `[app] id` in `hydvance-app.toml`.

Roles, from lowest to highest: `reader`, `editor`, `expert`, `admin`. Each application declares in
`hydvance-app.toml` the ones it uses and what each allows.

## Environment

| Variable | Set by | Purpose |
|---|---|---|
| `HYDVANCE_PORTAL_PUBLIC_KEY` | the portal, at publication | public key verifying the tokens (or `HYDVANCE_PORTAL_PUBLIC_KEY_FILE`) |
| `HYDVANCE_APP_SLUG` | the portal, at publication | the application's identifier |
| `HYDVANCE_USER_CONFIG_DIR` | the portal, at publication | where per-user files are kept |
| `HYDVANCE_AUTH_DEV_ROLE` | you, locally | e.g. `editor`: run the app alone on your machine. Refused on Cloud Run. |

## Tests

```bash
pip install -e ".[test]"
pytest
```

Copyright © Hydvance. All rights reserved.
