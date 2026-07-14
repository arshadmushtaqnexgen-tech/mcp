"""OAuth Authorization Server for the Twelve Data MCP server.

Public surface:
  build_auth()     -> (provider, AuthSettings) | (None, None)
  resolve_apikey() -> td_apikey for the currently authenticated request
  ENABLED          -> whether OAuth is active (MCP_DATA_PUBLIC_URL set)

The upstream Twelve Data login returns to the shared "/callback" route in
server.py (dispatched by state), so no dedicated route module is needed.
"""

from __future__ import annotations

import logging
from typing import Optional

from oauth.config import ENABLED, SCOPE, issuer_url, resource_url

log = logging.getLogger("oauth")


def build_auth():
    """Build the AS provider + AuthSettings, or (None, None) if OAuth is off.

    OAuth is off for stdio / local Claude Desktop (no MCP_DATA_PUBLIC_URL); those
    authenticate via the oauth_login tool instead.
    """
    if not ENABLED:
        return None, None

    from mcp.server.auth.settings import (
        AuthSettings,
        ClientRegistrationOptions,
        RevocationOptions,
    )

    from oauth import storage
    from oauth.provider import TwelveDataASProvider

    # Fail fast: OAuth needs Redis to persist clients/codes/tokens. Without it the
    # storage layer would silently no-op (clients vanish → "Client ID not found",
    # tokens never validate) — a confusing, hard-to-debug degradation. Refuse to
    # start instead, so the misconfiguration is loud and obvious at boot. (With
    # docker-compose's depends_on: redis healthy, this only fires on a real
    # connectivity/dependency problem, where crash-looping until Redis is up is
    # the correct behaviour.)
    if not storage.available():
        raise RuntimeError(
            "OAuth is enabled (MCP_DATA_PUBLIC_URL is set) but Redis is unavailable. "
            "OAuth cannot persist clients/codes/tokens without it. "
            "Fix REDIS_URL / start Redis, or unset MCP_DATA_PUBLIC_URL to disable OAuth."
        )

    provider = TwelveDataASProvider()
    settings = AuthSettings(
        issuer_url=issuer_url(),
        resource_server_url=resource_url(),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[SCOPE],
            default_scopes=[SCOPE],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=None,
    )
    log.info("oauth: Authorization Server enabled (issuer=%s)", issuer_url())
    return provider, settings


def resolve_apikey() -> Optional[str]:
    """Return the Twelve Data API key for the current request."""
    import os
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token
        token = get_access_token()
        user_id = getattr(token, "user_id", None) if token else None

        if user_id:
            from store import store
            api_key = store.get_user_token(user_id)
            if api_key:
                return api_key
    except Exception:
        pass
    # Fallback for self-hosted Horizon deployments
    return os.getenv("TWELVE_DATA_API_KEY")
