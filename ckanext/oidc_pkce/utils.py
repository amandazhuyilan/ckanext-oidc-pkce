from __future__ import annotations

import base64
import hashlib
import jwt
import logging
import requests
import secrets
from jwt.algorithms import RSAAlgorithm
from typing import Any, Optional
import json

import ckan.plugins.toolkit as tk
from ckan import model
from ckan.common import session
from ckan.plugins import PluginImplementations

from .interfaces import IOidcPkce

log = logging.getLogger(__name__)

AUTH0_DOMAIN = "login.test.biocommons.org.au"
API_AUDIENCE = "v82EoLw0NzR5GXcdHgLMVL9urGIbZQHH"
DEFAULT_LENGTH = 64
JWKS_URL = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
ROLE_CLAIM = "https://biocommons.org.au/roles"
ROLE_PREFIX = "BPA/"
SESSION_USER = "ckanext:oidc-pkce:username"


def code_verifier(n_bytes: int = DEFAULT_LENGTH) -> str:
    """Generate PKCE verifier"""
    valid_range = range(31, 97)
    if n_bytes not in valid_range:
        raise ValueError(f"Verifier too short. n_bytes must be in {valid_range}")
    return secrets.token_urlsafe(n_bytes)


def code_challenge(verifier: str) -> str:
    """Generate a code challenge based on the code verifier"""
    digest = hashlib.sha256(bytes(verifier, "ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def app_state(n_bytes: int = DEFAULT_LENGTH) -> str:
    return secrets.token_urlsafe(n_bytes)

def sync_user(userinfo: dict[str, Any]) -> Optional[model.User]:
    plugin = next(iter(PluginImplementations(IOidcPkce)))
    log.debug("Synchronize user using plugin: %s", plugin)

    user = plugin.get_oidc_user(userinfo)
    if not user:
        log.error("Cannot locate or create unique user using OIDC info: %s", userinfo)
        return

    user_obj = model.User.get(user.name)
    context = {"user": user.name}
    token_roles = userinfo.get("https://biocommons.org.au/roles", [])

    log.info(f"[OIDC] User '{user.name}' has Auth0 roles: {token_roles}")

    # Load role-org mapping from config
    try:
        raw_map = tk.config.get("ckanext.oidc_pkce.role_org_map", "{}")
        role_map = json.loads(raw_map)
    except Exception as e:
        log.error("Failed to parse 'ckanext.oidc_pkce.role_org_map' config: %s", e)
        role_map = {}

    for role in token_roles:
        if not role.startswith("BPA/"):
            log.debug("Skipping non-BPA role: %s", role)
            continue

        mapped = role_map.get(role)
        if not mapped:
            log.warning(f"[OIDC] Role '{role}' not in configured role_org_map.")
            continue

        if mapped == "__sysadmin__":
            # Grant sysadmin if mapped as such
            if user_obj and not user_obj.sysadmin:
                user_obj.sysadmin = True
                model.Session.commit()
                log.info(f"[OIDC] Granted sysadmin to '{user.name}' via role '{role}'")
            continue

        # Expect format like "org-name:role"
        if ":" not in mapped:
            log.warning(f"[OIDC] Invalid role mapping format: {mapped}")
            continue

        org_name, ckan_role = mapped.split(":", 1)
        log.debug(f"[OIDC] Mapping role '{role}' to org '{org_name}' with role '{ckan_role}'")

        # Ensure org exists
        try:
            tk.get_action("organization_show")(context, {"id": org_name})
            log.debug(f"[OIDC] Organization '{org_name}' exists.")
        except tk.ObjectNotFound:
            try:
                tk.get_action("organization_create")(context, {"name": org_name, "title": org_name})
                log.info(f"[OIDC] Created organization '{org_name}'")
            except Exception as e:
                log.error(f"[OIDC] Failed to create org '{org_name}': {e}")
                continue

        # Add user to org
        try:
            tk.get_action("organization_member_create")(
                context,
                {"id": org_name, "username": user.name, "role": ckan_role}
            )
            log.info(f"[OIDC] Assigned '{user.name}' as '{ckan_role}' in org '{org_name}'")
        except tk.ValidationError:
            log.debug(f"[OIDC] '{user.name}' already has role in org '{org_name}'")
        except Exception as e:
            log.error(f"[OIDC] Failed to assign user '{user.name}' to '{org_name}': {e}")

    return user

def login(user: model.User):
    if tk.check_ckan_version("2.10"):
        from ckan.common import login_user
        login_user(user)
    else:
        session[SESSION_USER] = user.name


def get_jwks():
    """Fetch the JSON Web Key Set (JWKS) from Auth0 to validate JWTs."""
    response = requests.get(JWKS_URL)
    response.raise_for_status()
    return response.json()


def get_signing_key(token):
    unverified_header = jwt.get_unverified_header(token)
    jwks = get_jwks()
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:  # ✅ this is the correct line
            return RSAAlgorithm.from_jwk(json.dumps(key))
    raise Exception('Unable to find signing key for the token')

def decode_access_token(token):
    """
    Decode and verify a JWT token using RS256 and JWKS.
    """
    if isinstance(token, dict):
        log.warning("Token is already a dict — skipping JWT decode")
        return token

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    try:
        # Decode without verification first to inspect
        unverified = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception as e:
        log.error(f"Failed to decode JWT without verification: {e}")
        return {}

    try:
        key = get_signing_key(token)
        log.debug("Successfully resolved signing key for JWT.")

        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        log.info(f"Verified decoded JWT claims: {decoded}")
        return decoded
    except Exception as e:
        log.error(f"JWT decoding failed: {e}")
        return {}

def get_roles_from_token(access_token: dict[str, Any]) -> List[str]:
    """
    Extract and return role names from a decoded JWT access token.

    Only includes roles starting with ROLE_PREFIX.

    Args:
        access_token: The decoded Auth0 token (id_token or access_token)

    Returns:
        A list of role strings (filtered by prefix)
    """
    if not access_token:
        log.warning("No access token provided for role extraction")
        return []

    raw_roles = access_token.get(ROLE_CLAIM, [])
    log.debug(f"Raw roles in token: {raw_roles}")

    token_roles = [role for role in raw_roles if role.lower().startswith(ROLE_PREFIX)]
    log.info(f"Filtered roles from token: {token_roles}")
    return token_roles