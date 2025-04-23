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
        log.error("Cannot locate or create user using: %s", userinfo)
        return

    user_obj = model.User.get(user.name)
    context = {"user": user.name}
    token_roles = userinfo.get("https://biocommons.org.au/roles", [])

    log.info(f"User '{user.name}' roles from token: {token_roles}")

    # Load role-to-org-role mapping from config
    try:
        role_map_raw = tk.config.get("ckanext.oidc_pkce.role_org_map", "{}")
        role_map = json.loads(role_map_raw)
        if role_map:
            log.debug(f"[OIDC] Loaded role mapping: {role_map}")
        else:
            log.debug(f"role mapping empty!")
    except Exception as e:
        log.error("Failed to parse 'role_org_map': %s", e)
        return user

    for role in token_roles:
        mapped_value = role_map.get(role)
        if not mapped_value:
            log.debug(f"Role '{role}' not mapped in config.")
            continue

        if mapped_value == "__sysadmin__":
            if user_obj and not user_obj.sysadmin:
                user_obj.sysadmin = True
                model.Session.commit()
                log.info(f"Granted sysadmin to '{user.name}' via role '{role}'")
            continue

        if ":" not in mapped_value:
            log.warning(f"Invalid format for mapping '{mapped_value}', skipping.")
            continue

        org_name, ckan_role = mapped_value.split(":", 1)

        # Ensure org exists
        try:
            tk.get_action("organization_show")(context, {"id": org_name})
        except tk.ObjectNotFound:
            try:
                tk.get_action("organization_create")(context, {"name": org_name, "title": org_name})
                log.info(f"Created org '{org_name}' for role '{role}'")
            except Exception as e:
                log.error(f"Failed to create org '{org_name}': {e}")
                continue

        # Assign user to organization
        try:
            tk.get_action("organization_member_create")(
                context,
                {"id": org_name, "username": user.name, "role": ckan_role}
            )
            log.info(f"Assigned '{user.name}' as '{ckan_role}' in '{org_name}' via role '{role}'")
        except tk.ValidationError:
            log.debug(f"'{user.name}' already has role in '{org_name}'")
        except Exception as e:
            log.error(f"Error assigning role in '{org_name}' for '{user.name}': {e}")

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