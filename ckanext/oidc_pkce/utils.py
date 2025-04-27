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
import re

log = logging.getLogger(__name__)

AUTH0_DOMAIN = "login.test.biocommons.org.au"
API_AUDIENCE = "v82EoLw0NzR5GXcdHgLMVL9urGIbZQHH"
DEFAULT_LENGTH = 64
JWKS_URL = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
ROLE_CLAIM = "https://biocommons.org.au/roles"
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
    log.info("Synchronize user using plugin: %s", plugin)

    user = plugin.get_oidc_user(userinfo)
    if not user:
        log.error("Cannot locate or create user using: %s", userinfo)
        return

    user_obj = model.User.get(user.name)
    context = {"user": user.name}
    token_roles = userinfo.get("https://biocommons.org.au/roles", [])

    log.info(f"User '{user.name}' roles from token: {token_roles}")

    if not token_roles:
        log.warning("No roles found in userinfo token for user '%s'", user.name)
        return user

    for role in token_roles:
        if role == "BPA/SysAdmin":
            if user_obj and not user_obj.sysadmin:
                user_obj.sysadmin = True
                model.Session.commit()
                log.info(f"Granted sysadmin to '{user.name}' via BPA/SysAdmin")
            continue

        match = re.match(r"BPA/Org/(?P<org>[\w\-\.]+):(?P<ckan_role>\w+)", role)
        if not match:
            log.warning(f"Role '{role}' does not match expected pattern 'BPA/Org/<org-name>:<role-name>'")
            continue

        org_name = match.group("org").lower()
        ckan_role = match.group("ckan_role").lower()

        log.debug(f"Parsed Auth0 role '{role}' -> org: '{org_name}', role: '{ckan_role}'")

        # Validate organization exists
        try:
            tk.get_action("organization_show")(context, {"id": org_name})
        except tk.ObjectNotFound:
            log.error(f"[OIDC] Organization '{org_name}' does not exist. Cannot assign role '{ckan_role}' for user '{user.name}'.")
            continue
        except Exception as e:
            log.error(f"[OIDC] Error checking existence of organization '{org_name}': {e}")
            continue

        # Validate role is known
        if ckan_role not in {"admin", "editor", "member"}:
            log.warning(f"[OIDC] Invalid CKAN role '{ckan_role}' parsed from '{role}' — skipping.")
            continue

        try:
            # Check existing membership
            existing_roles = tk.get_action("organization_member_list")(
                context, {"id": org_name, "object_type": "user"}
            )
            user_roles = [r for r in existing_roles if r['name'] == user.name]

            if user_roles:
                current_role = user_roles[0]['capacity']
                log.debug(f"[OIDC] User '{user.name}' already has role '{current_role}' in org '{org_name}'")

                if current_role == 'admin':
                    log.info(f"[OIDC] '{user.name}' is already admin in '{org_name}', skipping downgrade to '{ckan_role}'")
                    continue
                if current_role == ckan_role:
                    log.info(f"[OIDC] '{user.name}' already has correct role '{ckan_role}' in '{org_name}', skipping.")
                    continue

            # Assign new role if needed
            tk.get_action("organization_member_create")(
                context,
                {"id": org_name, "username": user.name, "role": ckan_role}
            )
            log.info(f"Assigned '{user.name}' as '{ckan_role}' in org '{org_name}' via role '{role}'")

        except tk.ValidationError as ve:
            log.debug(f"Validation error while assigning '{user.name}' in '{org_name}': {ve}")
        except Exception as e:
            log.error(f"[OIDC] Error assigning user '{user.name}' to '{org_name}': {e}")

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
        log.info("Token is already a dict — skipping JWT decode")
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
        log.info("Successfully resolved signing key for JWT.")

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
