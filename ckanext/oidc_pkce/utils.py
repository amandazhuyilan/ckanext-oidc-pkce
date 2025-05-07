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
    """Main entry point for user sync on login."""
    plugin = next(iter(PluginImplementations(IOidcPkce)))
    log.debug("[OIDC] Synchronize user using plugin: %s", plugin)

    user = plugin.get_oidc_user(userinfo)
    if not user:
        raise tk.NotAuthorized("Unable to identify or create a CKAN user from your identity provider.")

    user_obj = model.User.get(user.name)
    context = {"user": user.name}
    token_roles = userinfo.get("https://biocommons.org.au/roles", [])

    # If no roles, still allow login
    if not token_roles:
        log.info(f"[OIDC] No role claims for '{user.name}', proceeding without org assignments.")
        return user

    for role in token_roles:
        if role == "BPA/SysAdmin":
            promote_to_sysadmin(user_obj)
            continue

        parsed = parse_org_role(role)
        if not parsed:
            log.debug(f"[OIDC] Skipping unrecognized role format: '{role}'")
            continue

        org_name, ckan_role = parsed
        if not validate_ckan_role(ckan_role):
            log.warning(f"[OIDC] Skipping invalid CKAN role: '{ckan_role}'")
            continue

        if not organization_exists(org_name, context):
            log.warning(f"[OIDC] Organization '{org_name}' not found. Skipping role assignment.")
            continue

        assign_role_in_organization(user.name, org_name, ckan_role, context)

    return user

def promote_to_sysadmin(user_obj: model.User):
    if user_obj and not user_obj.sysadmin:
        user_obj.sysadmin = True
        model.Session.commit()
        log.info(f"[OIDC] Granted sysadmin privileges to user '{user_obj.name}'")


def parse_org_role(role: str) -> Optional[tuple[str, str]]:
    match = re.match(r"BPA/Org/(?P<org>[\w\-\.]+):(?P<ckan_role>\w+)", role)
    if match:
        return match.group("org").lower(), match.group("ckan_role").lower()
    return None


def validate_ckan_role(ckan_role: str) -> bool:
    return ckan_role in {"admin", "editor", "member"}


def organization_exists(org_name: str, context: dict) -> bool:
    try:
        tk.get_action("organization_show")(context, {"id": org_name})
        return True
    except tk.ObjectNotFound:
        return False


def assign_role_in_organization(username: str, org_name: str, ckan_role: str, context: dict):
    try:
        existing_roles = tk.get_action("member_list")(
            context, {"id": org_name, "object_type": "user"}
        )
        user_roles = [r for r in existing_roles if r[0] == username]

        if user_roles:
            current_role = user_roles[0][2]
            if current_role == "admin":
                log.debug(f"[OIDC] '{username}' is already admin in '{org_name}', skipping downgrade.")
                return
            if current_role == ckan_role:
                log.debug(f"[OIDC] '{username}' already has correct role '{ckan_role}' in '{org_name}', skipping.")
                return

        tk.get_action("organization_member_create")(
            context,
            {"id": org_name, "username": username, "role": ckan_role}
        )
        log.info(f"[OIDC] Assigned '{username}' as '{ckan_role}' in '{org_name}'")

    except tk.NotAuthorized as e:
        log.warning(f"[OIDC] Not authorized to assign user '{username}' in '{org_name}': {e}")
    except Exception as e:
        log.error(f"[OIDC] Unexpected error assigning user '{username}' to '{org_name}': {e}")

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
