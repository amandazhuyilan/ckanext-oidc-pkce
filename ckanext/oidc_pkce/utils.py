from __future__ import annotations

import base64
import hashlib
import json
import jwt
import logging
import requests
import secrets
from jwt.algorithms import RSAAlgorithm
from typing import Any, Optional

import ckan.plugins.toolkit as tk
from ckan import model
from ckan.common import session
from ckan.plugins import PluginImplementations
from ckan.plugins.toolkit import h, redirect_to

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
    log.debug("Synchronize user using plugin: %s", plugin)

    user = plugin.get_oidc_user(userinfo)
    if not user:
        raise tk.NotAuthorized("Unable to identify or create a BPA Data Portal user from your identity provider.")

    user_obj = model.User.get(user.name)
    context = {"user": user.name}

    redirect = ensure_verified_email(userinfo, user.name)
    if redirect:
        return redirect

 
    app_metadata = userinfo.get("https://biocommons.org.au/app_metadata", {})
    if not app_metadata:
        log.warning(f"No Auth0 app_metadata found in userinfo for {user.name}!")


    user_metadata = userinfo.get("https://biocommons.org.au/user_metadata", {})
    if not user_metadata:
        log.warning(f"No Auth0 user_metadata found in userinfo for {user.name}!")

    bpa_data = user_metadata.get("bpa")
    if not bpa_data:
        log.warning(f"Missing 'bpa' field in user_metadata for userinfo: {userinfo}")
    else:
        username = bpa_data.get("username")
        if username:
            log.info(f"bpa.username='{username}' confirmed for user '{user.name}'")
        else:
            log.warning("Missing 'username' field in 'bpa' metadata")

    services = app_metadata.get("services", [])

    # Use roles to manage org membership
    token_roles = userinfo.get(ROLE_CLAIM, [])
    if token_roles:
        for role in token_roles:
            if role == "BPA/SysAdmin":
                promote_to_sysadmin(user_obj)
                continue

            parsed = parse_org_role(role)
            if not parsed:
                log.debug(f"Skipping unrecognized role format: '{role}'")
                continue

            org_name, ckan_role = parsed
            if not validate_ckan_role(ckan_role):
                log.warning(f"Skipping invalid CKAN role: '{ckan_role}'")
                continue

            if not organization_exists(org_name, context):
                log.warning(f"Organization '{org_name}' not found. Skipping role assignment.")
                continue

            assign_role_in_organization(user.name, org_name, ckan_role, context)
    else:
        log.info(f"No token-based roles for '{user.name}', evaluating app_metadata services.")

    # Handle pending status without creating requests
    pending_org_ids = get_pending_orgs_from_services(services, context)
    session["ckanext:oidc-pkce:pending_org_ids"] = pending_org_ids
    log.info(f"User '{user.name}' has pending access to: {pending_org_ids}")

    # flush changes for extras
    model.Session.add(user_obj)
    model.Session.commit()
    return user


def promote_to_sysadmin(user_obj: model.User):
    if user_obj and not user_obj.sysadmin:
        user_obj.sysadmin = True
        model.Session.commit()
        log.info(f"Granted sysadmin privileges to user '{user_obj.name}'")


def parse_org_role(role: str) -> Optional[tuple[str, str]]:
    match = re.match(r"BPA/Org/(?P<org>[\w\-\.]+):(?P<ckan_role>\w+)", role)
    if match:
        return match.group("org").lower(), match.group("ckan_role").lower()
    return None


def register_membership_request(username: str, org_id: str, context: dict[str, Any]):
    """
    Create a membership request if one does not already exist.
    """
    try:
        existing_requests = tk.get_action("ytp_request_list")(context, {
            "object_id": org_id,
            "object_type": "organization",
            "type": "membership",
            "user": username,
            "status": "pending"
        })

        if existing_requests:
            log.info(f"Skipping creation — pending request already exists for '{username}' in '{org_id}'.")
            return

        tk.get_action("ytp_request_create")(context, {
            "object_id": org_id,
            "object_type": "organization",
            "type": "membership",
            "message": "Auto-created from Auth0 app_metadata",
        })
        log.info(f"Created pending membership request for '{username}' in '{org_id}'")

    except tk.ValidationError as e:
        log.warning(f"[OIDC] Validation error on request creation for '{org_id}': {e}")
    except Exception as e:
        log.error(f"[OIDC] Failed to create request for '{org_id}': {e}")


def sync_resource_requests(username: str, services: list[dict[str, Any]], context: dict[str, Any]):
    for service in services:
        for resource in service.get("resources", []):
            org_id = resource.get("id")
            status = resource.get("status")

            if not org_id or not status:
                continue

            if not organization_exists(org_id, context):
                log.warning(f"Organization '{org_id}' from app_metadata not found, skipping.")
                continue

            if status == "approved":
                assign_role_in_organization(username, org_id, "member", context)
            elif status == "pending":
                register_membership_request(username, org_id, context)
            else:
                log.info(f"No act ion taken for org '{org_id}' with status '{status}'")


def validate_ckan_role(ckan_role: str) -> bool:
    return ckan_role in {"admin", "member"}


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
                log.debug(f"'{username}' is already admin in '{org_name}', skipping downgrade.")
                return
            if current_role == ckan_role:
                log.debug(f"'{username}' already has correct role '{ckan_role}' in '{org_name}', skipping.")
                return

        tk.get_action("organization_member_create")(
            context,
            {"id": org_name, "username": username, "role": ckan_role}
        )
        log.info(f"Assigned '{username}' as '{ckan_role}' in '{org_name}'")

    except tk.NotAuthorized as e:
        log.warning(f"Not authorized to assign user '{username}' in '{org_name}': {e}")
    except Exception as e:
        log.error(f"Unexpected error assigning user '{username}' to '{org_name}': {e}")


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
        if key['kid'] == unverified_header['kid']:
            return RSAAlgorithm.from_jwk(json.dumps(key))
    raise Exception('Unable to find signing key for the token')


def ensure_verified_email(userinfo: dict[str, Any], username: str):
    """Check if the user's email is verified. If not, show a UI error and redirect."""
    email_verified = userinfo.get("email_verified", False)
    if not email_verified:
        msg = "Your email address is not verified. Please check your inbox, confirm your email address and sign in again."
        log.warning(f"Blocking login for unverified user '{username}'")
        h.flash_error(msg)
        return redirect_to("home.index")


def decode_access_token(token):
    """
    Decode and verify a JWT token using RS256 and JWKS.
    """
    if isinstance(token, dict):
        log.info(" Token is already a dict — skipping JWT decode")
        return token

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    try:
        # Decode without verification first to inspect
        unverified = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception as e:
        log.error(f" Failed to decode JWT without verification: {e}")
        return {}

    try:
        key = get_signing_key(token)
        log.info(" Successfully resolved signing key for JWT.")

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


def get_pending_orgs_from_services(
    services: list[dict[str, Any]],
    context: dict[str, Any]
) -> list[str]:
    """
    Extract and validate pending org IDs from Auth0 app_metadata services block.
    Only return org IDs marked as 'pending' that exist in CKAN.
    """
    pending = []

    for service in services:
        for resource in service.get("resources", []):
            org_id = resource.get("id")
            status = resource.get("status")

            if status != "pending" or not org_id:
                continue

            if organization_exists(org_id, context):
                pending.append(org_id)
            else:
                log.warning(f"Pending org '{org_id}' from app_metadata not found in BPA, skipping.")

    return pending
