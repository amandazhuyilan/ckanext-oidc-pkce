from __future__ import annotations

import base64
import hashlib
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

from .interfaces import IOidcPkce

log = logging.getLogger(__name__)

AUTH0_DOMAIN = 'dev-bc.au.auth0.com'
API_AUDIENCE = 'https://dev-bc.au.auth0.com/api/v2/'
DEFAULT_LENGTH = 64
JWKS_URL = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
SESSION_USER = "ckanext:oidc-pkce:username"

def code_verifier(n_bytes: int = DEFAULT_LENGTH) -> str:
    """Generate PKCE verifier"""
    valid_range = range(31, 97)
    if n_bytes not in valid_range:
        raise ValueError(f"Verifier too short. n_bytes must in {valid_range}")

    return secrets.token_urlsafe(n_bytes)


def code_challenge(verifier: str) -> str:
    """Generate a code challenge based on the code verifier"""
    digest = hashlib.sha256(bytes(verifier, "ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def app_state(n_bytes: int = DEFAULT_LENGTH) -> str:
    return secrets.token_urlsafe(n_bytes)


def sync_user(userinfo: dict[str, Any]) -> Optional[model.User]:
    plugin = next(iter(PluginImplementations(IOidcPkce)))
    log.debug("Synchronize user using %s", plugin)

    user = plugin.get_oidc_user(userinfo)
    if not user:
        log.error("Cannot locate or create unique user using OIDC info: %s", userinfo)
        return

    return user


def login(user: model.User):
    if tk.check_ckan_version("2.10"):
        from ckan.common import login_user

        login_user(user)
    else:
        session[SESSION_USER] = user.name

def get_jwks():
    """
    Fetch the JSON Web Key Set (JWKS) from Auth0 to validate JWTs.
    """
    response = requests.get(JWKS_URL)
    response.raise_for_status()
    return response.json()

def get_signing_key(token):
    """
    Extract the appropriate public key from JWKS based on token header 'kid'.
    """
    unverified_header = jwt.get_unverified_header(token)
    jwks = get_jwks()
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            return RSAAlgorithm.from_jwk(key)
    raise Exception('Unable to find signing key for the token')

def decode_access_token(token):
    """
    Decode and verify an Auth0 access token using RS256 and JWKS.
    """
    key = get_signing_key(token)
    decoded = jwt.decode(
        token,
        key=key,
        algorithms=['RS256'],
        audience=API_AUDIENCE,
        issuer=f'https://{AUTH0_DOMAIN}/'
    )
    return decoded