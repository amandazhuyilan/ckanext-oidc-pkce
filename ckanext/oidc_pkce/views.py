from __future__ import annotations

import base64
import logging
from urllib.parse import urlencode

import requests
from flask import Blueprint, redirect

import ckan.plugins.toolkit as tk
from ckan.common import session
from ckan.plugins import PluginImplementations

from . import config, utils
from .interfaces import IOidcPkce

log = logging.getLogger(__name__)

SESSION_VERIFIER = "ckanext:oidc-pkce:verifier"
SESSION_STATE = "ckanext:oidc-pkce:state"
SESSION_CAME_FROM = "ckanext:oidc-pkce:came_from"
SESSION_ERROR = "ckanext:oidc-pkce:error"

bp = Blueprint("oidc_pkce", __name__)


def get_blueprints():
    return [bp]


@bp.route("/user/login/oidc-pkce")
def login():
    verifier = utils.code_verifier()
    state = utils.app_state()
    session[SESSION_VERIFIER] = verifier
    session[SESSION_STATE] = state
    session[SESSION_CAME_FROM] = tk.request.args.get("came_from")

    params = {
        "client_id": config.client_id(),
        "redirect_uri": config.redirect_url(),
        "scope": config.scope(),
        "state": state,
        "code_challenge": utils.code_challenge(verifier),
        "code_challenge_method": "S256",
        "response_type": "code",
        "response_mode": "query",
    }

    url = f"{config.auth_url()}?{urlencode(params)}"
    resp = redirect(url)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


def callback():
    error = tk.request.args.get("error")
    state = tk.request.args.get("state")
    code = tk.request.args.get("code")

    verifier = session.pop(SESSION_VERIFIER, None)
    session_state = session.pop(SESSION_STATE, None)
    came_from = config.error_redirect() or tk.url_for("user.login")

    if not error:
        if not verifier:
            error = "Login process was not started properly"
        elif not code:
            error = "The code was not returned or is not accessible"
        elif state != session_state:
            error = "The app state does not match"

    if error:
        log.error(f"Error: {error}")
        session[SESSION_ERROR] = error
        return tk.redirect_to(came_from)

    headers = {
        "accept": "application/json",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded",
    }

    if config.client_secret():
        auth_header = f"{config.client_id()}:{config.client_secret()}"
        headers["Authorization"] = "Basic " + base64.b64encode(auth_header.encode("ascii")).decode("ascii")

    data = {
        "grant_type": "authorization_code",
        "client_id": config.client_id(),
        "redirect_uri": config.redirect_url(),
        "code": code,
        "code_verifier": verifier,
    }

    exchange = requests.post(config.token_url(), headers=headers, data=data).json()

    log.debug(f"Token exchange keys: {list(exchange.keys())}")
    log.debug(f"access_token (start): {exchange.get('access_token', '')[:80]}")
    log.debug(f"id_token (start): {exchange.get('id_token', '')[:80]}")

    if not exchange.get("token_type"):
        error = "Unsupported token type. Should be 'Bearer'."
        log.error("Error: %s", error)
        session[SESSION_ERROR] = error
        return tk.redirect_to(came_from)

    access_token = exchange.get("access_token")
    id_token = exchange.get("id_token")

    decoded_token = {}
    if id_token:
        try:
            decoded_token = utils.decode_access_token(id_token)
            log.info(f"Decoded ID token: {decoded_token}")

            # Extract and log user roles from the decoded token
            user_roles = utils.get_roles_from_token(decoded_token)
            log.info(f"User roles from token: {user_roles}")
        except Exception as e:
            log.error(f"JWT decoding failed: {e}")
    else:
        log.warning("No id_token found in exchange. Skipping decode.")

    # Use access_token to get userinfo (as required by OIDC)
    userinfo = requests.get(
        config.userinfo_url(),
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()

    user = utils.sync_user(userinfo)
    if not user:
        error = "Unique user not found"
        log.error("Error: %s", error)
        tk.h.flash_error(error)
        session[SESSION_ERROR] = error
        return tk.redirect_to(came_from)

    for plugin in PluginImplementations(IOidcPkce):
        resp = plugin.oidc_login_response(user)
        if resp:
            return resp

    utils.login(user)

    came_from = session.pop(SESSION_CAME_FROM, None)
    return tk.redirect_to(came_from or tk.config.get("ckan.route_after_login", "dashboard.index"))


bp.add_url_rule(config.redirect_path(), view_func=callback)
