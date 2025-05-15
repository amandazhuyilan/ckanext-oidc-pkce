from __future__ import annotations

import base64
import logging
from urllib.parse import urlencode

import requests
from flask import Blueprint, redirect

import ckan.plugins.toolkit as tk
from ckan.common import session
from ckan.plugins import PluginImplementations
from ckan.plugins.toolkit import h, redirect_to

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


@bp.route("/user/login/oidc-pkce/callback")
def callback():
    error = tk.request.args.get("error")
    error_description = tk.request.args.get("error_description")
    state = tk.request.args.get("state")
    code = tk.request.args.get("code")

    verifier = session.pop(SESSION_VERIFIER, None)
    session_state = session.pop(SESSION_STATE, None)

    fallback_redirect = redirect_to("home.index")

    if error:
        msg = error_description or "OIDC login was denied."
        log.error(f"[OIDC] Error during callback: {error} - {msg}")
        h.flash_error(msg)
        return fallback_redirect

    if not verifier:
        h.flash_error("Login process was not started properly.")
        return fallback_redirect

    if not code:
        h.flash_error("The authorization code was not returned.")
        return fallback_redirect

    if state != session_state:
        h.flash_error("The OIDC app state does not match.")
        return fallback_redirect

    # Exchange code for tokens
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
        log.error("Unsupported token type or failed exchange.")
        h.flash_error("Authentication failed. Please try again later.")
        return fallback_redirect

    access_token = exchange.get("access_token")
    id_token = exchange.get("id_token")

    decoded_token = {}
    if id_token:
        try:
            decoded_token = utils.decode_access_token(id_token)
            log.info(f"Decoded ID token: {decoded_token}")
        except Exception as e:
            log.error(f"JWT decoding failed: {e}")
    else:
        log.warning("No id_token found in exchange. Skipping decode.")

    userinfo = requests.get(
        config.userinfo_url(),
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()

    try:
        user = utils.sync_user(userinfo)
    except tk.NotAuthorized as e:
        h.flash_error(str(e))
        return fallback_redirect

    if not user:
        h.flash_error("Unique user could not be resolved.")
        return fallback_redirect

    for plugin in PluginImplementations(IOidcPkce):
        resp = plugin.oidc_login_response(user)
        if resp:
            return resp

    utils.login(user)

    came_from = session.pop(SESSION_CAME_FROM, None)
    return tk.redirect_to(came_from or tk.config.get("ckan.route_after_login", "dashboard.index"))


bp.add_url_rule(config.redirect_path(), view_func=callback)
