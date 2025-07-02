# encoding: utf-8

from __future__ import annotations

import logging
import secrets
from typing import Any, Optional

import ckan.plugins.toolkit as tk
from ckan import model
from ckan.logic.action.create import _get_random_username_from_email
from ckan.plugins import Interface

from . import config, signals

log = logging.getLogger(__name__)


class IOidcPkce(Interface):
    """ """

    def get_oidc_user(self, userinfo: dict[str, Any]) -> Optional[model.User]:
        q = model.Session.query(model.User)

        log.debug("Querying for user with Auth0 ID: %s", userinfo["sub"])
        user = q.filter(
            model.User.plugin_extras["oidc_pkce"]["sub"].astext == userinfo["sub"]
        ).one_or_none()

        if user:
            log.info("Found user by Auth0 ID=%s, email=%s", user.id, user.email)
            signals.user_exist.send(user.id)
            return user

        # Fallback: Try to find by email
        log.debug("Querying for user with email: %s", userinfo["email"])
        users = q.filter(model.User.email.ilike(userinfo["email"])).all()

        if len(users) > 1:
            log.error("Unable to uniquely identify account, found %s matches for: %s",
                      len(users), userinfo["email"])
            return None
        elif users:
            user = users[0]
            log.info("Found user by email: id=%s, email=%s", user.id, user.email)

            admin = tk.get_action("get_site_user")({"ignore_auth": True}, {})
            user_dict = tk.get_action("user_show")(
                {"user": admin["name"]},
                {"id": user.id, "include_plugin_extras": True},
            )
            extras = user_dict.pop("plugin_extras", None) or {}

            # Update extras to include sub
            if "oidc_pkce" not in extras:
                extras["oidc_pkce"] = {}
            extras["oidc_pkce"].update(userinfo.copy())

            log.debug("Updating user plugin_extras with oidc_pkce data: %s", extras["oidc_pkce"])

            data = self.oidc_info_into_user_dict(userinfo)
            data["id"] = user.id
            data.pop("name")

            if not config.munge_password():
                data.pop("password")

            data["plugin_extras"] = extras
            user_dict.update(data)

            tk.get_action("user_update")({"user": admin["name"]}, user_dict)
            log.info("Updated user with Auth0 sub and other OIDC info: id=%s", user.id)

            signals.user_sync.send(user.id)
            return user

        # If no match, create new user
        log.info("No existing user found; creating new user for email: %s", userinfo["email"])
        return self.create_oidc_user(userinfo)

    def oidc_info_into_plugin_extras(
        self, userinfo: dict[str, Any]
    ) -> dict[str, Any]:
        log.debug("Creating plugin_extras from userinfo")
        return {"oidc_pkce": userinfo.copy()}

    def oidc_info_into_user_dict(
        self, userinfo: dict[str, Any]
    ) -> dict[str, Any]:
        log.debug("Creating user dict from userinfo")
        data = {
            "email": userinfo["email"],
            "name": _get_random_username_from_email(userinfo["email"]),
            "password": secrets.token_urlsafe(60) + "1A!a_",
            "fullname": userinfo.get("name", userinfo["email"]),
            "plugin_extras": self.oidc_info_into_plugin_extras(userinfo),
        }

        if config.same_id():
            data["id"] = userinfo["sub"]
            log.debug("Using Auth0 sub as user id: %s", userinfo["sub"])

        return data

    def create_oidc_user(self, userinfo: dict[str, Any]) -> model.User:
        log.debug("Creating new user with userinfo: %s", userinfo)
        user_dict = self.oidc_info_into_user_dict(userinfo)
        admin = tk.get_action("get_site_user")({"ignore_auth": True}, {})
        user = tk.get_action("user_create")({"user": admin["name"]}, user_dict)

        log.info("Created new user: id=%s, email=%s", user["id"], userinfo["email"])
        signals.user_create.send(user["id"])
        return model.User.get(user["id"])

    def oidc_login_response(self, user: model.User) -> Any:
        log.debug("Handling login response for user id=%s", user.id)
        return None
