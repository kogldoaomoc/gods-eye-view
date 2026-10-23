"""Pluggable delivery for verification codes.

Email goes out over SMTP. SMS goes through a provider interface; the console
provider is the local and test implementation. OAuth is the same kind of
plug: a provider proves a username by signing in, and the bridge never reads
client secrets from the request.

Secrets are read from the environment at send time. They are not returned to
the caller and they are not put in errors or logs.
"""

from __future__ import annotations

import json
import os
import smtplib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from urllib.parse import quote

from .http import USER_AGENT

# Public profile URLs the bridge will fetch. Callers cannot supply a URL.
# GitHub's API and Reddit's about.json expose profile text to an anonymous
# fetch. GitLab and X/Twitter do not, so they are not profile-code platforms;
# OAuth is the alternative there.
PLATFORM_URLS = {
    "github": "https://api.github.com/users/{username}",
    "reddit": "https://www.reddit.com/user/{username}/about.json",
}
PROFILE_TEXT_UNAVAILABLE = frozenset({"gitlab", "x", "twitter"})
_MAX_REDIRECTS = 5


class DeliveryError(RuntimeError):
    """A code could not be delivered. The message is safe to show a client."""


class SmtpEmailSender:
    """Send one message to one address. Reads SMTP settings from the environment."""

    def send(self, to: str, subject: str, body: str) -> None:
        if not isinstance(to, str) or "@" not in to or any(ch in to for ch in "\r\n,;"):
            raise DeliveryError("email delivery failed")
        host = os.environ.get("CASEFILE_SMTP_HOST", "").strip()
        from_addr = os.environ.get("CASEFILE_SMTP_FROM", "").strip()
        user = os.environ.get("CASEFILE_SMTP_USER", "").strip()
        password = os.environ.get("CASEFILE_SMTP_PASSWORD", "")
        if not host or not from_addr:
            raise DeliveryError("email delivery is not configured")
        try:
            port = int(os.environ.get("CASEFILE_SMTP_PORT", "587"))
        except ValueError:
            raise DeliveryError("email delivery is not configured") from None
        message = EmailMessage()
        message["From"] = from_addr
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        try:
            if port == 465:
                smtp = smtplib.SMTP_SSL(host, port, timeout=30)
            else:
                smtp = smtplib.SMTP(host, port, timeout=30)
                smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
            smtp.quit()
        except DeliveryError:
            raise
        except Exception:
            raise DeliveryError("email delivery failed") from None


class SmsSender:
    """Interface for an SMS provider. ``send`` delivers one message to one number."""

    def send(self, to: str, body: str) -> None:
        raise NotImplementedError


class ConsoleSmsSender(SmsSender):
    """Dev and test SMS provider.

    Messages are kept in memory so tests can read the code. The log line names
    the destination and the length only — the code itself is not logged.
    """

    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    def send(self, to: str, body: str) -> None:
        if not isinstance(to, str) or not to.startswith("+") or any(ch in to for ch in "\r\n,;"):
            raise DeliveryError("sms delivery failed")
        self.sent.append((to, body))
        print(f"casefile-sms: delivered to {mask_phone(to)} ({len(body)} chars)", file=sys.stderr)


class UnavailableSmsSender(SmsSender):
    def __init__(self, reason: str):
        self._reason = reason

    def send(self, to: str, body: str) -> None:
        raise DeliveryError(self._reason)


def sms_from_env() -> SmsSender:
    kind = os.environ.get("CASEFILE_SMS_PROVIDER", "console").strip().lower() or "console"
    if kind == "console":
        return ConsoleSmsSender()
    return UnavailableSmsSender("sms delivery is not configured")


class _Redirect(Exception):
    def __init__(self, url: str):
        self.url = url


class _ManualRedirect(urllib.request.HTTPRedirectHandler):
    """Surface the next URL instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _Redirect(newurl)


class HttpProfileFetcher:
    """Fetch the public profile text for a username on a known platform.

    Redirects stay on the same hostname and never drop from https to http.
    A total deadline covers every hop, not only one socket timeout.
    Path-like usernames are rejected.
    """

    def __init__(self, *, deadline_s: float = 20):
        self.deadline_s = deadline_s

    def supports(self, platform: str) -> bool:
        return platform in PLATFORM_URLS

    def fetch_text(self, platform: str, username: str) -> str:
        template = PLATFORM_URLS.get(platform)
        if not template or not profile_username_ok(username):
            raise DeliveryError("could not fetch the public profile")
        url = template.format(username=quote(username, safe=""))
        return self._fetch_limited(url)

    def _fetch_limited(self, url: str) -> str:
        deadline = time.monotonic() + self.deadline_s
        opener = urllib.request.build_opener(_ManualRedirect)
        current = url
        hops = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeliveryError("could not fetch the public profile")
            request = urllib.request.Request(
                current,
                headers={"Accept": "application/json, text/html;q=0.9", "User-Agent": USER_AGENT},
            )
            try:
                with opener.open(request, timeout=remaining) as response:
                    raw = response.read(65537)
                return raw[:65536].decode("utf-8", "replace")
            except _Redirect as hop:
                hops += 1
                if hops > _MAX_REDIRECTS or not _redirect_allowed(current, hop.url):
                    raise DeliveryError("could not fetch the public profile") from None
                current = hop.url
            except DeliveryError:
                raise
            except Exception:
                raise DeliveryError("could not fetch the public profile") from None


def profile_username_ok(username: str) -> bool:
    """False for empty, dotted, or path-like usernames."""
    if not isinstance(username, str) or not username or username in {".", ".."}:
        return False
    if username.startswith(".") or ".." in username:
        return False
    return not any(ch in username for ch in "/\\%\r\n?# \t")


def mask_identifier(identifier_type: str, value: str) -> str:
    if identifier_type == "email":
        return mask_email(value)
    if identifier_type == "phone":
        return mask_phone(value)
    return mask_username(value)


def mask_email(address: str) -> str:
    local, sep, domain = address.partition("@")
    if not sep or not local:
        return "•••"
    return local[0] + "•••@" + domain


def mask_phone(number: str) -> str:
    """Keep a short prefix and the last two digits. The full number is not a substring."""
    if not isinstance(number, str) or len(number) <= 4:
        return "•" * max(len(number) if isinstance(number, str) else 1, 1)
    return number[:2] + ("•" * (len(number) - 4)) + number[-2:]


def mask_username(name: str) -> str:
    if not name:
        return "•"
    if len(name) <= 2:
        return name[0] + "•"
    return name[0] + ("•" * (len(name) - 2)) + name[-1]


def _same_hostname(left: str, right: str) -> bool:
    a = (urllib.parse.urlparse(left).hostname or "").casefold()
    b = (urllib.parse.urlparse(right).hostname or "").casefold()
    return bool(a) and a == b


def _redirect_allowed(current: str, nxt: str) -> bool:
    """Same hostname only, and never from https down to http."""
    if not _same_hostname(current, nxt):
        return False
    left = urllib.parse.urlparse(current).scheme
    right = urllib.parse.urlparse(nxt).scheme
    if right not in ("http", "https"):
        return False
    return not (left == "https" and right == "http")


class OAuthProvider:
    """Pluggable proof that someone can sign in as a username.

    ``authorization_url`` must not include the client secret. ``identity``
    exchanges an authorization code and returns the username the provider
    reports. Implementations read secrets from the environment.
    """

    name = ""

    def authorization_url(self, *, state: str, redirect_uri: str) -> str:
        raise NotImplementedError

    def identity(self, *, code: str, redirect_uri: str) -> str:
        raise NotImplementedError


class EnvOAuthProvider(OAuthProvider):
    """One OAuth provider whose endpoints and secrets come from the environment.

    ``CASEFILE_OAUTH_<NAME>_CLIENT_ID``, ``_CLIENT_SECRET``, ``_AUTHORIZE_URL``,
    ``_TOKEN_URL``, ``_USERINFO_URL`` and optional ``_USER_FIELD`` (default
    ``login``). ``<NAME>`` is the provider id in upper case, so ``github``
    reads ``CASEFILE_OAUTH_GITHUB_*``.
    """

    def __init__(self, name: str):
        self.name = name
        prefix = "CASEFILE_OAUTH_" + name.upper().replace("-", "_") + "_"
        self._client_id = os.environ.get(prefix + "CLIENT_ID", "")
        self._client_secret = os.environ.get(prefix + "CLIENT_SECRET", "")
        self._authorize = os.environ.get(prefix + "AUTHORIZE_URL", "")
        self._token = os.environ.get(prefix + "TOKEN_URL", "")
        self._userinfo = os.environ.get(prefix + "USERINFO_URL", "")
        self._user_field = os.environ.get(prefix + "USER_FIELD", "login") or "login"
        if not all([self._client_id, self._client_secret, self._authorize, self._token, self._userinfo]):
            raise ValueError("incomplete oauth provider configuration")

    def authorization_url(self, *, state: str, redirect_uri: str) -> str:
        query = urllib.parse.urlencode(
            {
                "client_id": self._client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "response_type": "code",
            }
        )
        return f"{self._authorize}?{query}"

    def identity(self, *, code: str, redirect_uri: str) -> str:
        form = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
        ).encode()
        token_request = urllib.request.Request(self._token, data=form, method="POST")
        try:
            with urllib.request.urlopen(token_request, timeout=20) as response:
                token = json.loads(response.read(65536).decode("utf-8"))
        except (urllib.error.URLError, ValueError, json.JSONDecodeError):
            raise DeliveryError("oauth sign-in was not accepted") from None
        access = token.get("access_token") if isinstance(token, dict) else None
        if not isinstance(access, str) or not access:
            raise DeliveryError("oauth sign-in was not accepted")
        user_request = urllib.request.Request(
            self._userinfo,
            headers={"Authorization": f"Bearer {access}", "Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(user_request, timeout=20) as response:
                profile = json.loads(response.read(65536).decode("utf-8"))
        except (urllib.error.URLError, ValueError, json.JSONDecodeError):
            raise DeliveryError("oauth sign-in was not accepted") from None
        if not isinstance(profile, dict) or not profile.get(self._user_field):
            raise DeliveryError("oauth sign-in was not accepted")
        return str(profile[self._user_field])


class OAuthRegistry:
    def __init__(self, providers: list[OAuthProvider] | None = None, *, redirect_uri: str = ""):
        self._providers = {provider.name: provider for provider in providers or []}
        self.redirect_uri = redirect_uri

    def get(self, name: str) -> OAuthProvider | None:
        return self._providers.get(name)


def oauth_from_env() -> OAuthRegistry:
    redirect = os.environ.get("CASEFILE_OAUTH_REDIRECT_URI", "").strip()
    providers: list[OAuthProvider] = []
    for name in os.environ.get("CASEFILE_OAUTH_PROVIDERS", "").split(","):
        name = name.strip().lower()
        if not name:
            continue
        try:
            providers.append(EnvOAuthProvider(name))
        except ValueError:
            continue
    return OAuthRegistry(providers, redirect_uri=redirect)
