"""Leurre HTTP — site vitrine WordPress d'une entreprise fictive (voir ``site.py``).

Les adresses connues de WordPress répondent comme WordPress, le reste reçoit une vraie
404 : un serveur qui sert la même page partout se trahit. Chaque requête, quelle qu'elle
soit, devient un événement.

Aucune donnée reçue n'est réinjectée dans la réponse : la page ne dépend que de la
méthode et du chemin. Un leurre qui renverrait la saisie de l'attaquant serait
vulnérable au XSS réfléchi, ce qui serait à la fois ridicule et dangereux.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from email.utils import formatdate
from urllib.parse import parse_qs, unquote_plus

from shield.common.schema import ServiceName
from shield.decoys import site
from shield.decoys.base import DecoyService

#: Signature de version annoncée par défaut : un nginx et un PHP anciens, alléchants.
DEFAULT_SERVER = "nginx/1.18.0"
POWERED_BY = "PHP/7.4.33"

#: Champs d'identifiants reconnus : WordPress (``log``/``pwd``) et formulaires génériques.
_USER_FIELDS = ("log", "username", "user", "login", "email")
_PASSWORD_FIELDS = ("pwd", "password", "pass", "passwd")

#: Chaînes d'un appel XML-RPC : ``wp.getUsersBlogs(identifiant, mot de passe)``.
_XMLRPC_STRING = re.compile(r"<string>([^<]{0,255})</string>")

_WORDPRESS_LINK = ("Link", '</wp-json/>; rel="https://api.w.org/"')
_TEST_COOKIE = ("Set-Cookie", "wordpress_test_cookie=WP%20Cookie%20check; path=/; HttpOnly")


class HTTPDecoy(DecoyService):
    service = ServiceName.HTTP

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        payload = await self.read_some(reader)
        request = self.parse_request(payload)

        response = self.render(request.get("method", "GET"), request.get("path", "/"))
        writer.write(response)
        await writer.drain()

        event = self.build_raw_event(
            writer=writer,
            username=request.get("username", ""),
            password=request.get("password", ""),
            payload=payload,
        )
        await self.emit(event)

    def render(self, method: str, path: str) -> bytes:
        """Réponse complète, en octets. Ne dépend que de la méthode et du chemin."""
        page = site.route(method, path)
        body = b"" if method.upper() == "HEAD" else page.body.encode("utf-8")
        headers = [
            ("Server", self.banner or DEFAULT_SERVER),
            ("Date", formatdate(usegmt=True)),
            ("Content-Type", page.content_type),
            ("Content-Length", str(len(page.body.encode("utf-8")))),
            ("Connection", "close"),
            ("X-Powered-By", POWERED_BY),
        ]
        if page.content_type == site.HTML:
            headers.append(_WORDPRESS_LINK)
        if path.split("?", 1)[0] == "/wp-login.php":
            headers.append(_TEST_COOKIE)
        headers.extend(page.headers)
        head = f"HTTP/1.1 {page.status}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
        # latin-1 : l'encodage des en-têtes HTTP ; « replace » protège d'une bannière exotique.
        return (head + "\r\n").encode("latin-1", errors="replace") + body

    def serve_login_page(self) -> bytes:
        return site.login_page().encode()

    @staticmethod
    def parse_request(payload: bytes) -> dict[str, str]:
        """Analyse minimale d'une requête HTTP. Ne lève jamais sur une entrée malformée."""
        result: dict[str, str] = {}
        if not payload:
            return result
        text = payload.decode("utf-8", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        if lines:
            parts = lines[0].split(" ")
            if parts:
                result["method"] = parts[0][:10]
            if len(parts) > 1:
                result["path"] = parts[1][:200]
        for line in lines[1:]:
            name, _, value = line.partition(":")
            name = name.strip().lower()
            if name == "user-agent":
                result["user_agent"] = value.strip()[:255]
            elif name == "authorization":
                result.update(_basic_credentials(value.strip()))
        if body:
            result.update(_body_credentials(body))
        return result


def _first(fields: dict[str, list[str]], names: tuple[str, ...]) -> str | None:
    for name in names:
        if name in fields:
            return unquote_plus(fields[name][0])[:255]
    return None


def _body_credentials(body: str) -> dict[str, str]:
    """Identifiants d'un formulaire, ou d'un appel XML-RPC (force brute ``xmlrpc.php``)."""
    if body.lstrip().startswith("<?xml") or "<methodCall>" in body:
        strings = _XMLRPC_STRING.findall(body[:8192])
        if len(strings) >= 2:
            return {"username": strings[0], "password": strings[1]}
        return {}
    fields = parse_qs(body, keep_blank_values=True)
    found: dict[str, str] = {}
    username = _first(fields, _USER_FIELDS)
    password = _first(fields, _PASSWORD_FIELDS)
    if username is not None:
        found["username"] = username
    if password is not None:
        found["password"] = password
    return found


def _basic_credentials(value: str) -> dict[str, str]:
    """``Authorization: Basic …`` : des robots l'essaient sur toute page d'administration."""
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "basic":
        return {}
    try:
        decoded = base64.b64decode(token.strip()[:1024], validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return {}
    username, sep, password = decoded.partition(":")
    return {"username": username[:255], "password": password[:255]} if sep else {}
