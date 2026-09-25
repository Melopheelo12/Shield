"""Leurre HTTP — sert une fausse page d'administration et enregistre les soumissions.

La page est du HTML statique. Aucune donnée reçue n'est réinjectée dans la réponse :
un leurre qui renverrait la saisie de l'attaquant serait vulnérable au XSS réfléchi,
ce qui serait à la fois ridicule et dangereux.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, unquote_plus

from shield.common.schema import ServiceName
from shield.decoys.base import DecoyService

_LOGIN_PAGE = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    "<title>Administration</title></head><body>"
    "<h1>Administration</h1>"
    '<form method="post" action="/login">'
    '<input name="username" placeholder="Username">'
    '<input name="password" type="password" placeholder="Password">'
    '<button type="submit">Sign in</button>'
    "</form></body></html>"
)


class HTTPDecoy(DecoyService):
    service = ServiceName.HTTP

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        payload = await self.read_some(reader)
        request = self.parse_request(payload)

        if request.get("method") == "POST":
            body = _LOGIN_PAGE
            status = "401 Unauthorized"
        else:
            body = _LOGIN_PAGE
            status = "200 OK"

        response = (
            f"HTTP/1.1 {status}\r\n"
            "Server: nginx\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            "Connection: close\r\n\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()

        event = self.build_raw_event(
            writer=writer,
            username=request.get("username", ""),
            password=request.get("password", ""),
            payload=payload,
        )
        await self.emit(event)

    def serve_login_page(self) -> bytes:
        return _LOGIN_PAGE.encode()

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
            if name.strip().lower() == "user-agent":
                result["user_agent"] = value.strip()[:255]
        if body:
            fields = parse_qs(body, keep_blank_values=True)
            if "username" in fields:
                result["username"] = unquote_plus(fields["username"][0])[:255]
            if "password" in fields:
                result["password"] = unquote_plus(fields["password"][0])[:255]
        return result
