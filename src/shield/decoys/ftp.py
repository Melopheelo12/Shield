"""Leurre FTP — émule la séquence USER / PASS d'un serveur, puis refuse."""

from __future__ import annotations

import asyncio

from shield.common.schema import ServiceName
from shield.decoys.base import DecoyService


class FTPDecoy(DecoyService):
    service = ServiceName.FTP

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(self.greet())
        await writer.drain()

        collected = bytearray()
        username, password = "", ""

        for _ in range(2):
            chunk = await self.read_some(reader, limit=1024)
            if not chunk:
                break
            collected.extend(chunk)
            command, _, argument = chunk.strip().partition(b" ")
            verb = command.upper()
            if verb == b"USER":
                username = argument.decode("utf-8", errors="replace")
                writer.write(b"331 Please specify the password.\r\n")
            elif verb == b"PASS":
                password = argument.decode("utf-8", errors="replace")
                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"530 Please login with USER and PASS.\r\n")
            await writer.drain()

        event = self.build_raw_event(
            writer=writer, username=username, password=password, payload=bytes(collected)
        )
        await self.emit(event)

    def greet(self) -> bytes:
        return f"{self.banner}\r\n".encode()
