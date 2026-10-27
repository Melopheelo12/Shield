"""Recette US-09 — aucune réponse réseau ne doit trahir le honeypot.

Sonde les trois leurres avec des requêtes ordinaires, des méthodes et chemins
inhabituels et des octets parasites, puis cherche dans toutes les réponses un mot
qui révélerait la nature du service ou sa pile technique.

Certains chemins portent un marqueur unique : s'il revient dans une réponse, le leurre
réinjecte ce qu'envoie le visiteur, ce que ses règles interdisent (US-50).

    python scripts/qa/identity_leaks.py --host 127.0.0.1 --ssh 2222 --http 8080 --ftp 2121

Code de sortie = nombre de fuites et de réinjections.
"""

from __future__ import annotations

import argparse
import re
import socket
import time

LEAK = re.compile(
    rb"shield|honeypot|honey|decoy|leurre|python|uvicorn|asyncio|traceback", re.IGNORECASE
)

#: Ne contient aucun mot de ``LEAK`` : seule sa réapparition compte.
MARKER = b"qa7f3c1e"

HTTP_METHODS = (b"GET", b"HEAD", b"OPTIONS", b"PUT", b"TRACE", b"FOO")
HTTP_PATHS = (
    b"/",
    b"/admin",
    b"/does-not-exist",
    b"/../../etc/passwd",
    b"/.env",
    b"/" + MARKER,
    # Faux système de fichiers du leurre HTTP (US-50) : ses chemins, puis un fichier et un
    # dossier inconnus qui portent le marqueur.
    b"/wp-config.php.bak",
    b"/backup",
    b"/backup/",
    b"/backup/" + MARKER + b".sql.gz",
    b"/wp-content/uploads/",
    b"/wp-content/uploads/2023/",
    b"/wp-content/uploads/" + MARKER + b"/",
)

PROBES: dict[str, list[tuple[bytes, ...]]] = {
    "ssh": [(), (b"SSH-2.0-OpenSSH_9.6\r\n",), (b"root:root\r\n",), (b"\x00" * 64,)],
    "http": [
        (method + b" " + path + b" HTTP/1.1\r\nHost: x\r\n\r\n",)
        for method in HTTP_METHODS
        for path in HTTP_PATHS
    ]
    + [(b"garbage\r\n\r\n",), (b"POST /login HTTP/1.1\r\n\r\nusername=a&password=b",)],
    "ftp": [
        (),
        (b"SYST\r\n",),
        (b"HELP\r\n",),
        (b"FEAT\r\n",),
        (b"STAT\r\n",),
        (b"USER anonymous\r\n", b"PASS x\r\n"),
        (b"\xff\xf4\xff\xfd\x06",),
    ],
}


def talk(host: str, port: int, chunks: tuple[bytes, ...]) -> bytes:
    reply = b""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.settimeout(1.5)
            for chunk in (b"", *chunks):
                if chunk:
                    sock.sendall(chunk)
                    time.sleep(0.3)
                try:
                    reply += sock.recv(65_536)
                except (TimeoutError, OSError):
                    pass
    except OSError:
        pass
    return reply


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--ssh", type=int, default=2222)
    parser.add_argument("--http", type=int, default=8080)
    parser.add_argument("--ftp", type=int, default=2121)
    args = parser.parse_args()
    ports = {"ssh": args.ssh, "http": args.http, "ftp": args.ftp}

    total, leaks, echoes, silent = 0, 0, 0, 0
    for service, probes in PROBES.items():
        for chunks in probes:
            reply = talk(args.host, ports[service], chunks)
            total += 1
            silent += int(not reply)
            for match in LEAK.finditer(reply):
                leaks += 1
                context = reply[max(0, match.start() - 40) : match.end() + 40]
                print(f"FUITE {service} {chunks[:1]!r} → …{context!r}…")
            if MARKER in reply:
                echoes += 1
                print(f"RÉINJECTION {service} {chunks[:1]!r} → le marqueur revient dans la réponse")

    print(f"{total} sondes, {leaks} fuite(s), {echoes} réinjection(s), {silent} sans réponse")
    if silent == total:
        print("ÉCART aucun leurre n'a répondu : vérifiez l'hôte et les ports")
        return 1
    return leaks + echoes


if __name__ == "__main__":
    raise SystemExit(main())
