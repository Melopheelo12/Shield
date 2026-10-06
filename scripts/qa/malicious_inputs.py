"""Recette US-01 / US-05 — entrées malveillantes contre les leurres et le collecteur.

Envoie aux trois leurres du binaire, de l'UTF-8 invalide, des injections SQL et XSS,
des chaînes très longues et des octets NUL ; puis bombarde directement l'API
d'ingestion. Critères : rien n'est reflété ni interprété, tout est stocké inerte,
aucune tentative n'est perdue, aucun service ne tombe, jamais de 5xx.

    python scripts/qa/malicious_inputs.py --api http://localhost:8000

Les leurres doivent pointer vers le même collecteur. Code de sortie = nombre d'écarts.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import time

import httpx

XSS = "<script>alert(document.cookie)</script>"
SQLI = "admin' OR '1'='1'; DROP TABLE events;--"
LONG = "A" * 100_000
BINARY = bytes(range(256)) * 4
BAD_UTF8 = b"\xff\xfe\xc3\x28\xa0\xa1\xe2\x28\xa1\xf0\x28\x8c\xbc"
NUL = b"root\x00evil"

CASES: dict[str, list[tuple]] = {
    "ssh": [
        ("xss", XSS.encode() + b":x"),
        ("sqli", b"admin:" + SQLI.replace(" ", "").encode()),
        ("binaire", BINARY),
        ("utf8 invalide", BAD_UTF8 + b":" + BAD_UTF8),
        ("très long", LONG.encode()),
        ("NUL", NUL + b":pw"),
    ],
    "http": [
        ("xss", f"POST /login HTTP/1.1\r\nHost: x\r\n\r\nusername={XSS}&password=x".encode()),
        ("sqli", f"GET /index.php?id={SQLI} HTTP/1.1\r\nHost: x\r\n\r\n".encode()),
        ("binaire", BINARY),
        ("utf8 invalide", b"POST /login HTTP/1.1\r\n\r\nusername=" + BAD_UTF8),
        ("très long", b"GET /" + LONG.encode() + b" HTTP/1.1\r\n\r\n"),
        ("NUL", b"POST /login HTTP/1.1\r\n\r\nusername=root%00evil&password=x"),
    ],
    "ftp": [
        ("xss", b"USER " + XSS.encode() + b"\r\n", b"PASS x\r\n"),
        ("sqli", b"USER " + SQLI.encode() + b"\r\n", b"PASS x\r\n"),
        ("binaire", BINARY[:1000]),
        ("utf8 invalide", b"USER " + BAD_UTF8 + b"\r\n", b"PASS " + BAD_UTF8 + b"\r\n"),
        ("très long", b"USER " + LONG.encode()[:1000] + b"\r\n"),
        ("NUL", b"USER " + NUL + b"\r\n", b"PASS x\r\n"),
        ("pipeline USER+PASS", b"USER bob\r\nPASS secret\r\n"),
    ],
}


class Report:
    def __init__(self) -> None:
        self.gaps = 0

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.gaps += int(not ok)
        suffix = f"  [{detail}]" if detail and not ok else ""
        print(f"{'OK   ' if ok else 'ÉCART'} {name}{suffix}")


def talk(host: str, port: int, *chunks: bytes) -> bytes:
    """Dialogue TCP brut : lit la bannière, envoie chaque morceau, accumule les réponses."""
    reply = b""
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
    return reply


def alive(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=2).close()
        return True
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--token", default="dev-token", help="jeton d'ingestion")
    parser.add_argument("--host", default="127.0.0.1", help="hôte des leurres")
    parser.add_argument("--ssh", type=int, default=2222)
    parser.add_argument("--http", type=int, default=8080)
    parser.add_argument("--ftp", type=int, default=2121)
    args = parser.parse_args()
    ports = {"ssh": args.ssh, "http": args.http, "ftp": args.ftp}
    report = Report()

    def count() -> int:
        return int(httpx.get(f"{args.api}/api/v1/stats/overview").json()["events"])

    # -------------------------------------------------------------- leurres
    before, sent = count(), 0
    for service, cases in CASES.items():
        for name, *chunks in cases:
            try:
                reply = talk(args.host, ports[service], *chunks)
            except OSError as error:
                report.check(f"{service} {name} : connexion", False, str(error))
                continue
            sent += 1
            reflected = XSS.encode() in reply or b"DROP TABLE" in reply
            report.check(f"{service} {name} : l'entrée n'est pas reflétée", not reflected)

    time.sleep(1.5)
    stored = count() - before
    # Sondé APRÈS le comptage : une connexion de vérification est aussi une tentative.
    for service, port in ports.items():
        report.check(f"{service} : leurre toujours vivant", alive(args.host, port))
    report.check(
        f"{sent} tentatives → {stored} événements stockés", stored == sent, f"attendu {sent}"
    )

    recent = httpx.get(f"{args.api}/api/v1/events", params={"limit": max(stored, 1)}).json()
    events = recent["items"]
    report.check("XSS stocké tel quel (chaîne inerte)", any(XSS in e["username"] for e in events))
    report.check(
        "identifiants ≤ 255 caractères",
        all(len(e["username"]) <= 255 and len(e["password"]) <= 255 for e in events),
    )
    report.check(
        "charges ≤ 4 096 octets, troncature signalée",
        all(len(base64.b64decode(e["payload"])) <= 4096 for e in events)
        and any(e["payload_truncated"] for e in events),
    )
    piped = next((e for e in events if e["service"] == "ftp" and "bob" in e["username"]), None)
    report.check(
        "FTP USER+PASS dans un même paquet → identifiants séparés (#53)",
        piped is not None and (piped["username"], piped["password"]) == ("bob", "secret"),
        f"obtenu {piped['username']!r} / {piped['password']!r}" if piped else "absent",
    )
    with_nul = [e for e in events if "\x00" in e["username"] + e["password"]]
    report.check(
        "aucun octet NUL dans les champs texte", not with_nul, f"{len(with_nul)} événement(s)"
    )

    # ----------------------------------------------------------- collecteur
    headers = {"X-Ingest-Token": args.token, "Content-Type": "application/json"}
    base = {"service": "ssh", "source_ip": "192.0.2.10", "source_port": 1234, "dest_port": 22}
    probes = {
        "JSON avec UTF-8 invalide": b'{"service":"ssh","source_ip":"192.0.2.10",'
        b'"source_port":1,"dest_port":22,"username":"\xff\xfe"}',
        "JSON tronqué": b'{"service":"ssh",',
        "chaîne de 1 Mo": json.dumps({**base, "username": "A" * 1_000_000}).encode(),
        "charge base64 de 5 Mo": json.dumps(
            {**base, "payload": base64.b64encode(b"\x00" * 5_000_000).decode()}
        ).encode(),
        "IP malformée": json.dumps({**base, "source_ip": "1.2.3.4'; DROP TABLE--"}).encode(),
        "port hors bornes": json.dumps({**base, "source_port": 99_999}).encode(),
        "service inconnu": json.dumps({**base, "service": "telnet"}).encode(),
        "JSON très imbriqué (#54)": b'{"username":' + b"[" * 50_000 + b"]" * 50_000 + b"}",
    }
    for name, body in probes.items():
        try:
            status = httpx.post(f"{args.api}/api/v1/ingest", content=body, headers=headers)
            code = status.status_code
            report.check(f"collecteur, {name} : pas de 5xx", code < 500, f"HTTP {code}")
        except httpx.HTTPError as error:
            report.check(f"collecteur, {name} : pas de 5xx", False, repr(error))

    health = httpx.get(f"{args.api}/api/v1/health").status_code
    report.check("collecteur toujours vivant", health == 200)
    anonymous = httpx.post(f"{args.api}/api/v1/ingest", json=base).status_code
    report.check("ingestion sans jeton → 401", anonymous == 401, f"HTTP {anonymous}")

    print(f"\n{report.gaps} écart(s)")
    return report.gaps


if __name__ == "__main__":
    raise SystemExit(main())
