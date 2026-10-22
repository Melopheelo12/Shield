"""Export des événements (US-42, S4-06) et pseudonymisation (US-47, S4-04).

Trois règles, toutes testées :

1. **Pseudonymisation** — sur un export pseudonymisé, le dernier octet d'une adresse
   IPv4 est mis à zéro (une IPv6 est tronquée à son /48), et les mots de passe testés
   sont **retirés** : ils sont exclus de toute donnée publiée.
2. **Injection de formule** — les identifiants viennent des attaquants. Une cellule
   CSV commençant par ``=``, ``+``, ``-``, ``@`` (ou une tabulation, un retour) est
   préfixée d'une apostrophe : ouvrir l'export dans un tableur n'exécute rien.
3. **Par lots** — l'export est produit page par page (pagination par curseur) et
   envoyé en flux : la mémoire du collecteur ne dépend pas de la taille de l'export.
   La charge utile brute n'est jamais exportée, seulement son empreinte.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from shield.common.schema import NormalizedEvent

EXPORT_BATCH_SIZE = 1000

COLUMNS = (
    "event_id",
    "occurred_at",
    "service",
    "source_ip",
    "source_port",
    "dest_port",
    "username",
    "password",
    "session_id",
    "country_code",
    "asn",
    "as_org",
    "reputation_score",
    "technique_id",
    "threat_score",
    "payload_sha256",
)
PUBLIC_COLUMNS = tuple(column for column in COLUMNS if column != "password")

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

#: Une page d'export : (curseur après lequel lire, taille) → événements, ordre croissant.
PageFetcher = Callable[[tuple | None, int], Awaitable[list[NormalizedEvent]]]


def pseudonymize_ip(ip: str | IPv4Address | IPv6Address) -> str:
    """``203.0.113.42`` → ``203.0.113.0`` ; une IPv6 est ramenée à son préfixe /48."""
    address = ip_address(str(ip))
    prefix = 24 if address.version == 4 else 48
    return str(ip_network(f"{address}/{prefix}", strict=False).network_address)


def export_row(event: NormalizedEvent, pseudonymize: bool) -> dict[str, object]:
    data = event.model_dump(mode="json")
    row = {column: data.get(column) for column in COLUMNS}
    if pseudonymize:
        row["source_ip"] = pseudonymize_ip(event.source_ip)
        del row["password"]
    return row


def neutralize_formula(value: object) -> object:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


async def iterate_events(fetch_page: PageFetcher) -> AsyncIterator[NormalizedEvent]:
    """Parcourt tout l'export, page par page, sans jamais tout charger."""
    cursor: tuple | None = None
    while True:
        page = await fetch_page(cursor, EXPORT_BATCH_SIZE)
        for event in page:
            yield event
        if len(page) < EXPORT_BATCH_SIZE:
            return
        last = page[-1]
        cursor = (last.occurred_at, last.event_id)


async def csv_stream(fetch_page: PageFetcher, pseudonymize: bool) -> AsyncIterator[str]:
    columns = PUBLIC_COLUMNS if pseudonymize else COLUMNS
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    async for event in iterate_events(fetch_page):
        row = export_row(event, pseudonymize)
        writer.writerow({key: neutralize_formula(value) for key, value in row.items()})
        if buffer.tell() > 64_000:
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
    yield buffer.getvalue()


async def json_stream(fetch_page: PageFetcher, pseudonymize: bool) -> AsyncIterator[str]:
    """Un tableau JSON valide, écrit au fil de l'eau."""
    yield "["
    first = True
    async for event in iterate_events(fetch_page):
        row = json.dumps(export_row(event, pseudonymize), ensure_ascii=False)
        yield row if first else "," + row
        first = False
    yield "]\n"
