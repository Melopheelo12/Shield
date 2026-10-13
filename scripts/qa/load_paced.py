"""Recette US-01 — test de charge cadencé sur l'horloge.

Contrairement à ``make load`` (voir #55), chaque envoi est planifié à ``t0 + i / rate`` :
la latence du collecteur ne ralentit pas l'injection, on mesure donc vraiment la
tenue à 50 événements par seconde.

    python scripts/qa/load_paced.py --count 3000 --rate 50

Code de sortie non nul si un envoi échoue ou si la durée dépasse la cible de 10 %.
Le comptage en base se fait ensuite avec ``/api/v1/stats/overview`` ou ``psql``.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time

import httpx

from shield.tools.fake_events import make_event


async def run(url: str, token: str, count: int, rate: float, seed: int) -> int:
    rng = random.Random(seed)  # noqa: S311 - jeu reproductible, pas de cryptographie
    events = [make_event(rng).model_dump(mode="json") for _ in range(count)]
    latencies: list[float] = []
    failures = 0

    limits = httpx.Limits(max_connections=200)
    async with httpx.AsyncClient(timeout=10.0, limits=limits) as client:
        start = time.perf_counter()

        async def send(index: int, body: dict[str, object]) -> None:
            nonlocal failures
            await asyncio.sleep(max(0.0, start + index / rate - time.perf_counter()))
            sent_at = time.perf_counter()
            try:
                response = await client.post(url, json=body, headers={"X-Ingest-Token": token})
                failures += int(response.status_code >= 400)
            except httpx.HTTPError:
                failures += 1
            latencies.append((time.perf_counter() - sent_at) * 1000)

        await asyncio.gather(*(send(i, body) for i, body in enumerate(events)))
        duration = time.perf_counter() - start

    latencies.sort()
    p95 = latencies[int(0.95 * (len(latencies) - 1))]
    print(
        f"envoyés={count} échecs={failures} durée={duration:.1f}s "
        f"latence p50={statistics.median(latencies):.1f}ms p95={p95:.1f}ms "
        f"max={latencies[-1]:.1f}ms"
    )
    target = count / rate
    return 0 if failures == 0 and duration <= target * 1.1 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://localhost:8000/api/v1/ingest")
    parser.add_argument("--token", default="dev-token")
    parser.add_argument("--count", type=int, default=3000)
    parser.add_argument("--rate", type=float, default=50.0, help="événements par seconde")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    return asyncio.run(run(args.url, args.token, args.count, args.rate, args.seed))


if __name__ == "__main__":
    raise SystemExit(main())
