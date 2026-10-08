"""Point d'entrée des leurres : lance un service et le sert jusqu'à l'arrêt.

python -m shield.decoys.runner ssh
python -m shield.decoys.runner http --port 8080
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os

from shield.decoys import FTPDecoy, HTTPDecoy, SSHDecoy

DECOYS = {"ssh": SSHDecoy, "http": HTTPDecoy, "ftp": FTPDecoy}
DEFAULT_PORTS = {"ssh": 22, "http": 80, "ftp": 21}
DEFAULT_BANNERS = {
    "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "ftp": "220 (vsFTPd 3.0.5)",
    "http": "",
}


async def main_async(args: argparse.Namespace) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    decoy = DECOYS[args.service](
        port=args.port,
        ingest_url=os.getenv("COLLECTOR_INGEST_URL", "http://localhost:8000/api/v1/ingest"),
        ingest_token=os.getenv("INGEST_TOKEN", "change-me-ingest-token"),
        banner=args.banner,
        proxy_protocol=args.proxy_protocol,
    )
    try:
        await decoy.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await decoy.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Lance un leurre SHIELD")
    parser.add_argument("service", choices=sorted(DECOYS))
    parser.add_argument("--port", type=int)
    parser.add_argument("--banner")
    parser.add_argument(
        "--proxy-protocol",
        action="store_true",
        default=os.getenv("DECOY_PROXY_PROTOCOL", "").lower() in {"1", "true", "yes"},
        help="attend un en-tête PROXY v1 du relais d'entrée (ADR 008)",
    )
    args = parser.parse_args()
    args.port = args.port or int(
        os.getenv(f"DECOY_{args.service.upper()}_PORT", DEFAULT_PORTS[args.service])
    )
    args.banner = args.banner or os.getenv(
        f"DECOY_{args.service.upper()}_BANNER", DEFAULT_BANNERS[args.service]
    )
    asyncio.run(main_async(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
