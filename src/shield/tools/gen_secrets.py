"""Secrets de production pour le ``.env`` du serveur (``make secrets``).

    make secrets                                   # avec make
    PYTHONPATH=src python3 -m shield.tools.gen_secrets   # sans make ni venv

Affiche des lignes ``CLE=valeur`` à recopier dans ``.env`` : rien n'est écrit sur le
disque ni envoyé ailleurs. Chaque appel tire de nouvelles valeurs (module ``secrets``,
générateur du système). Les valeurs passent les contrôles de
``check_production_secrets`` : le collecteur démarre avec ``SHIELD_ENV=prod``.

Bibliothèque standard seulement, pour tourner sur le serveur avant toute installation.
"""

from __future__ import annotations

import secrets

POSTGRES_USER = "shield"
POSTGRES_DB = "shield"


def generate() -> dict[str, str]:
    postgres_password = secrets.token_urlsafe(32)
    return {
        # Nom imprévisible : un robot n'essaie que admin, root, user…
        "ADMIN_USERNAME": f"op-{secrets.token_hex(4)}",
        "ADMIN_PASSWORD": secrets.token_urlsafe(24),
        "JWT_SECRET": secrets.token_urlsafe(48),
        "INGEST_TOKEN": secrets.token_urlsafe(32),
        "BLOCKLIST_TOKEN": secrets.token_urlsafe(32),
        "POSTGRES_PASSWORD": postgres_password,
        # Même mot de passe que POSTGRES_PASSWORD, sinon le collecteur ne se connecte pas.
        "DATABASE_URL": (
            f"postgresql+asyncpg://{POSTGRES_USER}:{postgres_password}"
            f"@postgres:5432/{POSTGRES_DB}"
        ),
    }


def main() -> int:
    print("# Secrets générés pour le .env de production : à recopier, puis à ranger dans")
    print("# un gestionnaire de mots de passe. Ne les collez jamais dans un message.")
    print("SHIELD_ENV=prod")
    for key, value in generate().items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
