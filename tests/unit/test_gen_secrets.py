"""make secrets : des valeurs neuves, qui passent les contrôles de production."""

from urllib.parse import urlsplit

from shield.collector.api import auth
from shield.tools import gen_secrets


def test_les_secrets_generes_passent_les_controles_de_production():
    assert auth.production_secret_problems(gen_secrets.generate()) == []


def test_chaque_appel_tire_de_nouvelles_valeurs():
    first, second = gen_secrets.generate(), gen_secrets.generate()
    assert all(first[key] != second[key] for key in first)


def test_database_url_reprend_le_mot_de_passe_postgres():
    values = gen_secrets.generate()
    url = urlsplit(values["DATABASE_URL"])
    assert url.password == values["POSTGRES_PASSWORD"]
    assert (url.username, url.hostname, url.path) == ("shield", "postgres", "/shield")


def test_la_sortie_est_un_env_valide(capsys):
    assert gen_secrets.main() == 0
    lines = [line for line in capsys.readouterr().out.splitlines() if not line.startswith("#")]
    keys = [line.split("=", 1)[0] for line in lines]
    assert keys[0] == "SHIELD_ENV" and "SHIELD_ENV=prod" in lines
    assert {"ADMIN_USERNAME", "ADMIN_PASSWORD", "JWT_SECRET", "DATABASE_URL"} <= set(keys)
    assert all(" " not in line for line in lines)
