"""Alertes (S4-01, S4-03, S4-10) : exactement une alerte par franchissement, canaux isolés."""

import json
import ssl
from ipaddress import ip_address

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from shield.collector.alerts import AlertManager, AlertService, Metric, Notifier, Threshold
from shield.collector.alerts.channels import (
    DiscordChannel,
    DiscordError,
    EmailChannel,
    overall_status,
)
from shield.collector.alerts.manager import filtered_view_url
from shield.collector.api import app as api
from shield.collector.api.auth import create_access_token
from shield.collector.repositories import InMemoryEventRepository
from shield.common.schema import NormalizedEvent, ServiceName


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


def event(ip="203.0.113.1", score=0):
    return NormalizedEvent(
        service=ServiceName.SSH,
        source_ip=ip_address(ip),
        source_port=1,
        dest_port=22,
        threat_score=score,
    )


VOLUME = Threshold("volume", Metric.EVENTS, threshold=3, window_seconds=60, silence_seconds=0)


def manager_with(*thresholds, clock):
    return AlertManager(thresholds=list(thresholds), clock=clock)


# --------------------------------------------------------------------------- unicité (S4-03)


def test_un_franchissement_prolonge_donne_exactement_une_alerte():
    clock = Clock()
    manager = manager_with(VOLUME, clock=clock)
    notices = []
    for _ in range(50):  # largement au-dessus du seuil, longtemps
        notices += manager.observe(event())
        clock.now += 0.5
        notices += manager.evaluate()
    assert len(notices) == 1
    assert notices[0].value == 3


def test_redescendre_sous_le_seuil_rearme():
    clock = Clock()
    manager = manager_with(VOLUME, clock=clock)
    first = [n for _ in range(3) for n in manager.observe(event())]
    assert len(first) == 1

    clock.now += 61  # la fenêtre se vide : la mesure repasse sous le seuil
    assert manager.evaluate() == []

    second = [n for _ in range(3) for n in manager.observe(event())]
    assert len(second) == 1, "nouveau franchissement, nouvelle alerte"


def test_la_periode_de_silence_absorbe_les_oscillations():
    clock = Clock()
    silent = Threshold("volume", Metric.EVENTS, threshold=3, window_seconds=60, silence_seconds=600)
    manager = manager_with(silent, clock=clock)
    alerts = 0
    for _ in range(5):  # cinq franchissements en moins de 10 minutes
        alerts += len([n for _ in range(3) for n in manager.observe(event())])
        clock.now += 61
        manager.evaluate()
    assert alerts == 1

    clock.now += 600
    alerts += len([n for _ in range(3) for n in manager.observe(event())])
    assert alerts == 2, "silence écoulé : on alerte de nouveau"


def test_mesures():
    clock = Clock()
    manager = manager_with(VOLUME, clock=clock)
    for ip, score in (("203.0.113.1", 10), ("203.0.113.2", 85), ("203.0.113.1", 40)):
        manager.observe(event(ip, score))
    assert manager.measure(Metric.EVENTS, 60) == 3
    assert manager.measure(Metric.UNIQUE_IPS, 60) == 2
    assert manager.measure(Metric.MAX_THREAT_SCORE, 60) == 85


def test_un_seuil_desactive_ne_declenche_rien():
    clock = Clock()
    off = Threshold("volume", Metric.EVENTS, threshold=1, enabled=False)
    manager = manager_with(off, clock=clock)
    assert manager.observe(event()) == []


def test_reconfigurer_un_seuil_le_rearme():
    clock = Clock()
    manager = manager_with(VOLUME, clock=clock)
    assert len([n for _ in range(3) for n in manager.observe(event())]) == 1
    manager.configure([Threshold("volume", Metric.EVENTS, threshold=4, window_seconds=60)])
    assert len(manager.observe(event())) == 1


@pytest.mark.parametrize(
    "data",
    [
        {"id": "x", "metric": "inconnue", "threshold": 1},
        {"id": "x", "metric": "events", "threshold": 0},
        {"id": "x", "metric": "events", "threshold": 1, "window_seconds": 0},
        {"id": "x", "metric": "events", "threshold": 1, "silence_seconds": -1},
        {"metric": "events", "threshold": 1},
    ],
)
def test_un_seuil_invalide_est_refuse(data):
    with pytest.raises((KeyError, ValueError)):
        Threshold.from_dict(data)


@pytest.mark.parametrize(
    "window,period",
    [(60, "1h"), (3_600, "1h"), (3_601, "24h"), (86_400, "24h")],  # fenêtre ≤ 24 h
)
def test_le_lien_mene_au_journal_filtre_sur_une_periode_connue_du_front(window, period):
    """#95 : seuls ``?periode=`` et ``#/journal`` sont compris par le tableau de bord."""
    threshold = Threshold("critique", Metric.MAX_THREAT_SCORE, threshold=80, window_seconds=window)
    url = filtered_view_url("https://shield.example/", threshold)
    assert url == f"https://shield.example/?periode={period}#/journal"


# --------------------------------------------------------------------------- canaux


class FailingChannel:
    name = "panne"

    async def send(self, notice):
        raise ConnectionError("injoignable")


class RecordingChannel:
    name = "trace"

    def __init__(self):
        self.sent = []

    async def send(self, notice):
        self.sent.append(notice)


async def test_un_canal_en_panne_ne_bloque_pas_les_autres():
    recording = RecordingChannel()
    notifier = Notifier([FailingChannel(), recording])
    notice = AlertManager().test_notice()
    results = await notifier.send(notice)
    assert results == {"panne": "failed", "trace": "sent"}
    assert recording.sent == [notice]
    assert overall_status(results) == "sent"
    assert overall_status({"panne": "failed"}) == "failed"
    assert overall_status({}) == "logged"


async def test_le_message_discord_contient_regle_valeur_et_lien():
    captured = {}

    def handler(request):
        captured.update(json.loads(request.content))
        return httpx.Response(204)

    channel = DiscordChannel(
        "https://discord.example/webhook",
        "https://shield.example:8443",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    notice = manager_with(VOLUME, clock=Clock())
    [alert] = [n for _ in range(3) for n in notice.observe(event())]
    await channel.send(alert)

    assert "volume" in captured["content"]
    assert "3" in captured["content"]
    assert "https://shield.example:8443/?periode=1h#/journal" in captured["content"]
    assert captured["allowed_mentions"] == {"parse": []}, "jamais de @everyone"


async def test_un_webhook_refuse_est_un_echec():
    channel = DiscordChannel(
        "https://discord.example/webhook",
        "https://x",
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))),
    )
    with pytest.raises(DiscordError):
        await channel.send(AlertManager().test_notice())


async def test_un_webhook_refuse_ne_met_pas_son_jeton_dans_les_journaux(caplog):
    """Les journaux du collecteur se collent dans une issue : le jeton n'y va jamais."""
    channel = DiscordChannel(
        "https://discord.example/api/webhooks/123/jeton-secret",
        "https://x",
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))),
    )
    results = await Notifier([channel]).send(AlertManager().test_notice())

    assert results == {"discord": "failed"}
    assert "HTTP 404" in caplog.text
    assert "jeton-secret" not in caplog.text


async def test_le_courriel_verifie_le_certificat_du_serveur(monkeypatch):
    contexts = []

    class FakeSmtp:
        def __init__(self, host, port, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            contexts.append(context)

        def send_message(self, message):
            pass

    monkeypatch.setattr("shield.collector.alerts.channels.smtplib.SMTP", FakeSmtp)
    channel = EmailChannel("smtp.example", 587, "shield@x", "ops@x", "https://x")
    await channel.send(AlertManager().test_notice())

    [context] = contexts
    assert context is not None, "sans contexte, smtplib ne vérifie rien"
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


async def test_le_courriel_part_au_destinataire_configure(monkeypatch):
    sent = []

    class FakeSmtp:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("smtp.example", 587)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            pass

        def login(self, user, password):
            assert (user, password) == ("u", "p")

        def send_message(self, message):
            sent.append(message)

    monkeypatch.setattr("shield.collector.alerts.channels.smtplib.SMTP", FakeSmtp)
    channel = EmailChannel("smtp.example", 587, "shield@x", "ops@x", "https://x", "u", "p")
    await channel.send(AlertManager().test_notice())
    [message] = sent
    assert message["To"] == "ops@x"
    assert message["Subject"].startswith("[TEST]")


# --------------------------------------------------------------------------- service


async def test_chaque_alerte_est_tracee_avec_le_resultat_des_canaux():
    repo = InMemoryEventRepository()
    service = AlertService(manager_with(VOLUME, clock=Clock()), Notifier([FailingChannel()]))
    await service.load(repo)
    assert await repo.load_alert_thresholds(), "instance neuve : seuils par défaut écrits"

    service.manager.configure([VOLUME])
    for _ in range(3):
        service.observe(event())
    notice = service.queue.get_nowait()
    await service.deliver(repo, notice)

    [alert] = await repo.recent_alerts()
    assert alert["threshold_id"] == "volume"
    assert alert["status"] == "failed"
    assert alert["channels"] == {"panne": "failed"}


async def test_les_seuils_enregistres_sont_recharges():
    repo = InMemoryEventRepository()
    await repo.save_alert_thresholds([VOLUME.to_dict()])
    service = AlertService(AlertManager(), Notifier([]))
    await service.load(repo)
    assert service.manager.thresholds == [VOLUME]


# --------------------------------------------------------------------------- API


@pytest.fixture
async def client(monkeypatch):
    recording = RecordingChannel()
    monkeypatch.setattr(api, "alerts", AlertService(AlertManager(), Notifier([recording])))
    api.app.state.repository = InMemoryEventRepository()
    token, _ = create_access_token("admin")
    async with AsyncClient(
        transport=ASGITransport(app=api.app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as http:
        http.recording = recording
        yield http
    del api.app.state.repository


async def test_configuration_des_seuils_par_l_api(client):
    body = {"items": [VOLUME.to_dict()]}
    response = await client.put("/api/v1/alerts/thresholds", json=body)
    assert response.status_code == 200
    assert response.json()["items"] == [VOLUME.to_dict()]
    assert response.json()["channels"] == ["trace"]
    assert api.app.state.repository.alert_thresholds == [VOLUME.to_dict()]


@pytest.mark.parametrize(
    "items",
    [
        [{"id": "x", "metric": "inconnue", "threshold": 1}],
        [VOLUME.to_dict(), VOLUME.to_dict()],
    ],
)
async def test_une_configuration_invalide_est_refusee(client, items):
    response = await client.put("/api/v1/alerts/thresholds", json={"items": items})
    assert response.status_code == 422


async def test_le_bouton_tester(client):
    response = await client.post("/api/v1/alerts/test")
    assert response.json() == {"channels": {"trace": "sent"}}
    [notice] = client.recording.sent
    assert notice.test


async def test_l_ingestion_alimente_les_seuils(client):
    api.alerts.manager.configure([VOLUME])
    headers = {"X-Ingest-Token": api.INGEST_TOKEN}
    body = {"service": "ssh", "source_ip": "192.0.2.9", "source_port": 1, "dest_port": 22}
    for _ in range(5):
        await client.post("/api/v1/ingest", json=body, headers=headers)
    assert api.alerts.queue.qsize() == 1
