"""Authentification du tableau de bord (US-19, S3-01).

Un seul compte, défini dans l'environnement (``ADMIN_USERNAME`` / ``ADMIN_PASSWORD``) :
SHIELD n'a pas d'utilisateurs, il a un exploitant. Le jeton est un JWT HS256 à courte
durée de vie (``ACCESS_TOKEN_TTL_MINUTES``).

Contre la force brute — ironie d'un honeypot qui se ferait deviner son mot de passe :

* nginx limite déjà ``/auth/login`` à 5 requêtes par minute et par adresse ;
* ici, après **5 échecs** en 15 minutes depuis une même adresse, chaque nouvel essai
  est refusé (429) pendant un délai qui double à chaque échec, plafonné à 15 minutes.
  Pendant ce délai, le mot de passe n'est même pas comparé.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 900.0
FIRST_DELAY_SECONDS = 30.0
MAX_DELAY_SECONDS = 900.0
INSECURE_PREFIX = "change-me"


def _jwt_secret() -> str:
    return os.getenv("JWT_SECRET", "change-me-jwt-secret")


def _ttl() -> timedelta:
    return timedelta(minutes=int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "30")))


def check_production_secrets() -> None:
    """En production, refuser de démarrer avec un secret d'exemple de ``.env.example``."""
    if os.getenv("SHIELD_ENV", "dev") != "prod":
        return
    weak = [
        name
        for name in ("JWT_SECRET", "ADMIN_PASSWORD", "INGEST_TOKEN")
        if os.getenv(name, INSECURE_PREFIX).startswith(INSECURE_PREFIX)
    ]
    if weak or len(_jwt_secret()) < 32:
        raise RuntimeError(
            f"secrets d'exemple ou trop courts en production : {weak or ['JWT_SECRET']}"
        )


# --------------------------------------------------------------------------- jetons


def create_access_token(username: str, now: datetime | None = None) -> tuple[str, int]:
    issued = now or datetime.now(UTC)
    ttl = _ttl()
    claims = {"sub": username, "iat": issued, "exp": issued + ttl}
    return jwt.encode(claims, _jwt_secret(), algorithm=ALGORITHM), int(ttl.total_seconds())


def decode_access_token(token: str) -> str | None:
    """Le nom de l'exploitant, ou ``None`` pour un jeton invalide, expiré ou falsifié."""
    try:
        claims = jwt.decode(token, _jwt_secret(), algorithms=[ALGORITHM])
    except JWTError:
        return None
    subject = claims.get("sub")
    return subject if isinstance(subject, str) and subject else None


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def credentials_are_valid(username: str, password: str) -> bool:
    """Comparaison à temps constant des deux champs, sans court-circuit."""
    expected_user = os.getenv("ADMIN_USERNAME", "admin")
    expected_password = os.getenv("ADMIN_PASSWORD", "")
    if not expected_password:
        return False  # aucun mot de passe configuré : personne n'entre
    user_ok = secrets.compare_digest(_digest(username), _digest(expected_user))
    password_ok = secrets.compare_digest(_digest(password), _digest(expected_password))
    return user_ok and password_ok


# --------------------------------------------------------------------------- limitation


class LoginThrottle:
    """Compte les échecs par adresse et impose un délai croissant au-delà du seuil."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._failures: dict[str, list[float]] = defaultdict(list)

    def _recent(self, key: str) -> list[float]:
        horizon = self._clock() - FAILURE_WINDOW_SECONDS
        recent = [moment for moment in self._failures.get(key, []) if moment > horizon]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def retry_after(self, key: str) -> float:
        """Secondes à attendre avant le prochain essai ; 0 si l'essai est permis."""
        recent = self._recent(key)
        if len(recent) < MAX_FAILURES:
            return 0.0
        delay = min(FIRST_DELAY_SECONDS * 2 ** (len(recent) - MAX_FAILURES), MAX_DELAY_SECONDS)
        return max(recent[-1] + delay - self._clock(), 0.0)

    def failure(self, key: str) -> None:
        self._recent(key)
        self._failures[key].append(self._clock())

    def success(self, key: str) -> None:
        self._failures.pop(key, None)


throttle = LoginThrottle()


def client_address(request: Request) -> str:
    """nginx transmet l'adresse réelle ; le collecteur n'est joignable que par lui."""
    forwarded = request.headers.get("x-real-ip", "").strip()
    if forwarded:
        return forwarded
    return request.client.host if request.client else "inconnue"


# --------------------------------------------------------------------------- routes


class LoginRequest(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - type de jeton OAuth2, pas un secret
    expires_in: int


router = APIRouter(prefix="/api/v1/auth", tags=["authentification"])


@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest, request: Request) -> TokenResponse:
    address = client_address(request)
    wait = throttle.retry_after(address)
    if wait > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many failed attempts",
            headers={"Retry-After": str(int(wait) + 1)},
        )
    if not credentials_are_valid(credentials.username, credentials.password):
        throttle.failure(address)
        logger.warning("échec de connexion au tableau de bord depuis %s", address)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    throttle.success(address)
    token, expires_in = create_access_token(credentials.username)
    return TokenResponse(access_token=token, expires_in=expires_in)


bearer = HTTPBearer(auto_error=False)


def require_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> str:
    """Dépendance des routes de consultation : un jeton valide, sinon 401."""
    username = decode_access_token(credentials.credentials) if credentials else None
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


def require_user_query(token: Annotated[str | None, Query()] = None) -> str | None:
    """Pour le WebSocket : un navigateur ne peut pas y poser d'en-tête ``Authorization``."""
    return decode_access_token(token) if token else None


@router.get("/me")
async def me(username: Annotated[str, Depends(require_user)]) -> dict[str, str]:
    return {"username": username}
