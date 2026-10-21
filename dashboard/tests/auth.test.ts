import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getToken, login, LOGOUT_EVENT, parseRetryAfter, setToken, streamUrl } from "../src/api/auth";
import { ApiError, getJson } from "../src/api/client";

function memoryStorage() {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };
}

function mockFetch(body: unknown, status = 200, headers: Record<string, string> = {}) {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status, headers }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

let win: EventTarget & { location: { protocol: string; host: string } };

beforeEach(() => {
  win = Object.assign(new EventTarget(), { location: { protocol: "https:", host: "shield.test:8443" } });
  vi.stubGlobal("window", win);
  vi.stubGlobal("sessionStorage", memoryStorage());
});

afterEach(() => vi.unstubAllGlobals());

describe("getJson — jeton d'accès", () => {
  it("ajoute l'en-tête Authorization quand un jeton est présent", async () => {
    setToken("abc");
    const fetchMock = mockFetch({ ok: true });
    await getJson("/api/v1/stats/overview");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/stats/overview", {
      headers: { Accept: "application/json", Authorization: "Bearer abc" },
      signal: undefined,
    });
  });

  it("n'envoie aucun en-tête Authorization sans jeton", async () => {
    const fetchMock = mockFetch({ ok: true });
    await getJson("/api/v1/health");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/health", {
      headers: { Accept: "application/json" },
      signal: undefined,
    });
  });

  it("un 401 efface le jeton et émet shield:logout", async () => {
    setToken("périmé");
    mockFetch({ detail: "authentication required" }, 401);
    const reasons: unknown[] = [];
    win.addEventListener(LOGOUT_EVENT, (event) => reasons.push((event as CustomEvent).detail));

    await expect(getJson("/api/v1/events")).rejects.toBeInstanceOf(ApiError);
    expect(getToken()).toBeNull();
    expect(reasons).toEqual(["expired"]);
  });

  it("une autre erreur ne déconnecte pas", async () => {
    setToken("abc");
    mockFetch({}, 500);
    await expect(getJson("/api/v1/events")).rejects.toThrow("HTTP 500");
    expect(getToken()).toBe("abc");
  });
});

describe("login", () => {
  it("conserve le jeton reçu", async () => {
    const fetchMock = mockFetch({ access_token: "jwt", token_type: "bearer", expires_in: 1800 });
    await login("admin", "secret");
    expect(getToken()).toBe("jwt");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/auth/login",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ username: "admin", password: "secret" }) }),
    );
  });

  it("401 : identifiants refusés", async () => {
    mockFetch({ detail: "invalid credentials" }, 401);
    await expect(login("admin", "faux")).rejects.toMatchObject({ failure: { kind: "invalid" } });
    expect(getToken()).toBeNull();
  });

  it("429 : délai lu dans Retry-After", async () => {
    mockFetch({ detail: "too many failed attempts" }, 429, { "Retry-After": "31" });
    await expect(login("admin", "faux")).rejects.toMatchObject({ failure: { kind: "throttled", retryAfter: 31 } });
  });

  it("autre statut : collecteur indisponible", async () => {
    mockFetch({}, 502);
    await expect(login("admin", "x")).rejects.toMatchObject({ failure: { kind: "unavailable", status: 502 } });
  });
});

describe("parseRetryAfter", () => {
  it.each([
    ["30", 30],
    ["2.5", 3],
    [null, 60],
    ["", 60],
    ["demain", 60],
    ["-5", 60],
  ])("%s → %d s", (header, expected) => {
    expect(parseRetryAfter(header)).toBe(expected);
  });
});

describe("streamUrl", () => {
  it("passe en wss sous HTTPS et encode le jeton", () => {
    setToken("a.b+c/d");
    expect(streamUrl()).toBe("wss://shield.test:8443/ws/events?token=a.b%2Bc%2Fd");
  });

  it("sans jeton, aucun paramètre", () => {
    win.location.protocol = "http:";
    expect(streamUrl()).toBe("ws://shield.test:8443/ws/events");
  });
});
