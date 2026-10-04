import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchEventsPage, periodStart } from "../src/api/attacks";
import { DEFAULT_FILTERS } from "../src/hooks/useFilters";

function mockFetch(body: unknown, status = 200) {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function event(occurredAt: string) {
  return { event_id: occurredAt, occurred_at: occurredAt };
}

afterEach(() => vi.unstubAllGlobals());

describe("fetchEventsPage — pagination par curseur", () => {
  it("transmet filtres, curseur et limite à l'API", async () => {
    const fetchMock = mockFetch({ items: [], count: 0 });
    await fetchEventsPage({ period: "all", service: "ssh", country: "FR" }, "abc", 50);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/events?service=ssh&country=FR&cursor=abc&limit=50",
      expect.anything(),
    );
  });

  it("n'envoie ni filtre vide ni curseur sur la première page", async () => {
    const fetchMock = mockFetch({ items: [], count: 0 });
    await fetchEventsPage({ ...DEFAULT_FILTERS, period: "all" }, null, 50);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/events?limit=50", expect.anything());
  });

  it("expose next_cursor quand l'API le fournit", async () => {
    mockFetch({ items: [], count: 0, next_cursor: "page-2" });
    const page = await fetchEventsPage({ ...DEFAULT_FILTERS, period: "all" }, null, 50);
    expect(page.nextCursor).toBe("page-2");
  });

  it("considère l'absence de next_cursor comme la dernière page", async () => {
    mockFetch({ items: [], count: 0 });
    const page = await fetchEventsPage({ ...DEFAULT_FILTERS, period: "all" }, null, 50);
    expect(page.nextCursor).toBeNull();
  });

  it("applique la période côté client si l'API ignore `since`", async () => {
    const recent = new Date(Date.now() - 60_000).toISOString();
    const old = new Date(Date.now() - 2 * 86_400_000).toISOString();
    mockFetch({ items: [event(recent), event(old)], count: 2 });
    const page = await fetchEventsPage({ ...DEFAULT_FILTERS, period: "24h" }, null, 50);
    expect(page.items.map((item) => item.occurred_at)).toEqual([recent]);
  });

  it("lève une erreur sur une réponse HTTP en échec", async () => {
    mockFetch({ detail: "boom" }, 503);
    await expect(fetchEventsPage(DEFAULT_FILTERS, null, 50)).rejects.toThrow("HTTP 503");
  });
});

describe("periodStart", () => {
  it("renvoie null pour « Tout »", () => {
    expect(periodStart("all")).toBeNull();
  });

  it("calcule la borne basse", () => {
    const now = Date.parse("2026-10-04T12:00:00Z");
    expect(periodStart("1h", now)).toBe("2026-10-04T11:00:00.000Z");
  });
});
