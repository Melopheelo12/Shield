import { describe, expect, it } from "vitest";
import type { NormalizedEvent } from "../src/types/events";
import { mergeFeed } from "../src/utils/feed";

function event(id: string, occurredAt: string) {
  return { event_id: id, occurred_at: occurredAt } as NormalizedEvent;
}

const ids = (events: NormalizedEvent[]) => events.map((item) => item.event_id);

describe("mergeFeed — flux temps réel + premier chargement REST", () => {
  it("place les trames du WebSocket devant l'historique", () => {
    const rest = [event("b", "2026-10-14T10:00:01Z"), event("a", "2026-10-14T10:00:00Z")];
    const live = [event("c", "2026-10-14T10:00:05Z")];
    expect(ids(mergeFeed(live, rest, 10))).toEqual(["c", "b", "a"]);
  });

  it("n'affiche qu'une fois un événement reçu par les deux chemins", () => {
    const shared = event("b", "2026-10-14T10:00:01Z");
    expect(ids(mergeFeed([shared], [shared, event("a", "2026-10-14T10:00:00Z")], 10))).toEqual(["b", "a"]);
  });

  it("retrie par date : une trame en retard ne passe pas devant", () => {
    const live = [event("late", "2026-10-14T09:59:00Z")];
    const rest = [event("b", "2026-10-14T10:00:01Z")];
    expect(ids(mergeFeed(live, rest, 10))).toEqual(["b", "late"]);
  });

  it("plafonne la liste", () => {
    const live = Array.from({ length: 5 }, (_, i) => event(`e${i}`, `2026-10-14T10:00:0${i}Z`));
    expect(ids(mergeFeed(live, [], 3))).toEqual(["e4", "e3", "e2"]);
  });
});
