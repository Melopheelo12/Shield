import { describe, expect, it } from "vitest";
import { fillTimeline, PERIODS } from "../src/utils/timeline";

const HOUR = 3_600_000;
const t = (iso: string) => Date.parse(iso);
const point = (bucket: string, events: number, max_threat_score = 0) => ({ bucket, events, max_threat_score });

describe("fillTimeline — chronologie de l'API", () => {
  it("garde les tranches vides entre deux pics", () => {
    const slots = fillTimeline(
      [point("2026-10-14T08:00:00+00:00", 3, 40), point("2026-10-14T11:00:00+00:00", 1, 90)],
      t("2026-10-14T07:30:00Z"),
      HOUR,
      t("2026-10-14T11:20:00Z"),
    );
    expect(slots.map((slot) => [new Date(slot.start).toISOString().slice(11, 16), slot.events, slot.maxScore])).toEqual([
      ["07:00", 0, 0],
      ["08:00", 3, 40],
      ["09:00", 0, 0],
      ["10:00", 0, 0],
      ["11:00", 1, 90],
    ]);
  });

  it("couvre toute la période même sans aucune tentative", () => {
    const slots = fillTimeline([], t("2026-10-14T00:00:00Z"), HOUR, t("2026-10-14T23:59:00Z"));
    expect(slots).toHaveLength(24);
    expect(slots.every((slot) => slot.events === 0)).toBe(true);
  });

  it("se cale sur les tranches de l'API, même décalées de l'heure ronde", () => {
    const slots = fillTimeline([point("2026-10-14T08:30:00Z", 2)], t("2026-10-14T07:00:00Z"), HOUR, t("2026-10-14T09:10:00Z"));
    expect(slots.map((slot) => new Date(slot.start).toISOString().slice(11, 16))).toEqual(["06:30", "07:30", "08:30"]);
    expect(slots[2].events).toBe(2);
  });

  it("ignore une tranche illisible au lieu de décaler les autres", () => {
    const slots = fillTimeline(
      [point("pas une date", 9), point("2026-10-14T01:00:00Z", 1)],
      t("2026-10-14T00:00:00Z"),
      HOUR,
      t("2026-10-14T02:00:00Z"),
    );
    expect(slots.map((slot) => slot.events)).toEqual([0, 1, 0]);
  });

  it("chaque période reste sous le plafond de 1 000 tranches de l'API", () => {
    for (const period of PERIODS) {
      expect((period.hours * 60) / period.bucketMinutes).toBeLessThanOrEqual(1000);
    }
  });
});
