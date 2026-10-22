import { describe, expect, it, vi } from "vitest";
import { loadGameStart, reportVerdict, saveGameStart, summarize } from "../src/utils/scorecard";

describe("summarize — bilan d'une partie de sandbox", () => {
  it("n'a pas de taux tant que rien n'a été tenté", () => {
    expect(summarize({})).toEqual({ attempted: 0, detected: 0, missed: [], rate: null });
  });

  it("calcule le taux sur les seules techniques tentées", () => {
    const summary = summarize({
      "R-001": { attempted: true, detected: true },
      "R-007": { attempted: true, detected: false },
      "R-009": { attempted: true, detected: true },
    });
    expect(summary.rate).toBe(67);
    expect(summary.missed).toEqual(["R-007"]);
  });

  it("ne crédite pas l'agent d'une détection sur une technique non tentée", () => {
    const summary = summarize({
      "R-001": { attempted: true, detected: false },
      "R-010": { attempted: false, detected: true },
    });
    expect(summary).toEqual({ attempted: 1, detected: 0, missed: ["R-001"], rate: 0 });
  });
});

describe("partie mesurée par le collecteur (US-37)", () => {
  const report = (detection_rate: number | null, target_met = false) => ({
    since: null,
    events: 10,
    detected: 8,
    detection_rate,
    target: 80,
    target_met,
    by_service: {},
    missed_by_technique: [],
  });

  it("annonce l'objectif atteint ou manqué, avec les chiffres", () => {
    expect(reportVerdict(report(85, true))).toEqual({
      tone: "ok",
      text: "Objectif atteint : 85 % détectées (objectif 80 %).",
    });
    expect(reportVerdict(report(79)).tone).toBe("down");
    expect(reportVerdict(report(79)).text).toContain("il en faut 80 %");
  });

  it("sans tentative, ne conclut rien", () => {
    expect(reportVerdict(report(null)).tone).toBe("pending");
  });

  it("garde le début de partie et ignore une valeur illisible", () => {
    const values = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (key: string) => values.get(key) ?? null,
        setItem: (key: string, value: string) => void values.set(key, value),
        removeItem: (key: string) => void values.delete(key),
      },
    });
    saveGameStart("2026-10-14T10:00:00.000Z");
    expect(loadGameStart()).toBe("2026-10-14T10:00:00.000Z");
    values.set("shield.sandbox.debut", "n'importe quoi");
    expect(loadGameStart()).toBeNull();
    saveGameStart(null);
    expect(values.size).toBe(0);
    vi.unstubAllGlobals();
  });
});
