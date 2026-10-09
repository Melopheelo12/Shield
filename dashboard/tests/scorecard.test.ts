import { describe, expect, it } from "vitest";
import { summarize } from "../src/utils/scorecard";

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
