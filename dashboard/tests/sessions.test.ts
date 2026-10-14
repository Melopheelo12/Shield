import { describe, expect, it } from "vitest";
import { formatDuration, heaviestFirst, sessionPath, type SessionRule } from "../src/api/sessions";

const rule = (rule_id: string, total_contribution: number, matches = 1) =>
  ({ rule_id, total_contribution, matches }) as SessionRule;

describe("heaviestFirst — règles d'une session", () => {
  it("classe par contribution totale, puis par fréquence, puis par identifiant", () => {
    const sorted = heaviestFirst([rule("R-005", 8, 8), rule("R-010", 60), rule("R-019", 8, 2), rule("R-001", 8, 2)]);
    expect(sorted.map((item) => item.rule_id)).toEqual(["R-010", "R-005", "R-001", "R-019"]);
  });

  it("ne modifie pas la liste reçue", () => {
    const rules = [rule("R-001", 1), rule("R-002", 5)];
    heaviestFirst(rules);
    expect(rules.map((item) => item.rule_id)).toEqual(["R-001", "R-002"]);
  });
});

describe("formatDuration", () => {
  it.each([
    ["2026-10-14T10:00:00Z", "2026-10-14T10:00:42Z", "42 s"],
    ["2026-10-14T10:00:00Z", "2026-10-14T10:03:05Z", "3 min 05 s"],
    ["2026-10-14T10:00:00Z", "2026-10-14T12:10:00Z", "2 h 10 min"],
    ["2026-10-14T10:00:00Z", null, "0 s"],
    ["illisible", "2026-10-14T10:00:00Z", "—"],
    ["2026-10-14T10:00:00Z", "2026-10-14T09:00:00Z", "—"],
  ])("%s → %s : %s", (start, end, expected) => {
    expect(formatDuration(start, end)).toBe(expected);
  });
});

it("encode l'identifiant de session dans le chemin", () => {
  expect(sessionPath("a/b")).toBe("/api/v1/sessions/a%2Fb");
});
