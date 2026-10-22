import { describe, expect, it } from "vitest";
import { fieldFromServerError, validateThresholds, type Threshold } from "../src/api/alerts";

const threshold = (patch: Partial<Threshold> = {}): Threshold => ({
  id: "volume",
  metric: "events",
  threshold: 200,
  window_seconds: 300,
  silence_seconds: 3600,
  enabled: true,
  ...patch,
});

describe("validateThresholds — mêmes règles que le collecteur", () => {
  it("accepte les seuils par défaut", () => {
    expect(validateThresholds([threshold(), threshold({ id: "critique", metric: "max_threat_score", threshold: 80 })])).toEqual([{}, {}]);
  });

  it("refuse un seuil nul ou négatif", () => {
    expect(validateThresholds([threshold({ threshold: 0 })])[0]).toHaveProperty("threshold");
    expect(validateThresholds([threshold({ threshold: Number.NaN })])[0]).toHaveProperty("threshold");
  });

  it("borne la fenêtre à 1 s – 24 h et le silence à 0 – 7 j", () => {
    expect(validateThresholds([threshold({ window_seconds: 0 })])[0]).toHaveProperty("window_seconds");
    expect(validateThresholds([threshold({ window_seconds: 86_401 })])[0]).toHaveProperty("window_seconds");
    expect(validateThresholds([threshold({ window_seconds: 86_400, silence_seconds: 0 })])[0]).toEqual({});
    expect(validateThresholds([threshold({ silence_seconds: 7 * 86_400 + 1 })])[0]).toHaveProperty("silence_seconds");
  });

  it("signale les identifiants vides ou en double, espaces compris", () => {
    const errors = validateThresholds([threshold(), threshold({ id: " volume " }), threshold({ id: "  " })]);
    expect(errors[0].id).toBe("Identifiant en double.");
    expect(errors[1].id).toBe("Identifiant en double.");
    expect(errors[2].id).toBe("Identifiant obligatoire.");
  });
});

describe("fieldFromServerError — refus 422 du collecteur", () => {
  it.each([
    ["invalid threshold: identifiants de seuil en double", "id"],
    ["invalid threshold: le seuil doit être positif", "threshold"],
    ["invalid threshold: fenêtre entre 1 s et 24 h", "window_seconds"],
    ["invalid threshold: silence entre 0 et 7 jours", "silence_seconds"],
    ["invalid threshold: 'nope' is not a valid Metric", "metric"],
    ["autre chose", null],
    [undefined, null],
  ])("%s → %s", (detail, field) => {
    expect(fieldFromServerError(detail)).toBe(field);
  });
});
