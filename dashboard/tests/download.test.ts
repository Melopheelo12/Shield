import { describe, expect, it } from "vitest";
import { parseBlocklist } from "../src/utils/blocklist";
import { filenameFromDisposition, pseudonymizationState } from "../src/utils/download";

describe("filenameFromDisposition", () => {
  it.each([
    ['attachment; filename="shield-export-20261014-091500-pseudonymise.csv"', "shield-export-20261014-091500-pseudonymise.csv"],
    ["attachment; filename=export.json", "export.json"],
    ['attachment; filename="../../etc/passwd"', "passwd"],
    [null, "repli.csv"],
    ["attachment", "repli.csv"],
  ])("%s → %s", (header, expected) => {
    expect(filenameFromDisposition(header, "repli.csv")).toBe(expected);
  });
});

describe("pseudonymizationState — US-47, jamais silencieux", () => {
  it("lit le mode réel annoncé par le serveur", () => {
    expect(pseudonymizationState("true")).toBe("on");
    expect(pseudonymizationState("false")).toBe("off");
  });

  it("en-tête absent ou inattendu : inconnu, jamais supposé pseudonymisé", () => {
    expect(pseudonymizationState(null)).toBe("unknown");
    expect(pseudonymizationState("yes")).toBe("unknown");
  });
});

describe("parseBlocklist — liste du collecteur", () => {
  it("garde les adresses, dans l'ordre reçu, sans doublon", () => {
    expect(parseBlocklist("203.0.113.9\n198.51.100.7\r\n203.0.113.9\n2001:db8::5\n\n")).toEqual({
      ips: ["203.0.113.9", "198.51.100.7", "2001:db8::5"],
      rejected: 0,
    });
  });

  it("écarte et compte toute ligne qui n'est pas une adresse", () => {
    const { ips, rejected } = parseBlocklist("198.51.100.7\n1.2.3.4; rm -rf /\n300.1.1.1\n<html>");
    expect(ips).toEqual(["198.51.100.7"]);
    expect(rejected).toBe(3);
  });

  it("liste vide : aucune adresse", () => {
    expect(parseBlocklist("")).toEqual({ ips: [], rejected: 0 });
  });
});
