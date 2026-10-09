import { describe, expect, it } from "vitest";
import { buildBlocklist, isIp } from "../src/utils/blocklist";

describe("isIp — seules des adresses entrent dans une commande", () => {
  it.each(["192.0.2.1", "203.0.113.255", "0.0.0.0", "2001:db8::1", "::1"])("accepte %s", (ip) => {
    expect(isIp(ip)).toBe(true);
  });

  it.each([
    "192.0.2.1; rm -rf /",
    "$(curl evil)",
    "192.0.2.256",
    "192.0.2",
    "2001:db8::1::2",
    "1.2.3.4\nsudo reboot",
    "",
    "abc",
  ])("refuse %j", (value) => {
    expect(isIp(value)).toBe(false);
  });
});

describe("buildBlocklist", () => {
  const ips = ["192.0.2.1", "2001:db8::7"];

  it("produit une ligne par adresse, terminée par un saut de ligne", () => {
    expect(buildBlocklist(ips, "liste")).toBe("192.0.2.1\n2001:db8::7\n");
  });

  it("insère les règles ufw en tête, avant les autorisations", () => {
    expect(buildBlocklist(["192.0.2.1"], "ufw")).toBe("sudo ufw insert 1 deny from 192.0.2.1\n");
  });

  it("choisit ip6tables pour une adresse IPv6", () => {
    expect(buildBlocklist(ips, "iptables")).toBe(
      "sudo iptables -I INPUT -s 192.0.2.1 -j DROP\nsudo ip6tables -I INPUT -s 2001:db8::7 -j DROP\n",
    );
  });

  it("produit des directives nginx", () => {
    expect(buildBlocklist(["192.0.2.1"], "nginx")).toBe("deny 192.0.2.1;\n");
  });

  it("écarte toute valeur qui n'est pas une adresse et dédoublonne", () => {
    const out = buildBlocklist(["192.0.2.1", "192.0.2.1", "192.0.2.1; reboot"], "ufw");
    expect(out).toBe("sudo ufw insert 1 deny from 192.0.2.1\n");
    expect(out).not.toContain("reboot");
  });

  it("ne produit rien sans adresse valide", () => {
    expect(buildBlocklist([], "liste")).toBe("");
  });
});
