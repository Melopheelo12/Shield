import { describe, expect, it } from "vitest";
import { attemptSummary } from "../src/utils/format";

const b64 = (text: string) => btoa(text);

describe("attemptSummary — la tentative en une ligne", () => {
  it("montre l'identifiant et le mot de passe essayés", () => {
    expect(attemptSummary({ username: "root", password: "123456", payload: "" })).toBe("root / 123456");
  });

  it("signale un mot de passe vide", () => {
    expect(attemptSummary({ username: "admin", password: "", payload: "" })).toBe("admin / —");
  });

  it("sinon, la première ligne de la charge utile", () => {
    const payload = b64("GET /cgi-bin/admin.cgi?cmd=;id HTTP/1.1\r\nHost: decoy\r\n\r\n");
    expect(attemptSummary({ username: "", password: "", payload })).toBe("GET /cgi-bin/admin.cgi?cmd=;id HTTP/1.1");
  });

  it("reste inerte : un octet de contrôle est montré, pas interprété", () => {
    expect(attemptSummary({ username: "", password: "", payload: b64("\x1b[31mX") })).toBe("\\x1b[31mX");
  });

  it("une connexion muette est dite comme telle", () => {
    expect(attemptSummary({ username: "", password: "", payload: "" })).toBe("connexion sans échange");
  });
});
