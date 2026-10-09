import { describe, expect, it } from "vitest";
import { decodePayload } from "../src/utils/base64";

const b64 = (bytes: number[]) => btoa(String.fromCharCode(...bytes));

describe("decodePayload — charge utile inerte", () => {
  it("laisse le texte ASCII lisible", () => {
    expect(decodePayload(btoa("GET /admin HTTP/1.1")).text).toBe("GET /admin HTTP/1.1");
  });

  it("montre les fins de ligne au lieu de les interpréter", () => {
    expect(decodePayload(btoa("a\r\nb")).text).toBe("a\\r\\n\nb");
  });

  it("échappe le binaire et les octets de contrôle", () => {
    expect(decodePayload(b64([0x00, 0xff, 0x1b, 0x41])).text).toBe("\\x00\\xff\\x1bA");
  });

  it("neutralise une séquence d'échappement de terminal", () => {
    const { text } = decodePayload(btoa("\x1b[2J\x1b]0;pwned\x07"));
    expect(text).not.toContain("\x1b");
    expect(text).toBe("\\x1b[2J\\x1b]0;pwned\\x07");
  });

  it("échappe la barre oblique inverse pour rester non ambigu", () => {
    expect(decodePayload(btoa("\\x41")).text).toBe("\\\\x41");
  });

  it("compte les octets décodés", () => {
    expect(decodePayload(b64([1, 2, 3, 4])).bytes).toBe(4);
  });

  it("affiche une charge non base64 telle quelle plutôt que de lever", () => {
    expect(decodePayload("@@pas du base64@@").text).toBe("@@pas du base64@@");
  });

  it("une charge vide reste vide", () => {
    expect(decodePayload("")).toEqual({ text: "", bytes: 0 });
  });
});
