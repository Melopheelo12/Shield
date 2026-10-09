/**
 * Rend lisible une charge utile d'attaquant transportée en base64.
 *
 * Les octets ASCII imprimables restent tels quels ; tout le reste (contrôle,
 * binaire, octets UTF-8) devient `\xNN`, et les fins de ligne `\r` `\n` sont
 * montrées plutôt qu'interprétées. Le résultat est donc toujours une chaîne inerte,
 * qu'aucun octet reçu ne peut transformer en mise en forme ou en séquence de
 * terminal. Une charge illisible n'est jamais une erreur : on affiche ce qu'on a.
 */
export function decodePayload(base64: string): { text: string; bytes: number } {
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    return { text: base64, bytes: base64.length };
  }

  let text = "";
  for (let index = 0; index < binary.length; index += 1) {
    const code = binary.charCodeAt(index);
    if (code === 0x0a) text += "\\n\n";
    else if (code === 0x0d) text += "\\r";
    else if (code === 0x09) text += "\\t";
    else if (code === 0x5c) text += "\\\\";
    else if (code >= 0x20 && code < 0x7f) text += binary[index];
    else text += `\\x${code.toString(16).padStart(2, "0")}`;
  }
  return { text, bytes: binary.length };
}
