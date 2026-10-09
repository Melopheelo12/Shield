export type BlocklistFormat = "liste" | "ufw" | "iptables" | "nginx";

export const FORMATS: Record<BlocklistFormat, string> = {
  liste: "Liste brute",
  ufw: "ufw",
  iptables: "iptables",
  nginx: "nginx (deny)",
};

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// Volontairement strict : uniquement des chiffres hexadécimaux et des « : ».
const IPV6 = /^[0-9a-f:]{2,39}$/i;

/**
 * Vrai si la chaîne est une adresse IP et rien d'autre.
 *
 * Ces commandes seront collées dans un terminal root : une « adresse » contenant
 * `; rm -rf /` doit être écartée ici, même si l'API n'est pas censée en renvoyer.
 */
export function isIp(value: string): boolean {
  if (IPV4.test(value)) return true;
  return IPV6.test(value) && value.includes(":") && (value.match(/::/g) ?? []).length <= 1;
}

/** Commandes de blocage pour les adresses valides ; les autres sont ignorées. */
export function buildBlocklist(ips: string[], format: BlocklistFormat): string {
  const valid = [...new Set(ips.filter(isIp))];
  const line = (ip: string): string => {
    switch (format) {
      case "liste":
        return ip;
      case "ufw":
        return `sudo ufw insert 1 deny from ${ip}`;
      case "iptables":
        return `sudo ${ip.includes(":") ? "ip6tables" : "iptables"} -I INPUT -s ${ip} -j DROP`;
      case "nginx":
        return `deny ${ip};`;
    }
  };
  return valid.map(line).join("\n") + (valid.length ? "\n" : "");
}
