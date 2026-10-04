#!/usr/bin/env bash
# =============================================================================
# SHIELD — durcissement du VPS (S0-10, US-49)
#
# A lancer UNE fois, en root, sur un Ubuntu 24.04 LTS fraichement livre :
#
#   ADMIN_USER=antho ADMIN_SSH_PORT=49222 \
#   ADMIN_PUBKEY="ssh-ed25519 AAAA... antho@portable" \
#   ./scripts/harden_vps.sh
#
# Idempotent : le relancer remet la machine dans l'etat attendu.
#
# NE FERMEZ PAS la session courante avant d'avoir verifie, dans un SECOND
# terminal, que `ssh -p $ADMIN_SSH_PORT $ADMIN_USER@<ip>` fonctionne.
# =============================================================================
set -euo pipefail

DECOY_PORTS=(22 80 21)

die() { echo "ERREUR : $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

# ------------------------------------------------------------------ preconditions

[[ $EUID -eq 0 ]] || die "a lancer en root."
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || [[ "${FORCE:-}" == "1" ]] \
  || die "teste sur Ubuntu 24.04 uniquement (FORCE=1 pour passer outre)."

: "${ADMIN_USER:?ADMIN_USER manquant}"
: "${ADMIN_SSH_PORT:?ADMIN_SSH_PORT manquant}"
: "${ADMIN_PUBKEY:?ADMIN_PUBKEY manquant (cle PUBLIQUE, jamais la privee)}"

[[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "ADMIN_USER invalide."
[[ "$ADMIN_SSH_PORT" =~ ^[0-9]+$ ]] && (( ADMIN_SSH_PORT >= 1024 && ADMIN_SSH_PORT <= 65535 )) \
  || die "ADMIN_SSH_PORT doit etre entre 1024 et 65535."
for port in "${DECOY_PORTS[@]}"; do
  (( ADMIN_SSH_PORT != port )) || die "ADMIN_SSH_PORT ne peut pas etre un port de leurre ($port)."
done
[[ "$ADMIN_PUBKEY" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com|ssh-rsa)\  ]] \
  || die "ADMIN_PUBKEY ne ressemble pas a une cle publique OpenSSH."
[[ "$ADMIN_PUBKEY" != *"PRIVATE KEY"* ]] || die "c'est une cle PRIVEE. Ne la copiez jamais sur le serveur."

EXT_IFACE="$(ip -o route get 1.1.1.1 | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}')"
[[ -n "$EXT_IFACE" ]] || die "interface reseau externe introuvable."

# ------------------------------------------------------------------ paquets

step "Mise a jour et paquets"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q ufw unattended-upgrades docker.io docker-compose-v2 git

# ------------------------------------------------------------------ compte admin

step "Compte d'administration : $ADMIN_USER"
id "$ADMIN_USER" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$ADMIN_USER"
usermod -aG sudo,docker "$ADMIN_USER"
# Pas de mot de passe : sudo sans mot de passe, la cle SSH est le seul facteur.
echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$ADMIN_USER"
chmod 440 "/etc/sudoers.d/90-$ADMIN_USER"
visudo -cf "/etc/sudoers.d/90-$ADMIN_USER" >/dev/null

home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
echo "$ADMIN_PUBKEY" > "$home/.ssh/authorized_keys"
chown "$ADMIN_USER:$ADMIN_USER" "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"

# ------------------------------------------------------------------ sshd

step "SSH d'administration : cle uniquement, port $ADMIN_SSH_PORT"
cat > /etc/ssh/sshd_config.d/00-shield.conf <<EOF
# Gere par scripts/harden_vps.sh — ne pas modifier a la main.
Port $ADMIN_SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers $ADMIN_USER
MaxAuthTries 3
LoginGraceTime 20
# Un agent SSH transfere serait utilisable par quiconque obtient root ici.
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
# Le tunnel local vers le tableau de bord (ssh -L 8443:localhost:8443) reste permis.
AllowTcpForwarding local
EOF
sshd -t || die "configuration sshd invalide : rien n'a ete redemarre."

# Ubuntu 24.04 demarre sshd par activation de socket, qui ignore `Port` :
# on repasse au service classique pour que le port decale soit pris en compte.
if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
  systemctl disable --now ssh.socket
  rm -f /etc/systemd/system/ssh.service.d/00-socket.conf
  systemctl daemon-reload
fi
systemctl enable ssh.service >/dev/null

# ------------------------------------------------------------------ pare-feu

step "Pare-feu : ${DECOY_PORTS[*]} (leurres) + $ADMIN_SSH_PORT (admin)"
# Le port d'admin est ouvert AVANT d'activer ufw : pas de coupure de session.
ufw allow "$ADMIN_SSH_PORT/tcp" comment "ssh admin"
for port in "${DECOY_PORTS[@]}"; do
  ufw allow "$port/tcp" comment "leurre SHIELD"
done
ufw default deny incoming
ufw default allow outgoing

# Docker publie ses ports en contournant ufw. La chaine DOCKER-USER, que Docker
# ne touche jamais, refuse toute nouvelle connexion entrante vers un conteneur
# sauf vers les ports de leurre. Consequence voulue : le 8443 du tableau de bord
# n'est joignable que par tunnel SSH.
python3 - "$EXT_IFACE" "${DECOY_PORTS[@]}" <<'PY'
import re, sys
iface, ports = sys.argv[1], sys.argv[2:]
rules = ["# BEGIN SHIELD DOCKER-USER", "*filter", ":DOCKER-USER - [0:0]", "-F DOCKER-USER",
         "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"]
rules += [f"-A DOCKER-USER -i {iface} -p tcp -m conntrack --ctstate NEW --ctorigdstport {p} -j RETURN"
          for p in ports]
rules += [f"-A DOCKER-USER -i {iface} -m conntrack --ctstate NEW -j DROP", "-A DOCKER-USER -j RETURN",
          "COMMIT", "# END SHIELD DOCKER-USER"]
path = "/etc/ufw/after.rules"
text = open(path).read()
text = re.sub(r"\n?# BEGIN SHIELD DOCKER-USER.*?# END SHIELD DOCKER-USER\n?", "\n", text, flags=re.S)
open(path, "w").write(text.rstrip("\n") + "\n\n" + "\n".join(rules) + "\n")
PY
ufw --force enable
ufw reload

# ------------------------------------------------------------------ mises a jour

step "Mises a jour de securite automatiques"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52shield-unattended <<'EOF'
// Gere par scripts/harden_vps.sh
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
systemctl enable --now unattended-upgrades >/dev/null
unattended-upgrade --dry-run >/dev/null || die "unattended-upgrades mal configure."

# ------------------------------------------------------------------ aucun secret

step "Verification : aucun secret sur la machine"
found="$(grep -rlsE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' /root /home 2>/dev/null || true)"
if [[ -n "$found" ]]; then
  echo "$found" >&2
  die "cle(s) privee(s) trouvee(s) ci-dessus : supprimez-les, ce serveur sera attaque."
fi
for env_file in /home/*/Shield/.env /root/Shield/.env; do
  [[ -f "$env_file" ]] && chmod 600 "$env_file"
done

# ------------------------------------------------------------------ redemarrage sshd

step "Redemarrage de sshd sur le port $ADMIN_SSH_PORT"
systemctl restart ssh.service
ss -ltn "sport = :$ADMIN_SSH_PORT" | grep -q LISTEN || die "sshd n'ecoute pas sur $ADMIN_SSH_PORT."
if ss -ltnp "sport = :22" | grep -q sshd; then
  die "sshd ecoute encore sur 22 : le leurre SSH ne pourra pas demarrer."
fi

cat <<EOF

Durcissement termine.

  1. SANS fermer cette session, dans un autre terminal :
       ssh -p $ADMIN_SSH_PORT $ADMIN_USER@<ip-du-vps>
  2. Verifier que le mot de passe est refuse :
       ssh -p $ADMIN_SSH_PORT -o PubkeyAuthentication=no $ADMIN_USER@<ip-du-vps>
  3. Etat du pare-feu :  ufw status verbose  &&  iptables -L DOCKER-USER -n
EOF
