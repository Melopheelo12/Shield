"""Contenu du leurre HTTP : le site vitrine WordPress d'une petite entreprise fictive.

Pourquoi WordPress : il fait tourner une large part du web et c'est la cible n°1 des
robots. Une version ancienne annoncée (5.8.3) attire les tentatives d'exploitation ;
``/wp-login.php`` et ``/xmlrpc.php`` attirent la force brute.

Pourquoi un vrai routage : un serveur qui répond la même page avec un 200 à toutes
les adresses (``/.env``, ``/nimporte-quoi``…) est la signature classique d'un honeypot.
Ici, les adresses connues de WordPress répondent comme WordPress, et tout le reste
reçoit une vraie 404.

Règles, vérifiées par les tests :

* **Tout est statique.** Aucune page n'est construite à partir de la requête : rien de
  ce qu'envoie l'attaquant n'est réinjecté (pas de XSS réfléchi, pas même l'identifiant
  dans le message d'erreur, contrairement au vrai WordPress).
* **Entreprise fictive.** Aucune marque, adresse, téléphone ou domaine réel : imiter une
  organisation existante serait de l'usurpation. Le nom se change avec
  ``DECOY_HTTP_SITE_NAME``.
* **Rien ne trahit le leurre** : aucune mention du projet ni du mot « honeypot ».
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from html import escape

WORDPRESS_VERSION = "5.8.3"
DEFAULT_SITE_NAME = "Menuiserie des Tilleuls"

HTML = "text/html; charset=UTF-8"
JSON = "application/json; charset=UTF-8"


@dataclass(frozen=True)
class Page:
    status: str
    body: str = ""
    content_type: str = HTML
    headers: tuple[tuple[str, str], ...] = ()


def site_name() -> str:
    """Nom affiché. Échappé une fois pour toutes : il vient de la configuration."""
    return escape(os.getenv("DECOY_HTTP_SITE_NAME", DEFAULT_SITE_NAME).strip()[:80])


def _head(title: str) -> str:
    return (
        '<!DOCTYPE html>\n<html lang="fr-FR">\n<head>\n<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{title}</title>\n"
        f'<meta name="generator" content="WordPress {WORDPRESS_VERSION}">\n'
        "<link rel='stylesheet' id='twenty-twenty-one-style-css' "
        f"href='/wp-content/themes/twentytwentyone/style.css?ver={WORDPRESS_VERSION}' "
        "media='all'>\n"
        '<link rel="https://api.w.org/" href="/wp-json/">\n'
        "</head>\n"
    )


def home_page() -> str:
    name = site_name()
    return (
        _head(f"{name} – Fabrication et pose sur mesure")
        + '<body class="home page-template-default">\n'
        '<header class="site-header"><div class="site-branding">'
        f'<h1 class="site-title"><a href="/">{name}</a></h1>'
        '<p class="site-description">Fabrication et pose sur mesure</p></div>'
        '<nav class="primary-navigation"><ul>'
        '<li><a href="/">Accueil</a></li><li><a href="/realisations/">Réalisations</a></li>'
        '<li><a href="/devis/">Demander un devis</a></li><li><a href="/contact/">Contact</a></li>'
        "</ul></nav></header>\n"
        '<main id="main" class="site-main"><article class="page">'
        '<h2 class="entry-title">Bienvenue</h2><div class="entry-content">'
        "<p>Depuis trois générations, notre atelier conçoit et pose escaliers, cuisines, "
        "placards et menuiseries extérieures, en bois massif et sur mesure.</p>"
        "<p>Chaque projet commence par une visite et un devis gratuit. Nous travaillons "
        "avec des essences locales et des finitions naturelles.</p>"
        '<p><a class="wp-block-button__link" href="/devis/">Demander un devis gratuit</a></p>'
        "</div></article></main>\n"
        '<footer class="site-footer"><p>© 2021 '
        f'{name} · <a href="/mentions-legales/">Mentions légales</a> · '
        'Fièrement propulsé par <a href="https://wordpress.org/">WordPress</a></p></footer>\n'
        "</body>\n</html>\n"
    )


def login_page(*, failed: bool = False) -> str:
    """Formulaire de connexion. Champs ``log`` et ``pwd`` : ceux du vrai WordPress."""
    error = (
        '<div id="login_error"><strong>Erreur :</strong> l\'identifiant ou le mot de passe '
        'est incorrect. <a href="/wp-login.php?action=lostpassword">Mot de passe oublié '
        "?</a></div>\n"
        if failed
        else ""
    )
    return (
        _head(f"Se connecter ‹ {site_name()} — WordPress")
        + '<body class="login no-js login-action-login wp-core-ui locale-fr-fr">\n'
        '<div id="login"><h1><a href="https://fr.wordpress.org/">Propulsé par WordPress</a></h1>\n'
        + error
        + '<form name="loginform" id="loginform" action="/wp-login.php" method="post">\n'
        '<p><label for="user_login">Identifiant ou adresse e-mail</label>\n'
        '<input type="text" name="log" id="user_login" class="input" size="20" '
        'autocapitalize="off" autocomplete="username"></p>\n'
        '<div class="user-pass-wrap"><label for="user_pass">Mot de passe</label>\n'
        '<input type="password" name="pwd" id="user_pass" class="input" size="20" '
        'autocomplete="current-password"></div>\n'
        '<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme">'
        ' <label for="rememberme">Se souvenir de moi</label></p>\n'
        '<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" '
        'class="button button-primary button-large" value="Se connecter">\n'
        '<input type="hidden" name="redirect_to" value="/wp-admin/">\n'
        '<input type="hidden" name="testcookie" value="1"></p>\n'
        "</form>\n"
        '<p id="nav"><a href="/wp-login.php?action=lostpassword">Mot de passe oublié ?</a></p>\n'
        '<p id="backtoblog"><a href="/">&larr; Aller sur le site</a></p>\n'
        "</div>\n</body>\n</html>\n"
    )


def not_found_page() -> str:
    return (
        _head(f"Page non trouvée – {site_name()}")
        + '<body class="error404">\n<main id="main" class="site-main">'
        '<h1 class="page-title">Rien de trouvé</h1>'
        "<p>Il semble que rien n’ait été trouvé à cette adresse. "
        'Essayez peut-être une recherche ?</p><p><a href="/">Retour à l’accueil</a></p>'
        "</main>\n</body>\n</html>\n"
    )


README = (
    '<!DOCTYPE html>\n<html lang="fr-FR">\n<head><meta charset="utf-8">'
    "<title>WordPress &#8250; LisezMoi</title></head>\n<body>\n"
    '<h1 id="logo">WordPress</h1>\n'
    f'<p style="text-align: center">Version {WORDPRESS_VERSION}</p>\n'
    "<p>Sémantique de publication personnelle</p>\n"
    "<h2>Installation : la fameuse installation en 5 minutes</h2>\n"
    "<ol><li>Décompressez l’archive dans un dossier vide.</li>"
    "<li>Ouvrez <code>wp-admin/install.php</code> dans votre navigateur.</li></ol>\n"
    "</body>\n</html>\n"
)

ROBOTS = "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"

STYLE = (
    "/*\nTheme Name: Twenty Twenty-One\nAuthor: the WordPress team\nVersion: 1.4\n*/\n"
    "body{margin:0;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;"
    "background:#d1e4dd;color:#28303d}"
    ".site-header,.site-main,.site-footer{max-width:960px;margin:0 auto;padding:24px}"
    ".primary-navigation ul{display:flex;gap:16px;list-style:none;padding:0}"
    "a{color:#28303d}.wp-block-button__link{background:#28303d;color:#d1e4dd;"
    "padding:12px 20px;text-decoration:none}"
    "#login{width:320px;margin:8% auto}#loginform{background:#fff;padding:24px}"
    ".input{width:100%;padding:6px;margin:4px 0 12px}#login_error{background:#fff;"
    "border-left:4px solid #d63638;padding:12px;margin-bottom:16px}\n"
)

#: Utilisateur fictif révélé par l'énumération WordPress. Un robot qui essaie ensuite
#: « atelier » a fait de la reconnaissance : c'est une information pour l'analyse.
BAIT_USER = "atelier"

WP_JSON_USERS = (
    '[{"id":1,"name":"Atelier","url":"","description":"","link":"/author/'
    + BAIT_USER
    + '/","slug":"'
    + BAIT_USER
    + '","avatar_urls":{}}]'
)

WP_JSON_ROOT = (
    '{"name":"","description":"Fabrication et pose sur mesure","url":"","home":"",'
    '"gmt_offset":"1","timezone_string":"Europe/Paris",'
    '"namespaces":["oembed/1.0","wp/v2","wp-site-health/v1"],'
    '"authentication":[],"routes":{}}'
)

XMLRPC_GET = "XML-RPC server accepts POST requests only."

XMLRPC_FAULT = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<methodResponse>\n  <fault>\n    <value>\n'
    "      <struct>\n"
    "        <member><name>faultCode</name><value><int>403</int></value></member>\n"
    "        <member><name>faultString</name>"
    "<value><string>Incorrect username or password.</string></value></member>\n"
    "      </struct>\n    </value>\n  </fault>\n</methodResponse>\n"
)

#: Comme WordPress : l'administration sans session renvoie vers la connexion.
_REDIRECT_TO_LOGIN = (
    ("Location", "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1"),
    ("Cache-Control", "no-cache, must-revalidate, max-age=0"),
)


def route(method: str, target: str) -> Page:
    """Réponse à une requête. Ne dépend que de la méthode et du chemin, jamais du reste."""
    path, _, query = target.split("#", 1)[0].partition("?")
    path = path or "/"
    method = method.upper()

    if path in ("/", "/index.php"):
        # Énumération des auteurs : /?author=1 → /author/<identifiant>/, comme WordPress.
        # Seule la présence du paramètre compte ; sa valeur n'est jamais réutilisée.
        if query.startswith("author=") or "&author=" in query:
            return Page("301 Moved Permanently", headers=(("Location", f"/author/{BAIT_USER}/"),))
        return Page("200 OK", home_page())
    if path == f"/author/{BAIT_USER}/":
        return Page("200 OK", home_page())
    if path in ("/wp-json/wp/v2/users", "/wp-json/wp/v2/users/"):
        return Page("200 OK", WP_JSON_USERS, JSON)
    if path in ("/wp-json", "/wp-json/"):
        return Page("200 OK", WP_JSON_ROOT, JSON)
    if path == "/wp-login.php":
        if method == "POST":
            # Comme WordPress : 200 et le formulaire, avec un message d'erreur générique.
            return Page("200 OK", login_page(failed=True))
        return Page("200 OK", login_page())
    if path in ("/wp-admin", "/wp-admin/") or path.startswith("/wp-admin/index.php"):
        return Page("302 Found", headers=_REDIRECT_TO_LOGIN)
    if path == "/xmlrpc.php":
        if method == "POST":
            return Page("200 OK", XMLRPC_FAULT, "text/xml; charset=UTF-8")
        return Page("405 Method Not Allowed", XMLRPC_GET, "text/plain; charset=UTF-8")
    if path == "/readme.html":
        return Page("200 OK", README)
    if path == "/robots.txt":
        return Page("200 OK", ROBOTS, "text/plain; charset=UTF-8")
    if path == "/wp-content/themes/twentytwentyone/style.css":
        return Page("200 OK", STYLE, "text/css")
    return Page("404 Not Found", not_found_page())
