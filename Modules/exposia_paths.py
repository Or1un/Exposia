#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_paths.py — Résolution centralisée des chemins du projet Exposia.

Source de vérité UNIQUE de l'arborescence. Tous les modules (D_Data et R_Report)
importent ce fichier plutôt que de coder des chemins en dur ou des '../' relatifs
au dossier d'appel.

Arborescence :

    projet/
    ├── Parameters/                     fichiers de référence (CSV, CVSS, ...)
    ├── Modules/
    │   ├── exposia_paths.py            <- ce fichier
    │   ├── D_Data/                     D1, D2, D3  (production de données)
    │   └── R_Report/                   R0..R13     (rapport et exports)
    └── Result/
        └── <campagne>/                 ex. exemple/
            ├── data/                   fichiers internes : CSV + PDF intermédiaires,
            │                           run_summary.json, caches, campaign.json
            │                           (domaine propriétaire du dossier)
            └── livrables               Rapport_Final_*.pdf, Exposia_*_presentation.csv,
                                        Exposia_*_results.json, Exposia_*_digest.md

Nom de campagne : nom du domaine enregistré, sans suffixe public
(www.exemple.com -> exemple, shop.exemple.co.uk -> exemple). Si ce nom
est déjà pris par un AUTRE domaine (x.com analysé, puis x.fr), le suffixe est
ajouté pour ne jamais écraser une campagne existante (x.fr -> x_fr).

Les chemins sont résolus à partir de __file__ : les scripts fonctionnent quel que
soit le répertoire depuis lequel ils sont lancés.
"""

import csv
import glob
import json
import os
import re

__all__ = [
    "project_root", "parameters_dir", "parameter", "results_root",
    "normalize_domain", "split_domain", "main_domain", "domain_dir", "data_dir",
    "latest_domain_dir", "resolve_data_dir",
]

CAMPAIGN_MARKER = "campaign.json"   # dans data/ (à la racine de la campagne avant novembre 2026)

# Suffixes publics à deux niveaux les plus courants : repli utilisé uniquement si
# la bibliothèque tldextract (liste publique complète, embarquée, hors ligne)
# n'est pas installée.
_FALLBACK_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.za", "co.jp", "ne.jp", "or.jp",
    "co.kr", "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.sg",
    "co.in", "co.il", "co.ma", "net.ma", "org.ma", "gov.ma", "ac.ma", "press.ma",
    "com.tn", "com.dz", "com.eg", "gouv.fr", "asso.fr", "com.fr", "co.id",
}

_extractor = None


def project_root():
    """
    Racine du projet : premier dossier parent contenant 'Modules'.
    Repli : deux niveaux au-dessus de ce fichier (Modules/exposia_paths.py).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    current = here
    while True:
        if os.path.isdir(os.path.join(current, "Modules")):
            return current
        parent = os.path.dirname(current)
        if parent == current:          # racine du système atteinte
            return os.path.dirname(here)
        current = parent


def parameters_dir():
    """Dossier Parameters/ (fichiers de référence)."""
    return os.path.join(project_root(), "Parameters")


def parameter(*parts):
    """Chemin absolu d'un fichier de Parameters/ : parameter('CVSS', 'CVSS_step1.csv')."""
    return os.path.join(parameters_dir(), *parts)


def results_root():
    """Dossier Result/ (créé si absent)."""
    path = os.path.join(project_root(), "Result")
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Domaine -> nom de campagne
# ---------------------------------------------------------------------------

def normalize_domain(domain):
    """
    Forme canonique d'un domaine saisi : minuscules, sans schéma, chemin, port
    ni point final ('https://WWW.Exemple.co.uk:443/x' -> 'www.exemple.co.uk').
    """
    d = str(domain or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)   # schéma (https://, http://...)
    d = d.split("/", 1)[0].split("?", 1)[0]       # chemin, requête
    d = d.rsplit("@", 1)[-1]                       # identifiants éventuels
    if not d.startswith("["):                      # port (hors IPv6 entre crochets)
        d = d.split(":", 1)[0]
    return d.strip(".")


def _get_extractor():
    """Extracteur tldextract hors ligne (liste publique embarquée), ou None."""
    global _extractor
    if _extractor is None:
        try:
            import tldextract
            # suffix_list_urls=() : aucune requête réseau, liste embarquée uniquement.
            _extractor = tldextract.TLDExtract(suffix_list_urls=())
        except Exception:
            _extractor = False
    return _extractor or None


def split_domain(domain):
    """
    (nom enregistré, suffixe public) : 'shop.exemple.co.uk' -> ('exemple', 'co.uk').
    Pour une IP ou un nom sans suffixe : (valeur normalisée, '').
    """
    d = normalize_domain(domain)
    if not d or re.fullmatch(r"[\d.]+", d) or ":" in d:
        return d, ""
    extractor = _get_extractor()
    if extractor is not None:
        parts = extractor(d)
        if parts.domain and parts.suffix:
            return parts.domain, parts.suffix
        return d, ""
    labels = d.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _FALLBACK_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return d, ""


def _registered_domain(domain):
    """Domaine enregistré complet : 'www.exemple.co.uk' -> 'exemple.co.uk'."""
    name, suffix = split_domain(domain)
    return f"{name}.{suffix}" if suffix else name


def _safe_name(value):
    """Nom de dossier / fichier sûr (lettres, chiffres, '-', '_')."""
    return re.sub(r"[^\w-]+", "_", value, flags=re.UNICODE).strip("_") or "campagne"


def _marker_paths(campaign_path):
    """(emplacement actuel, ancien emplacement) du marqueur de propriété."""
    return (os.path.join(campaign_path, "data", CAMPAIGN_MARKER),
            os.path.join(campaign_path, CAMPAIGN_MARKER))


def _migrate_marker(campaign_path):
    """
    Déplace un marqueur resté à la racine de la campagne (ancien emplacement)
    dans data/ ; s'il existe déjà dans data/, l'ancien est supprimé. Idempotent.
    Retourne l'emplacement actuel du marqueur.
    """
    marker, legacy = _marker_paths(campaign_path)
    if os.path.exists(legacy):
        try:
            os.makedirs(os.path.dirname(marker), exist_ok=True)
            if os.path.exists(marker):
                os.remove(legacy)
            else:
                os.replace(legacy, marker)
        except OSError:
            pass
    return marker


def _campaign_owner(campaign_path):
    """
    Domaine propriétaire d'un dossier de campagne : data/campaign.json, puis
    campaign.json à la racine (emplacement d'avant novembre 2026), sinon (dossier
    créé avant ce marqueur) colonne Domain du fichier Exposia_*.csv ; None si inconnu.
    """
    for marker in _marker_paths(campaign_path):
        try:
            with open(marker, encoding="utf-8") as f:
                owner = json.load(f).get("domain")
            if owner:
                return _registered_domain(owner)
        except (OSError, ValueError, AttributeError):
            continue
    for path in glob.glob(os.path.join(campaign_path, "data", "Exposia_*.csv")):
        try:
            with open(path, encoding="utf-8-sig", newline="") as f:
                row = next(csv.DictReader(f, delimiter=";"), None)
            owner = row and (row.get("Domain") or row.get("domain"))
            if owner and owner not in ("#N/A", "nan"):
                return _registered_domain(owner)
        except (OSError, csv.Error, UnicodeDecodeError):
            continue
    return None


def main_domain(domain):
    """
    Nom de campagne d'un domaine (nom du dossier Result/<campagne>/ et des
    fichiers Exposia_<campagne>.csv) :

      • nom enregistré sans suffixe public : 'www.exemple.com' -> 'exemple',
        'shop.exemple.co.uk' -> 'exemple' ;
      • si ce nom appartient déjà à un AUTRE domaine (x.com puis x.fr), le suffixe
        est ajouté : 'x_fr'. Une campagne existante n'est jamais écrasée.

    Fonction de lecture seule : le dossier est réservé (campaign.json) par domain_dir().
    """
    name, suffix = split_domain(domain)
    registered = f"{name}.{suffix}" if suffix else name
    base = _safe_name(name)
    candidates = [base]
    if suffix:
        candidates.append(_safe_name(f"{name}_{suffix}"))
    for candidate in candidates:
        owner = _campaign_owner(os.path.join(results_root(), candidate))
        if owner is None or owner == registered:
            return candidate
    # Cas extrême (les deux noms déjà pris par d'autres domaines) : nom complet unique.
    return _safe_name(registered.replace(".", "_")) + "_campagne"


def domain_dir(domain, create=True):
    """
    Result/<campagne>/ — dossier de campagne (contient le livrable PDF).
    À la création, enregistre le domaine propriétaire dans data/campaign.json ;
    un marqueur resté à la racine (ancien emplacement) y est déplacé.
    """
    path = os.path.join(results_root(), main_domain(domain))
    if create:
        os.makedirs(os.path.join(path, "data"), exist_ok=True)
        marker = _migrate_marker(path)
        try:
            if not os.path.exists(marker):
                with open(marker, "w", encoding="utf-8") as f:
                    json.dump({"domain": _registered_domain(domain)}, f, ensure_ascii=False)
        except OSError:
            pass
    return path


def data_dir(domain, create=True):
    """Result/<campagne>/data/ — CSV et PDF intermédiaires."""
    path = os.path.join(domain_dir(domain, create=create), "data")
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def latest_domain_dir():
    """
    Dossier de campagne le plus récent sous Result/ (repli quand aucun
    --result-dir n'est fourni : permet de lancer un script isolément).
    Retourne None si aucune campagne n'existe.
    """
    candidates = [d for d in glob.glob(os.path.join(results_root(), "*")) if os.path.isdir(d)]
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def resolve_data_dir(result_dir=None, domain=None):
    """
    Résolution standard utilisée par tous les scripts, par ordre de priorité :

      1. --result-dir explicite (chemin de la campagne, ex. Result/exemple)
      2. domaine fourni       -> Result/<campagne>/data
      3. repli                -> data/ de la campagne la plus récente

    Lève FileNotFoundError si rien ne peut être déterminé.
    """
    if result_dir:
        path = os.path.join(os.path.abspath(result_dir), "data")
        os.makedirs(path, exist_ok=True)
        _migrate_marker(os.path.dirname(path))
        return path

    if domain:
        return data_dir(domain)

    latest = latest_domain_dir()
    if latest:
        path = os.path.join(latest, "data")
        os.makedirs(path, exist_ok=True)
        _migrate_marker(latest)
        return path

    raise FileNotFoundError(
        f"Aucune campagne trouvée dans {results_root()} : "
        "précisez --result-dir ou lancez d'abord la découverte d'actifs (D1)."
    )
