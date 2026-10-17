#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R10_presentation_export.py — Vue « présentation » de l'export Exposia.

Étape finale du pipeline (après R9). Produit le livrable CSV lisible à partir
du fichier de travail et le dépose à la RACINE de la campagne, à côté du
Rapport_Final PDF — les deux livrables (PDF + CSV) au même endroit, les
intermédiaires restant dans data/.

Prend un fichier de travail Exposia_*.csv (format doublement explosé :
1 exposition -> N narratifs d'attaque -> N mesures de mitigation) et le
ré-agrège en une vue LISIBLE à plat, à la granularité EXPOSITION × CVE :
une ligne par couple (subdomain, ip_address, port, cve).

Les scénarios génériques de service (type PORT) ne portent pas de CVE : ils sont
regroupés sur la ligne « exposition sans CVE » du service concerné.

NON DESTRUCTIF : lit le CSV de travail, écrit un NOUVEAU fichier
Exposia_<domaine>_presentation.csv. Le fichier de travail (consommé par
les modules R) n'est jamais modifié.

Dans chaque ligne :
  - les colonnes d'exposition et de vulnérabilité sont reprises telles quelles
    (elles sont constantes au sein d'un couple exposition×CVE) ;
  - la qualification retenue est la plus élevée du groupe ;
  - les chemins d'attaque (reconnaissance / exploitation / impact) sont repliés,
    dédupliqués, et numérotés s'il y en a plusieurs ;
  - les mesures de mitigation sont repliées : décompte, liste d'IDs, priorité
    maximale, et détail « ID (priorité) : mesure organisationnelle ».

Le détail complet par mesure reste disponible dans
mitigation_prioritization_enhanced.csv (vue complémentaire, par mesure).
"""

import argparse
import glob
import json
import os
import sys

import pandas as pd

# Résolution centralisée des chemins Exposia (optionnelle) : présente dans
# l'arborescence du projet, absente en exécution isolée. Le script fonctionne
# dans les deux cas — exposia_paths ne sert qu'à l'auto-résolution de campagne.
try:
    _sys_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _sys_dir not in sys.path:
        sys.path.insert(0, _sys_dir)
    import exposia_paths  # noqa: E402
except Exception:
    exposia_paths = None

# UI console centralisée (même rendu que R1..R9). Absente hors du projet :
# repli sur un shim minimal pour que le script reste exécutable en isolé.
try:
    import exposia_ui  # noqa: E402,F401
    from exposia_ui import ModernUI  # noqa: E402
except Exception:
    class ModernUI:  # shim de secours — API réduite à ce que R10 utilise
        @staticmethod
        def status(message, state="info"):
            print(f"[{state}] {message}")

        @staticmethod
        def section(title):
            print(f"\n── {title} ──")

        @staticmethod
        def section_end():
            print()

        @staticmethod
        def print_result(title, value, unit=""):
            print(f"  • {title}: {value}{unit}")


# --- Vocabulaires d'ordonnancement (pour tri et agrégats) --------------------
QUALIF_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
PRIORITY_RANK = {'CRITIQUE': 4, 'HAUTE': 3, 'MOYENNE': 2, 'FAIBLE': 1}

# Séparateur interne des champs repliés. Volontairement différent du délimiteur
# CSV (';') pour rester lisible une fois ouvert dans un tableur.
LIST_SEP = ' | '

# Colonnes d'exposition/vulnérabilité : constantes au sein d'un couple
# exposition×CVE, reprises telles quelles (première occurrence).
PASSTHROUGH_COLS = [
    'domain', 'subdomain', 'ip_address', 'port', 'classification',
    'service', 'category', 'cve', 'cve_year', 'cvss_score', 'cvss_version',
    'cvss_vector', 'epss_score', 'exploits_count', 'exploit_references',
    'business_impact', 'exposia_qualification',
]

# Clé d'agrégation = exposition × vulnérabilité.
GROUP_KEY = ['subdomain', 'ip_address', 'port', 'cve']

NA_TOKENS = {'', '#n/a', 'n/a', 'none', 'no data', 'nan'}

# Criticité globale du domaine (criticality_rating calculé par D1) : mêmes
# libellés que la page de garde (R5).
RATING_LABELS = {'critical': 'Critique', 'high': 'Élevé', 'medium': 'Moyen', 'low': 'Faible'}


def _is_empty(value):
    """Vrai pour une cellule vide / marqueur d'absence."""
    return str(value).strip().lower() in NA_TOKENS


def find_exposia_csv(data_dir):
    """Dernier Exposia_*.csv du dossier, en excluant une éventuelle vue présentation."""
    candidates = [
        f for f in glob.glob(os.path.join(data_dir, 'Exposia_*.csv'))
        if not f.endswith('_presentation.csv')
    ]
    if not candidates:
        raise FileNotFoundError(
            f"Aucun fichier Exposia_*.csv trouvé dans {os.path.abspath(data_dir)}")
    return max(candidates, key=os.path.getmtime)


def fold_attack_paths(group):
    """
    Replie les chemins d'attaque d'un couple exposition×CVE.

    Retourne (types, count, reconnaissance, exploitation, impact) où les trois
    narratifs sont dédupliqués et, s'il y a plusieurs chemins, numérotés.
    """
    # Un « chemin » = triplet (reconnaissance, exploitation, impact) non vide.
    seen, paths, types = set(), [], []
    for _, row in group.iterrows():
        recon, expl, imp = row['reconnaissance'], row['exploitation'], row['impact']
        if _is_empty(recon) and _is_empty(expl) and _is_empty(imp):
            continue
        key = (recon, expl, imp)
        if key in seen:
            continue
        seen.add(key)
        paths.append(key)
        t = str(row.get('attack_path_type', '')).strip()
        if t and t not in types:
            types.append(t)

    if not paths:
        return '', 0, '', '', ''

    if len(paths) == 1:
        r, e, i = paths[0]
        return LIST_SEP.join(types), 1, r, e, i

    # Plusieurs chemins : numéroter chaque narratif pour garder la correspondance.
    recon = LIST_SEP.join(f"[{n}] {p[0]}" for n, p in enumerate(paths, 1))
    expl = LIST_SEP.join(f"[{n}] {p[1]}" for n, p in enumerate(paths, 1))
    imp = LIST_SEP.join(f"[{n}] {p[2]}" for n, p in enumerate(paths, 1))
    return LIST_SEP.join(types), len(paths), recon, expl, imp


def fold_mitigations(group):
    """
    Replie les mesures de mitigation d'un couple exposition×CVE.

    Retourne (count, ids, priority_max, detail) en dédoublonnant par mitigation_id.
    """
    seen, measures = set(), []
    for _, row in group.iterrows():
        mid = str(row.get('mitigation_id', '')).strip()
        if _is_empty(mid) or mid in seen:
            continue
        seen.add(mid)
        measures.append({
            'id': mid,
            'priority': str(row.get('priority', '')).strip(),
            'org': str(row.get('organizational_measure', '')).strip(),
        })

    if not measures:
        return 0, '', '', ''

    # Trier par priorité décroissante pour une lecture « du plus urgent au moins ».
    measures.sort(key=lambda m: PRIORITY_RANK.get(m['priority'].upper(), 0), reverse=True)
    ids = ', '.join(m['id'] for m in measures)
    priority_max = measures[0]['priority']
    detail = LIST_SEP.join(
        f"{m['id']} ({m['priority']}) : {m['org']}" if m['org'] else f"{m['id']} ({m['priority']})"
        for m in measures
    )
    return len(measures), ids, priority_max, detail


def max_qualification(group):
    """Qualification la plus élevée d'un groupe (Critical > High > Medium > Low)."""
    quals = [str(q).strip() for q in group['exposia_qualification'] if str(q).strip() in QUALIF_ORDER]
    if not quals:
        return str(group['exposia_qualification'].iloc[0])
    return min(quals, key=lambda q: QUALIF_ORDER[q])


def build_presentation(df):
    """Construit le DataFrame de présentation à partir du CSV de travail."""
    df = df.fillna('')
    # Sécuriser la présence des colonnes attendues.
    for col in PASSTHROUGH_COLS + ['reconnaissance', 'exploitation', 'impact',
                                   'attack_path_type', 'mitigation_id',
                                   'priority', 'organizational_measure']:
        if col not in df.columns:
            df[col] = ''

    # Anciens fichiers : une ligne PORT peut porter la CVE de sa ligne source.
    # On la rattache à l'exposition sans CVE.
    port_rows = df['attack_path_type'].astype(str).str.strip().str.upper() == 'PORT'
    if port_rows.any():
        for col in ['cve', 'cve_year', 'cvss_score', 'cvss_version', 'cvss_vector',
                    'epss_score', 'exploit_references']:
            df.loc[port_rows, col] = ''
        df.loc[port_rows, 'exploits_count'] = '0'

    records = []
    for _, group in df.groupby(GROUP_KEY, dropna=False, sort=False):
        base = group.iloc[0]
        rec = {col: base[col] for col in PASSTHROUGH_COLS}
        rec['exposia_qualification'] = max_qualification(group)

        types, n_paths, recon, expl, imp = fold_attack_paths(group)
        rec['attack_path_types'] = types
        rec['attack_paths_count'] = n_paths
        rec['reconnaissance'] = recon
        rec['exploitation'] = expl
        rec['impact'] = imp

        n_mit, ids, prio_max, detail = fold_mitigations(group)
        rec['mitigation_count'] = n_mit
        rec['mitigation_ids'] = ids
        rec['mitigation_priority_max'] = prio_max
        rec['mitigations'] = detail

        records.append(rec)

    out = pd.DataFrame.from_records(records)

    # Tri présentation : criticité décroissante, puis EPSS décroissant.
    out['_q'] = out['exposia_qualification'].map(QUALIF_ORDER).fillna(99)
    out['_e'] = pd.to_numeric(out['epss_score'], errors='coerce').fillna(-1)
    out = out.sort_values(['_q', '_e'], ascending=[True, False]).drop(columns=['_q', '_e'])
    return out.reset_index(drop=True)


def _format_duration(seconds):
    """Secondes -> 'HH:MM:SS'."""
    seconds = max(0, int(round(float(seconds))))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _norm_port(value):
    """Normalise un port : '443.0' -> '443' ; renvoie None si non numérique."""
    v = str(value).strip()
    try:
        return str(int(float(v)))
    except (ValueError, TypeError):
        return None


def compute_kpis(df, out):
    """
    Valeurs clés de synthèse, aux définitions alignées sur R2 :
      - sous-domaines : hors domaine racine (exemple.com n'est pas un sous-domaine) ;
      - adresses IP : toutes les IP résolues (indépendamment d'un port ouvert) ;
      - services exposés : couples (IP, port) distincts réellement exposés ;
      - services présumés sensibles : couples (IP, port) classés « Internal »
        (service habituellement réservé à un usage interne) ;
    """
    d = df.fillna('')
    NA = ['', '#N/A', 'N/A', 'None', 'nan']
    NA_IP = NA + ['No IP found']

    domain = str(d['domain'].iloc[0]).strip() if 'domain' in d and len(d) else ''

    # Sous-domaines : exclure le domaine racine lui-même
    sub = d['subdomain'].astype(str).str.strip()
    n_subdomains = sub[~sub.isin(NA) & (sub != domain)].nunique()

    # IP : toutes les IP résolues (pas de filtre sur le port).
    ip = d['ip_address'].astype(str).str.strip()
    all_ips = set(ip[~ip.isin(NA_IP)])

    # Services exposés : couples (IP, port) distincts (option B)
    port_n = d['port'].map(_norm_port)
    valid = d[~ip.isin(NA_IP) & port_n.notna()].copy()
    valid['_port'] = port_n[valid.index]
    services = valid[['ip_address', '_port']].drop_duplicates()
    cat = valid['category'].astype(str).str.strip()
    n_categories = cat[~cat.isin(NA)].nunique()

    # Services présumés sensibles (classification « Internal »)
    is_internal = valid['classification'].astype(str).str.strip().str.upper() == 'INTERNAL'
    sensitive = valid[is_internal][['ip_address', '_port']].drop_duplicates()

    # CVE uniques
    cve = d['cve'].astype(str).str.strip()
    n_cves = cve[~cve.isin(NA)].nunique()

    # Exploits publics uniques
    exploits = set()
    for raw in d['exploit_references'].astype(str):
        raw = raw.strip()
        if not raw or raw in ('#N/A', 'None', 'nan'):
            continue
        for part in raw.split(','):
            p = part.strip()
            if p and p.lower() != 'no unique public exploit found':
                exploits.add(p)

    return {
        'subdomains': int(n_subdomains),
        'total_ips': len(all_ips),
        'services': len(services),
        'sensitive_services': len(sensitive),
        'categories': int(n_categories),
        'cves': int(n_cves),
        'exploits': len(exploits),
    }


def load_global_rating(data_dir):
    """
    Criticité globale du domaine : criticality_rating de run_summary.json (écrit
    par D1, la même valeur que la page de garde). Renvoie le libellé français,
    ou None si le fichier ou la valeur est absent.
    """
    try:
        with open(os.path.join(data_dir, 'run_summary.json'), encoding='utf-8') as f:
            rating = str(json.load(f).get('criticality_rating') or '').strip().lower()
    except (OSError, ValueError):
        return None
    return RATING_LABELS.get(rating)


def print_summary(kpis, elapsed_seconds=None, global_rating=None):
    """Affiche la section de synthèse (même chrome que R1..R9)."""
    ModernUI.section("SYNTHÈSE")
    ModernUI.print_result("Sous-domaines découverts", kpis['subdomains'])
    ModernUI.print_result("Adresses IP", kpis['total_ips'])
    ModernUI.print_result("Services exposés", f"{kpis['services']} ({kpis['categories']} catégories)")
    ModernUI.print_result("Services présumés sensibles", kpis['sensitive_services'])
    ModernUI.print_result("CVE uniques", kpis['cves'])
    ModernUI.print_result("Exploits publics", kpis['exploits'])
    ModernUI.print_result("Criticité globale", global_rating or "non disponible (run_summary.json absent)")
    if elapsed_seconds is not None:
        ModernUI.print_result("Temps de traitement", _format_duration(elapsed_seconds))
    ModernUI.section_end()


def resolve_output_path(in_path, explicit_output):
    """
    Emplacement du livrable : à la RACINE de la campagne, à côté du Rapport_Final
    PDF (même logique que R9). La racine est le dossier PARENT de data/, où vit
    le fichier de travail. En exécution isolée (entrée hors d'un data/), on
    retombe sur le dossier de l'entrée.
    """
    if explicit_output:
        return explicit_output
    in_dir = os.path.dirname(os.path.abspath(in_path))
    # Si l'entrée est dans un dossier 'data', le livrable monte d'un cran.
    campaign_root = os.path.dirname(in_dir) if os.path.basename(in_dir) == 'data' else in_dir
    base = os.path.basename(in_path)[:-4]  # 'Exposia_<domaine>'
    return os.path.join(campaign_root, base + '_presentation.csv')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Génère la vue présentation (exposition×CVE) d'un export Exposia. "
                    "Livrable déposé à la racine de la campagne, à côté du rapport final.")
    parser.add_argument('-r', '--result-dir', default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/ "
                             "(nécessite exposia_paths).")
    parser.add_argument('-i', '--input', default=None,
                        help="Fichier Exposia_*.csv explosé (défaut : le plus récent du data-dir)")
    parser.add_argument('-d', '--data-dir', default=None,
                        help="Dossier contenant l'entrée Exposia_*.csv (défaut : data/ de la campagne)")
    parser.add_argument('-o', '--output', default=None,
                        help="Fichier de sortie (défaut : racine de campagne / "
                             "<entrée>_presentation.csv)")
    parser.add_argument('--elapsed', type=float, default=None,
                        help="Durée de traitement du pipeline en secondes (passée par "
                             "run_pipeline.sh, hors étape interactive D3) ; affichée dans la synthèse.")
    args = parser.parse_args(argv)

    # Résolution de l'entrée : -i explicite > -d > auto (exposia_paths) > dossier courant.
    if args.input:
        in_path = args.input
    else:
        data_dir = args.data_dir
        if data_dir is None and exposia_paths is not None:
            data_dir = exposia_paths.resolve_data_dir(args.result_dir, None)
        in_path = find_exposia_csv(data_dir or '.')

    out_path = resolve_output_path(in_path, args.output)

    df = pd.read_csv(in_path, sep=';', dtype=str)
    ModernUI.status(f"Lecture du fichier de travail : {os.path.basename(in_path)} "
                    f"({len(df)} lignes)", "info")

    out = build_presentation(df)
    # utf-8-sig : BOM UTF-8, pour qu'Excel (Windows) affiche correctement les accents.
    out.to_csv(out_path, sep=';', index=False, encoding='utf-8-sig')

    with_cve = int((out['cve'].astype(str).str.strip() != '').sum())
    ModernUI.status(f"Vue présentation écrite : {os.path.basename(out_path)} "
                    f"({len(out)} lignes exposition×CVE, dont {with_cve} avec CVE)", "success")

    print_summary(compute_kpis(df, out), args.elapsed,
                  load_global_rating(os.path.dirname(os.path.abspath(in_path))))
    return 0


if __name__ == '__main__':
    sys.exit(main())