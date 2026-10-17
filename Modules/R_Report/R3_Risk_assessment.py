#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de Rapport Risk Assessment PDF
Lit automatiquement le fichier Exposia_*.csv et génère un rapport PDF
Version optimisée avec WeasyPrint pour un rendu PDF professionnel

Les chemins d'attaque présentés sont des SCÉNARIOS TYPES (assumé : rapport de
sensibilisation produit sans analyste) :
  • type CVE  : scénario dérivé du vecteur CVSS de la vulnérabilité, affiché avec sa CVE ;
  • type PORT : scénario représentatif des attaques courantes sur le service exposé,
                affiché SANS CVE (il ne décrit pas une vulnérabilité précise).
"""
import csv
from html import escape as esc  # échappement HTML de toute valeur injectée dans un rapport
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
try:  # le thème peut être nommé report_theme.py ou R0_report_theme.py
    import report_theme
except ImportError:
    import R0_report_theme as report_theme
import os
import glob
from datetime import datetime
from collections import defaultdict, Counter
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration

# Rang de l'impact métier du service (criticité dans services_list.csv), utilisé
# pour départager deux actifs de même qualification : à qualification égale, un
# kubelet (CRITIQUE) passe devant une application web (HAUTE).
IMPACT_ORDER = {'CRITIQUE': 0, 'HAUTE': 1, 'MOYENNE': 2, 'FAIBLE': 3}

class RiskAssessmentPDFGenerator:
    def __init__(self, data_dir=None):
        # Répertoire des CSV d'entrée : dossier courant par défaut, surchargeable.
        self.data_dir = data_dir or "."
        self.config = {
            'thresholds': {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low'
            },
            'level_icons': {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            },
            'rank_emojis': ['🥇', '🥈', '🥉', '4', '5', '6', '7', '8', '9', '10']
        }

    def find_csv_file(self):
        """Trouve le fichier Exposia_*.csv le plus récent dans self.data_dir."""
        motif = os.path.join(self.data_dir, "Exposia_*.csv")
        csv_files = glob.glob(motif)
        if not csv_files:
            raise FileNotFoundError(
                f"Aucun fichier Exposia_*.csv trouvé dans {os.path.abspath(self.data_dir)}")
        return max(csv_files, key=os.path.getmtime)

    def load_csv_data(self, filename):
        """
        Charge et parse les données CSV.

        Tolère le délimiteur (';', ',' ou tab), le BOM (utf-8-sig) et DEUX conventions
        de nommage : noms d'affichage (sortie asset_discovery) et noms internes
        (fichier enrichi par mitigation_plan). Les lignes sont normalisées vers les
        noms d'affichage utilisés par le générateur.
        """
        aliases = {
            'Subdomain': ['Subdomain', 'subdomain'],
            'IP Address': ['IP Address', 'ip_address'],
            'Port': ['Port', 'port'],
            'Catégorie': ['Catégorie', 'category'],
            'Vulnerability (CVE)': ['Vulnerability (CVE)', 'cve'],
            'Number of Exploits': ['Number of Exploits', 'exploits_count'],
            'Exposia - Qualification': ['Exposia - Qualification', 'exposia_qualification'],
            'EPSS Score': ['EPSS Score', 'epss_score'],
            'Reconnaissance': ['Reconnaissance', 'reconnaissance'],
            'Exploitation': ['Exploitation', 'exploitation'],
            'Impact': ['Impact', 'impact'],
            'Exploits': ['Exploits', 'Exploits', 'exploit_references'],
        }
        # Colonnes optionnelles (absentes des fichiers anciens).
        optional_aliases = {
            'Attack_Path_Type': ['Attack_Path_Type', 'attack_path_type'],
            'Impact business / opérationnel': ['Impact business / opérationnel', 'business_impact'],
        }
        try:
            best = None
            for delimiter in (';', ',', '\t'):
                with open(filename, 'r', encoding='utf-8-sig', newline='') as csvfile:
                    reader = csv.DictReader(csvfile, delimiter=delimiter)
                    fieldnames = reader.fieldnames or []
                    resolved, missing = {}, []
                    for canon, options in aliases.items():
                        found = next((o for o in options if o in fieldnames), None)
                        if found:
                            resolved[canon] = found
                        else:
                            missing.append(canon)
                    if not missing:
                        for canon, options in optional_aliases.items():
                            found = next((o for o in options if o in fieldnames), None)
                            if found:
                                resolved[canon] = found
                        data = []
                        for row in reader:
                            for canon, actual in resolved.items():
                                if canon != actual:
                                    row[canon] = row.get(actual)
                            data.append(row)
                        return data
                    if best is None or len(missing) < best[0]:
                        best = (len(missing), delimiter, fieldnames, missing)

            raise ValueError(
                "Colonnes requises introuvables (ni noms d'affichage ni noms internes). "
                f"Meilleur essai (délimiteur '{best[1]}') — manquantes : "
                f"{', '.join(best[3])}. Colonnes détectées : {best[2]}"
            )
        except Exception as e:
            raise Exception(f"Erreur lors de la lecture du CSV: {str(e)}")

    @staticmethod
    def _is_port_path(row):
        """Vrai pour un scénario générique de service (type PORT)."""
        return str(row.get('Attack_Path_Type', '') or '').strip().upper() == 'PORT'

    @classmethod
    def _path_cve(cls, row):
        """
        CVE d'un scénario ('' pour un scénario générique de service).

        Fait partie de la clé d'unicité : deux CVE distinctes dont le texte du
        scénario est identique (même impact, même vecteur) restent deux scénarios.
        Sans elle, la première rencontrée écrasait l'autre, y compris une CVE
        Critical remplacée par une CVE Medium.
        """
        if cls._is_port_path(row):
            return ''
        cve = str(row.get('Vulnerability (CVE)', '') or '').strip()
        return '' if cve in ('#N/A', 'None', 'No data', 'nan') else cve

    @staticmethod
    def _format_port(port):
        """'80.0' -> '80' (ports stockés en float par pandas dans le fichier enrichi)."""
        sp = str(port).strip()
        try:
            return str(int(float(sp)))
        except (TypeError, ValueError):
            return sp

    @staticmethod
    def _format_ips(ips):
        """Liste d'IP lisible : 2 adresses au plus, puis « +N »."""
        if not ips:
            return '&mdash;'
        shown = ', '.join(esc(str(ip)) for ip in ips[:2])
        return shown + (f" +{len(ips) - 2}" if len(ips) > 2 else '')

    @staticmethod
    def _impact_rank(rows):
        """
        Rang de l'impact métier le plus élevé parmi les lignes d'un actif
        (0 = CRITIQUE … 3 = FAIBLE, 4 = inconnu, ex. port sans service connu).
        """
        ranks = [IMPACT_ORDER.get(str(r.get('Impact business / opérationnel', '') or '').strip().upper(), 4)
                 for r in rows]
        return min(ranks) if ranks else 4

    def build_scenario_cards(self, assets, limit=3):
        """
        Cartes « scénarios types », une par hôte et par type de service.

        Un même logiciel exposé sur plusieurs ports (80 / 443) produit les mêmes
        scénarios : les actifs d'un même sous-domaine et d'une même catégorie de
        service sont regroupés sur une seule carte (ports cumulés, scénarios
        dédupliqués, les 3 plus critiques affichés). Deux sous-domaines distincts
        ne sont réunis que s'ils partagent une IP ET présentent exactement les
        mêmes scénarios (même serveur publié sous deux noms) : des sites distincts
        hébergés derrière un même CDN restent séparés.
        """
        def signature(paths):
            return tuple(
                (p.get('Vulnerability (CVE)', ''), p.get('Reconnaissance', ''),
                 p.get('Exploitation', ''), p.get('Impact', ''))
                for p in paths
            )

        cards = []
        for asset in assets:
            if asset['attack_paths_count'] == 0:
                continue
            asset_sig = signature(self.get_top_attack_paths_for_asset(asset['all_attack_paths']))
            target = None
            for card in cards:
                if card['service'] != asset['service']:
                    continue
                same_name = asset['subdomain_display'] in card['subdomains']
                same_server = (set(asset['ip_addresses']) & set(card['ip_addresses'])
                               and asset_sig == card['first_signature'])
                if same_name or same_server:
                    target = card
                    break
            if target is None:
                if len(cards) >= limit:
                    continue
                target = {
                    'first_signature': asset_sig,
                    'subdomains': [], 'ip_addresses': [], 'ports': [],
                    'paths': {}, 'service': asset['service'], 'level': asset['level'],
                    'rank': asset['criticality_rank'],
                }
                cards.append(target)
            if asset['subdomain_display'] not in target['subdomains']:
                target['subdomains'].append(asset['subdomain_display'])
            for ip in asset['ip_addresses']:
                if ip not in target['ip_addresses']:
                    target['ip_addresses'].append(ip)
            if asset['port'] not in target['ports']:
                target['ports'].append(asset['port'])
            for path in asset['all_attack_paths']:
                key = (self._path_cve(path), path.get('Reconnaissance', ''),
                       path.get('Exploitation', ''), path.get('Impact', ''))
                target['paths'].setdefault(key, path)
            if asset['criticality_rank'] < target['rank']:
                target['rank'], target['level'] = asset['criticality_rank'], asset['level']

        for card in cards:
            card['top_paths'] = self.get_top_attack_paths_for_asset(list(card['paths'].values()))
        return cards

    def normalize_subdomains(self, data):
        for row in data:
            subdomain = row['Subdomain']
            if subdomain.startswith('www.www.'):
                subdomain = subdomain.replace('www.www.', 'www.')
            row['subdomain_display'] = subdomain
            subdomain_for_grouping = subdomain
            if subdomain.startswith('www.'):
                subdomain_for_grouping = subdomain[4:]
            row['Subdomain'] = subdomain_for_grouping
        return data

    def count_unique_cves(self, csv_data):
        """Compte les CVE uniques"""
        unique_cves = set()
        for row in csv_data:
            cve = row.get('Vulnerability (CVE)', '#N/A')
            if cve and cve not in ['#N/A', 'None', 'No data', '']:
                unique_cves.add(cve)
        return len(unique_cves)

    def count_unique_exploits(self, csv_data):
        """Compte le nombre d'exploits publics uniques."""
        unique_exploits = set()
        for row in csv_data:
            exploits = (row.get('Exploits', '') or '').strip()
            if exploits and exploits not in ('#N/A', 'None', '', 'No unique public exploit found'):
                exploits_list = exploits.split(',') if ',' in exploits else [exploits]
                for exploit in exploits_list:
                    unique_exploits.add(exploit.strip())
        return len(unique_exploits)

    def count_unique_attack_paths(self, csv_data):
        """Compte les chemins d'attaque uniques basés sur reconnaissance + exploitation + impact"""
        unique_paths = set()
        for row in csv_data:
            reconnaissance = row.get('Reconnaissance', '').strip()
            exploitation = row.get('Exploitation', '').strip()
            impact = row.get('Impact', '').strip()
            if (reconnaissance and reconnaissance != '#N/A' and
                exploitation and exploitation != '#N/A' and
                impact and impact != '#N/A'):
                path_key = f"{self._path_cve(row)}|{reconnaissance}|{exploitation}|{impact}"
                unique_paths.add(path_key)
        return len(unique_paths)

    def process_data(self, csv_data):
        """Traite les données CSV avec agrégation et scoring"""
        csv_data = self.normalize_subdomains(csv_data)
        # Un actif = (sous-domaine, port). Les différentes IP d'un même nom (IPv4 /
        # IPv6, adresses multiples d'un CDN) exposent le même service : elles sont
        # fusionnées au lieu de produire une ligne par adresse.
        for row in csv_data:
            row['asset_key'] = f"{row['Subdomain']} / {self._format_port(row['Port'])}"
        asset_groups = defaultdict(list)
        for row in csv_data:
            asset_groups[row['asset_key']].append(row)
        processed_assets = []
        for asset_key, attack_paths in asset_groups.items():
            base_info = attack_paths[0]
            unique_paths = {}
            for path in attack_paths:
                reconnaissance = path.get('Reconnaissance', '').strip()
                exploitation = path.get('Exploitation', '').strip()
                impact = path.get('Impact', '').strip()
                if (reconnaissance and reconnaissance != '#N/A' and
                    exploitation and exploitation != '#N/A' and
                    impact and impact != '#N/A'):
                    path_key = f"{self._path_cve(path)}|{reconnaissance}|{exploitation}|{impact}"
                    if path_key not in unique_paths:
                        unique_paths[path_key] = path
            valid_paths = list(unique_paths.values())
            criticality_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            max_criticality = min(attack_paths,
                                key=lambda x: criticality_order.get(x['Exposia - Qualification'], 999))
            ip_addresses = []
            for row in attack_paths:
                ip = str(row.get('IP Address', '') or '').strip()
                if ip and ip.lower() not in ('no ip found', '#n/a', 'nan', 'none') and ip not in ip_addresses:
                    ip_addresses.append(ip)
            processed_assets.append({
                'asset_key': asset_key,
                'subdomain': base_info['Subdomain'],
                'subdomain_display': base_info['subdomain_display'],
                'ip_address': ip_addresses[0] if ip_addresses else base_info['IP Address'],
                'ip_addresses': ip_addresses,
                'port': int(float(base_info['Port'])) if base_info['Port'] and str(base_info['Port']).replace('.', '').isdigit() else base_info['Port'],
                'service': base_info['Catégorie'],
                'level': max_criticality['Exposia - Qualification'],
                'attack_paths_count': len(valid_paths),
                'criticality_rank': criticality_order.get(max_criticality['Exposia - Qualification'], 999),
                'impact_rank': self._impact_rank(attack_paths),
                'all_attack_paths': valid_paths,
                'max_epss_score': max([float(p.get('EPSS Score', 0)) for p in valid_paths if p.get('EPSS Score', '#N/A') not in ['#N/A', 'None', '']] or [0])
            })
        # Ordre : qualification, puis impact métier du service, puis EPSS. Sans
        # l'impact, les actifs de même qualification sans CVE (EPSS nul) restaient
        # dans l'ordre du fichier : un service d'administration critique pouvait
        # sortir du top 10 derrière des applications web.
        processed_assets.sort(key=lambda x: (x['criticality_rank'], x['impact_rank'], -x['max_epss_score']))
        assets_with_ip = [asset for asset in processed_assets if asset['ip_address'] and asset['ip_address'].lower() != 'no ip found']
        top_10_assets = assets_with_ip[:10]
        return {
            'assets': processed_assets,
            'top_10_assets': top_10_assets,
            'total_assets': len(processed_assets),
            'raw_data': csv_data
        }

    def generate_executive_summary(self, data):
        """Génère la synthèse exécutive avec focus sur les impacts business"""
        raw_data = data['raw_data']
        unique_cves = self.count_unique_cves(raw_data)
        unique_attack_paths = self.count_unique_attack_paths(raw_data)
        unique_exploits = self.count_unique_exploits(raw_data)
        critical_assets = len([asset for asset in data['assets'] if asset['level'] == 'Critical'])
        top_services = list(set([asset['service'] for asset in data['top_10_assets'][:3] if asset['service'] and asset['service'] != '#N/A']))[:3]
        top_asset = data['top_10_assets'][0] if data['top_10_assets'] else None
        top_asset_name = top_asset['subdomain_display'] if top_asset else "N/A"
        return {
            'unique_cves': unique_cves,
            'unique_attack_paths': unique_attack_paths,
            'unique_exploits': unique_exploits,
            'critical_assets': critical_assets,
            'top_services': top_services,
            'top_asset_name': top_asset_name,
            'total_scenarios': len(raw_data)
        }

    def get_level_class(self, level):
        """Retourne la classe CSS basée sur le niveau"""
        level_mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low'
        }
        return level_mapping.get(level, 'low')

    def get_top_attack_paths_for_asset(self, attack_paths, limit=3):
        """Récupère les top chemins d'attaque pour un asset (déjà dédupliqués)"""
        criticality_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        def sort_key(path):
            criticality_rank = criticality_order.get(path.get('Exposia - Qualification', 'Low'), 999)
            epss_score = float(path.get('EPSS Score', 0)) if path.get('EPSS Score', '#N/A') not in ['#N/A', 'None', ''] else 0
            return (criticality_rank, -epss_score)
        sorted_paths = sorted(attack_paths, key=sort_key)
        return sorted_paths[:limit]

    def get_pdf_css(self):
        """CSS = système Exposia partagé + spécifique au risk assessment."""
        return report_theme.get_exposia_css() + """
        .prose ul { margin:2mm 0 1mm; padding-left:6mm; }
        .prose li { margin-bottom:1.2mm; }
        .xtable.risk { table-layout: fixed; }
        .xtable.risk th, .xtable.risk td { padding:2.8mm 3mm; font-size:9pt; word-break:break-word; }
        .xtable.risk th { font-size:8pt; }

        .asset-card { border:1px solid #E7E9F4; border-radius:3mm; overflow:hidden; margin-bottom:6mm; }
        .asset-head { padding:2.8mm 5mm; color:#fff; display:flex; align-items:baseline; page-break-after:avoid; }
        .asset-head.sev-critical { background:#D8434C; }
        .asset-head.sev-high { background:#E8823C; }
        .asset-head.sev-medium { background:#E0A94A; color:#3A2A0C; }
        .asset-head.sev-low { background:#6BA84E; }
        .asset-head .name { font-size:11pt; font-weight:700; letter-spacing:.3pt; }
        .asset-head .meta { font-size:8.5pt; opacity:.9; font-weight:500; margin-left:4mm; padding-left:4mm; border-left:1px solid rgba(255,255,255,.4); }
        .asset-body { padding:4.5mm 5mm; }
        .apath { border:1px solid #EFF1F8; border-radius:2mm; margin-bottom:3.5mm; overflow:hidden; page-break-inside:avoid; }
        .apath:last-child { margin-bottom:0; }
        .apath-head { background:#F5F6FD; padding:2.6mm 4mm; font-size:8.5pt; font-weight:700; color:#3B37AE; letter-spacing:.3pt; }
        .astep { padding:2.8mm 4mm; border-top:1px solid #EFF1F8; }
        .astep .lab { display:block; font-size:7.5pt; font-weight:700; letter-spacing:.8pt; text-transform:uppercase; margin-bottom:1mm; }
        .astep.recon .lab { color:#4B47C9; }
        .astep.exploit .lab { color:#E8823C; }
        .astep.impact .lab { color:#D8434C; }
        .astep .txt { display:block; font-size:9pt; line-height:1.5; color:#3A4160; }
        .section-note { font-size:9pt; color:#6A7191; line-height:1.55; margin:0 0 4mm; }
"""

    def generate_html_content(self, data):
        """Génère le contenu HTML (système de design Exposia)."""
        summary = self.generate_executive_summary(data)
        top_10_assets = data['top_10_assets']

        try:
            org = os.path.basename(os.path.dirname(os.path.abspath(self.data_dir)))
        except Exception:
            org = ""
        org_disp = esc(org.capitalize()) if org else "—"

        lvl_text = {'critical': 'Critique', 'high': 'Élevé', 'medium': 'Moyen', 'low': 'Faible'}
        services_str = ', '.join(summary['top_services']) if summary['top_services'] else "—"

        # Encadré « En clair » : formulation adaptée aux cas vides (aucune CVE,
        # aucun scénario, aucun exploit) pour ne jamais afficher « 0 vulnérabilités ».
        n_cves, n_paths, n_expl = summary['unique_cves'], summary['unique_attack_paths'], summary['unique_exploits']
        def _pl(n, word):
            return f"{n} {word}{'s' if n > 1 else ''}"
        parts = []
        if n_cves:
            parts.append(
                f"Nous avons identifi&eacute; <strong>{_pl(n_cves, 'vuln&eacute;rabilit&eacute;')}</strong> "
                f"et en avons tir&eacute; <strong>{_pl(n_paths, 'sc&eacute;nario')} d'attaque type{'s' if n_paths > 1 else ''} distinct{'s' if n_paths > 1 else ''}</strong> "
                f"(un m&ecirc;me sc&eacute;nario peut concerner plusieurs actifs)."
            )
        elif n_paths:
            parts.append(
                "Aucune vuln&eacute;rabilit&eacute; connue n'a &eacute;t&eacute; identifi&eacute;e sur vos services expos&eacute;s. "
                f"Leur seule exposition permet n&eacute;anmoins d'envisager <strong>{_pl(n_paths, 'sc&eacute;nario')} "
                f"d'attaque type{'s' if n_paths > 1 else ''}</strong>, li&eacute;{'s' if n_paths > 1 else ''} au type de service."
            )
        else:
            parts.append(
                "Aucune vuln&eacute;rabilit&eacute; connue ni sc&eacute;nario d'attaque significatif n'a &eacute;t&eacute; "
                "identifi&eacute; sur vos services expos&eacute;s. Le principal levier reste de <strong>limiter les services "
                "accessibles depuis Internet</strong> au strict n&eacute;cessaire."
            )
        if n_expl:
            vuln_ref = ("certaines des vuln&eacute;rabilit&eacute;s identifi&eacute;es" if n_cves > 1
                        else "la vuln&eacute;rabilit&eacute; identifi&eacute;e")
            if n_expl > 1:
                parts.append(
                    f"Des exploits publics sont r&eacute;f&eacute;renc&eacute;s pour {vuln_ref}&nbsp;: "
                    f"<strong>{n_expl} exploits</strong> sont recens&eacute;s."
                )
            else:
                parts.append(
                    f"Un <strong>exploit public</strong> est r&eacute;f&eacute;renc&eacute; pour {vuln_ref}."
                )
        if n_cves or n_paths:
            parts.append(
                f"Parmi vos actifs, <strong>{esc(str(summary['top_asset_name']))}</strong> se d&eacute;marque et "
                f"n&eacute;cessite une attention particuli&egrave;re."
            )
            cats = [esc(str(c)) for c in summary['top_services']]
            if cats:
                if len(cats) == 1:
                    cats_txt = f"la cat&eacute;gorie <strong>{cats[0]}</strong>"
                else:
                    cats_txt = ("les cat&eacute;gories <strong>" + "</strong>, <strong>".join(cats[:-1])
                                + f"</strong> et <strong>{cats[-1]}</strong>")
                parts.append(f"Les vecteurs d'attaque se concentrent sur {cats_txt}.")
        risk_callout = " ".join(parts)

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Rapport Risk Assessment</title></head>
<body>
  <div class="rh-brand">E<span class="x">x</span>posia</div>
  <div class="rh-doc">Rapport d'analyse &middot; {org_disp}</div>

  <div class="kicker">Partie 3 &middot; Risques</div>
  <div class="part-title">Quels impacts sur votre business&nbsp;?</div>
  <div class="rule"></div>

  <div class="callout">
    <div class="ttl">En clair</div>
    <p>{risk_callout}</p>
  </div>

  <div class="xsection"><span class="t">M&eacute;thodologie</span></div>
  <div class="prose">
    <p>Notre approche combine l'<b>analyse des impacts op&eacute;rationnels</b> avec des <b>sc&eacute;narios d'attaque types</b>, repr&eacute;sentatifs des attaques courantes sur vos services expos&eacute;s et sur les vuln&eacute;rabilit&eacute;s identifi&eacute;es. Chaque sc&eacute;nario est &eacute;valu&eacute; selon sa <b>criticit&eacute; contextuelle</b>, int&eacute;grant&nbsp;:</p>
    <ul>
      <li>la <b>criticit&eacute; technique</b> (CVSS),</li>
      <li>la <b>probabilit&eacute; d'exploitation</b> (EPSS),</li>
      <li>l'<b>impact m&eacute;tier</b> du service concern&eacute; (interruption, fuite de donn&eacute;es, perte financi&egrave;re, conformit&eacute;).</li>
    </ul>
    <p>En clair&nbsp;: comprendre <b>comment une menace technique peut affecter votre activit&eacute;</b>, selon sa probabilit&eacute; et son impact potentiel.</p>
  </div>

  <div class="xsection" style="page-break-before: always;"><span class="t">Matrice de priorisation des risques</span></div>
  <table class="xtable risk">
    <colgroup><col style="width:8%"><col style="width:26%"><col style="width:24%"><col style="width:14%"><col style="width:14%"><col style="width:14%"></colgroup>
    <thead><tr><th>Rang</th><th>Actif</th><th>Service</th><th class="center">Criticit&eacute;</th><th class="center">Exploits</th><th class="center">Sc&eacute;narios applicables</th></tr></thead>
    <tbody>"""

        for index, asset in enumerate(top_10_assets):
            level_class = self.get_level_class(asset['level'])
            unique_exploits = set()
            for path in asset['all_attack_paths']:
                exploits = (path.get('Exploits', '') or '').strip()
                if exploits and exploits not in ('#N/A', 'None', '', 'No unique public exploit found'):
                    for exploit in (exploits.split(',') if ',' in exploits else [exploits]):
                        unique_exploits.add(exploit.strip())
            rank_cls = ' r1' if index == 0 else ''
            html += f"""
      <tr><td><span class="rank{rank_cls}">{index + 1}</span></td><td><strong>{esc(str(asset['subdomain_display']))}</strong></td><td>{esc(str(asset['service']))} (Port {esc(str(asset['port']))})</td><td class="center"><span class="sev-badge sev-{level_class}">{lvl_text.get(level_class, 'Faible')}</span></td><td class="center">{len(unique_exploits)}</td><td class="center">{asset['attack_paths_count']}</td></tr>"""

        html += """
    </tbody>
  </table>

  <div class="xsection" style="page-break-before: always;"><span class="t">Sc&eacute;narios d'attaque types sur vos actifs critiques</span></div>
  <p class="section-note">Ces sc&eacute;narios illustrent la mani&egrave;re dont un attaquant pourrait exploiter vos services les plus expos&eacute;s. Lorsqu'une vuln&eacute;rabilit&eacute; pr&eacute;cise est en cause, sa r&eacute;f&eacute;rence (CVE) est indiqu&eacute;e&nbsp;; les autres sc&eacute;narios d&eacute;crivent des attaques courantes sur ce type de service.</p>"""

        scenario_cards = self.build_scenario_cards(top_10_assets)
        for card in scenario_cards:
            level_class = self.get_level_class(card['level'])
            top_paths = card['top_paths']
            ports = card['ports']
            ports_txt = f"Port{'s' if len(ports) > 1 else ''} {esc(', '.join(str(p) for p in ports))}"
            html += f"""
  <div class="asset-card">
    <div class="asset-head sev-{level_class}">
      <span class="name">{esc(' / '.join(card['subdomains']).upper())}</span>
      <span class="meta">Service {esc(str(card['service']))} &bull; {self._format_ips(card['ip_addresses'])} &bull; {ports_txt} &bull; {lvl_text.get(level_class, 'Faible')}</span>
    </div>
    <div class="asset-body">"""
            for i, path in enumerate(top_paths, 1):
                cve = path.get('Vulnerability (CVE)', '#N/A')
                qualification = lvl_text.get(self.get_level_class(path.get('Exposia - Qualification', 'Low')), 'Faible')
                # Un scénario générique de service (PORT) n'affiche jamais de CVE, même
                # si un fichier ancien en porte encore une sur la ligne.
                has_cve = cve and cve not in ['#N/A', 'None', 'No data', ''] and not self._is_port_path(path)
                if has_cve:
                    header_text = f"Sc&eacute;nario #{i} &bull; {esc(str(cve))} &bull; {qualification}"
                else:
                    header_text = f"Sc&eacute;nario #{i} &bull; Attaque courante sur ce service &bull; {qualification}"
                html += f"""
      <div class="apath">
        <div class="apath-head">{header_text}</div>
        <div class="astep recon"><span class="lab">Reconnaissance</span><span class="txt">{esc(str(path.get('Reconnaissance', 'N/A')))}</span></div>
        <div class="astep exploit"><span class="lab">Exploitation</span><span class="txt">{esc(str(path.get('Exploitation', 'N/A')))}</span></div>
        <div class="astep impact"><span class="lab">Impact</span><span class="txt">{esc(str(path.get('Impact', 'N/A')))}</span></div>
      </div>"""
            html += """
    </div>
  </div>"""

        if not scenario_cards:
            html += """
  <p class="prose" style="text-align:center; color:#8A90AC; font-style:italic;">Aucun sc&eacute;nario d'attaque d&eacute;taill&eacute; identifi&eacute; sur les actifs critiques.</p>"""

        html += """
</body>
</html>"""
        return html

    def generate_pdf_report(self, data):
        """Génère le rapport PDF avec WeasyPrint"""
        try:
            html_content = self.generate_html_content(data)
            font_config = FontConfiguration()
            css_content = self.get_pdf_css()
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"risk_assessment_report_{timestamp}.pdf"
            html_doc.write_pdf(pdf_filename, stylesheets=[css_doc], font_config=font_config)
            ModernUI.status(f"PDF généré avec succès: {pdf_filename}", "success")
            return pdf_filename
        except Exception as e:
            ModernUI.status(f"Erreur lors de la génération PDF: {str(e)}", "error")
            raise

    def generate_report(self):
        """Fonction principale qui orchestrate la génération du rapport PDF"""
        try:
            try:
                from weasyprint import HTML
            except ImportError:
                ModernUI.status("WeasyPrint non installé. Installation requise:", "error")
                print("   pip install weasyprint")
                raise ImportError("WeasyPrint requis pour la génération PDF")
            csv_file = self.find_csv_file()
            csv_data = self.load_csv_data(csv_file)
            processed_data = self.process_data(csv_data)
            pdf_filename = self.generate_pdf_report(processed_data)
            return pdf_filename
        except Exception as e:
            ModernUI.status(f"Erreur: {str(e)}", "error")
            raise

def main():
    """Point d'entrée du script"""
    import argparse
    parser = argparse.ArgumentParser(description="Génère le rapport PDF Risk Assessment.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("-d", "--data-dir", default=None,
                        help="Répertoire contenant Exposia_*.csv (défaut : dossier courant)")
    args = parser.parse_args()

    # Dossier de travail = data/ de la campagne (lecture CSV + écriture PDF)
    data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    os.chdir(data_dir)
    generator = RiskAssessmentPDFGenerator(data_dir='.')
    generator.generate_report()

if __name__ == "__main__":
    main()