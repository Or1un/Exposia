#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de Rapport Asset Discovery PDF - Partie 1
Cartographie de la Surface d'Attaque
Version optimisée avec WeasyPrint pour un rendu PDF professionnel

Classification « Internal » / « External » (D1) : c'est une PRÉSOMPTION fondée
sur le port, le service ou un mot-clé du sous-domaine. Le rapport l'affiche donc
comme « nature présumée » du service : « Sensible » (habituellement réservé à un
usage interne : administration, transfert de fichiers, base de données…) ou
« Standard ».
"""

import csv
from html import escape as esc  # échappement HTML de toute valeur injectée dans un rapport
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_vocab as vocab  # codes stables (JSON canonique)
import exposia_i18n as i18n  # langue des livrables (EXPOSIA_LANG)
from exposia_i18n import tr
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
try:  # le thème peut être nommé report_theme.py ou R0_report_theme.py
    import report_theme
except ImportError:
    import R0_report_theme as report_theme
import os
import glob
from datetime import datetime
from collections import Counter

# Libellés de catégories affichés dans la répartition (les données gardent le libellé d'origine).
CAT_LABELS_FR = {"Application web": "Applications web",
                 "Non catégorisé": "Services non catégorisés"}
# Libellés anglais au pluriel pour la répartition (code de catégorie -> libellé).
CAT_LABELS_EN = {"web_application": "Web applications", None: "Uncategorised services"}

# Textes fixes de la partie 2 (FR, EN)
T = {
    'title_tag': ("Rapport Asset Discovery", "Asset Discovery report"),
    'kicker': ("Partie 2 &middot; Actifs", "Part 2 &middot; Assets"),
    'title': ("Quel est votre p&eacute;rim&egrave;tre expos&eacute;&nbsp;?", "What is your exposed perimeter?"),
    'method': ("Notre d&eacute;couverte repose exclusivement sur des <b>m&eacute;thodes passives et non intrusives</b>, sans aucun impact sur vos syst&egrave;mes&nbsp;: analyse des certificats SSL publics, r&eacute;solution DNS et examen des services expos&eacute;s &agrave; partir de donn&eacute;es ouvertes. Chaque service est cat&eacute;goris&eacute; et qualifi&eacute; selon sa <b>nature pr&eacute;sum&eacute;e</b>&nbsp;: <b>sensible</b> lorsqu'il s'agit d'un type de service habituellement r&eacute;serv&eacute; &agrave; un usage interne, <b>standard</b> sinon. Son <b>impact potentiel sur votre activit&eacute;</b> est ensuite estim&eacute; selon sa criticit&eacute; et son exposition. En clair&nbsp;: un inventaire <b>complet et actionnable</b>, obtenu sans jamais toucher &agrave; votre production.",
               "Our discovery relies exclusively on <b>passive, non-intrusive methods</b>, with no impact on your systems: analysis of public SSL certificates, DNS resolution and review of exposed services based on open data. Each service is categorised and qualified according to its <b>presumed nature</b>: <b>sensitive</b> when it is a type of service usually reserved for internal use, <b>standard</b> otherwise. Its <b>potential impact on your business</b> is then estimated from its criticality and exposure. In short: a <b>complete and actionable</b> inventory, obtained without ever touching your production."),
    'matrix': ("Matrice de d&eacute;couverte des actifs", "Asset discovery matrix"),
    'th': ("<th>Rang</th><th>Sous-domaine</th><th>Service</th><th>Cat&eacute;gorie</th><th class=\"center\">Nature pr&eacute;sum&eacute;e</th><th class=\"center\">Impact</th>",
           "<th>Rank</th><th>Subdomain</th><th>Service</th><th>Category</th><th class=\"center\">Presumed nature</th><th class=\"center\">Impact</th>"),
    'note': ("Nature pr&eacute;sum&eacute;e&nbsp;: d&eacute;duite du type de service (port, protocole, nom du sous-domaine). &laquo;&nbsp;Sensible&nbsp;&raquo; signale un service habituellement r&eacute;serv&eacute; &agrave; un usage interne, &agrave; confirmer avec vos &eacute;quipes.",
             "Presumed nature: inferred from the type of service (port, protocol, subdomain name). &ldquo;Sensitive&rdquo; flags a service usually reserved for internal use, to be confirmed with your teams."),
    'breakdown': ("R&eacute;partition par cat&eacute;gories de services", "Breakdown by service category"),
    'sensitive': ("Sensible", "Sensitive"),
    'standard': ("Standard", "Standard"),
}
IMPACT_LABELS = {'CRITIQUE': ('Critique', 'Critical'), 'HAUTE': ('Haute', 'High'), 'MOYENNE': ('Moyenne', 'Medium')}


class AssetDiscoveryPDFGenerator:
    def __init__(self, data_dir=None):
        # Répertoire des CSV d'entrée : dossier courant par défaut, surchargeable
        # (plus de chemin en dur — cohérent avec l'emplacement de sortie du scanner).
        self.data_dir = data_dir or "."
        self.config = {
            'classification_colors': {
                'INTERNAL': '#e74c3c',
                'EXTERNAL': '#2ecc71'
            },
            'impact_colors': {
                'CRITIQUE': '#e74c3c',
                'HAUTE': '#f39c12',
                'MOYENNE': '#f1c40f',
                'LOW': '#95a5a6'
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

        # Retourner le fichier le plus récent
        latest_file = max(csv_files, key=os.path.getmtime)
        return latest_file

    def load_csv_data(self, filename):
        """
        Charge et parse les données CSV.

        Tolère : le délimiteur (';', ',' ou tab), un éventuel BOM (utf-8-sig),
        et DEUX conventions de nommage des colonnes —
          • noms d'affichage (sortie asset_discovery_assessment) : 'Domain', 'IP Address'...
          • noms internes (sortie mitigation_plan, fichier enrichi) : 'domain', 'ip_address'...
        Les lignes sont normalisées vers les noms d'affichage utilisés par le générateur.
        """
        # canonique (clé utilisée dans le code) -> alias acceptés dans l'en-tête
        aliases = {
            'Domain': ['Domain', 'domain'],
            'Subdomain': ['Subdomain', 'subdomain'],
            'IP Address': ['IP Address', 'ip_address'],
            'Port': ['Port', 'port'],
            'Catégorie': ['Catégorie', 'category'],
            'Internal_External_Classification': ['Internal_External_Classification', 'classification'],
            'Impact business / opérationnel': ['Impact business / opérationnel', 'business_impact'],
        }
        try:
            best = None  # (nb_manquantes, delimiteur, colonnes_detectees, manquantes)
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
                        data = []
                        for row in reader:
                            # normaliser vers les clés canoniques (les autres colonnes restent)
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

    def process_data(self, csv_data):
        """Traite les données CSV avec agrégation et priorisation"""

        # Filtrer les données valides
        valid_data = []
        for row in csv_data:
            if (row.get('IP Address') and
                row['IP Address'] not in ['No IP found', '#N/A', '', 'None'] and
                row.get('Port') and
                row['Port'] not in ['#N/A', '', 'None']):
                valid_data.append(row)


        # Calculer les statistiques
        stats = self.calculate_statistics(csv_data, valid_data)

        # Prioriser les assets
        top_assets = self.prioritize_assets(valid_data)

        return {
            'stats': stats,
            'top_assets': top_assets,
            'valid_data': valid_data,
            'raw_data': csv_data
        }

    @staticmethod
    def _format_port(port):
        """
        Normalise un port pour l'affichage : '21.0' -> '21'.
        Le fichier enrichi (écrit par pandas via mitigation_plan) stocke les ports
        en float, d'où le '.0' parasite.
        """
        s = str(port).strip()
        try:
            return str(int(float(s)))
        except (ValueError, TypeError):
            return s

    def calculate_statistics(self, csv_data, valid_data):
        """Calcule les statistiques pour l'Asset Discovery"""
        stats = {}

        _NA = ('', '#N/A', 'N/A', 'None', 'nan')
        _NA_IP = _NA + ('No IP found',)

        # Domaine principal
        stats['domain'] = csv_data[0]['Domain'] if csv_data else "Unknown"
        root_domain = str(stats['domain']).strip()

        # Sous-domaines uniques — SANS le domaine racine (exemple.com lui-même
        # n'est pas un sous-domaine).
        unique_subdomains = set()
        for row in csv_data:
            sub = str(row.get('Subdomain', '')).strip()
            if sub and sub not in _NA and sub != root_domain:
                unique_subdomains.add(sub)
        stats['total_subdomains'] = len(unique_subdomains)

        # IPs uniques : comptées sur TOUTES les lignes à IP résolue (indépendamment
        # d'un port ouvert), sinon une IP sans service exposé disparaîtrait du total.
        # Une IP vue INTERNAL quelque part est comptée interne (interne prioritaire) ;
        # externe = reste, de sorte que internes + externes == IPs uniques.
        # (Le rapport raisonne en services présumés sensibles, voir plus bas.)
        internal_ips = set()
        all_ips = set()
        for row in csv_data:
            ip = str(row.get('IP Address', '')).strip()
            if not ip or ip in _NA_IP:
                continue
            all_ips.add(ip)
            if str(row.get('Internal_External_Classification', '')).strip().upper() == 'INTERNAL':
                internal_ips.add(ip)
        external_ips = all_ips - internal_ips

        stats['total_ips'] = len(all_ips)
        stats['internal_ips'] = len(internal_ips)
        stats['external_ips'] = len(external_ips)

        # Services distincts exposés = couples (IP, port) réellement exposés.
        # (Un même IP:port vu sous plusieurs sous-domaines — CNAME — ne compte qu'une
        # fois ; le fichier peut par ailleurs être explosé par mitigation_plan.)
        seen_services = set()
        unique_services = []
        for row in valid_data:
            key = (str(row.get('IP Address', '')).strip(),
                   self._format_port(row.get('Port')))
            if key not in seen_services:
                seen_services.add(key)
                unique_services.append(row)

        stats['distinct_services'] = len(unique_services)

        # Services présumés sensibles : couples (IP, port) distincts classés
        # « Internal » par D1 (service habituellement réservé à un usage interne).
        sensitive_services = {
            (str(row.get('IP Address', '')).strip(), self._format_port(row.get('Port')))
            for row in valid_data
            if str(row.get('Internal_External_Classification', '')).strip().upper() == 'INTERNAL'
        }
        stats['sensitive_services'] = len(sensitive_services)

        # Catégories de services (comptées sur les services uniques (IP, port))
        categories = []
        uncategorized = 0
        for row in unique_services:
            cat = row.get('Catégorie')
            if cat and str(cat).strip() not in _NA:
                categories.append(cat)
            else:
                uncategorized += 1

        category_counter = Counter(categories)
        stats['service_categories'] = len(category_counter)

        # Distribution : pourcentages sur le total de services (= distinct_services),
        # avec un bucket "Non catégorisé". Ainsi la somme du graphique == la carte
        # "Services distincts exposés".
        total_services = len(unique_services)
        stats['category_distribution'] = [
            {
                'name': cat,
                'count': count,
                'percentage': (count / total_services * 100) if total_services > 0 else 0
            }
            for cat, count in category_counter.most_common()
        ]
        if uncategorized > 0:
            stats['category_distribution'].append({
                'name': 'Non catégorisé',
                'count': uncategorized,
                'percentage': (uncategorized / total_services * 100) if total_services > 0 else 0
            })

        # Pourcentage d'exposition interne : au niveau des IP (part d'IP internes).
        stats['internal_percentage'] = (len(internal_ips) / len(all_ips) * 100) if all_ips else 0

        return stats

    def prioritize_assets(self, valid_data):
        """Priorise les assets : services présumés sensibles d'abord, puis par impact"""
        priority_map = {
            ('INTERNAL', 'CRITIQUE'): 1,
            ('INTERNAL', 'HAUTE'): 2,
            ('EXTERNAL', 'CRITIQUE'): 3,
            ('EXTERNAL', 'HAUTE'): 4,
            ('INTERNAL', 'MOYENNE'): 5,
            ('EXTERNAL', 'MOYENNE'): 6,
            ('INTERNAL', 'LOW'): 7,
            ('EXTERNAL', 'LOW'): 8,
        }

        # Ajouter la priorité à chaque ligne
        for row in valid_data:
            classification = row.get('Internal_External_Classification', '').upper()
            impact = row.get('Impact business / opérationnel', 'LOW').upper()
            row['priority'] = priority_map.get((classification, impact), 99)

        # Trier par priorité puis regrouper par (sous-domaine, port) : les différentes
        # IP d'un même nom (IPv4 / IPv6, adresses multiples d'un CDN) exposent le même
        # service et forment une seule ligne. On garde la ligne la plus prioritaire.
        sorted_assets = sorted(valid_data, key=lambda x: x['priority'])
        groups = {}
        for a in sorted_assets:
            key = (a.get('Subdomain'), self._format_port(a.get('Port')))
            ip = str(a.get('IP Address', '')).strip()
            if key not in groups:
                entry = dict(a)
                entry['ip_addresses'] = []
                groups[key] = entry
            if ip and ip not in groups[key]['ip_addresses']:
                groups[key]['ip_addresses'].append(ip)
        return list(groups.values())[:10]

    @staticmethod
    def _format_endpoint(ip, port):
        """Adresse:port lisible ; IPv6 entre crochets ([2620:127:f00f:e::]:443)."""
        host = f"[{ip}]" if ':' in ip else ip
        return f"{host}:{port}"

    def get_pdf_css(self):
        """CSS = système Exposia partagé + spécifique à l'asset discovery."""
        return report_theme.get_exposia_css() + """
        .cls-badge { display:inline-block; padding:1.1mm 3.4mm; border-radius:20px; font-size:8pt; font-weight:700; letter-spacing:.8pt; text-transform:uppercase; }
        .cls-internal { background:#4B47C9; color:#fff; }
        .cls-external { background:#EEF0FA; color:#6A7191; }
        .cat-bars { margin-top:1mm; }
        .cat-bar { margin-bottom:4.2mm; }
        .cat-bar .cbl { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:1.6mm; }
        .cat-bar .cn { font-size:9.5pt; font-weight:600; color:#20263F; }
        .cat-bar .cp { font-size:9pt; font-weight:600; color:#4B47C9; }
        .cat-bar .track { height:3.2mm; background:#EEF0FA; border-radius:20px; overflow:hidden; }
        .cat-bar .fill { height:100%; background:linear-gradient(90deg,#4B47C9,#6C68DA); }
        .cat-bar.other .fill { background:#C7CADF; }
        .xtable.assets { table-layout: fixed; }
        .xtable.assets th, .xtable.assets td { padding:2.8mm 3mm; font-size:9pt; word-break:break-word; }
        .xtable.assets th { font-size:8pt; }
        .table-note { font-size:8pt; color:#8A90AC; margin-top:2.5mm; line-height:1.5; }
        .ip-more { display:block; font-size:7.5pt; color:#8A90AC; margin-top:.6mm; }
"""

    # ------------------------------------------------------------------
    # Données de la partie (source unique du PDF et du JSON canonique)
    # ------------------------------------------------------------------
    @staticmethod
    def build_in_short(stats):
        """Encadré « En clair » : paragraphes de segments, et chiffres utilisés."""
        if i18n.is_en():
            return AssetDiscoveryPDFGenerator._build_in_short_en(stats)
        seg = report_theme.seg
        n_uncat = sum(c['count'] for c in stats['category_distribution'] if c['name'] == 'Non catégorisé')
        # Services sans catégorie : déjà inclus dans le total, signalés pour que le
        # décompte corresponde au graphique de répartition.
        uncat = (f", dont {n_uncat} service{'s' if n_uncat > 1 else ''} "
                 f"non catégorisé{'s' if n_uncat > 1 else ''}") if n_uncat else ""
        para = [seg("Votre périmètre comprend "), seg(f"{stats['total_subdomains']} sous-domaines", True),
                seg(" et "), seg(f"{stats['distinct_services']} services distincts", True),
                seg(", répartis en "), seg(f"{stats['service_categories']} catégories", True),
                seg(f"{uncat}. ")]
        # Services présumés sensibles (classification « Internal »).
        nb_sens = stats['sensitive_services']
        if nb_sens:
            pl = 's' if nb_sens > 1 else ''
            para += [seg("Parmi eux, "), seg(f"{nb_sens} service{pl} présumé{pl} sensible{pl}", True),
                     seg(f" (administration, transfert de fichiers, base de données…)\u00a0: "
                         f"généralement destiné{pl} à un usage interne, il{pl} "
                         f"mérite{'nt' if nb_sens > 1 else ''} une vérification de "
                         f"{'leur' if nb_sens > 1 else 'son'} accessibilité depuis Internet.")]
        else:
            para.append(seg("Aucun service habituellement réservé à un usage interne "
                            "(administration, transfert de fichiers, base de données) n'a été "
                            "repéré sur votre périmètre exposé."))
        facts = {'subdomains': stats['total_subdomains'], 'services': stats['distinct_services'],
                 'service_categories': stats['service_categories'], 'sensitive_services': nb_sens,
                 'uncategorized_services': n_uncat}
        return {'paragraphs': [para], 'facts': facts}

    @staticmethod
    def _build_in_short_en(stats):
        """« In brief » en anglais : mêmes chiffres, mêmes faits que la version française."""
        seg, pl = report_theme.seg, i18n.plural
        n_uncat = sum(c['count'] for c in stats['category_distribution'] if c['name'] == 'Non catégorisé')
        uncat = f", including {n_uncat} uncategorised {pl(n_uncat, 'service')}" if n_uncat else ""
        n_sub, n_srv, n_cat = stats['total_subdomains'], stats['distinct_services'], stats['service_categories']
        para = [seg("Your perimeter includes "), seg(f"{n_sub} {pl(n_sub, 'subdomain')}", True),
                seg(" and "), seg(f"{n_srv} distinct {pl(n_srv, 'service')}", True),
                seg(", spread across "), seg(f"{n_cat} {pl(n_cat, 'category', 'categories')}", True),
                seg(f"{uncat}. ")]
        nb_sens = stats['sensitive_services']
        if nb_sens:
            one = nb_sens == 1
            para += [seg("Among them, "), seg(f"{nb_sens} presumed sensitive {pl(nb_sens, 'service')}", True),
                     seg(" (administration, file transfer, database…): usually intended for internal use, "
                         + ("it deserves a check of its" if one else "they deserve a check of their")
                         + " accessibility from the Internet.")]
        else:
            para.append(seg("No service usually reserved for internal use (administration, file transfer, "
                            "database) was spotted on your exposed perimeter."))
        facts = {'subdomains': n_sub, 'services': n_srv, 'service_categories': n_cat,
                 'sensitive_services': nb_sens, 'uncategorized_services': n_uncat}
        return {'paragraphs': [para], 'facts': facts}

    def build_data(self, processed_data):
        """Bloc parts.assets du JSON canonique : « En clair » et données des visuels (codes)."""
        stats, top = processed_data['stats'], processed_data['top_assets']
        matrix = []
        for rank, asset in enumerate(top, 1):
            host = str(asset.get('Subdomain', '')).strip()
            port = self._format_port(asset.get('Port', ''))
            matrix.append({
                'rank': rank, 'exposure_id': f"{host}:{port}", 'host': host, 'port': int(port),
                'ips': list(asset.get('ip_addresses') or [asset.get('IP Address')]),
                'category': vocab.code('service_category', asset.get('Catégorie')),
                'nature': vocab.code('nature', asset.get('Internal_External_Classification')) or 'standard',
                'business_impact': vocab.code('severity', asset.get('Impact business / opérationnel')),
            })
        return {
            'in_short': self.build_in_short(stats),
            'visuals': {
                'key_figures': {'subdomains': stats['total_subdomains'], 'services': stats['distinct_services'],
                                'service_categories': stats['service_categories'],
                                'sensitive_services': stats['sensitive_services'], 'ips': stats['total_ips'],
                                'internal_ips': stats['internal_ips'], 'external_ips': stats['external_ips']},
                'category_distribution': [
                    {'category': None if c['name'] == 'Non catégorisé' else vocab.code('service_category', c['name']),
                     'count': c['count'], 'percentage': round(c['percentage'], 1)}
                    for c in stats['category_distribution']],
                'discovery_matrix': matrix,
            },
        }

    def generate_html_content(self, processed_data):
        """Génère le contenu HTML (système de design Exposia)."""
        stats = processed_data['stats']
        top_assets = processed_data['top_assets']

        try:
            org = os.path.basename(os.path.dirname(os.path.abspath(self.data_dir)))
        except Exception:
            org = ""
        org_disp = esc(org.capitalize()) if org else "—"

        imp_map = {'CRITIQUE': 'sev-critical', 'HAUTE': 'sev-high', 'MOYENNE': 'sev-medium'}
        assets_rows = ""
        for index, asset in enumerate(top_assets):
            subdomain = esc(str(asset.get('Subdomain', 'N/A')))
            port = self._format_port(asset.get('Port', 'N/A'))
            ips = asset.get('ip_addresses') or [asset.get('IP Address', 'N/A')]
            endpoint = esc(self._format_endpoint(ips[0], port))
            if len(ips) > 1:
                others = len(ips) - 1
                endpoint += (f'<span class="ip-more">+{others} autre{"s" if others > 1 else ""} '
                             f'adresse{"s" if others > 1 else ""}</span>') if not i18n.is_en() else \
                            f'<span class="ip-more">+{others} other {i18n.plural(others, "address", "addresses")}</span>'
            category = asset.get('Catégorie', 'Non catégorisé')
            if category in ['#N/A', '', 'None', None]:
                category = 'Non catégorisé'
            if i18n.is_en():
                category = vocab.label('service_category', vocab.code('service_category', category), 'en',
                                       fallback='Uncategorised') if category != 'Non catégorisé' else 'Uncategorised'
            classification = asset.get('Internal_External_Classification', '').upper()
            impact = asset.get('Impact business / opérationnel', 'LOW').upper()
            cls_class = 'cls-internal' if classification == 'INTERNAL' else 'cls-external'
            cls_text = tr(T, 'sensitive') if classification == 'INTERNAL' else (tr(T, 'standard') if classification == 'EXTERNAL' else '&mdash;')
            imp_class = imp_map.get(impact, 'sev-low')
            imp_text = i18n.pick(*IMPACT_LABELS.get(impact, ('Faible', 'Low')))
            rank_cls = ' r1' if index == 0 else ''
            assets_rows += f"""
      <tr><td><span class="rank{rank_cls}">{index + 1}</span></td><td><strong>{subdomain}</strong></td><td>{endpoint}</td><td>{esc(str(category))}</td><td class="center"><span class="cls-badge {cls_class}">{cls_text}</span></td><td class="center"><span class="sev-badge {imp_class}">{imp_text}</span></td></tr>"""

        cat_bars = ""
        for cat_info in stats['category_distribution']:
            name = cat_info['name']
            count = cat_info['count']
            pct = cat_info['percentage']
            other = ' other' if name == 'Non catégorisé' else ''
            s = 's' if count > 1 else ''
            if i18n.is_en():
                code = None if name == 'Non catégorisé' else vocab.code('service_category', name)
                shown = CAT_LABELS_EN.get(code) or vocab.label('service_category', code, 'en', fallback=name)
                s = 's' if count != 1 else ''
            else:
                shown = CAT_LABELS_FR.get(name, name)
            cat_bars += f"""
      <div class="cat-bar{other}">
        <div class="cbl"><span class="cn">{esc(str(shown))} ({count} service{s})</span><span class="cp">{i18n.percent(pct)}</span></div>
        <div class="track"><div class="fill" style="width:{pct:.1f}%;"></div></div>
      </div>"""

        in_short = self.build_data(processed_data)['in_short']

        html = f"""<!DOCTYPE html>
<html lang="{i18n.lang()}">
<head><meta charset="UTF-8"><title>{tr(T, 'title_tag')}</title></head>
<body>
  {report_theme.doc_header(org_disp)}

  <div class="kicker">{tr(T, 'kicker')}</div>
  <div class="part-title">{tr(T, 'title')}</div>
  <div class="rule"></div>

  <div class="callout">
    <div class="ttl">{tr(report_theme.T, 'in_short')}</div>
    {report_theme.render_in_short(in_short['paragraphs'])}
  </div>

  <div class="xsection"><span class="t">{tr(report_theme.T, 'methodology')}</span></div>
  <p class="prose">{tr(T, 'method')}</p>

  <div class="xsection" style="page-break-before: always;"><span class="t">{tr(T, 'matrix')}</span></div>
  <table class="xtable assets">
    <colgroup><col style="width:7%"><col style="width:28%"><col style="width:20%"><col style="width:14%"><col style="width:16%"><col style="width:15%"></colgroup>
    <thead><tr>{tr(T, 'th')}</tr></thead>
    <tbody>{assets_rows}
    </tbody>
  </table>
  <p class="table-note">{tr(T, 'note')}</p>

  <div class="xsection" style="page-break-before: always;"><span class="t">{tr(T, 'breakdown')}</span></div>
  <div class="cat-bars">{cat_bars}
  </div>
</body>
</html>"""
        return html

    def generate_pdf_report(self, processed_data):
        """Génère le rapport PDF avec WeasyPrint"""

        from weasyprint import HTML, CSS  # PDF seulement : build_data reste importable sans WeasyPrint
        from weasyprint.text.fonts import FontConfiguration
        try:
            # Génération du contenu HTML
            html_content = self.generate_html_content(processed_data)

            # Configuration des polices
            font_config = FontConfiguration()

            # CSS optimisé pour PDF
            css_content = self.get_pdf_css()

            # Création du PDF
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)

            # Génération du nom de fichier
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"asset_discovery_report_{timestamp}.pdf"

            # Écriture du PDF
            html_doc.write_pdf(pdf_filename, stylesheets=[css_doc], font_config=font_config)

            ModernUI.status(f"PDF généré avec succès: {pdf_filename}", "success")
            return pdf_filename

        except Exception as e:
            ModernUI.status(f"Erreur lors de la génération PDF: {str(e)}", "error")
            raise

    def generate_report(self):
        """Fonction principale qui orchestre la génération du rapport PDF"""
        try:

            # Vérification de WeasyPrint
            try:
                from weasyprint import HTML
            except ImportError:
                ModernUI.status("WeasyPrint non installé. Installation requise:", "error")
                print("   pip install weasyprint")
                raise ImportError("WeasyPrint requis pour la génération PDF")

            # 1. Détection du fichier CSV
            csv_file = self.find_csv_file()

            # 2. Chargement des données
            csv_data = self.load_csv_data(csv_file)

            # 3. Traitement et analyse
            processed_data = self.process_data(csv_data)

            # 4. Génération du PDF
            pdf_filename = self.generate_pdf_report(processed_data)


            return pdf_filename

        except Exception as e:
            ModernUI.status(f"Erreur: {str(e)}", "error")
            raise

def main():
    """Point d'entrée du script"""
    import argparse
    parser = argparse.ArgumentParser(description="Génère le rapport PDF Asset Discovery.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("-d", "--data-dir", default=None,
                        help="Répertoire contenant Exposia_*.csv (défaut : dossier courant)")
    args = parser.parse_args()

    # Dossier de travail = data/ de la campagne (lecture CSV + écriture PDF)
    data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    os.chdir(data_dir)
    generator = AssetDiscoveryPDFGenerator(data_dir='.')
    generator.generate_report()

if __name__ == "__main__":
    main()

def build_assets_data(data_dir='.'):
    """parts.assets du JSON canonique, calculé depuis le dossier data/ d'une campagne."""
    generator = AssetDiscoveryPDFGenerator(data_dir=data_dir)
    return generator.build_data(generator.process_data(generator.load_csv_data(generator.find_csv_file())))
