#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de Rapport Synthèse Globale PDF - Partie 5
Chemins d'Attaque Complets : Acteur → Asset → Vecteur → Mitigation
Version optimisée avec WeasyPrint pour un rendu PDF professionnel

Chaînes de menaces (3 scénarios) :
  • vulnérabilités : les 3 CVE distinctes les plus critiques (qualification, puis EPSS),
    même ordre que la partie Risques ;
  • acteur : l'acteur le mieux classé (Score_Acteur de D3, comme R1) dont une
    motivation correspond à l'impact de la CVE (vecteur CVSS : confidentialité →
    lucratif / espionnage, disponibilité → entrave, intégrité → influence) ;
  • impact : le récit d'impact de la CVE (mapping CVSS de D1) ;
  • mesure : une mesure qui traite la CVE, priorité CRITIQUE d'abord, en variant
    les mesures d'un scénario à l'autre.

Focus sur les mesures prioritaires : les FOCUS_SIZE premières mesures du
classement de D2 (final_score), le même que la partie Mitigation (R4). Le
rapport présente ainsi un seul ordre de priorité ; les chaînes, elles, citent
une mesure propre à chaque CVE.
"""

import csv
from html import escape as esc  # échappement HTML de toute valeur injectée dans un rapport
import os
import glob
from datetime import datetime
from collections import defaultdict, Counter
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
from exposia_ui import Colors, ModernUI  # UI console centralisée
try:  # thème partagé (report_theme.py ou R0_report_theme.py)
    import report_theme
except ImportError:
    import R0_report_theme as report_theme

_NA = ('', '#N/A', 'N/A', 'None', 'nan', 'No data')

# Composante CVSS impactée (H) -> motivations cohérentes, par ordre de préférence.
IMPACT_TO_MOTIVATIONS = {
    'C': ['Lucratif', 'Espionnage'],
    'A': ['Entrave au fonctionnement'],
    'I': ['Influence', 'Entrave au fonctionnement'],
}

QUALIF_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
PRIORITY_ORDER = {'CRITIQUE': 0, 'HAUTE': 1, 'MOYENNE': 2, 'FAIBLE': 3}

# Nombre de mesures du « Focus sur les mesures prioritaires » (top du classement D2).
FOCUS_SIZE = 3


def _float(value, default=0.0):
    try:
        return float(str(value).strip().replace(',', '.'))
    except (TypeError, ValueError):
        return default


class SynthesisGlobalPDFGenerator:
    def __init__(self):
        self.config = {
            'actor_icons': {
                'Étatique': '🏛️',
                'Crime organisé': '💰',
                'Terroriste': '💥',
                'Activiste': '✊',
                'Officine': '🕵️',
                'Amateur': '🔰',
                'Vengeur': '😠',
                'Malveillant': '🎭'
            },
            'actor_characteristics': {
                'Étatique': {
                    'sophistication': 'Très élevée',
                    'resources': 'Illimitées',
                    'probability': 'Très élevée'
                },
                'Crime organisé': {
                    'sophistication': 'Élevée',
                    'resources': 'Importantes',
                    'probability': 'Élevée'
                },
                'Terroriste': {
                    'sophistication': 'Moyenne à élevée',
                    'resources': 'Importantes',
                    'probability': 'Variable'
                },
                'Activiste': {
                    'sophistication': 'Moyenne à élevée',
                    'resources': 'Importantes',
                    'probability': 'Très élevée'
                },
                'Officine': {
                    'sophistication': 'Moyenne',
                    'resources': 'Importantes',
                    'probability': 'Modérée'
                },
                'Amateur': {
                    'sophistication': 'Faible à moyenne',
                    'resources': 'Significatives',
                    'probability': 'Élevée'
                },
                'Vengeur': {
                    'sophistication': 'Moyenne',
                    'resources': 'Significatives',
                    'probability': 'Élevée'
                },
                'Malveillant': {
                    'sophistication': 'Variable',
                    'resources': 'Significatives',
                    'probability': 'Élevée'
                }
            }
        }

    def find_csv_files(self):
        """Trouve automatiquement les fichiers CSV nécessaires dans le répertoire courant."""
        chemin_repertoire = os.getcwd()

        # Construction des motifs de recherche
        motif_threat = os.path.join(chemin_repertoire, "threat_analysis_*.csv")
        motif_exposia = os.path.join(chemin_repertoire, "Exposia_*.csv")
        motif_mitigation = os.path.join(chemin_repertoire, "mitigation_prioritization_enhanced.csv")

        # Recherche des fichiers (la vue présentation R10 n'est pas une entrée)
        threat_files = glob.glob(motif_threat)
        exposia_files = [f for f in glob.glob(motif_exposia) if not f.endswith('_presentation.csv')]
        mitigation_files = glob.glob(motif_mitigation)

        # Vérification des résultats
        if not threat_files:
            raise FileNotFoundError(f"Aucun fichier threat_analysis_*.csv trouvé dans {chemin_repertoire}")
        if not exposia_files:
            raise FileNotFoundError(f"Aucun fichier Exposia_*.csv trouvé dans {chemin_repertoire}")
        if not mitigation_files:
            raise FileNotFoundError(f"Fichier mitigation_prioritization_enhanced.csv non trouvé dans {chemin_repertoire}")

        # Prendre les fichiers les plus récents
        threat_file = max(threat_files, key=os.path.getmtime)
        exposia_file = max(exposia_files, key=os.path.getmtime)
        mitigation_file = mitigation_files[0]  # Un seul fichier attendu

        return threat_file, exposia_file, mitigation_file

    def load_threat_data(self, threat_file):
        """Charge les données de threat modeling"""
        threat_data = []
        try:
            with open(threat_file, 'r', encoding='utf-8', newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')
                for row in reader:
                    threat_data.append(row)

            return threat_data

        except Exception as e:
            raise Exception(f"Erreur lors du chargement {threat_file}: {str(e)}")

    # Correspondance colonnes CSV Exposia actuel (snake_case) -> noms attendus par R6.
    EXPOSIA_ALIASES = {
        "Vulnerability (CVE)": "cve",
        "Exposia - Qualification": "exposia_qualification",
        "CVSS Score": "cvss_score",
        "CVSS_Vector": "cvss_vector",
        "EPSS Score": "epss_score",
        "Subdomain": "subdomain",
        "IP Address": "ip_address",
        "Port": "port",
        "Catégorie": "category",
        "Internal_External_Classification": "classification",
        "Impact": "impact",
        "Attack_Path_Type": "attack_path_type",
    }

    def load_exposia_data(self, exposia_file):
        """Charge les données Exposia"""
        exposia_data = []
        try:
            with open(exposia_file, 'r', encoding='utf-8', newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')

                for row in reader:
                    # Ajoute les alias attendus par R6 à partir des colonnes réelles.
                    for expected, actual in self.EXPOSIA_ALIASES.items():
                        if expected not in row:
                            row[expected] = (row.get(actual) or "")
                    exposia_data.append(row)

            return exposia_data

        except Exception as e:
            raise Exception(f"Erreur lors du chargement {exposia_file}: {str(e)}")

    def load_mitigation_data(self, mitigation_file):
        """Charge les données de mitigation"""
        mitigation_data = []
        try:
            with open(mitigation_file, 'r', encoding='utf-8', newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')
                for row in reader:
                    mitigation_data.append(row)

            return mitigation_data

        except Exception as e:
            raise Exception(f"Erreur lors du chargement {mitigation_file}: {str(e)}")

    def process_threat_actors(self, threat_data):
        """
        Traite les acteurs de menace avec priorisation.
        Classement par Score_Acteur (score pondéré D3, identique à R1) si présent,
        sinon par l'ancien score motivation × ressources × probabilité.
        """

        # Conversion des scores comme dans part1.py
        def convert_to_score(value):
            conversion = {
                "Very relevant": 5, "Quite relevant": 4, "Moderately relevant": 3,
                "Not really relevant": 2, "Not relevant": 0,
                "High": 5, "Quite": 4, "Poor": 2, "Very low": 1,
                "Unlimited": 5, "Significant": 4, "Important": 3, "Limited": 2
            }
            return conversion.get(value, 0)

        # Grouper par acteur
        actor_groups = defaultdict(list)
        for row in threat_data:
            actor_groups[row['Threat_Actor']].append(row)

        weighted = bool(actor_groups) and all(
            _float(r.get('Score_Acteur'), None) is not None for rows in actor_groups.values() for r in rows
        )

        processed_actors = []
        for actor, motivations in actor_groups.items():
            # Calculer le score maximum
            max_score = 0
            best_motivation = None

            for motivation in motivations:
                motivation_score = convert_to_score(motivation['Niveau_Motivation_Matrice2'])
                resources_score = convert_to_score(motivation['Resources_Matrice3'])
                probability_score = convert_to_score(motivation['Probabilite_Occurrence_Matrice4'])

                individual_score = motivation_score * resources_score * probability_score

                if individual_score > max_score:
                    max_score = individual_score
                    best_motivation = motivation

            # Déterminer le profil de menace
            motivation_count = len(motivations)
            if motivation_count >= 4:
                threat_profile = "Multi-objectifs"
            elif motivation_count == 3:
                threat_profile = "Triple-menace"
            elif motivation_count == 2:
                threat_profile = "Double finalité"
            else:
                threat_profile = "Ciblé"

            processed_actors.append({
                'actor': actor,
                'max_score': max_score,
                'rank_score': _float(motivations[0].get('Score_Acteur')) if weighted else max_score,
                'primary_motivation': best_motivation['Motivation'] if best_motivation else '',
                'motivations': [m['Motivation'] for m in motivations],
                'threat_profile': threat_profile,
                'motivation_count': motivation_count
            })

        # Trier par score décroissant
        processed_actors.sort(key=lambda x: x['rank_score'], reverse=True)

        return processed_actors

    def process_exposia_vulnerabilities(self, exposia_data):
        """Traite les vulnérabilités Exposia avec priorisation et agrégation des assets"""

        # Filtrer les entrées sans CVE valide
        valid_vulns = []
        for row in exposia_data:
            cve = row.get('Vulnerability (CVE)', '').strip()
            if cve and cve not in _NA:
                valid_vulns.append(row)

        # Prioriser par Exposia - Qualification puis EPSS (même ordre que la partie Risques)
        def sort_key(vuln):
            qualification_rank = QUALIF_ORDER.get(vuln.get('Exposia - Qualification', 'Low'), 999)
            return (qualification_rank, -_float(vuln.get('EPSS Score')), -_float(vuln.get('CVSS Score')))

        valid_vulns.sort(key=sort_key)

        return {
            'raw_data': valid_vulns,
            'all_data': exposia_data,  # données complètes
            'total_vulns': len(valid_vulns)
        }

    def match_mitigations_to_cves(self, mitigation_data, cves):
        """Associe toutes les mesures de mitigation aux CVE (priorité CRITIQUE d'abord, puis score)"""

        cve_set = set(cves)
        cve_mitigation_map = {}

        ordered = sorted(
            mitigation_data,
            key=lambda m: (PRIORITY_ORDER.get(str(m.get('priority', '')).strip().upper(), 9),
                           -_float(m.get('final_score')))
        )
        for mitigation in ordered:
            treated_cves = mitigation.get('treated_cves', '')
            if treated_cves:
                cve_list = [cve.strip() for cve in treated_cves.split(',') if cve.strip()]
                for cve in cve_list:
                    if cve in cve_set:
                        cve_mitigation_map.setdefault(cve, []).append(mitigation)

        return cve_mitigation_map

    @staticmethod
    def _impacted_components(vector):
        """Composantes C / I / A à impact élevé d'un vecteur CVSS (v3 : H ; v2 : C)."""
        parts = dict(p.split(':', 1) for p in str(vector or '').split('/') if ':' in p)
        return [k for k in ('C', 'A', 'I') if parts.get(k) in ('H', 'C')]

    # Un acteur pas encore utilisé n'est préféré que s'il reste pertinent :
    # score au moins égal à cette fraction du score de l'acteur le mieux classé.
    ACTOR_DIVERSITY_MIN_RATIO = 0.25

    def select_actor(self, threat_actors, vuln, used_actors=()):
        """
        Acteur dont une motivation correspond à l'impact de la CVE.

        Ordre de préférence :
          1. acteur PAS ENCORE UTILISÉ dans les chaînes précédentes, si son score
             atteint ACTOR_DIVERSITY_MIN_RATIO du meilleur score (variété des scénarios
             sans mettre en avant un acteur marginal) ;
          2. sinon, l'acteur le mieux classé dont une motivation correspond ;
          3. repli : l'acteur le mieux classé, avec sa motivation principale.
        """
        wanted = []
        for comp in self._impacted_components(vuln.get('CVSS_Vector', '')):
            for motivation in IMPACT_TO_MOTIVATIONS[comp]:
                if motivation not in wanted:
                    wanted.append(motivation)

        def first_match(candidates):
            for actor in candidates:
                for motivation in wanted:
                    if motivation in actor['motivations']:
                        return actor, motivation
            return None

        top_score = threat_actors[0]['rank_score'] if threat_actors else 0
        fresh = [a for a in threat_actors
                 if a['actor'] not in used_actors
                 and a['rank_score'] >= self.ACTOR_DIVERSITY_MIN_RATIO * top_score]
        choice = first_match(fresh) or first_match(threat_actors)
        if choice:
            return choice
        top = threat_actors[0]
        return top, top['primary_motivation']

    def _cve_impact_text(self, cve, rows):
        """Récit d'impact de la CVE (ligne de type CVE), ou None."""
        for row in rows:
            if row.get('Vulnerability (CVE)') != cve:
                continue
            if str(row.get('Attack_Path_Type', '')).strip().upper() not in ('', 'CVE'):
                continue
            impact = str(row.get('Impact', '') or '').strip()
            if impact and impact not in _NA:
                return impact
        return None

    def create_attack_paths(self, threat_actors, exposia_vulns, cve_mitigations):
        """Crée les chemins d'attaque complets avec des mesures de mitigation diversifiées"""

        attack_paths = []
        used_mitigations = set()  # Ensemble pour suivre les mesures de mitigation déjà utilisées
        used_actors = set()       # acteurs déjà mis en scène (variété des chaînes)

        if not threat_actors:
            return attack_paths

        # Sélectionner les vulnérabilités uniques par CVE (exposia_vulns est déjà trié)
        unique_vulns = {}
        for vuln in exposia_vulns:
            cve = vuln.get('Vulnerability (CVE)', '')
            if cve not in unique_vulns:
                unique_vulns[cve] = vuln

        # Prendre les 3 vulnérabilités uniques les plus critiques
        top_vulns = list(unique_vulns.values())[:3]

        for i, vuln in enumerate(top_vulns):
            cve = vuln.get('Vulnerability (CVE)', '')

            # Acteur cohérent avec l'impact de la vulnérabilité
            selected_actor, motivation = self.select_actor(threat_actors, vuln, used_actors)
            used_actors.add(selected_actor['actor'])

            # Récupérer toutes les mesures de mitigation associées au CVE
            mitigations = cve_mitigations.get(cve, [])

            # Trouver une mesure de mitigation non utilisée
            mitigation = None
            for mit in mitigations:
                mit_id = mit.get('mitigation_id', 'N/A')
                if mit_id not in used_mitigations:
                    mitigation = mit
                    used_mitigations.add(mit_id)
                    break

            # Si aucune mesure non utilisée n'est trouvée, prendre la première
            if mitigation is None and mitigations:
                mitigation = mitigations[0]

            attack_path = {
                'rank': i + 1,
                'cve': cve,
                'asset': {
                    'subdomain': vuln.get('Subdomain', ''),
                    'ip': vuln.get('IP Address', ''),
                    'port': self._format_port(vuln.get('Port', '')),
                    'classification': vuln.get('Internal_External_Classification', ''),
                    'category': vuln.get('Catégorie', '')
                },
                'vulnerability': {
                    'cve': cve,
                    'cvss': vuln.get('CVSS Score', ''),
                    'qualification': vuln.get('Exposia - Qualification', ''),
                    'category': vuln.get('Catégorie', ''),
                    'impact': self._cve_impact_text(cve, exposia_vulns)
                },
                'actor': {
                    'name': selected_actor['actor'],
                    'motivation': motivation,
                    'profile': selected_actor['threat_profile'],
                    'characteristics': self.config['actor_characteristics'].get(selected_actor['actor'], {})
                },
                'mitigation': {
                    'id': mitigation.get('mitigation_id', 'N/A') if mitigation else 'N/A',
                    'measure': mitigation.get('organizational_measure', 'Mesure non définie') if mitigation else 'Mesure non définie',
                    'cve_count': mitigation.get('cve_count', '0') if mitigation else '0'
                }
            }
            attack_paths.append(attack_path)

        return attack_paths

    def calculate_statistics(self, threat_actors, exposia_vulns, mitigation_data, attack_paths):
        """Calcule les statistiques pour la synthèse exécutive"""

        # Compter les CVE uniques (sur données filtrées)
        unique_cves = set()
        for vuln in exposia_vulns['raw_data']:
            cve = vuln.get('Vulnerability (CVE)', '').strip()
            if cve and cve not in _NA:
                unique_cves.add(cve)

        # Compter les IPs UNIQUES (IPv4 ET IPv6)
        unique_ips = set()
        for vuln in exposia_vulns['all_data']:
            ip = vuln.get('IP Address', '').strip()
            if ip and ip.lower() not in ['no ip found', 'n/a', '', 'none', 'null', 'no data', '#n/a']:
                unique_ips.add(ip)

        # Services distincts exposés = couples (IP, port), même définition que R2
        # (un même IP:port vu sous plusieurs sous-domaines ne compte qu'une fois).
        def _svc_port(p):
            sp = str(p).strip()
            try:
                return str(int(float(sp)))
            except Exception:
                return sp
        distinct_services = set()
        for vuln in exposia_vulns['all_data']:
            ip = (vuln.get('IP Address', '') or '').strip()
            port = (vuln.get('Port', '') or '').strip()
            if (ip and ip.lower() not in ['no ip found', 'n/a', '', 'none', 'null', 'no data', '#n/a']
                    and port and port.lower() not in ['#n/a', 'n/a', '', 'none', 'null']):
                distinct_services.add((ip, _svc_port(port)))

        # Assets critiques
        critical_assets = 0
        for vuln in exposia_vulns['raw_data']:
            qualification = vuln.get('Exposia - Qualification', '')
            if qualification in ['Critical', 'High']:
                critical_assets += 1

        # Top acteurs
        top_actor_types = [actor['actor'] for actor in threat_actors[:3]]

        # Top catégories
        category_counter = Counter()
        for vuln in exposia_vulns['raw_data'][:10]:
            category = vuln.get('Catégorie', '').strip()
            if category:
                category_counter[category] += 1

        top_categories = [cat for cat, _ in category_counter.most_common(3)]

        return {
            'total_actors': len(threat_actors),
            'total_ips': len(unique_ips),
            'total_services': len(distinct_services),
            'total_cves': len(unique_cves),
            'total_mitigations': len(mitigation_data),
            'top_paths': len(attack_paths),
            'critical_assets': critical_assets,
            'top_actor_types': ', '.join(top_actor_types),
            'top_categories': ', '.join(top_categories),
            'qualification_level': attack_paths[0]['vulnerability']['qualification'] if attack_paths else 'N/A'
        }

    def get_level_class(self, qualification):
        """Retourne la classe CSS basée sur la qualification"""
        mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low'
        }
        return mapping.get(qualification, 'low')

    def get_classification_class(self, classification):
        """Retourne la classe CSS pour la classification"""
        if classification and 'external' in classification.lower():
            return 'external'
        return 'internal'

    def get_pdf_css(self):
        """CSS = système Exposia partagé + spécifique à la synthèse."""
        return report_theme.get_exposia_css() + """
        .stats { margin-bottom: 7mm; }

        .chain-card { border:1px solid #E7E9F4; border-radius:3mm; overflow:hidden; margin-bottom:6mm; page-break-inside:avoid; }
        .chain-head { background:#F5F6FD; padding:3mm 5mm; border-bottom:1px solid #E7E9F4; display:flex; align-items:center; }
        .chain-head .sc { font-size:10pt; font-weight:700; color:#20263F; margin-right:3mm; }
        .chain-body { padding:4.5mm 5mm; }
        .chain { display:flex; align-items:stretch; margin-bottom:4.5mm; }
        .chain-el { flex:1; background:#FAFBFE; border:1px solid #EFF1F8; border-radius:2mm; padding:3mm 2mm; text-align:center; }
        .chain-el .cl { font-size:7pt; font-weight:700; letter-spacing:.8pt; text-transform:uppercase; color:#4B47C9; margin-bottom:1.6mm; }
        .chain-el .cm { font-size:9pt; font-weight:700; color:#20263F; word-break:break-word; }
        .chain-el .cd { font-size:7.5pt; color:#8A90AC; margin-top:1mm; word-break:break-word; }
        .chain-arrow { flex:none; display:flex; align-items:center; padding:0 1.5mm; color:#B9BCE8; font-size:12pt; font-weight:700; }
        .chain-narr { font-size:9.5pt; line-height:1.6; color:#3A4160; margin:0; }
        .chain-narr strong { color:#20263F; font-weight:600; }

        .fm-card { border:1px solid #E7E9F4; border-radius:3mm; overflow:hidden; margin-bottom:4mm; page-break-inside:avoid; }
        .fm-head { background:#F5F6FD; padding:2.8mm 5mm; border-bottom:1px solid #E7E9F4; display:flex; justify-content:space-between; align-items:baseline; }
        .fm-head .fid { font-size:10pt; font-weight:700; color:#4B47C9; }
        .fm-head .fcov { font-size:8.5pt; font-weight:600; color:#6A7191; }
        .fm-body { padding:3.5mm 5mm; font-size:9.5pt; color:#20263F; font-weight:600; line-height:1.5; }
        .prose ul { margin:2mm 0 1mm; padding-left:6mm; }
        .prose li { margin-bottom:1.4mm; }
"""

    @staticmethod
    def _format_port(port):
        """'80.0' -> '80' (ports stockés en float par pandas dans le fichier enrichi)."""
        sp = str(port).strip()
        try:
            return str(int(float(sp)))
        except (TypeError, ValueError):
            return sp

    @classmethod
    def _esc_deep(cls, obj):
        """Échappe récursivement toutes les chaînes d'une structure (données injectées dans le HTML)."""
        if isinstance(obj, str):
            return esc(obj)
        if isinstance(obj, dict):
            return {k: cls._esc_deep(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [cls._esc_deep(v) for v in obj]
        return obj

    @staticmethod
    def _lower_first(text):
        """'Il peut…' -> 'il peut…' pour l'insérer en milieu de phrase."""
        text = str(text).strip().rstrip('.')
        return text[:1].lower() + text[1:] if text else text

    @staticmethod
    def priority_measures(mitigation_data, limit=FOCUS_SIZE):
        """
        Mesures prioritaires : les `limit` premières du classement de D2
        (final_score décroissant), soit le même ordre que la partie Mitigation.
        Le tri est stable : à score égal, l'ordre du fichier D2 est conservé.
        """
        ranked = sorted(mitigation_data, key=lambda m: -_float(m.get('final_score')))
        return ranked[:limit]

    def generate_html_content(self, attack_paths, stats, mitigation_data):
        """Génère le contenu HTML de la synthèse (système de design Exposia)."""
        try:
            org = os.path.basename(os.path.dirname(os.path.abspath(os.getcwd())))
        except Exception:
            org = ""
        org_disp = esc(org.capitalize()) if org else "—"

        sev_map = {'Critical': 'sev-critical', 'High': 'sev-high', 'Medium': 'sev-medium', 'Low': 'sev-low'}
        sev_disp = {'Critical': 'Critique', 'High': 'Élevé', 'Medium': 'Moyen', 'Low': 'Faible'}

        # Chaînes de menaces
        chains_html = ""
        for i, path in enumerate(attack_paths):
            path = self._esc_deep(path)
            mid = path['mitigation']['id']
            q = path['vulnerability']['qualification']
            sev_cls = sev_map.get(q, 'sev-low')
            sev_txt = sev_disp.get(q, q)
            impact = path['vulnerability']['impact']
            impact_txt = self._lower_first(impact) if impact else "il peut compromettre votre système d'information"
            if mid != 'N/A':
                remedy = (
                    f"La première mesure consiste à <strong>mettre à jour le logiciel concerné</strong>&nbsp;; "
                    f"la mesure <strong>{mid}</strong> (&laquo;&nbsp;{path['mitigation']['measure']}&nbsp;&raquo;) "
                    f"contribue à réduire durablement ce type de risque."
                )
            else:
                remedy = "La première mesure consiste à <strong>mettre à jour le logiciel concerné</strong>."
            narr = (
                f"Un acteur de type <strong>{path['actor']['name']}</strong> "
                f"(motivation&nbsp;: <strong>{path['actor']['motivation'].lower()}</strong>) cible <strong>{path['asset']['subdomain']}</strong> "
                f"({path['asset']['ip']}:{path['asset']['port']}). En exploitant la vulnérabilité "
                f"<strong>{path['vulnerability']['cve']}</strong> sur votre <strong>{path['vulnerability']['category']}</strong>, "
                f"{impact_txt}. {remedy}"
            )
            cov = path['mitigation']['cve_count']
            cov_txt = f"Couvre {cov} vuln." if str(cov).strip() not in ('', '0') else "Bonne pratique"
            chains_html += f"""
  <div class="chain-card">
    <div class="chain-head"><span class="sc">Sc&eacute;nario {i + 1}</span><span class="sev-badge {sev_cls}">{sev_txt}</span></div>
    <div class="chain-body">
      <div class="chain">
        <div class="chain-el"><div class="cl">Acteur</div><div class="cm">{path['actor']['name']}</div><div class="cd">{path['actor']['motivation']}</div></div>
        <div class="chain-arrow">&rarr;</div>
        <div class="chain-el"><div class="cl">Actif</div><div class="cm">{path['asset']['subdomain']}</div><div class="cd">{path['asset']['ip']}:{path['asset']['port']}</div></div>
        <div class="chain-arrow">&rarr;</div>
        <div class="chain-el"><div class="cl">Vecteur</div><div class="cm">{path['vulnerability']['category']}</div><div class="cd">{path['vulnerability']['cve']}</div></div>
        <div class="chain-arrow">&rarr;</div>
        <div class="chain-el"><div class="cl">Mitigation</div><div class="cm">{mid}</div><div class="cd">{cov_txt}</div></div>
      </div>
      <p class="chain-narr">{narr}</p>
    </div>
  </div>"""

        # Focus mesures prioritaires : top du classement D2, même ordre que la partie 4.
        focus_html = ""
        for measure in self.priority_measures(mitigation_data):
            measure_id = esc(str(measure.get('mitigation_id', '')))
            measure_text = esc(str(measure.get('organizational_measure', 'Mesure non définie')))
            try:
                n_cve = int(_float(measure.get('cve_count'), 0))
            except (TypeError, ValueError):
                n_cve = 0
            if n_cve > 0:
                cov_txt = f"Couvre {n_cve} vuln&eacute;rabilit&eacute;{'s' if n_cve > 1 else ''}"
            else:
                cov_txt = "Bonne pratique"
            focus_html += f"""
  <div class="fm-card">
    <div class="fm-head"><span class="fid">{measure_id}</span><span class="fcov">{cov_txt}</span></div>
    <div class="fm-body">{measure_text}</div>
  </div>"""

        # Encadré « En clair » : formulation adaptée aux cas vides.
        n_act, n_cves = stats['total_actors'], stats['total_cves']
        n_svc, n_mit = stats['total_services'], stats['total_mitigations']
        s_act = 's' if n_act > 1 else ''
        s_svc = 's' if n_svc > 1 else ''
        if n_cves:
            synthesis_callout = (
                f"Notre analyse r&eacute;v&egrave;le <strong>{n_act} profil{s_act} d'attaque</strong> susceptible{s_act} "
                f"d'exploiter <strong>{n_cves} vuln&eacute;rabilit&eacute;{'s' if n_cves > 1 else ''}</strong> sur "
                f"<strong>{n_svc} service{s_svc}</strong> expos&eacute;{s_svc}. La priorit&eacute; est la "
                f"<strong>mise &agrave; jour des logiciels concern&eacute;s</strong>."
            )
        else:
            synthesis_callout = (
                f"Notre analyse r&eacute;v&egrave;le <strong>{n_act} profil{s_act} d'attaque</strong> susceptible{s_act} "
                f"de cibler votre organisation et <strong>{n_svc} service{s_svc}</strong> expos&eacute;{s_svc}, sans "
                f"vuln&eacute;rabilit&eacute; connue identifi&eacute;e. L'enjeu est de <strong>maintenir ce niveau</strong>&nbsp;: "
                f"mises &agrave; jour r&eacute;guli&egrave;res et services expos&eacute;s limit&eacute;s au strict n&eacute;cessaire."
            )
        if n_mit:
            synthesis_callout += (
                f" En compl&eacute;ment, <strong>{n_mit} mesure{'s' if n_mit > 1 else ''}</strong> "
                f"{'composent' if n_mit > 1 else 'compose'} une feuille de route pour r&eacute;duire durablement l'exposition et concentrer les efforts "
                f"l&agrave; o&ugrave; ils cr&eacute;ent le plus de valeur."
            )

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Synth&egrave;se globale</title></head>
<body>
  <div class="rh-brand">E<span class="x">x</span>posia</div>
  <div class="rh-doc">Rapport d'analyse &middot; {org_disp}</div>

  <div class="kicker">Synth&egrave;se</div>
  <div class="part-title">De la menace &agrave; la mitigation</div>
  <div class="rule"></div>

  <div class="callout">
    <div class="ttl">En clair</div>
    <p>{synthesis_callout}</p>
  </div>

  <div class="xsection"><span class="t">M&eacute;thodologie</span></div>
  <div class="prose">
    <p>Notre d&eacute;marche croise quatre volets compl&eacute;mentaires pour vous donner une vision claire et hi&eacute;rarchis&eacute;e de vos risques&nbsp;:</p>
    <ul>
      <li><b>Threat Modeling</b> &mdash; identification des <b>attaquants les plus cr&eacute;dibles</b> selon votre profil.</li>
      <li><b>Asset Discovery</b> &mdash; cartographie de votre <b>p&eacute;rim&egrave;tre expos&eacute;</b> (sous-domaines, services, ports).</li>
      <li><b>Risk Assessment</b> &mdash; mise en &eacute;vidence des <b>vuln&eacute;rabilit&eacute;s exploitables</b> et des <b>sc&eacute;narios d'attaque types</b>.</li>
      <li><b>Mitigation Plan</b> &mdash; s&eacute;lection et classement des <b>bonnes pratiques</b> les plus utiles.</li>
    </ul>
    <p>Chaque cha&icirc;ne ci-dessous relie une vuln&eacute;rabilit&eacute; prioritaire &agrave; un profil d'attaquant dont les motivations sont compatibles avec les impacts envisag&eacute;s, pour rendre le sc&eacute;nario et la r&eacute;ponse &agrave; y apporter plus concrets.</p>
  </div>

  <div class="xsection" style="page-break-before: always;"><span class="t">Cha&icirc;nes de menaces</span></div>
  {chains_html if chains_html else '<p class="prose" style="color:#8A90AC;font-style:italic;">Aucune cha&icirc;ne de menace significative identifi&eacute;e.</p>'}

  <div class="xsection"><span class="t">Focus sur les mesures prioritaires</span></div>
  {focus_html if focus_html else '<p class="prose" style="color:#8A90AC;font-style:italic;">Aucune mesure prioritaire associ&eacute;e.</p>'}
</body>
</html>"""
        return html

    def generate_pdf_report(self, attack_paths, stats, mitigation_data):
        """Génère le rapport PDF avec WeasyPrint"""

        try:
            # Génération du contenu HTML
            html_content = self.generate_html_content(attack_paths, stats, mitigation_data)

            # Configuration des polices
            font_config = FontConfiguration()

            # CSS optimisé pour PDF
            css_content = self.get_pdf_css()

            # Création du PDF
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)

            # Génération du nom de fichier
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"synthesis_global_report_{timestamp}.pdf"

            # Écriture du PDF
            html_doc.write_pdf(pdf_filename, stylesheets=[css_doc], font_config=font_config)

            ModernUI.status(f"PDF généré avec succès: {pdf_filename}", "success")
            return pdf_filename

        except Exception as e:
            ModernUI.status(f"Erreur lors de la génération PDF: {str(e)}", "error")
            raise

    def generate_report(self):
        """Fonction principale qui orchestrate la génération du rapport PDF"""
        try:

            # Vérification de WeasyPrint
            try:
                from weasyprint import HTML
            except ImportError:
                ModernUI.status("WeasyPrint non installé. Installation requise:", "error")
                print("   pip install weasyprint")
                raise ImportError("WeasyPrint requis pour la génération PDF")

            # 1. Détection des fichiers CSV
            threat_file, exposia_file, mitigation_file = self.find_csv_files()

            # 2. Chargement des données
            threat_data = self.load_threat_data(threat_file)
            exposia_data = self.load_exposia_data(exposia_file)
            mitigation_data = self.load_mitigation_data(mitigation_file)

            # 3. Traitement des données
            threat_actors = self.process_threat_actors(threat_data)
            exposia_vulns = self.process_exposia_vulnerabilities(exposia_data)

            # 4. Association CVE-Mitigations
            cves = [vuln.get('Vulnerability (CVE)', '') for vuln in exposia_vulns['raw_data']]
            cve_mitigations = self.match_mitigations_to_cves(mitigation_data, cves)

            # 5. Création des chemins d'attaque
            attack_paths = self.create_attack_paths(threat_actors, exposia_vulns['raw_data'], cve_mitigations)

            # 6. Calcul des statistiques
            stats = self.calculate_statistics(threat_actors, exposia_vulns, mitigation_data, attack_paths)

            # 7. Génération du PDF
            pdf_filename = self.generate_pdf_report(attack_paths, stats, mitigation_data)


            return pdf_filename

        except Exception as e:
            ModernUI.status(f"Erreur: {str(e)}", "error")
            raise

def main():
    """Point d'entrée : résout le dossier data/ de la campagne puis génère la synthèse."""
    import argparse
    ap = argparse.ArgumentParser(description="Rapport de synthèse globale (Partie 5).")
    ap.add_argument("-r", "--result-dir", default=None, help="Dossier de campagne.")
    ap.add_argument("--domain", default=None, help="Domaine analysé.")
    args = ap.parse_args()

    data_dir = exposia_paths.resolve_data_dir(args.result_dir, args.domain)
    os.chdir(data_dir)

    generator = SynthesisGlobalPDFGenerator()
    generator.generate_report()


if __name__ == "__main__":
    main()