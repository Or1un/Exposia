#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de Rapport Threat Modeling PDF
Lit automatiquement le fichier threat_analysis_*.csv et génère un rapport PDF
Version optimisée avec WeasyPrint pour un rendu PDF professionnel

Classement et niveau des acteurs : fondés sur la colonne Score_Acteur exportée
par D3 (score final pondéré par secteur, taille, zone et note ASM). Un fichier
threat_analysis plus ancien, sans cette colonne, reste lisible : on retombe
alors sur l'ancien calcul (motivation × ressources × probabilité).
"""

import csv
import re
from html import escape as esc  # échappement HTML de toute valeur injectée dans un rapport
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_scoring as scoring  # seuils de niveau d'acteur (partagés avec le digest R12)
import exposia_vocab as vocab  # codes stables (JSON canonique)
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

# Libellés des matrices M2 / M3 / M4 (anglais) -> français affiché dans le rapport.
FR_MOTIVATION = {"High": "élevé", "Quite": "modéré", "Poor": "faible", "Very low": "très faible"}
FR_RESOURCES = {"Unlimited": "illimitées", "Important": "importantes",
                "Significant": "significatives", "Limited": "limitées"}
FR_RELEVANCE = {"Very relevant": "très élevée", "Quite relevant": "modérée",
                "Moderately relevant": "limitée", "Not really relevant": "faible"}


import exposia_i18n as i18n  # langue des livrables (EXPOSIA_LANG)
from exposia_i18n import tr

# Textes fixes de la partie 1 (FR, EN)
T = {
    'title_tag': ("Rapport Threat Modeling", "Threat Modeling report"),
    'kicker': ("Partie 1 &middot; Menaces", "Part 1 &middot; Threats"),
    'title': ("Qui vous attaque, et pourquoi&nbsp;?", "Who is targeting you, and why?"),
    'method': ("Notre approche du <b>threat modeling</b> croise le profil de votre organisation &mdash; <b>secteur, taille, zone g&eacute;ographique et niveau d'exposition</b> &mdash; avec les caract&eacute;ristiques de <b>huit types d'acteurs malveillants</b>. Nous analysons leurs motivations &mdash; <b>espionnage, profit, sabotage, influence</b> &mdash; pour compl&eacute;ter l'analyse des menaces en tenant compte de votre profil, puis nous pond&eacute;rons chaque acteur selon ces m&ecirc;mes crit&egrave;res afin de le <b>hi&eacute;rarchiser par un filtrage probabiliste</b>. En clair&nbsp;: nous identifions <b>qui peut vous attaquer, pourquoi et avec quel niveau de pertinence au regard de votre profil</b>.",
               "Our <b>threat modeling</b> approach cross-references your organization's profile &mdash; <b>sector, size, geographic zone and exposure level</b> &mdash; with the characteristics of <b>eight types of malicious actors</b>. We analyse their motivations &mdash; <b>espionage, profit, sabotage, influence</b> &mdash; to complete the threat analysis in light of your profile, then weight each actor against these same criteria in order to <b>rank them through probabilistic filtering</b>. In short: we identify <b>who may attack you, why, and how relevant each threat is to your profile</b>."),
    'matrix': ("Matrice de priorisation des menaces", "Threat prioritization matrix"),
    'th': ("<th>Rang</th><th>Acteur</th><th>Motivation principale</th><th>Profil</th><th class=\"center\">Niveau</th>",
           "<th>Rank</th><th>Actor</th><th>Primary motivation</th><th>Profile</th><th class=\"center\">Level</th>"),
    'profiles': ("Profils d'attaquants d&eacute;taill&eacute;s", "Detailed attacker profiles"),
    'profile': ("Profil&nbsp;: {p} &bull; {n} {mot}", "Profile: {p} &bull; {n} {mot}"),
    'meta': ("<b>Sophistication</b>&nbsp;: {s} &nbsp;&bull;&nbsp; <b>Ressources</b>&nbsp;: {r} &nbsp;&bull;&nbsp; <b>Probabilit&eacute;</b>&nbsp;: {p}",
             "<b>Sophistication</b>: {s} &nbsp;&bull;&nbsp; <b>Resources</b>: {r} &nbsp;&bull;&nbsp; <b>Probability</b>: {p}"),
    'typology': ("Typologie", "Typology"),
    'motivations': ("Motivations identifi&eacute;es", "Identified motivations"),
    'mot_line': ("Niveau {l} &times; Ressources {r} &times; Pertinence {p}", "Level {l} &times; Resources {r} &times; Relevance {p}"),
    'no_desc': ("Description non disponible.", "Description not available."),
}
LEVEL_TEXT = {'critical': ('CRITIQUE', 'CRITICAL'), 'high': ('ÉLEVÉ', 'HIGH'),
              'medium': ('MODÉRÉ', 'MODERATE'), 'low': ('FAIBLE', 'LOW')}

# Typologies des acteurs en anglais (clé : nom français de l'acteur, comme actor_descriptions)
ACTOR_DESCRIPTIONS_EN = {
    'Étatique': """These groups have <strong>unlimited resources and cutting-edge expertise</strong>.
            They operate over the long term with strategic objectives:
            <strong>economic espionage</strong>, <strong>political influence</strong>,
            <strong>geopolitical positioning</strong>, or <strong>sabotage of critical infrastructure</strong>.
            Their approach favours <strong>stealth</strong> and <strong>persistence</strong> to avoid detection.""",
    'Crime organisé': """Driven by <strong>financial profit</strong>, these groups operate like criminal businesses,
            with structured business models (ransomware-as-a-service, banking fraud, data theft).
            They often target <strong>small and medium-sized businesses</strong> because of their greater vulnerability.
            Their attacks are generally <strong>opportunistic</strong> but well organised.""",
    'Terroriste': """They use cyberspace to complement their physical actions:
            <strong>propaganda</strong>, <strong>recruitment</strong>, <strong>symbolic sabotage</strong>,
            or <strong>psychological attacks</strong> (e.g. website defacement).
            Their technical sophistication varies, but their media impact is often disproportionate.""",
    'Activiste': """Driven by <strong>ideological convictions</strong> (political, social, environmental),
            they aim to <strong>damage the image</strong> of their targets through visible actions:
            <strong>data leaks</strong>, <strong>defacements</strong>, or <strong>DDoS</strong>.
            Their attacks are rarely destructive but can have a <strong>major reputational impact</strong>.""",
    'Officine': """Mercenary companies or parallel intelligence services, they operate in a <strong>legal grey area</strong>.
            Their missions include <strong>industrial espionage</strong>, <strong>intelligence gathering</strong>,
            or <strong>circumventing regulations</strong> on behalf of third-party clients (states, companies).
            Their sophistication is high, with techniques close to those of APTs.""",
    'Amateur': """Inexperienced actors using <strong>public tools</strong> (e.g. Metasploit, automated SQLi).
            Their motivations are often <strong>personal challenge</strong> or <strong>vandalism</strong>,
            but they can unintentionally cause <strong>significant damage</strong>
            by exploiting known vulnerabilities.""",
    'Vengeur': """Disgruntled employees, contractors or former staff. Their <strong>inside knowledge</strong>
            of systems makes them particularly dangerous: <strong>data theft</strong>,
            <strong>sabotage</strong>, or <strong>strategic leaks</strong>.
            Their attacks are hard to detect in advance because of their <strong>apparent legitimacy</strong>.""",
    'Malveillant': """Driven by <strong>technical recognition</strong> or <strong>intellectual challenge</strong>,
            they exploit vulnerabilities to prove their skills (e.g. taking part in underground CTFs).
            Although their actions do not always seek direct gain, they can serve as an
            <strong>entry point</strong> for more serious attacks.""",
}


def _cap(text):
    """Première lettre en majuscule (libellés anglais en tête de champ)."""
    text = str(text)
    return text[:1].upper() + text[1:]


def _fr(table, value):
    """Traduit un libellé de matrice ; repli sur la valeur d'origine si inconnue."""
    return table.get(str(value).strip(), value)


class ThreatReportPDFGenerator:
    def __init__(self, data_dir=None):
        # Répertoire des CSV d'entrée : dossier courant par défaut, surchargeable.
        self.data_dir = data_dir or "."
        self.config = {
            # Seuils de l'ancien score (motivation × ressources × probabilité, max 125).
            # Utilisés uniquement pour un fichier sans colonne Score_Acteur.
            'thresholds': {
                'critical': 80,
                'high': 50,
                'medium': 20
            },
            # Seuils du score pondéré D3 (Score_Acteur). Calibrés sur la distribution
            # de tous les profils possibles (10 secteurs × 4 tailles × 8 zones × 4 notes
            # ASM, 7 424 couples acteur/profil) : CRITIQUE ≈ 13 % les plus élevés,
            # ÉLEVÉ ≈ 20 % suivants, MODÉRÉ ≈ 30 % suivants. À recalibrer si les
            # matrices M1..M7 évoluent sensiblement.
            'score_thresholds': dict(scoring.ACTOR_SCORE_THRESHOLDS),
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
            'motivation_icons': {
                'Espionnage': '🔍',
                'Influence': '📢',
                'Géopositionnement stratégique': '🗺️',
                'Entrave au fonctionnement': '⚡',
                'Lucratif': '💰',
                'Défi, amusement': '🎮'
            },
            'profile_emojis': ['🥇', '🥈', '🥉', '4', '5', '6', '7', '8']
        }

        self.actor_characteristics = {
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

        self.actor_descriptions = {
            'Étatique': """
            Ces groupes disposent de <strong>ressources illimitées et d'une expertise de pointe</strong>.
            Ils opèrent sur le long terme avec des objectifs stratégiques&nbsp;:
            <strong>espionnage économique</strong>, <strong>influence politique</strong>,
            <strong>positionnement géopolitique</strong>, ou <strong>sabotage d'infrastructures critiques</strong>.
            Leur approche privilégie la <strong>furtivité</strong> et la <strong>persistance</strong> pour éviter la détection.
            """,
            'Crime organisé': """
            Motivés par le <strong>profit financier</strong>, ces groupes agissent comme des entreprises criminelles,
            avec des modèles économiques structurés (ransomware-as-a-service, fraude bancaire, vol de données).
            Ils ciblent souvent les <strong>TPE/PME</strong> en raison de leur vulnérabilité accrue.
            Leurs attaques sont généralement <strong>opportunistes</strong> mais bien organisées.</p>
            """,
            'Terroriste': """
            Utilisation du cyberespace pour compléter leurs actions physiques :
            <strong>propagande</strong>, <strong>recrutement</strong>, <strong>sabotage symbolique</strong>,
            ou <strong>attaques psychologiques</strong> (ex: défacement de sites).
            Leur sophistication technique est variable, mais leur impact médiatique est souvent disproportionné.</p>
            """,
            'Activiste': """
            Animés par des <strong>convictions idéologiques</strong> (politiques, sociales, environnementales),
            ils visent à <strong>nuire à l'image</strong> de leurs cibles via des actions visibles :
            <strong>fuites de données</strong>, <strong>défacements</strong>, ou <strong>DDoS</strong>.
            Leurs attaques sont rarement destructrices mais peuvent avoir un <strong>impact réputationnel majeur</strong>.</p>
            """,
            'Officine': """
            Sociétés mercenaires ou services de renseignement parallèles, elles opèrent dans une <strong>zone grise légale</strong>.
            Leurs missions incluent l'<strong>espionnage industriel</strong>, la <strong>collecte de renseignements</strong>,
            ou le <strong>contournement de réglementations</strong> pour le compte de clients tiers (États, entreprises).
            Leur sophistication est élevée, avec des techniques proches des APT.</p>
            """,
            'Amateur': """
            Acteurs peu expérimentés utilisant des <strong>outils publics</strong> (ex: Metasploit, SQLi automatisés).
            Leurs motivations sont souvent le <strong>défi personnel</strong> ou le <strong>vandalisme</strong>,
            mais ils peuvent involontairement causer des <strong>dommages significatifs</strong>
            en exploitant des vulnérabilités connues.</p>
            """,
            'Vengeur': """
            Employés, prestataires ou anciens collaborateurs mécontents. Leur <strong>connaissance interne</strong>
            des systèmes les rend particulièrement dangereux : <strong>vol de données</strong>,
            <strong>sabotage</strong>, ou <strong>fuites stratégiques</strong>.
            Leurs attaques sont difficiles à détecter en amont en raison de leur <strong>légitimité apparente</strong>.</p>
            """,
            'Malveillant': """
            Motivés par la <strong>reconnaissance technique</strong> ou le <strong>défi intellectuel</strong>,
            ils exploitent les vulnérabilités pour prouver leurs compétences (ex: participation à des CTF underground).
            Bien que leurs actions ne visent pas toujours un gain direct, elles peuvent servir de
            <strong>porte d'entrée</strong> pour des attaques plus graves.</p>
            """
        }

    def convert_to_score(self, value):
        """Convertit les valeurs qualitatives en scores numériques"""
        conversion = {
            # Probabilité/Relevance levels
            "Very relevant": 5,
            "Quite relevant": 4,
            "Moderately relevant": 3,
            "Not really relevant": 2,
            "Not relevant": 0,

            # Motivation levels
            "High": 5,
            "Quite": 4,
            "Poor": 2,
            "Very low": 1,

            # Resource levels
            "Unlimited": 5,
            "Important": 4,
            "Significant": 3,
            "Limited": 2
        }
        return conversion.get(value, 0)

    @staticmethod
    def _parse_score(value):
        """Score_Acteur -> float, ou None si absent / illisible."""
        try:
            return float(str(value).strip().replace(',', '.'))
        except (TypeError, ValueError):
            return None

    def find_csv_file(self):
        """Trouve le fichier threat_analysis_*.csv le plus récent dans self.data_dir."""
        motif = os.path.join(self.data_dir, "threat_analysis_*.csv")
        csv_files = glob.glob(motif)
        if not csv_files:
            raise FileNotFoundError(
                f"Aucun fichier threat_analysis_*.csv trouvé dans {os.path.abspath(self.data_dir)}")
        latest_file = max(csv_files, key=os.path.getmtime)
        return latest_file

    def load_csv_data(self, filename):
        """Charge et parse les données CSV (Score_Acteur optionnel)."""
        data = []
        try:
            with open(filename, 'r', encoding='utf-8', newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')

                required_columns = ['Threat_Actor', 'Motivation', 'Niveau_Motivation_Matrice2',
                                  'Resources_Matrice3', 'Probabilite_Occurrence_Matrice4']
                missing_columns = [col for col in required_columns if col not in reader.fieldnames]

                if missing_columns:
                    raise ValueError(f"Colonnes manquantes dans le CSV: {', '.join(missing_columns)}")

                for row in reader:
                    data.append(row)

            return data

        except Exception as e:
            raise Exception(f"Erreur lors de la lecture du CSV: {str(e)}")

    def process_data(self, csv_data):
        """Traite les données CSV avec scoring et agrégation"""

        scored_data = []
        for row in csv_data:
            motivation_score = self.convert_to_score(row['Niveau_Motivation_Matrice2'])
            resources_score = self.convert_to_score(row['Resources_Matrice3'])
            probability_score = self.convert_to_score(row['Probabilite_Occurrence_Matrice4'])

            individual_score = motivation_score * resources_score * probability_score

            scored_data.append({
                'actor': row['Threat_Actor'],
                'motivation': row['Motivation'],
                'motivation_level': row['Niveau_Motivation_Matrice2'],
                'resources': row['Resources_Matrice3'],
                'probability': row['Probabilite_Occurrence_Matrice4'],
                'motivation_score': motivation_score,
                'resources_score': resources_score,
                'probability_score': probability_score,
                'individual_score': individual_score,
                'actor_score': self._parse_score(row.get('Score_Acteur'))
            })

        actor_groups = defaultdict(list)
        for item in scored_data:
            actor_groups[item['actor']].append(item)

        # Score pondéré D3 disponible pour tous les acteurs ?
        weighted = bool(actor_groups) and all(
            m['actor_score'] is not None for motivations in actor_groups.values() for m in motivations
        )
        if not weighted:
            ModernUI.status("Score_Acteur absent du fichier threat_analysis : classement sur "
                            "l'ancien score (sans pondération taille / zone / ASM)", "warning")

        aggregated_actors = []
        for actor, motivations in actor_groups.items():
            max_score = max(m['individual_score'] for m in motivations)
            # À score égal, ordre de la matrice M2 (règle documentée, identique dans R6).
            sorted_motivations = sorted(motivations, key=lambda x: (-x['individual_score'],
                                                                    vocab.rank('motivation', x['motivation'])))

            motivation_count = len(motivations)
            if motivation_count >= 4:
                threat_profile = "Multi-objectifs"
            elif motivation_count == 3:
                threat_profile = "Triple-menace"
            elif motivation_count == 2:
                threat_profile = "Double finalité"
            else:
                threat_profile = "Ciblé"

            # Score de classement : pondéré (D3) si disponible, sinon ancien score.
            rank_score = motivations[0]['actor_score'] if weighted else max_score
            level_class, level_text = self.get_level_info(
                rank_score,
                self.config['score_thresholds'] if weighted else self.config['thresholds']
            )

            aggregated_actors.append({
                'actor': actor,
                'max_score': max_score,
                'rank_score': rank_score,
                'level_class': level_class,
                'level_text': level_text,
                'motivation_count': motivation_count,
                'primary_motivation': sorted_motivations[0]['motivation'],
                'all_motivations': sorted_motivations,
                'threat_profile': threat_profile
            })

        # À score égal, ordre de la matrice M1 (Étatique, Crime organisé…), identique dans R6.
        prioritized_actors = sorted(aggregated_actors, key=lambda x: (-x['rank_score'], vocab.rank('actor', x['actor'])))


        return {
            'actors': prioritized_actors,
            'total_actors': len(prioritized_actors),
            'raw_data': scored_data
        }

    def generate_executive_summary(self, data):
        """Génère la synthèse exécutive dynamique"""
        actors = data['actors']
        all_motivations = [m for actor in actors for m in actor['all_motivations']]

        critical_actors = [a for a in actors if a['level_class'] == 'critical']

        motivation_counts = Counter(m['motivation'] for m in all_motivations)
        top_motivation, top_count = motivation_counts.most_common(1)[0]
        top_motivation_percent = round((top_count / len(all_motivations)) * 100)

        critical_names = [i18n.label('actor', a['actor']) for a in critical_actors]
        and_ = i18n.pick(" et ", " and ")
        if len(critical_names) > 2:
            critical_list = ', '.join(critical_names[:-1]) + f"{and_}{critical_names[-1]}"
        elif len(critical_names) == 2:
            critical_list = f"{critical_names[0]}{and_}{critical_names[1]}"
        elif len(critical_names) == 1:
            critical_list = critical_names[0]
        else:
            critical_list = ""

        return {
            'total_actors': len(actors),
            'critical_count': len(critical_actors),
            'critical_list': critical_list,
            'top_actor': actors[0]['actor'] if actors else "",
            'top_motivation': top_motivation,
            'top_motivation_percent': top_motivation_percent,
            'total_motivations': len(all_motivations)
        }

    def get_level_info(self, score, thresholds=None):
        """Détermine le niveau de criticité d'un score selon les seuils fournis."""
        thresholds = thresholds or self.config['thresholds']
        if score >= thresholds['critical']:
            level = 'critical'
        elif score >= thresholds['high']:
            level = 'high'
        elif score >= thresholds['medium']:
            level = 'medium'
        else:
            level = 'low'
        return level, i18n.pick(*LEVEL_TEXT[level])

    @staticmethod
    def _motivation_line(m):
        """« Niveau … × Ressources … × Pertinence … » d'une motivation (libellés de matrice)."""
        if i18n.is_en():
            vals = [vocab.label(v, vocab.code(v, m[k]), 'en', fallback=str(m[k]))
                    for v, k in (('motivation_level', 'motivation_level'), ('resources_level', 'resources'),
                                 ('relevance', 'probability'))]
        else:
            vals = [_fr(FR_MOTIVATION, m['motivation_level']), _fr(FR_RESOURCES, m['resources']),
                    _fr(FR_RELEVANCE, m['probability'])]
        return tr(T, 'mot_line', **{k: esc(str(v)) for k, v in zip('lrp', vals)})

    def get_pdf_css(self):
        """CSS = système Exposia partagé + spécifique aux cartes d'acteurs détaillées."""
        return report_theme.get_exposia_css() + """
        .threat-actor { border:1px solid #E7E9F4; border-radius:3mm; overflow:hidden; margin-bottom:6mm; page-break-inside:avoid; }
        .threat-head { padding:2.8mm 5mm; color:#fff; display:flex; align-items:baseline; }
        .threat-head.sev-critical { background:#D8434C; }
        .threat-head.sev-high { background:#E8823C; }
        .threat-head.sev-medium { background:#E0A94A; color:#3A2A0C; }
        .threat-head.sev-low { background:#6BA84E; }
        .threat-head .name { font-size:11pt; font-weight:700; letter-spacing:.3pt; }
        .threat-head .prof { font-size:8.5pt; opacity:.9; font-weight:500; margin-left:4mm; padding-left:4mm; border-left:1px solid rgba(255,255,255,.4); }
        .threat-body { padding:4.5mm 5mm; }
        .threat-meta { font-size:9pt; color:#454B68; margin-bottom:3.5mm; }
        .threat-meta b { color:#20263F; }
        .typology { background:#F5F6FD; border-radius:2mm; padding:3.5mm 4mm; margin-bottom:3.5mm; }
        .typology .tt { font-weight:700; color:#3B37AE; font-size:8pt; letter-spacing:.8pt; text-transform:uppercase; display:block; margin-bottom:1.5mm; }
        .typology p { font-size:9.5pt; line-height:1.6; color:#3A4160; margin:0; }
        .typology strong { color:#20263F; }
        .mot-title { font-size:8.5pt; font-weight:700; letter-spacing:.8pt; text-transform:uppercase; color:#6A7191; margin:0 0 2.5mm; }
        .mot-list { list-style:none; padding:0; margin:0; }
        .mot-item { padding:2.4mm 0 2.4mm 5mm; position:relative; border-top:1px solid #EFF1F8; }
        .mot-item:first-child { border-top:none; }
        .mot-item::before { content:""; position:absolute; left:0; top:3.4mm; width:2.4mm; height:2.4mm; border-radius:50%; background:#4B47C9; }
        .mot-item.secondary::before { background:#B9BCE8; }
        .mot-item .m { font-weight:600; color:#20263F; font-size:10pt; }
        .mot-item .d { font-size:8.5pt; color:#8A90AC; margin-top:.8mm; }
"""

    # ------------------------------------------------------------------
    # Données de la partie (source unique du PDF et du JSON canonique)
    # ------------------------------------------------------------------
    @staticmethod
    def build_in_short(summary):
        """Encadré « En clair » de la partie Menaces (segments)."""
        seg = report_theme.seg
        crit = summary['critical_count']
        if i18n.is_en():
            pl = i18n.plural
            n = summary['total_actors']
            p = [seg("The analysis identified "), seg(f"{n} attacker {pl(n, 'profile')}", True),
                 seg(" likely to target your organization. ")]
            if crit:
                p += [seg("Among them, "), seg(f"{crit} {pl(crit, 'actor')} rated critical", True),
                      seg(f" ({summary['critical_list']}) {'deserves' if crit == 1 else 'deserve'} particular attention.")]
            else:
                p += [seg("None reaches the critical level given your profile; the most relevant is "),
                      seg(i18n.label('actor', summary['top_actor']), True), seg(".")]
            p += [seg(" The most common motivation is "),
                  seg(f"\u201c{i18n.label('motivation', summary['top_motivation'])}\u201d", True), seg(", associated with "),
                  seg(f"{summary['top_motivation_percent']}% of potential attacks", True), seg(".")]
            return {'paragraphs': [p], 'facts': ThreatReportPDFGenerator._facts(summary, crit)}
        s_crit = 's' if crit > 1 else ''
        p = [seg("L'analyse a identifié "), seg(f"{summary['total_actors']} profils d'attaquants", True),
             seg(" susceptibles de cibler votre organisation. ")]
        if crit:
            p += [seg("Parmi eux, "), seg(f"{crit} acteur{s_crit} classé{s_crit} critique{s_crit}", True),
                  seg(f" ({summary['critical_list']}) mérite{'nt' if crit > 1 else ''} une attention particulière.")]
        else:
            p += [seg("Aucun n'atteint le niveau critique au regard de votre profil\u00a0; le plus pertinent est "),
                  seg(str(summary['top_actor']), True), seg(".")]
        p += [seg(" La motivation la plus représentée est "),
              seg(f"«\u00a0{summary['top_motivation']}\u00a0»", True), seg(", associée à "),
              seg(f"{summary['top_motivation_percent']}\u00a0% des attaques potentielles", True), seg(".")]
        return {'paragraphs': [p], 'facts': ThreatReportPDFGenerator._facts(summary, crit)}

    @staticmethod
    def _facts(summary, crit):
        return {'actors': summary['total_actors'], 'critical_actors': crit,
                'top_actor': vocab.code('actor', summary['top_actor']),
                'top_motivation': vocab.code('motivation', summary['top_motivation']),
                'top_motivation_percent': summary['top_motivation_percent']}

    def _description(self, actor, default):
        """Typologie HTML d'un acteur dans la langue du run."""
        if i18n.is_en():
            return ACTOR_DESCRIPTIONS_EN.get(actor, default)
        return self.actor_descriptions.get(actor, default)

    @staticmethod
    def _characteristic(vocab_name, value):
        """Sophistication / ressources / probabilité affichées (FR : texte d'origine)."""
        return _cap(i18n.label(vocab_name, value)) if i18n.is_en() else value

    @staticmethod
    def _plain_text(html_text):
        """Description HTML d'un acteur -> texte brut (balises retirées, espaces normalisés)."""
        from html import unescape
        return re.sub(r'\s+', ' ', unescape(re.sub(r'<[^>]+>', '', html_text))).strip()

    def build_data(self, data):
        """Bloc parts.threats du JSON canonique : « En clair » et données des visuels (codes)."""
        actors = data['actors']
        matrix = [{
            'rank': rank, 'actor': vocab.code('actor', a['actor']),
            'primary_motivation': vocab.code('motivation', a['primary_motivation']),
            'profile_type': vocab.code('profile_type', a['threat_profile']),
            'motivation_count': a['motivation_count'], 'level': a['level_class'],
            'score': round(float(a['rank_score']), 2),
        } for rank, a in enumerate(actors, 1)]
        profiles = []
        for a in actors[:3]:
            ch = self.actor_characteristics.get(a['actor'], {})
            profiles.append({
                'actor': vocab.code('actor', a['actor']), 'level': a['level_class'],
                'profile_type': vocab.code('profile_type', a['threat_profile']),
                'sophistication': vocab.code('qualitative_level', ch.get('sophistication')) or 'variable',
                'resources': vocab.code('resources_level', ch.get('resources')) or 'variable',
                'probability': vocab.code('qualitative_level', ch.get('probability')) or 'variable',
                'description': self._plain_text(self._description(a['actor'], tr(T, 'no_desc'))),
                'motivations': [{
                    'motivation': vocab.code('motivation', m['motivation']),
                    'motivation_level': vocab.code('motivation_level', m['motivation_level']),
                    'resources_level': vocab.code('resources_level', m['resources']),
                    'relevance': vocab.code('relevance', m['probability']),
                } for m in a['all_motivations']],
            })
        return {'in_short': self.build_in_short(self.generate_executive_summary(data)),
                'visuals': {'priority_matrix': matrix, 'attacker_profiles': profiles}}

    def generate_html_content(self, data):
        """Génère le contenu HTML (système de design Exposia)."""
        actors = data['actors']
        summary = self.generate_executive_summary(data)
        raw_summary = summary
        summary = {k: (esc(v) if isinstance(v, str) else v) for k, v in summary.items()}

        try:
            org = os.path.basename(os.path.dirname(os.path.abspath(self.data_dir)))
        except Exception:
            org = ""
        org_disp = esc(org.capitalize()) if org else "—"

        in_short = self.build_in_short(raw_summary)

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

  <div class="xsection"><span class="t">{tr(T, 'matrix')}</span></div>
  <table class="xtable">
    <thead><tr>{tr(T, 'th')}</tr></thead>
    <tbody>"""

        for index, actor in enumerate(actors):
            level_class, level_text = actor['level_class'], actor['level_text']
            rank_cls = ' r1' if index == 0 else ''
            html += f"""
      <tr><td><span class="rank{rank_cls}">{index + 1}</span></td><td><strong>{esc(i18n.label('actor', actor['actor']))}</strong></td><td>{esc(i18n.label('motivation', actor['primary_motivation']))}</td><td style="color:#6A7191">{i18n.label('profile_type', actor['threat_profile'])} ({actor['motivation_count']})</td><td class="center"><span class="sev-badge sev-{level_class}">{level_text}</span></td></tr>"""

        html += f"""
    </tbody>
  </table>

  <div class="xsection" style="page-break-before: always;"><span class="t">{tr(T, 'profiles')}</span></div>"""

        for actor in actors[:3]:
            level_class = actor['level_class']
            ch = self.actor_characteristics.get(actor['actor'], {'sophistication': 'Variable', 'resources': 'Variables', 'probability': 'Variable'})
            desc = self._description(actor['actor'], f"<p><em>{tr(T, 'no_desc')}</em></p>")
            n = actor['motivation_count']
            if i18n.is_en():
                mot_txt = f"active {i18n.plural(n, 'motivation')}"
            else:
                mot_txt = f"motivation{'s' if n > 1 else ''} active{'s' if n > 1 else ''}"
            html += f"""
  <div class="threat-actor avoid-break">
    <div class="threat-head sev-{level_class}">
      <span class="name">{esc(i18n.label('actor', actor['actor']).upper())}</span>
      <span class="prof">{tr(T, 'profile', p=i18n.label('profile_type', actor['threat_profile']), n=n, mot=mot_txt)}</span>
    </div>
    <div class="threat-body">
      <div class="threat-meta">{tr(T, 'meta', s=self._characteristic('qualitative_level', ch['sophistication']), r=self._characteristic('resources_level', ch['resources']), p=self._characteristic('qualitative_level', ch['probability']))}</div>
      <div class="typology"><span class="tt">{tr(T, 'typology')}</span><p>{desc.replace('<p>', '').replace('</p>', '').strip()}</p></div>
      <div class="mot-title">{tr(T, 'motivations')}</div>
      <ul class="mot-list">"""
            for idx, m in enumerate(actor['all_motivations']):
                sec = '' if idx < 2 else ' secondary'
                html += f"""
        <li class="mot-item{sec}"><div class="m">{esc(i18n.label('motivation', m['motivation']))}</div><div class="d">{self._motivation_line(m)}</div></li>"""
            html += """
      </ul>
    </div>
  </div>"""

        html += """
</body>
</html>"""
        return html

    def generate_pdf_report(self, data):
        """Génère le rapport PDF avec WeasyPrint"""

        from weasyprint import HTML, CSS  # PDF seulement : build_data reste importable sans WeasyPrint
        from weasyprint.text.fonts import FontConfiguration
        try:
            # Génération du contenu HTML
            html_content = self.generate_html_content(data)

            # Configuration des polices
            font_config = FontConfiguration()

            # CSS optimisé pour PDF
            css_content = self.get_pdf_css()

            # Création du PDF
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)

            # Génération du nom de fichier
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"threat_modeling_report_{timestamp}.pdf"

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
    parser = argparse.ArgumentParser(description="Génère le rapport PDF Threat Modeling.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("-d", "--data-dir", default=None,
                        help="Répertoire contenant threat_analysis_*.csv (défaut : dossier courant)")
    args = parser.parse_args()

    # Dossier de travail = data/ de la campagne (lecture CSV + écriture PDF)
    data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    os.chdir(data_dir)
    generator = ThreatReportPDFGenerator(data_dir='.')
    generator.generate_report()

if __name__ == "__main__":
    main()

def build_threats_data(data_dir='.'):
    """parts.threats du JSON canonique, calculé depuis le dossier data/ d'une campagne."""
    generator = ThreatReportPDFGenerator(data_dir=data_dir)
    return generator.build_data(generator.process_data(generator.load_csv_data(generator.find_csv_file())))
