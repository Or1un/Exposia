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

# Libellés des matrices M2 / M3 / M4 (anglais) -> français affiché dans le rapport.
FR_MOTIVATION = {"High": "élevé", "Quite": "modéré", "Poor": "faible", "Very low": "très faible"}
FR_RESOURCES = {"Unlimited": "illimitées", "Important": "importantes",
                "Significant": "significatives", "Limited": "limitées"}
FR_RELEVANCE = {"Very relevant": "très élevée", "Quite relevant": "modérée",
                "Moderately relevant": "limitée", "Not really relevant": "faible"}


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
            'score_thresholds': {
                'critical': 300,
                'high': 120,
                'medium': 40
            },
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
            sorted_motivations = sorted(motivations, key=lambda x: x['individual_score'], reverse=True)

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

        prioritized_actors = sorted(aggregated_actors, key=lambda x: x['rank_score'], reverse=True)


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

        critical_names = [a['actor'] for a in critical_actors]
        if len(critical_names) > 2:
            critical_list = ', '.join(critical_names[:-1]) + f" et {critical_names[-1]}"
        elif len(critical_names) == 2:
            critical_list = f"{critical_names[0]} et {critical_names[1]}"
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
            return 'critical', 'CRITIQUE'
        elif score >= thresholds['high']:
            return 'high', 'ÉLEVÉ'
        elif score >= thresholds['medium']:
            return 'medium', 'MODÉRÉ'
        else:
            return 'low', 'FAIBLE'

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

    def generate_html_content(self, data):
        """Génère le contenu HTML (système de design Exposia)."""
        actors = data['actors']
        summary = self.generate_executive_summary(data)
        summary = {k: (esc(v) if isinstance(v, str) else v) for k, v in summary.items()}

        try:
            org = os.path.basename(os.path.dirname(os.path.abspath(self.data_dir)))
        except Exception:
            org = ""
        org_disp = esc(org.capitalize()) if org else "—"

        crit = summary['critical_count']
        s_crit = 's' if crit > 1 else ''
        if crit:
            crit_sentence = (
                f"Parmi eux, <strong>{crit} acteur{s_crit} class&eacute;{s_crit} critique{s_crit}</strong> "
                f"({summary['critical_list']}) m&eacute;rite{'nt' if crit > 1 else ''} une attention particuli&egrave;re."
            )
        else:
            crit_sentence = (
                f"Aucun n'atteint le niveau critique au regard de votre profil&nbsp;; "
                f"le plus pertinent est <strong>{summary['top_actor']}</strong>."
            )

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Rapport Threat Modeling</title></head>
<body>
  <div class="rh-brand">E<span class="x">x</span>posia</div>
  <div class="rh-doc">Rapport d'analyse &middot; {org_disp}</div>

  <div class="kicker">Partie 1 &middot; Menaces</div>
  <div class="part-title">Qui vous attaque, et pourquoi&nbsp;?</div>
  <div class="rule"></div>

  <div class="callout">
    <div class="ttl">En clair</div>
    <p>L'analyse a identifi&eacute; <strong>{summary['total_actors']} profils d'attaquants</strong> susceptibles de cibler votre organisation. {crit_sentence} La motivation la plus repr&eacute;sent&eacute;e est <strong>&laquo;&nbsp;{summary['top_motivation']}&nbsp;&raquo;</strong>, associ&eacute;e &agrave; <strong>{summary['top_motivation_percent']}&nbsp;% des attaques potentielles</strong>.</p>
  </div>

  <div class="xsection"><span class="t">M&eacute;thodologie</span></div>
  <p class="prose">Notre approche du <b>threat modeling</b> croise le profil de votre organisation &mdash; <b>secteur, taille, zone g&eacute;ographique et niveau d'exposition</b> &mdash; avec les caract&eacute;ristiques de <b>huit types d'acteurs malveillants</b>. Nous analysons leurs motivations &mdash; <b>espionnage, profit, sabotage, influence</b> &mdash; pour compl&eacute;ter l'analyse des menaces en tenant compte de votre profil, puis nous pond&eacute;rons chaque acteur selon ces m&ecirc;mes crit&egrave;res afin de le <b>hi&eacute;rarchiser par un filtrage probabiliste</b>. En clair&nbsp;: nous identifions <b>qui peut vous attaquer, pourquoi et avec quel niveau de pertinence au regard de votre profil</b>.</p>

  <div class="xsection"><span class="t">Matrice de priorisation des menaces</span></div>
  <table class="xtable">
    <thead><tr><th>Rang</th><th>Acteur</th><th>Motivation principale</th><th>Profil</th><th class="center">Niveau</th></tr></thead>
    <tbody>"""

        for index, actor in enumerate(actors):
            level_class, level_text = actor['level_class'], actor['level_text']
            rank_cls = ' r1' if index == 0 else ''
            html += f"""
      <tr><td><span class="rank{rank_cls}">{index + 1}</span></td><td><strong>{esc(str(actor['actor']))}</strong></td><td>{esc(str(actor['primary_motivation']))}</td><td style="color:#6A7191">{actor['threat_profile']} ({actor['motivation_count']})</td><td class="center"><span class="sev-badge sev-{level_class}">{level_text}</span></td></tr>"""

        html += """
    </tbody>
  </table>

  <div class="xsection" style="page-break-before: always;"><span class="t">Profils d'attaquants d&eacute;taill&eacute;s</span></div>"""

        for actor in actors[:3]:
            level_class = actor['level_class']
            ch = self.actor_characteristics.get(actor['actor'], {'sophistication': 'Variable', 'resources': 'Variables', 'probability': 'Variable'})
            desc = self.actor_descriptions.get(actor['actor'], '<p><em>Description non disponible.</em></p>')
            n = actor['motivation_count']
            html += f"""
  <div class="threat-actor avoid-break">
    <div class="threat-head sev-{level_class}">
      <span class="name">{esc(str(actor['actor']).upper())}</span>
      <span class="prof">Profil&nbsp;: {actor['threat_profile']} &bull; {n} motivation{'s' if n > 1 else ''} active{'s' if n > 1 else ''}</span>
    </div>
    <div class="threat-body">
      <div class="threat-meta"><b>Sophistication</b>&nbsp;: {ch['sophistication']} &nbsp;&bull;&nbsp; <b>Ressources</b>&nbsp;: {ch['resources']} &nbsp;&bull;&nbsp; <b>Probabilit&eacute;</b>&nbsp;: {ch['probability']}</div>
      <div class="typology"><span class="tt">Typologie</span><p>{desc.replace('<p>', '').replace('</p>', '').strip()}</p></div>
      <div class="mot-title">Motivations identifi&eacute;es</div>
      <ul class="mot-list">"""
            for idx, m in enumerate(actor['all_motivations']):
                sec = '' if idx < 2 else ' secondary'
                html += f"""
        <li class="mot-item{sec}"><div class="m">{esc(str(m['motivation']))}</div><div class="d">Niveau {esc(str(_fr(FR_MOTIVATION, m['motivation_level'])))} &times; Ressources {esc(str(_fr(FR_RESOURCES, m['resources'])))} &times; Pertinence {esc(str(_fr(FR_RELEVANCE, m['probability'])))}</div></li>"""
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