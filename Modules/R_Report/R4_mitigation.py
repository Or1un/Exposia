#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de Rapport Mitigation Plan PDF - Partie 4
Que faire concrètement ?
Version optimisée avec WeasyPrint pour un rendu PDF professionnel

Positionnement : les vulnérabilités identifiées relèvent quasi systématiquement
de versions logicielles non à jour (leur correction = mises à jour éditeur, dit
en tête de partie). Les mesures présentées sont des BONNES PRATIQUES
complémentaires, indépendantes d'une vulnérabilité particulière, destinées à
sensibiliser le décideur.
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

def _lower_first_measure(text):
    """'Établir une procédure…' -> 'établir une procédure…' (sigle en tête conservé : 'MFA …')."""
    text = str(text).strip()
    return text if text[:2].isupper() else text[:1].lower() + text[1:]


class MitigationPlanPDFGenerator:
    def __init__(self, data_dir=None, output_dir=None):
        # Répertoires d'E/S : dossier courant par défaut, surchargeables.
        self.data_dir = data_dir or "."
        self.output_dir = output_dir or self.data_dir
        self.config = {
            'priority_colors': {
                'CRITIQUE': '#e74c3c',
                'HAUTE': '#f39c12',
                'MOYENNE': '#f1c40f',
                'FAIBLE': '#95a5a6'
            },
            'difficulty_colors': {
                'Faible': '#2ecc71',
                'Moyen': '#f39c12',
                'Élevé': '#e74c3c',
                'Très Élevé': '#8e44ad'
            }
        }

    @staticmethod
    def _cve_count(measure):
        """Nombre de CVE couvertes par une mesure (0 si absent / illisible)."""
        try:
            return int(float(measure.get('cve_count', 0) or 0))
        except (TypeError, ValueError):
            return 0

    def find_csv_files(self):
        """Trouve les fichiers CSV nécessaires dans self.data_dir."""
        motif_exposia = os.path.join(self.data_dir, "Exposia_*.csv")
        motif_mitigation = os.path.join(self.data_dir, "mitigation_prioritization_enhanced.csv")

        exposia_files = glob.glob(motif_exposia)
        mitigation_files = glob.glob(motif_mitigation)

        abs_dir = os.path.abspath(self.data_dir)
        if not exposia_files:
            raise FileNotFoundError(f"Aucun fichier Exposia_*.csv trouvé dans {abs_dir}")
        if not mitigation_files:
            raise FileNotFoundError(
                f"Fichier mitigation_prioritization_enhanced.csv non trouvé dans {abs_dir}")

        # Fichier Exposia le plus récent en tête
        exposia_files = sorted(exposia_files, key=os.path.getmtime, reverse=True)
        return exposia_files, mitigation_files

    def load_mitigation_data(self, mitigation_file):
        """Charge les données de priorisation des mesures"""
        mitigation_data = []
        try:
            with open(mitigation_file, 'r', encoding='utf-8', newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')
                for row in reader:
                    mitigation_data.append(row)

            return mitigation_data

        except Exception as e:
            raise Exception(f"Erreur lors du chargement {mitigation_file}: {str(e)}")

    def load_exposia_data(self, exposia_file):
        """Charge les données Exposia pour statistiques complémentaires"""
        exposia_data = []
        try:
            with open(exposia_file, 'r', encoding='utf-8-sig', newline='') as csvfile:
                # Délimiteur déduit de l'en-tête (';' par défaut, tabulation tolérée).
                # (L'ancienne lecture en tabulation n'échouait jamais et ne retombait
                # donc jamais sur ';' : les données Exposia étaient illisibles.)
                header = csvfile.readline()
                csvfile.seek(0)
                delimiter = '\t' if header.count('\t') > header.count(';') else ';'
                reader = csv.DictReader(csvfile, delimiter=delimiter)

                for row in reader:
                    exposia_data.append(row)

            return exposia_data

        except Exception as e:
            ModernUI.status(f"Avertissement - Données Exposia: {str(e)}", "warning")
            return []

    def calculate_statistics(self, mitigation_data, exposia_data):
        """Calcule les statistiques dynamiques pour la synthèse"""
        stats = {}

        # Compter les mesures par type
        type_counts = Counter(row['mitigation_type'] for row in mitigation_data if row['mitigation_type'])
        total_measures = len(mitigation_data)

        stats['total_measures'] = total_measures
        stats['type_distribution'] = {
            'Préventif': type_counts.get('Préventif', 0),
            'Détectif': type_counts.get('Détectif', 0),
            'Curatif': type_counts.get('Curatif', 0)
        }

        # Calculer les pourcentages
        stats['type_percentages'] = {}
        for type_name, count in stats['type_distribution'].items():
            percentage = round((count / total_measures) * 100) if total_measures > 0 else 0
            stats['type_percentages'][type_name] = percentage

        # Compter les mesures par catégorie
        category_counts = Counter(row['category'] for row in mitigation_data if row['category'])
        stats['category_distribution'] = dict(category_counts)
        stats['category_percentages'] = {}
        for category, count in category_counts.items():
            percentage = round((count / total_measures) * 100) if total_measures > 0 else 0
            stats['category_percentages'][category] = percentage

        # CVEs uniques traitées
        unique_cves = set()
        for row in mitigation_data:
            treated_cves = row.get('treated_cves', '')
            if treated_cves:
                cves = [cve.strip() for cve in treated_cves.split(',') if cve.strip()]
                unique_cves.update(cves)

        stats['unique_cves_count'] = len(unique_cves)

        # CVE identifiées sur le périmètre (même définition que R3) : base de la
        # phrase « mises à jour » de l'encadré, indépendante des mesures retenues.
        identified_cves = set()
        for row in exposia_data:
            cve = str(row.get('cve', row.get('Vulnerability (CVE)', '')) or '').strip()
            if cve and cve not in ('#N/A', 'None', 'No data', 'nan'):
                identified_cves.add(cve)
        stats['identified_cves_count'] = len(identified_cves) or len(unique_cves)

        # Top 3 mesures pour les détails
        sorted_measures = sorted(mitigation_data, key=lambda x: float(x.get('final_score', 0)), reverse=True)
        stats['top_measures'] = sorted_measures[:4]
        stats['top_measure'] = sorted_measures[0] if sorted_measures else None

        # Utiliser directement le fichier mitigation comme référence fiable
        # On peut estimer que le fichier de priorisation contient toutes les mesures pertinentes
        stats['total_available_measures'] = total_measures


        return stats

    def get_pdf_css(self):
        """CSS = système Exposia partagé + spécifique au plan de mitigation."""
        return report_theme.get_exposia_css() + """
        .cat-bars { margin-top:1mm; margin-bottom:2mm; }
        .cat-bar { margin-bottom:4mm; }
        .cat-bar .cbl { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:1.6mm; }
        .cat-bar .cn { font-size:9.5pt; font-weight:600; color:#20263F; }
        .cat-bar .cp { font-size:9pt; font-weight:600; color:#4B47C9; }
        .cat-bar .track { height:3.2mm; background:#EEF0FA; border-radius:20px; overflow:hidden; }
        .cat-bar .fill { height:100%; background:linear-gradient(90deg,#4B47C9,#6C68DA); }

        .xtable.measures { table-layout: fixed; }
        .xtable.measures th, .xtable.measures td { padding:2.8mm 2.6mm; font-size:8.5pt; word-break:break-word; }
        .xtable.measures .sev-badge, .xtable.measures .diff-badge { font-size:7.5pt; padding:1mm 2.8mm; white-space:nowrap; }
        .xtable.measures th { font-size:7.5pt; }

        .diff-badge { display:inline-block; padding:1mm 3mm; border-radius:20px; font-size:7.5pt; font-weight:700; letter-spacing:.5pt; text-transform:uppercase; }
        .diff-faible { background:#E6F4E6; color:#4A8A3E; }
        .diff-moyen { background:#FBF0DC; color:#B9812B; }
        .diff-eleve { background:#FBE7E8; color:#C23E45; }
        .diff-tres-eleve { background:#EFE9F6; color:#7A4F9E; }

        .mit-card { border:1px solid #E7E9F4; border-radius:3mm; overflow:hidden; margin-bottom:5mm; page-break-inside:avoid; }
        .mit-head { background:#F5F6FD; padding:3mm 5mm; border-bottom:1px solid #E7E9F4; }
        .mit-head .mn { font-size:10.5pt; font-weight:700; color:#20263F; }
        .mit-head .mid { font-size:8.5pt; font-weight:600; color:#4B47C9; margin-left:2mm; }
        .mit-body { padding:4mm 5mm; }
        .mit-body p { font-size:9.5pt; line-height:1.55; color:#3A4160; margin:0 0 2.5mm; }
        .mit-body p:last-child { margin-bottom:0; }
        .mit-body b { color:#20263F; }
        .mit-foot { font-size:8.5pt; color:#6A7191; }
        .mit-foot b { color:#20263F; }
"""

    def generate_html_content(self, mitigation_data, stats):
        """Génère le contenu HTML (système de design Exposia)."""
        try:
            org = os.path.basename(os.path.dirname(os.path.abspath(self.data_dir)))
        except Exception:
            org = ""
        org_disp = esc(org.capitalize()) if org else "—"

        prio_class = {'CRITIQUE': 'sev-critical', 'HAUTE': 'sev-high', 'MOYENNE': 'sev-medium', 'FAIBLE': 'sev-low'}
        prio_disp = {'CRITIQUE': 'Critique', 'HAUTE': 'Haute', 'MOYENNE': 'Moyenne', 'FAIBLE': 'Faible'}
        diff_class = {'FAIBLE': 'diff-faible', 'MOYEN': 'diff-moyen', 'ÉLEVÉ': 'diff-eleve',
                      'ELEVE': 'diff-eleve', 'TRÈS ÉLEVÉ': 'diff-tres-eleve', 'TRES ELEVE': 'diff-tres-eleve'}
        diff_disp = {'FAIBLE': 'Faible', 'MOYEN': 'Moyen', 'ÉLEVÉ': 'Élevé',
                     'ELEVE': 'Élevé', 'TRÈS ÉLEVÉ': 'Très élevé', 'TRES ELEVE': 'Très élevé'}

        def prio_badge(measure):
            p = (measure.get('priority', '') or '').upper()
            return f'<span class="sev-badge {prio_class.get(p, "sev-low")}">{prio_disp.get(p, "Faible")}</span>'

        def diff_badge(measure):
            d = (measure.get('implementation_difficulty', '') or '').upper()
            return f'<span class="diff-badge {diff_class.get(d, "diff-moyen")}">{diff_disp.get(d, esc(d.title()))}</span>'

        def coverage_cell(measure):
            n = self._cve_count(measure)
            return str(n) if n else '&mdash;'

        def coverage_sentence(measure):
            n = self._cve_count(measure)
            if n:
                return f"<b>{n} vuln&eacute;rabilit&eacute;{'s' if n > 1 else ''}</b> concern&eacute;e{'s' if n > 1 else ''} par cette mesure."
            return "<b>Bonne pratique</b> issue des sc&eacute;narios d'attaque types sur vos services expos&eacute;s."

        tp = stats['type_percentages']
        top = stats['top_measure']

        # Barres par catégorie (triées)
        cat_bars = ""
        cats = sorted(stats['category_distribution'].items(), key=lambda x: x[1], reverse=True)
        total_m = stats['total_measures'] or 1
        for name, count in cats:
            pct = round(count / total_m * 100, 1)
            s = 's' if count > 1 else ''
            cat_bars += f"""
      <div class="cat-bar">
        <div class="cbl"><span class="cn">{esc(str(name))} ({count} mesure{s})</span><span class="cp">{str(pct).replace('.', ',')}&nbsp;%</span></div>
        <div class="track"><div class="fill" style="width:{pct}%;"></div></div>
      </div>"""

        # Lignes de la matrice (top 10)
        rows = ""
        for index, measure in enumerate(mitigation_data[:10]):
            rank_cls = ' r1' if index == 0 else ''
            rows += f"""
      <tr><td><span class="rank{rank_cls}">{index + 1}</span></td><td><strong>{esc(str(measure.get('mitigation_id', '')))}</strong></td><td>{esc(str(measure.get('organizational_measure', '')))}</td><td>{esc(str(measure.get('category', '')))}</td><td class="center">{coverage_cell(measure)}</td><td class="center">{prio_badge(measure)}</td><td class="center">{diff_badge(measure)}</td></tr>"""

        # Cartes focus
        focus = ""
        for measure in stats['top_measures']:
            focus += f"""
  <div class="mit-card">
    <div class="mit-head"><span class="mn">{esc(str(measure.get('organizational_measure', '')))}</span><span class="mid">{esc(str(measure.get('mitigation_id', '')))}</span></div>
    <div class="mit-body">
      <p>{coverage_sentence(measure)}</p>
      <p><b>Mesure compl&eacute;mentaire&nbsp;:</b> {esc(str(measure.get('technical_measure', '')))}</p>
      <p class="mit-foot">Priorit&eacute;&nbsp;: {prio_badge(measure)} &nbsp;&bull;&nbsp; Difficult&eacute;&nbsp;: {diff_badge(measure)} &nbsp;&bull;&nbsp; Type&nbsp;: <b>{esc(str(measure.get('mitigation_type', '')))}</b></p>
    </div>
  </div>"""

        # Encadré « En clair » : 1) la correction des vulnérabilités = mises à jour ;
        # 2) les mesures listées = bonnes pratiques complémentaires.
        nb_cves = stats['identified_cves_count']
        if nb_cves:
            update_sentence = (
                f"Les <strong>{nb_cves} vuln&eacute;rabilit&eacute;{'s' if nb_cves > 1 else ''}</strong> "
                f"identifi&eacute;e{'s' if nb_cves > 1 else ''} {'sont' if nb_cves > 1 else 'est'} principalement associ&eacute;e{'s' if nb_cves > 1 else ''} &agrave; des versions "
                f"logicielles potentiellement vuln&eacute;rables&nbsp;: leur traitement passe d'abord par "
                f"<strong>l'application des mises &agrave; jour &eacute;diteur</strong>, en commen&ccedil;ant par les "
                f"services les plus expos&eacute;s."
            )
        else:
            update_sentence = (
                "Maintenir vos logiciels &agrave; jour reste la premi&egrave;re protection&nbsp;: "
                "<strong>appliquez les mises &agrave; jour &eacute;diteur</strong> d&egrave;s leur publication."
            )
        top_sentence = ""
        if top:
            top_sentence = (
                f" La mesure prioritaire consiste &agrave; <strong>{esc(_lower_first_measure(top.get('organizational_measure', '')))}</strong> "
                f"({esc(str(top.get('mitigation_id', '')))})."
            )

        nb_measures = stats['total_measures']
        if nb_measures:
            pl = 's' if nb_measures > 1 else ''
            measures_sentence = (
                f"Les <strong>{nb_measures} mesure{pl}</strong> pr&eacute;sent&eacute;e{pl} ci-dessous "
                f"{'sont' if nb_measures > 1 else 'est'} <strong>compl&eacute;mentaire{pl}</strong>&nbsp;: "
                f"ce sont des <strong>bonnes pratiques</strong> qui r&eacute;duisent durablement votre exposition, "
                f"ind&eacute;pendamment d'une vuln&eacute;rabilit&eacute; particuli&egrave;re. Elles sont majoritairement "
                f"<strong>pr&eacute;ventives ({tp['Préventif']}&nbsp;%)</strong>, compl&eacute;t&eacute;es par des mesures "
                f"<strong>d&eacute;tectives ({tp['Détectif']}&nbsp;%)</strong> et <strong>curatives ({tp['Curatif']}&nbsp;%)</strong>."
                f"{top_sentence}"
            )
        else:
            measures_sentence = (
                "Aucune mesure sp&eacute;cifique ne ressort de l'analyse&nbsp;: votre exposition est limit&eacute;e. "
                "Refaites une analyse r&eacute;guli&egrave;rement pour vous assurer qu'elle le reste."
            )

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Rapport Mitigation Plan</title></head>
<body>
  <div class="rh-brand">E<span class="x">x</span>posia</div>
  <div class="rh-doc">Rapport d'analyse &middot; {org_disp}</div>

  <div class="kicker">Partie 4 &middot; Mitigation</div>
  <div class="part-title">Que faire concr&egrave;tement&nbsp;?</div>
  <div class="rule"></div>

  <div class="callout">
    <div class="ttl">En clair</div>
    <p>{update_sentence}</p>
    <p>{measures_sentence}</p>
  </div>

  <div class="xsection"><span class="t">M&eacute;thodologie</span></div>
  <p class="prose">Les mesures sont s&eacute;lectionn&eacute;es &agrave; partir des <b>sc&eacute;narios d'attaque</b> associ&eacute;s &agrave; vos services expos&eacute;s et &agrave; vos vuln&eacute;rabilit&eacute;s, puis <b>class&eacute;es par ordre de priorit&eacute;</b>. Chaque mesure est class&eacute;e selon son efficacit&eacute; estim&eacute;e, sa couverture de plusieurs types de menaces et sa facilit&eacute; de mise en &oelig;uvre. En clair&nbsp;: une <b>feuille de route de bonnes pratiques, claire et hi&eacute;rarchis&eacute;e</b>, qui compl&egrave;te la mise &agrave; jour de vos logiciels.</p>

  <div class="xsection"><span class="t">R&eacute;partition par cat&eacute;gorie</span></div>
  <div class="cat-bars">{cat_bars}
  </div>

  <div class="xsection" style="page-break-before: always;"><span class="t">Matrice de priorisation des mesures</span></div>
  <table class="xtable measures">
    <colgroup><col style="width:6%"><col style="width:15%"><col style="width:18%"><col style="width:13%"><col style="width:16%"><col style="width:17%"><col style="width:15%"></colgroup>
    <thead><tr><th>Rang</th><th>ID</th><th>Mesure</th><th>Cat&eacute;gorie</th><th class="center" style="font-size:6.8pt;letter-spacing:.1pt;">Vuln&eacute;rabilit&eacute;s concern&eacute;es</th><th class="center">Priorit&eacute;</th><th class="center">Difficult&eacute;</th></tr></thead>
    <tbody>{rows}
    </tbody>
  </table>

  <div class="xsection" style="page-break-before: always;"><span class="t">Focus sur les mesures prioritaires</span></div>
  {focus}
</body>
</html>"""
        return html

    def generate_pdf_report(self, mitigation_data, stats):
        """Génère le rapport PDF avec WeasyPrint"""

        try:
            # Génération du contenu HTML
            html_content = self.generate_html_content(mitigation_data, stats)

            # Configuration des polices
            font_config = FontConfiguration()

            # CSS optimisé pour PDF
            css_content = self.get_pdf_css()

            # Création du PDF
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)

            # Répertoire de destination (configurable, défaut = dossier courant)
            output_directory = self.output_dir

            # Créer le répertoire s'il n'existe pas
            os.makedirs(output_directory, exist_ok=True)

            # Génération du nom de fichier avec chemin complet
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = os.path.join(output_directory, f"mitigation_plan_report_{timestamp}.pdf")

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

            # 1. Détection des fichiers CSV
            exposia_files, mitigation_files = self.find_csv_files()
            exposia_file = exposia_files[0]  # Prend le premier fichier Exposia
            mitigation_file = mitigation_files[0]  # Prend le premier fichier mitigation

            # 2. Chargement des données
            mitigation_data = self.load_mitigation_data(mitigation_file)
            exposia_data = self.load_exposia_data(exposia_file)

            # 3. Calcul des statistiques
            stats = self.calculate_statistics(mitigation_data, exposia_data)

            # 4. Génération du PDF
            pdf_filename = self.generate_pdf_report(mitigation_data, stats)


            return pdf_filename

        except Exception as e:
            ModernUI.status(f"Erreur: {str(e)}", "error")
            raise

def main():
    """Point d'entrée du script"""
    import argparse
    parser = argparse.ArgumentParser(description="Génère le rapport PDF Mitigation Plan.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("-d", "--data-dir", default=None,
                        help="Répertoire des CSV d'entrée (défaut : dossier courant)")
    parser.add_argument("-o", "--output-dir", default=None,
                        help="Répertoire de sortie du PDF (défaut : identique à --data-dir)")
    args = parser.parse_args()

    # Dossier de travail = data/ de la campagne (lecture CSV + écriture PDF)
    data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    os.chdir(data_dir)
    generator = MitigationPlanPDFGenerator(data_dir='.', output_dir='.')
    generator.generate_report()

if __name__ == "__main__":
    main()