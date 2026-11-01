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

import exposia_i18n as i18n  # langue des livrables (EXPOSIA_LANG)
from exposia_i18n import tr

# Textes fixes de la partie 4 (FR, EN)
T = {
    'title_tag': ("Rapport Mitigation Plan", "Mitigation Plan report"),
    'kicker': ("Partie 4 &middot; Mitigation", "Part 4 &middot; Mitigation"),
    'title': ("Que faire concr&egrave;tement&nbsp;?", "What should you actually do?"),
    'method': ("Les mesures sont s&eacute;lectionn&eacute;es &agrave; partir des <b>sc&eacute;narios d'attaque</b> associ&eacute;s &agrave; vos services expos&eacute;s et &agrave; vos vuln&eacute;rabilit&eacute;s, puis <b>class&eacute;es par ordre de priorit&eacute;</b>. Chaque mesure est class&eacute;e selon son efficacit&eacute; estim&eacute;e, sa couverture de plusieurs types de menaces et sa facilit&eacute; de mise en &oelig;uvre. En clair&nbsp;: une <b>feuille de route de bonnes pratiques, claire et hi&eacute;rarchis&eacute;e</b>, qui compl&egrave;te la mise &agrave; jour de vos logiciels.",
               "The measures are selected from the <b>attack scenarios</b> associated with your exposed services and your vulnerabilities, then <b>ranked by priority</b>. Each measure is ranked according to its estimated effectiveness, its coverage of several types of threats and its ease of implementation. In short: a <b>clear, prioritised roadmap of good practices</b> that complements keeping your software up to date."),
    'categories': ("R&eacute;partition par cat&eacute;gorie", "Breakdown by category"),
    'matrix': ("Matrice de priorisation des mesures", "Measure prioritization matrix"),
    'th': ("<th>Rang</th><th>ID</th><th>Mesure</th><th>Cat&eacute;gorie</th><th class=\"center\" style=\"font-size:6.8pt;letter-spacing:.1pt;\">Vuln&eacute;rabilit&eacute;s concern&eacute;es</th><th class=\"center\">Priorit&eacute;</th><th class=\"center\">Difficult&eacute;</th>",
           "<th>Rank</th><th>ID</th><th>Measure</th><th>Category</th><th class=\"center\" style=\"font-size:6.8pt;letter-spacing:.1pt;\">Vulnerabilities addressed</th><th class=\"center\">Priority</th><th class=\"center\">Difficulty</th>"),
    'focus': ("Focus sur les mesures prioritaires", "Focus on the priority measures"),
    'complementary': ("<b>Mesure compl&eacute;mentaire&nbsp;:</b>", "<b>Complementary measure:</b>"),
    'foot': ("Priorit&eacute;&nbsp;: {p} &nbsp;&bull;&nbsp; Difficult&eacute;&nbsp;: {d} &nbsp;&bull;&nbsp; Type&nbsp;: <b>{t}</b>",
             "Priority: {p} &nbsp;&bull;&nbsp; Difficulty: {d} &nbsp;&bull;&nbsp; Type: <b>{t}</b>"),
    'good_practice': ("<b>Bonne pratique</b> issue des sc&eacute;narios d'attaque types sur vos services expos&eacute;s.",
                      "<b>Good practice</b> drawn from the typical attack scenarios on your exposed services."),
}


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
        # Comptage par code : un référentiel en anglais (Preventive…) compte comme en français.
        type_counts = Counter(vocab.code('mitigation_type', row['mitigation_type'])
                              for row in mitigation_data if row['mitigation_type'])
        total_measures = len(mitigation_data)

        stats['total_measures'] = total_measures
        stats['type_distribution'] = {
            'Préventif': type_counts.get('preventive', 0),
            'Détectif': type_counts.get('detective', 0),
            'Curatif': type_counts.get('corrective', 0)
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

    # ------------------------------------------------------------------
    # Données de la partie (source unique du PDF et du JSON canonique)
    # ------------------------------------------------------------------
    @staticmethod
    def build_in_short(stats):
        """
        Encadré « En clair » : 1) la correction des vulnérabilités passe par les
        mises à jour ; 2) les mesures listées sont des bonnes pratiques complémentaires.
        """
        seg = report_theme.seg
        tp, top = stats['type_percentages'], stats['top_measure']
        nb_cves = stats['identified_cves_count']
        if i18n.is_en():
            return MitigationPlanPDFGenerator._build_in_short_en(stats)
        if nb_cves:
            s_ = 's' if nb_cves > 1 else ''
            p1 = [seg("Les "), seg(f"{nb_cves} vulnérabilité{s_}", True),
                  seg(f" identifiée{s_} {'sont' if nb_cves > 1 else 'est'} principalement associée{s_} à des "
                      "versions logicielles potentiellement vulnérables\u00a0: leur traitement passe d'abord par "),
                  seg("l'application des mises à jour éditeur", True),
                  seg(", en commençant par les services les plus exposés.")]
        else:
            p1 = [seg("Maintenir vos logiciels à jour reste la première protection\u00a0: "),
                  seg("appliquez les mises à jour éditeur", True), seg(" dès leur publication.")]
        nb = stats['total_measures']
        if nb:
            pl = 's' if nb > 1 else ''
            p2 = [seg("Les "), seg(f"{nb} mesure{pl}", True),
                  seg(f" présentée{pl} ci-dessous {'sont' if nb > 1 else 'est'} "), seg(f"complémentaire{pl}", True),
                  seg("\u00a0: ce sont des "), seg("bonnes pratiques", True),
                  seg(" qui réduisent durablement votre exposition, indépendamment d'une vulnérabilité "
                      "particulière. Elles sont majoritairement "),
                  seg(f"préventives ({tp['Préventif']}\u00a0%)", True), seg(", complétées par des mesures "),
                  seg(f"détectives ({tp['Détectif']}\u00a0%)", True), seg(" et "),
                  seg(f"curatives ({tp['Curatif']}\u00a0%)", True), seg(".")]
            if top:
                p2 += [seg(" La mesure prioritaire consiste à "),
                       seg(_lower_first_measure(top.get('organizational_measure', '')), True),
                       seg(f" ({top.get('mitigation_id', '')}).")]
        else:
            p2 = [seg("Aucune mesure spécifique ne ressort de l'analyse\u00a0: votre exposition est limitée. "
                      "Refaites une analyse régulièrement pour vous assurer qu'elle le reste.")]
        return {'paragraphs': [p1, p2], 'facts': MitigationPlanPDFGenerator._facts(stats)}

    @staticmethod
    def _facts(stats):
        tp, top = stats['type_percentages'], stats['top_measure']
        return {'cves': stats['identified_cves_count'], 'mitigations': stats['total_measures'],
                'preventive_pct': tp['Préventif'], 'detective_pct': tp['Détectif'], 'corrective_pct': tp['Curatif'],
                'top_mitigation': top.get('mitigation_id') if top else None}

    @staticmethod
    def _build_in_short_en(stats):
        """« In brief » en anglais : mêmes cas, mêmes chiffres que la version française."""
        seg, pl = report_theme.seg, i18n.plural
        tp, top = stats['type_percentages'], stats['top_measure']
        nb_cves = stats['identified_cves_count']
        if nb_cves:
            one = nb_cves == 1
            p1 = [seg("The "), seg(f"{nb_cves} identified {pl(nb_cves, 'vulnerability', 'vulnerabilities')}", True),
                  seg(f" {'is' if one else 'are'} mainly associated with potentially vulnerable software versions: "
                      f"addressing {'it' if one else 'them'} starts with "),
                  seg("applying the vendor updates", True),
                  seg(", beginning with the most exposed services.")]
        else:
            p1 = [seg("Keeping your software up to date remains the first line of defense: "),
                  seg("apply vendor updates", True), seg(" as soon as they are released.")]
        nb = stats['total_measures']
        if nb:
            one = nb == 1
            p2 = [seg("The "), seg(f"{nb} {pl(nb, 'measure')}", True),
                  seg(f" presented below {'is' if one else 'are'} "), seg("complementary", True),
                  seg(f": {'it is a' if one else 'they are'} "), seg("good " + pl(nb, 'practice'), True),
                  seg(f" that durably {'reduces' if one else 'reduce'} your exposure, independently of any specific "
                      f"vulnerability. {'It is' if one else 'They are'} mostly "),
                  seg(f"preventive ({tp['Préventif']}%)", True), seg(", complemented by "),
                  seg(f"detective ({tp['Détectif']}%)", True), seg(" and "),
                  seg(f"corrective ({tp['Curatif']}%)", True), seg(" measures.")]
            if top:
                p2 += [seg(" The top-priority measure is to "),
                       seg(_lower_first_measure(i18n.text(top.get('organizational_measure', ''))), True),
                       seg(f" ({top.get('mitigation_id', '')}).")]
        else:
            p2 = [seg("No specific measure stands out from the analysis: your exposure is limited. "
                      "Run a new analysis regularly to make sure it stays that way.")]
        return {'paragraphs': [p1, p2], 'facts': MitigationPlanPDFGenerator._facts(stats)}

    def build_data(self, mitigation_data, stats):
        """Bloc parts.mitigations du JSON canonique : « En clair » et données des visuels (codes)."""
        total = stats['total_measures'] or 1
        # Visuels : valeur exacte à une décimale (le texte et le graphique du PDF gardent l'entier).
        types = {vocab.code('mitigation_type', k): {'count': v, 'percentage': round(v / stats['total_measures'] * 100, 1)
                                                    if stats['total_measures'] else 0.0}
                 for k, v in stats['type_distribution'].items()}
        cats = sorted(stats['category_distribution'].items(), key=lambda x: x[1], reverse=True)
        return {
            'in_short': self.build_in_short(stats),
            'visuals': {
                'type_distribution': types,
                'category_distribution': [{'category': vocab.code('mitigation_category', name), 'count': count,
                                           'percentage': round(count / total * 100, 1)} for name, count in cats],
                'priority_matrix': [{
                    'rank': rank, 'mitigation_id': m.get('mitigation_id', ''), 'cve_count': self._cve_count(m),
                    'priority': vocab.code('severity', m.get('priority')) or 'low',
                    'difficulty': vocab.code('difficulty', m.get('implementation_difficulty')),
                } for rank, m in enumerate(mitigation_data[:10], 1)],
                'focus': [{'mitigation_id': m.get('mitigation_id', '')} for m in stats['top_measures']],
            },
        }

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

        if i18n.is_en():
            prio_disp = {'CRITIQUE': 'Critical', 'HAUTE': 'High', 'MOYENNE': 'Medium', 'FAIBLE': 'Low'}
            diff_disp = {k: vocab.label('difficulty', vocab.code('difficulty', v), 'en', fallback=v)
                         for k, v in diff_disp.items()}

        def prio_badge(measure):
            p = (measure.get('priority', '') or '').upper()
            return f'<span class="sev-badge {prio_class.get(p, "sev-low")}">{prio_disp.get(p, prio_disp["FAIBLE"])}</span>'

        def diff_badge(measure):
            d = (measure.get('implementation_difficulty', '') or '').upper()
            return f'<span class="diff-badge {diff_class.get(d, "diff-moyen")}">{diff_disp.get(d, esc(d.title()))}</span>'

        def coverage_cell(measure):
            n = self._cve_count(measure)
            return str(n) if n else '&mdash;'

        def coverage_sentence(measure):
            n = self._cve_count(measure)
            if n and i18n.is_en():
                return f"<b>{n} {i18n.plural(n, 'vulnerability', 'vulnerabilities')}</b> addressed by this measure."
            if n:
                return f"<b>{n} vuln&eacute;rabilit&eacute;{'s' if n > 1 else ''}</b> concern&eacute;e{'s' if n > 1 else ''} par cette mesure."
            return tr(T, 'good_practice')


        # Barres par catégorie (triées)
        cat_bars = ""
        cats = sorted(stats['category_distribution'].items(), key=lambda x: x[1], reverse=True)
        total_m = stats['total_measures'] or 1
        for name, count in cats:
            pct = round(count / total_m * 100, 1)
            unit = i18n.plural(count, 'measure') if i18n.is_en() else f"mesure{'s' if count > 1 else ''}"
            cat_bars += f"""
      <div class="cat-bar">
        <div class="cbl"><span class="cn">{esc(i18n.label('mitigation_category', name))} ({count} {unit})</span><span class="cp">{i18n.percent(pct)}</span></div>
        <div class="track"><div class="fill" style="width:{pct}%;"></div></div>
      </div>"""

        # Lignes de la matrice (top 10)
        rows = ""
        for index, measure in enumerate(mitigation_data[:10]):
            rank_cls = ' r1' if index == 0 else ''
            rows += f"""
      <tr><td><span class="rank{rank_cls}">{index + 1}</span></td><td><strong>{esc(str(measure.get('mitigation_id', '')))}</strong></td><td>{esc(i18n.text(measure.get('organizational_measure', '')))}</td><td>{esc(i18n.label('mitigation_category', measure.get('category', '')))}</td><td class="center">{coverage_cell(measure)}</td><td class="center">{prio_badge(measure)}</td><td class="center">{diff_badge(measure)}</td></tr>"""

        # Cartes focus
        focus = ""
        for measure in stats['top_measures']:
            focus += f"""
  <div class="mit-card">
    <div class="mit-head"><span class="mn">{esc(i18n.text(measure.get('organizational_measure', '')))}</span><span class="mid">{esc(str(measure.get('mitigation_id', '')))}</span></div>
    <div class="mit-body">
      <p>{coverage_sentence(measure)}</p>
      <p>{tr(T, 'complementary')} {esc(i18n.text(measure.get('technical_measure', '')))}</p>
      <p class="mit-foot">{tr(T, 'foot', p=prio_badge(measure), d=diff_badge(measure), t=esc(i18n.label('mitigation_type', measure.get('mitigation_type', ''))))}</p>
    </div>
  </div>"""

        in_short = self.build_in_short(stats)

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

  <div class="xsection"><span class="t">{tr(T, 'categories')}</span></div>
  <div class="cat-bars">{cat_bars}
  </div>

  <div class="xsection" style="page-break-before: always;"><span class="t">{tr(T, 'matrix')}</span></div>
  <table class="xtable measures">
    <colgroup><col style="width:6%"><col style="width:15%"><col style="width:18%"><col style="width:13%"><col style="width:16%"><col style="width:17%"><col style="width:15%"></colgroup>
    <thead><tr>{tr(T, 'th')}</tr></thead>
    <tbody>{rows}
    </tbody>
  </table>

  <div class="xsection" style="page-break-before: always;"><span class="t">{tr(T, 'focus')}</span></div>
  {focus}
</body>
</html>"""
        return html

    def generate_pdf_report(self, mitigation_data, stats):
        """Génère le rapport PDF avec WeasyPrint"""

        from weasyprint import HTML, CSS  # PDF seulement : build_data reste importable sans WeasyPrint
        from weasyprint.text.fonts import FontConfiguration
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

def build_mitigations_data(data_dir='.'):
    """parts.mitigations du JSON canonique, calculé depuis le dossier data/ d'une campagne."""
    generator = MitigationPlanPDFGenerator(data_dir=data_dir, output_dir=data_dir)
    exposia_files, mitigation_files = generator.find_csv_files()
    mitigation_data = generator.load_mitigation_data(mitigation_files[0])
    stats = generator.calculate_statistics(mitigation_data, generator.load_exposia_data(exposia_files[0]))
    return generator.build_data(mitigation_data, stats)
