#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R11_table_of_contents.py — Sommaire du rapport Exposia (page dédiée).

N'est PAS lancé seul par le pipeline : les numéros de page ne sont connus qu'à
l'assemblage. R9 compte les pages de chaque partie, puis appelle build_toc()
et insère la page entre l'avant-propos et la synthèse. R9 ajoute ensuite les
liens cliquables (zones renvoyées par build_toc) et les signets PDF.

Système de design Exposia partagé (R0_report_theme), comme les autres parties.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:  # thème partagé (report_theme.py ou R0_report_theme.py)
    import report_theme
except ImportError:
    import R0_report_theme as report_theme

from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration


# Parties listées au sommaire : motif du PDF intermédiaire -> (surtitre, titre).
# Mêmes libellés que les en-têtes des parties.
TOC_PARTS = [
    ("synthesis_global_report_", "Synthèse", "De la menace à la mitigation"),
    ("threat_modeling_report_", "Partie 1 · Menaces", "Qui vous attaque, et pourquoi ?"),
    ("asset_discovery_report_", "Partie 2 · Actifs", "Quel est votre périmètre exposé ?"),
    ("risk_assessment_report_", "Partie 3 · Risques", "Quels impacts sur votre business ?"),
    ("mitigation_plan_report_", "Partie 4 · Mitigation", "Que faire concrètement ?"),
]

_NUMBERS_FR = {2: "deux", 3: "trois", 4: "quatre", 5: "cinq", 6: "six"}

TOC_CSS = """
.intro { font-size: 10pt; line-height: 1.65; color: #6A7191; margin: -2mm 0 9mm; }

.toc { list-style: none; margin: 0; padding: 0; border-top: 1px solid #E7E9F4; }
.toc li { border-bottom: 1px solid #E7E9F4; }
.toc a { display: table; width: 100%; padding: 7.5mm 0; text-decoration: none; color: inherit; }
.toc .txt { display: table-cell; vertical-align: middle; }
.toc .num { display: table-cell; vertical-align: middle; text-align: right; width: 22mm;
            font-family: 'FrauncesExposia', Georgia, serif; font-weight: 300; font-size: 20pt;
            color: #4B47C9; }
.toc .kick { display: block; font-size: 7.5pt; font-weight: 700; letter-spacing: 1.6pt;
             text-transform: uppercase; color: #3B37AE; margin-bottom: 1.4mm; }
.toc .title { display: block; font-family: 'FrauncesExposia', Georgia, serif; font-weight: 300;
              font-size: 15pt; line-height: 1.25; color: #20263F; }
"""


def _html_escape(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def build_html(org_disp, entries):
    """entries : liste de (surtitre, titre, numéro de page affiché)."""
    count = len(entries)
    n_txt = _NUMBERS_FR.get(count, str(count))
    title = f"Votre rapport en {n_txt} temps" if count > 1 else "Votre rapport"
    rows = "".join(
        f'<li><a href="toc:{page}"><span class="txt"><span class="kick">{_html_escape(kick)}</span>'
        f'<span class="title">{_html_escape(name)}</span></span>'
        f'<span class="num">{page}</span></a></li>'
        for kick, name, page in entries
    )
    return f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Sommaire</title></head>
<body>
  <div class="rh-brand">E<span class="x">x</span>posia</div>
  <div class="rh-doc">Rapport d'analyse &middot; {_html_escape(org_disp)}</div>

  <div class="kicker">Sommaire</div>
  <div class="part-title">{title}</div>
  <div class="rule"></div>

  <p class="intro">Chaque partie s'ouvre sur un encadr&eacute; &laquo;&nbsp;En clair&nbsp;&raquo; qui en r&eacute;sume l'essentiel&nbsp;: la synth&egrave;se suffit pour d&eacute;cider, les parties suivantes apportent le d&eacute;tail.</p>

  <ul class="toc">{rows}
  </ul>
</body>
</html>"""


def build_toc(output_file, org_disp, entries):
    """
    Génère la page de sommaire.

    entries : liste de (surtitre, titre, numéro de page affiché, 1 = page de garde).
    Retourne (nombre de pages produites, liens) où liens est une liste de
    (numéro de page cible, (x1, y1, x2, y2)) en points PDF, origine en bas à
    gauche, pour créer les zones cliquables à l'assemblage.
    """
    links = []
    font_config = FontConfiguration()
    css = CSS(string=report_theme.get_exposia_css() + TOC_CSS, font_config=font_config)
    document = HTML(string=build_html(org_disp, entries)).render(
        stylesheets=[css], font_config=font_config)

    # Une zone cliquable par entrée : WeasyPrint renvoie une boîte par élément
    # imbriqué dans le lien, on en prend l'enveloppe. Rectangles WeasyPrint en
    # px CSS (x1, y1, x2, y2), origine en haut à gauche -> points PDF, bas à gauche.
    zones = {}
    for page in document.pages[:1]:
        page_height_pt = page.height * 0.75
        for link in page.links:
            target, rect = str(link[1]), link[2]
            if not target.startswith("toc:"):
                continue
            x1, y1, x2, y2 = (v * 0.75 for v in rect)
            num = int(target[4:])
            if num in zones:
                a1, b1, a2, b2 = zones[num]
                x1, y1, x2, y2 = min(a1, x1), min(b1, y1), max(a2, x2), max(b2, y2)
            zones[num] = (x1, y1, x2, y2)
        links = [(num, (x1, page_height_pt - y2, x2, page_height_pt - y1))
                 for num, (x1, y1, x2, y2) in zones.items()]
    document.write_pdf(output_file)
    return len(document.pages), links