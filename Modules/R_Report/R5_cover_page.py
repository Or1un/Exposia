#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R5_cover_page.py — Page de garde du rapport Exposia.

Génère automatiquement (non-interactif) la couverture PDF :
  - organisation = nom de la campagne,
  - domaine = --domain,
  - niveau de criticité = criticality_rating de run_summary.json (note ASM de D1).

Design : fond indigo profond, lueur "révélation" en bas, wordmark Exposia,
titre serif (Fraunces) et texte sans-serif (Inter), bloc d'infos sans encadré.
Les polices sont embarquées en base64 (rendu garanti, indépendant du système) ;
WeasyPrint ne conserve au final que les glyphes utilisés. Positionnement absolu
(flexbox WeasyPrint peu fiable) et couleur pleine pour le « x » (background-clip
: text non supporté par WeasyPrint).

Fichiers de police attendus dans Parameters/branding/fonts/ :
  Inter-Regular.ttf, Inter-Medium.ttf, Inter-SemiBold.ttf, Inter-Bold.ttf,
  Fraunces-Light.ttf, Fraunces-LightItalic.ttf
"""

from weasyprint import HTML
from datetime import datetime
import sys
import os
import json
import base64
from html import escape as esc  # échappement HTML de toute valeur injectée dans un rapport

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
from exposia_ui import Colors, ModernUI  # UI console centralisée


# Niveau de criticité -> (label FR, couleur haute, couleur basse du dégradé du badge)
RISK_STYLES = {
    'low':      ('Faible',   '#7FB84E', '#6BA33E'),
    'medium':   ('Moyen',    '#E0A94A', '#D0993A'),
    'high':     ('Élevé',    '#F0973F', '#E8823C'),
    'critical': ('Critique', '#E85761', '#D8434C'),
}

_FONT_FACES = [
    ('InterExposia',    400, 'normal',  'Inter-Regular.ttf'),
    ('InterExposia',    500, 'normal',  'Inter-Medium.ttf'),
    ('InterExposia',    600, 'normal',  'Inter-SemiBold.ttf'),
    ('InterExposia',    700, 'normal',  'Inter-Bold.ttf'),
    ('FrauncesExposia', 300, 'normal',  'Fraunces-Light.ttf'),
    ('FrauncesExposia', 300, 'italic',  'Fraunces-LightItalic.ttf'),
]


def _build_font_css(fonts_dir):
    """Construit les @font-face avec les polices embarquées en base64 (skip si absent)."""
    faces = []
    for family, weight, style, filename in _FONT_FACES:
        path = os.path.join(fonts_dir, filename)
        try:
            with open(path, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('ascii')
        except Exception:
            continue  # police absente -> fallback générique
        faces.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"font-style:{style};src:url(data:font/ttf;base64,{b64}) format('truetype');}}"
        )
    return "\n".join(faces)


def _french_date():
    d = datetime.now().strftime('%d %B %Y')
    months = {'January': 'janvier', 'February': 'février', 'March': 'mars',
              'April': 'avril', 'May': 'mai', 'June': 'juin', 'July': 'juillet',
              'August': 'août', 'September': 'septembre', 'October': 'octobre',
              'November': 'novembre', 'December': 'décembre'}
    for en, fr in months.items():
        d = d.replace(en, fr)
    return d.lstrip('0')


def generate_cover_page(organization, domain, risk_level, output_file, fonts_dir):
    """Génère la page de garde PDF."""
    organization, domain = esc(str(organization)), esc(str(domain))  # valeurs injectées dans le HTML
    risk_label, badge_hi, badge_lo = RISK_STYLES.get(str(risk_level).lower(), RISK_STYLES['critical'])
    current_date = _french_date()
    font_css = _build_font_css(fonts_dir)

    html_content = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport d'analyse — {organization.capitalize()}</title>
<style>
{font_css}
@page {{ size: A4; margin: 0; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
.page {{
  position: relative; width: 210mm; height: 297mm; overflow: hidden;
  background:
    radial-gradient(115% 72% at 50% 6%, #161C46 0%, transparent 56%),
    linear-gradient(180deg, #0A0E24 0%, #0B0F2A 55%, #0D1130 100%);
  font-family: 'InterExposia', Arial, sans-serif; color: #EAEEFB;
}}
.vignette {{ position: absolute; inset: 0;
  background: radial-gradient(140% 108% at 50% 42%, transparent 64%, rgba(4,6,18,.45) 100%); }}
.dawn {{ position: absolute; left: 50%; bottom: -13%; transform: translateX(-50%);
  width: 158%; height: 58%;
  background: radial-gradient(56% 100% at 50% 100%,
    rgba(245,160,90,.26) 0%, rgba(232,90,155,.15) 38%, rgba(232,90,155,.05) 60%, transparent 76%); }}

.brand {{ position: absolute; top: 24mm; left: 20mm; right: 20mm; }}
.wordmark {{ font-size: 33pt; font-weight: 600; letter-spacing: -.5pt; line-height: 1; color: #F3F5FF; }}
.wordmark .x {{ color: #EF8A54; font-weight: 700; }}
.baseline {{ font-family: 'FrauncesExposia', Georgia, serif; font-style: italic; font-weight: 300;
  font-size: 13.5pt; color: #C8B6D8; letter-spacing: .2pt; margin-top: 3mm; }}

.hero {{ position: absolute; top: 106mm; left: 20mm; right: 20mm; }}
.title {{ font-family: 'FrauncesExposia', Georgia, serif; font-weight: 300; font-size: 40pt;
  line-height: 1.02; letter-spacing: 1pt; color: #F1F3FF; white-space: nowrap; }}
.subtitle {{ font-size: 14.5pt; font-weight: 400; color: #98A2C6; margin-top: 5mm; line-height: 1.5; }}
.signature {{ font-size: 9.5pt; font-weight: 500; letter-spacing: 2.2pt; text-transform: uppercase;
  color: #B9C2E4; margin-top: 7mm; }}
.signature .sep {{ color: #F5A05A; margin: 0 3px; }}

.info {{ position: absolute; left: 20mm; right: 20mm; bottom: 34mm; }}
.row {{ padding: 5.2mm 0; }}
.row + .row {{ border-top: 1px solid rgba(160,180,240,.10); }}
.label {{ display: inline-block; width: 46mm; font-size: 8.5pt; font-weight: 600;
  letter-spacing: 1.5pt; text-transform: uppercase; color: #6B76A0; vertical-align: middle; }}
.value {{ font-size: 14pt; font-weight: 500; color: #EDF0FC; vertical-align: middle; }}
.badge {{ display: inline-block; padding: 1.7mm 5mm; border-radius: 2mm; font-size: 10pt;
  font-weight: 700; letter-spacing: 1.2pt; text-transform: uppercase; color: #fff;
  background: linear-gradient(135deg, {badge_hi}, {badge_lo});
  box-shadow: 0 4px 16px rgba(0,0,0,.28); }}

.footer {{ position: absolute; left: 20mm; right: 20mm; bottom: 16mm; text-align: center; }}
.footer .txt {{ font-size: 8.5pt; font-weight: 500; letter-spacing: 2pt;
  text-transform: uppercase; color: #6B76A0; }}
</style>
</head>
<body>
  <div class="page">
    <div class="vignette"></div>
    <div class="dawn"></div>

    <div class="brand">
      <div class="wordmark">E<span class="x">x</span>posia</div>
      <div class="baseline">Révéler ce qui vous expose</div>
    </div>

    <div class="hero">
      <div class="title">RAPPORT D'ANALYSE</div>
      <div class="subtitle">De la menace &agrave; l'action&nbsp;: comprendre votre exposition et prioriser les mesures.</div>
      <div class="signature">Threat<span class="sep">—</span>Assets<span class="sep">—</span>Risks<span class="sep">—</span>Mitigations</div>
    </div>

    <div class="info">
      <div class="row"><span class="label">Organisation</span><span class="value">{organization.capitalize()}</span></div>
      <div class="row"><span class="label">Domaine analysé</span><span class="value">{domain}</span></div>
      <div class="row"><span class="label">Date d'analyse</span><span class="value">{current_date}</span></div>
      <div class="row"><span class="label">Niveau de criticité</span><span class="value"><span class="badge">{risk_label}</span></span></div>
    </div>

    <div class="footer">
      <div class="txt">Confidentiel — Usage interne uniquement</div>
    </div>
  </div>
</body>
</html>'''

    HTML(string=html_content).write_pdf(output_file)
    ModernUI.status(f"PDF généré : {output_file}", "success")


def main():
    """Génération automatisée de la page de garde (org/domaine/risque déduits du run)."""
    import argparse
    ap = argparse.ArgumentParser(description="Page de garde du rapport Exposia.")
    ap.add_argument("-r", "--result-dir", default=None, help="Dossier de campagne.")
    ap.add_argument("--domain", default=None, help="Domaine analysé.")
    args = ap.parse_args()

    # Dossier data/ de la campagne ; on s'y place pour écrire le PDF au bon endroit.
    data_dir = exposia_paths.resolve_data_dir(args.result_dir, args.domain)
    os.chdir(data_dir)

    # Organisation = nom de la campagne (dossier parent de data/) ; domaine = --domain.
    organization = os.path.basename(os.path.dirname(os.path.abspath(data_dir)))
    domain = args.domain or organization

    # Niveau de risque = criticality_rating de run_summary.json (note ASM de D1).
    risk_level = "critical"
    try:
        with open("run_summary.json", encoding="utf-8") as f:
            rating = json.load(f).get("criticality_rating")
        if rating:
            risk_level = rating.lower()
    except Exception:
        ModernUI.status("run_summary.json introuvable — niveau de risque par défaut (critical)", "warning")

    fonts_dir = exposia_paths.parameter("branding", "fonts")

    org_slug = organization.lower().replace(' ', '_').replace("'", '').replace('"', '')
    output_file = f"rapport_{org_slug}.pdf"

    try:
        generate_cover_page(organization, domain, risk_level, output_file, fonts_dir)
    except Exception as e:
        ModernUI.status(f"Erreur lors de la génération de la page de garde : {e}", "error")
        sys.exit(1)


if __name__ == '__main__':
    main()