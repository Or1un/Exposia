#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R8_back_cover.py — Quatrième de couverture du rapport Exposia.

Même fond que la page de garde (R5), à l'identique : halo indigo en haut, lueur
chaude en bas, vignettage. Seul le contenu change : la couverture et la
quatrième forment ainsi une paire cohérente.

Contenu volontairement épuré : le wordmark Exposia, un filet, puis la phrase de
clôture, et la mention de confidentialité. Assemblée par R9 en dernière page,
non numérotée.
"""

import os
import sys
import base64
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
from exposia_ui import ModernUI  # UI console centralisée

from weasyprint import HTML

_FONT_FACES = [
    ('InterExposia',    400, 'normal',  'Inter-Regular.ttf'),
    ('InterExposia',    500, 'normal',  'Inter-Medium.ttf'),
    ('InterExposia',    600, 'normal',  'Inter-SemiBold.ttf'),
    ('InterExposia',    700, 'normal',  'Inter-Bold.ttf'),
    ('FrauncesExposia', 300, 'normal',  'Fraunces-Light.ttf'),
    ('FrauncesExposia', 300, 'italic',  'Fraunces-LightItalic.ttf'),
]


def _build_font_css(fonts_dir):
    """@font-face embarqués en base64 (mêmes polices que R5 ; ignore une police absente)."""
    faces = []
    for family, weight, style, filename in _FONT_FACES:
        try:
            with open(os.path.join(fonts_dir, filename), 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('ascii')
        except Exception:
            continue
        faces.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"font-style:{style};src:url(data:font/ttf;base64,{b64}) format('truetype');}}"
        )
    return "\n".join(faces)


def generate_back_cover(output_file, fonts_dir):
    font_css = _build_font_css(fonts_dir)

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Exposia</title>
<style>
{font_css}
@page {{ size: A4; margin: 0; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
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

.hero {{ position: absolute; top: 100mm; left: 20mm; right: 20mm; }}
.wordmark {{ font-size: 33pt; font-weight: 600; letter-spacing: -.5pt; line-height: 1; color: #F3F5FF; }}  /* = page de garde */
.wordmark .x {{ color: #EF8A54; font-weight: 700; }}
.rule {{ height: 2px; width: 22mm; margin: 9mm 0 8mm;
  background: linear-gradient(90deg, #EF8A54, rgba(239,138,84,0)); }}
.statement {{ font-family: 'FrauncesExposia', Georgia, serif; font-weight: 300; font-size: 20pt;
  line-height: 1.3; letter-spacing: .2pt; color: #F1F3FF; }}
.statement em {{ font-style: italic; color: #C8B6D8; }}

.footer {{ position: absolute; left: 20mm; right: 20mm; bottom: 16mm; text-align: center; }}
.footer .txt {{ font-size: 8.5pt; font-weight: 500; letter-spacing: 2pt; text-transform: uppercase; color: #6B76A0; }}
</style>
</head>
<body>
  <div class="page">
    <div class="vignette"></div>
    <div class="dawn"></div>

    <div class="hero">
      <div class="wordmark">E<span class="x">x</span>posia</div>
      <div class="rule"></div>
      <div class="statement">Votre exposition &eacute;volue chaque jour.<br><em>Votre visibilit&eacute; aussi devrait.</em></div>
    </div>

    <div class="footer"></div>
  </div>
</body>
</html>'''
    HTML(string=html).write_pdf(output_file)
    ModernUI.status(f"PDF généré : {os.path.basename(output_file)}", "success")
    return output_file


def main():
    ap = argparse.ArgumentParser(description="Quatrième de couverture du rapport Exposia.")
    ap.add_argument("-r", "--result-dir", default=None, help="Dossier de campagne.")
    ap.add_argument("-d", "--data-dir", default=None, help="Répertoire de sortie (défaut : data/ de la campagne)")
    args = ap.parse_args()

    data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generate_back_cover(os.path.join(data_dir, f"back_cover_report_{timestamp}.pdf"),
                            exposia_paths.parameter("branding", "fonts"))
    except Exception as e:
        ModernUI.status(f"Erreur lors de la génération de la quatrième de couverture : {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()