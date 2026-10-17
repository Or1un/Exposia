#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R7_disclaimer.py — Avant-propos du rapport Exposia (« Ce que ce rapport dit — et
ce qu'il ne dit pas »).

Page assemblée par R9 juste après la page de garde, avant la synthèse (R6).
Contenu volontairement court (une demi-page) : périmètre de l'analyse, ce qu'elle
est, ce qu'elle n'est pas, et comment lire les constats. Texte fixe : il décrit
la méthode, pas les résultats d'une campagne.

Système de design Exposia partagé (R0_report_theme) : en-tête courant, kicker,
titre Fraunces, filet dégradé, mêmes couleurs que les autres parties.
"""

import os
import sys
import argparse
from html import escape as esc  # échappement HTML de toute valeur injectée dans un rapport
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
from exposia_ui import ModernUI  # UI console centralisée
try:  # thème partagé (report_theme.py ou R0_report_theme.py)
    import report_theme
except ImportError:
    import R0_report_theme as report_theme

from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration


DISCLAIMER_CSS = """
.lead { font-size: 10.5pt; line-height: 1.66; color: #3A4160; margin: -2mm 0 6mm; }
.lead b { color: #20263F; font-weight: 600; }

.scope { width: 100%; border-collapse: separate; border-spacing: 0; table-layout: fixed; margin-bottom: 6mm; }
.scope td.is { width: 37%; }
.scope td { vertical-align: top; padding: 0; }
.scope td.gap { width: 6mm; }
.scope .box { border-top: 2.5px solid #4B47C9; padding: 3.6mm 0 0; }
.scope .box.not { border-top-color: #EF8A54; }
.scope .lab { font-size: 7.5pt; font-weight: 700; letter-spacing: 1.6pt; text-transform: uppercase;
              color: #3B37AE; margin-bottom: 2.2mm; }
.scope .box.not .lab { color: #C2643A; }
.scope p { font-size: 9.6pt; line-height: 1.62; color: #454B68; margin: 0; }
"""


def build_html(org_disp):
    """Contenu HTML de l'avant-propos (texte fixe, validé)."""
    return f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><title>Avant-propos</title></head>
<body>
  <div class="rh-brand">E<span class="x">x</span>posia</div>
  <div class="rh-doc">Rapport d'analyse &middot; {org_disp}</div>

  <div class="kicker">Avant-propos</div>
  <div class="part-title">Ce que ce rapport dit &mdash; et ce qu'il ne dit pas</div>
  <div class="rule"></div>

  <p class="lead">Ce rapport d&eacute;crit votre exposition <b>depuis Internet</b>, du point de vue d'un attaquant externe&nbsp;: <b>sans acc&egrave;s privil&eacute;gi&eacute;, sans jamais toucher &agrave; vos syst&egrave;mes</b>. Chaque constat repose sur des sources publiques et reconnues&nbsp;: certificats publi&eacute;s, DNS, Shodan, base de vuln&eacute;rabilit&eacute;s du NIST (NVD), probabilit&eacute;s d'exploitation (EPSS) et r&eacute;f&eacute;rentiels d'exploits publics.</p>

  <table class="scope">
    <tr>
      <td class="is">
        <div class="box">
          <div class="lab">Ce qu'il est</div>
          <p>Une photographie, &agrave; date, de votre surface d'attaque externe, hi&eacute;rarchis&eacute;e selon la gravit&eacute; technique, la probabilit&eacute; d'exploitation et l'impact m&eacute;tier. Un outil de d&eacute;cision&nbsp;: il indique o&ugrave; agir en premier.</p>
        </div>
      </td>
      <td class="gap"></td>
      <td>
        <div class="box not">
          <div class="lab">Ce qu'il n'est pas</div>
          <p>Un test d'intrusion. Aucune vuln&eacute;rabilit&eacute; n'a &eacute;t&eacute; exploit&eacute;e&nbsp;: la plupart sont d&eacute;duites des versions logicielles annonc&eacute;es par les services expos&eacute;s. Un correctif d&eacute;j&agrave; appliqu&eacute; peut ne pas &ecirc;tre d&eacute;tect&eacute; si la version annonc&eacute;e n'a pas chang&eacute;. Les actifs non publi&eacute;s et votre r&eacute;seau interne sont hors champ. Les sc&eacute;narios d'attaque sont repr&eacute;sentatifs, et la sensibilit&eacute; d'un service est pr&eacute;sum&eacute;e d'apr&egrave;s sa nature.</p>
        </div>
      </td>
    </tr>
  </table>

  <p class="lead">Chaque constat est rattach&eacute; &agrave; sa source et doit &ecirc;tre v&eacute;rifi&eacute; par vos &eacute;quipes avant toute intervention. Les informations pr&eacute;sent&eacute;es sont accessibles publiquement. Leur regroupement permet de mieux comprendre votre exposition et de prioriser les actions.</p>
  </div>
</body>
</html>"""


def generate(data_dir):
    """Génère disclaimer_report_<horodatage>.pdf dans data_dir."""
    try:
        org = os.path.basename(os.path.dirname(os.path.abspath(data_dir)))
    except Exception:
        org = ""
    org_disp = esc(org.capitalize()) if org else "—"

    font_config = FontConfiguration()
    css = CSS(string=report_theme.get_exposia_css() + DISCLAIMER_CSS, font_config=font_config)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = os.path.join(data_dir, f"disclaimer_report_{timestamp}.pdf")
    HTML(string=build_html(org_disp)).write_pdf(pdf_filename, stylesheets=[css], font_config=font_config)
    ModernUI.status(f"PDF généré avec succès: {os.path.basename(pdf_filename)}", "success")
    return pdf_filename


def main():
    parser = argparse.ArgumentParser(description="Génère l'avant-propos du rapport Exposia.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("-d", "--data-dir", default=None,
                        help="Répertoire de sortie du PDF (défaut : data/ de la campagne)")
    args = parser.parse_args()

    data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    try:
        generate(data_dir)
    except Exception as e:
        ModernUI.status(f"Erreur lors de la génération de l'avant-propos : {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()
