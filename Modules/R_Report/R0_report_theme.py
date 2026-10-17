#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_theme.py — Système de design partagé des rapports Exposia.

Source de vérité UNIQUE pour la mise en forme commune à tous les générateurs de
rapports PDF (page de garde, threat modeling, asset discovery, risk assessment,
mitigation, synthèse globale). Chaque générateur importe BASE_CSS et n'ajoute
que son CSS spécifique (visualisations, badges de sévérité, cartes, etc.).

Objectif : un rendu ABSOLUMENT UNIFORME entre toutes les parties du rapport
final. Pour changer l'apparence commune (couleurs, en-têtes, tables...),
on modifie ce fichier — et lui seul.
"""

# --- Palette (design tokens) : source unique des couleurs de marque ----------
COLORS = {
    "brand_dark":    "#1E293B",  # slate — texte principal, en-têtes, chrome
    "brand_slate":   "#334155",
    "text_muted":    "#475569",
    "border":        "#E2E8F0",
    "surface":       "#F1F5F9",
    "surface_alt":   "#f8f9fa",
    "panel":         "#ecf0f1",
    "accent_orange": "#F97316",
    "warning":       "#F59E0B",
    "accent_blue":   "#2563EB",
    "blue_500":      "#3B82F6",
    "blue_300":      "#60A5FA",
    "accent_green":  "#84CC16",
    # Échelle de sévérité (héritée, réutilisée par plusieurs rapports)
    "sev_critical":  "#e74c3c",
    "sev_high":      "#f39c12",
    "sev_medium":    "#f1c40f",
    "sev_low":       "#95a5a6",
    "white":         "#FFFFFF",
}

FONT_STACK = "'DejaVu Sans', Arial, sans-serif"

# --- Feuille de style de base commune (le « chrome » partagé) -----------------
# Version canonique unique. Les générateurs NE redéfinissent PLUS ces règles ;
# ils concatènent BASE_CSS + leur CSS spécifique.
BASE_CSS = """
@page {
    size: A4;
    margin: 15mm;
}

body {
    font-family: 'DejaVu Sans', Arial, sans-serif;
    line-height: 1.6;
    color: #1E293B;
    font-size: 11px;
}

.header {
    border-bottom: 3px solid #1E293B;
    padding-bottom: 20px;
    margin-bottom: 30px;
}
.header h1 {
    color: #1E293B;
    font-size: 24px;
    margin: 0;
    font-weight: 700;
}
.header .subtitle {
    color: #1E293B;
    font-size: 14px;
    margin-top: 8px;
}

.section-title {
    background: #1E293B;
    color: white;
    padding: 12px 20px;
    margin: 25px 0 20px 0;
    border-radius: 6px;
    font-size: 16px;
    font-weight: 600;
}

.executive-summary {
    background: #ecf0f1;
    padding: 20px;
    border-radius: 5px;
    margin-bottom: 25px;
}
.executive-summary h3 {
    margin-top: 0;
    color: #1E293B;
    font-size: 14px;
}

.methodology {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 8px;
    border: 1px solid #dee2e6;
    margin-bottom: 25px;
}

.priority-table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
}
.priority-table th,
.priority-table td {
    padding: 10px 8px;
    text-align: left;
    border-bottom: 1px solid #ecf0f1;
    font-size: 10px;
}
.priority-table th {
    background: #1E293B;
    color: white;
    font-weight: 600;
}
.priority-table tr:nth-child(even) {
    background: #f8f9fa;
}

.footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 2px solid #ecf0f1;
    font-size: 10px;
    color: #1E293B;
    text-align: center;
}

.page-break {
    page-break-before: always;
}

h3 { font-size: 14px; }
h4 { font-size: 12px; }
"""


def base_css():
    """Retourne la feuille de style de base commune (chrome partagé)."""
    return BASE_CSS


# =============================================================================
# SYSTÈME DE DESIGN EXPOSIA — s'ajoute à BASE_CSS sans le modifier.
# Les modules migrés utilisent get_exposia_css() au lieu de BASE_CSS.
# =============================================================================
import os as _os
import base64 as _base64

# --- Tokens de couleur Exposia ----------------------------------------------
COLORS.update({
    "ex_ink":         "#20263F",
    "ex_muted":       "#6A7191",
    "ex_faint":       "#9AA0BC",
    "ex_line":        "#E7E9F4",
    "ex_tint":        "#F5F6FD",
    "ex_surface":     "#FFFFFF",
    "ex_accent":      "#4B47C9",
    "ex_accent_ink":  "#3B37AE",
    "ex_accent_tint": "#ECEBFB",
    "ex_warm":        "#EF8A54",
    "ex_sev_critical":"#D8434C",
    "ex_sev_high":    "#E8823C",
    "ex_sev_medium":  "#E0A94A",
    "ex_sev_low":     "#6BA84E",
})

# --- Polices embarquées (base64) — mêmes familles que la couverture R5 -------
_EX_FONT_FACES = [
    ('InterExposia',    400, 'normal',  'Inter-Regular.ttf'),
    ('InterExposia',    500, 'normal',  'Inter-Medium.ttf'),
    ('InterExposia',    600, 'normal',  'Inter-SemiBold.ttf'),
    ('InterExposia',    700, 'normal',  'Inter-Bold.ttf'),
    ('FrauncesExposia', 300, 'normal',  'Fraunces-Light.ttf'),
    ('FrauncesExposia', 300, 'italic',  'Fraunces-LightItalic.ttf'),
]

def _ex_fonts_dir():
    here = _os.path.dirname(_os.path.abspath(__file__))          # Modules/R_Report
    root = _os.path.dirname(_os.path.dirname(here))              # racine projet
    return _os.path.join(root, "Parameters", "branding", "fonts")

def _ex_build_font_css():
    faces = []
    d = _ex_fonts_dir()
    for family, weight, style, filename in _EX_FONT_FACES:
        try:
            with open(_os.path.join(d, filename), 'rb') as f:
                b64 = _base64.b64encode(f.read()).decode('ascii')
        except Exception:
            continue
        faces.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"font-style:{style};src:url(data:font/ttf;base64,{b64}) format('truetype');}}"
        )
    return "\n".join(faces)

FONT_CSS = _ex_build_font_css()

# --- Icônes SVG (line, cohérentes) ------------------------------------------
ICONS = {
    "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l7 4v6c0 4.5-3 7.5-7 10-4-2.5-7-5.5-7-10V6z"/></svg>',
    "chart":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>',
    "users":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="8" r="3"/><path d="M3 20a6 6 0 0 1 12 0"/><path d="M16 5a3 3 0 0 1 0 6M18 20a6 6 0 0 0-3-5"/></svg>',
    "book":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 5a2 2 0 0 1 2-2h9v15H6a2 2 0 0 0-2 2z"/><path d="M15 3h3a1 1 0 0 1 1 1v15a2 2 0 0 0-2-1.9H15z"/></svg>',
    "server": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
    "alert":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/></svg>',
    "target": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/></svg>',
    "wrench": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 6a4 4 0 0 1 5.5 4.6L21 12l-3 3-1.4-1.5A4 4 0 0 1 12 8l-6.5 6.5a2 2 0 1 0 3 3L15 11"/></svg>',
}

def icon(name, size=15):
    svg = ICONS.get(name, "")
    return svg.replace("<svg ", f'<svg width="{size}" height="{size}" ', 1) if svg else ""

# --- CSS commun du corps (thème clair Exposia) ------------------------------
EXPOSIA_CSS = """
* { box-sizing: border-box; }

@page {
  size: A4;
  margin: 22mm 18mm 20mm 18mm;
  @top-left  { content: element(rhBrand); vertical-align: bottom; }
  @top-right { content: element(rhDoc);   vertical-align: bottom; }
}

body { font-family: 'InterExposia', Arial, sans-serif; color: #20263F; font-size: 10.5pt; line-height: 1.55; }

.rh-brand { position: running(rhBrand); font-size: 11pt; font-weight: 700; letter-spacing: -.3pt; color: #20263F; }
.rh-brand .x { color: #EF8A54; }
.rh-doc { position: running(rhDoc); font-size: 7.5pt; font-weight: 600; letter-spacing: .8pt; text-transform: uppercase; color: #9AA0BC; }

.kicker { font-size: 8pt; font-weight: 700; letter-spacing: 1.8pt; text-transform: uppercase; color: #4B47C9; margin-bottom: 2mm; }
.part-title { font-family: 'FrauncesExposia', Georgia, serif; font-weight: 400; font-size: 23pt; line-height: 1.06; color: #20263F; letter-spacing: .2pt; margin: 0; }
.rule { height: 2.5px; width: 22mm; background: linear-gradient(90deg, #4B47C9, #9C99E8); border-radius: 3px; margin: 4mm 0 7mm; }

.callout { background: #F5F6FD; border: 1px solid #E7E9F4; border-radius: 3mm; padding: 5mm 6mm; margin-bottom: 8mm; }
.callout .ttl { display: flex; align-items: center; gap: 2.5mm; font-size: 8.5pt; font-weight: 700; letter-spacing: 1.2pt; text-transform: uppercase; color: #3B37AE; margin-bottom: 3mm; }
.callout .ttl svg { width: 14px; height: 14px; }
.callout p { font-size: 10.5pt; line-height: 1.6; color: #3A4160; margin: 0; }
.callout b, .callout strong { color: #20263F; font-weight: 600; }

.stats { display: flex; border: 1px solid #E7E9F4; border-radius: 3mm; margin-bottom: 8mm; overflow: hidden; }
.stat { flex: 1; padding: 5.5mm 4mm; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
.stat + .stat { border-left: 1px solid #E7E9F4; }
.stat .num { font-family: 'FrauncesExposia', Georgia, serif; font-weight: 400; font-size: 22pt; line-height: 1; color: #20263F; }
.stat.crit .num { color: #D8434C; }
.stat .lab { font-size: 7.5pt; font-weight: 600; letter-spacing: .5pt; text-transform: uppercase; color: #6A7191; line-height: 1.35; margin-top: 2.4mm; }

.xsection { margin: 7mm 0 5mm; padding-bottom: 2.6mm; border-bottom: 1px solid #E7E9F4; display: flex; align-items: center; gap: 2.5mm; }
.xsection svg { width: 15px; height: 15px; color: #4B47C9; }
.xsection .t { font-size: 11pt; font-weight: 600; letter-spacing: .3pt; color: #3B37AE; }

.xtable { width: 100%; border-collapse: collapse; font-size: 9.5pt; }
.xtable thead th { background: #20263F; color: #EEF0FA; text-align: left; font-weight: 600; letter-spacing: .4pt; font-size: 8.5pt; text-transform: uppercase; padding: 3.2mm 4mm; }
.xtable thead th:first-child { border-radius: 2mm 0 0 0; }
.xtable thead th:last-child { border-radius: 0 2mm 0 0; }
.xtable tbody td { padding: 3.4mm 4mm; border-bottom: 1px solid #E7E9F4; vertical-align: middle; }
.xtable tbody tr:nth-child(even) { background: #FAFBFE; }
.xtable td.center { text-align: center; }
.rank { display: inline-flex; align-items: center; justify-content: center; width: 6.5mm; height: 6.5mm; border-radius: 50%; background: #ECEBFB; color: #3B37AE; font-weight: 700; font-size: 8.5pt; }
.rank.r1 { background: #D8434C; color: #fff; }

.sev-badge { display: inline-block; padding: 1.1mm 3.4mm; border-radius: 20px; font-size: 8pt; font-weight: 700; letter-spacing: .8pt; text-transform: uppercase; color: #fff; }
.sev-critical { background: #D8434C; }
.sev-high { background: #E8823C; }
.sev-medium { background: #E0A94A; }
.sev-low { background: #6BA84E; }

.prose { font-size: 10pt; line-height: 1.7; color: #454B68; }
.prose b, .prose strong { color: #20263F; font-weight: 600; }
.avoid-break { page-break-inside: avoid; }
"""

def get_exposia_css():
    """CSS du nouveau système Exposia (polices + corps clair). Les modules
    migrés font : report_theme.get_exposia_css() + <CSS spécifique>."""
    return FONT_CSS + "\n" + EXPOSIA_CSS