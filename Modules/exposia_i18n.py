#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_i18n.py — Langue des livrables (FR / EN).

La langue est choisie une fois pour tout le run : run_pipeline.sh --lang en
exporte EXPOSIA_LANG=en ; un module lancé seul la lit aussi (EXPOSIA_LANG=en
python R3_…). Français par défaut.

Trois sortes de textes :
  • textes fixes des modules (titres, méthodologies, notes) : chaque module
    déclare ses textes FR et EN côte à côte, T = {'clé': ("…", "…")}, et les lit
    avec tr(T, 'clé', **valeurs) ;
  • textes des référentiels (récits d'attaque, mesures) : le fichier de travail
    garde le texte français, copié tel quel depuis Parameters/ ; text(fr) le
    remplace au rendu par sa colonne _EN. Une campagne déjà collectée se rend
    donc en anglais sans nouvelle collecte ;
  • libellés de vocabulaire (sévérités, acteurs, catégories) : exposia_vocab.

Un texte introuvable reste en français et est signalé une fois (missing()).
"""

import csv
import os
from datetime import date, datetime

LANGS = ('fr', 'en')

# Référentiels traduits : fichier -> colonnes FR qui ont une jumelle <colonne>_EN.
REFERENTIALS = {
    ('Ports_to_attack.csv',): ('Reconnaissance', 'Exploitation', 'Impact'),
    ('CVSS', 'CVSS_step1.csv'): ('Reconnaissance (Étape 1)',),
    ('CVSS', 'CVSS_step2.csv'): ('Modificateur Exploitation (Étape 2)',),
    ('CVSS', 'CVSS_step3.csv'): ('Impact Métier (Étape 3)',),
    ('CVSS', 'CVSS_step3_attenuation.csv'): ('Modificateur Impact (Étape 3)',),
    ('mitigation_measures.csv',): ('Mesure Technique', 'Mesure Organisationnelle', 'KPI_Principal'),
}

_MONTHS_FR = ('janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août',
              'septembre', 'octobre', 'novembre', 'décembre')
_MONTHS_EN = ('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
              'September', 'October', 'November', 'December')

_table = None
_missing = set()


def lang():
    """Langue du run : EXPOSIA_LANG (fr ou en), français par défaut."""
    value = str(os.environ.get('EXPOSIA_LANG') or 'fr').strip().lower()
    return value if value in LANGS else 'fr'


def is_en():
    return lang() == 'en'


def tr(table, key, **values):
    """Texte fixe d'un module : table[key] = (fr, en), formaté avec values."""
    fr, en = table[key]
    text = en if is_en() and en else fr
    return text.format(**values) if values else text


def pick(fr, en):
    """Variante courte, pour un texte isolé : pick("Rang", "Rank")."""
    return en if is_en() else fr


def label(vocab_name, value):
    """
    Valeur de vocabulaire affichée (acteur, motivation, catégorie…) : inchangée en
    français, libellé anglais de son code en anglais (repli : la valeur).
    """
    raw = '' if value is None else str(value)
    if not is_en():
        return raw
    import exposia_vocab as vocab
    return vocab.label(vocab_name, vocab.code(vocab_name, raw), 'en', fallback=raw) or raw


def _load():
    global _table
    if _table is not None:
        return _table
    _table = {}
    try:
        import exposia_paths
        base = exposia_paths.parameters_dir()
    except Exception:
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Parameters')
    for parts, columns in REFERENTIALS.items():
        try:
            with open(os.path.join(base, *parts), encoding='utf-8-sig', newline='') as f:
                for row in csv.DictReader(f, delimiter=';'):
                    for column in columns:
                        fr = (row.get(column) or '').strip()
                        en = (row.get(column + '_EN') or '').strip()
                        if fr and en:
                            _table.setdefault(fr, en)
        except OSError:
            continue
    return _table


def text(fr):
    """
    Texte issu d'un référentiel (récit, mesure, indicateur), dans la langue du
    run. En anglais, sa traduction _EN ; à défaut, le texte français (signalé).
    """
    value = '' if fr is None else str(fr)
    if not is_en():
        return value
    key = value.strip()
    if not key or key in ('#N/A', 'nan', 'None'):
        return value
    en = _load().get(key)
    if en is None:
        _missing.add(key)
        return value
    return en


def missing():
    """Textes de référentiel restés en français pendant le rendu anglais."""
    return sorted(_missing)


def number(value, digits=1):
    """Nombre décimal affiché : virgule en français, point en anglais."""
    txt = f"{float(value):.{digits}f}"
    return txt if is_en() else txt.replace('.', ',')


def percent(value, digits=1, html=True):
    """Pourcentage : « 66,7 % » (espace insécable) en français, « 66.7% » en anglais."""
    num = number(value, digits) if digits else str(int(round(float(value))))
    if is_en():
        return f"{num}%"
    return f"{num}&nbsp;%" if html else f"{num} %"


def long_date(value=None):
    """Date longue : « 18 octobre 2026 » / « October 18, 2026 »."""
    d = value or date.today()
    if isinstance(d, datetime):
        d = d.date()
    if is_en():
        return f"{_MONTHS_EN[d.month - 1]} {d.day}, {d.year}"
    return f"{d.day} {_MONTHS_FR[d.month - 1]} {d.year}"


def plural(n, singular, plural_form=None):
    """
    Forme selon le nombre, dans la langue du run : singulier pour 0 et 1 en
    français, pour 1 seulement en anglais (« 0 vulnerabilities »).
    """
    one = abs(n) == 1 if is_en() else abs(n) <= 1
    return singular if one else (plural_form or singular + 's')
