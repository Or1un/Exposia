#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_vocab.py — Vocabulaire partagé : codes stables et libellés FR / EN.

Les données d'Exposia mélangent des libellés français (matrices, référentiels)
et anglais (matrices M2..M4, niveaux de qualification). Les sorties destinées à
d'autres programmes (JSON canonique, Lucid) utilisent des CODES : anglais,
en snake_case, indépendants de la langue du rapport. Ce module fait la
correspondance valeur -> code -> libellé, dans les deux sens.

Deux familles de vocabulaires :
  • fermés : définis par l'algorithme d'Exposia (sévérités, types de mesures,
    difficultés, niveaux des matrices M2..M4…). Une valeur inconnue est une erreur
    de données ; code() renvoie None.
  • extensibles : issus des fichiers de Parameters/ que les contributeurs
    enrichissent (secteurs, tailles, zones, acteurs, motivations, catégories).
    Une valeur sans code connu reçoit un code dérivé de son libellé (slug) :
    le JSON reste valide, et un test signale l'oubli.

Codes des catégories : Parameters/service_categories.csv et
Parameters/mitigation_categories.csv (colonnes Code;FR;EN).

Module sans dépendance : importable par tous les modules R et par les tests.
"""

import csv
import os
import re
import unicodedata

# ---------------------------------------------------------------------------
# Tables : code -> (libellé FR, libellé EN, autres valeurs reconnues)
# ---------------------------------------------------------------------------

SEVERITY = {
    'critical': ("Critique", "Critical", ("Critical", "CRITIQUE", "CRITICAL")),
    'high': ("Élevé", "High", ("High", "HAUTE", "HIGH", "ÉLEVÉ", "ELEVE")),
    'medium': ("Modéré", "Medium", ("Medium", "MOYENNE", "MEDIUM", "MODÉRÉ", "MOYEN")),
    'low': ("Faible", "Low", ("Low", "FAIBLE", "LOW")),
}

NATURE = {
    'sensitive': ("Sensible", "Sensitive", ("Internal", "INTERNAL")),
    'standard': ("Standard", "Standard", ("External", "EXTERNAL")),
}

MITIGATION_TYPE = {
    'preventive': ("Préventif", "Preventive", ("Préventif", "Preventive")),
    'detective': ("Détectif", "Detective", ("Détectif", "Detective")),
    'corrective': ("Curatif", "Corrective", ("Curatif", "Corrective")),
}

DIFFICULTY = {
    'low': ("Faible", "Low", ("Faible", "Low")),
    'medium': ("Moyen", "Medium", ("Moyen", "Medium")),
    'high': ("Élevé", "High", ("Élevé", "High")),
    'very_high': ("Très élevé", "Very high", ("Très Élevé", "Très élevé", "Very High", "Very high")),
}

DURATION_UNIT = {
    'week': ("semaine(s)", "week(s)", ("semaine", "semaines", "week", "weeks")),
    'month': ("mois", "month(s)", ("mois", "month", "months")),
}

# Matrice M2 (niveau de motivation), M3 (ressources), M4 (pertinence)
MOTIVATION_LEVEL = {
    'high': ("élevé", "high", ("High",)),
    'quite': ("modéré", "moderate", ("Quite",)),
    'poor': ("faible", "low", ("Poor",)),
    'very_low': ("très faible", "very low", ("Very low",)),
}

RESOURCES_LEVEL = {
    'unlimited': ("illimitées", "unlimited", ("Unlimited", "Illimitées")),
    'important': ("importantes", "substantial", ("Important", "Importantes")),
    'significant': ("significatives", "significant", ("Significant", "Significatives")),
    'limited': ("limitées", "limited", ("Limited", "Limitées")),
    'variable': ("variables", "variable", ("Variables", "Variable")),
}

RELEVANCE = {
    'very_relevant': ("très élevée", "very high", ("Very relevant",)),
    'quite_relevant': ("modérée", "moderate", ("Quite relevant",)),
    'moderately_relevant': ("limitée", "limited", ("Moderately relevant",)),
    'not_really_relevant': ("faible", "low", ("Not really relevant",)),
    'not_relevant': ("nulle", "none", ("Not relevant",)),
}

# Caractéristiques des acteurs (R1) : sophistication et probabilité
QUALITATIVE_LEVEL = {
    'very_high': ("Très élevée", "Very high", ("Très élevée",)),
    'high': ("Élevée", "High", ("Élevée",)),
    'medium_to_high': ("Moyenne à élevée", "Medium to high", ("Moyenne à élevée",)),
    'medium': ("Moyenne", "Medium", ("Moyenne",)),
    'moderate': ("Modérée", "Moderate", ("Modérée",)),
    'low_to_medium': ("Faible à moyenne", "Low to medium", ("Faible à moyenne",)),
    'low': ("Faible", "Low", ("Faible",)),
    'variable': ("Variable", "Variable", ("Variable",)),
}

# Profil d'un acteur selon son nombre de motivations retenues (R1, R6)
# Hébergement d'une exposition (D1 : 'Direct' ou 'CDN <fournisseur>')
HOSTING = {
    'direct': ("Direct", "Direct", ()),
    'cdn': ("CDN", "CDN", ()),
}

PROFILE_TYPE = {
    'targeted': ("Ciblé", "Targeted", ("Ciblé",)),
    'dual': ("Double finalité", "Dual purpose", ("Double finalité",)),
    'triple': ("Triple-menace", "Triple threat", ("Triple-menace",)),
    'multi': ("Multi-objectifs", "Multi-objective", ("Multi-objectifs",)),
}

# --- Vocabulaires extensibles (Parameters/Threat_matrices) -------------------

SECTOR = {
    'finance': ("Finance", "Finance", ()), 'health': ("Santé", "Healthcare", ()),
    'government': ("Gouvernement", "Government", ()), 'energy': ("Énergie", "Energy", ()),
    'defense': ("Défense", "Defense", ()), 'ecommerce': ("E-commerce", "E-commerce", ()),
    'education': ("Éducation", "Education", ()), 'telecom': ("Télécoms", "Telecoms", ()),
    'transport': ("Transport", "Transport", ()), 'industry': ("Industrie", "Industry", ()),
}

SIZE = {
    'micro': ("TPE", "Micro-enterprise", ()), 'sme': ("PME", "SME", ()),
    'midcap': ("ETI", "Mid-cap", ()), 'large': ("Grande", "Large enterprise", ()),
}

ZONE = {
    'western_europe': ("Europe Ouest", "Western Europe", ()),
    'eastern_europe': ("Europe Est", "Eastern Europe", ()),
    'north_america': ("Amérique Nord", "North America", ()),
    'south_america': ("Amérique Sud", "South America", ()),
    'asia_pacific': ("Asie-Pacifique", "Asia-Pacific", ()),
    'middle_east': ("Moyen-Orient", "Middle East", ()),
    'north_africa': ("Afrique Nord", "North Africa", ()),
    'sub_saharan_africa': ("Afrique Sub-saharienne", "Sub-Saharan Africa", ()),
}

ACTOR = {
    'state': ("Étatique", "State-sponsored", ()),
    'organized_crime': ("Crime organisé", "Organized crime", ()),
    'terrorist': ("Terroriste", "Terrorist", ()),
    'activist': ("Activiste", "Hacktivist", ()),
    'mercenary': ("Officine", "Cyber-mercenary", ()),
    'amateur': ("Amateur", "Amateur", ()),
    'avenger': ("Vengeur", "Avenger", ()),
    'malicious': ("Malveillant", "Malicious hacker", ()),
}

MOTIVATION = {
    'espionage': ("Espionnage", "Espionage", ()),
    'strategic_positioning': ("Géopositionnement stratégique", "Strategic positioning", ()),
    'influence': ("Influence", "Influence", ()),
    'disruption': ("Entrave au fonctionnement", "Disruption of operations", ()),
    'profit': ("Lucratif", "Financial gain", ()),
    'challenge': ("Défi, amusement", "Challenge, fun", ()),
}

CLOSED = ('severity', 'nature', 'mitigation_type', 'difficulty', 'duration_unit', 'motivation_level',
          'resources_level', 'relevance', 'qualitative_level', 'profile_type', 'hosting')
EXTENSIBLE = ('sector', 'size', 'zone', 'actor', 'motivation', 'service_category', 'mitigation_category')


def _load_categories(filename):
    """Codes de catégories depuis Parameters/<filename> (Code;FR;EN). {} si absent."""
    try:
        import exposia_paths
        path = exposia_paths.parameter(filename)
    except Exception:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Parameters', filename)
    table = {}
    try:
        with open(path, encoding='utf-8-sig', newline='') as f:
            for row in csv.DictReader(f, delimiter=';'):
                code = (row.get('Code') or '').strip()
                if code:
                    table[code] = ((row.get('FR') or code).strip(), (row.get('EN') or code).strip(), ())
    except OSError:
        pass
    return table


TABLES = {
    'severity': SEVERITY, 'nature': NATURE, 'mitigation_type': MITIGATION_TYPE, 'difficulty': DIFFICULTY,
    'duration_unit': DURATION_UNIT, 'motivation_level': MOTIVATION_LEVEL, 'resources_level': RESOURCES_LEVEL,
    'relevance': RELEVANCE, 'qualitative_level': QUALITATIVE_LEVEL, 'profile_type': PROFILE_TYPE,
    'hosting': HOSTING,
    'sector': SECTOR, 'size': SIZE, 'zone': ZONE, 'actor': ACTOR, 'motivation': MOTIVATION,
    'service_category': _load_categories('service_categories.csv'),
    'mitigation_category': _load_categories('mitigation_categories.csv'),
}

# ---------------------------------------------------------------------------
# Correspondances
# ---------------------------------------------------------------------------

def _norm(value):
    """Clé de comparaison : sans casse ni accents, espaces / tirets / _ équivalents."""
    text = unicodedata.normalize('NFKD', str(value or '')).encode('ascii', 'ignore').decode()
    return re.sub(r'[\s_-]+', ' ', text).strip().lower()


def slug(value):
    """Code dérivé d'un libellé : 'Services P2P' -> 'services_p2p'."""
    return re.sub(r'[^a-z0-9]+', '_', _norm(value)).strip('_') or None


_INDEX = {}


def _index(vocab):
    if vocab not in _INDEX:
        idx = {}
        for code, (fr, en, aliases) in TABLES[vocab].items():
            for v in (code, fr, en) + tuple(aliases):
                idx.setdefault(_norm(v), code)
        _INDEX[vocab] = idx
    return _INDEX[vocab]


def code(vocab, value):
    """
    Valeur (libellé FR / EN, valeur de matrice, code) -> code. Valeur vide ou
    marqueur d'absence : None. Vocabulaire fermé, valeur inconnue : None ;
    vocabulaire extensible : code dérivé du libellé (slug).
    """
    text = str(value if value is not None else '').strip()
    if not text or text.lower() in ('#n/a', 'n/a', 'nan', 'none', 'no data'):
        return None
    hit = _index(vocab).get(_norm(text))
    if hit or vocab in CLOSED:
        return hit
    return slug(text)


def label(vocab, code_value, lang='fr', fallback=None):
    """Code -> libellé dans la langue demandée ; fallback (ou le code) si inconnu."""
    entry = TABLES[vocab].get(code_value)
    if entry is None:
        return fallback if fallback is not None else code_value
    return entry[0] if lang == 'fr' else entry[1]


def rank(vocab, value):
    """
    Clé de départage : rang de la valeur dans l'ordre de référence du vocabulaire
    (pour les acteurs et motivations, l'ordre des matrices M1 / M2). Valeur sans
    code connu : après les autres, par ordre alphabétique de son code.
    """
    codes = list(TABLES[vocab])
    c = code(vocab, value) or ''
    return (codes.index(c) if c in codes else len(codes), c)


def unknown_values(vocab, values):
    """Valeurs sans code explicite dans un vocabulaire extensible (pour les tests)."""
    return sorted({v for v in values if str(v).strip() and _index(vocab).get(_norm(v)) is None})


_DURATION_RE = re.compile(r'^\s*(\d+)(?:\s*-\s*(\d+))?\s*(\w+)\s*$')


def duration(text):
    """'1-2 mois' -> {'min': 1, 'max': 2, 'unit': 'month'} ; forme inconnue -> None."""
    m = _DURATION_RE.match(str(text or ''))
    if not m:
        return None
    unit = code('duration_unit', m.group(3))
    if unit is None:
        return None
    low = int(m.group(1))
    return {'min': low, 'max': int(m.group(2) or low), 'unit': unit}
