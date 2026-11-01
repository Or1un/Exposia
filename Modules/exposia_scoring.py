#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_scoring.py — Constantes de notation partagées (source unique).

Tout ce qui fixe une qualification ou un niveau vit ici : D1 calcule avec ces
valeurs, les modules R les affichent ou les expliquent avec ces mêmes valeurs.
Changer un poids ou un seuil se fait donc à un seul endroit, et le texte du
digest (R12) ou de la méthodologie suit automatiquement.

Module volontairement sans dépendance (ni pandas, ni réseau) : un module R peut
l'importer sans tirer les dépendances de D1.
"""

# --- Qualification d'une exposition (D1) -------------------------------------

# base = EPSS × w_epss + (CVSS / 10) × w_cvss + exp(−âge / TEMPORAL_DECAY_YEARS) × w_age
QUALIF_WEIGHTS = {'epss': 0.60, 'cvss': 0.25, 'age': 0.15}
TEMPORAL_DECAY_YEARS = 8.0      # constante de décroissance du facteur temporel
TEMPORAL_FLOOR = 0.05           # plancher du facteur temporel

# Multiplicateur appliqué à la base quand le service est connu (services_list.csv).
SERVICE_MULTIPLIERS = {'CRITIQUE': 1.3, 'HAUTE': 1.1, 'MOYENNE': 1.0, 'FAIBLE': 0.8}

# Seuils de qualification, du plus élevé au plus bas ; sous le dernier : Low.
QUALIF_THRESHOLDS = (('Critical', 0.75), ('High', 0.55), ('Medium', 0.35))

# Service connu sans CVE : qualification tirée de la seule criticité du service.
SERVICE_ONLY_QUALIF = {'CRITIQUE': 'Medium', 'HAUTE': 'Medium', 'MOYENNE': 'Low', 'FAIBLE': 'Low'}

# Plancher « exploit public » : (CVSS minimal, plancher), lus dans l'ordre ;
# un CVSS inconnu vaut 0. Une liste vide désactive le plancher.
EXPLOIT_FLOOR_RULES = ((7.0, 'High'), (0.0, 'Medium'))

QUALIFICATION_ORDER = ('Low', 'Medium', 'High', 'Critical')

# Plancher « EPSS » : une CVE absente du KEV mais dont la probabilité
# d'exploitation observée dépasse ce seuil est au moins High. Rattrape les CVE
# que le CVSS ou l'âge tirent vers le bas alors que l'activité est réelle.
EPSS_FLOOR = (0.10, 'High')    # (EPSS strictement supérieur à, plancher)

# Plancher « KEV » : une CVE inscrite au catalogue CISA des vulnérabilités
# exploitées est une urgence. Critical, sauf l'élévation de privilèges isolée :
# vecteur local ou physique, portée inchangée, sur un service non critique et
# sans autre porte d'entrée réseau sur le même hôte (High).
KEV_FLOOR_DEFAULT = 'Critical'
KEV_FLOOR_ISOLATED_LOCAL = 'High'
KEV_CRITICAL_SERVICE = 'CRITIQUE'   # criticité de services_list.csv


def raise_to(qualification, floor):
    """Relève une qualification à un plancher, sans jamais l'abaisser."""
    if floor not in QUALIFICATION_ORDER or qualification not in QUALIFICATION_ORDER:
        return qualification
    if QUALIFICATION_ORDER.index(qualification) < QUALIFICATION_ORDER.index(floor):
        return floor
    return qualification


def parse_cvss_vector(vector):
    """
    (vecteur d'attaque, portée) d'un vecteur CVSS v2 ou v3 :
    'CVSS:3.1/AV:L/…/S:C/…' -> ('L', 'C') ; v2 'AV:N/AC:L/Au:N/…' -> ('N', None).
    Valeurs absentes ou illisibles : None.
    """
    parts = {}
    for item in str(vector or '').split('/'):
        if ':' in item:
            key, value = item.split(':', 1)
            parts[key.strip()] = value.strip().upper()
    av = parts.get('AV')
    scope = parts.get('S')
    return (av if av in ('N', 'A', 'L', 'P') else None,
            scope if scope in ('U', 'C') else None)


def epss_floor(epss):
    """Plancher EPSS d'une CVE (None si le seuil n'est pas dépassé ou EPSS inconnu)."""
    threshold, level = EPSS_FLOOR
    try:
        return level if float(epss) > threshold else None
    except (TypeError, ValueError):
        return None


def kev_floor(vector, service_criticality, host_has_network_cve):
    """
    Plancher d'une CVE inscrite au KEV :
      • vecteur réseau ou adjacent (AV:N, AV:A)            -> Critical
      • portée modifiée (S:C) : évasion de conteneur, d'hyperviseur -> Critical
      • vecteur local ou physique sur un service CRITIQUE    -> Critical
      • vecteur local ou physique, une CVE de vecteur réseau
        exposée sur le même hôte (chaînage)                  -> Critical
      • autres cas (élévation de privilèges isolée)          -> High
    Vecteur inconnu : Critical (on ne relâche pas une urgence faute de donnée).
    """
    av, scope = parse_cvss_vector(vector)
    if av is None or av in ('N', 'A') or scope == 'C':
        return KEV_FLOOR_DEFAULT
    if str(service_criticality or '').strip().upper() == KEV_CRITICAL_SERVICE:
        return KEV_FLOOR_DEFAULT
    if host_has_network_cve:
        return KEV_FLOOR_DEFAULT
    return KEV_FLOOR_ISOLATED_LOCAL


def qualification_from_score(score):
    """Score final (plafonné à 1) -> Critical / High / Medium / Low."""
    for level, threshold in QUALIF_THRESHOLDS:
        if score >= threshold:
            return level
    return 'Low'


# --- Niveau d'un acteur de menace (R1, R12) ----------------------------------

# Seuils du score pondéré D3 (Score_Acteur). Calibrés sur la distribution de
# tous les profils possibles (10 secteurs × 4 tailles × 8 zones × 4 notes ASM) :
# CRITIQUE ≈ 13 % les plus élevés, ÉLEVÉ ≈ 20 % suivants, MODÉRÉ ≈ 30 % suivants.
ACTOR_SCORE_THRESHOLDS = {'critical': 300, 'high': 120, 'medium': 40}


def actor_level(score, thresholds=ACTOR_SCORE_THRESHOLDS):
    """Score_Acteur -> 'critical' / 'high' / 'medium' / 'low'."""
    if score >= thresholds['critical']:
        return 'critical'
    if score >= thresholds['high']:
        return 'high'
    if score >= thresholds['medium']:
        return 'medium'
    return 'low'
