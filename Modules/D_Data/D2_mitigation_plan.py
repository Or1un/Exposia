#!/usr/bin/env python3
"""
Matching entre la sortie ASM (asset_discovery_assessment.py) et les mesures de mitigation.
Consomme le format Exposia_*.csv (structure d'attaque unifiée) et enrichit
directement ce fichier avec les mesures de mitigation correspondantes.
"""

import pandas as pd
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
from collections import defaultdict
import sys
import math
import os
import glob


def _clean(value):
    """
    Normalise une valeur en chaîne nettoyée. Renvoie '' pour NaN/None.
    Évite les AttributeError quand pandas renvoie NaN (float) pour une cellule vide :
    `row.get(col, '')` ne protège que contre l'absence de clé, pas contre une valeur NaN.
    """
    if pd.isna(value):
        return ''
    return str(value).strip()


# Colonnes ajoutées par l'enrichissement mitigation (source unique de vérité,
# utilisée pour construire les lignes et pour le garde-fou d'idempotence).
MITIGATION_COLUMNS = [
    'mitigation_id', 'mitigation_category', 'technical_measure',
    'organizational_measure', 'mitigation_type', 'priority', 'frequency',
    'implementation_difficulty', 'implementation_duration', 'kpi',
]

# Socle CVE : mesure(s) toujours proposée(s) pour une ligne portant une CVE qui,
# après filtrage par qualification, n'aurait reçu aucune mesure (CVE qualifiée Low,
# ou CVE sans récit exploitable : vecteur CVSS v2 seul, données NVD absentes).
# Corriger une CVE, c'est d'abord mettre à jour le logiciel : MIT-VULN-001 est la
# mesure de gestion des correctifs de mitigation_measures.csv. Les identifiants
# absents du fichier sont ignorés (avertissement au chargement).
CVE_BASELINE_MITIGATION_IDS = ['MIT-VULN-001']

_NO_CVE_VALUES = ('', '#N/A', 'None', 'No data', 'nan', 'NaN')


def _has_cve(row):
    """Vrai si la ligne porte une CVE (ligne de type CVE, pas un scénario PORT)."""
    return _clean(row.get('cve', '')) not in _NO_CVE_VALUES


def load_mitigation_measures(filepath):
    """
    Charge le fichier des mesures de mitigation
    """
    try:
        df = pd.read_csv(filepath, delimiter=';', encoding='utf-8')
        return df
    except FileNotFoundError:
        ModernUI.status(f"Fichier non trouvé: {filepath}", "error")
        return None
    except Exception as e:
        ModernUI.status(f"Erreur lors du chargement des mesures de mitigation: {e}", "error")
        return None

def find_exposia_output():
    """
    Trouve automatiquement le fichier de sortie Exposia (format: Exposia_*.csv)
    """
    pattern = "Exposia_*.csv"
    files = glob.glob(pattern)

    if not files:
        ModernUI.status(f"Aucun fichier trouvé avec le pattern '{pattern}'", "warning")
        return None
    elif len(files) == 1:
        return files[0]
    else:
        # Trier par date de modification et prendre le plus récent
        latest_file = max(files, key=os.path.getmtime)
        return latest_file

def load_asm_output(filepath=None):
    """
    Charge le fichier output ASM (asset_discovery_assessment.py) avec adaptation automatique des colonnes
    """
    if filepath is None:
        filepath = find_exposia_output()
        if filepath is None:
            return None, None

    try:
        # Forcer le type texte sur l'année CVE et sur le port pour éviter la promotion
        # en float (colonne entière + valeurs manquantes -> float64 -> "2019.0",
        # "443.0"). Les deux libellés couvrent le fichier brut (D1) comme un fichier
        # déjà enrichi.
        df = pd.read_csv(
            filepath, delimiter=';', encoding='utf-8',
            dtype={'CVE - Year': str, 'cve_year': str, 'Port': str, 'port': str}
        )

        # Mapping des colonnes Exposia vers un format interne normalisé
        column_mapping = {
            'Domain': 'domain',
            'Subdomain': 'subdomain',
            'IP Address': 'ip_address',
            'Port': 'port',
            'Internal_External_Classification': 'classification',
            'Service': 'service',
            'Catégorie': 'category',
            'Vulnerability (CVE)': 'cve',
            'Number of Exploits': 'exploits_count',
            'Exploits': 'exploit_references',
            'CVE - Year': 'cve_year',
            'CVSS Score': 'cvss_score',
            'EPSS Score': 'epss_score',
            'Impact business / opérationnel': 'business_impact',
            'Exposia - Qualification': 'exposia_qualification',
            'CVSS_Version': 'cvss_version',
            'CVSS_Vector': 'cvss_vector',
            'Tags': 'tags',
            'Attack_Path_Type': 'attack_path_type',
            'Reconnaissance': 'reconnaissance',
            'Exploitation': 'exploitation',
            'Impact': 'impact',
            'Hosting': 'hosting'
        }

        # Renommer les colonnes présentes
        existing_columns = {k: v for k, v in column_mapping.items() if k in df.columns}
        df = df.rename(columns=existing_columns)


        return df, filepath

    except FileNotFoundError:
        ModernUI.status(f"Fichier non trouvé: {filepath}", "error")
        return None, None
    except Exception as e:
        ModernUI.status(f"Erreur lors du chargement de l'output ASM: {e}", "error")
        return None, None

def create_mitigation_index(df_mitigation):
    """
    Crée un index des mesures de mitigation par tag
    """
    mitigation_index = defaultdict(list)

    for _, row in df_mitigation.iterrows():
        tag = _clean(row.get('Tag Attack Path', ''))
        if tag:
            mitigation_index[tag].append(row.to_dict())

    return dict(mitigation_index)

def load_cve_baseline(df_mitigation, baseline_ids=CVE_BASELINE_MITIGATION_IDS):
    """
    Mesures du socle CVE, dans l'ordre de baseline_ids. Un identifiant absent de
    mitigation_measures.csv est signalé puis ignoré (le socle peut être vide).
    """
    by_id = {}
    for _, row in df_mitigation.iterrows():
        mid = _clean(row.get('ID Mitigation', ''))
        if mid and mid not in by_id:
            by_id[mid] = row.to_dict()

    baseline = []
    for mid in baseline_ids:
        if mid in by_id:
            baseline.append(by_id[mid])
        else:
            ModernUI.status(f"Socle CVE : mesure {mid} absente de mitigation_measures.csv - ignorée", "warning")
    return baseline

def parse_tags(tags_string):
    """
    Parse la chaîne de tags séparés par des virgules
    Amélioration: gère aussi les tags vides et les espaces
    """
    if pd.isna(tags_string) or not tags_string or tags_string == '#N/A':
        return []
    return [tag.strip() for tag in str(tags_string).split(',') if tag.strip() and tag.strip() != '#N/A']

def determine_degradation_levels(df_asm):
    """
    Niveau de traitement appliqué à chaque qualification Exposia.

    Règle ABSOLUE : une vulnérabilité est traitée selon sa propre qualification
    (Critical -> Critical, High -> High, ...). L'ancienne règle relative promouvait
    le niveau le plus élevé présent au rang « Critical » : un périmètre propre
    (pire niveau Medium ou Low) recevait alors des mesures CRITIQUE et le rapport
    dramatisait un bon résultat.

    Socle minimal : si le périmètre ne présente que du Low, ces expositions sont
    traitées comme Medium (mesures préventives CRITIQUE / HAUTE uniquement), pour
    que le rapport de sensibilisation propose tout de même quelques bonnes
    pratiques, sans surenchère.
    """
    levels_present = set(df_asm['exposia_qualification'].dropna().astype(str).str.strip())

    degradation_mapping = {level: level for level in ('Critical', 'High', 'Medium', 'Low')}

    if not levels_present & {'Critical', 'High', 'Medium'}:
        degradation_mapping['Low'] = 'Medium'

    return degradation_mapping

def filter_mitigations_by_criticality_with_degradation(mitigations, original_level, degradation_mapping):
    """
    Filtre les mesures selon le niveau de traitement après dégradation
    """
    # Obtenir le niveau de traitement effectif
    treatment_level = degradation_mapping.get(original_level, original_level)

    # Définir les règles de filtrage par niveau de traitement
    treatment_rules = {
        'Critical': {
            'priorities': ['CRITIQUE', 'HAUTE', 'MOYENNE', 'FAIBLE'],
            'types': ['Préventif', 'Détectif', 'Curatif']
        },
        'High': {
            'priorities': ['CRITIQUE', 'HAUTE'],
            'types': ['Préventif', 'Détectif']  # Préventif + une mesure Détectif prioritaire
        },
        'Medium': {
            'priorities': ['CRITIQUE', 'HAUTE'],
            'types': ['Préventif']  # Préventif uniquement
        },
        'Low': {
            'priorities': [],
            'types': []  # Aucune mesure
        }
    }

    # Si le niveau de traitement n'est pas reconnu, retourner une liste vide
    if treatment_level not in treatment_rules:
        return []

    rules = treatment_rules[treatment_level]

    # Si aucune priorité autorisée (cas Low), retourner liste vide
    if not rules['priorities']:
        return []

    # Filtrer par priorité et type
    filtered = []
    for mitigation in mitigations:
        priority = _clean(mitigation.get('Priorité', ''))
        mitigation_type = _clean(mitigation.get('Type', ''))

        if priority in rules['priorities'] and mitigation_type in rules['types']:
            filtered.append(mitigation)

    # Pour High level: limiter à une mesure Détectif prioritaire
    if treatment_level == 'High':
        preventive = [m for m in filtered if _clean(m.get('Type', '')) == 'Préventif']
        detective = [m for m in filtered if _clean(m.get('Type', '')) == 'Détectif']

        # Garder toutes les préventives + une seule détective (la plus prioritaire)
        if detective:
            # Trier par priorité (CRITIQUE en premier). Lookup sûr : une priorité
            # inattendue est reléguée en fin de liste au lieu de lever ValueError.
            priority_order = ['CRITIQUE', 'HAUTE', 'MOYENNE', 'FAIBLE']

            def _priority_rank(m):
                p = _clean(m.get('Priorité', ''))
                return priority_order.index(p) if p in priority_order else len(priority_order)

            detective_sorted = sorted(detective, key=_priority_rank)
            detective = [detective_sorted[0]]  # Garder seulement la première

        filtered = preventive + detective

    return filtered

def enrich_input_file_with_mitigations(df_asm, mitigation_index, original_filepath, cve_baseline=None):
    """
    Enrichit directement le fichier input avec les mesures de mitigation.
    Format explosé : 1 vulnérabilité avec N mitigations = N lignes.

    Socle CVE : une ligne portant une CVE ne reste jamais sans mesure. Si le
    filtrage par qualification n'en retient aucune (CVE Low, ou CVE sans tags),
    les mesures de cve_baseline (mise à jour du logiciel) lui sont associées.

    Idempotent : si le fichier a déjà été enrichi (colonnes mitigation_*),
    ces colonnes sont retirées et les lignes de base reconstituées avant
    ré-enrichissement, pour éviter que l'explosion se compose sur elle-même.
    """
    cve_baseline = cve_baseline or []

    # Garde-fou anti-double-exécution : réinitialiser un fichier déjà enrichi.
    existing_mit_cols = [c for c in MITIGATION_COLUMNS if c in df_asm.columns]
    if existing_mit_cols:
        df_asm = df_asm.drop(columns=existing_mit_cols).drop_duplicates().reset_index(drop=True)

    # Déterminer le mapping de dégradation basé sur les niveaux présents
    degradation_mapping = determine_degradation_levels(df_asm)

    enriched_results = []
    baseline_applied = 0

    for _, vuln in df_asm.iterrows():
        # Parser les tags
        tags = parse_tags(vuln.get('tags', ''))
        matched_mitigations = []

        # Trouver toutes les mesures correspondant aux tags
        for tag in tags:
            if tag in mitigation_index:
                matched_mitigations.extend(mitigation_index[tag])

        # Filtrer selon la criticité avec dégradation
        exposia_qual = _clean(vuln.get('exposia_qualification', ''))
        filtered_mitigations = filter_mitigations_by_criticality_with_degradation(
            matched_mitigations, exposia_qual, degradation_mapping
        )

        # Socle CVE : aucune mesure retenue pour une ligne qui porte une CVE.
        if not filtered_mitigations and cve_baseline and _has_cve(vuln):
            filtered_mitigations = list(cve_baseline)
            baseline_applied += 1

        # DÉDOUBLONNAGE : Garder seulement une occurrence par ID de mesure
        seen_mitigation_ids = set()
        unique_mitigations = []
        for mitigation in filtered_mitigations:
            mitigation_id = mitigation.get('ID Mitigation', '')
            if mitigation_id and mitigation_id not in seen_mitigation_ids:
                seen_mitigation_ids.add(mitigation_id)
                unique_mitigations.append(mitigation)

        # Créer les lignes enrichies (format explosé)
        if unique_mitigations:
            # Une ligne par mesure de mitigation unique
            for mitigation in unique_mitigations:
                enriched_row = vuln.to_dict()  # Garder toutes les colonnes originales

                # Ajouter les colonnes de mitigation (SANS les 4 colonnes indésirables)
                enriched_row.update({
                    'mitigation_id': mitigation.get('ID Mitigation', ''),
                    'mitigation_category': mitigation.get('Catégorie', ''),
                    'technical_measure': mitigation.get('Mesure Technique', ''),
                    'organizational_measure': mitigation.get('Mesure Organisationnelle', ''),
                    'mitigation_type': mitigation.get('Type', ''),
                    'priority': mitigation.get('Priorité', ''),
                    'frequency': mitigation.get('Fréquence', ''),
                    'implementation_difficulty': mitigation.get('Difficulté_implémentation', ''),
                    'implementation_duration': mitigation.get('Durée_implémentation_indicatif', ''),
                    'kpi': mitigation.get('KPI_Principal', '')
                })
                enriched_results.append(enriched_row)
        else:
            # Ligne sans mesures de mitigation (colonnes vides)
            enriched_row = vuln.to_dict()  # Garder toutes les colonnes originales
            enriched_row.update({
                'mitigation_id': '',
                'mitigation_category': '',
                'technical_measure': '',
                'organizational_measure': '',
                'mitigation_type': '',
                'priority': '',
                'frequency': '',
                'implementation_difficulty': '',
                'implementation_duration': '',
                'kpi': ''
            })
            enriched_results.append(enriched_row)

    if baseline_applied:
        ModernUI.status(f"Socle CVE appliqué à {baseline_applied} ligne(s) sans autre mesure", "info")

    # Sauvegarder le fichier enrichi (écrase l'original)
    try:
        df_enriched = pd.DataFrame(enriched_results)
        df_enriched.to_csv(original_filepath, sep=';', index=False, encoding='utf-8')

        return enriched_results

    except Exception as e:
        ModernUI.status(f"Erreur lors de la sauvegarde du fichier enrichi: {e}", "error")
        return None

def exposure_key(result):
    """
    Clé d'une exposition distincte : (sous-domaine, port, CVE). L'IP n'en fait
    pas partie : un sous-domaine servi par plusieurs adresses (CDN, round-robin
    DNS) reste une seule exposition. Les valeurs absentes sont normalisées.
    """
    def norm(value):
        v = _clean(value)
        return '' if v in _NO_CVE_VALUES else v
    return (norm(result.get('subdomain', '')), norm(result.get('port', '')), norm(result.get('cve', '')))

def calculate_risk_score(exposia_qualification):
    """
    Calcule le score de risque basé sur la qualification Exposia
    """
    risk_mapping = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }
    return risk_mapping.get(_clean(exposia_qualification), 1)

def calculate_efficacy_score(priority):
    """
    Calcule le score d'efficacité basé sur la priorité de la mesure
    """
    efficacy_mapping = {
        'CRITIQUE': 4,
        'HAUTE': 3,
        'MOYENNE': 2,
        'FAIBLE': 1
    }
    return efficacy_mapping.get(_clean(priority), 1)

def calculate_feasibility_score(implementation_difficulty):
    """
    Calcule le score de faisabilité basé sur la difficulté d'implémentation
    """
    feasibility_mapping = {
        'Faible': 4,
        'Moyen': 3,
        'Élevé': 2,
        'Très Élevé': 1
    }
    return feasibility_mapping.get(_clean(implementation_difficulty), 1)

def calculate_composite_score(exposia_qual, priority, difficulty):
    """
    Calcule le score composite pour une mesure sur une vulnérabilité donnée
    """
    risk_score = calculate_risk_score(exposia_qual)
    efficacy_score = calculate_efficacy_score(priority)
    feasibility_score = calculate_feasibility_score(difficulty)

    return risk_score * efficacy_score * feasibility_score

def analyze_mitigation_impact(results):
    """
    Analyse l'impact transversal des mesures de mitigation
    Prend en compte les données enrichies de la sortie Exposia.
    """

    # Grouper par mesure de mitigation
    mitigation_analysis = defaultdict(list)

    for result in results:
        if result['mitigation_id']:  # Seulement les résultats avec des mesures
            # Calculer le score composite pour cette vulnérabilité
            composite_score = calculate_composite_score(
                result['exposia_qualification'],
                result['priority'],
                result['implementation_difficulty']
            )

            mitigation_analysis[result['mitigation_id']].append({
                'exposure_key': exposure_key(result),
                'cve': result['cve'],
                'domain': result['domain'],
                'classification': result['classification'],
                'business_impact': result['business_impact'],
                'exposia_qual': result['exposia_qualification'],
                'cvss_score': result['cvss_score'],
                'composite_score': composite_score,
                'priority': result['priority'],
                'difficulty': result['implementation_difficulty'],
                'category': result['mitigation_category'],
                'technical_measure': result['technical_measure'],
                'organizational_measure': result['organizational_measure'],
                'mitigation_type': result['mitigation_type'],
                'frequency': result['frequency'],
                'implementation_duration': result['implementation_duration'],
                'kpi': result['kpi'],
                'attack_path_type': result['attack_path_type'],
                'has_attack_narrative': result['attack_path_type'] != 'FALLBACK'  # Dérivé du type
            })

    # Calculer les scores finaux pour chaque mesure
    mitigation_scores = []

    for mitigation_id, vulnerability_list in mitigation_analysis.items():
        if not vulnerability_list:
            continue

        # Expositions DISTINCTES traitées par la mesure : une exposition est un
        # couple (sous-domaine, port, CVE). Les lignes du fichier explosé (une par
        # récit, une par IP d'un même sous-domaine) ne comptent plus chacune :
        # sinon le volume (CDN, round-robin DNS, récits multiples) faisait le
        # classement. Pour chaque exposition, on retient son composite le plus élevé.
        exposures = {}
        for v in vulnerability_list:
            k = v['exposure_key']
            exposures[k] = max(exposures.get(k, 0), v['composite_score'])

        # Niveau de la mesure = l'exposition la plus grave qu'elle traite. La
        # moyenne diluait une mesure traitant une CVE critique parmi de nombreuses
        # expositions mineures, et favorisait une mesure générique appliquée à
        # beaucoup d'expositions moyennes. La couverture départage via impact_factor.
        avg_score = max(exposures.values())

        # Facteur de couverture : nombre d'expositions distinctes traitées
        impact_factor = math.log(1 + len(exposures))

        # Bonus pour diversité des types d'attaque
        attack_types = set(v['attack_path_type'] for v in vulnerability_list)
        diversity_bonus = 1 + (len(attack_types) - 1) * 0.1  # 10% bonus par type supplémentaire

        # Services présumés sensibles (classification « Internal ») : décompte
        # conservé pour information, mais SANS bonus de score. La classification
        # est une présomption (port / service / mot-clé), pas un constat : elle ne
        # doit pas modifier l'ordre des mesures.
        internal_count = sum(1 for v in vulnerability_list if v['classification'] == 'Internal')
        internal_bonus = 1.0

        # Score final avec facteurs enrichis
        final_score = avg_score * impact_factor * diversity_bonus * internal_bonus

        # Prendre les données de la première occurrence pour les métadonnées
        first_occurrence = vulnerability_list[0]

        # CVE RÉELLEMENT traités par la mesure, dédoublonnés : une même paire
        # (mesure, CVE) apparaît plusieurs fois dans vulnerability_list à cause de
        # l'explosion narratifs/expositions. cve_count = nombre de CVE DISTINCTS.
        # Le scoring (avg_score, impact_factor) porte, lui, sur les expositions
        # distinctes (voir plus haut).
        treated_cves_unique = sorted({
            str(v['cve']).strip() for v in vulnerability_list
            if pd.notna(v['cve']) and str(v['cve']).strip() not in ('', '#N/A', 'nan', 'NaN')
        })

        mitigation_scores.append({
            'mitigation_id': mitigation_id,
            'cve_count': len(treated_cves_unique),
            'exposure_count': len(exposures),
            # Nom de colonne conservé pour compatibilité : contient désormais le
            # composite MAXIMAL sur les expositions traitées, plus une moyenne.
            'avg_composite_score': round(avg_score, 2),
            'impact_factor': round(impact_factor, 2),
            'diversity_bonus': round(diversity_bonus, 2),
            'internal_bonus': round(internal_bonus, 2),
            'final_score': round(final_score, 2),
            'internal_vulnerabilities': internal_count,
            'attack_types_covered': list(attack_types),
            'treated_cves': treated_cves_unique,
            'category': first_occurrence['category'],
            'technical_measure': first_occurrence['technical_measure'],
            'organizational_measure': first_occurrence['organizational_measure'],
            'priority': first_occurrence['priority'],
            'implementation_difficulty': first_occurrence['difficulty'],
            'implementation_duration': first_occurrence['implementation_duration'],
            'frequency': first_occurrence['frequency'],
            'mitigation_type': first_occurrence['mitigation_type'],
            'kpi': first_occurrence['kpi'],
            'vulnerability_details': vulnerability_list
        })

    # Trier par score final décroissant
    mitigation_scores.sort(key=lambda x: x['final_score'], reverse=True)


    return mitigation_scores

def save_prioritization_to_csv(mitigation_scores, output_file):
    """
    Sauvegarde l'analyse de priorisation dans un fichier CSV
    Colonnes enrichies avec les données Exposia.
    """
    # Préparer les données pour le CSV
    prioritization_data = []

    for measure in mitigation_scores:
        row = {
            'mitigation_id': measure['mitigation_id'],
            'final_score': measure['final_score'],
            'cve_count': measure['cve_count'],
            'exposure_count': measure['exposure_count'],
            'internal_vulnerabilities': measure['internal_vulnerabilities'],
            'avg_composite_score': measure['avg_composite_score'],
            'impact_factor': measure['impact_factor'],
            'diversity_bonus': measure['diversity_bonus'],
            'internal_bonus': measure['internal_bonus'],
            'attack_types_covered': ', '.join(measure['attack_types_covered']),
            'category': measure['category'],
            'technical_measure': measure['technical_measure'],
            'organizational_measure': measure['organizational_measure'],
            'priority': measure['priority'],
            'implementation_difficulty': measure['implementation_difficulty'],
            'implementation_duration': measure['implementation_duration'],
            'frequency': measure['frequency'],
            'mitigation_type': measure['mitigation_type'],
            'kpi': measure['kpi'],
            'treated_cves': ', '.join(measure['treated_cves'])
        }
        prioritization_data.append(row)

    try:
        df_prioritization = pd.DataFrame(prioritization_data)
        df_prioritization.to_csv(output_file, sep=';', index=False, encoding='utf-8')
    except Exception as e:
        ModernUI.status(f"Erreur lors de la sauvegarde de l'analyse: {e}", "error")

def main():
    """
    Fonction principale - Version modifiée pour enrichissement direct du fichier input
    """
    import argparse
    parser = argparse.ArgumentParser(
        description="Enrichit le CSV Exposia avec les mesures de mitigation.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("--domain", default=None,
                        help="Domaine analysé (alternative à --result-dir)")
    args = parser.parse_args()


    # Se placer dans le dossier data/ de la campagne : les lectures/écritures
    # relatives (Exposia_*.csv, priorisation) y sont alors résolues.
    data_dir = exposia_paths.resolve_data_dir(args.result_dir, args.domain)
    os.chdir(data_dir)

    # Configuration des chemins de fichiers
    mitigation_file = exposia_paths.parameter("mitigation_measures.csv")
    prioritization_file = "mitigation_prioritization_enhanced.csv"

    # Chargement des données
    df_mitigation = load_mitigation_measures(mitigation_file)
    if df_mitigation is None:
        sys.exit(1)

    # Auto-détection du fichier Exposia
    df_asm, original_filepath = load_asm_output()  # Récupérer aussi le chemin original
    if df_asm is None or original_filepath is None:
        ModernUI.status("Conseil: Exécutez d'abord asset_discovery_assessment.py pour générer un fichier Exposia_*.csv", "info")
        sys.exit(1)

    # Création de l'index et enrichissement direct du fichier input
    mitigation_index = create_mitigation_index(df_mitigation)
    cve_baseline = load_cve_baseline(df_mitigation)
    enriched_results = enrich_input_file_with_mitigations(
        df_asm, mitigation_index, original_filepath, cve_baseline=cve_baseline)

    if enriched_results is None:
        ModernUI.status("Erreur lors de l'enrichissement du fichier input", "error")
        sys.exit(1)

    # Analyse de priorisation enrichie (uniquement le fichier de priorisation)
    mitigation_scores = analyze_mitigation_impact(enriched_results)

    # Sauvegarde de l'analyse de priorisation
    save_prioritization_to_csv(mitigation_scores, prioritization_file)

    # Ajout de la métrique D2 au récapitulatif du run (SUMMARY de fin de pipeline).
    try:
        import json
        _summary = {}
        if os.path.exists("run_summary.json"):
            with open("run_summary.json", encoding="utf-8") as _f:
                _summary = json.load(_f)
        _summary["mitigation_measures"] = len(mitigation_scores)
        with open("run_summary.json", "w", encoding="utf-8") as _f:
            json.dump(_summary, _f, ensure_ascii=False)
    except Exception as _e:
        ModernUI.status(f"Mise à jour run_summary.json impossible : {_e}", "warning")

    ModernUI.status("Enrichissement et analyse terminés avec succès!", "success")
    ModernUI.status(f"Fichier input enrichi: {original_filepath}", "info")
    ModernUI.status(f"Analyse de priorisation: {prioritization_file}", "info")

if __name__ == "__main__":
    main()