#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modélisation des menaces : évalue les acteurs de la menace sur plusieurs
motivations, ne retient que les probabilités élevées (Very / Quite relevant) et
exporte le score final pondéré (secteur × taille × zone × note ASM) dans la
colonne Score_Acteur, utilisée par R1 pour classer les acteurs et fixer leur niveau.
"""

import csv
import os
import json
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
from datetime import datetime

def _load_asm_from_d1():
    """Note ASM calculée par D1, lue dans run_summary.json (dossier data/ courant).
    Renvoie 'Critical'/'High'/'Medium'/'Low', ou None si absent/invalide."""
    try:
        with open("run_summary.json", encoding="utf-8") as f:
            rating = json.load(f).get("criticality_rating")
        if rating in ("Critical", "High", "Medium", "Low"):
            return rating
    except Exception:
        return None
    return None


def get_user_inputs():
    """Collecte les 4 inputs utilisateur + options de filtrage"""

    # 1. Secteur d'activité
    secteurs = [
        "Finance", "Santé", "Gouvernement", "Énergie", "Défense",
        "E-commerce", "Éducation", "Télécoms", "Transport", "Industrie"
    ]
    print("1. SECTEUR D'ACTIVITÉ :")
    for i, secteur in enumerate(secteurs, 1):
        print(f"   {i}. {secteur}")

    while True:
        try:
            choix = int(input("\nVotre choix (1-10) : "))
            if 1 <= choix <= 10:
                secteur = secteurs[choix-1]
                break
            else:
                print("Veuillez choisir un nombre entre 1 et 10")
        except ValueError:
            print("Veuillez entrer un nombre valide")

    # 2. Taille d'entreprise
    tailles = ["TPE", "PME", "ETI", "Grande"]
    print(f"\n2. TAILLE D'ENTREPRISE :")
    for i, taille in enumerate(tailles, 1):
        print(f"   {i}. {taille}")

    while True:
        try:
            choix = int(input("\nVotre choix (1-4) : "))
            if 1 <= choix <= 4:
                taille = tailles[choix-1]
                break
            else:
                print("Veuillez choisir un nombre entre 1 et 4")
        except ValueError:
            print("Veuillez entrer un nombre valide")

    # 3. Zone géographique
    zones = [
        "Europe Ouest", "Europe Est", "Amérique Nord", "Amérique Sud",
        "Asie-Pacifique", "Moyen-Orient", "Afrique Nord", "Afrique Sub-saharienne"
    ]
    print(f"\n3. ZONE GÉOGRAPHIQUE :")
    for i, zone in enumerate(zones, 1):
        print(f"   {i}. {zone}")

    while True:
        try:
            choix = int(input("\nVotre choix (1-8) : "))
            if 1 <= choix <= 8:
                zone = zones[choix-1]
                break
            else:
                print("Veuillez choisir un nombre entre 1 et 8")
        except ValueError:
            print("Veuillez entrer un nombre valide")

    # 4. Note ASM : issue de D1 (run_summary.json) si disponible, sinon demandée.
    asm = _load_asm_from_d1()
    if asm:
        ModernUI.status(f"Note ASM (issue de D1) : {asm}", "info")
    else:
        asm_categories = [
            "Critical (9.0-10.0)",
            "High (6.0-8.9)",
            "Medium (3.0-5.9)",
            "Low (0.0-2.9)"
        ]
        print(f"\n4. NOTE ASM :")
        for i, cat in enumerate(asm_categories, 1):
            print(f"   {i}. {cat}")

        while True:
            try:
                choix = int(input("\nVotre choix (1-4) : "))
                if 1 <= choix <= 4:
                    asm = asm_categories[choix-1].split(" ")[0]  # Récupère "Critical", "High", etc.
                    break
                else:
                    print("Veuillez choisir un nombre entre 1 et 4")
            except ValueError:
                print("Veuillez entrer un nombre valide")

    return secteur, taille, zone, asm

def convert_to_score(value):
    """Convertit les valeurs qualitatives en scores numériques (0-5)"""
    conversion = {
        # Relevance levels
        "Very relevant": 5,
        "Quite relevant": 4,
        "Moderately relevant": 3,
        "Not really relevant": 2,
        "Not relevant": 0,

        # Motivation levels
        "High": 5,
        "Quite": 4,
        "Poor": 2,
        "Very low": 1,

        # Resource levels
        "Unlimited": 5,
        "Important": 4,
        "Significant": 3,
        "Limited": 2,

        # Ponderation levels
        "Très élevé": 5,
        "Très Élevé": 5,
        "Élevé": 4,
        "Moyen": 3,
        "Neutre": 3,
        "Faible": 2,
        "Très faible": 1,
        "Très Faible": 1,
        "Négligeable": 0
    }
    return conversion.get(value, 0)

_MATRIX_DIR = "Threat_matrices"  # sous-dossier de Parameters/


def _load_matrix(filename):
    """Charge une matrice 2D (ligne ; colonnes) de Parameters/Threat_matrices/ en dict imbriqué."""
    filepath = exposia_paths.parameter(_MATRIX_DIR, filename)
    with open(filepath, encoding="utf-8", newline="") as f:
        reader = csv.reader(f, delimiter=";")
        columns = next(reader)[1:]
        matrix = {}
        for row in reader:
            if not row or not row[0].strip():
                continue
            matrix[row[0]] = {col: val for col, val in zip(columns, row[1:])}
    return matrix


def get_matrices():
    """Charge les 7 matrices depuis Parameters/Threat_matrices/ (référentiel éditable, hors code)."""
    secteur_to_actor                    = _load_matrix("M1_secteur_to_actor.csv")
    actor_to_motivation                 = _load_matrix("M2_actor_to_motivation.csv")
    actor_motivation_to_resources       = _load_matrix("M3_actor_motivation_to_resources.csv")
    motivation_resources_to_probability = _load_matrix("M4_motivation_resources_to_probability.csv")
    asm_weighting                       = _load_matrix("M5_asm_weighting.csv")
    taille_weighting                    = _load_matrix("M6_taille_weighting.csv")
    zone_weighting                      = _load_matrix("M7_zone_weighting.csv")
    return (secteur_to_actor, actor_to_motivation, actor_motivation_to_resources,
            motivation_resources_to_probability, asm_weighting, taille_weighting, zone_weighting)


def filter_by_probability_level(motivations):
    """Filtre strict : conserve uniquement les motivations 'Very relevant' et 'Quite relevant'."""
    allowed_probs = ["Very relevant", "Quite relevant"]
    return [m for m in motivations if m['probability'] in allowed_probs]

def calculate_multi_motivation_threat(actor, base_score, matrices):
    """Calcule le score multi-motivations."""

    (secteur_to_actor, actor_to_motivation, actor_motivation_to_resources,
     motivation_resources_to_probability, asm_weighting, taille_weighting, zone_weighting) = matrices

    total_threat = 0
    motivation_details = []

    motivations = ["Espionnage", "Géopositionnement stratégique",
                  "Influence", "Entrave au fonctionnement", "Lucratif", "Défi, amusement"]

    for motivation in motivations:
        # Étape 2: Threat Actor → Motivation
        motivation_level = actor_to_motivation[actor][motivation]
        motivation_score = convert_to_score(motivation_level)

        # Étape 3: Threat Actor × Motivation → Ressources
        resources_level = actor_motivation_to_resources[actor][motivation]

        # Étape 4: Motivation × Ressources → Probabilité
        probability_level = motivation_resources_to_probability[motivation_level][resources_level]
        probability_score = convert_to_score(probability_level)

        # Score pour cette motivation spécifique
        individual_threat = base_score * motivation_score * probability_score

        # Accumulation de toutes les motivations
        total_threat += individual_threat

        motivation_details.append({
            'motivation': motivation,
            'level': motivation_level,
            'resources': resources_level,
            'probability': probability_level,
            'individual_score': individual_threat,
            'motivation_score': motivation_score,
            'probability_score': probability_score
        })

    # Tri des motivations par score décroissant
    motivation_details.sort(key=lambda x: x['individual_score'], reverse=True)

    return total_threat, motivation_details

def analyze_threats(secteur, taille, zone, asm):
    """Analyse les acteurs sur toutes leurs motivations, puis filtre par probabilité."""

    matrices = get_matrices()
    (secteur_to_actor, actor_to_motivation, actor_motivation_to_resources,
     motivation_resources_to_probability, asm_weighting, taille_weighting, zone_weighting) = matrices

    results = []
    filter_stats = {"total_motivations": 0, "filtered_motivations": 0, "excluded_by_weighting": 0}

    # Liste des threat actors
    threat_actors = ["Étatique", "Crime organisé", "Terroriste", "Activiste",
                    "Officine", "Amateur", "Vengeur", "Malveillant"]

    for actor in threat_actors:
        # Étape 1: Secteur → Threat Actor (relevance de base)
        base_relevance = secteur_to_actor[secteur][actor]
        base_score = convert_to_score(base_relevance)

        # Exclusion totale des "Not relevant"
        if base_relevance == "Not relevant":
            continue

        # Calcul multi-motivations
        total_threat, motivation_details = calculate_multi_motivation_threat(
            actor, base_score, matrices
        )

        # Filtrage par probabilité
        filter_stats["total_motivations"] += len(motivation_details)
        filtered_motivations = filter_by_probability_level(motivation_details)
        filter_stats["filtered_motivations"] += len(filtered_motivations)

        # Si aucune motivation ne passe le filtre, on exclut ce threat actor
        if not filtered_motivations:
            continue

        # Recalcul du score total basé sur les motivations filtrées
        filtered_total_threat = sum(m['individual_score'] for m in filtered_motivations)

        # Application des pondérations sur le score filtré
        asm_weight_raw = asm_weighting[asm][actor]
        taille_weight_raw = taille_weighting[actor][taille]
        zone_weight_raw = zone_weighting[actor][zone]

        asm_weight = convert_to_score(asm_weight_raw) / 3.0
        taille_weight = convert_to_score(taille_weight_raw) / 3.0
        zone_weight = convert_to_score(zone_weight_raw) / 3.0

        # Score final pondéré sur les motivations filtrées
        final_score = filtered_total_threat * asm_weight * taille_weight * zone_weight

        # Une pondération « Négligeable » (= 0) annule le score : l'acteur n'est
        # pas pertinent pour ce profil (taille / zone / exposition) et n'est pas
        # présenté dans le rapport.
        if final_score <= 0:
            filter_stats["excluded_by_weighting"] += 1
            continue

        # Profil de menace basé sur les motivations filtrées
        active_count = len(filtered_motivations)
        if active_count >= 4:
            threat_profile = "Multi-objectifs"
        elif active_count == 3:
            threat_profile = "Triple-menace"
        elif active_count == 2:
            threat_profile = "Dual-purpose"
        elif active_count == 1:
            threat_profile = "Ciblé"
        else:
            threat_profile = "Minimal"

        results.append({
            'actor': actor,
            'base_relevance': base_relevance,
            'base_score': base_score,
            'total_threat_score': total_threat,  # Score avant filtrage
            'filtered_threat_score': filtered_total_threat,  # Score après filtrage
            'final_score': final_score,
            'all_motivations': motivation_details,  # Toutes les motivations
            'filtered_motivations': filtered_motivations,  # Motivations après filtrage
            'motivation_count': len(filtered_motivations),
            'threat_profile': threat_profile,
            'primary_motivation': filtered_motivations[0]['motivation'] if filtered_motivations else "Aucune",
            'asm_weight_raw': asm_weight_raw,
            'taille_weight_raw': taille_weight_raw,
            'zone_weight_raw': zone_weight_raw,
            'asm_weight': asm_weight,
            'taille_weight': taille_weight,
            'zone_weight': zone_weight
        })

    # Tri par score final décroissant
    results.sort(key=lambda x: x['final_score'], reverse=True)

    return results, filter_stats

def export_to_csv(results, secteur, taille, zone, asm):
    """Exporte le CSV : une ligne par motivation retenue, avec le score final pondéré."""

    # Nom du fichier avec timestamp et niveau de filtrage
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threat_analysis_strict_{timestamp}.csv"

    # Headers : 5 colonnes descriptives + le score final pondéré de l'acteur
    # (répété sur chaque ligne de l'acteur). R1 s'en sert pour classer les
    # acteurs et fixer leur niveau ; un fichier sans cette colonne reste lisible.
    headers = [
        'Threat_Actor',
        'Motivation',
        'Niveau_Motivation_Matrice2',
        'Resources_Matrice3',
        'Probabilite_Occurrence_Matrice4',
        'Score_Acteur'
    ]

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, delimiter=';')

            # Écriture des en-têtes
            writer.writerow(headers)

            # Une ligne par motivation retenue
            total_rows = 0
            for result in results:

                # Pour chaque motivation filtrée de cet acteur
                for motivation_data in result['filtered_motivations']:

                    row = [
                        result['actor'],
                        motivation_data['motivation'],
                        motivation_data['level'],
                        motivation_data['resources'],
                        motivation_data['probability'],
                        f"{result['final_score']:.2f}"
                    ]
                    writer.writerow(row)
                    total_rows += 1

        ModernUI.status(f"Résultats exportés vers: {filename}", "success")
        return filename

    except Exception as e:
        ModernUI.status(f"Erreur lors de l'export CSV: {e}", "error")
        return None

def display_results(results, secteur, taille, zone, asm, filter_stats):
    """Affichage console minimal — le détail complet est dans le CSV généré."""
    if not results:
        ModernUI.status("Aucune menace significative identifiée avec ce niveau de filtrage.", "warning")
        ModernUI.status("Essayez un niveau de filtrage moins strict (modéré ou complet).", "info")
        return

    ModernUI.status(
        f"{len(results)} acteurs identifiés "
        f"(filtrage strict, "
        f"{filter_stats['filtered_motivations']}/{filter_stats['total_motivations']} motivations)",
        "success",
    )
    if filter_stats.get("excluded_by_weighting"):
        ModernUI.status(
            f"{filter_stats['excluded_by_weighting']} acteur(s) écarté(s) : pondération nulle "
            f"pour ce profil ({taille}, {zone}, ASM {asm})",
            "info",
        )

def main():
    """Point d'entrée : saisie du profil, analyse, affichage et export."""
    import argparse
    parser = argparse.ArgumentParser(
        description="Analyseur de menaces : produit threat_analysis_*.csv pour une campagne.")
    parser.add_argument("--domain", default=None,
                        help="Domaine de la campagne (le CSV ira dans Result/<domaine>/data/)")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (alternative à --domain)")
    args = parser.parse_args()

    try:
        # Écrire le CSV dans le dossier data/ de la campagne concernée.
        # L'analyse elle-même ne dépend pas du domaine (secteur/taille/zone/ASM),
        # mais son résultat appartient à la campagne et alimente R1.
        try:
            data_dir = exposia_paths.resolve_data_dir(args.result_dir, args.domain)
            os.chdir(data_dir)
        except FileNotFoundError as e:
            ModernUI.status(f"{e}", "warning")
            ModernUI.status("Le CSV sera écrit dans le répertoire courant.", "info")

        # Collecte des inputs utilisateur + niveau de filtrage
        secteur, taille, zone, asm = get_user_inputs()

        # Analyse des menaces avec nouvelle logique + filtrage
        results, filter_stats = analyze_threats(secteur, taille, zone, asm)

        # Résumé avec statistiques de filtrage
        display_results(results, secteur, taille, zone, asm, filter_stats)

        # Export vers CSV avec niveau de filtrage appliqué
        csv_filename = export_to_csv(results, secteur, taille, zone, asm)

        if not csv_filename:
            ModernUI.status("Analyse terminée mais problème lors de l'export CSV", "warning")

        # Ajout de la métrique D3 au récapitulatif du run (SUMMARY de fin de pipeline).
        try:
            _summary = {}
            if os.path.exists("run_summary.json"):
                with open("run_summary.json", encoding="utf-8") as _f:
                    _summary = json.load(_f)
            _summary["threat_actors"] = len(results)
            with open("run_summary.json", "w", encoding="utf-8") as _f:
                json.dump(_summary, _f, ensure_ascii=False)
        except Exception as _e:
            ModernUI.status(f"Mise à jour run_summary.json impossible : {_e}", "warning")

    except KeyboardInterrupt:
        print(f"\n\nAnalyse interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\nErreur lors de l'analyse: {e}")

if __name__ == "__main__":
    main()