#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modélisation des menaces : évalue les acteurs de la menace sur plusieurs
motivations, ne retient que les probabilités élevées (Very / Quite relevant) et
exporte le score final pondéré (secteur × taille × zone × note ASM) dans la
colonne Score_Acteur, utilisée par R1 pour classer les acteurs et fixer leur niveau.

Profil : --secteur, --taille, --zone (valeurs des matrices ou leur libellé
anglais, casse et accents indifférents, « _ » à la place des espaces) ; un champ absent est demandé au
clavier, et refusé sans terminal. Les valeurs acceptées figurent dans --help.
La note ASM n'est jamais saisie : c'est la criticité calculée par D1 (run_summary.json).
Codes de sortie : 0 succès, 1 erreur, 2 profil invalide ou note ASM absente.
"""

import csv
import os
import json
import re
import unicodedata
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
import exposia_events  # événements de progression (--events), sans effet sinon
import exposia_vocab as vocab  # libellés anglais des valeurs du profil (--secteur Healthcare…)
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


# ---------------------------------------------------------------------------
# Profil de l'organisation : secteur, taille, zone
# ---------------------------------------------------------------------------
# Les valeurs valides sont lues dans les matrices, seule source de vérité :
# secteurs = lignes de M1, tailles = colonnes de M6, zones = colonnes de M7.
# Ajouter un secteur dans M1 suffit pour qu'il soit proposé et accepté.

PROFILE_FIELDS = (
    # (clé, option CLI, libellé du menu)
    ("secteur", "--secteur", "SECTEUR D'ACTIVITÉ"),
    ("taille", "--taille", "TAILLE D'ENTREPRISE"),
    ("zone", "--zone", "ZONE GÉOGRAPHIQUE"),
)


class ProfileError(Exception):
    """Profil invalide ou incomplet en mode non interactif (code de sortie 2)."""


def profile_options():
    """Valeurs acceptées pour chaque champ du profil, dans l'ordre des matrices."""
    secteurs = list(_load_matrix("M1_secteur_to_actor.csv"))
    tailles = list(next(iter(_load_matrix("M6_taille_weighting.csv").values())))
    zones = list(next(iter(_load_matrix("M7_zone_weighting.csv").values())))
    return {"secteur": secteurs, "taille": tailles, "zone": zones}


def _norm(value):
    """Comparaison tolérante : sans casse, sans accents, espaces/tirets/_ équivalents."""
    text = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode()
    return re.sub(r"[\s_-]+", " ", text).strip().lower()


def cli_value(value):
    """Forme à taper en ligne de commande : espaces remplacées par « _ » (Europe_Ouest)."""
    return str(value).replace(" ", "_")


# Champ du profil -> vocabulaire (exposia_vocab) qui porte son libellé anglais.
PROFILE_VOCAB = {"secteur": "sector", "taille": "size", "zone": "zone"}


def match_option(field, value, options):
    """
    Valeur saisie -> valeur exacte de la matrice ; ProfileError si inconnue.
    Le libellé anglais d'une valeur est accepté aussi (Healthcare = Santé, SME = PME).
    """
    index = {}
    for o in options:
        code = vocab.code(PROFILE_VOCAB[field], o)
        index.setdefault(_norm(vocab.label(PROFILE_VOCAB[field], code, 'en', fallback=o)), o)
    index.update({_norm(o): o for o in options})
    hit = index.get(_norm(value))
    if hit is None:
        option = dict((k, o) for k, o, _ in PROFILE_FIELDS)[field]
        raise ProfileError(f"{option} {value!r} inconnu. Valeurs acceptées : "
                           f"{', '.join(cli_value(o) for o in options)}")
    return hit


def _ask(label, options, number):
    """Menu numéroté pour un champ (mode interactif)."""
    print(f"\n{number}. {label} :")
    for i, opt in enumerate(options, 1):
        print(f"   {i}. {opt}")
    while True:
        try:
            choix = int(input(f"\nVotre choix (1-{len(options)}) : "))
            if 1 <= choix <= len(options):
                return options[choix - 1]
            print(f"Veuillez choisir un nombre entre 1 et {len(options)}")
        except ValueError:
            print("Veuillez entrer un nombre valide")


def resolve_profile(secteur=None, taille=None, zone=None, interactive=None):
    """
    Profil (secteur, taille, zone) à partir des options, en demandant au clavier
    les seuls champs absents. Sans terminal (pipeline, Lucid, CI), un champ
    absent est une erreur : on ne reste jamais bloqué sur une saisie.
    """
    if interactive is None:
        interactive = _sys.stdin.isatty()
    options = profile_options()
    given = {"secteur": secteur, "taille": taille, "zone": zone}
    missing = [opt for key, opt, _ in PROFILE_FIELDS if not given[key]]
    if missing and not interactive:
        raise ProfileError(f"Profil incomplet, options manquantes : {', '.join(missing)} "
                           f"(valeurs : --help)")
    profile = {}
    for number, (key, _opt, label) in enumerate(PROFILE_FIELDS, 1):
        if given[key]:
            profile[key] = match_option(key, given[key], options[key])
        else:
            profile[key] = _ask(label, options[key], number)
    return profile["secteur"], profile["taille"], profile["zone"]


def validate_cli(argv):
    """
    Validation anticipée du profil passé en options, sans rien écrire ni rien
    demander : run_pipeline.sh l'appelle avant D1 pour qu'une faute de frappe
    n'échoue pas après la collecte. Renvoie 0 si valide, 2 sinon.
    """
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    for _key, opt, _label in PROFILE_FIELDS:
        parser.add_argument(opt, default=None)
    args, _ = parser.parse_known_args(argv)
    options = profile_options()
    try:
        for key, opt, _label in PROFILE_FIELDS:
            value = getattr(args, key)
            if value:
                match_option(key, value, options[key])
    except ProfileError as e:
        ModernUI.status(str(e), "error")
        return 2
    return 0


def get_asm():
    """
    Note ASM : la criticité calculée par D1 (run_summary.json). Elle n'est jamais
    saisie : sans elle, D3 s'arrête et demande de lancer D1.
    """
    asm = _load_asm_from_d1()
    if not asm:
        raise ProfileError("Note ASM absente (run_summary.json de D1) : lancez d'abord la découverte d'actifs (D1).")
    ModernUI.status(f"Note ASM (issue de D1) : {asm}", "info")
    return asm


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
    exposia_events.count('actors', len(results))
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

def main(argv=None):
    """Point d'entrée : profil, analyse, affichage et export. Code de sortie : 0, 1 (erreur), 2 (profil)."""
    import argparse
    import textwrap

    class _HelpFormatter(argparse.HelpFormatter):
        """Aide sans coupure aux traits d'union (Asie-Pacifique reste entier)."""
        def _split_lines(self, text, width):
            return textwrap.wrap(text, width, break_on_hyphens=False)

    parser = argparse.ArgumentParser(
        formatter_class=_HelpFormatter,
        description="Analyseur de menaces : produit threat_analysis_*.csv pour une campagne. "
                    "Sans --secteur, --taille ou --zone, le champ manquant est demandé au clavier. "
                    "Casse et accents indifférents ; « _ » à la place des espaces (Europe_Ouest).")
    parser.add_argument("--domain", default=None,
                        help="Domaine de la campagne (le CSV ira dans Result/<domaine>/data/)")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (alternative à --domain)")
    try:  # valeurs lues dans les matrices, affichées dans --help
        _opts = {k: ", ".join(cli_value(o) for o in v) for k, v in profile_options().items()}
    except (OSError, StopIteration):
        _opts = {k: "valeur d'une matrice de Parameters/Threat_matrices/" for k in ("secteur", "taille", "zone")}
    parser.add_argument("--secteur", default=None, help=f"Secteur d'activité : {_opts['secteur']}")
    parser.add_argument("--taille", default=None, help=f"Taille de l'organisation : {_opts['taille']}")
    parser.add_argument("--zone", default=None, help=f"Zone géographique : {_opts['zone']}")
    args = parser.parse_args(argv)

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

        # Note ASM de D1 d'abord (inutile de saisir un profil si elle manque),
        # puis profil : options, sinon saisie des seuls champs absents.
        asm = get_asm()
        secteur, taille, zone = resolve_profile(args.secteur, args.taille, args.zone)
        ModernUI.status(f"Profil : {secteur}, {taille}, {zone}", "info")

        # Analyse des menaces avec nouvelle logique + filtrage
        results, filter_stats = analyze_threats(secteur, taille, zone, asm)

        # Résumé avec statistiques de filtrage
        display_results(results, secteur, taille, zone, asm, filter_stats)

        # Export vers CSV avec niveau de filtrage appliqué
        csv_filename = export_to_csv(results, secteur, taille, zone, asm)

        if not csv_filename:
            ModernUI.status("Analyse terminée mais problème lors de l'export CSV", "warning")

        # Métrique D3 et profil déclaré dans le récapitulatif du run : le profil
        # n'était écrit nulle part, et le digest (R12) ne pouvait pas l'afficher.
        # La note ASM n'en fait pas partie : c'est criticality_rating, écrit par D1.
        try:
            _summary = {}
            if os.path.exists("run_summary.json"):
                with open("run_summary.json", encoding="utf-8") as _f:
                    _summary = json.load(_f)
            _summary["threat_actors"] = len(results)
            _summary["threat_profile"] = {"secteur": secteur, "taille": taille, "zone": zone}
            with open("run_summary.json", "w", encoding="utf-8") as _f:
                json.dump(_summary, _f, ensure_ascii=False)
        except Exception as _e:
            ModernUI.status(f"Mise à jour run_summary.json impossible : {_e}", "warning")
        return 0

    except ProfileError as e:
        ModernUI.status(str(e), "error")
        return 2
    except KeyboardInterrupt:
        print(f"\n\nAnalyse interrompue par l'utilisateur.")
        return 130
    except Exception as e:
        # Code d'erreur non nul : sans lui, le pipeline poursuivait et R1 lisait
        # le threat_analysis d'un run précédent.
        print(f"\nErreur lors de l'analyse: {e}")
        return 1

if __name__ == "__main__":
    _sys.exit(main())
