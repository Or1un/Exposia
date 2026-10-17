#!/usr/bin/env python3
"""
Assemblage automatique de fichiers PDF.
Fusionne plusieurs fichiers PDF selon des patterns spécifiques dans un ordre défini.

Non-destructif par défaut : les PDF sources sont CONSERVÉS après l'assemblage.
Utilisez --clean pour les supprimer explicitement (le pipeline redevient rejouable).

Numérotation : « Page X sur Y » en bas à droite (page de garde et quatrième de
               couverture exclues).
Sommaire     : page dédiée insérée après l'avant-propos (R11), numéros de page
               calculés sur les pages réellement assemblées, entrées cliquables,
               et signets PDF (panneau de navigation du lecteur).

VERSION NON-INTERACTIVE pour intégration dans pipelines automatisés.
"""

import os
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
import sys
import glob
import re
import shutil
import argparse
from datetime import datetime
from pathlib import Path

try:
    from pypdf import PdfReader, PdfWriter
except ImportError:
    print("Erreur : pypdf n'est pas installé.")
    print("Installez-le avec : pip install pypdf")
    sys.exit(1)

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    import io
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Info : ReportLab n'est pas installé. La renumérotation des pages ne sera pas disponible.")
    print("Pour l'installer : pip install reportlab")

def trouver_fichiers_pdf(pattern_base, dossier="Data"):
    """
    Trouve tous les fichiers correspondant au pattern dans le dossier spécifié

    Args:
        pattern_base: Base du pattern de recherche (ex: "rapport")
        dossier: Dossier de recherche (par défaut: dossier 'Data')

    Returns:
        Liste des chemins de fichiers trouvés, triés par date (plus récent en premier)
    """
    pattern = os.path.join(dossier, f"{pattern_base}*.pdf")
    fichiers = glob.glob(pattern)

    # Trier par date de modification (plus récent en premier)
    fichiers_tries = sorted(fichiers, key=lambda x: os.path.getmtime(x), reverse=True)

    return fichiers_tries

def ajouter_numeros_pages(fichier_pdf, fichier_sortie_numerote, sans_numero_derniere=False):
    """
    Ajoute une numérotation continue des pages à un PDF assemblé
    Format : "Page X sur Y" en bas à droite
    La première page (page de garde) n'est PAS numérotée

    Args:
        fichier_pdf: Chemin du fichier PDF à numéroter
        fichier_sortie_numerote: Chemin du fichier de sortie avec numérotation
        sans_numero_derniere: True si la dernière page est une quatrième de couverture

    Returns:
        True si succès, False sinon
    """
    if not REPORTLAB_AVAILABLE:
        ModernUI.status("ReportLab non disponible - PDF créé sans numérotation", "warning")
        return False

    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        import io

        # Lire le PDF existant
        reader = PdfReader(fichier_pdf)
        writer = PdfWriter()
        total_pages = len(reader.pages)

        # Police Inter (charte Exposia) pour la numérotation, sinon Helvetica.
        font_name = "Helvetica"
        try:
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            _here = os.path.dirname(os.path.abspath(__file__))
            _fpath = os.path.join(os.path.dirname(os.path.dirname(_here)),
                                  "Parameters", "branding", "fonts", "Inter-Medium.ttf")
            if os.path.exists(_fpath):
                pdfmetrics.registerFont(TTFont("InterExposia", _fpath))
                font_name = "InterExposia"
        except Exception:
            pass
        from reportlab.lib.colors import HexColor

        calques = []
        for page_num in range(total_pages):
            page = reader.pages[page_num]
            numero_affiche = page_num + 1  # Numéro de page réel (1-indexed)

            # Page de garde (et quatrième de couverture le cas échéant) : pas de numéro
            if page_num == 0 or (sans_numero_derniere and page_num == total_pages - 1):
                writer.add_page(page)
                continue

            # Pour les autres pages : numérotation en bas à droite (charte Exposia)
            page_width = float(page.mediabox.width)
            page_height = float(page.mediabox.height)

            packet = io.BytesIO()
            can = canvas.Canvas(packet, pagesize=(page_width, page_height))

            text = f"Page {numero_affiche} sur {total_pages}"
            can.setFont(font_name, 8)
            can.setFillColor(HexColor("#8A90AC"))  # gris-indigo atténué

            # Aligné à droite sur la marge de contenu (18 mm), à ~12 mm du bas
            mm = 72.0 / 25.4
            x_right = page_width - 18 * mm
            y_position = 12 * mm

            can.drawRightString(x_right, y_position, text)
            can.save()

            # Revenir au début du buffer
            packet.seek(0)

            # Créer un nouveau PDF avec le numéro
            new_pdf = PdfReader(packet)
            calques.append(new_pdf)  # gardé en vie jusqu'à l'écriture (cf. assembler_pdfs)

            # Fusionner avec la page existante
            page.merge_page(new_pdf.pages[0])
            writer.add_page(page)

        # Écrire le PDF final avec numérotation
        with open(fichier_sortie_numerote, 'wb') as output_file:
            writer.write(output_file)

        return True

    except Exception as e:
        ModernUI.status(f"Erreur lors de la numérotation : {e}", "error")
        import traceback
        traceback.print_exc()
        return False

def extraire_timestamp(nom_fichier):
    """
    Extrait le timestamp d'un nom de fichier

    Args:
        nom_fichier: Nom du fichier

    Returns:
        Timestamp ou None si pas trouvé
    """
    match = re.search(r'(\d{8}_\d{6})', nom_fichier)
    if match:
        return match.group(1)
    return None

def selectionner_fichiers_uniques(fichiers):
    """
    Sélectionne le fichier le plus récent pour chaque type

    Args:
        fichiers: Liste des fichiers trouvés

    Returns:
        Liste avec un seul fichier (le plus récent) ou tous si pas de timestamp
    """
    if not fichiers:
        return []

    # Si un seul fichier ou aucun timestamp, retourner tel quel
    if len(fichiers) == 1:
        return fichiers

    # Vérifier s'il y a des timestamps
    fichiers_avec_timestamp = [f for f in fichiers if extraire_timestamp(f)]

    if fichiers_avec_timestamp:
        # Retourner le plus récent (déjà trié)
        return [fichiers_avec_timestamp[0]]
    else:
        # Pas de timestamp, retourner tous les fichiers
        return fichiers

def assembler_pdfs(fichiers_pdf, fichier_sortie):
    """
    Assemble plusieurs fichiers PDF en un seul

    Args:
        fichiers_pdf: Liste des chemins de fichiers PDF à assembler
        fichier_sortie: Nom du fichier de sortie

    Returns:
        True si succès, False sinon
    """
    writer = PdfWriter()
    total_pages = 0

    try:
        # Première passe : compter le nombre total de pages
        for pdf_path in fichiers_pdf:
            reader = PdfReader(pdf_path)
            total_pages += len(reader.pages)


        # Deuxième passe : assembler les PDFs
        # Les lecteurs restent référencés jusqu'à l'écriture : pypdf indexe les
        # objets copiés par id(reader), un lecteur libéré trop tôt peut voir son
        # id réutilisé et mélanger les objets de deux fichiers.
        page_courante = 0
        lecteurs = []
        for pdf_path in fichiers_pdf:
            reader = PdfReader(pdf_path)
            lecteurs.append(reader)


            for page in reader.pages:
                page_courante += 1
                writer.add_page(page)

        # Écriture du fichier final
        with open(fichier_sortie, 'wb') as output_file:
            writer.write(output_file)

        ModernUI.status(f"Document assemblé : {total_pages} pages au total", "success")
        return True

    except Exception as e:
        ModernUI.status(f"Erreur lors de l'assemblage : {e}", "error")
        import traceback
        traceback.print_exc()
        return False

# Libellés des signets PDF par motif de fichier (None = pas de signet).
LIBELLES_SIGNETS = {
    "rapport_": "Page de garde",
    "disclaimer_report_": "Avant-propos",
    "table_of_contents_": "Sommaire",
    "synthesis_global_report_": "Synthèse",
    "threat_modeling_report_": "Partie 1 · Menaces",
    "asset_discovery_report_": "Partie 2 · Actifs",
    "risk_assessment_report_": "Partie 3 · Risques",
    "mitigation_plan_report_": "Partie 4 · Mitigation",
    "back_cover_report_": None,
}


def inserer_sommaire(dossier, fichiers, motif_par_fichier, organisation):
    """
    Insère la page de sommaire (R11) après l'avant-propos, ou à défaut après la
    page de garde. Les numéros de page sont calculés sur les pages réelles de
    chaque partie. Retourne (fichiers ordonnés, navigation) où navigation décrit
    les liens du sommaire et les signets à ajouter au PDF final.
    """
    navigation = {"toc_index": None, "liens": [], "signets": []}
    try:
        import R11_table_of_contents as sommaire
    except Exception as e:
        ModernUI.status(f"Sommaire non généré (module R11 indisponible : {e})", "warning")
        return fichiers, navigation

    nb_pages = {f: len(PdfReader(f).pages) for f in fichiers}
    motifs = [motif_par_fichier[f] for f in fichiers]
    if "disclaimer_report_" in motifs:
        position = motifs.index("disclaimer_report_") + 1
    elif "rapport_" in motifs:
        position = motifs.index("rapport_") + 1
    else:
        position = 0

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin_toc = os.path.join(dossier, f"table_of_contents_{timestamp}.pdf")

    def calculer(pages_toc):
        entrees, debut = [], 1
        ordre = fichiers[:position] + [chemin_toc] + fichiers[position:]
        for f in ordre:
            motif = "table_of_contents_" if f == chemin_toc else motif_par_fichier[f]
            for m, surtitre, titre in sommaire.TOC_PARTS:
                if motif == m:
                    entrees.append((surtitre, titre, debut))
            debut += pages_toc if f == chemin_toc else nb_pages[f]
        return ordre, entrees

    pages_toc = 1
    ordre, entrees = calculer(pages_toc)
    if not entrees:
        return fichiers, navigation
    try:
        pages_reelles, liens = sommaire.build_toc(chemin_toc, organisation, entrees)
        if pages_reelles != pages_toc:  # sommaire plus long que prévu : on recalcule
            ordre, entrees = calculer(pages_reelles)
            pages_reelles, liens = sommaire.build_toc(chemin_toc, organisation, entrees)
            pages_toc = pages_reelles
    except Exception as e:
        ModernUI.status(f"Sommaire non généré : {e}", "warning")
        return fichiers, navigation

    motif_par_fichier[chemin_toc] = "table_of_contents_"
    nb_pages[chemin_toc] = pages_toc
    navigation["toc_index"] = position_page = sum(nb_pages[f] for f in fichiers[:position])
    navigation["liens"] = [(page_cible - 1, rect) for page_cible, rect in liens]

    debut = 0
    for f in ordre:
        libelle = LIBELLES_SIGNETS.get(motif_par_fichier[f])
        if libelle:
            navigation["signets"].append((libelle, debut))
        debut += nb_pages[f]
    ModernUI.status(f"Sommaire inséré en page {position_page + 1} ({len(entrees)} parties)", "success")
    return ordre, navigation


def ajouter_navigation(fichier_pdf, navigation):
    """Ajoute au PDF final les liens cliquables du sommaire et les signets."""
    if navigation["toc_index"] is None and not navigation["signets"]:
        return
    try:
        from pypdf.generic import (ArrayObject, DictionaryObject, NameObject,
                                   NumberObject, RectangleObject)
        reader = PdfReader(fichier_pdf)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        toc_index = navigation["toc_index"]
        if toc_index is not None and navigation["liens"]:
            # Les liens « toc:N » posés par WeasyPrint sont remplacés par de vrais
            # liens internes vers la page N du document assemblé.
            page = writer.pages[toc_index]
            annotations = ArrayObject()
            for page_cible, rect in navigation["liens"]:
                if not 0 <= page_cible < len(writer.pages):
                    continue
                lien = DictionaryObject({
                    NameObject("/Type"): NameObject("/Annot"),
                    NameObject("/Subtype"): NameObject("/Link"),
                    NameObject("/Rect"): RectangleObject(rect),
                    NameObject("/Border"): ArrayObject([NumberObject(0)] * 3),
                    NameObject("/Dest"): ArrayObject([
                        writer.pages[page_cible].indirect_reference, NameObject("/Fit")]),
                })
                annotations.append(writer._add_object(lien))
            page[NameObject("/Annots")] = annotations

        for libelle, page_index in navigation["signets"]:
            writer.add_outline_item(libelle, page_index)
        try:
            writer.page_mode = "/UseOutlines"   # ouvre le panneau des signets
        except Exception:
            pass

        temporaire = fichier_pdf.replace('.pdf', '_nav.pdf')
        with open(temporaire, 'wb') as f:
            writer.write(f)
        os.replace(temporaire, fichier_pdf)
    except Exception as e:
        ModernUI.status(f"Navigation PDF (liens, signets) non ajoutée : {e}", "warning")


def supprimer_fichiers_source(fichiers_a_supprimer):
    """
    Supprime les fichiers PDF source après la génération du rapport global.

    Args:
        fichiers_a_supprimer: Liste des chemins des fichiers à supprimer.
    """
    try:
        for fichier in fichiers_a_supprimer:
            if os.path.exists(fichier):
                os.remove(fichier)
    except Exception as e:
        ModernUI.status(f"Erreur lors de la suppression des fichiers : {e}", "warning")

def extraire_nom_organisation(dossier="Data"):
    """
    Tente d'extraire le nom de l'organisation depuis le fichier rapport_*.pdf

    Args:
        dossier: Dossier contenant les rapports

    Returns:
        Nom de l'organisation ou None
    """
    fichiers_rapport = glob.glob(os.path.join(dossier, "rapport_*.pdf"))
    if fichiers_rapport:
        # Extraire le nom depuis le premier fichier trouvé
        nom_fichier = os.path.basename(fichiers_rapport[0])
        # Format attendu: rapport_<organisation>.pdf ou rapport_<organisation>_timestamp.pdf
        match = re.match(r'rapport_(.+?)(?:_\d{8}_\d{6})?\.pdf', nom_fichier)
        if match:
            return match.group(1).capitalize()
    return None

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Assemble les rapports PDF en un rapport final. "
                    "Non-destructif par défaut (les sources sont conservées)."
    )
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). "
                             "Par défaut : campagne la plus récente sous Result/.")
    parser.add_argument("-d", "--data-dir", default=None,
                        help="Dossier contenant les PDF à assembler "
                             "(défaut : data/ de la campagne)")
    parser.add_argument("-o", "--output", default=None,
                        help="Nom du fichier de sortie (défaut : Rapport_Final_<org>_<timestamp>.pdf)")
    parser.add_argument("--clean", action="store_true",
                        help="Supprime les PDF sources APRÈS un assemblage réussi "
                             "(désactivé par défaut pour garder le pipeline rejouable)")
    return parser.parse_args(argv)


def main():
    """
    Fonction principale - MODE AUTOMATISÉ (non-destructif par défaut)
    """
    args = parse_args()

    # Dossier source des PDF intermédiaires = data/ de la campagne ;
    # le rapport final est déposé à la RACINE de la campagne (le livrable).
    dossier = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
    dossier_livrable = os.path.dirname(os.path.abspath(dossier))

    if not os.path.exists(dossier):
        ModernUI.status(f"Erreur : Le dossier '{dossier}' n'existe pas.", "error")
        sys.exit(1)

    # Ordre des fichiers à assembler
    patterns_ordre = [
        ("rapport_", "Rapports principaux"),
        ("disclaimer_report_", "Avant-propos (périmètre et limites)"),
        ("synthesis_global_report_", "Rapports de synthèse globale"),
        ("threat_modeling_report_", "Rapports de modélisation des menaces"),
        ("asset_discovery_report_", "Rapports de découverte d'actifs"),
        ("risk_assessment_report_", "Rapports d'évaluation des risques"),
        ("mitigation_plan_report_", "Rapports de plan d'atténuation"),
        ("back_cover_report_", "Quatrième de couverture")
    ]

    # Collecte des fichiers (le plus récent par catégorie)
    tous_les_fichiers = []
    fichiers_trouves = {}
    for pattern, description in patterns_ordre:
        fichiers = trouver_fichiers_pdf(pattern, dossier)
        if fichiers:
            fichiers_selectionnes = selectionner_fichiers_uniques(fichiers)
            fichiers_trouves[pattern] = fichiers_selectionnes
            tous_les_fichiers.extend(fichiers_selectionnes)

    if not tous_les_fichiers:
        ModernUI.status("Aucun fichier PDF trouvé pour l'assemblage.", "error")
        sys.exit(1)

    # Nom du fichier de sortie : --output prioritaire, sinon génération automatique
    organisation = extraire_nom_organisation(dossier) or os.path.basename(dossier_livrable)

    # Sommaire : page dédiée après l'avant-propos, numéros calculés sur les pages réelles.
    motif_par_fichier = {f: motif for motif, fs in fichiers_trouves.items() for f in fs}
    tous_les_fichiers, navigation = inserer_sommaire(
        dossier, tous_les_fichiers, motif_par_fichier,
        os.path.basename(dossier_livrable).capitalize())
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        fichier_sortie = args.output
    elif organisation:
        fichier_sortie = f"Rapport_Final_{organisation}_{timestamp}.pdf"
    else:
        fichier_sortie = f"rapport_complet_{timestamp}.pdf"

    chemin_sortie = os.path.join(dossier_livrable, fichier_sortie)

    # Écrasement automatique si le fichier existe déjà
    if os.path.exists(chemin_sortie):
        os.remove(chemin_sortie)

    # Renumérotation activée par défaut si ReportLab disponible
    renumeroter = REPORTLAB_AVAILABLE
    if not renumeroter:
        ModernUI.status("Renumérotation désactivée (ReportLab non disponible)", "warning")

    if assembler_pdfs(tous_les_fichiers, chemin_sortie):
        if renumeroter:
            chemin_numerote = chemin_sortie.replace('.pdf', '_numerote.pdf')
            if ajouter_numeros_pages(chemin_sortie, chemin_numerote,
                                     sans_numero_derniere="back_cover_report_" in fichiers_trouves):
                try:
                    os.remove(chemin_sortie)
                    shutil.move(chemin_numerote, chemin_sortie)
                except Exception as e:
                    ModernUI.status(f"Impossible de remplacer le fichier original : {e}", "warning")
                    chemin_sortie = chemin_numerote

        ajouter_navigation(chemin_sortie, navigation)

        if args.clean:
            supprimer_fichiers_source(tous_les_fichiers)

        ModernUI.status(f"Rapport final : {chemin_sortie}", "success")
    else:
        ModernUI.status("Erreur lors de l'assemblage des fichiers.", "error")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ModernUI.status("Opération annulée par l'utilisateur.", "warning")
        sys.exit(0)
    except Exception as e:
        ModernUI.status(f"Erreur inattendue : {e}", "error")
        import traceback
        traceback.print_exc()
        sys.exit(1)