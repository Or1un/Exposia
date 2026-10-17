#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_ui.py — Système d'interface console partagé du projet Exposia.

Source de vérité UNIQUE de l'affichage terminal pour tous les modules (D_Data et
R_Report). Pendant du fichier R0_report_theme.py (qui centralise le thème PDF) :
ici on centralise le « chrome » console — palette de couleurs, en-têtes, statuts
horodatés, résultats, barres de progression, sections.

Objectif : un rendu ABSOLUMENT UNIFORME entre tous les scripts. Pour changer
l'apparence console (couleurs, icônes, format des logs), on modifie ce fichier —
et lui seul. Les modules NE redéfinissent plus leur propre classe Colors/UI ;
ils font :

    import exposia_ui
    from exposia_ui import Colors, ModernUI

Robustesse :
  * Détection TTY : si la sortie est redirigée (pipe, fichier de log), les codes
    ANSI sont automatiquement désactivés — plus de séquences \\033[...] illisibles
    dans les logs de run_pipeline.sh.
  * Respect des conventions NO_COLOR / FORCE_COLOR.
  * status() tolère un état inconnu au lieu de lever une exception.
  * tqdm optionnel : si absent, on dégrade proprement sans planter l'import.
"""

import os
import sys
from datetime import datetime

__all__ = ["Colors", "ModernUI", "set_color", "color_enabled"]

# --- Détection de la prise en charge des couleurs ----------------------------


def _should_use_color() -> bool:
    """
    Décide si l'on émet des codes ANSI.

    Priorité : NO_COLOR (désactive) > FORCE_COLOR (force) > stdout est un TTY.
    Ainsi la sortie reste propre quand run_pipeline.sh redirige vers un fichier.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


# Codes ANSI 256 couleurs — source unique. Les attributs de Colors sont dérivés
# de ce dictionnaire selon que la couleur est activée ou non.
_RAW = {
    "PRIMARY":   "\033[38;5;45m",
    "SECONDARY": "\033[38;5;141m",
    "ACCENT":    "\033[38;5;208m",
    "SUCCESS":   "\033[38;5;40m",
    "WARNING":   "\033[38;5;221m",
    "ERROR":     "\033[38;5;203m",
    "INFO":      "\033[38;5;117m",
    "HEADER":    "\033[38;5;45m",
    "TEXT":      "\033[38;5;255m",
    "DIM":       "\033[38;5;245m",
    "BG_DARK":   "\033[48;5;234m",
    "BG_LIGHT":  "\033[48;5;238m",
    "BOLD":      "\033[1m",
    "RESET":     "\033[0m",
}


class Colors:
    """Palette ANSI. Attributs peuplés par set_color() (chaînes vides si off)."""
    # Déclarés pour l'auto-complétion / la lisibilité ; valeurs posées plus bas.
    PRIMARY = SECONDARY = ACCENT = SUCCESS = WARNING = ERROR = INFO = ""
    HEADER = TEXT = DIM = BG_DARK = BG_LIGHT = BOLD = RESET = ""
    enabled = False


def set_color(enabled: bool) -> None:
    """(Ré)active ou désactive la colorisation à la volée."""
    for name, code in _RAW.items():
        setattr(Colors, name, code if enabled else "")
    Colors.enabled = enabled


def color_enabled() -> bool:
    """Renvoie True si la colorisation est actuellement active."""
    return Colors.enabled


# État initial déterminé à l'import.
set_color(_should_use_color())


# --- Interface console partagée ----------------------------------------------

# Table des statuts : état -> (attribut couleur, icône). Glyphes monochromes
# colorisés (cohérents avec le thème) plutôt que des emojis.
_STATUS = {
    "info":    ("INFO",    "●"),
    "success": ("SUCCESS", "✓"),
    "warning": ("WARNING", "⚠"),
    "error":   ("ERROR",   "✗"),
    "step":    ("PRIMARY", "▸"),
}
_STATUS_DEFAULT = ("TEXT", "•")

_RULE_WIDTH = 40  # largeur des en-têtes/sections, alignée sur print_header


class ModernUI:
    # -- En-tête principal ----------------------------------------------------
    @staticmethod
    def print_header(title: str = "Exposia") -> None:
        """Bannière d'ouverture. `title` permet à chaque module d'afficher le sien."""
        centered = title.center(_RULE_WIDTH)
        print(f"\n{Colors.BG_DARK}{Colors.HEADER}{'▀' * _RULE_WIDTH}{Colors.RESET}")
        print(f"{Colors.BG_DARK}{Colors.HEADER}{centered}{Colors.RESET}")
        print(f"{Colors.BG_DARK}{Colors.HEADER}{'▄' * _RULE_WIDTH}{Colors.RESET}\n")

    # -- Statut horodaté ------------------------------------------------------
    @staticmethod
    def status(message: str, state: str = "info") -> None:
        """
        Ligne de statut horodatée : [HH:MM:SS] <icône> <message>.
        Un état inconnu retombe sur un rendu neutre au lieu de lever.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_attr, icon = _STATUS.get(state.lower(), _STATUS_DEFAULT)
        color = getattr(Colors, color_attr, Colors.TEXT)
        print(f"{Colors.DIM}[{timestamp}]{Colors.RESET} {color}{icon} {message}{Colors.RESET}")

    # -- Résultat clé / valeur ------------------------------------------------
    @staticmethod
    def print_result(title, value, unit: str = "") -> None:
        print(
            f"  {Colors.SECONDARY}•{Colors.RESET} {Colors.TEXT}{title}: "
            f"{Colors.BOLD}{Colors.PRIMARY}{value}{Colors.RESET}{Colors.TEXT}{unit}{Colors.RESET}"
        )

    # -- Séparateurs / sections ----------------------------------------------
    @staticmethod
    def rule(char: str = "─") -> None:
        """Trait de séparation simple, pleine largeur."""
        print(f"{Colors.DIM}{char * _RULE_WIDTH}{Colors.RESET}")

    @staticmethod
    def section(title: str) -> None:
        """
        En-tête de section encadré (remplace les blocs '──── SUMMARY ────'
        écrits à la main). Titre centré sur bande sombre.
        """
        centered = f" {title} ".center(_RULE_WIDTH, "─")
        print(f"\n{Colors.BG_DARK}{Colors.HEADER}{centered}{Colors.RESET}")

    @staticmethod
    def section_end() -> None:
        """Ferme visuellement une section ouverte par section()."""
        print(f"{Colors.BG_DARK}{Colors.HEADER}{'─' * _RULE_WIDTH}{Colors.RESET}\n")

    # -- Étape de pipeline ----------------------------------------------------
    @staticmethod
    def step(index: int, total: int, label: str) -> None:
        """Repère de progression inter-modules : « [2/8] Threat modeling »."""
        print(
            f"{Colors.ACCENT}{Colors.BOLD}[{index}/{total}]{Colors.RESET} "
            f"{Colors.TEXT}{label}{Colors.RESET}"
        )

    # -- Barre de progression -------------------------------------------------
    @staticmethod
    def tqdm_progress(iterable, desc=None, total=None, unit="subs",
                      color=None, ip_counter=None):
        """
        Enveloppe tqdm homogène. Si tqdm n'est pas installé, renvoie l'itérable
        tel quel (dégradation propre plutôt qu'un ImportError à l'import).
        """
        try:
            from tqdm import tqdm
        except Exception:
            return iterable

        bar_format = "{l_bar}{bar}| {n_fmt}/{total_fmt} {unit}"
        if ip_counter is not None:
            bar_format += f" | {Colors.ACCENT}{{postfix[0]}}{Colors.RESET} IPs"
        return tqdm(
            iterable,
            desc=desc,
            total=total,
            unit=unit,
            bar_format=bar_format,
            colour="cyan",
            postfix=[ip_counter] if ip_counter is not None else None,
            dynamic_ncols=True,
        )

    # -- Utilitaire de saisie -------------------------------------------------
    @staticmethod
    def is_positive_answer(answer: str) -> bool:
        return answer.lower() == "y" or answer == ""


# Exécuté directement : petite démo/mire pour vérifier le rendu.
if __name__ == "__main__":
    ModernUI.print_header("Exposia UI")
    ModernUI.step(1, 3, "Démonstration des statuts")
    ModernUI.status("Message d'information", "info")
    ModernUI.status("Opération réussie", "success")
    ModernUI.status("Avertissement", "warning")
    ModernUI.status("Erreur rencontrée", "error")
    ModernUI.status("État inconnu (fallback neutre)", "banana")
    ModernUI.section("SUMMARY")
    ModernUI.print_result("Sous-domaines trouvés", 128)
    ModernUI.print_result("Temps d'exécution", "00:01:42")
    ModernUI.section_end()
    print(f"Colorisation active : {color_enabled()}")
