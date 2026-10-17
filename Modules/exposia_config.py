#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_config.py — Lecture centralisée de config.yaml (clés API).

Source des secrets du projet : variables d'environnement SHODAN_API_KEY et
NVD_API_KEY (prioritaires, pratiques en CI / conteneur), sinon config.yaml à la
racine du projet (à côté de run_pipeline.sh). Les clés ne transitent jamais par
la ligne de commande (historique du shell, liste des processus) ni par le code.

    api_keys:
      shodan: "..."   # scan de vulnérabilités (D1) — vide = scan ignoré
      nvd: "..."      # données CVSS NVD (D1) — vide = ~6 s par CVE

Usage dans un module :

    import exposia_config
    key = exposia_config.get_api_key("shodan")   # str, ou None si absente / vide

Diagnostic (utilisé par run_pipeline.sh), sans jamais afficher les clés :

    python3 Modules/exposia_config.py
      -> code 0 : lignes « shodan=ok|vide », « nvd=ok|vide », éventuellement « PERM ... »
      -> code 2 : config.yaml absent
      -> code 1 : config.yaml illisible (YAML invalide, PyYAML manquant)
"""

import os
import stat
import sys

import exposia_paths

__all__ = ["CONFIG_FILENAME", "config_path", "load_config", "get_api_key", "permission_warning"]

CONFIG_FILENAME = "config.yaml"
KNOWN_KEYS = ("shodan", "nvd")
# Variable d'environnement associée à chaque clé (prioritaire sur config.yaml).
ENV_VARS = {"shodan": "SHODAN_API_KEY", "nvd": "NVD_API_KEY"}

_config_cache = None


def config_path():
    """Chemin absolu de config.yaml (racine du projet)."""
    return os.path.join(exposia_paths.project_root(), CONFIG_FILENAME)


def load_config():
    """
    Contenu de config.yaml sous forme de dict ({} si le fichier est absent).
    Lève une exception explicite si le fichier existe mais est illisible.
    """
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    path = config_path()
    data = {}
    if os.path.exists(path):
        try:
            import yaml
        except ImportError as e:
            raise RuntimeError("PyYAML est requis pour lire config.yaml : pip install pyyaml") from e
        with open(path, encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                raise ValueError(f"{path} : YAML invalide ({e})") from e
        if not isinstance(data, dict):
            raise ValueError(f"{path} : format invalide (une section api_keys est attendue)")

    _config_cache = data
    return data


def get_api_key(name):
    """Clé API `name` : variable d'environnement, sinon api_keys.<name> de config.yaml ; None si absente ou vide."""
    env_value = os.environ.get(ENV_VARS.get(name, ""), "").strip()
    if env_value:
        return env_value
    keys = load_config().get("api_keys") or {}
    if not isinstance(keys, dict):
        raise ValueError(f"{config_path()} : api_keys doit être une section clé: valeur")
    value = keys.get(name)
    value = "" if value is None else str(value).strip()
    return value or None


def permission_warning():
    """Message d'alerte si config.yaml est lisible par d'autres utilisateurs (POSIX), sinon None."""
    path = config_path()
    if os.name != "posix" or not os.path.exists(path):
        return None
    mode = os.stat(path).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return f"{path} est lisible par d'autres utilisateurs : chmod 600 {path}"
    return None


if __name__ == "__main__":
    # Diagnostic pour run_pipeline.sh — n'affiche jamais la valeur des clés.
    env_keys = any(os.environ.get(var, "").strip() for var in ENV_VARS.values())
    if not os.path.exists(config_path()) and not env_keys:
        print(f"ABSENT {config_path()}")
        sys.exit(2)
    try:
        for key_name in KNOWN_KEYS:
            print(f"{key_name}={'ok' if get_api_key(key_name) else 'vide'}")
    except Exception as exc:  # YAML invalide, PyYAML manquant, structure incorrecte
        print(f"ERREUR {exc}")
        sys.exit(1)
    warning = permission_warning()
    if warning:
        print(f"PERM {warning}")
    sys.exit(0)
