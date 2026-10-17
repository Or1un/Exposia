#!/usr/bin/env bash
#
# run_pipeline.sh — Orchestrateur Exposia
# =============================================================================
# Enchaîne les modules de production de données (D_Data) puis de génération
# du rapport (R_Report) pour un domaine donné.
#
#   D1  asset_discovery_assessment découverte d'actifs + vulnérabilités
#   D2  mitigation_plan            enrichissement mitigations
#   D3  threat_modeling            modélisation des menaces (INTERACTIF ; lit la note ASM de D1)
#   R5  cover_page                 page de garde (rapport_*.pdf, assemblée en tête)
#   R7  disclaimer                 avant-propos « ce que ce rapport dit » (après la garde)
#   R8  back_cover                 quatrième de couverture (dernière page, non numérotée)
#   R1  threat_modeling            rapport menaces
#   R2  Asset_discovery            rapport découverte d'actifs
#   R3  Risk_assessment            rapport risques
#   R4  mitigation                 rapport plan de mitigation
#   R6  synthesis_global           synthèse « de la menace à la mitigation »
#                                  (assemblée juste après la page de garde)
#   R9  Global_report              assemblage du livrable final
#   R10 presentation_export        vue présentation (livrable CSV exposition×CVE)
#
# Arborescence :
#
#   projet/
#   ├── run_pipeline.sh   <- ce script (à la racine)
#   ├── config.yaml       clés API Shodan / NVD (secrets, chmod 600, non versionné)
#   ├── Parameters/       fichiers de référence
#   ├── Modules/
#   │   ├── exposia_paths.py
#   │   ├── exposia_config.py   lecture de config.yaml
#   │   ├── D_Data/       D1..D3
#   │   └── R_Report/     R0..R10
#   └── Result/
#       └── <domaine>/    data/ (CSV + PDF intermédiaires)
#                         + Rapport_Final_*.pdf  + Exposia_*_presentation.csv (livrables)
#
# Les scripts résolvent leurs chemins depuis __file__ : ils fonctionnent quel
# que soit le dossier d'appel. Ce script transmet la campagne via --result-dir.
#
# Clés API : config.yaml à la racine (api_keys.shodan, api_keys.nvd), lu par
# D1 via Modules/exposia_config.py. Jamais passées en argument (historique du
# shell, liste des processus). Ce script vérifie seulement leur présence.
#   shodan vide = scan de vulnérabilités ignoré
#   nvd vide    = NVD limité à ~6 s par CVE (~0,7 s avec une clé)
# =============================================================================

set -uo pipefail

# --- Couleurs / logs ---------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''
fi
log_info() { echo -e "${C_BLUE}•${C_RESET} $*"; }
log_ok()   { echo -e "${C_GREEN}✓${C_RESET} $*"; }
log_warn() { echo -e "${C_YELLOW}⚠${C_RESET} $*"; }
log_err()  { echo -e "${C_RED}✗${C_RESET} $*" >&2; }
log_step() { echo -e "\n${C_BOLD}${C_BLUE}»${C_RESET} ${C_BOLD}$*${C_RESET}"; }

# --- Options -----------------------------------------------------------------
DOMAIN=""
RESOLVE_IPS=false
SKIP_THREAT=false
SKIP_DISCOVERY=false
SKIP_MITIGATION=false
SKIP_REPORT=false
SKIP_PRESENTATION=false
CLEAN=false
CONTINUE_ON_ERROR=false
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
    cat <<EOF
${C_BOLD}run_pipeline.sh${C_RESET} — orchestrateur Exposia

Usage : ./run_pipeline.sh -d <domaine> [options]

Options principales :
  -d, --domain <domaine>   Domaine à analyser (obligatoire, sauf --skip-discovery)
      --resolve-ips        Résout les IPs et ignore le scan de vulnérabilités

Contrôle du pipeline :
      --skip-threat        Ignore D3 (modélisation des menaces, interactif)
      --skip-discovery     Ignore D1 (découverte d'actifs)
      --skip-mitigation    Ignore D2 (enrichissement mitigations)
      --skip-report        Ignore R1..R9 (génération du rapport PDF)
      --skip-presentation  Ignore R10 (vue présentation CSV)
      --clean              Supprime les PDF intermédiaires après assemblage
      --continue-on-error  Poursuit même si une étape échoue
  -h, --help               Affiche cette aide

Clés API (Shodan, NVD) : variables SHODAN_API_KEY / NVD_API_KEY, sinon config.yaml à la racine du projet.

Variable d'environnement :
  PYTHON_BIN    Interpréteur Python (défaut : python3)

Exemples :
  ./run_pipeline.sh -d exemple.com
  ./run_pipeline.sh -d exemple.com --skip-threat
  ./run_pipeline.sh -d exemple.com --skip-discovery --skip-mitigation  # rapport seul
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)         DOMAIN="${2:-}"; shift 2 ;;
        -k|--shodan-key)
            log_err "Option $1 supprimée : renseignez la clé dans config.yaml (api_keys.shodan)."
            exit 2 ;;
        --resolve-ips)       RESOLVE_IPS=true; shift ;;
        --skip-threat)       SKIP_THREAT=true; shift ;;
        --skip-discovery)    SKIP_DISCOVERY=true; shift ;;
        --skip-mitigation)   SKIP_MITIGATION=true; shift ;;
        --skip-report)       SKIP_REPORT=true; shift ;;
        --skip-presentation) SKIP_PRESENTATION=true; shift ;;
        --clean)             CLEAN=true; shift ;;
        --continue-on-error) CONTINUE_ON_ERROR=true; shift ;;
        -h|--help)           usage; exit 0 ;;
        *) log_err "Option inconnue : $1"; echo; usage; exit 2 ;;
    esac
done

# --- Chemins (indépendants du dossier d'appel) -------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/Modules"
D_DIR="$MODULES_DIR/D_Data"
R_DIR="$MODULES_DIR/R_Report"
PARAMS_DIR="$SCRIPT_DIR/Parameters"

log_step "Vérifications préalables"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || { log_err "Python introuvable : '$PYTHON_BIN'"; exit 1; }
log_ok "Python : $("$PYTHON_BIN" --version 2>&1)"

for d in "$MODULES_DIR" "$D_DIR" "$R_DIR"; do
    [[ -d "$d" ]] || { log_err "Dossier manquant : $d"; exit 1; }
done
log_ok "Arborescence Modules/ conforme"

if [[ ! -d "$PARAMS_DIR" ]]; then
    log_warn "Dossier Parameters/ introuvable : $PARAMS_DIR"
    log_info "D1 et D2 échoueront sans leurs fichiers de référence."
else
    log_ok "Parameters/ trouvé"
fi

# Domaine requis si la découverte est active
if [[ "$SKIP_DISCOVERY" == false && -z "$DOMAIN" ]]; then
    read -r -p "$(echo -e "${C_YELLOW}Domaine à analyser : ${C_RESET}")" DOMAIN
    [[ -n "$DOMAIN" ]] || { log_err "Aucun domaine fourni (utilisez -d, ou --skip-discovery)."; exit 1; }
fi

# Nom de campagne : calculé par exposia_paths (source unique de la règle)
if [[ -n "$DOMAIN" ]]; then
    # Domaine passé en argument (jamais interpolé dans le code Python).
    CAMPAIGN="$("$PYTHON_BIN" -c 'import sys; sys.path.insert(0, sys.argv[1]); import exposia_paths; print(exposia_paths.main_domain(sys.argv[2]))' "$MODULES_DIR" "$DOMAIN")" \
        || { log_err "Nom de campagne impossible à déterminer pour « $DOMAIN »."; exit 1; }
    RESULT_DIR="$SCRIPT_DIR/Result/$CAMPAIGN"
    log_ok "Campagne : $CAMPAIGN  ($RESULT_DIR)"
else
    RESULT_DIR=""
    log_info "Aucun domaine : les étapes R utiliseront la campagne la plus récente."
fi

# Clés API : présence vérifiée dans config.yaml (les valeurs ne sont jamais affichées).
# Utiles uniquement à la découverte (D1).
if [[ "$SKIP_DISCOVERY" == false ]]; then
    cfg_out="$("$PYTHON_BIN" "$MODULES_DIR/exposia_config.py" 2>&1)"
    cfg_rc=$?
    case "$cfg_rc" in
        0)
            log_ok "Configuration des clés API chargée"
            if [[ "$RESOLVE_IPS" == false ]] && ! grep -q "^shodan=ok" <<<"$cfg_out"; then
                log_warn "Clé Shodan absente (SHODAN_API_KEY ou config.yaml, api_keys.shodan) : scan de vulnérabilités ignoré."
            fi
            if [[ "$RESOLVE_IPS" == false ]] && ! grep -q "^nvd=ok" <<<"$cfg_out"; then
                log_warn "Clé NVD absente (NVD_API_KEY ou config.yaml, api_keys.nvd) : ~6 s par CVE."
            fi
            perm="$(grep "^PERM " <<<"$cfg_out" | cut -d' ' -f2-)"
            [[ -n "$perm" ]] && log_warn "$perm"
            ;;
        2)
            log_warn "config.yaml introuvable ($SCRIPT_DIR/config.yaml ; modèle : config.example.yaml) : scan Shodan ignoré, NVD sans clé."
            ;;
        *)
            log_err "config.yaml illisible : ${cfg_out#ERREUR }"
            exit 1
            ;;
    esac
fi

# --- Exécution ---------------------------------------------------------------
PIPELINE_RC=0
PIPELINE_START=$(date +%s)   # début du traitement (pour la métrique « temps »)
D3_SECONDS=0                 # temps de l'étape interactive D3, exclu du total
run_step() {
    local label="$1"; shift
    if "$@"; then
        log_ok "$label terminé"
    else
        local rc=$?
        log_err "$label a échoué (code $rc)"
        PIPELINE_RC=$rc
        if [[ "$CONTINUE_ON_ERROR" == false ]]; then
            log_info "Arrêt du pipeline (--continue-on-error pour poursuivre)."
            exit "$rc"
        fi
    fi
}

# Argument de campagne pour les étapes qui l'acceptent
res_args=()
[[ -n "$RESULT_DIR" ]] && res_args=(--result-dir "$RESULT_DIR")

# === D1 : Asset discovery ====================================================
if [[ "$SKIP_DISCOVERY" == true ]]; then
    log_step "D1 — asset_discovery_assessment ${C_DIM}(ignoré)${C_RESET}"
else
    log_step "D1 — asset_discovery_assessment"
    d1_args=("$DOMAIN")
    [[ "$RESOLVE_IPS" == true ]] && d1_args+=(--resolve-ips)
    run_step "Asset discovery" "$PYTHON_BIN" "$D_DIR/D1_asset_discovery_assessment.py" "${d1_args[@]}"
fi

# === D2 : Mitigation plan ====================================================
if [[ "$SKIP_MITIGATION" == true ]]; then
    log_step "D2 — mitigation_plan ${C_DIM}(ignoré)${C_RESET}"
else
    log_step "D2 — mitigation_plan"
    run_step "Mitigation plan" "$PYTHON_BIN" "$D_DIR/D2_mitigation_plan.py" ${res_args[@]+"${res_args[@]}"}
fi

# === D3 : Threat modeling (interactif) ======================================
# APRÈS D1/D2 : D3 lit la note ASM (criticité du domaine) produite par D1.
if [[ "$SKIP_THREAT" == true ]]; then
    log_step "D3 — threat_modeling ${C_DIM}(ignoré)${C_RESET}"
else
    log_step "D3 — threat_modeling ${C_DIM}(interactif)${C_RESET}"
    d3_args=()
    [[ -n "$DOMAIN" ]] && d3_args=(--domain "$DOMAIN")
    _d3_t0=$(date +%s)
    run_step "Threat modeling" "$PYTHON_BIN" "$D_DIR/D3_threat_modeling.py" ${d3_args[@]+"${d3_args[@]}"}
    D3_SECONDS=$(( $(date +%s) - _d3_t0 ))   # exclu du temps de traitement (saisie humaine)
fi

# === R1..R6 : Génération des parties du rapport ==============================
if [[ "$SKIP_REPORT" == true ]]; then
    log_step "R1..R9 — génération du rapport ${C_DIM}(ignorée)${C_RESET}"
else
    # === R5 : Page de garde (générée AVANT R9 pour être assemblée en tête) ====
    log_step "R5 — cover_page ${C_DIM}(page de garde)${C_RESET}"
    r5_args=(${res_args[@]+"${res_args[@]}"})
    [[ -n "$DOMAIN" ]] && r5_args+=(--domain "$DOMAIN")
    run_step "Page de garde" "$PYTHON_BIN" "$R_DIR/R5_cover_page.py" ${r5_args[@]+"${r5_args[@]}"}

    # === R7 : Avant-propos (assemblé juste après la page de garde) ============
    log_step "R7 — disclaimer ${C_DIM}(avant-propos)${C_RESET}"
    run_step "Avant-propos" "$PYTHON_BIN" "$R_DIR/R7_disclaimer.py" ${res_args[@]+"${res_args[@]}"}

    # R6 (synthèse) s'appuie sur les sorties de D1, D2 et D3 ; R9 l'assemble
    # juste après la page de garde (motif synthesis_global_report_*).
    for step in "R1_threat_modeling:Rapport menaces" \
                "R2_Asset_discovery:Rapport asset discovery" \
                "R3_Risk_assessment:Rapport risques" \
                "R4_mitigation:Rapport mitigation" \
                "R6_synthesis_global:Synthèse globale" \
                "R8_back_cover:Quatrième de couverture"; do
        script="${step%%:*}"; label="${step##*:}"
        log_step "${script%%_*} — ${script#*_}"
        run_step "$label" "$PYTHON_BIN" "$R_DIR/$script.py" ${res_args[@]+"${res_args[@]}"}
    done

    # === R9 : Assemblage du livrable =========================================
    log_step "R9 — Global_report ${C_DIM}(assemblage)${C_RESET}"
    r9_args=(${res_args[@]+"${res_args[@]}"})
    [[ "$CLEAN" == true ]] && r9_args+=(--clean)
    run_step "Assemblage" "$PYTHON_BIN" "$R_DIR/R9_Global_report.py" ${r9_args[@]+"${r9_args[@]}"}
fi

# === R10 : Vue présentation (livrable CSV exposition×CVE) ====================
# Export de données indépendant des PDF : il tourne même avec --skip-report,
# tant qu'un Exposia_*.csv de travail existe (produit par D1/D2 ou un run
# précédent). Dépose le CSV à la racine de la campagne, près du Rapport_Final.
if [[ "$SKIP_PRESENTATION" == true ]]; then
    log_step "R10 — presentation_export ${C_DIM}(ignoré)${C_RESET}"
else
    log_step "R10 — presentation_export ${C_DIM}(vue exposition×CVE)${C_RESET}"
    # Temps de traitement = total écoulé moins l'étape interactive D3 (saisie humaine).
    ELAPSED=$(( $(date +%s) - PIPELINE_START - D3_SECONDS ))
    [[ "$ELAPSED" -lt 0 ]] && ELAPSED=0
    r10_args=(${res_args[@]+"${res_args[@]}"} --elapsed "$ELAPSED")
    run_step "Vue présentation" "$PYTHON_BIN" "$R_DIR/R10_presentation_export.py" "${r10_args[@]}"
fi

# --- Résumé ------------------------------------------------------------------
echo
if [[ "$PIPELINE_RC" -eq 0 ]]; then
    log_ok "${C_BOLD}Pipeline terminé avec succès.${C_RESET}"
else
    log_warn "${C_BOLD}Pipeline terminé avec des erreurs (code $PIPELINE_RC).${C_RESET}"
fi
[[ -n "$RESULT_DIR" ]] && log_info "Campagne : $RESULT_DIR"
exit "$PIPELINE_RC"