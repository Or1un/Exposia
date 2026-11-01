#!/usr/bin/env bash
#
# run_pipeline.sh — Orchestrateur Exposia
# =============================================================================
# Enchaîne les modules de production de données (D_Data) puis de génération
# du rapport (R_Report) pour un domaine donné.
#
#   D1  asset_discovery_assessment découverte d'actifs + vulnérabilités
#   D2  mitigation_plan            enrichissement mitigations
#   D3  threat_modeling            modélisation des menaces (profil : --secteur/--taille/--zone,
#                                  sinon demandé au clavier ; note ASM lue dans D1)
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
#   R13 results_json               JSON canonique des résultats (codes, catalogues)
#   R12 llm_digest                 digest Markdown pour un assistant IA (lit le JSON R13)
#   R10 presentation_export        vue présentation (livrable CSV exposition×CVE) + synthèse
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
#   │   ├── exposia_scoring.py  poids et seuils de qualification (source unique)
#   │   ├── D_Data/       D1..D3
#   │   └── R_Report/     R0..R13
#   └── Result/
#       └── <domaine>/    data/ (CSV + PDF intermédiaires)
#                         + Rapport_Final_*.pdf (Final_Report_*.pdf en anglais)
#                         + Exposia_*_presentation.csv
#                         + Exposia_*_results.json + Exposia_*_digest.md (livrables)
#
# Langue des livrables (PDF, CSV, JSON, digest) : --lang fr|en, exportée en
# EXPOSIA_LANG pour tous les modules ; français par défaut. La console reste en français.
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
# Événement --events (sans effet sans l'option) ; une erreur d'écriture n'arrête jamais le run.
emit_event() {
    [[ -n "${EXPOSIA_EVENTS:-}" ]] || return 0
    "$PYTHON_BIN" "$MODULES_DIR/exposia_events.py" "$@" 2>/dev/null || true
}

# --- Options -----------------------------------------------------------------
DOMAIN=""
SECTEUR=""
TAILLE=""
ZONE=""
RESOLVE_IPS=false
SKIP_THREAT=false
SKIP_DISCOVERY=false
SKIP_MITIGATION=false
SKIP_REPORT=false
SKIP_PRESENTATION=false
CLEAN=false
CONTINUE_ON_ERROR=false
EVENTS=false
LANG_OUT="${EXPOSIA_LANG:-fr}"
CAMPAIGN=""
EXPOSIA_EVENTS=""
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Options de profil D3 avec leurs valeurs, lues dans les matrices par D3
# (profile_options) : la liste affichée par --help suit Parameters/Threat_matrices/.
profile_help() {
    local d3
    d3="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Modules/D_Data/D3_threat_modeling.py"
    "$PYTHON_BIN" -c '
import importlib.util, sys, textwrap
spec = importlib.util.spec_from_file_location("d3", sys.argv[1])
d3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(d3)
opts = d3.profile_options()
rows = [("--secteur <secteur>", "Secteur d\x27activité", "secteur"),
        ("--taille <taille>", "Taille", "taille"),
        ("--zone <zone>", "Zone géographique", "zone")]
pad = " " * 27
for flag, label, key in rows:
    values = ", ".join(o.replace(" ", "_") for o in opts[key])
    lines = textwrap.wrap(label + " : " + values, 52, break_on_hyphens=False)
    print(f"      {flag:<21}{lines[0]}")
    for line in lines[1:]:
        print(pad + line)
' "$d3" 2>/dev/null && return
    # Repli (Python ou matrices indisponibles) : options sans la liste des valeurs.
    cat <<EOF
      --secteur <secteur>  Secteur d'activité
      --taille <taille>    Taille
      --zone <zone>        Zone géographique
                           Valeurs : lignes de M1, colonnes de M6 et M7
                           (Parameters/Threat_matrices/)
EOF
}

usage() {
    cat <<EOF
${C_BOLD}run_pipeline.sh${C_RESET} — orchestrateur Exposia

Usage : ./run_pipeline.sh -d <domaine> [options]

Options principales :
  -d, --domain <domaine>   Domaine à analyser (obligatoire, sauf --skip-discovery)
      --resolve-ips        Résout les IPs et ignore le scan de vulnérabilités
      --lang <fr|en>       Langue des livrables : rapport PDF, CSV, JSON, digest (défaut : fr)

Profil de l'organisation (D3) — sans ces options, D3 les demande au clavier.
Casse et accents indifférents ; « _ » à la place des espaces (Europe_Ouest) ;
libellés anglais acceptés aussi (Healthcare, SME, Western_Europe) :
$(profile_help)

Contrôle du pipeline :
      --skip-threat        Ignore D3 (modélisation des menaces)
      --skip-discovery     Ignore D1 (découverte d'actifs)
      --skip-mitigation    Ignore D2 (enrichissement mitigations)
      --skip-report        Ignore R1..R9 (génération du rapport PDF)
      --skip-presentation  Ignore R10 (vue présentation CSV et synthèse console)
      --clean              Supprime les PDF intermédiaires après assemblage
      --continue-on-error  Poursuit même si une étape échoue
      --events             Écrit les événements de progression (JSON Lines) dans
                           Result/<campagne>/data/events.jsonl, pour une interface qui pilote
                           Exposia (format : Modules/exposia_events.py)
  -h, --help               Affiche cette aide

Clés API (Shodan, NVD) : variables SHODAN_API_KEY / NVD_API_KEY, sinon config.yaml à la racine du projet.

Variable d'environnement :
  PYTHON_BIN    Interpréteur Python (défaut : python3)

Exemples :
  ./run_pipeline.sh -d exemple.com
  ./run_pipeline.sh -d exemple.com --secteur Finance --taille PME --zone Europe_Ouest  # sans saisie
  ./run_pipeline.sh -d exemple.com --lang en                           # livrables en anglais
  ./run_pipeline.sh -d exemple.com --skip-threat
  ./run_pipeline.sh -d exemple.com --skip-discovery --skip-mitigation  # rapport seul
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)         DOMAIN="${2:-}"; shift 2 ;;
        --secteur)           SECTEUR="${2:-}"; shift 2 ;;
        --taille)            TAILLE="${2:-}"; shift 2 ;;
        --zone)              ZONE="${2:-}"; shift 2 ;;
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
        --events)            EVENTS=true; shift ;;
        --lang)              LANG_OUT="${2:-}"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *) log_err "Option inconnue : $1"; echo; usage; exit 2 ;;
    esac
done

LANG_OUT="$(tr '[:upper:]' '[:lower:]' <<<"$LANG_OUT")"
case "$LANG_OUT" in
    fr|en) ;;
    *) log_err "--lang : « $LANG_OUT » inconnue (valeurs : fr, en)."; exit 2 ;;
esac
EXPOSIA_LANG="$LANG_OUT"
export EXPOSIA_LANG

# --- Chemins (indépendants du dossier d'appel) -------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/Modules"
D_DIR="$MODULES_DIR/D_Data"
R_DIR="$MODULES_DIR/R_Report"
PARAMS_DIR="$SCRIPT_DIR/Parameters"

log_step "Vérifications préalables"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || { log_err "Python introuvable : '$PYTHON_BIN'"; exit 1; }
log_ok "Python : $("$PYTHON_BIN" --version 2>&1)"
log_ok "Langue des livrables : $EXPOSIA_LANG"

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

# Profil D3 : validé avant D1, pour qu'une faute de frappe n'échoue pas après
# la collecte (D3 tourne en dernier, il lit la note ASM produite par D1).
d3_profile_args=()
[[ -n "$SECTEUR" ]] && d3_profile_args+=(--secteur "$SECTEUR")
[[ -n "$TAILLE" ]] && d3_profile_args+=(--taille "$TAILLE")
[[ -n "$ZONE" ]] && d3_profile_args+=(--zone "$ZONE")
PROFILE_COMPLETE=false
[[ -n "$SECTEUR" && -n "$TAILLE" && -n "$ZONE" ]] && PROFILE_COMPLETE=true
if [[ "$SKIP_THREAT" == false && ${#d3_profile_args[@]} -gt 0 ]]; then
    "$PYTHON_BIN" -c 'import importlib.util, sys
spec = importlib.util.spec_from_file_location("d3", sys.argv[1])
d3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(d3)
sys.exit(d3.validate_cli(sys.argv[2:]))' "$D_DIR/D3_threat_modeling.py" "${d3_profile_args[@]}" \
        || { log_err "Profil invalide (voir ci-dessus)."; exit 2; }
    log_ok "Profil D3 valide"
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

# Événements de progression (--events) : Result/<campagne>/data/events.jsonl,
# réécrit à chaque run ; identifiant du run partagé avec le JSON canonique (run.run_id).
EVENTS_DIR="$RESULT_DIR"
if [[ "$EVENTS" == true && -z "$EVENTS_DIR" ]]; then
    # Sans domaine, les étapes R prennent la campagne la plus récente : les événements aussi.
    EVENTS_DIR="$("$PYTHON_BIN" -c 'import sys; sys.path.insert(0, sys.argv[1]); import exposia_paths; print(exposia_paths.latest_domain_dir() or "")' "$MODULES_DIR" 2>/dev/null)"
    [[ -z "$CAMPAIGN" && -n "$EVENTS_DIR" ]] && CAMPAIGN="$(basename "$EVENTS_DIR")"
fi
EXPOSIA_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${CAMPAIGN:-campagne}"
export EXPOSIA_RUN_ID
if [[ "$EVENTS" == true ]]; then
    if [[ -z "$EVENTS_DIR" ]]; then
        log_warn "--events : aucune campagne trouvée, événements non écrits."
    elif mkdir -p "$EVENTS_DIR/data" && : > "$EVENTS_DIR/data/events.jsonl"; then
        EXPOSIA_EVENTS="$EVENTS_DIR/data/events.jsonl"
        export EXPOSIA_EVENTS
        log_info "Événements : $EXPOSIA_EVENTS"
    else
        log_warn "--events : $EVENTS_DIR/data/events.jsonl impossible à créer, événements non écrits."
    fi
fi
emit_event run_started "domain=${DOMAIN}" "campaign=${CAMPAIGN}" "lang=${EXPOSIA_LANG}"
# Fin du run, y compris sur arrêt après une étape en échec : livrables présents.
on_exit() {
    local rc=$? outputs="" f
    if [[ -n "$EXPOSIA_EVENTS" ]]; then
        if [[ -n "$EVENTS_DIR" ]]; then
            for f in "$EVENTS_DIR"/Rapport_Final_*.pdf "$EVENTS_DIR"/Final_Report_*.pdf "$EVENTS_DIR"/Exposia_*_results.json \
                     "$EVENTS_DIR"/Exposia_*_digest.md "$EVENTS_DIR"/Exposia_*_presentation.csv; do
                [[ -e "$f" && "$(stat -c %Y "$f")" -ge "$PIPELINE_START" ]] || continue
                case "$f" in
                    *.pdf) outputs+="report:$(basename "$f")," ;;
                    *_results.json) outputs+="results:$(basename "$f")," ;;
                    *_digest.md) outputs+="digest:$(basename "$f")," ;;
                    *_presentation.csv) outputs+="presentation:$(basename "$f")," ;;
                esac
            done
        fi
        emit_event run_finished "status=$([[ $rc -eq 0 ]] && echo ok || echo failed)" "rc=$rc" \
            "duration_s=$(( $(date +%s) - PIPELINE_START ))" "campaign_dir=${EVENTS_DIR}" "outputs=${outputs%,}"
    fi
}
trap on_exit EXIT
run_step() {
    local label="$1"; shift
    # Étape = préfixe du script (D1, R13…), pour les événements --events.
    local step="" arg t0
    for arg in "$@"; do
        [[ "$arg" =~ /([DR][0-9]+)_[^/]*\.py$ ]] && { step="${BASH_REMATCH[1]}"; break; }
    done
    export EXPOSIA_STEP="$step"
    emit_event step_started "step=$step"
    t0=$(date +%s)
    if "$@"; then
        emit_event step_finished "step=$step" status=ok rc=0 "duration_s=$(( $(date +%s) - t0 ))"
        log_ok "$label terminé"
    else
        local rc=$?
        emit_event step_finished "step=$step" status=failed "rc=$rc" "duration_s=$(( $(date +%s) - t0 ))"
        log_err "$label a échoué (code $rc)"
        PIPELINE_RC=$rc
        if [[ "$CONTINUE_ON_ERROR" == false ]]; then
            log_info "Arrêt du pipeline (--continue-on-error pour poursuivre)."
            exit "$rc"
        fi
        return "$rc"
    fi
}

# Argument de campagne pour les étapes qui l'acceptent
res_args=()
[[ -n "$RESULT_DIR" ]] && res_args=(--result-dir "$RESULT_DIR")

# === D1 : Asset discovery ====================================================
if [[ "$SKIP_DISCOVERY" == true ]]; then
    log_step "D1 — asset_discovery_assessment ${C_DIM}(ignoré)${C_RESET}"
    emit_event step_skipped step=D1 reason=option
else
    log_step "D1 — asset_discovery_assessment"
    d1_args=("$DOMAIN")
    [[ "$RESOLVE_IPS" == true ]] && d1_args+=(--resolve-ips)
    run_step "Asset discovery" "$PYTHON_BIN" "$D_DIR/D1_asset_discovery_assessment.py" "${d1_args[@]}"
fi

# === D2 : Mitigation plan ====================================================
if [[ "$SKIP_MITIGATION" == true ]]; then
    log_step "D2 — mitigation_plan ${C_DIM}(ignoré)${C_RESET}"
    emit_event step_skipped step=D2 reason=option
else
    log_step "D2 — mitigation_plan"
    run_step "Mitigation plan" "$PYTHON_BIN" "$D_DIR/D2_mitigation_plan.py" ${res_args[@]+"${res_args[@]}"}
fi

# === D3 : Threat modeling ===================================================
# APRÈS D1/D2 : D3 lit la note ASM (criticité du domaine) produite par D1.
# Profil passé en options ; un champ absent est demandé au clavier.
if [[ "$SKIP_THREAT" == true ]]; then
    log_step "D3 — threat_modeling ${C_DIM}(ignoré)${C_RESET}"
    emit_event step_skipped step=D3 reason=option
else
    if [[ "$PROFILE_COMPLETE" == true ]]; then
        log_step "D3 — threat_modeling ${C_DIM}(profil : $SECTEUR, $TAILLE, $ZONE)${C_RESET}"
    else
        log_step "D3 — threat_modeling ${C_DIM}(interactif)${C_RESET}"
    fi
    d3_args=(${res_args[@]+"${res_args[@]}"} ${d3_profile_args[@]+"${d3_profile_args[@]}"})
    [[ -n "$DOMAIN" && -z "$RESULT_DIR" ]] && d3_args+=(--domain "$DOMAIN")
    _d3_t0=$(date +%s)
    run_step "Threat modeling" "$PYTHON_BIN" "$D_DIR/D3_threat_modeling.py" ${d3_args[@]+"${d3_args[@]}"}
    # Saisie au clavier exclue du temps de traitement ; sans saisie, D3 compte.
    [[ "$PROFILE_COMPLETE" == false ]] && D3_SECONDS=$(( $(date +%s) - _d3_t0 ))
fi

# === R1..R6 : Génération des parties du rapport ==============================
if [[ "$SKIP_REPORT" == true ]]; then
    log_step "R1..R9 — génération du rapport ${C_DIM}(ignorée)${C_RESET}"
    for s in R5 R7 R1 R2 R3 R4 R6 R8 R9; do emit_event step_skipped "step=$s" reason=option; done
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

# === R13 : JSON canonique des résultats =====================================
# Indépendant des PDF : calculé depuis data/ par les mêmes fonctions que le
# rapport. Écrit Exposia_<campagne>_results.json à la racine de la campagne.
log_step "R13 — results_json ${C_DIM}(JSON canonique)${C_RESET}"
R13_OK=false
run_step "JSON canonique" "$PYTHON_BIN" "$R_DIR/R13_results_json.py" ${res_args[@]+"${res_args[@]}"} && R13_OK=true

# === R12 : Digest pour assistant IA ==========================================
# Lit le JSON que R13 vient d'écrire : ignoré si R13 a échoué (--continue-on-error),
# pour ne jamais résumer le JSON d'un run précédent. Lecture seule, aucun accès réseau.
if [[ "$R13_OK" == true ]]; then
    log_step "R12 — llm_digest ${C_DIM}(digest pour assistant IA)${C_RESET}"
    run_step "Digest IA" "$PYTHON_BIN" "$R_DIR/R12_llm_digest.py" ${res_args[@]+"${res_args[@]}"}
else
    log_step "R12 — llm_digest ${C_DIM}(ignoré : R13 a échoué)${C_RESET}"
    emit_event step_skipped step=R12 reason=dependency_failed
fi

# === R10 : Vue présentation (livrable CSV exposition×CVE) ====================
# Export de données indépendant des PDF : il tourne même avec --skip-report,
# tant qu'un Exposia_*.csv de travail existe (produit par D1/D2 ou un run
# précédent). Dépose le CSV à la racine de la campagne, près du Rapport_Final.
# Dernière étape : R10 affiche la SYNTHÈSE du run, temps de traitement compris.
if [[ "$SKIP_PRESENTATION" == true ]]; then
    log_step "R10 — presentation_export ${C_DIM}(ignoré)${C_RESET}"
    emit_event step_skipped step=R10 reason=option
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
