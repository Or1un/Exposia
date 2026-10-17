import requests
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import exposia_paths  # résolution centralisée des chemins
import exposia_ui  # UI console centralisée (Colors, ModernUI)
from exposia_ui import Colors, ModernUI
import exposia_config  # clés API (config.yaml à la racine du projet)
import csv
import json
import re
import socket
import time
import shodan
import pandas as pd
import os
import argparse
import math
import random
import hashlib
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from tqdm import tqdm
from typing import Dict, Optional, Tuple

class CVEAnalyzer:
    def __init__(self, nvd_api_key=None):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Limite NVD : 5 requêtes / 30 s sans clé API (=> 6 s entre deux requêtes),
        # 50 requêtes / 30 s avec une clé (=> 0,6 s). Clé lue dans config.yaml
        # (api_keys.nvd), jamais en clair dans le code ni sur la ligne de commande.
        self.nvd_api_key = nvd_api_key or None
        self.delay_between_requests = 0.7 if self.nvd_api_key else 6.0
        self.cve_cache = {}  # Cache mémoire du run (évite les doublons d'appels)

    NVD_RETRY_STATUSES = (403, 429, 503)  # refus / limitation NVD => nouvelle tentative
    NVD_RETRY_WAIT = 35           # attente avant nouvelle tentative (fenêtre NVD = 30 s)
    NVD_MAX_ATTEMPTS = 3

    def get_cvss_info(self, cve_id: str) -> Optional[Dict]:
        """Données CVSS d'une CVE (version, vecteur, score, composantes), ou None."""
        cve_data = self.get_cve_info_from_nvd(cve_id)
        if not cve_data:
            return None
        return self.extract_cvss_info(cve_data)

    def load_mapping_files(self):
        """Charge les fichiers de mapping CVSS"""
        try:
            self.step1_mapping = pd.read_csv(exposia_paths.parameter('CVSS', 'CVSS_step1.csv'), sep=';')
            self.step2_mapping = pd.read_csv(exposia_paths.parameter('CVSS', 'CVSS_step2.csv'), sep=';')
            self.step3_mapping = pd.read_csv(exposia_paths.parameter('CVSS', 'CVSS_step3.csv'), sep=';')
            self.step3_attenuation = pd.read_csv(exposia_paths.parameter('CVSS', 'CVSS_step3_attenuation.csv'), sep=';')
            return True
        except Exception as e:
            print(f"Error loading CVSS mapping files: {e}")
            return False

    def get_cve_info_from_nvd(self, cve_id: str) -> Optional[Dict]:
        """Récupère les informations d'une CVE depuis NVD"""
        try:
            url = f"{self.nvd_base_url}?cveId={cve_id}"
            headers = {
                'User-Agent': 'CVE-Analyzer-Tool/1.0'
            }
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            for attempt in range(self.NVD_MAX_ATTEMPTS):
                response = requests.get(url, headers=headers, timeout=30)
                time.sleep(self.delay_between_requests)  # Respect du rate limit

                if response.status_code == 200:
                    data = response.json()
                    if data.get('totalResults', 0) > 0:
                        return data['vulnerabilities'][0]['cve']
                    return None
                if response.status_code in self.NVD_RETRY_STATUSES and attempt < self.NVD_MAX_ATTEMPTS - 1:
                    # Limitation NVD : on attend la fin de la fenêtre au lieu de
                    # perdre silencieusement la CVE.
                    time.sleep(self.NVD_RETRY_WAIT)
                    continue
                print(f"NVD: {cve_id} non récupérée (HTTP {response.status_code})")
                return None
            return None

        except Exception as e:
            print(f"Erreur lors de la récupération de {cve_id}: {e}")
            return None

    def extract_cvss_info(self, cve_data: Dict) -> Dict:
        """Extrait les informations CVSS de la réponse NVD"""
        result = {
            'cvss_version': None,
            'cvss_vector': None,
            'cvss_score': None,
            'av': None, 'ac': None, 'pr': None, 'ui': None,
            's': None, 'c': None, 'i': None, 'a': None
        }

        # Recherche des métriques CVSS dans l'ordre de préférence (3.1, 3.0, 2.0)
        metrics = cve_data.get('metrics', {})

        # CVSS v3.1
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            result.update(self._parse_cvss3_data(cvss_data, '3.1'))

        # CVSS v3.0
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            result.update(self._parse_cvss3_data(cvss_data, '3.0'))

        # CVSS v2.0
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            result.update({
                'cvss_version': '2.0',
                'cvss_vector': cvss_data.get('vectorString', ''),
                'cvss_score': cvss_data.get('baseScore', 0)
            })

        return result

    def _parse_cvss3_data(self, cvss_data: Dict, version: str) -> Dict:
        """Parse les données CVSS v3.x"""
        return {
            'cvss_version': version,
            'cvss_vector': cvss_data.get('vectorString', ''),
            'cvss_score': cvss_data.get('baseScore', 0),
            'av': cvss_data.get('attackVector', '').upper()[0] if cvss_data.get('attackVector') else None,
            'ac': cvss_data.get('attackComplexity', '').upper()[0] if cvss_data.get('attackComplexity') else None,
            'pr': cvss_data.get('privilegesRequired', '').upper()[0] if cvss_data.get('privilegesRequired') else None,
            'ui': cvss_data.get('userInteraction', '').upper()[0] if cvss_data.get('userInteraction') else None,
            's': cvss_data.get('scope', '').upper()[0] if cvss_data.get('scope') else None,
            'c': cvss_data.get('confidentialityImpact', '').upper()[0] if cvss_data.get('confidentialityImpact') else None,
            'i': cvss_data.get('integrityImpact', '').upper()[0] if cvss_data.get('integrityImpact') else None,
            'a': cvss_data.get('availabilityImpact', '').upper()[0] if cvss_data.get('availabilityImpact') else None
        }

    def apply_step1_mapping(self, av_value: str) -> Tuple[str, str]:
        """Applique le mapping de l'étape 1 (Attack Vector)"""
        if not av_value:
            return "", ""

        match = self.step1_mapping[self.step1_mapping['Valeur'] == av_value]
        if not match.empty:
            return match.iloc[0]['Reconnaissance (Étape 1)'], match.iloc[0]['Tags Mappés']
        return "", ""

    def apply_step2_mapping(self, ac_value: str, pr_value: str, ui_value: str) -> Tuple[str, str]:
        """Applique le mapping de l'étape 2 avec combinaisons fluides (AC+PR+UI)"""
        if not all([ac_value, pr_value, ui_value]):
            return "", ""

        # Créer la clé de combinaison
        combination_key = f"AC:{ac_value}+PR:{pr_value}+UI:{ui_value}"

        # Chercher la combinaison dans le mapping
        match = self.step2_mapping[self.step2_mapping['Combinaison'] == combination_key]

        if not match.empty:
            description = match.iloc[0]['Modificateur Exploitation (Étape 2)']
            tags = match.iloc[0]['Tags Mappés']
            return description, tags

        # Fallback si combinaison non trouvée
        return f"Il exploite cette vulnérabilité (AC:{ac_value}, PR:{pr_value}, UI:{ui_value})", "exploitation_code"

    def apply_step3_mapping(self, c_value: str, i_value: str, a_value: str) -> Tuple[str, str, str]:
        """Applique le mapping de l'étape 3 (Impact CIA)"""
        if not all([c_value, i_value, a_value]):
            return "", "", ""

        match = self.step3_mapping[
            (self.step3_mapping['Confidentialité'] == c_value) &
            (self.step3_mapping['Intégrité'] == i_value) &
            (self.step3_mapping['Disponibilité'] == a_value)
        ]

        if not match.empty:
            return (
                match.iloc[0]['Impact Métier (Étape 3)'],
                match.iloc[0]['Tags Mappés'],
                match.iloc[0]['Criticité']
            )
        return "", "", ""

    def apply_attenuation(self, s_value: str, base_criticite: str) -> str:
        """Applique l'atténuation basée sur le Scope"""
        if not s_value or not base_criticite:
            return base_criticite

        match = self.step3_attenuation[self.step3_attenuation['Valeur'] == s_value]
        if not match.empty:
            impact = match.iloc[0]['Impact Criticité']
            if '+1 niveau de criticité' in str(impact) and s_value == 'C':
                # Logique d'augmentation de criticité
                criticite_levels = ['NÉGLIGEABLE', 'TRÈS FAIBLE', 'FAIBLE', 'MOYEN', 'ÉLEVÉ', 'CRITIQUE']
                try:
                    current_index = criticite_levels.index(base_criticite)
                    if current_index < len(criticite_levels) - 1:
                        return criticite_levels[current_index + 1]
                except ValueError:
                    pass

        return base_criticite

class SubdomainScanner:
    EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
    GITHUB_API_URL = "https://poc-in-github.motikan2010.net/api/v1/"
    EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"

    # Critères de classification interne/externe (partagés par toutes les méthodes)
    INTERNAL_SUBDOMAIN_KEYWORDS = ['admin', 'dev', 'test', 'internal', 'intranet', 'staging', 'priv', 'private']
    # Conteneurs et orchestration (kubelet, API Kubernetes, etcd, API Docker) :
    # interfaces d'administration d'infrastructure, jamais destinées à Internet.
    # Codé en dur pour l'instant ; à terme, une colonne de services_list.csv.
    INTERNAL_SERVICE_KEYWORDS = ['ssh', 'mysql', 'postgresql', 'mssql', 'rdp', 'snmp', 'ftp', 'telnet', 'ldap',
                                 'kubelet', 'kubernetes', 'etcd', 'docker']
    INTERNAL_PORTS = [22, 1433, 3306, 3389, 5432, 161, 21, 23, 389, 636, 1521, 5984, 6379, 11211, 27017,
                      2375, 2376, 2379, 2380, 6443, 10250, 10255]
    _NA_VALUES = ['#n/a', 'nan', '']
    # Noms issus des journaux de transparence des certificats : données NON fiables.
    # Seuls les noms d'hôte syntaxiquement valides sont conservés (pas de balisage, d'espace, d'URL).
    HOSTNAME_RE = re.compile(r'^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$')
    _CRIT_RANK = {'FAIBLE': 0, 'MOYENNE': 1, 'HAUTE': 2, 'CRITIQUE': 3}

    # Plancher de qualification : une CVE pour laquelle au moins un exploit public
    # est référencé (ExploitDB ou PoC-in-GitHub) n'est jamais qualifiée en dessous
    # d'un niveau qui dépend de sa gravité CVSS. L'existence d'un exploit est un
    # fait observé ; l'EPSS, qui pèse 60 % du score, est une estimation qui peut
    # rester basse pour une faille pourtant exploitable clé en main. Le plancher
    # est conditionné au CVSS pour ne pas porter en High une faille mineure dotée
    # d'un simple PoC. Règles lues dans l'ordre : (CVSS minimal, plancher) ; un
    # CVSS inconnu vaut 0. Une liste vide désactive le plancher.
    EXPLOIT_FLOOR_RULES = ((7.0, 'High'), (0.0, 'Medium'))
    _QUALIFICATION_ORDER = ['Low', 'Medium', 'High', 'Critical']

    # CDN : derrière un CDN, les IP résolues sont celles des frontaux du
    # fournisseur, partagées par tous ses clients. Les ports qu'ils ouvrent
    # (2052, 2053, 2082, 2086, 8080, 8443, 8880…) et les CVE qu'y voit Shodan
    # décrivent le CDN, pas l'organisation. Pour un sous-domaine servi par un
    # CDN, on ne garde donc qu'une exposition par port web standard, sans CVE,
    # rattachée à une IP représentative. Plages : Parameters/cdn_ranges.csv.
    CDN_EDGE_PORTS = ('80', '443')

    # Colonnes propres à une vulnérabilité : vidées sur les lignes de chemin
    # d'attaque générique (PORT), qui ne décrivent pas la CVE de la ligne source.
    CVE_SPECIFIC_COLUMNS = {
        "Vulnerability (CVE)": "#N/A",
        "Number of Exploits": 0,
        "CVE - Year": "#N/A",
        "CVSS Score": "#N/A",
        "EPSS Score": "#N/A",
        "Exploits": "#N/A",
        "CVSS_Version": "#N/A",
        "CVSS_Vector": "#N/A",
    }

    def __init__(self, domain, nvd_api_key=None):
        self.domain = domain
        self.session = self._create_session()
        self.ui = ModernUI()
        self.service_matrix = self.load_service_matrix()
        self.cve_analyzer = CVEAnalyzer(nvd_api_key)
        self.cvss_mapping_available = self.cve_analyzer.load_mapping_files()
        # Index ExploitDB {cve_id: [exploit_ids]} chargé paresseusement une seule fois.
        # None = pas encore tenté ; {} = chargé (éventuellement vide / échec).
        self._exploitdb_index = None
        # Échecs par source d'enrichissement (EPSS, PoC-in-GitHub), pour le bilan
        # affiché en fin de recherche d'exploits.
        self.enrichment_failures = {"EPSS": 0, "PoC-in-GitHub": 0}
        # Plages et ASN des CDN, ASN par IP (rempli depuis resultats_shodan.csv),
        # et bilan du regroupement.
        self.ip_asn = {}
        self.cdn_networks = self.load_cdn_ranges()
        self.cdn_stats = {"subdomains": 0, "ips": set(), "rows_dropped": 0}

    # ------------------------------------------------------------------
    # CDN : détection et regroupement des frontaux partagés
    # ------------------------------------------------------------------
    def load_cdn_ranges(self, path=None):
        """
        CDN connus, depuis Parameters/cdn_ranges.csv (colonnes Fournisseur;Plage).
        « Plage » est soit un réseau (104.16.0.0/13, 2606:4700::/32), soit un numéro
        d'AS (AS13335) : l'ASN, renvoyé par Shodan pour chaque IP, couvre les
        adresses absentes des listes publiées (BYOIP, résolveur public…).
        Remplit self.cdn_asns ; renvoie la liste des réseaux.
        Fichier absent => regroupement désactivé.
        """
        path = path or exposia_paths.parameter('cdn_ranges.csv')
        networks = []
        self.cdn_asns = {}
        if not os.path.exists(path):
            self.ui.status("cdn_ranges.csv not found - CDN edge grouping disabled", "warning")
            return networks
        try:
            with open(path, encoding='utf-8', newline='') as f:
                for row in csv.DictReader(f, delimiter=';'):
                    try:
                        provider, value = row['Fournisseur'].strip(), row['Plage'].strip()
                        if value.upper().startswith('AS'):
                            self.cdn_asns[value.upper()] = provider
                        else:
                            networks.append((provider, ipaddress.ip_network(value, strict=False)))
                    except (KeyError, ValueError, AttributeError):
                        self.ui.status(f"Ligne ignorée dans cdn_ranges.csv : {row}", "warning")
        except OSError as e:
            self.ui.status(f"Lecture de cdn_ranges.csv impossible : {e}", "warning")
        return networks

    def cdn_provider(self, ip):
        """Nom du CDN auquel appartient l'IP (par plage, puis par ASN Shodan), ou None."""
        ip = str(ip).strip()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for provider, network in self.cdn_networks:
            if addr.version == network.version and addr in network:
                return provider
        asn = self.ip_asn.get(ip, '')
        return self.cdn_asns.get(asn.upper()) if asn else None

    @staticmethod
    def _ip_sort_key(ip):
        """Tri stable des IP : IPv4 avant IPv6, puis ordre numérique."""
        try:
            addr = ipaddress.ip_address(str(ip))
            return (addr.version, int(addr))
        except ValueError:
            return (99, 0)

    @staticmethod
    def _norm_port_str(value):
        try:
            return str(int(float(value)))
        except (ValueError, TypeError):
            return '#N/A'

    def _ip_jobs(self, ips, shodan_data):
        """
        Couples (ip, données Shodan) à traiter pour un sous-domaine.

        IP directes : une tâche par IP, données Shodan telles quelles.
        IP de CDN : une seule tâche, sur l'IP représentative (la plus petite) :
        uniquement les ports CDN_EDGE_PORTS, sans CVE, un port une seule fois,
        quel que soit le nombre de frontaux résolus.
        """
        direct = [ip for ip in ips if not self.cdn_provider(ip)]
        cdn = sorted((ip for ip in ips if self.cdn_provider(ip)), key=self._ip_sort_key)

        def rows_for(ip_list):
            if shodan_data.empty:
                return pd.DataFrame()
            return shodan_data[shodan_data["IP Address"].isin(ip_list)]

        for ip in direct:
            yield ip, rows_for([ip])

        if not cdn:
            return
        rep = cdn[0]
        self.cdn_stats["subdomains"] += 1
        self.cdn_stats["ips"].update(cdn)
        raw = rows_for(cdn)
        if raw.empty:
            yield rep, raw
            return
        raw = raw.copy()
        raw["_port"] = raw["Port"].map(self._norm_port_str)
        kept = raw[raw["_port"].isin(self.CDN_EDGE_PORTS)]
        kept = kept.drop_duplicates(subset="_port").copy()
        self.cdn_stats["rows_dropped"] += len(raw) - len(kept)
        # Les CVE vues sur un frontal de CDN concernent le fournisseur.
        kept["Vulnerability (CVE)"] = "None"
        kept["CVSS Score"] = "#N/A"
        kept["IP Address"] = rep
        yield rep, kept.drop(columns=["_port"])

    def _create_session(self):
        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        return session

    def get_main_domain(self, domain):
        """Nom de campagne (dossier Result/ et fichiers Exposia_<nom>.csv) :
        règle unique définie dans exposia_paths.main_domain."""
        return exposia_paths.main_domain(domain)

    # ------------------------------------------------------------------
    # Découverte de sous-domaines (Certificate Transparency)
    # ------------------------------------------------------------------
    CT_CACHE_TTL = 24 * 3600          # durée de validité du cache local (s)
    CRTSH_MAX_ATTEMPTS = 3            # tentatives par requête crt.sh
    CRTSH_WAITS = [30, 60]            # attentes sur 429 si pas de Retry-After (s)

    def _ct_get_json(self, url, source):
        """
        GET JSON avec gestion manuelle du 429 (sans les réessais rapides de la session,
        qui prolongent le blocage). Retourne (data, rate_limited).
        """
        headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
        for attempt in range(self.CRTSH_MAX_ATTEMPTS):
            try:
                response = requests.get(url, timeout=60, headers=headers)
            except requests.RequestException as e:
                self.ui.status(f"{source} unreachable: {e}", "warning")
                return None, False
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == self.CRTSH_MAX_ATTEMPTS - 1:
                    return None, response.status_code == 429
                retry_after = response.headers.get('Retry-After', '')
                wait = int(retry_after) if retry_after.isdigit() else self.CRTSH_WAITS[min(attempt, len(self.CRTSH_WAITS) - 1)]
                wait = min(wait, 300)
                self.ui.status(f"{source} returned HTTP {response.status_code} - waiting {wait}s before retry "
                               f"({attempt + 2}/{self.CRTSH_MAX_ATTEMPTS})", "warning")
                time.sleep(wait + random.uniform(0, 3))
                continue
            try:
                response.raise_for_status()
                return response.json(), False
            except (requests.RequestException, ValueError) as e:
                self.ui.status(f"{source} query failed: {e}", "warning")
                return None, False
        return None, False

    def _clean_names(self, names):
        """Normalise et filtre les noms issus des certificats (wildcards, hors périmètre)."""
        cleaned = set()
        for name in names:
            sub = name.strip().lower().rstrip('.')
            if not sub or sub.startswith('*.'):
                continue
            if not self.HOSTNAME_RE.match(sub):
                continue
            if sub == self.domain or sub.endswith('.' + self.domain):
                cleaned.add(sub)
        return cleaned

    def _query_crtsh(self):
        queries = [
            f"https://crt.sh/?q=%25.{self.domain}&output=json",
            f"https://crt.sh/?q={self.domain}&output=json"
        ]
        found = set()
        for i, query in enumerate(queries):
            if i > 0:
                # crt.sh limite le débit par IP : deux requêtes rapprochées => 429
                time.sleep(random.uniform(5, 10))
            self.ui.status("Querying certificate database (crt.sh)...", "info")
            entries, rate_limited = self._ct_get_json(query, "crt.sh")
            if entries is None:
                if rate_limited:
                    # Inutile d'insister : chaque requête prolonge le blocage
                    self.ui.status("crt.sh is rate-limiting this IP - skipping remaining crt.sh queries", "warning")
                    break
                continue
            subs = self._clean_names(
                sub for entry in entries for sub in entry.get("name_value", "").splitlines()
            )
            found.update(subs)
            self.ui.status(f"Found {len(subs)} subdomains via crt.sh (after filtering)", "success")
        return found

    def _query_certspotter(self):
        self.ui.status("Querying fallback CT source (Cert Spotter)...", "info")
        url = (f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
               f"&include_subdomains=true&expand=dns_names")
        entries, _ = self._ct_get_json(url, "Cert Spotter")
        if not entries:
            return set()
        subs = self._clean_names(name for entry in entries for name in entry.get("dns_names", []))
        self.ui.status(f"Found {len(subs)} subdomains via Cert Spotter (after filtering)", "success")
        return subs

    def get_subdomains(self):
        self.ui.status(f"Starting scan for {self.domain}", "info")
        cache_file = f"crtsh_cache_{self.domain}.json"

        # 1. Cache local récent => pas d'appel réseau
        try:
            if os.path.exists(cache_file) and time.time() - os.path.getmtime(cache_file) < self.CT_CACHE_TTL:
                with open(cache_file, encoding="utf-8") as f:
                    cached = json.load(f)
                if cached:
                    age_h = (time.time() - os.path.getmtime(cache_file)) / 3600
                    self.ui.status(f"Using cached CT results ({len(cached)} subdomains, {age_h:.1f}h old) - "
                                   f"delete {cache_file} to force a fresh query", "info")
                    return sorted(cached)
        except (OSError, ValueError):
            pass

        # 2. crt.sh, puis 3. Cert Spotter en secours
        subdomains = self._query_crtsh()
        if not subdomains:
            subdomains = self._query_certspotter()

        if subdomains:
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(sorted(subdomains), f)
            except OSError:
                pass
        else:
            self.ui.status("No CT source answered - wait a few minutes (crt.sh blocks for a while) and retry", "warning")
        return sorted(subdomains)

    def resolve_ips(self, subdomains):
        self.ui.status("Resolving IP addresses...", "info")
        results = []
        all_ips = set()
        filtered_subdomains = [sub for sub in subdomains if not sub.startswith('*.')]
        progress_bar = self.ui.tqdm_progress(
            filtered_subdomains,
            desc="Resolving IPs",
            total=len(filtered_subdomains),
            unit="subs",
            ip_counter=0
        )
        for sub in progress_bar:
            try:
                addr_info = socket.getaddrinfo(sub, None)
                ips = sorted({ai[4][0] for ai in addr_info})
                if ips:
                    results.extend((sub, ip) for ip in ips)
                    all_ips.update(ips)
                    progress_bar.postfix[0] = len(all_ips)
                else:
                    results.append((sub, None))
            except (socket.gaierror, socket.herror):
                results.append((sub, None))
        progress_bar.close()
        return results, all_ips

    def export_results(self, subdomains, ip_data, all_ips):
        try:
            base_name = "results"
            filtered_subdomains = [sub for sub in subdomains if not sub.startswith('*.')]
            filtered_ip_data = [(sub, ip) for sub, ip in ip_data if not sub.startswith('*.')]
            filtered_ips = {ip for ip in all_ips if ip}
            with open(f"{base_name}_subdomains_with_ips.csv", 'w', newline='') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(["Subdomain", "IP Address"])
                resolved_subdomains = {}
                for sub, ip in filtered_ip_data:
                    if sub not in resolved_subdomains:
                        resolved_subdomains[sub] = []
                    if ip:
                        resolved_subdomains[sub].append(ip)
                for sub in filtered_subdomains:
                    ips = resolved_subdomains.get(sub, [])
                    if ips:
                        for ip in ips:
                            writer.writerow([sub, ip])
                    else:
                        writer.writerow([sub, "No IP found"])
            self.ui.status(f"Exported full results to {base_name}_subdomains_with_ips.csv", "success")
            with open(f"{base_name}_subdomains_only.csv", 'w', newline='') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(["Subdomain"])
                writer.writerows([sub] for sub in filtered_subdomains)
            self.ui.status(f"Exported subdomains to {base_name}_subdomains_only.csv", "success")
            with open(f"{base_name}_ips_only.csv", 'w', newline='') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(["IP Address"])
                writer.writerows([ip] for ip in sorted(filtered_ips))
            self.ui.status(f"Exported IPs to {base_name}_ips_only.csv", "success")
            return True
        except Exception as e:
            self.ui.status(f"Export failed: {str(e)}", "error")
            return False

    def shodan_query(self, api_key, all_ips):
        self.ui.status("Starting vulnerability scan...", "info")
        try:
            masked_key = "****"  # aucun fragment de la clé dans la console / les journaux
            self.ui.status(f"Using Shodan API Key: {masked_key}", "info")
            api = shodan.Shodan(api_key)
            try:
                api.info()
                ModernUI.status("Shodan API key is valid", "success")
            except shodan.APIError as e:
                ModernUI.status(f"Invalid Shodan API key: {e}", "error")
                return 0, 0, 0
            csv_filename = "resultats_shodan.csv"
            cve_filename = "cve_identifies.csv"
            cve_set = set()
            vulnerabilities_found = 0
            scanned_ips = 0
            failed_ips = 0
            ip_list = list(all_ips)
            with open(csv_filename, "w", newline="") as csvfile:
                # ASN : sert à reconnaître les frontaux de CDN (voir cdn_provider).
                fieldnames = ["IP Address", "Port", "Vulnerability (CVE)", "CVSS Score", "Status", "ASN"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
                writer.writeheader()
                progress_bar = self.ui.tqdm_progress(
                    ip_list,
                    desc="Scanning IPs",
                    total=len(ip_list),
                    unit="IPs"
                )
                for ip in progress_bar:
                    try:
                        result = api.host(ip)
                        scanned_ips += 1
                        asn = str(result.get('asn') or '')
                        if not result.get('data'):
                            writer.writerow({
                                "IP Address": ip,
                                "Port": "#N/A",
                                "Vulnerability (CVE)": "No data",
                                "CVSS Score": "#N/A",
                                "Status": "No data",
                                "ASN": asn
                            })
                            continue
                        for item in result.get('data', []):
                            port_raw = item.get('port', '#N/A')
                            try:
                                port = str(int(float(port_raw))) if str(port_raw).replace('.', '').isdigit() else '#N/A'
                            except (ValueError, TypeError):
                                port = '#N/A'
                            if "vulns" in item:
                                for cve in item["vulns"]:
                                    cvss_score = item["vulns"][cve].get("cvss", "Unknown")
                                    writer.writerow({
                                        "IP Address": ip,
                                        "Port": port,
                                        "Vulnerability (CVE)": cve,
                                        "CVSS Score": str(cvss_score),
                                        "Status": "Success",
                                        "ASN": asn
                                    })
                                    cve_set.add(cve)
                                    vulnerabilities_found += 1
                            else:
                                writer.writerow({
                                    "IP Address": ip,
                                    "Port": port,
                                    "Vulnerability (CVE)": "None",
                                    "CVSS Score": "#N/A",
                                    "Status": "No vulns",
                                    "ASN": asn
                                })
                    except shodan.APIError:
                        failed_ips += 1
                        writer.writerow({
                            "IP Address": ip,
                            "Port": "#N/A",
                            "Vulnerability (CVE)": "#N/A",
                            "CVSS Score": "#N/A",
                            "Status": "Failed"
                        })
                    except Exception as e:
                        failed_ips += 1
                        writer.writerow({
                            "IP Address": ip,
                            "Port": "#N/A",
                            "Vulnerability (CVE)": f"Error: {str(e)}",
                            "CVSS Score": "#N/A",
                            "Status": "Error"
                        })
                progress_bar.close()
            self.ui.status(f"Exported results to {csv_filename}", "success")
            if cve_set:
                with open(cve_filename, "w", newline="") as cve_file:
                    writer = csv.writer(cve_file, delimiter=';')
                    writer.writerow(["CVE ID"])
                    for cve in cve_set:
                        writer.writerow([cve])
                self.ui.status(f"Exported list of unique CVEs to {cve_filename}", "success")
            else:
                with open(cve_filename, "w", newline="") as cve_file:
                    writer = csv.writer(cve_file, delimiter=';')
                    writer.writerow(["CVE ID"])
                self.ui.status(f"No vulnerabilities found - created empty {cve_filename}", "info")
            return vulnerabilities_found, len(cve_set), scanned_ips
        except Exception as e:
            self.ui.status(f"Unexpected error: {str(e)}", "error")
            return 0, 0, 0

    def analyze_cves_from_file(self, cve_file="cve_identifies.csv"):
        """Analyse automatique des CVE après scan Shodan"""
        if not self.cvss_mapping_available:
            self.ui.status("CVSS mapping files not available - skipping CVE narrative analysis", "warning")
            return {}

        if not os.path.exists(cve_file):
            self.ui.status("No CVE file found - skipping CVE analysis", "info")
            return {}

        try:
            df_cves = pd.read_csv(cve_file, sep=';')
            unique_cves = df_cves['CVE ID'].unique()

            if len(unique_cves) == 0:
                return {}

            if not self.cve_analyzer.nvd_api_key:
                eta_min = math.ceil(len(unique_cves) * self.cve_analyzer.delay_between_requests / 60)
                self.ui.status(f"No NVD API key (api_keys.nvd in config.yaml, or NVD_API_KEY): NVD rate limit applies (~{eta_min} min for "
                               f"{len(unique_cves)} CVEs). Add api_keys.nvd to speed this up.", "warning")

            self.ui.status(f"Analyzing {len(unique_cves)} unique CVEs with narrative mapping...", "info")

            cve_narratives = {}
            progress_bar = self.ui.tqdm_progress(
                unique_cves,
                desc="CVE Analysis",
                total=len(unique_cves),
                unit="CVEs"
            )

            for cve_id in progress_bar:
                if cve_id in self.cve_analyzer.cve_cache:
                    cve_narratives[cve_id] = self.cve_analyzer.cve_cache[cve_id]
                    continue

                cvss_info = self.cve_analyzer.get_cvss_info(cve_id)

                if cvss_info:
                    narrative_data = {
                        'CVSS_Version': cvss_info['cvss_version'],
                        'CVSS_Vector': cvss_info['cvss_vector'],
                        'CVSS_Score': cvss_info['cvss_score'],
                        'Step1_Description': '#N/A',
                        'Step1_Tags': '#N/A',
                        'Step2_Description': '#N/A',
                        'Step2_Tags': '#N/A',
                        'Step3_Description': '#N/A',
                        'Step3_Tags': '#N/A',
                        'Base_Criticite': '#N/A',
                        'Final_Criticite': '#N/A'
                    }

                    # Si version 3.x, appliquer les mappings
                    if cvss_info['cvss_version'] and cvss_info['cvss_version'].startswith('3.'):
                        step1_desc, step1_tags = self.cve_analyzer.apply_step1_mapping(cvss_info['av'])
                        step2_desc, step2_tags = self.cve_analyzer.apply_step2_mapping(
                            cvss_info['ac'], cvss_info['pr'], cvss_info['ui']
                        )
                        step3_desc, step3_tags, criticite = self.cve_analyzer.apply_step3_mapping(
                            cvss_info['c'], cvss_info['i'], cvss_info['a']
                        )
                        final_criticite = self.cve_analyzer.apply_attenuation(cvss_info['s'], criticite)

                        narrative_data.update({
                            'Step1_Description': step1_desc,
                            'Step1_Tags': step1_tags,
                            'Step2_Description': step2_desc,
                            'Step2_Tags': step2_tags,
                            'Step3_Description': step3_desc,
                            'Step3_Tags': step3_tags,
                            'Base_Criticite': criticite,
                            'Final_Criticite': final_criticite
                        })

                    cve_narratives[cve_id] = narrative_data
                    self.cve_analyzer.cve_cache[cve_id] = narrative_data
                else:
                    # CVE non trouvée
                    cve_narratives[cve_id] = {
                        'CVSS_Version': '#N/A',
                        'CVSS_Vector': '#N/A',
                        'CVSS_Score': '#N/A',
                        'Step1_Description': '#N/A',
                        'Step1_Tags': '#N/A',
                        'Step2_Description': '#N/A',
                        'Step2_Tags': '#N/A',
                        'Step3_Description': '#N/A',
                        'Step3_Tags': '#N/A',
                        'Base_Criticite': '#N/A',
                        'Final_Criticite': '#N/A'
                    }

            progress_bar.close()
            missing = sum(1 for n in cve_narratives.values() if n.get('CVSS_Version') in (None, '#N/A'))
            if missing:
                self.ui.status(f"{missing} CVE(s) without NVD data (not found or refused)", "warning")
            self.ui.status(f"CVE narrative analysis completed for {len(cve_narratives)} CVEs", "success")
            return cve_narratives

        except Exception as e:
            self.ui.status(f"Error during CVE analysis: {str(e)}", "error")
            return {}

    def qualify_internal_external(self, df):
        # Remplit la colonne de classification en réutilisant la logique unique
        # de classify_internal_external (plus de duplication des critères).
        for index, row in df.iterrows():
            is_internal = self.classify_internal_external(row)
            df.at[index, 'Internal_External_Classification'] = 'Internal' if is_internal else 'External'
        return df

    def normalize_cvss(self, cvss_score):
        """Normalise le score CVSS entre 0 et 1"""
        if cvss_score in ['#N/A', 'N/A', ''] or pd.isna(cvss_score):
            return 0.0
        try:
            score = float(cvss_score)
            return min(score / 10.0, 1.0)
        except (ValueError, TypeError):
            return 0.0

    def normalize_epss(self, epss_score):
        """Normalise le score EPSS"""
        if epss_score in ['#N/A', 'N/A', ''] or pd.isna(epss_score):
            return 0.0
        try:
            score = float(epss_score)
            return min(max(score, 0.0), 1.0)
        except (ValueError, TypeError):
            return 0.0

    def calculate_temporal_factor(self, cve_year):
        """Calcul du facteur temporel avec décroissance exponentielle"""
        if cve_year in ['#N/A', 'N/A', ''] or pd.isna(cve_year):
            return 0.0
        try:
            year = int(float(str(cve_year).replace('.0', '')))
            current_year = datetime.now().year
            age = current_year - year
            temporal_factor = math.exp(-age / 8.0)
            return max(temporal_factor, 0.05)
        except (ValueError, TypeError):
            return 0.0

    def load_service_matrix(self):
        """Charge la matrice de criticité des services depuis services_list.csv"""
        service_matrix = {}

        def _put(port, entry):
            prev = service_matrix.get(port)
            if prev is None or self._CRIT_RANK.get(entry['criticality'], 0) >= self._CRIT_RANK.get(prev['criticality'], 0):
                service_matrix[port] = entry

        try:
            if os.path.exists(exposia_paths.parameter('services_list.csv')):
                with open(exposia_paths.parameter('services_list.csv'), 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f, delimiter=';')
                    for row in reader:
                        try:
                            port_field = row['Port'].strip()
                            if '-' in port_field:
                                start, end = map(int, port_field.split('-'))
                                for port in range(start, end + 1):
                                    _put(port, {
                                        'service': row['Service'].strip().lower(),
                                        'criticality': row['Criticité'].strip().upper(),
                                        'category': row['Catégorie'].strip()
                                    })
                            else:
                                port = int(port_field)
                                _put(port, {
                                    'service': row['Service'].strip().lower(),
                                    'criticality': row['Criticité'].strip().upper(),
                                    'category': row['Catégorie'].strip()
                                })
                        except (ValueError, KeyError):
                            self.ui.status(f"Ligne ignorée dans services_list.csv : {row}", "warning")
            return service_matrix
        except Exception as e:
            self.ui.status(f"Erreur lors du chargement de services_list.csv : {e}", "error")
            return {}

    def load_attack_database(self, db_file=exposia_paths.parameter('Ports_to_attack.csv')):
        """
        Charge la base de données des attack paths
        """
        try:
            if not os.path.exists(db_file):
                self.ui.status(f"Attack database {db_file} not found - attack paths will be marked as #N/A", "warning")
                return {}

            df_attacks = pd.read_csv(db_file, sep=';', encoding='utf-8')
            attack_dict = {}

            for _, row in df_attacks.iterrows():
                port = str(row['Port']).strip()  # Convertir en string et nettoyer

                if port not in attack_dict:
                    attack_dict[port] = []

                attack_info = {
                    'Service': row['Service'],
                    'ID_Attack_Path': row['ID Attack Path'],
                    'Reconnaissance': row['Reconnaissance'],
                    'Exploitation': row['Exploitation'],
                    'Impact': row['Impact'],
                    'Mots_cles': row['Mots-clés']
                }

                attack_dict[port].append(attack_info)

            self.ui.status(f"Loaded attack paths for {len(attack_dict)} ports", "success")
            return attack_dict

        except Exception as e:
            self.ui.status(f"Error loading attack database: {str(e)} - attack paths will be marked as #N/A", "warning")
            return {}

    def enrich_with_unified_attack_paths(self, df, attack_dict, cve_narratives):
        """
        Enrichit le DataFrame avec une structure d'attaque unifiée : Reconnaissance + Exploitation + Impact
        AVEC LIMITE STRICTE par qualification et sélection aléatoire déterministe
        AVEC colonne Attack_Path_Type pour la traçabilité

        Les lignes PORT (scénarios génériques liés au service) ne portent AUCUNE
        donnée de CVE : elles héritent de l'exposition et de la qualification de la
        ligne source, mais pas de sa vulnérabilité, qu'elles ne décrivent pas.

        Invariant : chaque exposition source produit AU MOINS une ligne. Une
        exposition pour laquelle aucun récit n'est disponible (service connu sans
        CVE dont le port n'a pas de chemin d'attaque dans Ports_to_attack.csv, par
        exemple) est conservée avec Attack_Path_Type = 'NONE', pour rester visible
        dans l'inventaire des actifs et dans les décomptes du rapport.
        """
        enriched_rows = []

        # Définition des colonnes obsolètes à supprimer
        obsolete_columns = [
            'Step1_Description', 'Step1_Tags', 'Step2_Description', 'Step2_Tags',
            'Step3_Description', 'Step3_Tags',
            'Base_Criticite', 'Final_Criticite'
        ]

        for index, row in df.iterrows():
            port = str(row.get('Port', '#N/A')).strip()
            qualification = row.get('Exposia - Qualification', 'Low')
            cve = str(row.get('Vulnerability (CVE)', '#N/A'))
            has_cve = cve not in ['#N/A', 'None', 'No data', '', 'nan', 'NaN']
            domain = row.get('Domain', '')
            ip = row.get('IP Address', '')
            rows_before = len(enriched_rows)

            # 1. DÉTERMINER LE PLAFOND ABSOLU d'attack paths selon qualification
            max_attack_paths = 0
            if qualification == 'Critical':
                max_attack_paths = 3
            elif qualification == 'High':
                max_attack_paths = 2
            elif qualification == 'Medium':
                max_attack_paths = 1
            elif qualification == 'Low':
                # Exception : si CVE présente alors 1 attack path CVE uniquement
                max_attack_paths = 1 if has_cve else 0

            # 2. CALCULER LA RÉPARTITION CVE vs PORTS
            nb_cve_paths = 1 if has_cve else 0
            nb_ports_paths = max(0, max_attack_paths - nb_cve_paths)

            # 3. RÉCUPÉRER LES ATTACK PATHS DISPONIBLES POUR LE PORT
            available_port_attacks = []
            if port != '#N/A' and port in attack_dict:
                available_port_attacks = attack_dict[port]
                # Trier par ID pour assurer la cohérence
                try:
                    available_port_attacks = sorted(
                        available_port_attacks,
                        key=lambda x: int(x['ID_Attack_Path'].split('-')[-1])
                    )
                except (ValueError, IndexError):
                    pass

            # 4. SÉLECTION ALÉATOIRE DÉTERMINISTE DES ATTACK PATHS PORTS
            selected_port_attacks = []
            if nb_ports_paths > 0 and available_port_attacks:
                # Seed unique et STABLE entre exécutions basé sur les métadonnées métier.
                # hashlib (et non hash()) car hash() sur les strings est randomisé par process
                # (PYTHONHASHSEED), ce qui rendait la sélection non déterministe.
                seed_string = f"{domain}_{ip}_{port}"
                seed = int(hashlib.md5(seed_string.encode("utf-8")).hexdigest(), 16)

                # RNG local pour ne pas perturber l'état global du module random
                rng = random.Random(seed)

                # Sélectionner le nombre requis d'attack paths
                nb_to_select = min(nb_ports_paths, len(available_port_attacks))
                selected_port_attacks = rng.sample(available_port_attacks, nb_to_select)

            # 5. CRÉER LES LIGNES D'ATTACK PATHS PORTS
            for attack in selected_port_attacks:
                port_row = row.to_dict()

                # Supprimer les colonnes obsolètes
                for col in obsolete_columns:
                    if col in port_row:
                        del port_row[col]

                # Scénario générique du service : on retire les données propres à la
                # CVE de la ligne source (sinon le rapport afficherait la CVE au-dessus
                # d'un scénario qui ne la concerne pas).
                for col, empty_value in self.CVE_SPECIFIC_COLUMNS.items():
                    if col in port_row:
                        port_row[col] = empty_value

                # Mapper les données d'attack path port
                port_row['Reconnaissance'] = attack['Reconnaissance']
                port_row['Exploitation'] = attack['Exploitation']
                port_row['Impact'] = attack['Impact']
                port_row['Tags'] = attack['Mots_cles']
                port_row['Attack_Path_Type'] = 'PORT'  # type de chemin d'attaque

                enriched_rows.append(port_row)

            # 6. CRÉER LA LIGNE D'ATTACK PATH CVE (si applicable)
            if nb_cve_paths > 0:
                cve_row = row.to_dict()

                # Supprimer les colonnes obsolètes
                for col in obsolete_columns:
                    if col in cve_row:
                        del cve_row[col]

                # Récupérer les données narratives CVE
                cve_narrative = cve_narratives.get(cve, {})

                # Mapper les données CVE vers la structure unifiée
                cve_row['Reconnaissance'] = cve_narrative.get('Step1_Description', '#N/A')
                cve_row['Exploitation'] = cve_narrative.get('Step2_Description', '#N/A')
                cve_row['Impact'] = cve_narrative.get('Step3_Description', '#N/A')

                # Fusionner les tags CVE (seulement si non #N/A)
                tags_list = []
                for tag_key in ['Step1_Tags', 'Step2_Tags', 'Step3_Tags']:
                    tag_value = cve_narrative.get(tag_key, '#N/A')
                    if tag_value and tag_value != '#N/A':
                        tags_list.append(tag_value)

                cve_row['Tags'] = ', '.join(tags_list) if tags_list else '#N/A'
                cve_row['Attack_Path_Type'] = 'CVE'  # type de chemin d'attaque

                enriched_rows.append(cve_row)

            # 7. AUCUNE LIGNE PRODUITE : l'exposition est conservée sans récit.
            # Couvre le Low sans CVE (plafond 0), mais aussi le cas qui faisait
            # disparaître des actifs : plafond > 0 sans CVE et sans chemin
            # d'attaque pour ce port (service connu, absent de Ports_to_attack.csv).
            if len(enriched_rows) == rows_before:
                edge_row = row.to_dict()

                # Supprimer les colonnes obsolètes
                for col in obsolete_columns:
                    if col in edge_row:
                        del edge_row[col]

                edge_row['Reconnaissance'] = '#N/A'
                edge_row['Exploitation'] = '#N/A'
                edge_row['Impact'] = '#N/A'
                edge_row['Tags'] = '#N/A'
                edge_row['Attack_Path_Type'] = 'NONE'  # type de chemin d'attaque

                enriched_rows.append(edge_row)

        return pd.DataFrame(enriched_rows)

    def get_service_info(self, port, service_matrix):
        """Récupère les informations de service (match exact uniquement)"""
        if port in ['#N/A', 'N/A', ''] or pd.isna(port):
            return None
        try:
            port_int = int(float(str(port).replace('.0', '')))
            return service_matrix.get(port_int)
        except (ValueError, TypeError):
            return None

    def get_service_multiplier(self, criticality):
        """Multiplicateurs contextuels par criticité service"""
        multipliers = {
            'CRITIQUE': 1.3,
            'HAUTE': 1.1,
            'MOYENNE': 1.0,
            'FAIBLE': 0.8
        }
        return multipliers.get(criticality, 1.0)

    def get_internal_external_multiplier(self, row):
        """
        Multiplicateur basé sur la classification interne/externe — NEUTRALISÉ (1.0).

        La classification « interne » est une présomption (service habituellement
        réservé à un usage interne : administration, transfert de fichiers, base de
        données…), pas un constat. Elle est affichée dans les rapports comme
        « nature présumée » mais ne pondère plus la criticité.
        Point d'extension conservé : réintroduire ici une pondération le jour où la
        classification reposera sur un critère vérifiable.
        """
        return 1.0

    def classify_internal_external(self, row):
        """
        Classification interne/externe d'un asset (True = interne).
        Source unique de vérité : les constantes INTERNAL_* de la classe.
        Heuristique (mots-clés, service, port) : True signifie « service présumé
        sensible », habituellement réservé à un usage interne.
        """
        # Vérifier le Subdomain
        subdomain = str(row.get('Subdomain', '')).lower()
        if subdomain and subdomain not in self._NA_VALUES:
            for keyword in self.INTERNAL_SUBDOMAIN_KEYWORDS:
                if keyword in subdomain:
                    return True

        # Vérifier le Service
        service = str(row.get('Service', '')).lower()
        if service and service not in self._NA_VALUES:
            for keyword in self.INTERNAL_SERVICE_KEYWORDS:
                if keyword in service:
                    return True

        # Vérifier le Port
        port = row.get('Port', '')
        if port and str(port).lower() not in self._NA_VALUES:
            try:
                port_number = int(float(str(port).replace('.0', '')))
                if port_number in self.INTERNAL_PORTS:
                    return True
            except (ValueError, TypeError):
                pass

        return False

    def qualify_with_service_context(self, row, service_info):
        """
        Algorithme avec contexte service intégré + multiplicateur interne/externe
        """
        cvss_norm = self.normalize_cvss(row.get('CVSS Score'))
        epss_norm = self.normalize_epss(row.get('EPSS Score'))
        temporal_factor = self.calculate_temporal_factor(row.get('CVE - Year'))

        base_score = (
            0.60 * epss_norm +
            0.25 * cvss_norm +
            0.15 * temporal_factor
        )

        # Ordre d'application : contexte métier puis contexte infrastructure
        # 1. Multiplicateur service (impact métier)
        service_multiplier = self.get_service_multiplier(service_info['criticality'])
        score_with_service = base_score * service_multiplier

        # 2. Multiplicateur interne/externe (contexte infrastructure)
        ie_multiplier = self.get_internal_external_multiplier(row)
        final_score = score_with_service * ie_multiplier

        # Plafonnement à 1.0
        final_score = min(final_score, 1.0)

        if final_score >= 0.75:
            return 'Critical'
        elif final_score >= 0.55:
            return 'High'
        elif final_score >= 0.35:
            return 'Medium'
        else:
            return 'Low'

    def qualify_cve_standard(self, row):
        """
        Algorithme standard avec pondération unifiée + multiplicateur interne/externe
        """
        cvss_norm = self.normalize_cvss(row.get('CVSS Score'))
        epss_norm = self.normalize_epss(row.get('EPSS Score'))
        temporal_factor = self.calculate_temporal_factor(row.get('CVE - Year'))

        base_score = (
            0.60 * epss_norm +
            0.25 * cvss_norm +
            0.15 * temporal_factor
        )

        # Pas de multiplicateur service, seulement interne/externe
        ie_multiplier = self.get_internal_external_multiplier(row)
        final_score = min(base_score * ie_multiplier, 1.0)

        if final_score >= 0.75:
            return 'Critical'
        elif final_score >= 0.55:
            return 'High'
        elif final_score >= 0.35:
            return 'Medium'
        else:
            return 'Low'

    def map_service_to_qualification(self, criticality, row):
        """
        Mapping conservateur service seul -> qualification + multiplicateur interne/externe
        Modification : ajouter le paramètre row pour accéder aux données interne/externe
        """
        base_mapping = {
            'CRITIQUE': 'Medium',
            'HAUTE': 'Medium',
            'MOYENNE': 'Low',
            'FAIBLE': 'Low'
        }

        base_qualification = base_mapping.get(criticality, 'Low')

        # Conversion qualification vers score pour appliquer le multiplicateur
        score_mapping = {'Critical': 0.8, 'High': 0.6, 'Medium': 0.4, 'Low': 0.2}
        base_score = score_mapping[base_qualification]

        # Application du multiplicateur interne/externe
        ie_multiplier = self.get_internal_external_multiplier(row)
        final_score = min(base_score * ie_multiplier, 1.0)

        # Reconversion vers qualification
        if final_score >= 0.75:
            return 'Critical'
        elif final_score >= 0.55:
            return 'High'
        elif final_score >= 0.35:
            return 'Medium'
        else:
            return 'Low'

    def apply_exploit_floor(self, qualification, row):
        """
        Plancher « exploit public » : une CVE pour laquelle au moins un exploit
        public est référencé n'est jamais qualifiée sous le plancher que fixe
        EXPLOIT_FLOOR_RULES pour son CVSS (High si CVSS ≥ 7, Medium sinon). Ne fait
        que relever une qualification, jamais l'abaisser.
        """
        if not self.EXPLOIT_FLOOR_RULES or qualification not in self._QUALIFICATION_ORDER:
            return qualification
        try:
            exploits = int(float(row.get('Number of Exploits', 0) or 0))
        except (ValueError, TypeError):
            exploits = 0
        if exploits <= 0:
            return qualification
        try:
            cvss = float(row.get('CVSS Score'))
            if math.isnan(cvss):
                cvss = 0.0
        except (ValueError, TypeError):
            cvss = 0.0
        floor = next((level for min_cvss, level in self.EXPLOIT_FLOOR_RULES if cvss >= min_cvss), None)
        if floor not in self._QUALIFICATION_ORDER:
            return qualification
        if self._QUALIFICATION_ORDER.index(qualification) < self._QUALIFICATION_ORDER.index(floor):
            return floor
        return qualification

    def contextual_vulnerability_qualification(self, row):
        """
        Implémentation CORRECTE de la matrice de décision complète
        avec multiplicateur interne/externe intégré, puis plancher « exploit public »
        pour les lignes portant une CVE.
        """
        port = row.get('Port', '#N/A')
        cve = str(row.get('Vulnerability (CVE)', '#N/A'))
        has_cve = cve not in ['#N/A', 'None', 'No data', '', 'nan', 'NaN']

        service_info = self.get_service_info(port, self.service_matrix)
        has_valid_service = service_info is not None

        if has_valid_service and has_cve:
            return self.apply_exploit_floor(self.qualify_with_service_context(row, service_info), row)
        elif has_valid_service and not has_cve:
            return self.map_service_to_qualification(service_info['criticality'], row)
        elif not has_valid_service and has_cve:
            return self.apply_exploit_floor(self.qualify_cve_standard(row), row)
        else:
            # Cas sans service ni CVE - appliquer quand même le multiplicateur interne/externe
            base_score = 0.1  # Score très bas par défaut
            ie_multiplier = self.get_internal_external_multiplier(row)
            final_score = min(base_score * ie_multiplier, 1.0)

            if final_score >= 0.35:
                return 'Medium'
            else:
                return 'Low'

    def fetch_json_data(self, url, params=None):
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json(), None
        except requests.RequestException as e:
            return None, f"Error fetching data from {url}: {e}"
        except ValueError as e:
            # Réponse 200 dont le corps n'est pas du JSON (page d'erreur, maintenance)
            return None, f"Invalid JSON from {url}: {e}"

    def fetch_epss_score(self, cve_id):
        return self.fetch_json_data(self.EPSS_API_URL.format(cve_id=cve_id))

    def fetch_github_exploits(self, cve_id):
        return self.fetch_json_data(self.GITHUB_API_URL, params={"cve_id": cve_id})

    def _get_exploitdb_index(self):
        """
        Télécharge et indexe ExploitDB UNE SEULE FOIS par run.
        Retourne un dict {cve_id: [exploit_ids]} permettant un lookup O(1) par CVE,
        au lieu de re-télécharger/re-parser le CSV complet pour chaque CVE.
        Best-effort : en cas d'échec, retourne {} (et n'est pas re-tenté).
        """
        if self._exploitdb_index is not None:
            return self._exploitdb_index

        index = {}
        try:
            response = self.session.get(self.EXPLOITDB_URL)
            response.raise_for_status()
            decoded_content = response.content.decode("utf-8")
            csv_reader = csv.reader(decoded_content.splitlines(), delimiter=",")
            header = next(csv_reader)
            codes_index = header.index("codes")
            for row in csv_reader:
                exploit_id = row[0]
                for code in row[codes_index].split(";"):
                    code = code.strip()
                    if code:
                        index.setdefault(code, []).append(exploit_id)
            self.ui.status(f"Indexed ExploitDB ({len(index)} CVEs referenced)", "success")
        except (requests.RequestException, IndexError, StopIteration) as e:
            self.ui.status(f"ExploitDB unavailable ({e}) - ExploitDB exploit links will be skipped", "warning")

        self._exploitdb_index = index
        return index

    def get_cve_details(self, cve_id):
        """
        Détails EPSS + exploits d'une CVE. Retourne (details, exploits_count).

        Les trois sources sont indépendantes : l'échec de l'une ne fait jamais
        perdre les données des autres.
          • EPSS indisponible        -> EPSS Score = '#N/A' (exploits conservés) ;
          • PoC-in-GitHub indisponible -> aucun lien GitHub (EPSS conservé) ;
          • ExploitDB indisponible    -> aucun lien ExploitDB.
        Les échecs sont comptés dans self.enrichment_failures pour le bilan final.
        """
        epss_data, epss_error = self.fetch_epss_score(cve_id)
        github_data, github_error = self.fetch_github_exploits(cve_id)

        epss_score = "#N/A"
        if epss_error:
            self.enrichment_failures["EPSS"] += 1
        else:
            try:
                if epss_data and epss_data.get("data"):
                    epss_score = epss_data["data"][0]["epss"]
            except (AttributeError, KeyError, IndexError, TypeError):
                self.enrichment_failures["EPSS"] += 1

        github_exploits = []
        if github_error:
            self.enrichment_failures["PoC-in-GitHub"] += 1
        else:
            try:
                github_exploits = [poc['html_url'] for poc in (github_data or {}).get("pocs", [])
                                   if poc.get('html_url')]
            except (AttributeError, TypeError):
                self.enrichment_failures["PoC-in-GitHub"] += 1

        # ExploitDB est best-effort : indisponibilité => simplement aucun lien ExploitDB.
        exploitdb_index = self._get_exploitdb_index()
        exploitdb_exploits = [
            f"https://www.exploit-db.com/exploits/{eid}"
            for eid in exploitdb_index.get(cve_id, [])
        ]
        # Dédoublonnage (ordre conservé) : une même URL peut revenir plusieurs fois
        # dans la réponse PoC-in-GitHub. Sans cela, le décompte par CVE dépassait le
        # nombre d'exploits uniques affiché par le rapport (R3).
        combined_exploits = list(dict.fromkeys(github_exploits + exploitdb_exploits))
        exploits_count = len(combined_exploits)
        if exploits_count == 0:
            combined_exploits_str = "No unique public exploit found"
        else:
            combined_exploits_str = ", ".join(combined_exploits)
        return {
            "CVE ID": cve_id,
            "EPSS Score": str(epss_score),
            "Number of Exploits": exploits_count,
            "Exploits": combined_exploits_str
        }, exploits_count

    def report_enrichment_failures(self, total_cves):
        """Bilan des sources d'enrichissement indisponibles (une ligne par source)."""
        if self.enrichment_failures["EPSS"]:
            self.ui.status(f"EPSS unavailable for {self.enrichment_failures['EPSS']}/{total_cves} CVE(s) - "
                           f"EPSS set to #N/A, exploits kept", "warning")
        if self.enrichment_failures["PoC-in-GitHub"]:
            self.ui.status(f"PoC-in-GitHub unavailable for {self.enrichment_failures['PoC-in-GitHub']}/{total_cves} "
                           f"CVE(s) - EPSS and ExploitDB data kept", "warning")

    def export_cve_to_csv(self, cve_details, filename="cve_details.csv"):
        if not cve_details:
            self.ui.status("No CVE details to export", "warning")
            return
        keys = cve_details[0].keys()
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=keys, delimiter=';')
            writer.writeheader()
            for item in cve_details:
                writer.writerow({k: str(v) if v is not None else "" for k, v in item.items()})
        self.ui.status(f"Exported exploit(s) to {filename}", "success")

    def remove_duplicates(self, df):
        deduplicated_df = df.drop_duplicates(subset=["Subdomain", "IP Address", "Port"])
        return deduplicated_df

    def extract_cve_year(self, cve_id):
        """Extract year from CVE ID with proper null handling and ensure no decimal point"""
        if pd.isna(cve_id) or cve_id in ["None", "No data", "#N/A", ""]:
            return "#N/A"
        try:
            parts = str(cve_id).split("-")
            if len(parts) >= 2:
                year = parts[1]
                return str(int(float(year))) if year.replace('.', '').isdigit() else "#N/A"
            return "#N/A"
        except (IndexError, AttributeError, ValueError):
            return "#N/A"

    def generate_centralized_report(self):
        try:
            self.ui.status("Generating comprehensive centralized report with contextual qualification and internal/external classification...", "info")
            main_domain = self.get_main_domain(self.domain)
            output_filename = f"Exposia_{main_domain}.csv"

            # Analyse des CVE trouvées par Shodan
            cve_narratives = self.analyze_cves_from_file()

            # Initialisation des DataFrames
            all_subdomains = pd.DataFrame()
            subdomains_with_ips = pd.DataFrame()
            shodan_data = pd.DataFrame()
            cve_data = pd.DataFrame()

            # Chargement des fichiers
            try:
                if os.path.exists("results_subdomains_only.csv"):
                    all_subdomains = pd.read_csv("results_subdomains_only.csv", sep=";")
            except Exception as e:
                self.ui.status(f"Error loading subdomains file: {str(e)}", "warning")

            try:
                if os.path.exists("results_subdomains_with_ips.csv"):
                    subdomains_with_ips = pd.read_csv("results_subdomains_with_ips.csv", sep=";")
            except Exception as e:
                self.ui.status(f"Error loading subdomains with IPs file: {str(e)}", "warning")

            try:
                if os.path.exists("resultats_shodan.csv"):
                    shodan_data = pd.read_csv("resultats_shodan.csv", sep=";")
                    shodan_data["CVSS Score"] = shodan_data["CVSS Score"].astype(str).replace('nan', '#N/A')
                    # ASN par IP (absent des fichiers produits avant cette colonne).
                    if "ASN" in shodan_data.columns:
                        for _ip, _asn in shodan_data[["IP Address", "ASN"]].dropna().itertuples(index=False):
                            if str(_asn).strip():
                                self.ip_asn[str(_ip).strip()] = str(_asn).strip()
            except Exception as e:
                self.ui.status(f"Error loading Shodan data: {str(e)}", "warning")

            try:
                if os.path.exists("cve_details.csv"):
                    cve_data = pd.read_csv("cve_details.csv", sep=";")
                    cve_data["EPSS Score"] = cve_data["EPSS Score"].astype(str).replace('nan', '#N/A')
                    cve_dict = {}
                    for _, cve_row in cve_data.iterrows():
                        cve_id = cve_row['CVE ID']
                        cve_dict[cve_id] = {
                            'EPSS Score': str(cve_row['EPSS Score']),
                            'Number of Exploits': int(cve_row['Number of Exploits']),
                            'Exploits': str(cve_row['Exploits'])
                        }
                else:
                    cve_dict = {}
            except Exception as e:
                self.ui.status(f"Error loading CVE details: {str(e)}", "warning")
                cve_dict = {}

            # Création de la map subdomain-IP
            subdomain_ip_map = {}
            if not subdomains_with_ips.empty:
                for _, row in subdomains_with_ips.iterrows():
                    sub = row['Subdomain']
                    ip = row['IP Address']
                    if sub not in subdomain_ip_map:
                        subdomain_ip_map[sub] = []
                    if ip != "No IP found":
                        subdomain_ip_map[sub].append(ip)

            if not all_subdomains.empty:
                for sub in all_subdomains['Subdomain'].unique():
                    if sub not in subdomain_ip_map:
                        subdomain_ip_map[sub] = []

            all_rows = []

            for subdomain, ips in subdomain_ip_map.items():
                if ips:  # Sous-domaine avec IP résolue
                    # IP directes une à une ; IP de CDN regroupées (voir _ip_jobs).
                    for ip, ip_data in self._ip_jobs(ips, shodan_data):
                        if not ip_data.empty:
                            for _, row in ip_data.iterrows():
                                port_raw = row.get("Port", "#N/A")
                                try:
                                    port = str(int(float(port_raw))) if str(port_raw).replace('.', '').isdigit() else '#N/A'
                                except (ValueError, TypeError):
                                    port = '#N/A'
                                cve = str(row.get("Vulnerability (CVE)", "#N/A")).strip()
                                # Normaliser les valeurs manquantes : str(NaN) -> "nan", chaîne vide, etc.
                                if cve.lower() in ["nan", "none", "no data", ""]:
                                    cve = "#N/A"
                                has_cve = cve not in ["None", "No data", "#N/A", "", "nan", "NaN"]
                                service_info = self.get_service_info(port, self.service_matrix)
                                has_valid_service = service_info is not None

                                row_data = {
                                    'Port': port,
                                    'CVSS Score': str(row.get("CVSS Score", "#N/A")),
                                    'EPSS Score': "#N/A",
                                    'CVE - Year': self.extract_cve_year(cve),
                                    'Vulnerability (CVE)': cve,
                                    'Number of Exploits': 0,
                                }

                                if has_cve and cve in cve_dict:
                                    row_data['EPSS Score'] = cve_dict[cve]['EPSS Score']
                                    row_data['Number of Exploits'] = cve_dict[cve]['Number of Exploits']
                                    exploits = cve_dict[cve]['Exploits']
                                else:
                                    exploits = "#N/A"

                                qualification = self.contextual_vulnerability_qualification(row_data)
                                service = service_info['service'] if has_valid_service else '#N/A'
                                criticite = service_info['criticality'] if has_valid_service else '#N/A'
                                categorie = service_info['category'] if has_valid_service else '#N/A'

                                # Données narratives de la CVE
                                cve_narrative = cve_narratives.get(cve, {})

                                all_rows.append({
                                    "Domain": self.domain,
                                    "Subdomain": subdomain,
                                    "IP Address": ip,
                                    "Port": port,
                                    "Internal_External_Classification": "#N/A",
                                    "Service": service,
                                    "Catégorie": categorie,
                                    "Vulnerability (CVE)": cve,
                                    "Number of Exploits": row_data['Number of Exploits'],
                                    "CVE - Year": self.extract_cve_year(cve),
                                    "CVSS Score": str(row.get("CVSS Score", "#N/A")),
                                    "EPSS Score": row_data['EPSS Score'],
                                    "Impact business / opérationnel": criticite,
                                    "Exposia - Qualification": qualification,
                                    "Exploits": exploits,
                                    "CVSS_Version": cve_narrative.get('CVSS_Version', '#N/A'),
                                    "CVSS_Vector": cve_narrative.get('CVSS_Vector', '#N/A'),
                                })
                        else:
                            # CORRIGÉ : Cas sans données Shodan
                            qualification = self.contextual_vulnerability_qualification({
                                'Port': "#N/A",
                                'CVSS Score': "#N/A",
                                'EPSS Score': "#N/A",
                                'CVE - Year': "#N/A",
                                'Vulnerability (CVE)': "#N/A"
                            })
                            all_rows.append({
                                "Domain": self.domain,
                                "Subdomain": subdomain,
                                "IP Address": ip,
                                "Port": "#N/A",
                                "Internal_External_Classification": "#N/A",
                                "Service": "#N/A",
                                "Catégorie": "#N/A",
                                "Vulnerability (CVE)": "#N/A",
                                "Number of Exploits": 0,
                                "CVE - Year": "#N/A",
                                "CVSS Score": "#N/A",
                                "EPSS Score": "#N/A",
                                "Impact business / opérationnel": "#N/A",
                                "Exposia - Qualification": qualification,
                                "Exploits": "#N/A",
                                "CVSS_Version": "#N/A",
                                "CVSS_Vector": "#N/A",
                            })
                else:
                    # CORRIGÉ : Cas sans IP résolue
                    qualification = self.contextual_vulnerability_qualification({
                        'Port': "#N/A",
                        'CVSS Score': "#N/A",
                        'EPSS Score': "#N/A",
                        'CVE - Year': "#N/A",
                        'Vulnerability (CVE)': "#N/A"
                    })
                    all_rows.append({
                        "Domain": self.domain,
                        "Subdomain": subdomain,
                        "IP Address": "No IP found",
                        "Port": "#N/A",
                        "Internal_External_Classification": "#N/A",
                        "Service": "#N/A",
                        "Catégorie": "#N/A",
                        "Vulnerability (CVE)": "#N/A",
                        "Number of Exploits": 0,
                        "CVE - Year": "#N/A",
                        "CVSS Score": "#N/A",
                        "EPSS Score": "#N/A",
                        "Impact business / opérationnel": "#N/A",
                        "Exposia - Qualification": qualification,
                        "Exploits": "#N/A",
                        "CVSS_Version": "#N/A",
                        "CVSS_Vector": "#N/A",
                    })

            # Création du rapport initial
            final_report = pd.DataFrame(all_rows)

            # Hébergement : « CDN <fournisseur> » pour les expositions regroupées
            # sur un frontal de CDN, « Direct » sinon, #N/A sans IP résolue.
            def _hosting(ip):
                if str(ip) in ('No IP found', '#N/A', '', 'nan'):
                    return '#N/A'
                provider = self.cdn_provider(ip)
                return f"CDN {provider}" if provider else 'Direct'
            if not final_report.empty:
                final_report['Hosting'] = final_report['IP Address'].map(_hosting)
            if self.cdn_stats["subdomains"]:
                self.ui.status(
                    f"CDN: {self.cdn_stats['subdomains']} subdomain(s) behind {len(self.cdn_stats['ips'])} "
                    f"CDN edge IP(s) - kept ports {', '.join(self.CDN_EDGE_PORTS)} once per subdomain, "
                    f"{self.cdn_stats['rows_dropped']} edge row(s) set aside", "info")

            final_report = final_report.replace('', '#N/A')

            # Apply internal/external classification
            self.ui.status("Applying internal/external classification...", "info")
            final_report = self.qualify_internal_external(final_report)

            # Criticité calculée avant l'enrichissement par les chemins d'attaque
            self.ui.status("Assessing domain criticality (before attack path enrichment)...", "info")
            avg_criticality_score, avg_qualitative_rating = self.assess_domain_criticality_from_df(final_report)

            # Enrichissement avec attack paths APRÈS le calcul de criticité
            self.ui.status("Loading attack paths database...", "info")
            attack_dict = self.load_attack_database()

            self.ui.status("Enriching data with unified attack structure and deterministic selection...", "info")
            final_report = self.enrich_with_unified_attack_paths(final_report, attack_dict, cve_narratives)

            # Statistiques des chemins d'attaque
            self.log_attack_path_statistics(final_report)

            # Écriture dans le CSV
            try:
                final_report.to_csv(output_filename, index=False, sep=";")
                self.ui.status(f"Created comprehensive report with unified attack structure: {output_filename}", "success")

                # Display classification statistics
                total = len(final_report)
                if total > 0:
                    internal_count = len(final_report[final_report['Internal_External_Classification'] == 'Internal'])
                    external_count = len(final_report[final_report['Internal_External_Classification'] == 'External'])

                    self.ui.status(f"Classification results: Internal: {internal_count} ({internal_count/total*100:.1f}%), External: {external_count} ({external_count/total*100:.1f}%)", "info")

                else:
                    self.ui.status("No data to classify", "warning")

                # Nettoyage des fichiers temporaires
                temp_files = [
                    "results_subdomains_only.csv",
                    "results_subdomains_with_ips.csv",
                    "results_ips_only.csv",
                    "resultats_shodan.csv",
                    "cve_identifies.csv",
                    "cve_details.csv"
                ]
                for file in temp_files:
                    try:
                        if os.path.exists(file):
                            os.remove(file)
                    except Exception as e:
                        self.ui.status(f"Error deleting {file}: {str(e)}", "warning")

                # Retourner les scores de criticité calculés avant enrichissement
                return True, avg_criticality_score, avg_qualitative_rating

            except Exception as e:
                self.ui.status(f"Error writing centralized report: {str(e)}", "error")
                return False, None, None
        except Exception as e:
            self.ui.status(f"Error generating report: {str(e)}", "error")
            return False, None, None

    def log_attack_path_statistics(self, final_report):
        """
        Affiche les statistiques de répartition des attack paths
        """
        try:

            # Compter les attack paths par type
            cve_attack_count = len(final_report[
                (final_report['Vulnerability (CVE)'] != '#N/A') &
                (final_report['Vulnerability (CVE)'] != 'None') &
                (final_report['Vulnerability (CVE)'] != 'No data') &
                (final_report['Reconnaissance'] != '#N/A')
            ])

            port_attack_count = len(final_report[
                ((final_report['Vulnerability (CVE)'] == '#N/A') |
                (final_report['Vulnerability (CVE)'] == 'None') |
                (final_report['Vulnerability (CVE)'] == 'No data')) &
                (final_report['Reconnaissance'] != '#N/A')
            ])

            no_attack_count = len(final_report[final_report['Reconnaissance'] == '#N/A'])

            # Statistiques par qualification
            qualification_stats = final_report.groupby('Exposia - Qualification').size().to_dict()

            self.ui.status(f"Attack paths distribution: {port_attack_count} port-based, {cve_attack_count} CVE-based, {no_attack_count} no attack", "info")
            self.ui.status(f"Qualification distribution after enrichment: {qualification_stats}", "info")

        except Exception as e:
            self.ui.status(f"Error computing attack path statistics: {str(e)}", "warning")

    # Extraire la logique de assess_domain_criticality pour travailler sur un DataFrame
    def assess_domain_criticality_from_df(self, df):
        """
        Calcule la criticité à partir d'un DataFrame existant (avant enrichissement attack paths)
        """
        try:
            if df.empty:
                self.ui.status("No data available for criticality assessment", "warning")
                return None, None

            results = []
            for domain in df['Domain'].unique():
                domain_result = self.compute_criticality(df, domain)
                if domain_result:
                    results.append(domain_result)

            if not results:
                self.ui.status("No valid criticality results computed", "warning")
                return None, None

            avg_criticality_score = sum(result["Quantitative Score"] for result in results) / len(results)
            avg_qualitative_rating = self.get_qualitative_assessment(avg_criticality_score)

            return avg_criticality_score, avg_qualitative_rating

        except Exception as e:
            self.ui.status(f"Error assessing domain criticality: {str(e)}", "error")
            return None, None

    def replace_nan_with_na(self, domain):
        main_domain = self.get_main_domain(domain)
        file_path = f"Exposia_{main_domain}.csv"
        try:
            with open(file_path, mode='r', newline='') as file:
                reader = csv.reader(file, delimiter=';')
                rows = list(reader)
            for row in rows:
                row[:] = ['#N/A' if x == 'nan' else x for x in row]
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerows(rows)
        except Exception as e:
            self.ui.status(f"Error replacing 'nan' with '#N/A' in {file_path}: {str(e)}", "error")

    def get_qualitative_assessment(self, score):
        """Convert quantitative score to qualitative rating."""
        if isinstance(score, str) and score.lower() == 'nan':
            return "Low"
        try:
            score = float(score)
        except (ValueError, TypeError):
            return "Low"
        if score < 3:
            return "Low"
        elif 3 <= score < 6:
            return "Medium"
        elif 6 <= score < 9:
            return "High"
        else:
            return "Critical"

    def compute_criticality(self, df, domain):
        domain_data = df[df['Domain'] == domain]
        if domain_data['IP Address'].eq('No IP found').all() or domain_data['Vulnerability (CVE)'].eq('#N/A').all():
            return None
        cleaned_data = domain_data[
            (~domain_data['CVSS Score'].isin(['#N/A', 'nan'])) &
            (~domain_data['EPSS Score'].isin(['#N/A', 'nan']))
        ]
        if cleaned_data.empty:
            return None
        try:
            avg_cvss = cleaned_data['CVSS Score'].astype(float).mean()
            avg_epss = cleaned_data['EPSS Score'].astype(float).mean()
            total_exploits = cleaned_data['Number of Exploits'].astype(int).sum()
        except Exception:
            return {
                "Domain": domain,
                "Quantitative Score": 0,
                "Qualitative Rating": "Low",
                "Avg CVSS": 0,
                "Avg EPSS": 0,
                "Total Exploits": 0,
                "Services per IP": 0,
                "Vulnerabilities per IP": 0
            }
        qualification_weights = {
            'Critical': 1.0,
            'High': 0.7,
            'Medium': 0.4,
            'Low': 0.1
        }
        qualification_scores = cleaned_data['Exposia - Qualification'].map(qualification_weights)
        avg_qualification_score = qualification_scores.mean()
        nb_ips = domain_data['IP Address'].nunique()
        nb_services = domain_data['Service'].count()
        nb_vulnerabilities = domain_data['Vulnerability (CVE)'].count()
        cvss_component = 0.4 * avg_cvss
        epss_component = 0.3 * avg_epss * 10
        exploits_component = 0.2 * math.log(1 + total_exploits)
        qualification_component = 0.1 * avg_qualification_score * 10
        services_per_ip = nb_services / nb_ips if nb_ips > 0 else 0
        vulns_per_ip = nb_vulnerabilities / nb_ips if nb_ips > 0 else 0
        service_factor = 1 + 0.05 * math.log(1 + services_per_ip) if services_per_ip > 0 else 1
        vuln_factor = 1 + 0.05 * math.log(1 + vulns_per_ip) if vulns_per_ip > 0 else 1
        criticality_score = (cvss_component + epss_component + exploits_component + qualification_component) * service_factor * vuln_factor
        qualitative_rating = self.get_qualitative_assessment(criticality_score)
        return {
            "Domain": domain,
            "Quantitative Score": round(criticality_score, 2),
            "Qualitative Rating": qualitative_rating,
            "Avg CVSS": round(avg_cvss, 2),
            "Avg EPSS": round(avg_epss, 4),
            "Total Exploits": total_exploits,
            "Services per IP": round(services_per_ip, 2),
            "Vulnerabilities per IP": round(vulns_per_ip, 2),
            "Avg Qualification Score": round(avg_qualification_score, 2)
        }

    def assess_domain_criticality(self):
        self.ui.status("Assessing domain criticality...", "info")
        main_domain = self.get_main_domain(self.domain)
        report_filename = f"Exposia_{main_domain}.csv"
        if not os.path.exists(report_filename):
            self.ui.status(f"No report file found ({report_filename}) - skipping criticality assessment", "warning")
            return None, None
        try:
            df = pd.read_csv(report_filename, sep=';')
        except Exception as e:
            self.ui.status(f"Error reading {report_filename}: {str(e)}", "error")
            return None, None
        # Délègue le calcul à la version DataFrame (source unique de la logique)
        return self.assess_domain_criticality_from_df(df)

    def analyze_vulnerabilities(self):
        """Analyse des vulnérabilités avec la méthode de qualification existante."""
        self.ui.status("Analyzing vulnerabilities with contextual qualification...", "info")
        main_domain = self.get_main_domain(self.domain)
        report_filename = f"Exposia_{main_domain}.csv"

        try:
            if not os.path.exists(report_filename):
                self.ui.status(f"No report file found: {report_filename}", "warning")
                return False

            df = pd.read_csv(report_filename, delimiter=';')
            if df.empty:
                self.ui.status("No data available for analysis", "warning")
                return False

            # Affichage des statistiques de qualification
            qualification_counts = df['Exposia - Qualification'].value_counts().to_dict()
            self.ui.status(f"Qualification distribution: {qualification_counts}", "info")
            return True
        except Exception as e:
            self.ui.status(f"Error during vulnerability analysis: {str(e)}", "error")
            return False

_RATING_ORDER = ["Low", "Medium", "High", "Critical"]


def apply_critical_floor(rating, qualifications):
    """
    Plancher de la criticité globale : un seul actif « Critical » ne doit pas être
    dilué par la moyenne des autres. Dès qu'une exposition est qualifiée Critical,
    la criticité globale n'est jamais inférieure à « High » (jamais abaissée).
    """
    if rating not in _RATING_ORDER:
        return rating
    if any(str(q).strip() == "Critical" for q in qualifications):
        floor = _RATING_ORDER.index("High")
        if _RATING_ORDER.index(rating) < floor:
            return "High"
    return rating


def main():
    parser = argparse.ArgumentParser(description='Subdomain Scanner with Vulnerability Assessment')
    parser.add_argument('domain', nargs='?', help='Single domain to scan')
    parser.add_argument('--list', '-l', help='File containing a list of domains to scan')
    parser.add_argument('--resolve-ips', action='store_true', help='Automatically resolve IPs and skip vulnerability scan')
    args = parser.parse_args()

    if not os.path.exists(exposia_paths.parameter('services_list.csv')):
        ModernUI.status("Warning: services_list.csv not found. Contextual qualification will be limited.", "warning")

    domains = []
    if args.domain:
        domains.append(exposia_paths.normalize_domain(args.domain))
    elif args.list:
        try:
            with open(args.list, 'r') as file:
                domains = [exposia_paths.normalize_domain(line) for line in file if line.strip()]
        except FileNotFoundError:
            ModernUI.status(f"Error: The file {args.list} was not found.", "error")
            return
        except Exception as e:
            ModernUI.status(f"Error reading the file: {str(e)}", "error")
            return
    else:
        ModernUI.status("Please provide a domain or a list of domains to scan.", "error")
        return

    # Clés API : config.yaml à la racine du projet (source unique, jamais en argument).
    try:
        shodan_key = exposia_config.get_api_key("shodan")
        nvd_key = exposia_config.get_api_key("nvd")
    except Exception as e:
        ModernUI.status(f"Lecture de config.yaml impossible : {e}", "error")
        _sys.exit(1)
    perm_warning = exposia_config.permission_warning()
    if perm_warning:
        ModernUI.status(perm_warning, "warning")
    if args.resolve_ips:
        shodan_key = None  # --resolve-ips : résolution seule, pas de scan
    elif not shodan_key:
        ModernUI.status(f"No Shodan API key (api_keys.shodan in {exposia_config.config_path()}, or SHODAN_API_KEY): "
                        f"vulnerability scan will be skipped.", "warning")

    total_scanned_ips = 0
    total_subdomains = 0
    total_unique_ips = 0
    total_vulnerabilities = 0
    total_exploits = 0
    total_elapsed = 0
    global_criticality_score = 0
    global_qualitative_rating = "Low"  # Valeur par défaut
    total_cdn_subdomains = 0
    total_cdn_ips = set()

    # Répertoire de travail d'origine (restauré après chaque domaine)
    _initial_cwd = os.getcwd()

    for domain in domains:
        # Toutes les sorties de ce domaine vont dans Result/<domaine_sans_tld>/data/.
        # On s'y place : les écritures relatives du scanner atterrissent au bon endroit
        # (les fichiers de Parameters sont, eux, résolus en chemins absolus).
        domain_data_dir = exposia_paths.data_dir(domain)
        os.chdir(domain_data_dir)
        ModernUI.status(f"Output directory: {domain_data_dir}", "info")

        scanner = SubdomainScanner(domain, nvd_api_key=nvd_key)
        start_time = time.time()

        try:
            # Étape 1 : Récupération des sous-domaines
            subdomains = scanner.get_subdomains()
            if not subdomains:
                ModernUI.status(f"No subdomains found for {domain}", "warning")
                continue

            ModernUI.status(f"Found {len(subdomains)} unique subdomains for {domain}", "success")

            # Étape 2 : Résolution des IPs
            ip_data, all_ips = scanner.resolve_ips(subdomains)
            ModernUI.status(f"Resolved {len(all_ips)} unique IP addresses", "success")

            # Étape 3 : Export des résultats intermédiaires
            scanner.export_results(subdomains, ip_data, all_ips)

            # Étape 4 : Scan Shodan (si clé API fournie)
            vulnerabilities_found = 0
            unique_vulnerabilities = 0
            scanned_ips = 0
            total_exploits_domain = 0

            if all_ips and shodan_key:
                api_key = shodan_key
                try:
                    test_api = shodan.Shodan(api_key)
                    test_api.info()
                except shodan.APIError as e:
                    ModernUI.status(f"Invalid Shodan API key: {e}", "error")
                    continue

                # Scan des vulnérabilités avec Shodan
                vulnerabilities_found, unique_vulnerabilities, scanned_ips = scanner.shodan_query(api_key, all_ips)

                if unique_vulnerabilities > 0:
                    ModernUI.status("Finding known public exploits...", "info")
                    cve_ids = []
                    try:
                        with open("cve_identifies.csv", "r") as f:
                            reader = csv.reader(f, delimiter=';')
                            next(reader)  # Sauter l'en-tête
                            cve_ids = [row[0] for row in reader if row]
                    except FileNotFoundError:
                        ModernUI.status("cve_identifies.csv not found.", "error")
                        continue

                    all_results = []
                    total_exploits_domain = 0
                    progress_bar = ModernUI.tqdm_progress(
                        cve_ids,
                        desc="Checking exploits",
                        total=len(cve_ids),
                        unit="CVEs"
                    )

                    for cve_id in progress_bar:
                        # Sources indépendantes : chaque CVE est toujours conservée,
                        # avec les données des sources qui ont répondu.
                        cve_details, exploits_count = scanner.get_cve_details(cve_id.strip())
                        all_results.append(cve_details)
                        total_exploits_domain += exploits_count

                    progress_bar.close()
                    scanner.report_enrichment_failures(len(cve_ids))
                    scanner.export_cve_to_csv(all_results)
                else:
                    ModernUI.status("No vulnerabilities found - skipping exploit search.", "info")

            # Étape 5 : Génération du rapport centralisé avec calcul de criticité AVANT enrichissement
            success, avg_criticality_score, avg_qualitative_rating = scanner.generate_centralized_report()
            total_cdn_subdomains += scanner.cdn_stats["subdomains"]
            total_cdn_ips |= scanner.cdn_stats["ips"]

            if success:
                scanner.replace_nan_with_na(domain)

                # Utiliser les scores calculés AVANT enrichissement
                if avg_criticality_score is not None:
                    global_criticality_score += avg_criticality_score
                    global_qualitative_rating = avg_qualitative_rating

                # Analyse des vulnérabilités (après enrichissement)
                main_domain = scanner.get_main_domain(domain)
                if os.path.exists(f'Exposia_{main_domain}.csv'):
                    scanner.analyze_vulnerabilities()
                    # Plancher « High » si au moins une exposition est Critical.
                    try:
                        _quals = pd.read_csv(f'Exposia_{main_domain}.csv', sep=';',
                                             usecols=['Exposia - Qualification'])['Exposia - Qualification']
                        global_qualitative_rating = apply_critical_floor(global_qualitative_rating, _quals)
                    except Exception:
                        pass

            # Mise à jour des statistiques globales
            elapsed = time.time() - start_time
            total_elapsed += elapsed
            total_subdomains += len(subdomains)
            total_unique_ips += len(all_ips)
            total_vulnerabilities += unique_vulnerabilities
            total_exploits += total_exploits_domain
            total_scanned_ips += scanned_ips

        except KeyboardInterrupt:
            ModernUI.status("Scan interrupted by user", "warning")
        except Exception as e:
            ModernUI.status(f"Unexpected error: {str(e)}", "error")
        finally:
            # Toujours revenir au répertoire d'origine, même en cas d'erreur
            os.chdir(_initial_cwd)

    # --- Affichage du résumé final ---
    total_hours = int(total_elapsed // 3600)
    total_minutes = int((total_elapsed % 3600) // 60)
    total_seconds = int(total_elapsed % 60)

    # Calcul de la criticité globale moyenne
    if len(domains) > 0:
        avg_global_criticality_score = global_criticality_score / len(domains)
        if pd.isna(avg_global_criticality_score):
            avg_global_criticality_score = 0
            global_qualitative_rating = "Low"
    else:
        avg_global_criticality_score = 0
        global_qualitative_rating = "Low"

    # Métriques du run persistées pour le SUMMARY global affiché en fin de pipeline
    # (D1 initialise le fichier ; D2 et D3 y ajoutent ensuite leurs propres métriques).
    run_metrics = {
        "domains": len(domains),
        "subdomains": total_subdomains,
        "unique_ips": total_unique_ips,
        "scanned_ips": total_scanned_ips,
        "vulnerabilities": total_vulnerabilities,
        "exploits": total_exploits,
        "criticality_score": round(float(avg_global_criticality_score), 2),
        "criticality_rating": global_qualitative_rating,
        "cdn_subdomains": total_cdn_subdomains,
        "cdn_edge_ips": len(total_cdn_ips),
    }
    import json
    for _domain in domains:
        try:
            _path = os.path.join(exposia_paths.data_dir(_domain), "run_summary.json")
            with open(_path, "w", encoding="utf-8") as _f:
                json.dump(run_metrics, _f, ensure_ascii=False)
        except Exception as _e:
            ModernUI.status(f"Écriture run_summary.json impossible : {_e}", "warning")

if __name__ == "__main__":
    main()