#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R13_results_json.py — JSON canonique des résultats d'une campagne.

Écrit Result/<campagne>/Exposia_<campagne>_results.json, conforme à
schema/results.schema.json. Une seule source de vérité hors PDF : R12 (digest),
Lucid et tout outil tiers le lisent au lieu de parser les CSV.

Contenu :
  • parts     : « En clair » et données des visuels des cinq parties, tels que
                calculés par build_*_data() de R1, R2, R3, R4 et R6 — le même
                dict que celui dont le PDF est rendu (parité par construction) ;
  • catalogues: hosts, exposures, scenarios, mitigations, actors, auxquels les
                parties renvoient par identifiant ;
  • summary   : chiffres de synthèse et criticité ;
  • run       : identifiant, dates, langue, sources de collecte (run_summary.json).

Conventions : codes plutôt que libellés (libellés du run dans `labels`), null pour
une donnée absente, clés triées, écriture atomique. Deux exécutions sur les
mêmes données donnent le même fichier, hors run.generated_at et run.run_id.

Usage :
  python R13_results_json.py [-r Result/<campagne>] [-d <dossier data>] [-o <fichier>]
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULES = os.path.dirname(_HERE)
for _p in (_HERE, _MODULES):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import exposia_paths  # noqa: E402
import exposia_vocab as vocab  # noqa: E402
import exposia_i18n as i18n  # noqa: E402
from exposia_ui import ModernUI  # noqa: E402

import R1_threat_modeling as R1  # noqa: E402
import R2_Asset_discovery as R2  # noqa: E402
import R3_Risk_assessment as R3  # noqa: E402
import R4_mitigation as R4  # noqa: E402
import R6_synthesis_global as R6  # noqa: E402

SCHEMA_VERSION = "1.0.0"

SOURCE_KEYS = ('crtsh', 'certspotter', 'dns', 'shodan', 'nvd', 'epss', 'exploitdb', 'poc_in_github', 'kev')

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

_NA = {'', '#n/a', 'n/a', 'nan', 'none', 'null', 'no data', 'no ip found'}
_HOST_RE = re.compile(r'^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$')
_TAG_RE = re.compile(r'^[a-z0-9_]+$')
_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')

# Colonnes du fichier de travail : nom interne (après D2) puis nom d'affichage (D1).
COLUMNS = {
    'domain': ('domain', 'Domain'),
    'host': ('subdomain', 'Subdomain'),
    'ip': ('ip_address', 'IP Address'),
    'port': ('port', 'Port'),
    'nature': ('classification', 'Internal_External_Classification'),
    'service': ('service', 'Service'),
    'category': ('category', 'Catégorie'),
    'cve': ('cve', 'Vulnerability (CVE)'),
    'exploits_count': ('exploits_count', 'Number of Exploits'),
    'year': ('cve_year', 'CVE - Year'),
    'cvss': ('cvss_score', 'CVSS Score'),
    'epss': ('epss_score', 'EPSS Score'),
    'business_impact': ('business_impact', 'Impact business / opérationnel'),
    'qualification': ('exposia_qualification', 'Exposia - Qualification'),
    'exploit_references': ('exploit_references', 'Exploits'),
    'kev': ('kev', 'KEV'),
    'kev_date_added': ('kev_date_added', 'KEV Date Added'),
    'kev_ransomware': ('kev_ransomware', 'KEV Ransomware'),
    'cvss_version': ('cvss_version', 'CVSS_Version'),
    'cvss_vector': ('cvss_vector', 'CVSS_Vector'),
    'hosting': ('hosting', 'Hosting'),
    'reconnaissance': ('reconnaissance', 'Reconnaissance'),
    'exploitation': ('exploitation', 'Exploitation'),
    'impact': ('impact', 'Impact'),
    'tags': ('tags', 'Tags'),
    'path_type': ('attack_path_type', 'Attack_Path_Type'),
    'mitigation_id': ('mitigation_id',),
}


class ResultsError(Exception):
    """Données de campagne manquantes ou inexploitables."""


# ---------------------------------------------------------------------------
# Lecture
# ---------------------------------------------------------------------------

def _value(row, field):
    """Valeur nettoyée d'un champ ('' si absente ou marqueur d'absence)."""
    for name in COLUMNS[field]:
        if name in row:
            text = str(row.get(name) if row.get(name) is not None else '').strip()
            return '' if text.lower() in _NA else text
    return ''


def _int(text):
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def _float(text):
    try:
        number = float(text)
    except (TypeError, ValueError):
        return None
    return None if number != number else number  # NaN


def _read_csv(path):
    with open(path, encoding='utf-8-sig', newline='') as f:
        # Délimiteur deviné sur l'en-tête seul : les valeurs contiennent des virgules (listes de CVE).
        header = f.readline()
        f.seek(0)
        delimiter = max((';', ',', '\t'), key=header.count)
        return list(csv.DictReader(f, delimiter=delimiter))


def _working_csv(data_dir):
    files = [f for f in glob.glob(os.path.join(data_dir, 'Exposia_*.csv'))
             if not f.endswith('_presentation.csv')]
    if not files:
        raise ResultsError(f"Aucun fichier Exposia_*.csv dans {data_dir}")
    return max(files, key=os.path.getmtime)


def _load_run_summary(data_dir):
    path = os.path.join(data_dir, 'run_summary.json')
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _host(text):
    host = text.strip().lower().rstrip('.')
    if host.startswith('www.www.'):
        host = host[4:]
    return host


def _service(text):
    """Nom de service conforme au schéma ('https', 'ssh', 'ms-sql-s'…) ou None."""
    s = re.sub(r'\s+', '_', text.strip().lower())
    s = re.sub(r'[^a-z0-9_./+-]', '', s)[:32]
    return s if s and s[0].isalnum() else None


def _severity(text):
    return vocab.code('severity', text)


def _max_severity(codes):
    codes = [c for c in codes if c]
    return min(codes, key=lambda c: SEVERITY_RANK[c]) if codes else None


# ---------------------------------------------------------------------------
# Catalogues
# ---------------------------------------------------------------------------

class _Scenarios:
    """Registre des scénarios types : un identifiant par (CVE, reconnaissance, exploitation, impact)."""

    def __init__(self):
        self.by_key, self.items = {}, []

    @staticmethod
    def key(cve, recon, exploit, impact):
        return (cve or '', recon, exploit, impact)

    def add(self, key, kind, tags):
        if key not in self.by_key:
            sid = f"S{len(self.items) + 1:02d}"
            self.by_key[key] = sid
            self.items.append({'id': sid, 'kind': kind, 'cve': key[0] or None,
                               'reconnaissance': i18n.text(key[1]), 'exploitation': i18n.text(key[2]),
                               'impact': i18n.text(key[3]), 'tags': tags})
        return self.by_key[key]


def _path_of(row):
    """(clé de scénario, type) d'une ligne, ou None si le scénario est incomplet (règle de R3)."""
    recon, exploit, impact = (_value(row, f) for f in ('reconnaissance', 'exploitation', 'impact'))
    if not (recon and exploit and impact):
        return None
    is_port = _value(row, 'path_type').upper() == 'PORT'
    cve = '' if is_port else _value(row, 'cve')
    return _Scenarios.key(cve, recon, exploit, impact), ('port' if is_port else 'cve')


def _tags(row):
    return sorted({t.strip() for t in _value(row, 'tags').split(',') if _TAG_RE.match(t.strip())})


def _kev(rows):
    """null : non confrontée au catalogue ; {listed: false} ; {listed: true, date_added, ransomware}."""
    for row in rows:
        flag = _value(row, 'kev').lower()
        if flag == 'yes':
            date = _value(row, 'kev_date_added')
            if re.match(r'^\d{4}-\d{2}-\d{2}$', date):
                return {'listed': True, 'date_added': date,
                        'ransomware': _value(row, 'kev_ransomware').lower() == 'known'}
    if any(_value(r, 'kev').lower() == 'no' for r in rows):
        return {'listed': False}
    return None


def _cvss(row):
    score = _float(_value(row, 'cvss'))
    if score is None:
        return None
    return {'score': score, 'version': _value(row, 'cvss_version') or None,
            'vector': _value(row, 'cvss_vector') or None}


def build_exposures(rows, mitigation_rank):
    """
    Catalogue des expositions (sous-domaine, port), catalogue des scénarios et
    lignes groupées par exposition. Ordre : celui de R3 (qualification, impact
    métier, EPSS), puis nom et port pour départager.
    """
    groups = defaultdict(list)
    for row in rows:
        host, ip, port = _host(_value(row, 'host')), _value(row, 'ip'), _int(_value(row, 'port'))
        if host and ip and port is not None:
            groups[(host, port)].append(row)

    def order(item):
        (host, port), grp = item
        qual = _max_severity(_severity(_value(r, 'qualification')) for r in grp)
        impact = _max_severity(_severity(_value(r, 'business_impact')) for r in grp)
        epss = max([_float(_value(r, 'epss')) or 0.0 for r in grp if _path_of(r)] or [0.0])
        return (SEVERITY_RANK.get(qual, 4), SEVERITY_RANK.get(impact, 4), -epss, host, port)

    scenarios = _Scenarios()
    exposures = []
    for (host, port), grp in sorted(groups.items(), key=order):
        ips = list(dict.fromkeys(_value(r, 'ip') for r in grp))
        hosting = next((_value(r, 'hosting') for r in grp if _value(r, 'hosting')), '')
        is_cdn = hosting.upper().startswith('CDN')
        first = grp[0]

        by_cve = defaultdict(list)
        port_paths = {}
        for row in grp:
            path = _path_of(row)
            cve = _value(row, 'cve')
            if path and path[1] == 'port':
                port_paths.setdefault(path[0], row)
            elif _CVE_RE.match(cve) and _value(row, 'path_type').upper() != 'PORT':
                by_cve[cve].append(row)

        cves = []
        for cve, crow in by_cve.items():
            refs = []
            for r in crow:
                refs.extend(x.strip() for x in _value(r, 'exploit_references').split(','))
            paths = {}
            for r in crow:
                p = _path_of(r)
                if p:
                    paths.setdefault(p[0], r)
            cves.append({
                'cve': cve, 'year': _int(_value(crow[0], 'year')),
                'qualification': _max_severity(_severity(_value(r, 'qualification')) for r in crow) or 'low',
                'cvss': _cvss(crow[0]), 'epss': _float(_value(crow[0], 'epss')),
                'exploits_count': max(_int(_value(r, 'exploits_count')) or 0 for r in crow),
                'exploit_references': sorted({x for x in refs if x.startswith('https://')}),
                'kev': _kev(crow), '_paths': paths,
            })
        cves.sort(key=lambda c: (SEVERITY_RANK[c['qualification']], -(c['epss'] or 0.0), c['cve']))
        for c in cves:
            c['scenario_ids'] = [scenarios.add(k, 'cve', _tags(r)) for k, r in sorted(c.pop('_paths').items())]
        port_ids = [scenarios.add(k, 'port', _tags(r)) for k, r in sorted(port_paths.items())]

        mitigation_ids = {_value(r, 'mitigation_id') for r in grp} - {''}
        exposures.append({
            'id': f"{host}:{port}", 'host': host, 'port': port, 'ips': ips,
            'hosting': 'cdn' if is_cdn else 'direct',
            'cdn_provider': (hosting[3:].strip() or None) if is_cdn else None,
            'service': _service(_value(first, 'service')),
            'category': vocab.code('service_category', _value(first, 'category')),
            'nature': vocab.code('nature', next((_value(r, 'nature') for r in grp if _value(r, 'nature').upper() == 'INTERNAL'),
                                                _value(first, 'nature'))) or 'standard',
            'business_impact': _max_severity(_severity(_value(r, 'business_impact')) for r in grp),
            'qualification': _max_severity(_severity(_value(r, 'qualification')) for r in grp) or 'low',
            'cves': cves, 'scenario_ids': port_ids,
            'mitigation_ids': sorted(mitigation_ids, key=lambda m: (mitigation_rank.get(m, 10 ** 6), m)),
        })
    return exposures, scenarios


def build_hosts(rows, domain, exposures):
    """Un hôte par nom découvert, domaine racine compris, résolu ou non."""
    ips, names = defaultdict(list), set()
    for row in rows:
        host = _host(_value(row, 'host'))
        if not host:
            continue
        names.add(host)
        ip = _value(row, 'ip')
        if ip and ip not in ips[host]:
            ips[host].append(ip)
    by_host = defaultdict(list)
    for e in exposures:
        by_host[e['host']].append(e['id'])
    root = _host(domain)
    return [{'host': h, 'root': h == root, 'resolved': bool(ips[h]), 'ips': list(ips[h]),
             'exposure_ids': sorted(by_host[h])} for h in sorted(names)]


def build_mitigations(prio_rows, exposures):
    coverage = defaultdict(int)
    for e in exposures:
        for m in e['mitigation_ids']:
            coverage[m] += 1
    items = []
    for rank, row in enumerate(prio_rows, 1):
        mid = (row.get('mitigation_id') or '').strip()
        raw_duration = (row.get('implementation_duration') or '').strip()
        duration = vocab.duration(raw_duration)
        if duration is None and raw_duration:
            ModernUI.status(f"Durée non reconnue pour {mid} : « {raw_duration} »", "warning")
        cves = sorted({c.strip() for c in (row.get('treated_cves') or '').split(',') if _CVE_RE.match(c.strip())})
        text = lambda col: i18n.text((row.get(col) or '').strip()) or None  # noqa: E731
        items.append({
            'id': mid, 'rank': rank, 'score': round(_float(row.get('final_score')) or 0.0, 2),
            'priority': _severity(row.get('priority')) or 'low',
            'type': vocab.code('mitigation_type', row.get('mitigation_type')) or 'preventive',
            'category': vocab.code('mitigation_category', row.get('category')),
            'difficulty': vocab.code('difficulty', row.get('implementation_difficulty')),
            'duration': duration,
            'organizational': text('organizational_measure') or '',
            'technical': text('technical_measure'), 'kpi': text('kpi'),
            'coverage': {'exposures': coverage.get(mid, 0), 'cves': cves},
        })
    return items


def build_actors(data_dir):
    generator = R1.ThreatReportPDFGenerator(data_dir=data_dir)
    data = generator.process_data(generator.load_csv_data(generator.find_csv_file()))
    return [{
        'id': vocab.code('actor', a['actor']), 'score': round(float(a['rank_score']), 2), 'level': a['level_class'],
        'motivations': [{
            'motivation': vocab.code('motivation', m['motivation']),
            'motivation_level': vocab.code('motivation_level', m['motivation_level']),
            'resources_level': vocab.code('resources_level', m['resources']),
            'relevance': vocab.code('relevance', m['probability']),
        } for m in a['all_motivations']],
    } for a in data['actors']]


# ---------------------------------------------------------------------------
# Parties, synthèse, libellés
# ---------------------------------------------------------------------------

def link_scenario_cards(risks, scenarios):
    """Les cartes de R3 portent le récit de leurs scénarios : on le remplace par l'identifiant."""
    for card in risks['visuals']['scenario_cards']:
        linked = []
        for s in card['scenarios']:
            key = _Scenarios.key(s['cve'], s['reconnaissance'].strip(), s['exploitation'].strip(), s['impact'].strip())
            if key not in scenarios.by_key:
                raise ResultsError(f"Scénario de carte absent du catalogue : {key[0] or 'service'} / {key[3][:60]}")
            linked.append({'scenario_id': scenarios.by_key[key], 'cve': s['cve'], 'severity': s['severity']})
        card['scenarios'] = linked
    return risks


def build_sources(run_summary):
    sources = dict(run_summary.get('sources') or {})
    if not sources:
        ModernUI.status("run_summary.json sans bloc « sources » (D1 antérieur) : sources marquées indisponibles", "warning")
    for key in SOURCE_KEYS:
        sources.setdefault(key, {'status': 'unavailable', 'retrieved_at': None})
    return sources


def build_threat_profile(run_summary):
    profile = run_summary.get('threat_profile') or {}
    codes = {'sector': vocab.code('sector', profile.get('secteur')), 'size': vocab.code('size', profile.get('taille')),
             'zone': vocab.code('zone', profile.get('zone'))}
    return codes if all(codes.values()) else None


# Champ -> vocabulaire, pour la table `labels` (category dépend du contexte).
_LABEL_FIELDS = {
    'severity': 'severity', 'qualification': 'severity', 'business_impact': 'severity', 'level': 'severity',
    'priority': 'severity', 'rating': 'severity',
    'actor': 'actor', 'top_actor': 'actor', 'motivation': 'motivation', 'primary_motivation': 'motivation',
    'top_motivation': 'motivation', 'nature': 'nature', 'sophistication': 'qualitative_level',
    'probability': 'qualitative_level', 'resources': 'resources_level', 'resources_level': 'resources_level',
    'motivation_level': 'motivation_level', 'relevance': 'relevance', 'profile_type': 'profile_type',
    'difficulty': 'difficulty', 'unit': 'duration_unit', 'sector': 'sector', 'size': 'size', 'zone': 'zone',
    'hosting': 'hosting',
}
REQUIRED_LABELS = ('severity', 'actor', 'motivation', 'nature', 'mitigation_type', 'service_category',
                   'mitigation_category', 'qualitative_level', 'resources_level', 'difficulty', 'duration_unit',
                   'hosting')


def build_labels(doc, lang):
    used = defaultdict(set)

    def walk(node, mitigation_ctx):
        if isinstance(node, dict):
            for k, v in node.items():
                ctx = mitigation_ctx or k == 'mitigations'
                if isinstance(v, str):
                    if k == 'category':
                        used['mitigation_category' if mitigation_ctx else 'service_category'].add(v)
                    elif k == 'type' and mitigation_ctx:
                        used['mitigation_type'].add(v)
                    elif k in _LABEL_FIELDS:
                        used[_LABEL_FIELDS[k]].add(v)
                elif isinstance(v, list) and k == 'top_categories':
                    used['service_category'].update(x for x in v if isinstance(x, str))
                elif k == 'type_distribution' and isinstance(v, dict):
                    used['mitigation_type'].update(v)
                walk(v, ctx)
        elif isinstance(node, list):
            for v in node:
                walk(v, mitigation_ctx)

    walk({k: doc[k] for k in ('threat_profile', 'summary', 'parts', 'exposures', 'actors')}, False)
    walk({'mitigations': doc['mitigations']}, True)
    used['actor'].update(a['id'] for a in doc['actors'])
    labels = {}
    for name in sorted(set(used) | set(REQUIRED_LABELS)):
        labels[name] = {c: vocab.label(name, c, lang) for c in sorted(used.get(name, ())) if c}
    return labels


def build_summary(parts, exposures, hosts, run_summary):
    assets, risks = parts['assets']['visuals']['key_figures'], parts['risks']['in_short']['facts']
    distribution = {s: 0 for s in SEVERITY_RANK}
    for e in exposures:
        distribution[e['qualification']] += 1
    kev_known = any(c['kev'] is not None for e in exposures for c in e['cves'])
    score = _float(run_summary.get('criticality_score'))
    return {
        'criticality': {'rating': _severity(run_summary.get('criticality_rating')), 'score': score},
        'counts': {
            'subdomains': assets['subdomains'],
            'unresolved_subdomains': sum(1 for h in hosts if not h['root'] and not h['resolved']),
            'ips': assets['ips'], 'services': assets['services'],
            'sensitive_services': assets['sensitive_services'], 'service_categories': assets['service_categories'],
            'exposures': len(exposures), 'cves': risks['cves'], 'exploits': risks['exploits'],
            'kev_cves': risks.get('kev_cves', 0) if kev_known else None,
            'attack_scenarios': risks['attack_scenarios'],
            'actors': parts['threats']['in_short']['facts']['actors'],
            'mitigations': parts['mitigations']['in_short']['facts']['mitigations'],
        },
        'qualification_distribution': distribution,
    }


# ---------------------------------------------------------------------------
# Assemblage
# ---------------------------------------------------------------------------

def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def build_results(data_dir, lang=None, run_id=None, now=None):
    """
    Document complet (dict) pour le dossier data/ d'une campagne. Langue des
    textes et des libellés : celle du run (EXPOSIA_LANG), les codes restent stables.
    """
    data_dir = os.path.abspath(data_dir)
    if lang:  # langue imposée : les modules R la lisent aussi (EXPOSIA_LANG)
        os.environ['EXPOSIA_LANG'] = lang
    lang = i18n.lang()
    now = now or _utc_now()
    campaign = os.path.basename(os.path.dirname(data_dir))
    rows = _read_csv(_working_csv(data_dir))
    if not rows:
        raise ResultsError("Fichier de travail vide")
    prio_path = os.path.join(data_dir, 'mitigation_prioritization_enhanced.csv')
    prio_rows = _read_csv(prio_path) if os.path.exists(prio_path) else []
    run_summary = _load_run_summary(data_dir)
    domain = next((_value(r, 'domain') for r in rows if _value(r, 'domain')), campaign)

    mitigation_rank = {(r.get('mitigation_id') or '').strip(): i for i, r in enumerate(prio_rows, 1)}
    exposures, scenarios = build_exposures(rows, mitigation_rank)
    hosts = build_hosts(rows, domain, exposures)
    parts = {
        'threats': R1.build_threats_data(data_dir),
        'assets': R2.build_assets_data(data_dir),
        'risks': link_scenario_cards(R3.build_risks_data(data_dir), scenarios),
        'mitigations': R4.build_mitigations_data(data_dir),
        'synthesis': R6.build_synthesis_data(data_dir),
    }
    doc = {
        'schema_version': SCHEMA_VERSION,
        'run': {
            'run_id': run_id or os.environ.get('EXPOSIA_RUN_ID') or f"{now:%Y%m%dT%H%M%SZ}-{campaign}",
            'generated_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'analysis_date': now.strftime('%Y-%m-%d'),  # UTC, comme generated_at
            'lang': lang,
            'sources': build_sources(run_summary),
        },
        'target': {'domain': _host(domain), 'campaign': campaign},
        'threat_profile': build_threat_profile(run_summary),
        'parts': parts,
        'hosts': hosts,
        'exposures': exposures,
        'scenarios': scenarios.items,
        'mitigations': build_mitigations(prio_rows, exposures),
        'actors': build_actors(data_dir),
    }
    doc['summary'] = build_summary(parts, exposures, hosts, run_summary)
    doc['labels'] = build_labels(doc, lang)
    return doc


def derived_codes(doc):
    """Codes sans entrée de vocabulaire (slug d'un libellé) : catégorie ajoutée à un référentiel sans code."""
    return {name: sorted(table) for name, table in
            ((n, [c for c in t if c not in vocab.TABLES.get(n, {})]) for n, t in doc['labels'].items()) if table}


def write_results(doc, path):
    """Écriture atomique, clés triées (sortie déterministe)."""
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    os.replace(tmp, path)


def default_output(data_dir):
    campaign_dir = os.path.dirname(os.path.abspath(data_dir))
    return os.path.join(campaign_dir, f"Exposia_{os.path.basename(campaign_dir)}_results.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Écrit le JSON canonique des résultats d'une campagne.")
    parser.add_argument("-r", "--result-dir", default=None,
                        help="Dossier de campagne (ex. Result/exemple). Par défaut : campagne la plus récente.")
    parser.add_argument("-d", "--data-dir", default=None, help="Dossier data/ de la campagne")
    parser.add_argument("-o", "--output", default=None,
                        help="Fichier de sortie (défaut : Result/<campagne>/Exposia_<campagne>_results.json)")
    args = parser.parse_args(argv)
    try:
        data_dir = args.data_dir or exposia_paths.resolve_data_dir(args.result_dir, None)
        doc = build_results(data_dir)
        out = args.output or default_output(data_dir)
        write_results(doc, out)
    except (ResultsError, OSError, ValueError, KeyError) as e:
        ModernUI.status(f"JSON canonique non écrit : {e}", "error")
        return 1
    for name, codes in derived_codes(doc).items():
        ModernUI.status(f"Codes {name} dérivés du libellé (absents de Parameters/ ou du vocabulaire) : "
                        f"{', '.join(codes)}", "warning")
    counts = doc['summary']['counts']
    ModernUI.status(f"JSON canonique écrit : {os.path.basename(out)} ({counts['exposures']} expositions, "
                    f"{len(doc['scenarios'])} scénarios, {counts['mitigations']} mesures)", "success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
