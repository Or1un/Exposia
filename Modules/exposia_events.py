#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exposia_events.py — Événements de progression (JSON Lines) pour une interface
qui pilote Exposia (Lucid) : une ligne JSON par événement, ajoutée à
Result/<campagne>/data/events.jsonl avec `run_pipeline.sh --events` (fichier
réécrit à chaque run).

Inactif sans --events : run_pipeline.sh exporte EXPOSIA_EVENTS (chemin du
fichier) et EXPOSIA_RUN_ID ; sans eux, emit() ne fait rien. Une erreur
d'écriture n'interrompt jamais l'analyse.

Champs communs : v (format, 1), ts (UTC), run_id (celui de run.run_id dans le
JSON canonique), event. Événements :

  run_started    domain, campaign, lang       lang : fr | en (langue des livrables)
  step_started   step                       (D1, D2, D3, R1…R13)
  step_finished  step, status, rc, duration_s   status : ok | failed
  step_skipped   step, reason
  progress       step, phase, done, total   avancement d'une boucle (≤ 1 par seconde)
  count          step, name, value          compteur brut de collecte (subdomains, ips,
                                            services, cves, exploits, mitigations, actors)
  snapshot       step, phase, domain, items éléments trouvés, à la fin de chaque phase de D1 :
                   subdomains        [{host}]
                   resolving_ips     [{host, ips}]          (ips vide : non résolu)
                   scanning_ips      [{ip, port, cves}]
                   checking_exploits [{cve, exploits, epss, kev}]   (kev : true, false ou null)
                   cve_analysis      [{cve, cvss, vector}]
  source         source, status, …          état d'une source, mêmes clés que run.sources :
                                            ok | partial | unavailable | skipped (état publié
                                            dans run.sources), retry (http_status, attempt,
                                            max_attempts, wait_s) ou error (http_status ou message)
  consolidated   step, domain, counts, cdn  chiffres après consolidation (frontaux CDN
                                            écartés) : counts {subdomains, ips, services, cves,
                                            exploits}, cdn {subdomains, edge_ips, rows_set_aside}
  run_finished   status, rc, duration_s, campaign_dir, outputs

Deux familles de chiffres, aux noms distincts : `count` donne les compteurs bruts
de la collecte, au fil de l'eau (D1 y compte le domaine racine et les frontaux
CDN) ; `consolidated` donne, une fois les frontaux CDN écartés, les chiffres du
rapport, ceux de summary.counts dans le JSON canonique. L'écart entre les deux
est la consolidation, que `cdn` détaille.

Usage en ligne de commande (run_pipeline.sh) :
  python exposia_events.py <event> [clé=valeur …]   (entiers et décimaux reconnus)
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

EVENTS_FORMAT = 1
PROGRESS_INTERVAL = 1.0   # secondes entre deux événements `progress` d'une même boucle


def _path():
    return os.environ.get('EXPOSIA_EVENTS') or None


def enabled():
    return _path() is not None


def emit(event, **fields):
    """Ajoute un événement au fichier ; sans effet si --events n'est pas utilisé."""
    path = _path()
    if not path:
        return
    record = {'v': EVENTS_FORMAT,
              'ts': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
              'run_id': os.environ.get('EXPOSIA_RUN_ID') or None, 'event': event}
    if 'step' not in fields and os.environ.get('EXPOSIA_STEP') and event in ('progress', 'count'):
        fields['step'] = os.environ['EXPOSIA_STEP']
    record.update(fields)
    line = (json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)   # une écriture par ligne : pas de ligne coupée pour un lecteur qui suit le fichier
        finally:
            os.close(fd)
    except OSError:
        pass


def count(name, value, **fields):
    emit('count', name=name, value=int(value), **fields)


def _phase(label):
    return re.sub(r'[^a-z0-9]+', '_', str(label or 'loop').lower()).strip('_') or 'loop'


def track(iterable, phase, total=None):
    """
    Itérable inchangé, avec un événement `progress` au plus par seconde et un
    dernier à la fin de la boucle. Sans --events, renvoie l'itérable tel quel.
    """
    if not enabled():
        return iterable
    if total is None:
        try:
            total = len(iterable)
        except TypeError:
            total = None
    phase = _phase(phase)

    def gen():
        done, last, sent = 0, 0.0, 0
        emit('progress', phase=phase, done=0, total=total)
        for item in iterable:
            yield item
            done += 1
            now = time.monotonic()
            if now - last >= PROGRESS_INTERVAL:
                last, sent = now, done
                emit('progress', phase=phase, done=done, total=total)
        if sent != done:
            emit('progress', phase=phase, done=done, total=total)
    return gen()


def _cli_value(text):
    if re.fullmatch(r'-?\d+', text):
        return int(text)
    if re.fullmatch(r'-?\d+\.\d+', text):
        return float(text)
    return text


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    fields = {}
    for arg in argv[1:]:
        key, sep, value = arg.partition('=')
        if sep and key:
            fields[key] = _cli_value(value)
    if 'outputs' in fields and isinstance(fields['outputs'], str):
        fields['outputs'] = {k: v for k, _, v in (p.partition(':') for p in fields['outputs'].split(',') if p)}
    emit(argv[0], **fields)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
