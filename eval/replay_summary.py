#!/usr/bin/env python3
"""Summarize replay.json files: candidates, acceptances, rejection causes, FSM growth.

Usage: replay_summary.py RESULTS_DIR...   (each containing replay.json)

Rejection causes follow Finding 4 of the paper: keywords that the build does not implement
(500 not understood in every context), 530 before authentication, 502 not implemented, replies that
need a data connection (425, or 150 / no parseable reply while a transfer is pending), and the rest,
which ProFTPD answers with parameter-related 500, 501 or 504 replies.
"""
import collections
import json
import os
import sys

UNIMPLEMENTED = {'ADAT', 'AUTH', 'CCC', 'CONF', 'ENC', 'LANG', 'MIC', 'PBSZ', 'PROT'}


def cause(record):
    keyword = record['sent'].split()[0].upper()
    if keyword in UNIMPLEMENTED:
        return 'unimplemented'
    if record['code'] == '530':
        return 'before-login-530'
    if record['code'] == '502':
        return 'not-implemented-502'
    if record['code'] in ('425', '150') or record['error']:
        return 'data-connection'
    return 'missing-parameters'


for d in sys.argv[1:]:
    r = json.load(open(os.path.join(d, 'replay.json')))
    tested = [x for x in r['records'] if x.get('candidate')]
    rejected = [x for x in tested if not x['accepted']]
    accepted_codes = collections.Counter(x['code'] for x in tested if x['accepted'])
    print(f"{os.path.basename(d.rstrip('/'))}: candidates={len(tested)} accepted={r['accepted']} "
          f"({100 * r['accepted'] / len(tested):.0f}%) keywords={len(r['accepted_keywords'])} "
          f"fsm={tuple(r['fsm_before'])}->{tuple(r['fsm_after'])} seconds={r['seconds']}")
    print('  accepted keywords:', ' '.join(r['accepted_keywords']))
    print('  accepted codes:', dict(accepted_codes))
    print('  rejections:', dict(collections.Counter(cause(x) for x in rejected)))
    print('  errors:', collections.Counter(x['error'] for x in r['records'] if x['error']).most_common(5))
