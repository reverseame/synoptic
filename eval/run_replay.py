#!/usr/bin/env python3
"""Run Synoptic's replay stage against an uninstrumented server.

Usage: run_replay.py TARGET FSM_JSON OUTDIR [--conf FILE] [--delay MS]

The server runs as a standalone daemon, because the replayer reconnects after every QUIT. The
replayer loads FSM_JSON (an fsm.json exported by the analysis), sends every recovered keyword from
the initial state and from each state of the observed sequence, and adds accepted ones to the FSM.
OUTDIR receives replay.json (one record per exchange, candidate counts) and fsm-inferred.json.
"""
import argparse
import collections
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, '/opt/synoptic')

import capstone  # noqa: E402

import synoptic.tracemodeler.model as synoptic_model  # noqa: E402
import synoptic.tracemodeler.replayer as replayer  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_target import TARGETS, listening, log  # noqa: E402


def fsm_size(fsm_dict):
    """Number of states and transitions of an exported FSM."""
    states = fsm_dict['states']
    return len(states), sum(len(transitions) for transitions in states.values())


def instrument(records):
    """Record every exchange of the replayer, and which of them were judged as candidates."""
    original_exchange = replayer.Replayer._send_recv_message
    original_is_ok = replayer.Replayer.resp_is_ok

    def exchange(self, message):
        record = {'sent': message.buffer.decode(errors='replace'), 'code': None, 'error': None}
        records.append(record)
        try:
            (resp, code) = original_exchange(self, message)
        except Exception as e:
            record['error'] = f'{type(e).__name__}: {e}'
            raise
        record['code'] = code.decode(errors='replace')
        return (resp, code)

    def is_ok(self, code):
        accepted = original_is_ok(self, code)
        records[-1]['candidate'] = True
        records[-1]['accepted'] = bool(accepted)
        return accepted

    replayer.Replayer._send_recv_message = exchange
    replayer.Replayer.resp_is_ok = is_ok


def fixed_acceptance(self, response_code):
    """resp_is_ok with the intended list of accepted non-2xx codes, for replayers that predate the fix"""
    return (response_code[:1] == b'2') or (response_code in [b'150', b'331'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', choices=sorted(TARGETS))
    ap.add_argument('fsm')
    ap.add_argument('outdir')
    ap.add_argument('--conf', help='server configuration replacing the ProFuzzBench one')
    ap.add_argument('--delay', type=int, default=200, help='delay between messages (ms), as in the case study')
    ap.add_argument('--fixed-acceptance', action='store_true',
                    help='replace resp_is_ok by the corrected version (only for the original replayer)')
    args = ap.parse_args()

    cfg = TARGETS[args.target]
    os.makedirs(args.outdir)
    server_args = [a for a in cfg['args'] if a != '-X']
    if args.conf:
        server_args[server_args.index('-c') + 1] = args.conf
    server = subprocess.Popen([cfg['binary'], *server_args], cwd=cfg['cwd'], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    records = []
    if args.fixed_acceptance:
        replayer.Replayer.resp_is_ok = fixed_acceptance
    instrument(records)
    try:
        deadline = time.time() + 60
        while time.time() < deadline and not listening(cfg['port']):
            time.sleep(1)
        if not listening(cfg['port']):
            raise RuntimeError(f'{args.target}: server not listening')

        with open(args.fsm) as f:
            fsm_text = f.read()
        model = synoptic_model.Model(arch_mode=capstone.CS_MODE_64)
        model.fsm.loads(fsm_text)
        candidates = [m.buffer.decode(errors='replace') for m in model.fsm.generate_new_messages()]
        log(f'replaying {len(candidates)} candidates from {len(model.fsm.sequence)} contexts')

        t0 = time.time()
        fsm = replayer.Replayer('127.0.0.1', cfg['port'], 'tcp', args.delay / 1000).replay(
            model.fsm, symbolic_messages=True)
        seconds = round(time.time() - t0, 1)
        fsm.export_to_file(os.path.join(args.outdir, 'fsm-inferred.json'))
    finally:
        os.killpg(server.pid, signal.SIGTERM)
        try:
            server.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(server.pid, signal.SIGKILL)

    # Candidates whose exchange failed never reach resp_is_ok: count them as rejected candidates.
    for record in records:
        if 'candidate' not in record and record['error'] and record['sent'] in candidates:
            record['candidate'] = True
            record['accepted'] = False
    tested = [r for r in records if r.get('candidate')]
    with open(os.path.join(args.outdir, 'fsm-inferred.json')) as f:
        after = fsm_size(json.load(f))
    result = {
        'target': args.target, 'fsm': args.fsm, 'conf': args.conf, 'delay_ms': args.delay, 'seconds': seconds,
        'n_inferred_keywords': len(candidates), 'n_contexts': len(model.fsm.sequence),
        'candidates': len(tested), 'accepted': sum(r['accepted'] for r in tested),
        'accepted_keywords': sorted({r['sent'].strip() for r in tested if r['accepted']}),
        'rejected_codes': dict(collections.Counter(r['code'] or 'error' for r in tested if not r['accepted'])),
        'fsm_before': fsm_size(json.loads(fsm_text)), 'fsm_after': after,
        'records': records,
    }
    with open(os.path.join(args.outdir, 'replay.json'), 'w') as f:
        json.dump(result, f, indent=1)
    log(f"candidates={result['candidates']} accepted={result['accepted']} "
        f"fsm={result['fsm_before']}->{result['fsm_after']} keywords={len(result['accepted_keywords'])}")


if __name__ == '__main__':
    main()
