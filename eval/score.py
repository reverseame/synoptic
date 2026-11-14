#!/usr/bin/env python3
"""Score the two quantitative comparisons.

Usage: score.py RESULTS_DIR

RESULTS_DIR layout:
  ground_truth.json                       (ground_truth.py)
  runs/<target>/<condition>/result.json   (run_target.py)
  baselines/<target>.json                 (baselines/run_format_baselines.py)

Writes vocabulary.csv and format.csv into RESULTS_DIR and prints both tables.
"""
import csv
import glob
import json
import os
import sys
from collections import Counter


# --------------------------------------------------------------------------- metric 1

def vocabulary(results_dir):
    gt = json.load(open(os.path.join(results_dir, 'ground_truth.json')))
    rows = []
    for path in sorted(glob.glob(os.path.join(results_dir, 'runs', '*', '*', 'result.json'))):
        r = json.load(open(path))
        truth = set(gt[r['target']]['implemented'])
        observed = set(r['observed_keywords'])
        synoptic = observed | set(r['inferred_keywords'])
        row = {
            'target': r['target'], 'condition': r['condition'], 'engine': r['engine'], 'implemented': len(truth),
            'observed': len(observed), 'inferred': len(set(r['inferred_keywords']) - observed),
            'recall_trace': len(observed & truth) / len(truth),
            'recall_synoptic': len(synoptic & truth) / len(truth),
            'precision_synoptic': len(synoptic & truth) / len(synoptic) if synoptic else 0.0,
            'not_implemented': ' '.join(sorted(synoptic - truth)),
            'missed': ' '.join(sorted(truth - synoptic)),
            'tainted_loops': sum(r['tainted_loops'].values()),
            'symbolic_error': r.get('symbolic_error') or '',
        }
        if 'parser_table' in gt[r['target']]:
            table = set(gt[r['target']]['parser_table'])
            row['parser_table'] = len(table)
            row['recall_parser_table'] = len(synoptic & table) / len(table)
        rows.append(row)
    return rows


# --------------------------------------------------------------------------- metric 2

def truth_fields(data):
    """Ground-truth FTP request fields: keyword, SP, argument, CRLF."""
    end = len(data) - 2 if data.endswith(b'\r\n') else len(data)
    body = data[:end]
    kw, sp, arg = body.partition(b' ')
    cuts = {len(kw)}
    if sp:
        cuts.add(len(kw) + 1)
        if arg:
            cuts.add(end)
    else:
        cuts.add(end)
    cuts.discard(0)
    cuts.discard(len(data))
    return kw.upper(), cuts


def neutral(data):
    """The CR|LF split is neither required nor penalized."""
    return {len(data) - 1} if data.endswith(b'\r\n') else set()


def adjusted_rand(labels_true, labels_pred):
    n = len(labels_true)
    if n < 2:
        return 1.0
    pairs = Counter(zip(labels_true, labels_pred))
    a = Counter(labels_true)
    b = Counter(labels_pred)
    index = sum(comb(c, 2) for c in pairs.values())
    sum_a = sum(comb(c, 2) for c in a.values())
    sum_b = sum(comb(c, 2) for c in b.values())
    expected = sum_a * sum_b / comb(n, 2)
    maximum = (sum_a + sum_b) / 2
    return (index - expected) / (maximum - expected) if maximum != expected else 1.0


def score_tool(messages, get_cuts=None, get_cluster=None, get_keyword=None):
    """Boundary P/R/F1 (if get_cuts), keyword accuracy, and ARI of message types (if get_cluster)."""
    tp = fp = fn = 0
    kw_ok = 0
    labels_true, labels_pred = [], []
    for data, info in messages.items():
        kw, truth = truth_fields(data)
        if get_cuts:
            cuts = get_cuts(info)
            pred = set(cuts) - neutral(data)
            tp += len(pred & truth)
            fp += len(pred - truth)
            fn += len(truth - pred)
        if get_keyword:
            kw_ok += get_keyword(data, info).upper() == kw
        elif get_cuts:
            kw_ok += data[:min(cuts, default=len(data))].upper() == kw
        if get_cluster:
            labels_true.append(kw)
            labels_pred.append(get_cluster(data, info))
    out = {'messages': len(messages), 'precision': None, 'recall': None, 'f1': None, 'keyword_accuracy': None}
    if get_cuts:
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        out.update(precision=p, recall=r, f1=2 * p * r / (p + r) if p + r else 0.0)
    if (get_cuts or get_keyword) and messages:
        out['keyword_accuracy'] = kw_ok / len(messages)
    out['ari'] = adjusted_rand(labels_true, labels_pred) if get_cluster else None
    return out


def format_inference(results_dir):
    rows = []
    for bpath in sorted(glob.glob(os.path.join(results_dir, 'baselines', '*.json'))):
        if bpath.endswith('-netplier.json'):
            continue
        target = os.path.basename(bpath)[:-5]
        # Message structures come from the trace and do not depend on the symbolic engine.
        candidates = sorted(glob.glob(os.path.join(results_dir, 'runs', target, 'all-*', 'result.json')))
        if not candidates:
            continue
        rpath = candidates[0]
        base = json.load(open(bpath))['messages']
        syn = {}
        for m in json.load(open(rpath))['messages']:
            data = bytes.fromhex(m['buffer'])
            syn.setdefault(data, m)
        common = {bytes.fromhex(h): v for h, v in base.items() if bytes.fromhex(h) in syn}

        def syn_cuts(data):
            cuts, pos = [], 0
            for seg in syn[data]['structure'][:-1]:
                pos += len(bytes.fromhex(seg))
                cuts.append(pos)
            return cuts

        tools = {
            'Synoptic': score_tool({d: d for d in common}, syn_cuts,
                                   get_cluster=lambda d, _i: bytes.fromhex(syn[d]['keyword']).upper(),
                                   get_keyword=lambda d, _i: bytes.fromhex(syn[d]['keyword'])),
            'NEMESYS': score_tool({d: v for d, v in common.items() if 'nemesys' in v}, lambda v: v['nemesys']),
            'Netzob': score_tool({d: v for d, v in common.items() if 'netzob' in v}, lambda v: v['netzob'],
                                 get_cluster=lambda _d, v: v['netzob_symbol']),
        }
        npath = os.path.join(results_dir, 'baselines', f'{target}-netplier.json')
        netplier = json.load(open(npath)) if os.path.exists(npath) else None
        if netplier and netplier['messages']:
            labels = {bytes.fromhex(h): v['netplier_label'] for h, v in netplier['messages'].items()}
            tools['NetPlier'] = score_tool({d: labels[d] for d in common if d in labels},
                                           get_cluster=lambda _d, label: label)
        for tool, s in tools.items():
            rows.append({'target': target, 'tool': tool, 'unique_requests': len(base),
                         'matched_in_trace': len(common), **s, 'error': ''})
        if netplier and not netplier['messages']:
            rows.append({'target': target, 'tool': 'NetPlier', 'unique_requests': len(base),
                         'matched_in_trace': len(common), 'error': netplier.get('error') or 'no output'})
    return rows


def write(rows, path):
    if not rows:
        return
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        w.writeheader()
        w.writerows(rows)


def show(rows):
    for r in rows:
        print('  '.join(f'{k}={v:.3f}' if isinstance(v, float) else f'{k}={"-" if v is None else v}'
                        for k, v in r.items()))


def main():
    results = sys.argv[1]
    voc = vocabulary(results)
    fmt = format_inference(results)
    write(voc, os.path.join(results, 'vocabulary.csv'))
    write(fmt, os.path.join(results, 'format.csv'))
    print('# Vocabulary'); show(voc)
    print('# Format inference'); show(fmt)


if __name__ == '__main__':
    main()
