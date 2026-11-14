#!/usr/bin/env python3
"""Run NEMESYS and Netzob on the client requests of an FTP pcap.

Usage: run_format_baselines.py PCAP SERVER_PORT OUT_JSON

Output: for every unique client request (hex), the field boundaries inferred by
each tool and, for Netzob, the index of the symbol (message type) it was
clustered into.
"""
import json
import sys
import time

from netzob import all as netzob

from nemere.inference.segmentHandler import bcDeltaGaussMessageSegmentation, refinements
from nemere.utils.loader import SpecimenLoader


def boundaries(lengths):
    """Offsets between consecutive fields, excluding 0 and the message length."""
    out, pos = [], 0
    for n in lengths[:-1]:
        pos += n
        out.append(pos)
    return [b for b in out if b > 0]


def is_request(msg, port):
    dst = str(getattr(msg, 'destination', '') or '')
    return dst.endswith(f':{port}') or dst.endswith(f'.{port}')


def main():
    pcap, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    specimens = SpecimenLoader(pcap, layer=2, relativeToIP=True)
    all_msgs = list(specimens.messagePool.keys())
    requests = [m for m in all_msgs if is_request(m, port)]
    if not requests:
        raise SystemExit(f'no client requests to port {port} in {pcap}; '
                         f'example destination: {getattr(all_msgs[0], "destination", None)!r}')

    # Deduplicate by payload, keeping the first occurrence.
    unique = {}
    for m in requests:
        unique.setdefault(m.data, m)
    req_set = set(id(m) for m in unique.values())

    result = {'pcap': pcap, 'port': port, 'messages': {}}

    t = time.time()
    segmented = refinements(bcDeltaGaussMessageSegmentation(specimens, 0.6))
    result['nemesys_seconds'] = round(time.time() - t, 2)
    for segs in segmented:
        msg = segs[0].message
        if id(msg) in req_set:
            entry = result['messages'].setdefault(msg.data.hex(), {})
            entry['nemesys'] = boundaries([s.length for s in segs])

    t = time.time()
    symbols = netzob.Format.clusterByAlignment(list(unique.values()), minEquivalence=45, internalSlick=True)
    result['netzob_seconds'] = round(time.time() - t, 2)
    result['netzob_symbols'] = len(symbols)
    for idx, symbol in enumerate(symbols):
        cells = symbol.getMessageCells(encoded=False)
        for msg, values in cells.items():
            entry = result['messages'].setdefault(msg.data.hex(), {})
            entry['netzob'] = boundaries([len(v) for v in values])
            entry['netzob_symbol'] = idx

    with open(out, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'{pcap}: {len(unique)} unique requests, netzob symbols={len(symbols)}')


if __name__ == '__main__':
    main()
