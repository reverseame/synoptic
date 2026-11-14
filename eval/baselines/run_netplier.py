#!/usr/bin/env python3
"""Run NetPlier's keyword inference on an FTP pcap and export message types.

Usage: run_netplier.py PCAP SERVER_PORT OUT_JSON

NetPlier infers which aligned field is the keyword and clusters messages by
its value. We export, for every client request, the inferred keyword value
(used as the message-type label) so that score.py can compare it with the
ground-truth FTP command.
"""
import json
import os
import sys
import tempfile
import time

from alignment import Alignment
from clustering import Clustering
from netplier import NetPlier
from processing import Processing


def main():
    pcap, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    p = Processing(filepath=pcap, protocol_type=None, layer=5)
    workdir = tempfile.mkdtemp(prefix='netplier-')
    t = time.time()
    np_ = NetPlier(messages=p.messages, direction_list=p.direction_list, output_dir=workdir, mode='ginsi',
                   multithread=False)
    result = {'pcap': pcap, 'port': port, 'messages': {}, 'error': None}
    try:
        fid_inferred = np_.execute()
    except (IndexError, ValueError) as e:
        # NetPlier aborts when the alignment yields no keyword candidate field.
        result['error'] = f'{type(e).__name__}: {e}'
        result['aligned_fields'] = len(getattr(np_, 'fields', []) or [])
        fid_inferred = None
    if fid_inferred is not None:
        aligned = Alignment.get_messages_aligned(np_.messages, os.path.join(np_.output_dir, Alignment.FILENAME_OUTPUT_ONELINE))
        labels = Clustering(fields=np_.fields, protocol_type=None).cluster_by_kw_inferred(fid_inferred, aligned)
        result['fid_inferred'] = list(fid_inferred)
        for msg, label in zip(np_.messages, labels):
            if str(msg.destination).endswith(f':{port}'):
                result['messages'].setdefault(msg.data.hex(), {'netplier_label': label})
    result['netplier_seconds'] = round(time.time() - t, 2)
    with open(out, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'{pcap}: error={result["error"]} labels={len({v["netplier_label"] for v in result["messages"].values()})}')


if __name__ == '__main__':
    main()
