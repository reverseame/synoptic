"""Compare two replay logs (sent messages and reply codes). Usage: compare_replay_logs.py LOG_A LOG_B"""
import ast
import re
import sys


def exchanges(path):
    out = []
    accepted = 0
    for line in open(path, errors='replace'):
        if line.startswith('---> '):
            accepted += 1
            continue
        m = re.search(r': (send|recv): (b.*)$', line.rstrip('\n'))
        if not m:
            continue
        data = ast.literal_eval(m.group(2))
        if m.group(1) == 'send':
            out.append(['send', data])
        else:
            code = re.match(rb'^(\d{3})', data)
            out.append(['recv', code.group(1) if code else data[:20]])
    return out, accepted


a, acc_a = exchanges(sys.argv[1])
b, acc_b = exchanges(sys.argv[2])
print('exchanges', len(a), len(b), 'accepted', acc_a, acc_b)
diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
print('differences', len(diffs))
for i in diffs[:15]:
    print(i, a[max(0, i - 2):i + 1], '|', b[max(0, i - 2):i + 1])
