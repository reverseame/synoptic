#!/usr/bin/env python3
"""Export the case-study figures from a traced run: the initial FSM and the TDCFG of one function.

Usage: export_case_study_figures.py BINARY TRACE_DIR FUNCTION OUTDIR

The TDCFG of FUNCTION is enriched with static information (radare2) as in the symbolic stage,
so static paths appear as dashed nodes. Writes OUTDIR/initial-fsm.pdf and OUTDIR/tdcfg.pdf.
"""
import glob
import os
import shutil
import subprocess
import sys

import r2pipe

sys.path.insert(0, '/opt/synoptic')
import synoptic.utils as utils  # noqa: E402
from synoptic.tracemodeler.model import Model  # noqa: E402

binary, trace_dir, function, outdir = sys.argv[1:5]
os.makedirs(outdir, exist_ok=True)

traces = utils.get_traces(sorted(glob.glob(os.path.join(trace_dir, '*.log'))))
model = Model()
model.analyze(traces)
# The paper figure omits the "FSM" title that Synoptic adds to the graph
fsm_graph = os.path.join(outdir, 'initial-fsm')
model.fsm._generate_fsm_graph(fsm_graph)
with open(fsm_graph + '.gv') as f:
    source = f.read().replace('label=FSM ', '')
subprocess.run(['dot', '-Tpdf', '-o', fsm_graph + '.pdf'], input=source, text=True, check=True)
for leftover in (fsm_graph + '.gv', fsm_graph + '.gv.pdf'):
    os.remove(leftover)

base = model.get_base_addr(traces)
print(f'functions={len(model.cfg.cfgs)} base={base:#x}')
r2 = r2pipe.open(binary, flags=['-B', hex(base), '-2'])
for tainted_cfg in model.cfg.get_tainted_cfgs():
    leader = tainted_cfg.entry_node.group.leader
    if leader.routine != function:
        continue
    model.update_cfg_with_static_info(r2, tainted_cfg, function, leader.routine_addr)
    target = os.path.join(outdir, 'tdcfg')
    tainted_cfg.export_graph(target, first=True)
    shutil.move(f'{target}.gv.pdf', f'{target}.pdf')
    os.remove(f'{target}.gv')
    print(f'{function} at {leader.routine_addr:#x}: {len(tainted_cfg.nodes)} nodes')
r2.quit()
