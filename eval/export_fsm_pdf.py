"""Export an fsm.json/fsm-inferred.json as Synoptic's PDF graph. Usage: export_fsm_pdf.py FSM_JSON OUT_PDF"""
import sys

sys.path.insert(0, '/opt/synoptic')
import capstone  # noqa: E402

import synoptic.tracemodeler.model as synoptic_model  # noqa: E402

model = synoptic_model.Model(arch_mode=capstone.CS_MODE_64)
model.fsm.import_from_file(sys.argv[1])
model.fsm.export_graph(sys.argv[2])
