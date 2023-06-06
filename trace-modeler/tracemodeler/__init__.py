import os
import sys
import capstone

import tracemodeler.args
import tracemodeler.debug as debug
import tracemodeler.model
import tracemodeler.utils as utils
import tracemodeler.replayer as replayer

def main():
    args = tracemodeler.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        debug.info(f'Version\t: {utils.VERSION}')
        sys.exit(0)

    arch_mode = capstone.CS_MODE_32 if args.m32 else capstone.CS_MODE_64
    model = tracemodeler.model.Model(arch_mode=arch_mode)

    """ Import a model """
    if args.model_import:
        model.import_from_file(args.model_import)
        debug.info(f'{os.path.abspath(args.model_import)}\t: {len(model.fsm)} model messages imported')

    """ Analyze traces to create/refine a model """
    filenames = []
    if args.log: filenames.extend(args.log)
    if args.dirlog: filenames.extend(utils.get_logs(args.dirlog))

    """ We have nothing to work on """
    if not args.model_import and not filenames:
        debug.error('Unable to find logs')
        sys.exit(-1)

    traces = utils.get_traces(filenames)
    model.analyze(traces)

    if model.fsm.is_empty():
        debug.warning('Empty model')

    if args.cfg_analysis:
        cfg = model.cfg_analysis(traces, args.binary, args.symbolic_engine)

        if args.cfg_pdf:
            cfg.export_graph(args.cfg_pdf)
            debug.info(f'{args.cfg_pdf}\t: CFG graph')

    if args.model_export:
        model.export_to_file(args.model_export)
        debug.info(f'{args.model_export}\t: Model exported')
    else:
        print(model.fsm)

    if args.model_pdf:
        model.fsm.export_graph(args.model_pdf)
        debug.info(f'{args.model_pdf}\t: Model graph')

    """ Replay model to a target server """
    if args.replay:
        replayer.Replayer(args.server_ip, args.server_port, transport_layer=args.transport_layer).replay(model.fsm, delay=args.delay)
