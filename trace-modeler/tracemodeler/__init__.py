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

    """ Import a FSM """
    if args.fsm_import:
        filepath = os.path.abspath(args.fsm_import)
        model.fsm.import_from_file(filepath)
        debug.info(f'{filepath}\t: {len(model.fsm)} model messages imported')

    """ Analyze traces to create/refine a FSM """
    filenames = []
    if args.log: filenames.extend(args.log)
    if args.dirlog: filenames.extend(utils.get_logs(args.dirlog))

    """ We have nothing to work on """
    if not args.fsm_import and not filenames:
        debug.error('Unable to find logs')
        sys.exit(-1)

    if filenames:
        """ Proceed with CFG and FSM analysis """
        try:
            traces = utils.get_traces(filenames)
            model.analyze(traces)
        except KeyboardInterrupt:
            pass

        if args.symbolic_analysis:
            model.symbolic_analysis(traces, args.binary, args.symbolic_engine)

        if args.cfg_pdf:
            filepath = os.path.abspath(args.cfg_pdf)
            model.cfg.export_graph(filepath)
            debug.info(f'{filepath}\t: CFG graph')

    if model.fsm.is_empty():
        debug.warning('Empty model')

    if args.fsm_export:
        filepath = os.path.abspath(args.fsm_export)
        model.fsm.export_to_file(filepath)
        debug.info(f'{filepath}\t: FSM exported')
    else:
        debug.info(f'FSM infered\t:\n{str(model.fsm)}')

    if args.fsm_pdf:
        filepath = os.path.abspath(args.fsm_pdf)
        model.fsm.export_graph(filepath)
        debug.info(f'{filepath}\t: FSM graph')

    """ Replay model to a target server """
    if args.replay:
        replayer.Replayer(args.server_ip, args.server_port, transport_layer=args.transport_layer).replay(model.fsm, delay=(args.delay / 1000))
