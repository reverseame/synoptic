import os
import sys
import capstone

import tracemodeler.args
import tracemodeler.model
import tracemodeler.debug as debug
import tracemodeler.analyzer as analyzer
import tracemodeler.replayer as replayer

def main():
    args = tracemodeler.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        debug.info('v0.0.1')
        sys.exit(0)

    arch_mode = capstone.CS_MODE_32 if args.m32 else capstone.CS_MODE_64

    """ Either load a model file or generate a new one based in a trace file """
    if args.fsm:
        protocol_fsm = tracemodeler.model.ProtocolFSM()
        with open(args.fsm, 'r') as f:
            content = f.read()
        protocol_fsm.loads(content)
        debug.info(f'{os.path.abspath(args.fsm)}: {len(protocol_fsm)} model messages imported')
    else:
        protocol_fsm = analyzer.Analyzer(args.trace, arch_mode=arch_mode).analyze()
        if len(protocol_fsm) > 0:
            debug.info(f'{len(protocol_fsm)} messages infered in the model')

    """ Replay model to a target server """
    if args.replay:
        replayer.Replayer(args.host, args.port, tcp=not args.udp).replay(protocol_fsm, delay=args.delay)
    else:
        str_protocol_fsm = protocol_fsm.dumps()
        if args.output:
            """ Export model """
            try:
                with open(args.output, 'w') as f:
                    f.write(str_protocol_fsm)
                debug.info(f'{args.output}: Model exported')
            except FileNotFoundError:
                debug.error(f'{args.output}: Unable to export model to file')
        else:
            print(str_protocol_fsm)

    if args.export:
        protocol_fsm.export_graph(args.export)
        debug.info(f'{args.export}.gv: Graphviz file exported')
        debug.info(f'{args.export}.gv.pdf: PDF exported')
