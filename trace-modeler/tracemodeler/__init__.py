import sys
import capstone

import tracemodeler.args
import tracemodeler.debug as debug
import tracemodeler.utils as utils
import tracemodeler.analyzer as analyzer

def main():
    args = tracemodeler.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        debug.info(f'Version\t: {utils.VERSION}')
        sys.exit(0)

    filenames = []

    if args.log:
        filenames.extend(args.log)
        
    if args.dirlog:
        filenames.extend(utils.get_logs(args.dirlog))

    if not filenames:
        debug.error('Unable to find logs')
        sys.exit(-1)

    traces = utils.get_traces(filenames)
    arch_mode = capstone.CS_MODE_32 if args.m32 else capstone.CS_MODE_64

    if not args.binary:
        debug.warning('Binary file not provided, unable to update CFG with static information')

    dynamic_cfg = analyzer.Analyzer(binary=args.binary, arch_mode=arch_mode).analyze(traces)

    if dynamic_cfg.is_empty():
        debug.warning('Empty CFG')
    elif args.export:
        dynamic_cfg.export_graph(args.export)
        debug.info(f'{args.export}\t: CFG saved')
