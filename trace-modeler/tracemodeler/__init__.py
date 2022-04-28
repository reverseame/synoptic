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

    if args.model:
        model = tracemodeler.model.Model()
        with open(args.model, 'r') as f:
            content = f.read()
        model.load(content)
        debug.info(f'{os.path.abspath(args.model)}: {len(model)} model messages imported')
    else:
        model = analyzer.Analyzer(args.trace, arch_mode=arch_mode).analyze()
        debug.info(f'{len(model)} messages infered in the model')

    if args.output:
        with open(args.output, 'w') as f:
            f.write(model.dump())
        debug.info(f'{args.output}: Model exported')
    elif args.replay:
        replayer.Replayer(args.host, args.port, tcp=not args.udp).replay(model, delay=args.delay)
