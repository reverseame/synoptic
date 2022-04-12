import sys
import capstone

import traceanalyzer.args
import traceanalyzer.analyzer as analyzer

def main():
    args = traceanalyzer.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        print("trace analyzer: v0.0.1")
        sys.exit(0)

    arch_mode = capstone.CS_MODE_32 if args.t32 else capstone.CS_MODE_64
    
    analyzer.Analyzer(args.trace, arch_mode=arch_mode).analyze()
