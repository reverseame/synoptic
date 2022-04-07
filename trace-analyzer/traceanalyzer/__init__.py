import sys

import traceanalyzer.args
import traceanalyzer.anal as anal

def main():
    args = traceanalyzer.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        print("trace analyzer: v0.0.1")
        sys.exit(0)
    
    anal.Anal(args.trace).analyze()
