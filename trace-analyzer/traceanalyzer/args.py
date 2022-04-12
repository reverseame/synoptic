import os
import argparse

import traceanalyzer.debug as debug

class ArgumentParser:
    def __init__(self):
        description = 'This tool analyze a server execution trace to model a server protocol'
        self.argparser = argparse.ArgumentParser(description=description)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        self.argparser.add_argument('trace', type=str, metavar='<log>', help='specify the server execution trace')
        self.argparser.add_argument('-t32', action='store_true', help='trace of a 32-bit program')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        return args

    def _check_args(self, args):
        if not os.path.isfile(args.trace):
            debug.error(f'{os.path.abspath(args.trace)}: Unable to locate file')
