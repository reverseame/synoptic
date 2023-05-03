import os
import argparse
import ipaddress

import tracemodeler.debug as debug

description = 'This tool analyze server execution traces to infer its protocol model'

usage_examples = '''usage examples:
    Export CFG:
        $ python trace-modeler/modeler.py --log /path/to/trace.log --export /path/to/cfg.pdf
    '''

class ArgumentParser:
    def __init__(self):
        self.argparser = argparse.ArgumentParser(description=description, epilog=usage_examples, formatter_class=argparse.RawDescriptionHelpFormatter)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        """ CFG related """
        self.argparser.add_argument('--log', type=str, nargs='+', metavar='<file>', help='a list of .log files')
        self.argparser.add_argument('--dirlog', type=str, metavar='<folder>', help='folder containing .log files')
        self.argparser.add_argument('--export', type=str, metavar='<file>', help='PDF file to save generated CFG')
        self.argparser.add_argument('--m32', action='store_true', help='trace of a 32-bit program (64-bit by default)')
        """ Network interaction with server """
        self.argparser.add_argument('--replay', action='store_true', help='replay messages based in a model')
        self.argparser.add_argument('--host', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--udp', action='store_true', help='UDP transport protocol (TCP by default)')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        return args

    def _check_args(self, args):
        if args.log:
            for filename in args.log:
                if not os.path.isfile(filename):
                    debug.error(f'{os.path.abspath(filename)}: Not a file')
        elif args.dirlog:
            if not os.path.isdir(args.dirlog):
                debug.error(f'{os.path.abspath(args.dirlog)}: Not a directory')
        else:
            debug.error('You need to provide log files (--log or --dirlog)')

        if not args.export:
            debug.error('You need to provide a file to CFG PDF (--export)')

        if args.replay:
            if args.host:
                try:
                    ipaddress.ip_address(args.host)
                except ValueError as error:
                    debug.error(f'{str(error)}')
            else:
                debug.error('You need to provide a target address (--host)')

            if args.port:
                if (args.port < 0) or (args.port > 65535):
                    debug.error(f'{args.port}: Port number must be from 0 to 65535')
            elif args.port != 0:
                debug.error('You need to provide a target port (--port)')

            if (args.delay < 0):
                debug.error(f'{args.delay}: Delay must be positive (--help)')
