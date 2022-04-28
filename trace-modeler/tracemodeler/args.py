import os
import argparse
import ipaddress

import tracemodeler.debug as debug

class ArgumentParser:
    def __init__(self):
        description = 'This tool analyze a server execution trace to model a server protocol and generate new messages based in this model'
        self.argparser = argparse.ArgumentParser(description=description)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        self.argparser.add_argument('--trace', type=str, metavar='<log>', help='specify the server execution trace')
        self.argparser.add_argument('--m32', action='store_true', help='trace of a 32-bit program (64-bit by default)')
        self.argparser.add_argument('--output', type=str, metavar='<file>', help='output protocol model file')
        self.argparser.add_argument('--replay', action='store_true', help='replay messages based in a model')
        self.argparser.add_argument('--model', type=str, metavar='<file>', help='specify the protocol model')
        self.argparser.add_argument('--host', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--udp', action='store_true', help='UDP transport protocol (TCP by default)')
        self.argparser.add_argument('--delay', type=float, default=0.5 ,help='delay between send calls (default to 0.5 s)')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        return args

    def _check_args(self, args):
        if args.trace:
            if not os.path.isfile(args.trace):
                debug.error(f'{os.path.abspath(args.trace)}: Unable to locate file')

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

        if args.model:
            if not os.path.isfile(args.model):
                debug.error(f'{os.path.abspath(args.model)}: Unable to locate file')

        if args.replay:
            if (args.trace and args.model) or (not args.trace and not args.model):
                debug.error('You need to provide either a trace (--trace) or a model (--model)')

        if args.output:
            if not args.trace:
                debug.error('You need to provide a trace to create an model output file (--trace or --help)')

        if args.trace:
            if not args.output and not args.replay:
                debug.error('You need to provide either a output file (--output) or replay messages (--replay)')

        if not args.trace and not args.replay and not args.version:
            debug.error('You need to either analyze a trace to create a model (--trace) or replay messages (--replay)')