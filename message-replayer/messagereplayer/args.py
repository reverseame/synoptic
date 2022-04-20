import os
import argparse
import ipaddress

import messagereplayer.debug as debug

class ArgumentParser:
    def __init__(self):
        description = 'This tools interacts with a server based in protocol model'
        self.argparser = argparse.ArgumentParser(description=description)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        self.argparser.add_argument('--model', type=str, metavar='<file>', help='specify the protocol model')
        self.argparser.add_argument('--host', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--udp', action='store_true', help='UDP transport protocol (TCP by default)')
        self.argparser.add_argument('--delay', type=float, default=0.5 ,help='Delay between send calls')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        return args

    def _check_args(self, args):
        if not args.model:
            debug.error('You need to provide a protocol model (--model or --help)')
        if not args.host:
            debug.error('You need to provide a server IP (--host or --help)')
        if not args.port and args.port != 0:
            debug.error('You need to provide a server port (--port or --help)')

        if not os.path.isfile(args.model):
            debug.error(f'{os.path.abspath(args.model)}: Unable to locate file')
        
        try:
            ipaddress.ip_address(args.host)
        except ValueError as error:
            debug.error(f'{str(error)}')

        if (args.delay < 0):
            debug.error(f'{args.delay}: Delay must be positive')

        if (args.port < 0) or (args.port > 65535):
            debug.error(f'{args.port}: Port number must be from 0 to 65535')
