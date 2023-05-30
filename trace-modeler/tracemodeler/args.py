import os
import r2pipe
import shutil
import argparse
import platform
import ipaddress

import tracemodeler.debug as debug
import tracemodeler.utils as utils

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
        self.argparser.add_argument('--binary', type=str, metavar='<file>', help='binary file to complement the CFG')
        """ Network interaction with server """
        self.argparser.add_argument('--replay', action='store_true', help='replay messages based in a model')
        self.argparser.add_argument('--host', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--udp', action='store_true', help='UDP transport protocol (TCP by default)')
        """ Symbolic engine """
        self.argparser.add_argument('--symbolic', type=str, metavar='<angr|binsec>', default='angr', help='symbolic engine to use for new message inference (default to angr)')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        return args

    def _check_binsec(self):
        """ Search for binsec in the $PATH/%PATH% """
        filepath = shutil.which("binsec")
        
        if filepath is None:
            system = platform.system()
            if system == 'Linux':
                debug.error('Binsec not found in $PATH variable')
            elif system == 'Windows':
                debug.error('Binsec not found in %PATH% variable')
            else:
                debug.error('Binsec not found in system files')
            

    def _check_r2(self):
        """ Open radare2 withouth binary and close stderr """
        r2 = r2pipe.open('-', flags=['-2'])
        """ Check radare2 version """
        version_str = r2.cmd('?Vq').rstrip()
        """ Close radare2 """
        r2.quit()

        """ Transform '5.8.4' into 584 """
        min_r2_supported = int(utils.MIN_R2_VERSION.replace('.', ''))
        version = int(version_str.replace('.', ''))

        if version < min_r2_supported:
            debug.error(f'radare2 version found ({version_str}) older than minimun supported ({utils.MIN_R2_VERSION})')

    def _check_args(self, args):
        if args.log:
            for filename in args.log:
                if not os.path.isfile(filename):
                    debug.error(f'{os.path.abspath(filename)}\t: Not a file')
        elif args.dirlog:
            if not os.path.isdir(args.dirlog):
                debug.error(f'{os.path.abspath(args.dirlog)}\t: Not a directory')
        else:
            debug.error('You need to provide log files (--log or --dirlog)')

        if not args.export:
            debug.error('You need to provide a file to CFG PDF (--export)')

        if args.binary:
            if not os.path.isfile(args.binary):
                debug.error(f'{os.path.abspath(args.binary)}\t: Not a file')

            self._check_r2()

            if args.symbolic == 'angr':
                pass    # Assume angr is installed as Python library
            elif args.symbolic == 'binsec':
                self._check_binsec()
            else:
                debug.error(f'{args.symbolic}\t: Unknown symbolic engine (--symbolic <angr|binsec>)')
        else:
            debug.error('Binary file not provided (--binary)')

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
