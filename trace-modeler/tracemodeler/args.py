import os
import sys
import r2pipe
import shutil
import argparse
import platform
import ipaddress

import tracemodeler.debug as debug
import tracemodeler.utils as utils

description = 'This tool analyzes server execution traces to infer its protocol model, and\
 uses symbolic analysis to try to find new messages not contained in the traces'

usage_examples = '''usage examples:
    Displays a protocol model based on a trace:
        $ python trace-modeler/modeler.py --log /path/to/trace.log

    Exports a protocol model:
        $ python trace-modeler/modeler.py --log /path/to/trace.log --model-export /path/to/model.json

    Enables CFG analysis and exports the constructed CFG to a PDF file:
        $ python trace-modeler/modeler.py --log /path/to/trace.log --cfg-analysis --binary /path/to/binary --cfg-export /path/to/cfg.pdf

    Replays messages to a server based on a protocol model:
        $ python3 trace-modeler/modeler.py --model-import /path/to/model.json --replay --server-ip <ip> --server-port <port>
    '''

class ArgumentParser:
    def __init__(self):
        self.argparser = argparse.ArgumentParser(description=description, epilog=usage_examples, formatter_class=argparse.RawDescriptionHelpFormatter)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        """ Model analysis """
        self.argparser.add_argument('--log', type=str, nargs='+', metavar='<file>', help='a list of .log files')
        self.argparser.add_argument('--dirlog', type=str, metavar='<folder>', help='folder containing .log files')
        self.argparser.add_argument('--m32', action='store_true', help='trace of a 32-bit program (64-bit by default)')
        self.argparser.add_argument('--model-export', type=str, metavar='<file>', help='JSON file to export model')
        self.argparser.add_argument('--model-import', type=str, metavar='<file>', help='JSON file defining a model')
        """ CFG analysis """
        self.argparser.add_argument('--cfg-analysis', action='store_true', help='activate CFG analysis')
        self.argparser.add_argument('--cfg-export', type=str, metavar='<file>', help='PDF file to save generated CFG')
        self.argparser.add_argument('--cfg-export-force', action='store_true', help='force overwrite existing PDF file')
        self.argparser.add_argument('--binary', type=str, metavar='<file>', help='binary file to complement the CFG reconstructed from .log files')
        self.argparser.add_argument('--symbolic-engine', type=str, metavar='<angr|binsec>', default='angr', help='symbolic engine to use for new message inference (default to angr)')
        """ Replay properties """
        self.argparser.add_argument('--replay', action='store_true', help='replay messages based in a model')
        self.argparser.add_argument('--server-ip', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--server-port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--transport-layer', type=str, metavar='<tcp|udp>', default='tcp', help='Transport layer (default to TCP)')
        self.argparser.add_argument('--delay', type=int, metavar='<ms>', default=0, help='delay between sending messages (in ms)')

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
        """ Model analysis """
        if args.log:
            for filename in args.log:
                if not os.path.isfile(filename):
                    debug.error(f'{os.path.realpath(filename)}\t: Not a file')
        elif args.dirlog:
            if not os.path.isdir(args.dirlog):
                debug.error(f'{os.path.realpath(args.dirlog)}\t: Not a directory')
        elif args.model_import:
            if not os.path.isfile(args.model_import):
                debug.error(f'{os.path.realpath(args.model_import)}\t: Not a file')
        else:
            debug.error('You need to provide either log files (--log or --dirlog) or a model (--model-import)')

        """ CFG analysis """
        if args.cfg_analysis:
            if args.binary:
                if not os.path.isfile(args.binary):
                    debug.error(f'{os.path.realpath(args.binary)}\t: Not a file')

                self._check_r2()

                """ Check symnbolic engine """
                if args.symbolic_engine == 'angr':
                    pass    # Assume angr is installed as Python library
                elif args.symbolic_engine == 'binsec':
                    self._check_binsec()
                else:
                    debug.error(f'{args.symbolic_engine}\t: Unknown symbolic engine (--symbolic-engine <angr|binsec>)')

                """ Check if --cfg-export already exists """
                if args.cfg_export:
                    if os.path.isfile(args.cfg_export) and not args.cfg_export_force:
                        debug.warning(f'{os.path.realpath(args.cfg_export)}\t: File will be overwritten')
                        response = input('Do you want to continue? [Y/n] ')
                        if response.lower() not in ['', 'y', 'yes']:
                            print('Abort.')
                            sys.exit(-1)
            else:
                debug.error('Binary file not provided for CFG analysis (--binary)')

        """ Replay properties """
        if args.replay:
            if args.server_ip:
                """ Check if IP address is well formatted """
                try:
                    ipaddress.ip_address(args.server_ip)
                except ValueError as error:
                    debug.error(f'{str(error)}')
            else:
                debug.error('You need to provide a server IP address (--server-ip)')

            if args.server_port:
                if (args.server_port < 0) or (args.server_port > 65535):
                    debug.error(f'{args.server_port}\t: Port number must be from 0 to 65535')
            elif args.server_port != 0:
                debug.error('You need to provide a server port (--server-port)')

            if args.transport_layer not in ['tcp', 'udp']:
                debug.error(f'{args.transport_layer}\t: Unknown transport layer (--transport-layer <tcp|udp>)')

            if (args.delay < 0):
                debug.error(f'{args.delay}\t: Delay must be positive')
