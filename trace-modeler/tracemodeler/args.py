import os
import sys
import r2pipe
import shutil
import argparse
import platform
import ipaddress

import tracemodeler.debug as debug
import tracemodeler.utils as utils

description = 'This tool analyzes server execution traces to infer its protocol Finite-State Machine (FSM), and\
 uses symbolic analysis to try to find new messages not contained in the traces'

usage_examples = '''usage examples:
    Displays a protocol FSM based on a trace:
        $ python trace-modeler/modeler.py --log /path/to/trace.log

    Exports a protocol FSM for later use:
        $ python trace-modeler/modeler.py --log /path/to/trace.log --fsm-export /path/to/fsm.json

    Exports the constructed Control-Flow Graph (CFG) and FSM to a PDF file:
        $ python trace-modeler/modeler.py --log /path/to/trace.log --cfg-pdf /path/to/cfg.pdf --fsm-pdf /path/to/fsm.pdf

    Infers new keywords thanks to symbolic analysis and stores them in the FSM:
        $ python trace-modeler/modeler.py --log /path/to/trace.log --fsm-export /path/to/fsm.json --symbolic-analysis --binary /path/to/binary

    Replays messages to a server based on a previous FSM:
        $ python3 trace-modeler/modeler.py --fsm-import /path/to/fsm.json --replay --server-ip <ip> --server-port <port>

    Replay FSM messages and send new messages obtained thanks to symbolic analysis:
        $ python3 trace-modeler/modeler.py --fsm-import /path/to/fsm.json --replay --server-ip <ip> --server-port <port> --new-messages
    '''

class ArgumentParser:
    def __init__(self):
        self.argparser = argparse.ArgumentParser(description=description, epilog=usage_examples, formatter_class=argparse.RawDescriptionHelpFormatter)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        """ General options """
        self.argparser.add_argument('--force-overwrite', action='store_true', help='force overwrite of existing files')
        """ Protocol FSM and binary CFG analysis """
        self.argparser.add_argument('--log', type=str, nargs='+', metavar='<file>', help='a list of .log files')
        self.argparser.add_argument('--dirlog', type=str, metavar='<folder>', help='folder containing .log files')
        self.argparser.add_argument('--m32', action='store_true', help='trace of a 32-bit program (64-bit by default)')
        self.argparser.add_argument('--fsm-export', type=str, metavar='<file>', help='JSON file to export model')
        self.argparser.add_argument('--fsm-import', type=str, metavar='<file>', help='JSON file defining a model')
        self.argparser.add_argument('--fsm-pdf', type=str, metavar='<file>', help='PDF file representing the model')
        self.argparser.add_argument('--cfg-pdf', type=str, metavar='<file>', help='PDF file representing the traces CFG')
        """ Symbolic analysis """
        self.argparser.add_argument('--symbolic-analysis', action='store_true', help='activate symbolic analysis')
        self.argparser.add_argument('--binary', type=str, metavar='<file>', help='binary file to complement the CFG reconstructed from .log files')
        self.argparser.add_argument('--symbolic-engine', type=str, metavar='<angr|binsec>', default='angr', help='symbolic engine to use for new message inference (default to angr)')
        """ Replay options """
        self.argparser.add_argument('--replay', action='store_true', help='replay messages based in a model')
        self.argparser.add_argument('--server-ip', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--server-port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--transport-layer', type=str, metavar='<tcp|udp>', default='tcp', help='Transport layer (default to TCP)')
        self.argparser.add_argument('--delay', type=int, metavar='<ms>', default=200, help='delay between sending messages (in ms) (default to 200 ms)')
        self.argparser.add_argument('--new-messages', action='store_true', help='constructs and send new messages based in symbolic analysis results')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        return args

    def _check_binsec(self):
        """ Search for binsec in the $PATH/%PATH% """
        filepath = shutil.which("binsec")
        
        if filepath is None:
            where = 'system files'

            system = platform.system()
            if system == 'Linux':
                where = '$PATH variable'
            elif system == 'Windows':
                where = '%PATH% variable'

            debug.error(f'Binsec not found in {where}')

    def _check_r2(self):
        """ Open radare2 without binary and close stderr """
        r2 = r2pipe.open('-', flags=['-2'])
        """ Check radare2 version """
        version_str = r2.cmd('?Vq').rstrip()
        """ Close radare2 """
        r2.quit()

        """ Transform '5.8.4' into 584 """
        min_r2_supported = int(utils.MIN_R2_VERSION.replace('.', ''))
        version = int(version_str.replace('.', ''))

        if version < min_r2_supported:
            debug.error(f'radare2 version found ({version_str}) older than minimum supported ({utils.MIN_R2_VERSION})')

    def _check_existing_files(self, args):
        filenames = [filename for filename in [args.fsm_export, args.fsm_pdf, args.cfg_pdf] if (filename is not None) and os.path.isfile(filename)]

        if filenames:
            n_files = 'Files' if len(filenames) > 1 else 'File'
            debug.warning(f'{", ".join([os.path.realpath(filename) for filename in filenames])}\t: {n_files} will be overwritten')
            response = input('Do you want to continue? [Y/n] ')
            if response.lower() not in ['', 'y', 'yes']:
                print('Abort.')
                sys.exit(-1)

    def _check_args(self, args):
        """ Check for main arguments """
        if not any([args.log, args.dirlog, args.fsm_import]):
            debug.error('You need to provide either log files (--log or --dirlog) or a FSM (--fsm-import)')

        """ FSM analysis """
        if args.log:
            for filename in args.log:
                if not os.path.isfile(filename):
                    debug.error(f'{os.path.realpath(filename)}\t: Not a file')

        if args.dirlog and not os.path.isdir(args.dirlog):
            debug.error(f'{os.path.realpath(args.dirlog)}\t: Not a directory')

        if args.fsm_import and not os.path.isfile(args.fsm_import):
            debug.error(f'{os.path.realpath(args.fsm_import)}\t: Not a file')

        """ Symbolic analysis """
        if args.symbolic_analysis:
            if not args.log and not args.dirlog:
                debug.error(f'Log files are required to analyze CFG (--log or --dirlog)')

            if args.binary:
                if not os.path.isfile(args.binary):
                    debug.error(f'{os.path.realpath(args.binary)}\t: Not a file')

                self._check_r2()

                """ Check symbolic engine """
                if args.symbolic_engine == 'angr':
                    pass    # Assume angr is installed as Python library
                elif args.symbolic_engine == 'binsec':
                    self._check_binsec()
                else:
                    debug.error(f'{args.symbolic_engine}\t: Unknown symbolic engine (--symbolic-engine <angr|binsec>)')
            else:
                debug.error('Binary file not provided for symbolic analysis (--binary)')

        """ Replay options """
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

        if not args.force_overwrite:
            self._check_existing_files(args)
