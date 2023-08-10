import os
import sys
import r2pipe
import shutil
import logging
import argparse
import platform
import ipaddress

import synoptic.debug as debug
import synoptic.utils as utils

description = '''
   __            __   __  ___    __ 
  (__' \_/ |\ | /  \ |__)  |  | /  `
  .__)  |  | \| \__/ |     |  | \__,

(SYmbolic NetwOrk ProTocol InferenCe)

This script orchestrates the generation and analysis of server execution traces to infer
the Finite-State Machine (FSM) protocol, and uses symbolic analysis to attempt to find
new messages not contained in the traces. It relies on the construction of a Dynamic
Control-Flow Graph (CFG) from traces to analyze the execution flow of a program
'''

usage_examples = '''
usage examples:
    Display a protocol FSM based on a trace:
        $ python synoptic.py --log /path/to/trace.log

    Export a protocol FSM for future use:
        $ python synoptic.py --log /path/to/trace.log --fsm-export /path/to/fsm.json

    Create dynamic CFG and FSM PDF files:
        $ python synoptic.py --log /path/to/trace.log --cfg-pdf /path/to/cfg.pdf --fsm-pdf /path/to/fsm.pdf

    Infer new keywords through symbolic analysis and export them to the FSM:
        $ python synoptic.py --log /path/to/trace.log --fsm-export /path/to/fsm.json --symbolic-analysis --binary /path/to/binary

    Replay messages to a server based on a previously exported FSM:
        $ python synoptic.py --fsm-import /path/to/fsm.json --replay --server-ip <ip> --server-port <port>

    Replay FSM messages and send new messages obtained through symbolic analysis:
        $ python synoptic.py --fsm-import /path/to/fsm.json --replay --server-ip <ip> --server-port <port> --new-messages
    '''

class ArgumentParser:
    def __init__(self):
        self.argparser = argparse.ArgumentParser(description=description, epilog=usage_examples, formatter_class=argparse.RawDescriptionHelpFormatter)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        """ General options """
        self.argparser.add_argument('--force-overwrite', action='store_true', help='force overwriting of existing files')
        self.argparser.add_argument('--debug', action='store_true', help='display debug messages')
        """ FSM and dynamic CFG analysis """
        self.argparser.add_argument('--log', type=str, nargs='+', metavar='<file>', help='a list of .log files')
        self.argparser.add_argument('--dirlog', type=str, metavar='<folder>', help='a folder with .log files')
        self.argparser.add_argument('--m32', action='store_true', help='traces are in 32-bit mode (64-bit by default)')
        self.argparser.add_argument('--fsm-export', type=str, metavar='<file>', help='export FSM to JSON file')
        self.argparser.add_argument('--fsm-import', type=str, metavar='<file>', help='import FSM from JSON file')
        self.argparser.add_argument('--fsm-pdf', type=str, metavar='<file>', help='create a PDF with the FSM')
        self.argparser.add_argument('--cfg-pdf', type=str, metavar='<file>', help='create a PDF with the dynamic CFG')
        """ Symbolic analysis """
        self.argparser.add_argument('--symbolic-analysis', action='store_true', help='activate symbolic analysis')
        self.argparser.add_argument('--binary', type=str, metavar='<file>', help='binary file to add static information to the dynamic CFG')
        self.argparser.add_argument('--symbolic-engine', type=str, metavar='<angr|binsec>', default='angr', help='symbolic engine to use for new message inference (default to angr)')
        self.argparser.add_argument('--timeout', type=int, metavar='<s>', default=5, help='symbolic exploration timeout, it is reset after each result found (default to 5 s)')
        """ Replay options """
        self.argparser.add_argument('--replay', action='store_true', help='send messages to a server based on the FSM')
        self.argparser.add_argument('--server-ip', type=str, metavar='<ip>', help='server IP')
        self.argparser.add_argument('--server-port', type=int, metavar='<port>', help='server listening port')
        self.argparser.add_argument('--transport-layer', type=str, metavar='<tcp|udp>', default='tcp', help='transport layer (default to TCP)')
        self.argparser.add_argument('--delay', type=int, metavar='<ms>', default=200, help='delay between messages to be sent (in ms) (default to 200 ms)')
        self.argparser.add_argument('--new-messages', action='store_true', help='generate and send new messages based on symbolic analysis information')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        """ Do not need to check anything to only displaying version """
        if not args.version:
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
        """ Obtain radare2 version """
        version_str = r2.cmd('?Vq').rstrip()
        """ Close radare2 """
        r2.quit()

        """ Transform '5.8.4' str into 584 int """
        r2_supported = int(utils.R2_VERSION.replace('.', ''))
        version = int(version_str.replace('.', ''))

        if version != r2_supported:
            debug.error(f'radare2 {version_str} is not supported. Please, install version {utils.R2_VERSION} (sorry for the inconvenience, but radare2 output is too unstable between versions)')

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

                try:
                    self._check_r2()
                except Exception as e:
                    debug.error(str(e))

                """ Check symbolic engine """
                if args.symbolic_engine == 'angr':
                    pass    # Assume angr is installed as Python library
                elif args.symbolic_engine == 'binsec':
                    self._check_binsec()
                else:
                    debug.error(f'{args.symbolic_engine}\t: Unknown symbolic engine (--symbolic-engine <angr|binsec>)')
            else:
                debug.error('Binary file not provided for symbolic analysis (--binary)')

            if args.timeout < 0:
                debug.error(f'{args.timeout}\t: Timeout must be positive')

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

            if args.delay < 0:
                debug.error(f'{args.delay}\t: Delay must be positive')

        if not args.force_overwrite:
            self._check_existing_files(args)

        """ Set logger to DEBUG level """
        if args.debug:
            logging.getLogger(utils.TOOL_NAME).setLevel(logging.DEBUG)
