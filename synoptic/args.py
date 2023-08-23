import os
import sys
import r2pipe
import shutil
import logging
import argparse
import platform
import ipaddress
import configparser

import synoptic.debug as debug
import synoptic.utils as utils

description = f'''{utils.TOOL_HEADER}

This script orchestrates the generation and analysis of server execution traces to infer
the Finite-State Machine (FSM) protocol, and uses symbolic analysis to attempt to find
new messages not contained in the traces. It relies on the construction of a Dynamic
Control-Flow Graph (CFG) from traces to analyze the execution flow of a program
'''

class ArgumentParser:
    def __init__(self):
        self.argparser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display version and exit')
        self.argparser.add_argument('--conf', type=str, metavar='<file>', help='INI configuration file')

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

    def _create_working_dir(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)

        os.makedirs(path)

    def _get_user_confirmation(self, path):
        debug.warning(f'"{os.path.abspath(path)}" will be overwritten')
        response = input('Do you want to continue? [Y/n] ')
        if response.lower() not in ['', 'y', 'yes']:
            print('Abort.')
            sys.exit(-1)

    def _check_file(self, filepath):
        if not os.path.isfile(filepath):
            debug.error(f'{os.path.realpath(filepath)}\t: Not a file')

    def _get_field(self, conf_dict, key, type_):
        if key in conf_dict:
            value = conf_dict[key]
            if value:
                if type_ == bool:
                    try:
                        return conf_dict.getboolean(key)
                    except ValueError:
                        raise ValueError(f'{key}\t: {value}\t: Not a boolean')
                elif type_ == int:
                    try:
                        return conf_dict.getint(key)
                    except ValueError:
                        raise ValueError(f'{key}\t: {value}\t: Not a integer with base 10')

        raise ValueError(f'{key}\t: Empty key')

    def _parse_conf(self, args):
        """ Modify args namespace according to configuration file """
        self._check_file(args.conf)

        config = configparser.ConfigParser()
        config.read(args.conf)

        try:
            """ Synoptic general config """
            args.working_dir = config['synoptic']['workingdir']
            args.force_overwrite = self._get_field(config['synoptic'], 'forceoverwrite', bool)
            args.debug = self._get_field(config['synoptic'], 'debug', bool)
            args.export_pdf = self._get_field(config['synoptic'], 'exportpdf', bool)
            args.n_iterations = self._get_field(config['synoptic'], 'iterations', int)
            """ Binary config """
            args.binary = config['binary']['path']
            args.binary_args = config['binary']['args']
            args.binary_cwd = config['binary']['cwd'] if 'cwd' in config['binary'] else None    # Cwd could be optional
            args.binary_bitmode = config['binary']['bitmode']
            args.binary_privileges = self._get_field(config['binary'], 'privileges', bool)
            args.binary_modules = config['binary']['modules'] if 'modules' in config['binary'] else []
            """ servertracer config """
            args.pin = config['servertracer']['pin']
            args.pintool = config['servertracer']['pintoolpath']
            """ Symbolic analysis config """
            args.symbolic_analysis = self._get_field(config['symbolic-analysis'], 'enable', bool)
            args.symbolic_engine = config['symbolic-analysis']['engine']
            args.symbolic_timeout = self._get_field(config['symbolic-analysis'], 'timeout', int)
            """ Replay config """
            args.replay = self._get_field(config['replay'], 'enable', bool)
            args.replay_ip = config['replay']['server']
            args.replay_port = self._get_field(config['replay'], 'port', int)
            args.replay_transport_layer = config['replay']['transportlayer'].lower()
            args.replay_delay = self._get_field(config['replay'], 'delay', int)
            args.replay_symbolic_messages = self._get_field(config['replay'], 'symbolicmessages', bool)
        except KeyError as e:
            debug.error(f'{os.path.abspath(args.conf)}\t: {str(e)} key not found')
        except ValueError as e:
            debug.error(f'{os.path.abspath(args.conf)}\t: {str(e)}')

    def _check_args(self, args):
        print(utils.TOOL_HEADER)

        if args.conf:
            self._parse_conf(args)
        else:
            debug.error('You need to provide a configuration file (--conf)')

        """ Create working directory """
        if os.path.isdir(args.working_dir):
            if args.force_overwrite:
                debug.info(f'{args.working_dir}\t: Overriding folder content')
            else:
                self._get_user_confirmation(args.working_dir)
            self._create_working_dir(args.working_dir)
        elif os.path.exists(args.working_dir):
            debug.error(f'{os.path.abspath(args.working_dir)}: Not a directory')
        else:
            self._create_working_dir(args.working_dir)

        """ Set logger to DEBUG level """
        if args.debug:
            logging.getLogger(utils.TOOL_NAME).setLevel(logging.DEBUG)

        """ No. iterations """
        if args.n_iterations < 1:
            debug.error(f'{args.n_iterations}\t: Analysis must to be set to at least 1 iteration')

        """ Verify that all files exist """
        for filename in [args.binary, args.pin, args.pintool]:
            self._check_file(filename)

        if (args.binary_cwd is not None) and not os.path.isdir(args.binary_cwd):
            debug.error(f'{args.binary_cwd}\t: Not a directory')

        if args.binary_bitmode not in ['64-bit', '32-bit']:
            debug.error(f'{args.binary_bitmode}\t: Binary mode not recognized, should be either 64-bit or 32-bit')

        """ Symbolic analysis """
        if args.symbolic_analysis:
            try:
                self._check_r2()
            except Exception as e:
                debug.error(str(e))

            """ Check symbolic engine """
            if args.symbolic_engine == 'angr':
                pass                                # Assume angr is installed as Python library
            elif args.symbolic_engine == 'binsec':
                self._check_binsec()
            else:
                debug.error(f'{args.symbolic_engine}\t: Unknown symbolic engine, should be either angr or binsec')

            if args.symbolic_timeout < 0:
                debug.error(f'{args.symbolic_timeout}\t: Symbolic timeout must be positive')

        """ Replay options """
        if args.replay:
            """ Check if IP address is well formatted """
            try:
                ipaddress.ip_address(args.replay_ip)
            except ValueError as error:
                debug.error(f'{str(error)}')

            if (args.replay_port < 0) or (args.replay_port > 65535):
                debug.error(f'{args.replay_port}\t: Port number must be from 0 to 65535')

            if args.replay_transport_layer not in ['tcp', 'udp']:
                debug.error(f'{args.replay_transport_layer}\t: Unknown transport layer')

            if args.replay_delay < 0:
                debug.error(f'{args.replay_delay}\t: Delay must be positive')
