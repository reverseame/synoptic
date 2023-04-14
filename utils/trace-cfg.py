#!/usr/bin/env python

import os
import cfg
import sys
import shlex
import argparse
import binascii
import capstone

scriptname = os.path.basename(__file__)

def _print_log_msg(level, string):
    print(f'{scriptname}\t: {level}\t: {string}', file=sys.stderr)

def print_info(string):
    _print_log_msg('INFO\t', string)

def print_warning(string):
    _print_log_msg('WARNING', string)

def print_error(string):
    _print_log_msg('ERROR\t', string)

def parse_data(data):
    ret = []

    for (i, line) in enumerate(data, start=1):
        try:
            new_dict = {}
            splitted = shlex.split(line)
            for (key, value) in [item.split('=') for item in splitted]:
                new_dict[key] = value
            ret.append(new_dict)
        except ValueError as e:
            print_error(f'Parsing error: {str(e)}: line {i}: "{line}"')
            sys.exit(-1)

    return ret

def read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read().splitlines()
    except OSError as ex:
        print_error(f'{filename}\t: Unable to read file\t: {str(ex)}')
        sys.exit(-1)

def get_exec_addr(data):
    for item in data:
        if item['action'] == 'relocate':
            image_low = int(item['image-low'], 16)
            image_high = int(item['image-high'], 16)

            return (image_low, image_high)

def split_network_activity(session):
    """
    Split traces based in recv/read calls

    :param session: list of traces in a client session
    :returns: a new list of traces from a recv/read call until the next
    """
    ret = []
    last = 0

    for (i, item) in enumerate(session):
        if ('action' in item) and (item['action'] in ['recv', 'read']):
            ret.append(session[last:i])
            last = i

    """ Include remaining trace """
    ret.append(session[last:])

    return ret

def split_sessions(data):
    ret = []

    (index, fd) = (None, None)

    """ Asume there will be always a close call matching the file descriptor of a accept call """
    for (i, trace) in enumerate(data):
        if 'action' in trace:
            if (fd is None) and (trace['action'] == 'accept'):
                (index, fd) = (i, trace['return'])
            elif fd is not None:
                """ Duplicate file descriptor """
                if (trace['action'] == 'dup2') and (trace['file-descriptor'] == fd):
                    fd = trace['return']
                elif (trace['action'] == 'close') and (fd == trace['file-descriptor']):
                    ret.append(data[index:i])
                    (index, fd) = (None, None)

    return ret

def analyze_net_trace(dynamic_cfg, net_trace):
    group = cfg.Group()
    ins = None

    for item in net_trace:
        if 'ins-opcodes' in item:
            routine_addr = int(item['routine-addr'], 16)
            routine = item['routine']
            addr = int(item['ins-addr'], 16)
            opcodes = binascii.unhexlify(item['ins-opcodes'])

            """ Get call target """
            if (item['action'] == 'direct-call') or (item['action'] == 'indirect-call'):
                comment = item['target']
                ins = cfg.Ins(addr, opcodes, routine=routine, routine_addr=routine_addr, comment=comment)
            else:
                ins = cfg.Ins(addr, opcodes, routine=routine, routine_addr=routine_addr)

            if item['level'] == 'taint':
                ins.tainted = True
                group.tainted = True

            group.add(ins)

            """ End of group if last ins is either call, ret, or jump """
            if not ins.is_standard():
                dynamic_cfg.add(group)
                group = cfg.Group()

    """ Add last group if last instruction is standard """
    if (ins is not None) and (ins.is_standard()):
        dynamic_cfg.add(group)

    return dynamic_cfg

def analyze(data):
    dynamic_cfg = cfg.DynamicCFG()

    for session in split_sessions(data):
        net_traces = split_network_activity(session)
        for (i, net_trace) in enumerate(net_traces):
            if i == 1:
                dynamic_cfg.initialize()
                dynamic_cfg = analyze_net_trace(dynamic_cfg, net_trace)
                dynamic_cfg.finalize()
                print_info(f'CFG refinement {i}')
                return dynamic_cfg

    return dynamic_cfg

def main(args):
    file_data = read_file(args.log)
    print_info(f'Parsing {len(file_data)} records...')
    data = parse_data(file_data)

    dynamic_cfg = analyze(data)

    if dynamic_cfg.is_empty():
        print_warning('Empty CFG')
    elif args.export:
        dynamic_cfg.export_graph(args.export)
        print_info(f'{args.export}\t: CFG saved')

def check_args(args):
    if args.log:
        abspath = os.path.abspath(args.log)
        if not os.path.isfile(abspath):
            print_error(f'{abspath}\t: Not a file')
            sys.exit(-1)
    else:
        print_error('You need to specify a .log file (--log)')
        sys.exit(-1)

    if args.export:
        if os.path.isfile(args.export):
            print('The following file will be overwritten:')
            print(f'\t{args.export}')
            response = input('Do you want to continue? [Y/n] ')
            if response and (response not in ['y', 'Y', 'yes', 'Yes']):
                print('Abort.')
                sys.exit(-1)

def parse_args(arguments):
    argparser = argparse.ArgumentParser(description='Join all .log files ordered by timestamp')
    argparser.add_argument('--log', type=str, metavar='<file>', help='a .log file')
    argparser.add_argument('--export', type=str, metavar='<file>', help='output file to save .pdf')
    args = argparser.parse_args(arguments)

    check_args(args)

    return args

if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    main(args)
