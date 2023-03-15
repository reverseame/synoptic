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

def analyze_net_trace(trace_cfg, md, net_trace):
    group = cfg.Group()

    for item in net_trace:
        if 'ins-opcodes' in item:
            addr = int(item['ins-addr'], 16)
            opcodes = binascii.unhexlify(item['ins-opcodes'])
            dis = next(md.disasm(opcodes, addr))                # Just dissasemble one instruction

            ins = cfg.Ins(addr, opcodes, dis)
            group.add(ins)

            if ins.type != cfg.INS_TYPE_STANDARD:
                trace_cfg.add(group)
                group = cfg.Group()

    return trace_cfg
    
def analyze(data):
    trace_cfg = cfg.CFG()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    sessions = split_sessions(data)
    print_info(f'{len(sessions)} session/s found')

    for session in sessions:
        for (i, net_trace) in enumerate(split_network_activity(session)):
            print(f'Iteration {i}')
            trace_cfg.initialize()
            trace_cfg = analyze_net_trace(trace_cfg, md, net_trace)

    print_info(f'Done!')

    for (i, node) in enumerate(trace_cfg):
        print(f'\tNode {i}\n{str(node)}')

def main(args):
    file_data = read_file(args.log)
    print_info(f'Parsing {len(file_data)} records...')
    data = parse_data(file_data)

    analyze(data)

def check_args(args):
    if args.log:
        abspath = os.path.abspath(args.log)
        if not os.path.isfile(abspath):
            print_error(f'{abspath}\t: Not a file')
            sys.exit(-1)
    else:
        print_error('You need to specify a .log file (--log)')
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
