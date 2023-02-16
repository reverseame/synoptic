#!/usr/bin/env python

import os
import sys
import glob
import shlex
import datetime
import argparse

scriptname = os.path.basename(__file__)

def _print_log_msg(level, string):
    print(f'{scriptname}\t: {level}\t: {string}', file=sys.stderr)

def print_info(string):
    _print_log_msg('INFO\t', string)

def print_warning(string):
    _print_log_msg('WARNING', string)

def print_error(string):
    _print_log_msg('ERROR\t', string)

def dict_to_str(item):
    string = ""

    for (key, value) in item.items():
        string += f'{key}=\"{value}\" '
    
    """ Delete remaining blank space """
    return string[:-1]

def write_file(filename, data):
    try:
        with open(filename, 'w') as f:
            f.write('\n'.join([dict_to_str(x) for x in data]))
    except OSError as ex:
        print_error(f'{filename}\t: Unable to write to output file\t: {str(ex)}')
        sys.exit(-1)

def order_data_by_timestamp(data):
    return sorted(data, key=lambda x: datetime.datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S.%f'))

def filter_data(data):
    ret = []
    already_seen = set()

    for (filename, file_data) in data:
        for (i, item) in enumerate(file_data, start=1):
            if 'timestamp' not in item:
                print_warning(f'{filename}:{i}\t: \"{item}\"\t: missing timestamp')
                continue
            
            if item['timestamp'] in already_seen:
                print_warning(f'{item}\t: record with duplicate timestamp')

            already_seen.add(item['timestamp'])
            ret.append(item)

    return ret

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

def read_all_data(filenames, output):
    count = 0
    ret = []

    for filename in filenames:
        if filename == os.path.abspath(output):
            print_warning(f'{filename}\t: output file skipped')
        else:
            data = read_file(filename)
            count += len(data)
            print_info(f'{filename}\t: parsing {len(data)} records...')
            parsed_data = parse_data(data)
            ret.append((filename, parsed_data))

    return ret

def get_log_filenames(args):
    ret = []

    if args.log:
        ret = args.log

    if args.dirlog:
        logs_dir = [x for x in glob.glob(os.path.join(args.dirlog, '*.log'))]
        if logs_dir:
            ret.extend(logs_dir)
        else:
            print_warning(f'{args.dirlog}\t: Unable to find logs')

    """ Delete possible duplicates """
    return list(set([os.path.abspath(x) for x in ret]))

def main(args):
    filenames = get_log_filenames(args)

    if filenames:
        print_info(f'joining {len(filenames)} files...')
        data = read_all_data(filenames, args.output)
        filtered_data = filter_data(data)
        ordered_data = order_data_by_timestamp(filtered_data)
        write_file(args.output, ordered_data)
        print_info(f'{args.output}\t: {len(ordered_data)} records saved')
    else:
        print_error('No files to process')
        sys.exit(-1)

def check_args(args):
    if not any([args.log, args.dirlog]):
        print_error('You need to specify either a list of .log files (--log) or a folder containing all .log files (--dirlog)')
        sys.exit(-1)

    if args.log:
        for filename in args.log:
            abspath = os.path.abspath(filename)
            if not os.path.isfile(abspath):
                print_error(f'{abspath}\t: Not a file')
                sys.exit(-1)

    if args.dirlog:
        if not os.path.isdir(args.dirlog):
            print_error(f'{args.dirlog}\t: Not a folder')
            sys.exit(-1)

    if args.output:
        if os.path.isfile(args.output):
            if not args.force:
                print('The following file will be overwritten:')
                print(f'\t{args.output}')
                response = input('Do you want to continue? [Y/n] ')
                if response and (response not in ['y', 'Y', 'yes', 'Yes']):
                    print('Abort.')
                    sys.exit(-1)
    else:
        print_error('You need to specify an output log file (--output)')
        sys.exit(-1)

def parse_args(arguments):
    argparser = argparse.ArgumentParser(description='Join all .log files ordered by timestamp')
    argparser.add_argument('--log', type=str, nargs='+', metavar='<file>', help='a list of .log files')
    argparser.add_argument('--dirlog', type=str, metavar='<folder>', help='folder containing .log files')
    argparser.add_argument('--output', type=str, metavar='<file>', help='file with all .logs joined')
    argparser.add_argument('--force', action='store_true', help='force output overwrite')
    args = argparser.parse_args(arguments)

    check_args(args)

    return args

if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    main(args)
