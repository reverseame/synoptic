import os
import sys
import glob
import shlex
import datetime

""" Set auto local for user messages """
import locale
locale.setlocale(locale.LC_ALL, '')     # '' means auto

import tracemodeler.debug as debug

""" Tool version """
MAJOR = 0
MINOR = 1
PATCH = 0
VERSION = f'{MAJOR}.{MINOR}.{PATCH}'

""" Miminum radare2 version supported """
MIN_R2_VERSION = '5.8.4'

def get_logs(path):
    ret = []

    logs_dir = [x for x in glob.glob(os.path.join(path, '*.log'))]

    if logs_dir:
        """ Delete possible duplicates """
        ret = list(set([os.path.abspath(x) for x in logs_dir]))

    return ret

def get_traces(filenames):
    data = read_all_data(filenames)
    filtered_data = filter_data(data)
    ordered_data = order_data_by_timestamp(filtered_data)
    
    return ordered_data

def read_all_data(filenames):
    ret = []

    for filename in filenames:
        data = read_file(filename)
        debug.info(f'{filename}\t: Parsing {len(data):n} records...')
        parsed_data = parse_data(data)
        ret.append((filename, parsed_data))

    return ret

def read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read().splitlines()
    except Exception as ex:
        debug.error(f'{path}\t: Unable to read file\t: {str(ex)}')
        sys.exit(-1)

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
            debug.error(f'Parsing error\t: {str(e)}\t: line {i}\t: "{line}"')
            sys.exit(-1)

    return ret

def filter_data(data):
    ret = []
    already_seen = set()

    for (filename, file_data) in data:
        for (i, item) in enumerate(file_data, start=1):
            if 'timestamp' not in item:
                debug.warning(f'{filename}:{i}\t: \"{item}\"\t: Missing timestamp, line not processed')
                continue
            
            if item['timestamp'] in already_seen:
                debug.warning(f'{item}\t: Record with duplicate timestamp')

            already_seen.add(item['timestamp'])
            ret.append(item)

    return ret

def order_data_by_timestamp(data):
    return sorted(data, key=lambda x: datetime.datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S.%f'))
