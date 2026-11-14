import os
import sys
import glob
import re
import shlex
import signal
import datetime
import __main__

""" Set auto local for user messages """
import locale
locale.setlocale(locale.LC_ALL, '')     # '' means auto

import synoptic.debug as debug

TOOL_HEADER = ''' __            __   __  ___    __ 
(__' \_/ |\ | /  \ |__)  |  | /  `
.__)  |  | \| \__/ |     |  | \__,
'''

TOOL_ROOT_DIR = os.path.dirname(os.path.abspath(__main__.__file__))
""" Name of the top-level environment a.k.a. main file """
(TOOL_NAME, _) = os.path.splitext(os.path.basename(__main__.__file__))

""" Tool version """
MAJOR = 0
MINOR = 1
PATCH = 0
VERSION = f'{MAJOR}.{MINOR}.{PATCH}'

""" radare2 version supported """
R2_VERSION = '5.8.4'

def get_servertracer_info():
    version_file = os.path.join(TOOL_ROOT_DIR, 'synoptic', 'servertracer', 'version.txt')
    content = read_file(version_file)

    for line in content:
        splitted = line.split(' ')
        if splitted[0] == 'PACKAGE':
            name = splitted[1]
        elif splitted[0] == 'VERSION':
            version = splitted[1]
    
    return (name, version)

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

""" key=value or key="value with spaces", as written by the pintool """
_RECORD_FIELD = re.compile(r'([^\s="]+)=("[^"=]*"|[^\s"=]*)(?:\s+|$)')

def _parse_line(line, delimiter):
    """ Parse one trace record; fast path for pintool records, shlex for anything else """
    if delimiter == '=' and '\\' not in line:
        new_dict = {}
        pos = 0
        while pos < len(line):
            match = _RECORD_FIELD.match(line, pos)
            if not match:
                break
            (key, value) = match.groups()
            new_dict[key] = value[1:-1] if value.startswith('"') else value
            pos = match.end()
        else:
            return new_dict

    new_dict = {}
    for (key, value) in [item.split(delimiter) for item in shlex.split(line)]:
        new_dict[key] = value
    return new_dict

def parse_data(data, delimiter='='):
    ret = []

    for (i, line) in enumerate(data, start=1):
        try:
            ret.append(_parse_line(line, delimiter))
        except ValueError as e:
            if i == len(data):
                """ The traced process was stopped while the record was being written """
                debug.warning(f'Truncated last record discarded\t: line {i}\t: "{line}"')
                break
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

def setup_timeout(timeout):
    """ Set the signal handler and a {timeout}-second alarm """
    signal.signal(signal.SIGALRM, _signal_handler)
    signal.alarm(timeout)

def disable_timeout():
    signal.alarm(0)

def _signal_handler(signum, frame):
    raise TimeOutException

class TimeOutException(Exception):
    pass
