import os
import sys
import glob
import shlex
import datetime
import capstone.x86

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

def set_angr_reg(state, reg_id, value):
    if reg_id == capstone.x86.X86_REG_AH:
        state.regs.ah = value
    elif reg_id == capstone.x86.X86_REG_AL:
        state.regs.al = value
    elif reg_id == capstone.x86.X86_REG_AX:
        state.regs.ax = value
    elif reg_id == capstone.x86.X86_REG_BH:
        state.regs.bh = value
    elif reg_id == capstone.x86.X86_REG_BL:
        state.regs.bl = value
    elif reg_id == capstone.x86.X86_REG_BP:
        state.regs.bp = value
    elif reg_id == capstone.x86.X86_REG_BPL:
        state.regs.bpl = value
    elif reg_id == capstone.x86.X86_REG_BX:
        state.regs.bx = value
    elif reg_id == capstone.x86.X86_REG_CH:
        state.regs.ch = value
    elif reg_id == capstone.x86.X86_REG_CL:
        state.regs.cl = value
    elif reg_id == capstone.x86.X86_REG_CX:
        state.regs.cx = value
    elif reg_id == capstone.x86.X86_REG_DH:
        state.regs.dh = value
    elif reg_id == capstone.x86.X86_REG_DI:
        state.regs.di = value
    elif reg_id == capstone.x86.X86_REG_DIL:
        state.regs.dil = value
    elif reg_id == capstone.x86.X86_REG_DL:
        state.regs.dl = value
    elif reg_id == capstone.x86.X86_REG_DX:
        state.regs.dx = value
    elif reg_id == capstone.x86.X86_REG_EAX:
        state.regs.eax = value
    elif reg_id == capstone.x86.X86_REG_EBX:
        state.regs.ebx = value
    elif reg_id == capstone.x86.X86_REG_ECX:
        state.regs.ecx = value
    elif reg_id == capstone.x86.X86_REG_EDI:
        state.regs.edi = value
    elif reg_id == capstone.x86.X86_REG_EDX:
        state.regs.edx = value
    elif reg_id == capstone.x86.X86_REG_ESI:
        state.regs.esi = value
    elif reg_id == capstone.x86.X86_REG_RAX:
        state.regs.rax = value
    elif reg_id == capstone.x86.X86_REG_RBX:
        state.regs.rbx = value
    elif reg_id == capstone.x86.X86_REG_RCX:
        state.regs.rcx = value
    elif reg_id == capstone.x86.X86_REG_RDI:
        state.regs.rdi = value
    elif reg_id == capstone.x86.X86_REG_RDX:
        state.regs.rdx = value
    elif reg_id == capstone.x86.X86_REG_RSI:
        state.regs.rsi = value
    elif reg_id == capstone.x86.X86_REG_SI:
        state.regs.si = value
    elif reg_id == capstone.x86.X86_REG_SIL:
        state.regs.sil = value
    elif reg_id == capstone.x86.X86_REG_R8:
        state.regs.r8 = value
    elif reg_id == capstone.x86.X86_REG_R9:
        state.regs.r9 = value
    elif reg_id == capstone.x86.X86_REG_R10:
        state.regs.r10 = value
    elif reg_id == capstone.x86.X86_REG_R11:
        state.regs.r11 = value
    elif reg_id == capstone.x86.X86_REG_R12:
        state.regs.r12 = value
    elif reg_id == capstone.x86.X86_REG_R13:
        state.regs.r13 = value
    elif reg_id == capstone.x86.X86_REG_R14:
        state.regs.r14 = value
    elif reg_id == capstone.x86.X86_REG_R15:
        state.regs.r15 = value
    elif reg_id == capstone.x86.X86_REG_R8B:
        state.regs.r8b = value
    elif reg_id == capstone.x86.X86_REG_R9B:
        state.regs.r9b = value
    elif reg_id == capstone.x86.X86_REG_R10B:
        state.regs.r10b = value
    elif reg_id == capstone.x86.X86_REG_R11B:
        state.regs.r11b = value
    elif reg_id == capstone.x86.X86_REG_R12B:
        state.regs.r12b = value
    elif reg_id == capstone.x86.X86_REG_R13B:
        state.regs.r13b = value
    elif reg_id == capstone.x86.X86_REG_R14B:
        state.regs.r14b = value
    elif reg_id == capstone.x86.X86_REG_R15B:
        state.regs.r15b = value
    elif reg_id == capstone.x86.X86_REG_R8D:
        state.regs.r8d = value
    elif reg_id == capstone.x86.X86_REG_R9D:
        state.regs.r9d = value
    elif reg_id == capstone.x86.X86_REG_R10D:
        state.regs.r10d = value
    elif reg_id == capstone.x86.X86_REG_R11D:
        state.regs.r11d = value
    elif reg_id == capstone.x86.X86_REG_R12D:
        state.regs.r12d = value
    elif reg_id == capstone.x86.X86_REG_R13D:
        state.regs.r13d = value
    elif reg_id == capstone.x86.X86_REG_R14D:
        state.regs.r14d = value
    elif reg_id == capstone.x86.X86_REG_R15D:
        state.regs.r15d = value
    elif reg_id == capstone.x86.X86_REG_R8W:
        state.regs.r8w = value
    elif reg_id == capstone.x86.X86_REG_R9W:
        state.regs.r9w = value
    elif reg_id == capstone.x86.X86_REG_R10W:
        state.regs.r10w = value
    elif reg_id == capstone.x86.X86_REG_R11W:
        state.regs.r11w = value
    elif reg_id == capstone.x86.X86_REG_R12W:
        state.regs.r12w = value
    elif reg_id == capstone.x86.X86_REG_R13W:
        state.regs.r13w = value
    elif reg_id == capstone.x86.X86_REG_R14W:
        state.regs.r14w = value
    elif reg_id == capstone.x86.X86_REG_R15W:
        state.regs.r15w = value
    else:
        raise NotImplementedError(f'reg (ID: {reg_id}) not supported')
