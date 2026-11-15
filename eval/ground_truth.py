#!/usr/bin/env python3
"""Extract the command vocabulary of each target from its source code.

For every target we report the set of commands that the server implements
(it dispatches them to a handler). For ProFTPD we also report the command
table that pr_cmd_get_id() compares against, which can be larger because it
includes commands handled only by modules that were not compiled in.
"""
import json
import os
import re
import subprocess
import sys

TARGETS = os.environ.get('TARGETS', '/opt/targets')


def preprocess(path, cwd, flags):
    """Run the C preprocessor so that comments and disabled #ifdef blocks disappear."""
    out = subprocess.run(['gcc', '-E', '-P', *flags, path], cwd=cwd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f'gcc -E failed for {path}: {out.stderr[:500]}')
    return out.stdout


def proftpd(root):
    ftp_h = open(os.path.join(root, 'include', 'ftp.h')).read()
    macros = dict(re.findall(r'#define\s+(C_[A-Z0-9_]+)\s+"([^"]+)"', ftp_h))

    cmd_c = open(os.path.join(root, 'src', 'cmd.c')).read()
    table = cmd_c[cmd_c.index('cmd_ids[]'):]
    table = table[:table.index('};')]
    parser = sorted({macros[m] for m in re.findall(r'\{\s*(C_[A-Z0-9_]+)\s*,', table) if m in macros})

    glue = open(os.path.join(root, 'modules', 'module_glue.c')).read()
    modules = sorted(set(re.findall(r'&(\w+)_module', glue)))
    implemented = set()
    for mod in modules:
        candidates = [os.path.join(root, 'modules', f'{mod}.c'), os.path.join(root, 'modules', f'mod_{mod}.c')]
        src = next((p for p in candidates if os.path.exists(p)), None)
        if src is None:
            continue
        text = open(src).read()
        for name in re.findall(r'\{\s*CMD\s*,\s*(C_[A-Z0-9_]+)\s*,', text):
            if name in macros:
                implemented.add(macros[name])
    return {'implemented': sorted(implemented), 'parser_table': parser, 'modules': modules}


def lightftp(root):
    src = open(os.path.join(root, 'Source', 'ftpserv.c')).read()
    block = src[src.index('*ftpcmds[MAX_CMDS]'):]
    block = block[:block.index('};')]
    cmds = sorted(set(re.findall(r'"([A-Z]+)"', block)))
    return {'implemented': cmds}


def bftpd(root):
    text = preprocess('commands.c', root, ['-I.'])
    block = text[text.index('const struct command commands[]'):]
    block = block[:block.index('};')]
    cmds = sorted(set(re.findall(r'\{\s*"([A-Z_]+)"', block)))
    return {'implemented': cmds}


def pureftpd(root):
    text = preprocess('src/ftp_parser.c', root, ['-DHAVE_CONFIG_H', '-I.', '-Isrc'])
    cmds = sorted({c.upper() for c in re.findall(r'strcmp\(cmd,\s*"([a-z@]+)"\)', text)})
    return {'implemented': cmds}


def exim(root):
    """Commands of the cmd_list table that smtp_read_command() matches with strncmpic(). The names
    are lowercase and may include the argument prefix ("mail from:"); the keyword is the first word.
    Entries under #ifdef SUPPORT_TLS count only if the build enables TLS."""
    src = open(os.path.join(root, 'src', 'src', 'smtp_in.c')).read()
    block = src[src.index('static smtp_cmd_list cmd_list[]'):]
    block = block[:block.index('};')]
    config = open(os.path.join(root, 'src', 'build-Linux-x86_64', 'config.h')).read()
    if re.search(r'^#define\s+SUPPORT_TLS\b', config, re.M) is None:
        block = re.sub(r'#ifdef\s+SUPPORT_TLS.*?#endif', '', block, flags=re.S)
    entries = re.findall(r'\{\s*"([a-z_ :]+)"\s*,\s*([^,]+),', block)
    cmds = sorted({name.split()[0].upper() for name, length in entries if length.strip() != '0'})
    return {'implemented': cmds}


def live555(root):
    """Request names that RTSPServer::RTSPClientConnection::handleRequestBytes() and the session
    handlers compare with strcmp(), including the HTTP methods of RTSP-over-HTTP tunneling."""
    src = open(os.path.join(root, 'liveMedia', 'RTSPServer.cpp')).read()
    cmds = sorted(set(re.findall(r'strcmp\(cmdName,\s*"([A-Z_]+)"\)', src)))
    return {'implemented': cmds}


EXTRACTORS = {
    'proftpd-1.3.8': proftpd,
    'proftpd': proftpd,
    'lightftp': lightftp,
    'bftpd': bftpd,
    'pureftpd': pureftpd,
    'exim': exim,
    'live555': live555,
}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '/dev/stdout'
    result = {name: fn(os.path.join(TARGETS, name)) for name, fn in EXTRACTORS.items()}
    with open(out, 'w') as f:
        json.dump(result, f, indent=2)
    for name, gt in result.items():
        extra = f", parser table {len(gt['parser_table'])}" if 'parser_table' in gt else ''
        print(f'{name}: {len(gt["implemented"])} implemented{extra}', file=sys.stderr)


if __name__ == '__main__':
    main()
