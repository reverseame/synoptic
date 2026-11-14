#!/usr/bin/env python3
"""Trace an FTP target under Pin with seed sessions and run Synoptic's analysis.

Usage: run_target.py TARGET CONDITION OUTDIR [--engine binsec|angr] [--timeout S]

CONDITION selects the seed sessions that form the initial trace:
  first   the first ProFuzzBench seed of the target (sorted by name)
  all     every ProFuzzBench seed of the target, one server run per seed
  paper   the 23-command tnftp session of the paper (ProFTPD 1.3.8 only)
"""
import argparse
import glob
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, '/opt/synoptic')
import synoptic.utils as utils  # noqa: E402
from synoptic.tracemodeler.fsm import Message  # noqa: E402
from synoptic.tracemodeler.model import Model  # noqa: E402

# Synoptic locates its Binsec templates relative to the __main__ script; this harness lives elsewhere.
utils.TOOL_ROOT_DIR = '/opt/synoptic'

PIN = os.path.join(os.environ.get('PIN_ROOT', '/opt/pin-3.25'), 'pin')
PINTOOL = '/opt/synoptic/synoptic/servertracer/obj-intel64/server_tracer.so'
T = os.environ.get('TARGETS', '/opt/targets')
S = '/opt/subjects'
HERE = os.path.dirname(os.path.abspath(__file__))

TARGETS = {
    'proftpd-1.3.8': {'cwd': f'{T}/proftpd-1.3.8', 'binary': f'{T}/proftpd-1.3.8/proftpd',
                      'args': ['-n', '-c', f'{S}/ProFTPD/basic.conf', '-X'], 'port': 21, 'seeds': f'{S}/ProFTPD/in-ftp'},
    'proftpd': {'cwd': f'{T}/proftpd', 'binary': f'{T}/proftpd/proftpd',
                'args': ['-n', '-c', f'{S}/ProFTPD/basic.conf', '-X'], 'port': 21, 'seeds': f'{S}/ProFTPD/in-ftp'},
    'lightftp': {'cwd': f'{T}/lightftp/Source/Release', 'binary': f'{T}/lightftp/Source/Release/fftp',
                 'args': ['fftp.conf', '2200'], 'port': 2200, 'seeds': f'{S}/LightFTP/in-ftp'},
    'pureftpd': {'cwd': f'{T}/pureftpd', 'binary': f'{T}/pureftpd/src/pure-ftpd',
                 'args': ['-A'], 'port': 21, 'seeds': f'{S}/PureFTPD/in-ftp'},
    'bftpd': {'cwd': f'{T}/bftpd', 'binary': f'{T}/bftpd/bftpd',
              'args': ['-D', '-c', f'{S}/BFTPD/basic.conf'], 'port': 21, 'seeds': f'{S}/BFTPD/in-ftp'},
}


def log(msg):
    print(f'[run_target] {msg}', flush=True)


# --------------------------------------------------------------------------- FTP client

class Session:
    """Minimal FTP client that replays a seed file and services data connections."""

    def __init__(self, port, timeout):
        self.timeout = timeout
        self.ctrl = socket.create_connection(('127.0.0.1', port), timeout=timeout)
        self.buf = b''
        self.data_threads = []
        self.transcript = []

    def _drain(self, sock):
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass
        finally:
            sock.close()

    def reply(self):
        """Read one complete FTP reply (single or multi-line)."""
        lines = []
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            while b'\r\n' not in self.buf and b'\n' not in self.buf:
                try:
                    chunk = self.ctrl.recv(4096)
                except socket.timeout:
                    return b'\n'.join(lines)
                if not chunk:
                    return b'\n'.join(lines)
                self.buf += chunk
            line, _, self.buf = self.buf.partition(b'\n')
            line = line.rstrip(b'\r')
            lines.append(line)
            if re.match(rb'^\d{3} ', line):
                return b'\n'.join(lines)
        return b'\n'.join(lines)

    def command(self, line):
        verb = line.split(b' ', 1)[0].upper()
        listener = None
        if verb == b'PORT':
            nums = [int(x) for x in line.split(b' ', 1)[1].split(b',')]
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', nums[4] * 256 + nums[5]))
            listener.listen(1)
            listener.settimeout(self.timeout)
            t = threading.Thread(target=self._accept, args=(listener,), daemon=True)
            t.start()
            self.data_threads.append(t)
        self.ctrl.sendall(line + b'\r\n')
        resp = self.reply()
        self.transcript.append((line.decode(errors='replace'), resp.decode(errors='replace')))
        if verb == b'PASV':
            m = re.search(rb'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', resp)
            if m:
                self._connect_data(int(m.group(5)) * 256 + int(m.group(6)))
        elif verb == b'EPSV':
            m = re.search(rb'\|\|\|(\d+)\|', resp)
            if m:
                self._connect_data(int(m.group(1)))
        if resp[:3] == b'150':
            # Transfer in progress: wait for the completion reply.
            final = self.reply()
            self.transcript.append(('<transfer>', final.decode(errors='replace')))
        return resp

    def _accept(self, listener):
        try:
            conn, _ = listener.accept()
            self._drain(conn)
        except OSError:
            pass
        finally:
            listener.close()

    def _connect_data(self, port):
        try:
            sock = socket.create_connection(('127.0.0.1', port), timeout=self.timeout)
        except OSError:
            return
        t = threading.Thread(target=self._drain, args=(sock,), daemon=True)
        t.start()
        self.data_threads.append(t)

    def close(self):
        try:
            self.ctrl.close()
        except OSError:
            pass


def replay_seed(target, seed_file, logdir, timeout):
    """Start the target under Pin, replay one seed session, and stop the target."""
    cfg = TARGETS[target]
    cmd = [PIN, '-follow_execv', '-t', PINTOOL, '-dirlog', logdir, '--', cfg['binary'], *cfg['args']]
    proc = subprocess.Popen(cmd, cwd=cfg['cwd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        # Probe /proc/net/tcp instead of connecting: a probe connection would open an extra session.
        deadline = time.time() + 180
        while time.time() < deadline and not listening(cfg['port']):
            if proc.poll() is not None:
                raise RuntimeError(f'{target}: server exited before listening')
            time.sleep(1)
        if not listening(cfg['port']):
            raise RuntimeError(f'{target}: server not listening after 180 s')
        lines = [l for l in open(seed_file, 'rb').read().replace(b'\r\n', b'\n').split(b'\n') if l.strip()]
        sess = Session(cfg['port'], timeout)
        banner = sess.reply()
        sess.transcript.append(('<banner>', banner.decode(errors='replace')))
        for line in lines:
            try:
                sess.command(line)
            except OSError as e:
                # The server closed the control connection (e.g., after QUIT or REIN): end the session here.
                sess.transcript.append((line.decode(errors='replace'), f'<connection closed: {e}>'))
                break
        sess.close()
        for t in sess.data_threads:
            t.join(timeout)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
        return sess.transcript
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGINT)
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def listening(port):
    hexport = f'{port:04X}'
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            for row in open(path).read().splitlines()[1:]:
                cols = row.split()
                if cols[1].endswith(':' + hexport) and cols[3] == '0A':
                    return True
        except OSError:
            pass
    return False


# --------------------------------------------------------------------------- analysis

def seeds_for(target, condition):
    if condition == 'paper':
        return [os.path.join(HERE, 'seeds', 'paper_session.raw')]
    seeds = sorted(glob.glob(os.path.join(TARGETS[target]['seeds'], '*.raw')),
                   key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', os.path.basename(p))])
    return seeds[:1] if condition == 'first' else seeds


def prepare_environment():
    os.makedirs('/tmp/test', exist_ok=True)
    with open('/tmp/test/hello_world.txt', 'w') as f:
        f.write('Hello, world!\n\n')
    for d in ('/home/ubuntu/ftpshare', '/home/fuzzing'):
        os.makedirs(d, exist_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', choices=sorted(TARGETS))
    ap.add_argument('condition', choices=['first', 'all', 'paper'])
    ap.add_argument('outdir')
    ap.add_argument('--engine', default='binsec', choices=['binsec', 'angr'])
    ap.add_argument('--timeout', type=int, default=5, help='symbolic timeout (s)')
    ap.add_argument('--reply-timeout', type=int, default=20)
    args = ap.parse_args()

    prepare_environment()
    out = os.path.abspath(args.outdir)
    logdir = os.path.join(out, 'traces')
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(logdir)

    result = {'target': args.target, 'condition': args.condition, 'engine': args.engine,
              'timeout': args.timeout, 'seeds': [], 'transcripts': {}}
    t0 = time.time()
    for seed in seeds_for(args.target, args.condition):
        log(f'replaying {seed}')
        result['seeds'].append(os.path.basename(seed))
        result['transcripts'][os.path.basename(seed)] = replay_seed(args.target, seed, logdir, args.reply_timeout)
    result['tracing_seconds'] = round(time.time() - t0, 1)

    logs = sorted(glob.glob(os.path.join(logdir, '*.log')))
    log(f'{len(logs)} trace files')
    traces = utils.get_traces(logs)
    model = Model()
    t1 = time.time()
    model.analyze(traces)
    result['observed_keywords'] = sorted({k.decode(errors='replace').upper() for k in model.fsm.keywords})
    tainted = model.cfg.get_tainted_cfgs()
    result['functions'] = len(model.cfg.cfgs)
    result['tainted_loops'] = {
        f'{c.entry_node.group.leader.routine}@{c.id:#x}': len(c.get_tainted_loop_info()) for c in tainted
        if c.get_tainted_loop_info()}
    result['modeling_seconds'] = round(time.time() - t1, 1)
    # Per-message structure of every buffer read by the SUT (input for the format-inference metric)
    messages = []
    if model.fsm.delimiters is not None:
        for item in model.get_buffer_comparations(traces):
            if 'buffer' not in item:
                continue
            m = Message(item['buffer'])
            m.analyze_keyword(model.fsm.delimiters, model.fsm.textual)
            m.analyze_structure(model.fsm.delimiters)
            messages.append({'buffer': m.buffer.hex(), 'keyword': m.keyword.hex(),
                             'structure': [s.hex() for s in m.structure]})
    result['delimiters'] = [d.hex() for d in (model.fsm.delimiters or [])]
    result['messages'] = messages

    # Debug level for the symbolic stage only: it logs start, goal and cut addresses and every solution.
    logging.getLogger(utils.TOOL_NAME).setLevel(logging.DEBUG)
    t2 = time.time()
    try:
        model.symbolic_analysis(traces, TARGETS[args.target]['binary'], ' '.join(TARGETS[args.target]['args']),
                                args.engine, args.timeout)
        result['symbolic_error'] = None
    except Exception as e:  # keep the run: the error itself is a result
        result['symbolic_error'] = f'{type(e).__name__}: {e}'
    result['symbolic_seconds'] = round(time.time() - t2, 1)
    result['inferred_keywords'] = sorted({k.decode(errors='replace').upper() for k in model.fsm.inferred_keywords})

    if not model.fsm.is_empty():
        model.fsm.export_to_file(os.path.join(out, 'fsm.json'))
    with open(os.path.join(out, 'result.json'), 'w') as f:
        json.dump(result, f, indent=2)
    log(f"observed={len(result['observed_keywords'])} inferred={len(result['inferred_keywords'])} "
        f"loops={sum(result['tainted_loops'].values())} error={result['symbolic_error']}")


if __name__ == '__main__':
    main()
