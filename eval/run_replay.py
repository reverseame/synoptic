#!/usr/bin/env python3
"""Run Synoptic's replay stage against an uninstrumented server.

Usage: run_replay.py TARGET FSM_JSON OUTDIR [--conf FILE] [--delay MS]

The server runs as a standalone daemon, because the replayer reconnects after every session reset. The
replayer loads FSM_JSON (an fsm.json exported by the analysis), sends every recovered keyword from
the initial state and from each state of the observed sequence, and adds accepted ones to the FSM.
OUTDIR receives replay.json (one record per exchange, candidate counts) and fsm-inferred.json.
"""
import argparse
import collections
import json
import os
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, '/opt/synoptic')

import capstone  # noqa: E402

import synoptic.tracemodeler.model as synoptic_model  # noqa: E402
import synoptic.tracemodeler.replayer as replayer  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_target import TARGETS, listening, log  # noqa: E402


def fsm_size(fsm_dict):
    """Number of states and transitions of an exported FSM."""
    states = fsm_dict['states']
    return len(states), sum(len(transitions) for transitions in states.values())


def instrument(records, cls):
    """Record every exchange of the replayer, and which of them were judged as candidates."""
    original_exchange = cls._send_recv_message
    original_is_ok = cls.resp_is_ok

    def exchange(self, message):
        record = {'sent': message.buffer.decode(errors='replace'), 'code': None, 'error': None}
        records.append(record)
        try:
            (resp, code) = original_exchange(self, message)
        except Exception as e:
            record['error'] = f'{type(e).__name__}: {e}'
            raise
        record['code'] = code.decode(errors='replace')
        return (resp, code)

    def is_ok(self, code):
        accepted = original_is_ok(self, code)
        records[-1]['candidate'] = True
        records[-1]['accepted'] = bool(accepted)
        return accepted

    cls._send_recv_message = exchange
    cls.resp_is_ok = is_ok


def fixed_acceptance(self, response_code):
    """resp_is_ok with the intended list of accepted non-2xx codes, for replayers that predate the fix"""
    return (response_code[:1] == b'2') or (response_code in [b'150', b'331'])


class SMTPReplayer(replayer.Replayer):
    """Analyst glue for SMTP. There is no data channel, and QUIT ends the session, after which the
    replayer reconnects as it does for FTP. Positive completion (2xx) and positive intermediate (3xx,
    e.g., 354 after DATA) replies accept the command."""

    def _send_post_analysis(self, message):
        pass

    def _recv_post_analysis(self, response):
        if self.last_keyword is not None and self.last_keyword.upper() == b'QUIT':
            self._reconnect()
        return response

    def resp_is_ok(self, response_code):
        return response_code[:1] in (b'2', b'3')


class RTSPReplayer(replayer.Replayer):
    """Analyst glue for RTSP. The status code follows the protocol version, and no request closes the
    session: instead of sending the last observed request to reset the session, the replayer reconnects.
    A response is read up to the end of its Content-Length body, because a DESCRIBE response may arrive
    after the replay delay. The RTP streams started by PLAY are not received."""

    REPLY_TIMEOUT = 2

    def replay(self, fsm, symbolic_messages):
        self.reset_message = fsm.last_transition.message
        return super().replay(fsm, symbolic_messages)

    def _send_recv_message(self, message):
        if message is self.reset_message:
            self._reconnect()
            return (b'', b'')
        return super()._send_recv_message(message)

    def _recv(self, sock):
        buffer = b''
        sock.settimeout(self.REPLY_TIMEOUT)
        try:
            while b'\r\n\r\n' not in buffer:
                chunk = sock.recv(replayer.BUF_SIZE)
                if not chunk:
                    return buffer
                buffer += chunk
            head, _, body = buffer.partition(b'\r\n\r\n')
            match = re.search(rb'(?im)^content-length:\s*(\d+)', head)
            size = int(match.group(1)) if match else 0
            while len(body) < size:
                chunk = sock.recv(replayer.BUF_SIZE)
                if not chunk:
                    break
                body += chunk
                buffer += chunk
        except OSError:
            pass
        finally:
            sock.setblocking(False)
        return buffer

    def _send_post_analysis(self, message):
        pass

    def _recv_post_analysis(self, response):
        return response

    def _get_response_code(self, response):
        return re.search(rb'^RTSP/\d\.\d (\d+)', response).group(1)

    def resp_is_ok(self, response_code):
        return response_code[:1] == b'2'


REPLAYERS = {'ftp': replayer.Replayer, 'smtp': SMTPReplayer, 'rtsp': RTSPReplayer}


class Server:
    """Uninstrumented server. The ProFuzzBench builds of some servers serve a single session and
    exit, so the server is restarted whenever the replayer opens a control connection to it."""

    def __init__(self, command, cwd, port):
        self.command, self.cwd, self.port = command, cwd, port
        self.process = None
        self.starts = 0

    # Time a single-session server may take to exit after its session ends
    EXIT_GRACE = 1.0

    def ensure_listening(self):
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.wait(timeout=self.EXIT_GRACE)
            except subprocess.TimeoutExpired:
                pass
        if (self.process is not None) and (self.process.poll() is None) and listening(self.port):
            return
        if self.process is not None:
            self.stop()
        self.process = subprocess.Popen(self.command, cwd=self.cwd, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
        self.starts += 1
        deadline = time.time() + 60
        while time.time() < deadline and not listening(self.port):
            time.sleep(0.2)
        if not listening(self.port):
            raise RuntimeError(f'{self.command[0]}: server not listening')

    def stop(self):
        if self.process is None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            self.process.wait(timeout=20)
        except ProcessLookupError:
            pass
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
        self.process = None


def supervise(server, restart):
    """Make every control connection of the replayer find a listening server, restarted if requested."""
    original_create_socket = replayer.Replayer.create_socket

    def create_socket(self, host, port):
        if port == server.port:
            if restart:
                server.stop()
            server.ensure_listening()
        return original_create_socket(self, host, port)

    replayer.Replayer.create_socket = create_socket



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', choices=sorted(TARGETS))
    ap.add_argument('fsm')
    ap.add_argument('outdir')
    ap.add_argument('--conf', help='server configuration replacing the ProFuzzBench one')
    ap.add_argument('--delay', type=int, default=200, help='delay between messages (ms), as in the case study')
    ap.add_argument('--fixed-acceptance', action='store_true',
                    help='replace resp_is_ok by the corrected version (only for the original replayer)')
    args = ap.parse_args()

    cfg = TARGETS[args.target]
    os.makedirs(args.outdir)
    server_args = [a for a in cfg['args'] if a != '-X']
    if args.conf:
        server_args[server_args.index('-c') + 1] = args.conf
    server = Server([cfg['binary'], *server_args], cfg['cwd'], cfg['port'])
    records = []
    if args.fixed_acceptance:
        replayer.Replayer.resp_is_ok = fixed_acceptance
    replayer_class = REPLAYERS[cfg['protocol']]
    instrument(records, replayer_class)
    supervise(server, cfg.get('replay_restart', False))
    try:
        server.ensure_listening()

        with open(args.fsm) as f:
            fsm_text = f.read()
        model = synoptic_model.Model(arch_mode=capstone.CS_MODE_64)
        model.fsm.loads(fsm_text)
        candidates = [m.buffer.decode(errors='replace') for m in model.fsm.generate_new_messages()]
        log(f'replaying {len(candidates)} candidates from {len(model.fsm.sequence)} contexts')

        t0 = time.time()
        fsm = replayer_class('127.0.0.1', cfg['port'], 'tcp', args.delay / 1000).replay(
            model.fsm, symbolic_messages=True)
        seconds = round(time.time() - t0, 1)
        fsm.export_to_file(os.path.join(args.outdir, 'fsm-inferred.json'))
    finally:
        server.stop()

    # Candidates whose exchange failed never reach resp_is_ok: count them as rejected candidates.
    for record in records:
        if 'candidate' not in record and record['error'] and record['sent'] in candidates:
            record['candidate'] = True
            record['accepted'] = False
    tested = [r for r in records if r.get('candidate')]
    with open(os.path.join(args.outdir, 'fsm-inferred.json')) as f:
        after = fsm_size(json.load(f))
    result = {
        'target': args.target, 'fsm': args.fsm, 'conf': args.conf, 'delay_ms': args.delay, 'seconds': seconds,
        'n_inferred_keywords': len(candidates), 'n_contexts': len(model.fsm.sequence),
        'candidates': len(tested), 'accepted': sum(r['accepted'] for r in tested),
        'accepted_keywords': sorted({r['sent'].strip() for r in tested if r['accepted']}),
        'rejected_codes': dict(collections.Counter(r['code'] or 'error' for r in tested if not r['accepted'])),
        'fsm_before': fsm_size(json.loads(fsm_text)), 'fsm_after': after, 'server_starts': server.starts,
        'records': records,
    }
    with open(os.path.join(args.outdir, 'replay.json'), 'w') as f:
        json.dump(result, f, indent=1)
    log(f"candidates={result['candidates']} accepted={result['accepted']} "
        f"fsm={result['fsm_before']}->{result['fsm_after']} keywords={len(result['accepted_keywords'])}")


if __name__ == '__main__':
    main()
