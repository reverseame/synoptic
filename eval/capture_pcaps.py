#!/usr/bin/env python3
"""Capture the control-channel traffic of every seed session, without Pin.

The resulting pcaps are the input of the network-trace baselines (Netzob,
NEMESYS, NetPlier) for the format-inference comparison. Synoptic sees the
same client messages through its taint trace.

Usage: capture_pcaps.py OUTDIR [TARGET ...]
"""
import os
import signal
import subprocess
import sys
import time

from run_target import TARGETS, Session, listening, prepare_environment, seeds_for


def run_seed(target, seed):
    cfg = TARGETS[target]
    proc = subprocess.Popen([cfg['binary'], *cfg['args']], cwd=cfg['cwd'], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        deadline = time.time() + 30
        while time.time() < deadline and not listening(cfg['port']):
            time.sleep(0.2)
        sess = Session(cfg['port'], 10)
        sess.reply()
        for line in [l for l in open(seed, 'rb').read().replace(b'\r\n', b'\n').split(b'\n') if l.strip()]:
            sess.command(line)
        sess.close()
        for t in sess.data_threads:
            t.join(10)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait()
        while listening(cfg['port']):
            time.sleep(0.2)


def main():
    out = sys.argv[1]
    targets = sys.argv[2:] or sorted(TARGETS)
    os.makedirs(out, exist_ok=True)
    prepare_environment()
    for target in targets:
        port = TARGETS[target]['port']
        pcap = os.path.join(out, f'{target}.pcap')
        dump = subprocess.Popen(['tcpdump', '-i', 'lo', '-U', '-w', pcap, f'tcp port {port}'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        for seed in seeds_for(target, 'all'):
            run_seed(target, seed)
        time.sleep(1)
        dump.send_signal(signal.SIGINT)
        dump.wait()
        print(f'{target}: {pcap}', flush=True)


if __name__ == '__main__':
    main()
