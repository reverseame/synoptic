import binascii
import io
import time
import socket

import tracemodeler.model
import tracemodeler.debug as debug

BUF_SIZE = 4096

class Replayer:
    def __init__(self, host, port, tcp=True):
        self.host = host
        self.port = port
        self.tcp = tcp
        self.socket = self.create_socket()

    def create_socket(self):
        sock = None

        if self.tcp:
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            try:
                sock.connect((self.host, self.port))
            except ConnectionRefusedError:
                debug.error(f'Unable to connect to {self.host}:{self.port}')
        else:
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

        debug.info(f'Connected to {self.host}:{self.port}')

        return sock

    def replay(self, model, delay=0.5):
        try:
            debug.info(f'Sending {len(model)} messages...')

            for message in model:
                self.recv()
                self.send(binascii.unhexlify(message.bytes))
                time.sleep(delay)

            self.recv()
        finally:
            if self.tcp: self.socket.close()
            debug.info(f'Done! Bye!')

    def read_file(self, file):
        with open(file, 'r') as f:
            return f.read()

    def recv(self):
        buffer = b''

        if self.tcp:
            buffer =  self._recv()
        else:
            buffer = self._recvfrom()

        debug.info(f'recv: {buffer}')

    def send(self, buffer):
        if self.tcp:
            self._send(buffer)
        else:
            self._sendto(buffer)

        debug.info(f'send: {buffer}')
    
    def _recv(self):
        ret = io.BytesIO()
        buffer = b''

        while True:
            buffer = self.socket.recv(BUF_SIZE)
            ret.write(buffer)

            if len(buffer) != BUF_SIZE:
                break
        
        return ret.getvalue()

    def _recvfrom(self):
        ret = io.BytesIO()
        buffer = b''

        while True:
            (buffer, _) = self.socket.recvfrom(BUF_SIZE)
            ret.write(buffer)

            if len(buffer) != BUF_SIZE:
                break

        return ret.getvalue()

    def _send(self, buffer):
        self.socket.sendall(buffer)

    def _sendto(self, buffer):
        self.socket.sendto(buffer, (self.host, self.port))
