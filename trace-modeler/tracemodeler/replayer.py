import io
import time
import socket

import tracemodeler.debug as debug

BUF_SIZE = 4096

class Replayer:
    def __init__(self, host, port, transport_layer):
        self.host = host
        self.port = port
        self.tcp = (transport_layer == 'tcp')
        self.socket = self.create_socket()

    def create_socket(self):
        sock = None

        if self.tcp:
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            try:
                sock.connect((self.host, self.port))
                """ Non-blocking socket, returns -1 if sock would block execution """
                sock.setblocking(False)
            except ConnectionRefusedError:
                debug.error(f'Unable to connect to {self.host}:{self.port}')
        else:
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

        debug.info(f'Connected to {self.host}:{self.port}')

        return sock

    def replay(self, fsm, delay, new_messages):
        new_messages_triggered = False
        already_visited = []

        """ recv connection message """
        self.recv()

        try:
            debug.info(f'Sending {len(fsm)} messages...')

            for transition in fsm:
                next_state = transition.next
                if next_state is not None:
                    """
                    Create new messages based in inferred keywords once we are
                    back to an already visited state
                    """
                    if new_messages and not new_messages_triggered and (next_state.id in already_visited) and fsm.inferred_keywords:
                        for inferred_message in fsm.generate_new_messages():
                            self.send(inferred_message.buffer)
                            time.sleep(delay)
                            self.recv()
                        new_messages_triggered = True
                    else:
                        already_visited.append(next_state.id)
                        self.send(transition.message.buffer)
                        time.sleep(delay)
                        self.recv()
                else:
                    """ Disconnection message """
                    self.send(transition.message.buffer)
                    time.sleep(delay)
                    self.recv()
        except KeyboardInterrupt:
            debug.warning('User interrupt')
        except BrokenPipeError:
            debug.warning('Socket closed by remote peer')
        finally:
            if self.tcp: self.socket.close()
            debug.info(f'Done! Bye!')

    def recv(self):
        buffer = b''

        if self.tcp:
            buffer =  self._recv()
        else:
            buffer = self._recvfrom()

        debug.info(f'recv: {repr(buffer)}')

    def send(self, buffer):
        if self.tcp:
            self._send(buffer)
        else:
            self._sendto(buffer)

        debug.info(f'send: {repr(buffer)}')
    
    def _recv(self):
        ret = io.BytesIO()
        buffer = b''

        try:
            while True:
                buffer = self.socket.recv(BUF_SIZE)
                if buffer:
                    ret.write(buffer)
                else:
                    break
        except BlockingIOError:
            pass

        return ret.getvalue()

    def _recvfrom(self):
        ret = io.BytesIO()
        buffer = b''

        while True:
            (buffer, _) = self.socket.recvfrom(BUF_SIZE)
            if buffer:
                ret.write(buffer)
            else:
                break

        return ret.getvalue()

    def _send(self, buffer):
        self.socket.sendall(buffer)

    def _sendto(self, buffer):
        self.socket.sendto(buffer, (self.host, self.port))
