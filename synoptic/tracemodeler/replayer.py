import io
import re
import time
import socket

import synoptic.debug as debug

BUF_SIZE = 4096

""" Greeting of a new connection (e.g., FTP or SMTP), possibly multi-line """
GREETING = re.compile(rb'(220-[^\n]*\n)*220[ \r\n][^\n]*\n?')

class Replayer:
    def __init__(self, host, port, transport_layer, delay):
        self.host = host
        self.port = port
        self.tcp = (transport_layer == 'tcp')
        self.delay = delay
        self.socket = self.create_socket(self.host, self.port)
        self.sockets = [self.socket]
        self.last_keyword = None
        self.query_table = []
        """ The greeting of the current connection has not been received yet """
        self.awaiting_greeting = False

    def create_socket(self, host, port):
        sock = None

        if self.tcp:
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            try:
                sock.connect((host, port))
                """ Non-blocking socket, returns -1 if sock would block execution """
                sock.setblocking(False)
            except ConnectionRefusedError:
                debug.error(f'Unable to connect to {host}:{port}')
        else:
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

        debug.info(f'Connected to {host}:{port}')

        return sock

    def replay(self, fsm, symbolic_messages):
        try:
            if symbolic_messages:
                fsm = self._learn_protocol(fsm)
            else:
                """ recv connection message """
                time.sleep(self.delay)
                self.recv(self.socket)
                debug.info(f'Sending {len(fsm)} FSM messages...')

                for transition in fsm:
                    next_state = transition.next

                    if next_state is None:
                        """ Disconnection message """
                        self.send(transition.message, self.socket)
                        time.sleep(self.delay)
                        self.recv(self.socket)
                        break
                    else:
                        self.send(transition.message, self.socket)
                        time.sleep(self.delay)
                        resp = self.recv(self.socket)
        except KeyboardInterrupt:
            debug.warning('User interrupt')
        except BrokenPipeError:
            debug.warning('Socket closed by remote peer')
        finally:
            self.close(self.socket)
            debug.info(f'Done! Bye!')

        return fsm

    def recv(self, sock):
        self._recv_pre_analysis()

        buffer = b''

        if self.tcp:
            buffer =  self._recv(sock)
        else:
            buffer = self._recvfrom(sock)

        debug.info(f'recv: {repr(buffer)}')

        buffer = self._recv_post_analysis(buffer)

        return buffer

    def send(self, message, sock):
        self._send_pre_analysis(message)

        if self.tcp:
            self._send(message.buffer, sock)
        else:
            self._sendto(message.buffer, sock)

        self.last_keyword = message.keyword


        debug.info(f'send: {repr(message.buffer)}')

        self._send_post_analysis(message)
    
    def _recv(self, sock):
        ret = io.BytesIO()
        buffer = b''

        try:
            while True:
                buffer = sock.recv(BUF_SIZE)
                if buffer:
                    ret.write(buffer)
                else:
                    break
        except (BlockingIOError, OSError):
            pass

        return ret.getvalue()

    def _recvfrom(self, sock):
        ret = io.BytesIO()
        buffer = b''

        while True:
            (buffer, _) = sock.recvfrom(BUF_SIZE)
            if buffer:
                ret.write(buffer)
            else:
                break

        return ret.getvalue()

    def _send(self, buffer, sock):
        sock.sendall(buffer)

    def _sendto(self, buffer, sock):
        sock.sendto(buffer, (self.host, self.port))

    def close(self, sock):
        if self.tcp:
            sock.close()

    def _send_pre_analysis(self, message):
        pass

    def _send_post_analysis(self, message):
        if message.keyword in [b'LIST', b'NLST']:
            """ Change socket """
            self.socket = self.sockets.pop(-1)

    def _recv_pre_analysis(self):
        pass

    def _recv_post_analysis(self, response):
        """ Create socket for passive incoming data """
        if self.last_keyword == b'EPSV':
            port = response.split(b'|')[-2]
            port = int(port.decode('utf-8'))
            sock = self.create_socket(self.host, port)
            self.sockets.append(sock)
            time.sleep(self.delay)
        elif self.last_keyword in [b'LIST', b'NLST']:
            """ Restore main socket channel """
            self.socket.close()
            self.socket = self.sockets[0]
            """ Return code """
            self.last_keyword = None
            time.sleep(self.delay)
            """ Return response and code from main socket """
            return self.recv(self.socket)
        elif self.last_keyword == b'QUIT':
            self.socket.close()
            time.sleep(self.delay)
            """ Create a new connection again """
            self.socket = self.create_socket(self.host, self.port)
            self.sockets = [self.socket]
            self.last_keyword = None
            time.sleep(self.delay)
            """ Consume welcome message """
            self._consume_greeting(self.recv(self.socket))

        return response

    def _learn_protocol(self, fsm):
        """ recv connection message """
        time.sleep(self.delay)
        self._consume_greeting(self.recv(self.socket))

        fsm.initialize()

        messages = fsm.generate_new_messages()

        """
        Contexts: the initial state and every state reached along the observed sequence. The
        disconnection message ends the session, so no context follows it
        """
        contexts = [[]] + [fsm.sequence[:i+1] for i in range(0, len(fsm.sequence)) if fsm.sequence[i].next is not None]

        for sequence in contexts:
            state = sequence[-1].next if sequence else fsm.entry_state
            for message in messages:
                try:
                    """ Send all messages in sequence before testing new message """
                    for transition in sequence:
                        self._send_recv_message(transition.message)

                    """ New transition message """
                    (resp, resp_code) = self._send_recv_message(message)
                    if self.resp_is_ok(resp_code):
                        fsm.reset_to(state)
                        fsm.add(message)
                        print(f'---> {fsm.last_inserted.dump()}')
                        fsm.add(fsm.last_transition.message)
                    """ Reset connection """
                    self._send_recv_message(fsm.last_transition.message)
                except Exception as e:
                    debug.warning(f'Error in query {repr(message.buffer)}\t: {str(e)}')
                    """ The session is in an unknown state: start the next query from a new connection """
                    self._reconnect()

        return fsm

    def _reconnect(self):
        for sock in set(self.sockets + [self.socket]):
            self.close(sock)
        self.socket = self.create_socket(self.host, self.port)
        self.sockets = [self.socket]
        self.last_keyword = None
        time.sleep(self.delay)
        """ Consume welcome message """
        self._consume_greeting(self.recv(self.socket))

    def _consume_greeting(self, welcome):
        """ A greeting that has not arrived within the delay will precede the next reply """
        self.awaiting_greeting = not welcome

    def _send_recv_message(self, message):
        self.send(message, self.socket)
        time.sleep(self.delay)
        resp = self.recv(self.socket)
        if self.awaiting_greeting and resp:
            self.awaiting_greeting = False
            late = GREETING.match(resp)
            if late:
                """ The greeting arrived late: the reply to the message follows it """
                debug.info(f'Late greeting discarded\t: {repr(resp[:late.end()])}')
                resp = resp[late.end():]
                if not resp:
                    time.sleep(self.delay)
                    resp = self.recv(self.socket)
        resp_code = self._get_response_code(resp)

        return (resp, resp_code)

    def _get_response_code(self, response):
        return re.search(b'^([0-9]+)[^0-9]', response).group(1)

    def resp_is_ok(self, response_code):
        """ FIXME Based in write response codes from traces """
        return (response_code[:1] == b'2') or (response_code in [b'150', b'331'])
