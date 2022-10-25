import json
import binascii

""" Disable logging for graphviz library """
import logging
logging.getLogger('graphviz').setLevel(logging.WARNING)
import graphviz

class ProtocolFSM:
    def __init__(self):
        self.size = 0
        self.initial = None
        self.final = None
        self.states = {}

    def initial_state(self):
        return self.states[self.initial]

    def final_state(self):
        return self.states[self.final]

    def is_empty(self):
        return self.initial is None

    def _generate_id(self):
        return f'state{self.size}'

    def loads(self, content):
        dict_content = json.loads(content)

        self.size = dict_content['size']
        self.initial = dict_content['initial']
        self.final = dict_content['final']

        for (state_id, state_content) in dict_content['states'].items():
            state = State(id=state_id)
            state.load(state_content)
            self.states[state_id] = state

    def append(self, message):
        if self.exists(message):
            raise NotImplementedError
        else:
            state = State(id=self._generate_id())
            state.transition(message)

            if self.is_empty():
                self.initial = state.id
                self.final = state.id
                self.size += 1
                self.states[state.id] = state
            else:
                last_state = self.final_state()
                last_state.set_next(state.id)
                self.final = state.id
                self.size += 1
                self.states[state.id] = state

    def exists(self, message):
        if self.is_empty():
            return False
        
        for state in self.states.values():
            if state.contains(message):
                return True

        return False

    def dump(self):
        if self.is_empty():
            return {}

        ret = {'size': self.size}
        ret['initial'] = self.initial
        ret['final'] = self.final
        states = {}

        for state in self:
            dump_state = state.dump()
            states[state.id] = dump_state[state.id]

        ret['states'] = states

        return ret

    def dumps(self):
        return json.dumps(self.dump(), indent=4)

    def export_graph(self, output):
        graph = graphviz.Digraph(output)

        """ Set left to right graph """
        graph.attr(rankdir='LR')

        """ Initial node """
        graph.attr('node', shape='point')
        graph.node('initial')

        """ Final node """
        graph.attr('node', shape='doublecircle')
        graph.node(self.final)

        """ Intermediate nodes """
        graph.attr('node', shape='circle')

        """ Model graph """
        graph.edge('initial', self.initial)    # Initial transition
        for state in self:
            for trans in state:
                if trans.next is not None:
                    graph.edge(state.id, trans.next, label=trans.message.keyword)

        """ Generate Graphviz DOT file (.gv) """
        graph.render()

    def __len__(self):
        return self.size

    def __iter__(self):
        if self.is_empty():
            return

        next = self.initial
        while next is not None:
            current_state = self.states[next]
            for trans in current_state:
                next = trans.next
                yield current_state

class State:
    def __init__(self, id=None, trans=None):
        self.id = id
        self.trans = [] if trans is None else trans

    def set_next(self, next):
        for trans in self.trans:
            trans.set_next(next)

    def transition(self, message):
        trans = Transition(message)
        self.trans.append(trans)
    
    def generate_message(self):
        #TODO Generate message based in message transitions
        return self.trans[0].message.generate_message()

    def contains(self, message):
        for trans in self.trans:
            if trans.equals(message):
                return True
        
        return False

    def has_multiple_transition(self):
        return len(self.trans) > 1

    def dump(self):
        ret = {}
        trans = []

        for t in self.trans:
            trans.append(t.dump())

        ret[self.id] = trans

        return ret

    def load(self, state):
        for trans in state:
            t = Transition()
            t.load(trans)
            self.trans.append(t)

    def __iter__(self):
        for trans in self.trans:
            yield trans

class Transition:
    def __init__(self, message=None, next=None):
        self.message = message
        self.next = next

    def set_next(self, next):
        self.next = next

    def equals(self, message):
        return self.message == message

    def dump(self):
        ret = {}

        ret['message'] = self.message.dump()
        ret['next'] = self.next

        return ret

    def load(self, transition):
        msg = Message()
        msg.load(transition['message'])

        self.message = msg
        self.next = transition['next']

class Message:
    def __init__(self, hexbytes=None, keyword=None, constraints={}):
        self.hexbytes = hexbytes
        self.bytes = None if hexbytes is None else binascii.unhexlify(hexbytes)
        self.keyword = self.get_keyword() if keyword is None else keyword
        self.constraints = constraints

    def __eq__(self, other):
        if isinstance(other, Message):
            return self.keyword == other.keyword

        return False

    def get_keyword(self):
        if self.bytes is None:
            return None

        string = self.bytes.decode('utf-8').strip()

        if string.isprintable():
            """ Search for spaces as separators """
            if string.count(' ') > 0:
                return string.split(' ')[0]
            else:
                """ Assume is only a keyword """
                return string

        raise NotImplementedError

    def generate_message(self):
        return self.bytes

    def constrain(self, where, byte):
        self.constraints[where] = byte

    def dump(self):
        ret = {}

        ret['content'] = self.hexbytes
        ret['keyword'] = self.keyword
        ret['constraints'] = self.constraints

        return ret

    def load(self, message):
        self.hexbytes = message['content']
        self.bytes = binascii.unhexlify(message['content'])
        self.keyword = message['keyword']
        self.constraints = message['constraints']
