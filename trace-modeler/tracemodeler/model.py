import copy
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
        self.last = None
        self.index = None
        self.states = []

    def is_empty(self):
        return self.initial is None

    def _generate_id(self):
        return f'state{self.size}'

    def loads(self, content):
        dict_content = json.loads(content)

        self.size = dict_content['size']

        for (state_id, state_content) in dict_content['states'].items():
            state = State(id=state_id)
            state.load(state_content)
            self.states.append(state)

        """ Transform state id to state reference """
        ids = [state.id for state in self.states]
        self.initial = self.states[ids.index(dict_content['initial'])]
        for state in self.states:
            for trans in state:
                if trans.next is not None:
                    trans.next = self.states[ids.index(trans.next)]

    def append(self, message):
        """ Add first element """
        if self.is_empty():
            """ Create a new state """
            new_state = State(id=self._generate_id())
            new_state.transition(message)
            self.states.append(new_state)
            """ All pointers point to the new state """
            self.initial = new_state
            self.last = new_state
            self.index = new_state
            self.size += 1
        else:
            """ Check if an already defined states contains the message """
            for state in self.states:
                """
                We go over all transitions to check if message is already in a state.
                Index state needs to point to the a state containing reached with a transition for the same message
                """
                for trans in state:
                    """ We found the transition """
                    if trans.equals(message):
                        """ We now check a final transition in our index """
                        for index_trans in self.index:
                            if index_trans.is_final():
                                """ Create a new state to be pointed from index state transition """
                                new_state = State(id=self._generate_id())
                                new_state.transition(message)
                                index_trans.next = new_state
                                self.states.append(new_state)
                                """ And this new state must point to the previous state reached from the same message """
                                new_state.set_next(trans.next)
                                """ And needs to be the new index """
                                self.index = trans.next
                                self.last = new_state
                                self.size += 1
                                return

            """ This is only reached if the message is not contained in states """
            """
            If index and last are equal, we did not encounter a backwards transition yet. Create a new state at the end
            of the FSM corresponding to a new message
            """
            if self.index == self.last:
                for index_trans in self.index:
                    if index_trans.is_final():
                        """ Create a new state """
                        new_state = State(id=self._generate_id())
                        new_state.transition(message)
                        """ Set transition from index to the new state """
                        index_trans.next = new_state
                        self.states.append(new_state)
                        """ Change last and index to the new state """
                        self.index = new_state
                        self.last = new_state
                        self.size += 1
            else:
                """ We are in a backwards transition, where index is different from the last added state """
                """ Check if there is an already transition that matches the message """
                for trans in self.index:
                    if trans.equals(message):
                        self.index = trans.next
                        return

                """ Else, create a new transition to index """
                self.index.transition(message)
                self.last = self.index

    def exists(self, message):
        return any([state.contains(message) for state in self.states])

    def dump(self):
        if self.is_empty():
            return {}

        ret = {'size': self.size}
        ret['initial'] = self.initial.id
        states = {}

        for state in self.states:
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
        graph.node('final')

        """ Intermediate nodes """
        graph.attr('node', shape='circle')

        """ Model graph """
        graph.edge('initial', self.initial.id)     # Initial transition
        for state in self.states:
            for trans in state:
                if trans.next is None:
                    graph.edge(state.id, 'final', label=trans.message.keyword)
                else:
                    graph.edge(state.id, trans.next.id, label=trans.message.keyword)

        """ Generate Graphviz DOT file (.gv) """
        graph.render()

    def __len__(self):
        return self.size

    def __iter__(self):
        if self.is_empty():
            return

        fsm = copy.deepcopy(self)
        yield from self._traverse(fsm.initial)

    def _traverse(self, state):
        """ Final state """
        if state is None:
            return

        if state.has_multiple_transition():
            for trans in state:
                yield trans.message
                """
                Only delete current transition if next state hasn't several transitions. Otherwise,
                we need to visit this transition again to consume the upcoming transitions

                #FIXME What happen when multiple transition is not in the next state but in a state after the next?
                """
                if not trans.next.has_multiple_transition():
                    state.trans.remove(trans)
                yield from self._traverse(trans.next)
        else:
            yield state.trans[0].message
            state = state.trans[0].next
            yield from self._traverse(state)

class State:
    def __init__(self, id=None, trans=None):
        self.id = id
        self.trans = [] if trans is None else trans

    def set_next(self, next):
        for trans in self.trans:
            trans.set_next(next)

    def transition(self, message, next=None):
        trans = Transition(message, next)
        self.trans.append(trans)
    
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

    def is_final(self):
        return self.next is None

    def set_next(self, next):
        self.next = next

    def equals(self, message):
        return self.message == message

    def dump(self):
        ret = {}

        ret['message'] = self.message.dump()
        ret['next'] = None if self.next is None else self.next.id

        return ret

    def load(self, transition):
        msg = Message()
        msg.load(transition['message'])

        self.message = msg
        self.next = transition['next']

class Message:
    def __init__(self, hexbytes=None, keyword=None, constraints={}):
        self.hexbytes = hexbytes
        self.bytes = hexbytes if hexbytes is None else binascii.unhexlify(hexbytes)
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
