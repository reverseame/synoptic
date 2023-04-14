import os
import copy
import json
import binascii

""" Disable logging for graphviz library """
import logging
logging.getLogger('graphviz').setLevel(logging.WARNING)
import graphviz

class ProtocolFSM:
    def __init__(self):
        self.initial = None
        self.last = None
        self.index = None
        self.states = []

    def is_empty(self):
        return self.initial is None

    def _generate_id(self):
        return f'state{len(self.states)}'

    def initialize(self):
        """ Initialize FSM construction setting the index to the initial state """
        self.index = self.initial

    def loads(self, content):
        dict_content = json.loads(content)

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
        else:
            """
            A final state is already defining the message transition. This prevents to set a transition to itself
            """
            for trans in self.index:
                if trans.equals(message) and trans.is_final():
                    return
            """ Check if an already defined states contains the message """
            for state in self.states:
                """
                We go over all transitions to check if message is already in a state.
                Index state needs to point to the a state containing reached with a transition for the same message
                """
                for trans in state:
                    """ Check if transition contains the message """
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
                                return

                        """ We need to add a new transition from index to an already defined state with this message """
                        if self.index != state:
                            if not trans.is_final():
                                self.index.transition(message, next=trans.next)
                        """ We need to consume the transition if it is already defined for this state """
                        self.index = trans.next
                        return

            """ This is only reached if the message is not contained in states """

            """
            If index and last are equal, we did not encounter a backwards transition yet. Create a new state at the end
            of the FSM corresponding to a new message
            """
            if self.index == self.last:
                for index_trans in self.index:
                    """ Set from final transition to a new state """
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
                        return

                """ Create a new transition to the new state """
                self.index.transition(message)
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

        ret = {'initial': self.initial.id}
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
        graph.attr('node', shape='circle')
        graph.edge('initial', self.initial.id)      # Initial transition

        for state in self.states:
            for trans in state:
                """ Epsilon symbol if it is an empty keyword """
                label = trans.message.keyword if trans.message.keyword else '\u03B5'
                if trans.next is None:
                    """ Final node """
                    graph.attr('node', shape='doublecircle')
                    graph.node('final')
                    graph.edge(state.id, 'final', label=label)
                else:
                    """ Intermediate nodes """
                    graph.attr('node', shape='circle')
                    graph.edge(state.id, trans.next.id, label=label)


        """ Generate Graphviz DOT file (.gv) """
        graph.render()

        """ Rename output files """
        pdf_file = f'{output}.gv.pdf'
        os.rename(pdf_file, output)
        """ Eliminate output file extension """
        gv_file = f'{output}.gv'
        (gv_output, _) = os.path.splitext(output)
        gv_output = f'{gv_output}.gv'
        os.rename(gv_file, gv_output)

        return (output, gv_output)

    def __len__(self):
        return len(self.states)

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
                Two scenarios for deleting a transition:

                    1) If next state hasn't several transitions. Otherwise, we need to visit this transition
                    again to consume the upcoming transitions.

                    2) If its an inifinite loop to same state
                """
                #FIXME What happen when multiple transition is not in the next state but in a state after the next?
                if not trans.next.has_multiple_transition() or trans.is_transitition_to_state(state):
                    state.trans.remove(trans)
                yield from self._traverse(trans.next)
        else:
            trans = state.trans[0]
            yield trans.message
            state = trans.next
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
        if trans not in self.trans:
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

    def is_transitition_to_state(self, state):
        return state == self.next

    def __eq__(self, other):
        if isinstance(other, Transition):
            return (id(self) == id(other)) or ((self.message == other.message) and (self.next == other.next))

        return False

class Message:
    def __init__(self, msg_bytes=None, msg_addr=None, keyword=None, constraints={}):
        self.bytes = msg_bytes
        self.addr = msg_addr
        self.size = None if msg_bytes is None else len(msg_bytes)
        self.keyword = self.get_keyword() if keyword is None else keyword
        self.constraints = constraints

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
        ret['content'] = binascii.hexlify(self.bytes).decode('utf-8')
        ret['keyword'] = self.keyword
        ret['constraints'] = self.constraints

        return ret

    def load(self, message):
        self.bytes = binascii.unhexlify(message['content'])
        self.keyword = message['keyword']
        self.constraints = message['constraints']

    def _is_addr_in_range(self, addr):
        return (self.addr <= addr) and ((self.addr + self.size - 1) >= addr)

    def _get_index_by_addr(self, addr):
        if addr is None:
            return None

        if isinstance(addr, int):
            if self._is_addr_in_range(addr):
                return addr - self.addr
            else:
                raise IndexError(f'memory range from {hex(self.addr)} to {hex(self.addr + self.size - 1)}')
        else:
            raise TypeError(f'memory indices must be integers, not {type(addr).__name__}')

    def __len__(self):
        return self.size
    
    def __getitem__(self, addr):
        if isinstance(addr, slice):
            index_slice = slice(self._get_index_by_addr(addr.start), self._get_index_by_addr(addr.stop), addr.step)
            return self.bytes[index_slice]

        if isinstance(addr, int):
            return self.bytes[self._get_index_by_addr(addr)]

        raise TypeError(f'memory indices must be integers or slices, not {type(addr).__name__}')

    def __iter__(self):
        for b in self.bytes:
            yield b

    def __eq__(self, other):
        if isinstance(other, Message):
            return self.keyword == other.keyword

        return False
