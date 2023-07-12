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
        self.entry_state = None
        self.last_inserted = None
        self.states = []
        self.refine = False

    def is_empty(self):
        return self.entry_state is None

    def _generate_id(self):
        return f's{len(self.states):#02}'

    def initialize(self):
        """ Initialize FSM construction setting the last_inserted to the entry_state """
        if not self.is_empty():
            self.last_inserted = self.entry_state
            self.refine = True

    def import_from_file(self, filename):
        with open(filename, 'r') as f:
            content = f.read()
        self.loads(content)

    def export_to_file(self, filename):
        with open(filename, 'w') as f:
            f.write(self.dumps())

    def loads(self, content):
        dict_content = json.loads(content)

        for (state_id, state_content) in dict_content['states'].items():
            state = State(id_=state_id)
            state.load(state_content)
            self.states.append(state)

        """ Transform state ids to state references """
        ids = [state.id for state in self.states]
        self.entry_state = self.states[ids.index(dict_content['entry_state'])]
        for state in self.states:
            for trans in state:
                if trans.next is not None:
                    trans.next = self.states[ids.index(trans.next)]

        self.initialize()

    def _add_transition_to_new_state(self, message):
        state = State(self._generate_id())
        """ Add transition from previous state to new one """
        self.last_inserted.transition_to(state)
        state.transition_by(message)
        self.last_inserted = state
        self.states.append(state)

    def add(self, message):
        """ Add first state """
        if self.is_empty():
            state = State(self._generate_id())
            state.transition_by(message)
            self.entry_state = state
            self.last_inserted = state
            self.states.append(state)
        else:
            if self.refine:
                """ Consume transition from last_inserted if already defined """
                for trans in self.last_inserted:
                    if trans.message == message:
                        self.last_inserted.transition_by(message)
                        """ Consume transition """
                        self.last_inserted = trans.next
                        return

                """ Create a transition to a previous state """
                for state in self.states:
                    for trans in state:
                        if trans.message == message:
                            self.last_inserted.transition_by(message, next_=trans.next)
                            self.last_inserted = trans.next
                            return

                """ Add message transition if message not defined """
                self.last_inserted.transition_by(message)
                self.refine = False
            else:
                """ Check if message transition is already defined in the FSM """
                for state in self.states:
                    for trans in state:
                        if trans.message == message:
                            new_state = State(self._generate_id())
                            """ Transition from new_state to an already defined state """
                            new_state.transition_by(message, next_=trans.next)
                            """ Concretize last transition to new_state """
                            self.last_inserted.transition_to(new_state)
                            self.states.append(new_state)
                            """ Consume the transition to a previous state"""
                            self.last_inserted = trans.next
                            self.refine = True
                            return

                """ Add another state if message not defined """
                self._add_transition_to_new_state(message)

    def dump(self):
        if self.is_empty():
            return {}

        ret = {'entry_state': self.entry_state.id}
        states = {}

        for state in self.states:
            dump_state = state.dump()
            states[state.id] = dump_state[state.id]

        ret['states'] = states

        return ret

    def dumps(self, indent=4):
        return json.dumps(self.dump(), indent=indent)

    def export_graph(self, output):
        graph = graphviz.Digraph(output)

        """ Set left to right graph """
        graph.attr(rankdir='LR')

        """ General node style """
        graph.attr('node', shape='circle')
        """ Initial node style """
        graph.node('initial', label='', shape='circle', style='filled', color='black', fixedsize='true', width='0.3')
        """ Final node style """
        graph.node('final', label='', shape='doublecircle', style='filled', color='black', fixedsize='true', width='0.3')

        """ Initial transition """
        graph.edge('initial', self.entry_state.id)

        for state in self.states:
            for trans in state:
                """ Epsilon symbol if it is an empty keyword """
                label = trans.message.keyword if trans.message.keyword else '\u03B5'

                if trans.next is None:
                    graph.edge(state.id, 'final', label=label)
                else:
                    """ Intermediate nodes """
                    graph.edge(state.id, trans.next.id, label=label)

        """ Render graph """
        graph.render()

        """ Rename output file """
        pdf_file = f'{output}.gv.pdf'
        os.rename(pdf_file, output)
        """ Eliminate DOT file """
        gv_file = f'{output}.gv'
        os.remove(gv_file)

    def __len__(self):
        return len(self.states)

    def __str__(self):
        return self.dumps()

class State:
    def __init__(self, id_):
        self.id = id_
        self.transitions = []
        self.last_transition = None

    def transition_by(self, message, next_=None):
        for trans in self.transitions:
            if trans.message == message:
                trans.transition()
                last_transition = trans
                break
        else:
            last_transition = Transition(message, next_)
            self.transitions.append(last_transition)

        self.last_transition = last_transition

    def transition_to(self, state):
        """ If last_transition has no next state, set it to incoming state """
        if self.last_transition.is_final():
            self.last_transition.next = state
        else:
            raise NotImplementedError

    def dump(self):
        ret = {}
        transitions = []

        for transition in self.transitions:
            transitions.append(transition.dump())

        ret[self.id] = transitions

        return ret

    def load(self, content):
        for trans in content:
            t = Transition()
            t.load(trans)
            self.transitions.append(t)

    def __iter__(self):
        for transition in self.transitions:
            yield transition

class Transition:
    def __init__(self, message=None, next_=None):
        self.message = message
        self.next = next_
        self.count = 1

    def transition(self):
        self.count += 1

    def is_final(self):
        return self.next is None

    def dump(self):
        ret = {}

        ret['message'] = self.message.dump()
        ret['next'] = None if self.next is None else self.next.id

        return ret

    def load(self, content):
        msg = Message()
        msg.load(content['message'])

        self.message = msg
        self.next = content['next']

    def __eq__(self, other):
        if isinstance(other, Transition):
            return (self.message == other.message) and (self.next == other.next)

        return False

class Message:
    def __init__(self, bytes_=None, keyword=None):
        self.bytes = bytes_
        self.keyword = keyword

    def generate_message(self):
        return self.bytes

    def dump(self):
        ret = {}

        ret['hexbytes'] = binascii.hexlify(self.bytes).decode('utf-8')
        ret['keyword'] = self.keyword

        return ret

    def load(self, content):
        self.bytes = binascii.unhexlify(content['hexbytes'])
        self.keyword = content['keyword']

    def __eq__(self, other):
        if isinstance(other, Message):
            return self.keyword == other.keyword

        return False
