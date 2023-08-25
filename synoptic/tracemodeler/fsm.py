import os
import re
import copy
import json
import PyPDF2
import shutil
import tempfile

""" Disable logging for graphviz library """
import logging
logging.getLogger('graphviz').setLevel(logging.WARNING)
import graphviz

SYMBOL_REGEX = re.compile(r'([a-z]+)\{([0-9]+)\}')
BSYMBOL_REGEX = re.compile(rb'([a-z]+)\{([0-9]+)\}')
"""
Group 1: symbol type
Group 2: symbol index

Example: k{9}   -> Group 1: k
                -> Group 2: 9
"""
SYMBOL_TYPE = 1
SYMBOL_INDEX = 2

class ProtocolFSM:
    def __init__(self):
        self.entry_state = None
        self.last_inserted = None
        self.states = []
        self.sequence = []
        self.refine = False
        self.textual = False        # Textual or binary protocol
        self.keywords = []
        self.delimiters = []
        self.inferred_keywords = []

    def is_empty(self):
        return self.entry_state is None

    def _generate_id(self):
        return f's{len(self.states):#02}'

    def _get_transition(self, from_state, to_state):
        for state in self.states:
            if state.id == from_state:
                for transition in state:
                    if ((to_state is None) and (transition.next is None)) or ((transition.next is not None) and (transition.next.id == to_state)):
                        return transition

    def initialize(self):
        """ Initialize FSM construction setting the last_inserted to the entry_state """
        if not self.is_empty():
            self.last_inserted = self.entry_state
            self.refine = True

    def finalize(self):
        """ Translate each state structure to global symbols """
        for state in self.states:
            state.analyze_symbols(self.keywords, self.delimiters)

    def import_from_file(self, filename):
        with open(filename, 'r') as f:
            content = f.read()

        self.loads(content)

    def export_to_file(self, filename):
        with open(filename, 'w') as f:
            f.write(self.dumps())

    def loads(self, content):
        dict_content = json.loads(content)

        self.textual = (dict_content['type'] == 'textual')
        self.keywords = [bytes.fromhex(item) for item in dict_content['symbols']['keywords']]
        self.delimiters = [bytes.fromhex(item) for item in dict_content['symbols']['delimiters']]
        self.inferred_keywords = [bytes.fromhex(item) for item in dict_content['symbols']['inferred_keywords']]

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

        """ Get transitions corresponding to sequence """
        for (from_state, to_state) in zip(dict_content['sequence'], dict_content['sequence'][1:]):
            transition = self._get_transition(from_state, to_state)
            if transition is not None:
                self.sequence.append(transition)

        """ Get final transition """
        self.sequence.append(self._get_transition(dict_content['sequence'][-1], None))

        self.initialize()

    def _add_transition_to_new_state(self, message):
        state = State(self._generate_id())
        """ Add transition from previous state to new one """
        self.last_inserted.transition_to(state)
        self.sequence.append(state.transition_by(message))
        self.last_inserted = state
        self.states.append(state)

    def add(self, message):
        """ Collect message keywords """
        if message.keyword not in self.keywords:
            self.keywords.append(message.keyword)

        """ Add first state """
        if self.is_empty():
            state = State(self._generate_id())
            self.sequence.append(state.transition_by(message))
            self.entry_state = state
            self.last_inserted = state
            self.states.append(state)
        else:
            if self.refine:
                """ Consume transition from last_inserted if already defined """
                for trans in self.last_inserted:
                    if trans.message == message:
                        self.sequence.append(self.last_inserted.transition_by(message))
                        """ Consume transition """
                        self.last_inserted = trans.next
                        return

                """ Create a transition to a previous state """
                for state in self.states:
                    for trans in state:
                        if trans.message == message:
                            self.sequence.append(self.last_inserted.transition_by(message, next_=trans.next))
                            self.last_inserted = trans.next
                            return

                """ Add message transition if message not defined """
                self.sequence.append(self.last_inserted.transition_by(message))
                self.refine = False
            else:
                """ Check if message transition is already defined in the FSM """
                for state in self.states:
                    for trans in state:
                        if trans.message == message:
                            new_state = State(self._generate_id())
                            """ Transition from new_state to an already defined state """
                            self.sequence.append(new_state.transition_by(message, next_=trans.next))
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
        ret = {}

        if self.is_empty():
            return ret

        ret['type'] = 'textual' if self.textual else 'binary'

        ret['entry_state'] = self.entry_state.id
        states = {}

        for state in self.states:
            dump_state = state.dump()
            states[state.id] = dump_state[state.id]

        ret['states'] = states

        ret['sequence'] = [self.entry_state.id]
        ret['sequence'].extend([transition.next.id for transition in self.sequence if transition.next is not None])

        symbols = {}
        symbols['keywords'] = [item.hex() for item in self.keywords]
        symbols['inferred_keywords'] = [item.hex() for item in self.inferred_keywords]
        symbols['delimiters'] = [item.hex() for item in self.delimiters]

        ret['symbols'] = symbols

        return ret

    def dumps(self, indent=None):
        return json.dumps(self.dump(), indent=indent)

    def export_graph(self, output):
        """ Automatically deletes temp_dir and all its content """
        with tempfile.TemporaryDirectory() as temp_dir:
            fsm_file = os.path.join(temp_dir, 'fsm')
            self._generate_fsm_graph(fsm_file)
            if self.inferred_keywords:
                inferred_keywords_file = os.path.join(temp_dir, 'inferred_keywords')
                self._generate_inferred_keywords_graph(inferred_keywords_file)

                """ Join temp files """
                merger = PyPDF2.PdfMerger()
                merger.append(f'{fsm_file}.gv.pdf')
                merger.append(f'{inferred_keywords_file}.gv.pdf')
                merger.write(output)
                merger.close()
            else:
                shutil.move(f'{fsm_file}.gv.pdf', output)

    def _generate_fsm_graph(self, output):
        graph = graphviz.Digraph(output)

        """ Graph title """
        graph.attr('graph', label='FSM', labelloc='t', fontsize='16.00', fontname='sans')

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
                graph.node(state.id, label=state.id, fontname='monospace')
                """ Epsilon symbol if it is an empty keyword """
                label = trans.message.keyword if trans.message.keyword else '\u03B5'

                if self.textual:
                    label = label.decode('utf-8')

                if trans.next is None:
                    graph.edge(state.id, 'final', label=label, labelfontname='monospace', fontname='monospace')
                else:
                    """ Intermediate nodes """
                    graph.edge(state.id, trans.next.id, label=label, labelfontname='monospace', fontname='monospace')

        """ Render graph """
        graph.render()

    def _generate_inferred_keywords_graph(self, inferred_keywords_file):
        graph = graphviz.Digraph(inferred_keywords_file)

        """ Graph title """
        graph.attr('graph', label='Inferred Keywords', labelloc='t', fontsize='16.00', fontname='sans')

        """ General node style """
        graph.attr('node', shape='circle', style='dotted')
        """ Set top to bottom graph """
        graph.attr(rankdir='TB')

        max_label_length = len(max(self.inferred_keywords))

        for (i, inferred_keyword) in enumerate(self.inferred_keywords):
            label = f'{inferred_keyword.decode("utf-8")}'
            graph.node(str(i), label=label, fixedsize='true', width=str(max_label_length/5), fontname='monospace')    # Empirical width value

        """ Generate a grid of grid_columns to display inferred keywords """
        grid_columns = 5
        for i in range(grid_columns, len(self.inferred_keywords)):
            """ Invisible edges """
            graph.edge(str(i - grid_columns), str(i), style="invis")

        """ Render graph """
        graph.render()

    def generate_new_messages(self):
        symbols = sorted([transition.message.symbols for transition in self.sequence], key=lambda x: len(x))

        for inferred_keyword in self.inferred_keywords:
            yield self._generate_new_message(symbols, inferred_keyword)

    def _generate_new_message(self, symbols, inferred_keyword):
        buffer = self._set_up_message_buffer(symbols, inferred_keyword)
        message = Message(buffer)
        message.keyword = inferred_keyword
        message.analyze_structure(self.delimiters)
        message.analyze_symbols(self.keywords, self.delimiters)

        return message

    def _set_up_message_buffer(self, symbols, inferred_keyword):
        template = self._create_base_template(symbols)
        return self.generate_buffer(template, inferred_keyword)

    def _create_base_template(self, symbols):
        template = []

        """ Search for keyword in first position of all symbol lists """
        if all([self._is_keyword_symbol(symbol_list[0]) for symbol_list in symbols]):
            template.append('k')

        """ Search for end delimiters in all symbol lists """
        delimiter = None
        for i in range(-1, (len(min(symbols)) - 1) * -1, -1):
            for symbol in symbols:
                if self._is_delimiter_symbol(symbol[i]):
                    """ Set up delimiter to first delimiter occurrence """
                    if delimiter is None:
                        delimiter = symbol[i]
                    """ Ensure all delimiters are placed in the same position """
                    if symbol[i] != delimiter:
                        delimiter = None
                        break
                else:
                    break
            else:
                """ Delimiter is placed in the same position for all symbols """
                if i == -1:
                    template.insert(len(template), delimiter)       # `insert` function inserts a element **before** index, we need to set index properly
                else:
                    template.insert(i + 1, delimiter)

                """ Reset delimiter """
                delimiter = None

        return template

    def generate_buffer(self, template, keyword):
        buffer = bytearray()

        for symbol in template:
            if symbol == 'k':
                buffer += keyword
            elif self._is_delimiter_symbol(symbol):
                delimiter = self._get_delimiter(symbol)
                buffer += delimiter
            else:
                # TODO append a placeholder field
                buffer += b'[placeholder]'

        return bytes(buffer)
    
    def _get_delimiter(self, symbol):
        match = SYMBOL_REGEX.search(symbol)

        return self.delimiters[int(match.group(SYMBOL_INDEX))]

    def _is_symbol(self, symbol, type_=''):
        match = None

        if isinstance(symbol, str):
            match = SYMBOL_REGEX.search(symbol)
        elif isinstance(symbol, bytes):
            match = BSYMBOL_REGEX.search(symbol)

        if match is None:
            return False
        else:
            return match.group(SYMBOL_TYPE) == type_

    def _is_keyword_symbol(self, symbol):
        return self._is_symbol(symbol, type_='k')

    def _is_delimiter_symbol(self, symbol):
        return self._is_symbol(symbol, type_='d')

    def __len__(self):
        return len(self.states)

    def __str__(self):
        return self.dumps()

    def __iter__(self):
        for transition in self.sequence:
            yield transition

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

        return last_transition

    def transition_to(self, state):
        """ If last_transition has no next state, set it to incoming state """
        if self.last_transition.is_final():
            self.last_transition.next = state
        else:
            raise NotImplementedError

    def analyze_symbols(self, keywords, delimiters):
        for transition in self.transitions:
            transition.message.analyze_symbols(keywords, delimiters)

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
    def __init__(self, buffer=None):
        self.buffer = buffer
        self.keyword = buffer           # Set whole buffer as default keyword
        self.structure = []
        self.symbols = []

    def analyze_keyword(self, delimiters, textual=False):
        buffer = self.buffer

        if textual:
            """ Strip special chars at the end """
            buffer = self.buffer.rstrip()

        for delimiter in delimiters:
            """
            Assume that a delimiter at the end of buffer does not correspond to
            keyword delimitation, only as buffer termination
            """
            if (delimiter in buffer) and (delimiter != buffer[-1]):
                self.keyword = buffer.split(delimiter)[0]
                return

        """ Default keyword to decoded buffer in textual protocols """
        if textual:
            self.keyword = buffer

    def analyze_structure(self, delimiters):
        buffers = [self.buffer]

        for delimiter in delimiters:
            buffers = self.split_keep_delimiter(buffers, delimiter)

        self.structure = buffers

    def split_keep_delimiter(self, buffers, delimiter):
        ret = []

        for buffer in buffers:
            if delimiter in buffer:
                items = buffer.split(delimiter)
                for (item1, item2) in zip(items[:-1], items[1:]):
                    if item1: ret.append(item1)
                    ret.append(delimiter)
                    if item2: ret.append(item2)
            else:
                ret.append(buffer)

        return ret

    def analyze_symbols(self, keywords, delimiters):
        for item in self.structure:
            if item in keywords:
                self.symbols.append(f'k{{{keywords.index(item)}}}')
            elif item in delimiters:
                self.symbols.append(f'd{{{delimiters.index(item)}}}')
            else:
                self.symbols.append(item)

    def dump(self):
        ret = {}

        ret['hexbytes'] = self.buffer.hex()
        ret['keyword'] = self.keyword.hex()
        ret['structure'] = [item.hex() for item in self.structure]
        ret['symbols'] = [self._hexencode_unknown(item) for item in self.symbols]

        return ret

    def load(self, content):
        self.buffer = bytes.fromhex(content['hexbytes'])
        self.keyword = bytes.fromhex(content['keyword'])
        self.structure = [bytes.fromhex(item) for item in content['structure']]
        self.symbols = [self._hexdecode_unknown(item) for item in content['symbols']]

    def _hexdecode_unknown(self, item):
        if isinstance(item, bytes):
            regex = BSYMBOL_REGEX
        elif isinstance(item, str):
            regex = SYMBOL_REGEX

        if regex.findall(item):
            return item

        return bytes.fromhex(item)

    def _hexencode_unknown(self, item):
        if isinstance(item, bytes):
            regex = BSYMBOL_REGEX
        elif isinstance(item, str):
            regex = SYMBOL_REGEX

        if regex.findall(item):
            return item

        return item.hex()

    def __eq__(self, other):
        if isinstance(other, Message):
            return self.keyword == other.keyword

        return False