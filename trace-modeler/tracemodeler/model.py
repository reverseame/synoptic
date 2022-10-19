import json
import binascii
from tkinter.messagebox import RETRY

class ProtocolFSM:
    def __init__(self):
        self.size = 0
        self.first = None
        self.states = {}

    def is_empty(self):
        return self.first is None

    def _generate_id(self):
        return f'state{self.size}'

    def loads(self, content):
        dict_content = json.loads(content)


        self.size = len(dict_content['states'])
        self.first = dict_content['first']
        

        current = dict_content['first']

        while True:
            transitions = dict_content['states'][current]

            state = State(id=current)
            for transition in transitions:
                message = Message(hexbytes=transition['content'])
                self.append(message)

            self.states[current] = state
            current = dict_content['states'][current]['next']

    def append(self, message):
        state = State(id=self._generate_id())
        state.transition(message)

        if self.exists(message):
            raise NotImplementedError
        else:
            self._append(state)

    def _append(self, state):
        if self.is_empty():
            self.first = state.id
            self.size += 1
            self.states[state.id] = state
        else:
            last_state = None
            for s in self:
                last_state = s

            last_state.next = state.id
            self.size += 1
            self.states[state.id] = state

    def exists(self, message):
        if self.is_empty():
            return False
        
        for state in self.states.values():
            if state.contains(message):
                return True

        return False

    def dumps(self):
        if self.is_empty():
            return '\{\}'

        ret = {'first': self.first}
        states = {}

        for state in self:
            states[state.id] = state.dumps()

        ret['states'] = states

        return json.dumps(ret, indent=4)

    def __len__(self):
        return self.size

    def __iter__(self):
        next = self.first
        while True:
            if next is None:
                break
            current_state = self.states[next]
            next = current_state.next
            yield current_state

class State:
    def __init__(self, id):
        self.id = id
        self.trans = []
        self.next = None

    def transition(self, transition):
        self.trans.append(transition)
    
    def generate_message(self):
        #TODO Generate message based in message transitions
        return self.trans[0].generate_message()

    def merge(self, state):
        raise NotImplementedError

    def contains(self, message):
        for trans in self.trans:
            if trans.equals(message):
                return True
        
        return False

    def is_end(self):
        return self.next is None

    def has_multiple_transition(self):
        return len(self.trans) > 1

    def dumps(self):
        ret = []

        for trans in self.trans:
            trans_dict = trans.dumps()
            trans_dict['next'] = self.next
            ret.append(trans_dict)

        return ret

class Message:
    def __init__(self, hexbytes):
        self.keyword = None
        self.hexbytes = hexbytes
        self.bytes = binascii.unhexlify(hexbytes)
        self.constraints = {}

    def equals(self, message):
        # TODO: keyword comparison?
        return self.bytes == message.bytes

    def generate_message(self):
        return self.bytes

    def constrain(self, where, byte):
        self.constraints[where] = byte

    def dumps(self):
        ret = {}

        ret['content'] = self.hexbytes
        ret['keyword'] = self.keyword
        ret['constraints'] = self.constraints

        return ret
