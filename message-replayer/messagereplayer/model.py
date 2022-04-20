import shlex

class Model:
    def __init__(self):
        self.states = []

    def update(self, message):
        self.states.append(message)

    def load(self, string):
        lines = string.splitlines()

        for line in lines:
            splitted = shlex.split(line)
            for (key, value) in [item.split('=') for item in splitted]:
                if key == 'content':
                    message = Message(value)
                elif key == 'format':
                    (where, byte) = value.split(',')
                    message.constrain(where, byte)
            self.states.append(message)

    def dump(self):
        if not self.states:
            return ''

        ret = f'state=0 {self.states[0].dump()}\n'

        for (i, state) in enumerate(self.states[1:]):
            ret += f'state={i+1} below={i} {state.dump()}\n'

        return ret

    def __len__(self):
        return len(self.states)

    def __iter__(self):
        for state in self.states:
            yield state

class Message:
    def __init__(self, bytes):
        self.bytes = bytes
        self.constraints = {}

    def constrain(self, where, byte):
        self.constraints[where] = byte

    def dump(self):
        ret = f'content={self.bytes}'

        for constraint in self.constraints.keys():
            ret += f' format=({constraint},{self.constraints[constraint]})'

        return ret
