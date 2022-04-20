class Model:
    def __init__(self):
        self.states = []

    def update(self, message):
        self.states.append(message)

    def dump(self):
        if not self.states:
            return ''

        ret = f'state=0 {self.states[0].dump()}\n'

        for (i, state) in enumerate(self.states[1:]):
            ret += f'state={i+1} below={i} {state.dump()}\n'

        return ret

class Message:
    def __init__(self, bytes):
        self.bytes = bytes
        self.constraints = {}

    def constrain(self, where, byte):
        self.constraints[where] = byte

    def dump(self):
        ret = f'content={self.bytes}'

        for constraint in self.constraints.keys():
            ret += f' format={constraint},{self.constraints[constraint]}'

        return ret
