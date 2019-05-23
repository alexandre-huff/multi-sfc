from utils import OPTIONS


class MultiSFCException(Exception):
    pass


class NFVOAgentsException(MultiSFCException):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason


class NFVOAgentOptions(NFVOAgentsException):
    def __init__(self, reason, cp_list):
        super().__init__(OPTIONS, reason)
        self.cp_list = cp_list


class DatabaseException(MultiSFCException):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason
