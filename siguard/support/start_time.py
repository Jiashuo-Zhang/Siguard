from time import time
from siguard.support.support_utils import Singleton


class StartTime(metaclass=Singleton):
    """Maintains the start time of the current contract in execution"""

    def __init__(self):
        self.global_start_time = time()
