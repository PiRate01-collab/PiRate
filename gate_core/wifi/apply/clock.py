import time


class SystemClock:
    def now(self):
        return int(time.time())


class MockClock:
    def __init__(self, now=1700000000):
        self.value = now

    def now(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds
