"""Wi-Fi Safe Apply 0.2.13a: persistent mock simulation, never real radio apply."""
from .controller import ApplyController
from .executor import MockRadioExecutor
from .state import ApplyError, ApplyState

__all__ = ['ApplyController', 'MockRadioExecutor', 'ApplyWatchdog', 'ApplyError', 'ApplyState']


def __getattr__(name):
    if name == 'ApplyWatchdog':
        from .watchdog import ApplyWatchdog
        return ApplyWatchdog
    raise AttributeError(name)
