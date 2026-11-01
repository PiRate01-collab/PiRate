from enum import Enum


class ApplyError(ValueError):
    pass


class ApplyState(str, Enum):
    IDLE = 'idle'
    VALIDATING = 'validating'
    SNAPSHOTTING = 'snapshotting'
    APPLYING = 'applying'
    AWAITING_CONFIRMATION = 'awaiting_confirmation'
    CONFIRMED = 'confirmed'
    ROLLING_BACK = 'rolling_back'
    ROLLED_BACK = 'rolled_back'
    FAILED = 'failed'
    RECOVERY_REQUIRED = 'recovery_required'


TRANSITIONS = {
    'idle': {'validating', 'failed'},
    'validating': {'snapshotting', 'failed'},
    'snapshotting': {'applying', 'failed'},
    'applying': {'awaiting_confirmation', 'rolling_back'},
    'awaiting_confirmation': {'confirmed', 'rolling_back'},
    'rolling_back': {'rolled_back'},
    'failed': {'rolled_back'},  # Only after confirming no mock changes occurred.
    'recovery_required': {'rolling_back'},
    'confirmed': set(),
    'rolled_back': set(),
}
for state in ApplyState:
    if state.value not in ('confirmed', 'rolled_back', 'recovery_required'):
        TRANSITIONS[state.value].add('recovery_required')
TERMINAL = ('confirmed', 'rolled_back')


def transition(source, target):
    source, target = ApplyState(source).value, ApplyState(target).value
    if source == target and source in TERMINAL:
        return source
    if target not in TRANSITIONS[source]:
        raise ApplyError('Invalid Safe Apply state transition')
    return target
