"""Metadata-only connection plans and explicit lifecycle transitions."""
from dataclasses import dataclass, field
from enum import Enum
import uuid
from .core import ProfileStore


class ConnectionState(str, Enum):
    PLANNED = 'planned'
    PREPARING = 'preparing'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    STOPPING = 'stopping'
    STOPPED = 'stopped'
    FAILED = 'failed'
    CLEANUP_FAILED = 'cleanup_failed'
    RECOVERY_REQUIRED = 'recovery_required'


TRANSITIONS = {
    ConnectionState.PLANNED: {ConnectionState.PREPARING, ConnectionState.STOPPED},
    ConnectionState.PREPARING: {ConnectionState.CONNECTING, ConnectionState.FAILED, ConnectionState.STOPPING},
    ConnectionState.CONNECTING: {ConnectionState.CONNECTED, ConnectionState.FAILED, ConnectionState.STOPPING},
    ConnectionState.CONNECTED: {ConnectionState.FAILED, ConnectionState.STOPPING},
    ConnectionState.FAILED: {ConnectionState.STOPPING},
    ConnectionState.STOPPING: {ConnectionState.STOPPED, ConnectionState.CLEANUP_FAILED},
    ConnectionState.CLEANUP_FAILED: {ConnectionState.STOPPING},
    ConnectionState.STOPPED: set(),
    ConnectionState.RECOVERY_REQUIRED: {ConnectionState.STOPPING},
}

# Any unfinished lifecycle can require recovery; stopped remains terminal.
for _state in ConnectionState:
    if _state not in (ConnectionState.STOPPED, ConnectionState.RECOVERY_REQUIRED):
        TRANSITIONS[_state].add(ConnectionState.RECOVERY_REQUIRED)


@dataclass(frozen=True)
class ConnectionPlan:
    name: str
    backend: str
    server: str
    port: int | None
    dns_mode: str
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    execution_available: bool = field(default=False, init=False)

    @classmethod
    def from_profile(cls, payload):
        profile = ProfileStore.validate(payload)
        return cls(profile['name'], profile['type'], profile['server'], profile['port'], profile['dns_mode'])

    def __post_init__(self):
        ProfileStore.validate({'name': self.name, 'type': self.backend, 'server': self.server,
                              'port': self.port, 'dns_mode': self.dns_mode})
        uuid.UUID(self.plan_id)

    def as_dict(self):
        return {'plan_id': self.plan_id, 'name': self.name, 'type': self.backend,
                'server': self.server, 'port': self.port, 'dns_mode': self.dns_mode,
                'execution_available': False}


@dataclass
class ConnectionLifecycle:
    state: ConnectionState = field(default=ConnectionState.PLANNED, init=False)

    def transition(self, target):
        target = ConnectionState(target)
        if target == self.state == ConnectionState.STOPPED:
            return
        if target not in TRANSITIONS[self.state]:
            raise ValueError(f'Invalid transition: {self.state.value} -> {target.value}')
        self.state = target
