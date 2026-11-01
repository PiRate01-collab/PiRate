"""System executor contract. No real executor is provided; connection operations are simulation-only."""
from dataclasses import dataclass
from typing import Protocol, Sequence


class ResourceOwnershipError(ValueError):
    """Ownership cannot be verified; cleanup must require recovery."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int = 0
    stdout: str = ''
    stderr: str = ''


@dataclass(frozen=True)
class ProcessHandle:
    token: str


class SystemExecutor(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float = 10) -> CommandResult: ...
    def start(self, argv: Sequence[str]) -> ProcessHandle: ...
    def wait(self, process: ProcessHandle, *, timeout: float = 10) -> CommandResult: ...
    def stop(self, process: ProcessHandle, *, timeout: float = 10) -> CommandResult: ...
    def resource(self, action: str, owner: str, kind: str) -> CommandResult | str | None: ...


class MockExecutor:
    """Records calls and returns queued outcomes; never invokes the operating system."""
    def __init__(self, outcomes=()):
        self.calls = []
        self.outcomes = list(outcomes)
        self.processes = {}

    def _record(self, action, value, timeout=None):
        if timeout is not None and timeout <= 0:
            raise ValueError('Timeout must be positive')
        if action in ('run', 'start'):
            if isinstance(value, (str, bytes)) or not value or any(not isinstance(x, str) or not x or '\x00' in x for x in value):
                raise ValueError('Expected non-empty argv sequence')
            value = tuple(value)
        self.calls.append((action, value, timeout))
        outcome = self.outcomes.pop(0) if self.outcomes else CommandResult()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def run(self, argv, *, timeout=10):
        return self._record('run', argv, timeout)

    def start(self, argv):
        self._record('start', argv)
        handle = ProcessHandle(f'mock-{len(self.processes) + 1}')
        self.processes[handle] = True
        return handle

    def _known(self, process):
        if process not in self.processes:
            raise ValueError('Unknown process handle')

    def wait(self, process, *, timeout=10):
        self._known(process)
        result = self._record('wait', process, timeout)
        self.processes[process] = False
        return result

    def stop(self, process, *, timeout=10):
        self._known(process)
        result = self._record('stop', process, timeout)
        self.processes[process] = False
        return result

    def resource(self, action, owner, kind):
        """Typed simulation only; never reconstruct commands from journal data.

        inspect returns None ONLY for confirmed absence in the mock world,
        or a non-empty owner ID. Unknown ownership raises ResourceOwnershipError.
        cleanup rechecks ownership immediately before its simulated mutation.
        """
        from .journal import resource_name
        name = resource_name(owner, kind)
        if action not in ('create', 'inspect', 'cleanup'):
            raise ValueError('Unknown simulation action')
        if not hasattr(self, 'resources'):
            self.resources = {}
        key = (kind, name)
        if action == 'inspect':
            if key not in self.resources:
                return None  # Confirmed absence, never an inspection failure.
            observed = self.resources[key]
            if not isinstance(observed, str) or not observed:
                raise ResourceOwnershipError('Resource ownership unknown')
            return observed
        if action == 'cleanup' and key in self.resources and self.resources[key] != owner:
            raise ResourceOwnershipError('Resource ownership not verified')
        result = self._record(action, (owner, kind, name), 10)
        if result.returncode == 0:
            if action == 'create':
                if key in self.resources:
                    raise ValueError('Resource collision')
                self.resources[key] = owner
            else:
                if key in self.resources and self.resources[key] != owner:
                    raise ResourceOwnershipError('Resource ownership not verified')
                self.resources.pop(key, None)
        return result
