"""Durable mock radio world. No subprocess, system configuration or secrets."""
import copy
import uuid
from ..models import profile_id, validate_saved
from .persistence import CheckedRecords, fingerprint, interface_name
from .state import ApplyError


class OwnershipError(ApplyError):
    pass


class MockRadioExecutor:
    def __init__(self, root, faults=None):
        self.records = CheckedRecords(root, 'radio')
        self.faults = faults or {}
        self.calls = []
        self.rollback_available = True

    def _key(self, interface):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, 'pirate-mock-radio:' + interface_name(interface)))

    def register(self, interface, profile=None):
        """Explicitly seed a synthetic world; recovery never calls this method."""
        if profile is not None:
            validate_saved(profile)
        data = {'owner': 'pirate-mock-radio', 'mode': 'simulation', 'interface': interface_name(interface),
                'holder': None, 'profile': profile}
        self.records.write(self._key(interface), data, create=True)

    def inspect(self, interface):
        data = self.records.read(self._key(interface))
        if not isinstance(data, dict) or set(data) != {'owner', 'mode', 'interface', 'holder', 'profile'}:
            raise OwnershipError('Mock radio ownership unknown')
        if data['owner'] != 'pirate-mock-radio' or data['mode'] != 'simulation' or data['interface'] != interface:
            raise OwnershipError('Mock radio ownership not verified')
        if data['holder'] is not None:
            profile_id(data['holder'])
        if data['profile'] is not None:
            validate_saved(data['profile'])
        return copy.deepcopy(data)

    def _fault(self, action, operation):
        self.calls.append((action, operation))
        values = self.faults.get(action, [])
        outcome = values.pop(0) if values else True
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def apply(self, interface, operation, profile, before_digest):
        profile_id(operation)
        validate_saved(profile)
        data = self.inspect(interface)
        if fingerprint(data) != before_digest:
            raise OwnershipError('Mock baseline changed')
        outcome = self._fault('apply', operation)
        if outcome is False:
            return False
        data['holder'], data['profile'] = operation, copy.deepcopy(profile)
        self.records.write(self._key(interface), data)
        if outcome == 'partial':
            raise ApplyError('Simulated partial apply failure')
        return True

    def verify(self, interface, operation, digest):
        profile_id(operation)
        data = self.inspect(interface)
        return (data['holder'] == operation and fingerprint(data['profile']) == digest
                and self._fault('verify', operation) is True)

    def restore(self, interface, operation, before):
        profile_id(operation)
        if not isinstance(before, dict) or set(before) != {'owner', 'mode', 'interface', 'holder', 'profile'} or before['owner'] != 'pirate-mock-radio' or before['mode'] != 'simulation' or before['interface'] != interface_name(interface):
            raise OwnershipError('Rollback baseline ownership unknown')
        if before['holder'] is not None:
            profile_id(before['holder'])
        if before['profile'] is not None:
            validate_saved(before['profile'])
        data = self.inspect(interface)
        # Initial baseline may remain unchanged if apply failed before any mutation.
        if data['holder'] != operation and fingerprint(data) != fingerprint(before):
            raise OwnershipError('Mock radio belongs to another operation')
        outcome = self._fault('restore', operation)
        if outcome is False:
            return False
        data['holder'], data['profile'] = operation, copy.deepcopy(before['profile'])
        self.records.write(self._key(interface), data)
        if outcome == 'partial':
            raise ApplyError('Simulated partial rollback failure')
        return True
