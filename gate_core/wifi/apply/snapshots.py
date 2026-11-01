"""Snapshots contain synthetic profile metadata only; never read host files."""
from .persistence import CheckedRecords, fingerprint, interface_name
from .executor import OwnershipError
from ..models import profile_id, validate_saved


class SnapshotManager:
    def __init__(self, root):
        self.records = CheckedRecords(root, 'snapshots')

    def save(self, operation, interface, before):
        self._validate_before(before, interface)
        data = {'owner': 'pirate-mock-snapshot', 'mode': 'simulation', 'operation_id': profile_id(operation),
                'interface': interface_name(interface), 'before': before, 'before_digest': fingerprint(before)}
        self.records.write(operation, data, create=True)
        return operation

    def _validate_before(self, before, interface):
        if not isinstance(before, dict) or set(before) != {'owner', 'mode', 'interface', 'holder', 'profile'} or before['owner'] != 'pirate-mock-radio' or before['mode'] != 'simulation' or before['interface'] != interface:
            raise OwnershipError('Snapshot baseline ownership invalid')
        if before['holder'] is not None:
            profile_id(before['holder'])
        if before['profile'] is not None:
            validate_saved(before['profile'])

    def load(self, operation, interface):
        data = self.records.read(operation)
        if not isinstance(data, dict) or set(data) != {'owner','mode','operation_id','interface','before','before_digest'} or data['owner'] != 'pirate-mock-snapshot' or data['mode'] != 'simulation' or data['operation_id'] != operation or data['interface'] != interface:
            raise OwnershipError('Snapshot ownership invalid')
        self._validate_before(data['before'], interface)
        if fingerprint(data['before']) != data['before_digest']:
            raise OwnershipError('Snapshot baseline integrity invalid')
        return data
