"""In-memory ownership journal; recording never creates or deletes resources.

Durable crash recovery and an actual cleanup executor are future work.
"""
from dataclasses import dataclass, replace
from enum import Enum


class ResourceKind(str, Enum):
    NAMESPACE = 'namespace'
    LINK = 'link'
    NFT_TABLE = 'nft_table'
    PROCESS = 'process'
    TEMP_FILE = 'temp_file'


@dataclass(frozen=True)
class ResourceRecord:
    kind: ResourceKind
    name: str
    released: bool = False
    cleanup_failed: bool = False


class ResourceJournal:
    def __init__(self, owner_id):
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError('Owner ID required')
        self.owner_id = owner_id
        self._records = []

    @property
    def records(self):
        return tuple(self._records)

    def acquire(self, kind, name):
        kind = ResourceKind(kind)
        if not isinstance(name, str) or not name or '\x00' in name:
            raise ValueError('Resource name required')
        if any(r.kind == kind and r.name == name for r in self._records):
            raise ValueError('Resource already recorded')
        record = ResourceRecord(kind, name)
        self._records.append(record)
        return record

    def mark_cleanup(self, owner_id, kind, name, *, succeeded):
        if owner_id != self.owner_id:
            raise ValueError('Resource owner mismatch')
        kind = ResourceKind(kind)
        if not isinstance(succeeded, bool):
            raise ValueError('Expected boolean cleanup result')
        for i, record in enumerate(self._records):
            if (record.kind, record.name) == (kind, name):
                if record.released:
                    return
                self._records[i] = replace(record, released=succeeded, cleanup_failed=not succeeded)
                return
        raise ValueError('Unowned resource')

    def pending_cleanup(self):
        return tuple(r for r in reversed(self._records) if not r.released)

    def as_dict(self):
        return {'owner_id': self.owner_id, 'resources': [
            {'kind': r.kind.value, 'name': r.name, 'released': r.released,
             'cleanup_failed': r.cleanup_failed} for r in self._records]}
