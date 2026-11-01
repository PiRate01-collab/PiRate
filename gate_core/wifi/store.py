"""Separate Wi-Fi database: atomic writes, flock, strict reads, no migration."""
import json
import os
from pathlib import Path
import stat
import uuid
from ..journal import private_directory, atomic_json, JournalError
from ..process_lock import ProcessLock
from .models import WiFiError, validate_profile, validate_saved, saved_profile, profile_id, FIELDS


class WiFiStoreError(WiFiError):
    pass


class WiFiProfileStore:
    def __init__(self, path):
        self.path = Path(path).expanduser()

    def _directory(self):
        try:
            return private_directory(self.path.parent)
        except (JournalError, OSError):
            raise WiFiStoreError('Wi-Fi database directory unsafe or unavailable') from None

    def _read(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return []
        except OSError:
            raise WiFiStoreError('Wi-Fi database unavailable') from None
        try:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise WiFiStoreError('Wi-Fi database permissions unsafe')
                raw = stream.read(262145)
            if len(raw) > 262144:
                raise WiFiStoreError('Wi-Fi database too large')
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise WiFiStoreError('Duplicate Wi-Fi database field')
                    result[key] = value
                return result
            envelope = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(envelope, dict) or set(envelope) != {'schema', 'profiles'} or type(envelope['schema']) is not int or envelope['schema'] != 1:
                raise WiFiStoreError('Invalid Wi-Fi database schema')
            entries = envelope['profiles']
            if not isinstance(entries, list) or len(entries) > 100:
                raise WiFiStoreError('Invalid Wi-Fi profile count')
            entries = [validate_saved(x) for x in entries]
            if len({x['id'] for x in entries}) != len(entries):
                raise WiFiStoreError('Duplicate Wi-Fi profile ID')
            return entries
        except (ValueError, TypeError, OSError, RecursionError):
            raise WiFiStoreError('Wi-Fi database invalid; preserved without repair') from None

    def list(self):
        # Missing data is read-only: never create a directory just by opening the UI.
        if not self.path.parent.exists():
            return []
        directory = self._directory()
        with ProcessLock(directory / 'wifi.lock', timeout=2):
            return self._read()

    def _save(self, entries):
        # Validate the complete proposed database before replacing any existing bytes.
        entries = [validate_saved(entry) for entry in entries]
        if len({entry['id'] for entry in entries}) != len(entries):
            raise WiFiStoreError('Duplicate Wi-Fi profile ID')
        try:
            if self.path.is_symlink():
                raise WiFiStoreError('Wi-Fi database symlink forbidden')
            atomic_json(self.path, {'schema': 1, 'profiles': entries})
        except (JournalError, OSError):
            raise WiFiStoreError('Wi-Fi database write failed; reload required') from None

    def create(self, payload):
        values = validate_profile(payload)
        with ProcessLock(self._directory() / 'wifi.lock', timeout=2):
            entries = self._read()
            if len(entries) >= 100:
                raise WiFiError('Maximum 100 Wi-Fi profiles')
            identifier = str(uuid.uuid4())
            if any(entry['id'] == identifier for entry in entries):
                raise WiFiStoreError('Wi-Fi profile ID collision')
            record = saved_profile(values, identifier)
            entries.append(record)
            self._save(entries)
            return record

    def update(self, identifier, payload):
        profile_id(identifier)
        values = validate_profile(payload)
        with ProcessLock(self._directory() / 'wifi.lock', timeout=2):
            entries = self._read()
            for index, old in enumerate(entries):
                if old['id'] == identifier:
                    record = saved_profile(values, identifier)
                    entries[index] = record
                    self._save(entries)
                    return record
            return None

    def duplicate(self, identifier):
        profile_id(identifier)
        with ProcessLock(self._directory() / 'wifi.lock', timeout=2):
            entries = self._read()
            old = next((x for x in entries if x['id'] == identifier), None)
            if old is None:
                return None
            if len(entries) >= 100:
                raise WiFiError('Maximum 100 Wi-Fi profiles')
            payload = {key: old[key] for key in FIELDS}
            payload['name'] = old['name'][:72] + ' (copy)'
            identifier = str(uuid.uuid4())
            if any(entry['id'] == identifier for entry in entries):
                raise WiFiStoreError('Wi-Fi profile ID collision')
            record = saved_profile(payload, identifier)
            entries.append(record); self._save(entries)
            return record

    def delete(self, identifier):
        profile_id(identifier)
        with ProcessLock(self._directory() / 'wifi.lock', timeout=2):
            entries = self._read()
            after = [x for x in entries if x['id'] != identifier]
            if len(after) == len(entries):
                return False
            self._save(after)
            return True
