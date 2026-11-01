"""Private saved AP settings only; activation belongs to existing Safe Apply."""
import uuid
from pathlib import Path
from gate_core.core import ProfileError
from gate_core.journal import private_directory
from gate_core.process_lock import ProcessLock
from .admin import atomic_json
from .management import private_json
from .ap import normalize

FIELDS = {'interface', 'ssid', 'password', 'security', 'country', 'channel', 'band',
          'width', 'mac_mode', 'mac_address', 'fingerprint'}


class APProfiles:
    def __init__(self, path):
        self.path = Path(path)

    @staticmethod
    def values(data, previous=None):
        if not isinstance(data, dict) or set(data) != {'name', 'wifi'}:
            raise ProfileError('Укажите название и настройки Wi-Fi.')
        name = data['name']
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(ord(c) < 32 for c in name):
            raise ProfileError('Название профиля должно содержать от 1 до 80 символов.')
        wifi = data['wifi']
        if not isinstance(wifi, dict) or set(wifi) - FIELDS:
            raise ProfileError('Неизвестные настройки Wi-Fi.')
        # New profiles use the controller's actual automatic-selection sentinels.
        # Partial edits inherit this saved profile, never unrelated live settings.
        wifi = {**(previous['wifi'] if previous else {'band': 'auto', 'channel': 0, 'width': 'auto'}), **wifi}
        # The only password fallback is this profile, never a different live AP.
        value = normalize(wifi, previous['wifi'] if previous else None)
        return {'name': name.strip(), 'wifi': {k: value[k] for k in FIELDS}}

    @staticmethod
    def public(record):
        return {'id': record['id'], 'name': record['name'],
                'wifi': {k: v for k, v in record['wifi'].items() if k != 'password'},
                'password_saved': bool(record['wifi']['password'])}

    def _read(self):
        if not self.path.exists():
            return []
        entries = private_json(self.path)
        if not isinstance(entries, list) or len(entries) > 100:
            raise ProfileError('Хранилище профилей Wi-Fi повреждено.')
        ids = set()
        for record in entries:
            if not isinstance(record, dict) or set(record) != {'id', 'name', 'wifi'}:
                raise ProfileError('Неверный формат профиля Wi-Fi.')
            identifier = str(uuid.UUID(record['id']))
            if identifier != record['id'] or identifier in ids:
                raise ProfileError('Неверный идентификатор профиля Wi-Fi.')
            ids.add(identifier)
            self.values({'name': record['name'], 'wifi': record['wifi']})
        return entries

    def _lock(self):
        return ProcessLock(private_directory(self.path.parent) / 'ap-profiles.lock', timeout=2)

    def list(self):
        if not self.path.exists():
            return []
        with self._lock():
            return [self.public(x) for x in self._read()]

    def get(self, identifier):
        with self._lock():
            for record in self._read():
                if record['id'] == identifier:
                    return record
        raise ProfileError('Профиль Wi-Fi не найден.')

    def create(self, data):
        value = self.values(data)
        with self._lock():
            entries = self._read()
            if len(entries) >= 100:
                raise ProfileError('Можно сохранить не более 100 профилей Wi-Fi.')
            value['id'] = str(uuid.uuid4())
            atomic_json(self.path, entries + [value])
            return self.public(value)

    def update(self, identifier, data):
        with self._lock():
            entries = self._read()
            for index, old in enumerate(entries):
                if old['id'] == identifier:
                    entries[index] = dict(self.values(data, old), id=identifier)
                    atomic_json(self.path, entries)
                    return self.public(entries[index])
        raise ProfileError('Профиль Wi-Fi не найден.')

    def duplicate(self, identifier):
        source = self.get(identifier)
        return self.create({'name': source['name'][:70] + ' (копия)', 'wifi': source['wifi']})

    def delete(self, identifier):
        with self._lock():
            entries = self._read()
            remaining = [x for x in entries if x['id'] != identifier]
            if len(entries) == len(remaining):
                raise ProfileError('Профиль Wi-Fi не найден.')
            atomic_json(self.path, remaining)
            return {'deleted': True}


def store(app):
    if not hasattr(app, 'ap_profiles'):
        app.ap_profiles = APProfiles(app.profiles.path.parent / 'ap-profiles.json')
    return app.ap_profiles


def selection(app):
    """Snapshot identity travels with existing AP rollback/confirmed records."""
    ap = app.ap
    active = (ap.active or {}).get('saved_profile_id')
    previous = (ap.previous or {}).get('saved_profile_id')
    confirmed = (ap.saved or {}).get('saved_profile_id')
    return {'active_present': bool(ap.active), 'active_id': active, 'previous_id': previous, 'confirmed_id': confirmed,
            'protected_ids': list(dict.fromkeys(x for x in (active, previous, confirmed) if x)),
            'pending': bool(app.pending)}
