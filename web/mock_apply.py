"""Explicit synthetic radio API adapter, isolated from live diagnostics/configuration."""
from pathlib import Path
from gate_core.process_lock import ProcessLock
from gate_core.wifi.apply import ApplyController, MockRadioExecutor
from gate_core.wifi.radio import RadioCapabilities, Channel
from gate_core.wifi.validation import MockSecretReferences

INTERFACE = 'mock-wlan0'
MOCK_CAPABILITIES = RadioCapabilities(
    interface=INTERFACE, hardware_mac='02:00:00:00:00:01', ap_mode=True,
    bssid_change=True, regulatory_domain='US',
    channels=(Channel('2.4',1,2412,(20,40)), Channel('2.4',6,2437,(20,40)),
              Channel('2.4',11,2462,(20,40)), Channel('5',36,5180,(20,40,80))),
    features=('wmm','ht','vht','he','isolate_clients','short_gi'),
    security=('wpa2','wpa3'), limitations=('Synthetic fixture only; no hardware guarantees',), source='mock')


def controller(root, store, *, initialize=False):
    executor = MockRadioExecutor(root)
    result = ApplyController(root, executor, store=store, capabilities=MOCK_CAPABILITIES,
                             # Availability is simulated; no credential storage is consulted.
                             secrets=MockSecretReferences(x['password_ref'] for x in store.list() if x['password_ref']) if initialize else None,
                             watchdog_ready=True)
    if not initialize:
        return result
    with ProcessLock(Path(root)/'bootstrap.lock', timeout=0):
        radio_path = executor.records.path(executor._key(INTERFACE))
        if not radio_path.exists() and not radio_path.is_symlink():
            # Never invent a new baseline when existing journals/snapshots need recovery.
            if not list(result.records.directory.iterdir()) and not list(result.snapshots.records.directory.iterdir()):
                executor.register(INTERFACE)
    return result
