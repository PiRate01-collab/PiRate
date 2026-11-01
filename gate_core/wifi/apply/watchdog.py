"""Independent one-shot mock watchdog; no web-server dependency or radio commands."""
from .controller import ApplyController
from .executor import MockRadioExecutor
from .state import ApplyError


class ApplyWatchdog:
    def __init__(self, controller):
        self.controller = controller

    def tick(self, *, reboot=False):
        return self.controller.recover(reboot=reboot)


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description='PiRate mock-only Safe Apply recovery tick')
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--reboot', action='store_true', help='Recover all unconfirmed mock operations')
    args = parser.parse_args()
    try:
        controller = ApplyController(args.state_dir, MockRadioExecutor(args.state_dir))
        result = ApplyWatchdog(controller).tick(reboot=args.reboot)
    except (ApplyError, OSError, TimeoutError):
        result = {'state': 'recovery_required', 'diagnostics': ['storage_or_lock_unavailable'],
                  'mock_only': True, 'real_apply_available': False}
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get('state') == 'recovery_required' or any(x['state'] == 'recovery_required' for x in result.get('operations', [])) else 0


if __name__ == '__main__':
    raise SystemExit(main())
