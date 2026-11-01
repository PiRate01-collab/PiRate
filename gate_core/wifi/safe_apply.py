"""Future real Safe Apply protocol; mock orchestration lives in wifi.apply."""
from dataclasses import dataclass, field
from .models import profile_id, WiFiError
from typing import Protocol


@dataclass(frozen=True)
class ApplyPlan:
    profile_id: str
    snapshot_ref: str  # Private reference; never raw hostapd text or secrets in API.
    confirmation_timeout: int
    preserve_admin_access: bool = True
    rollback_on_timeout: bool = True
    recover_after_reboot: bool = True
    execution_available: bool = field(default=False, init=False)

    def __post_init__(self):
        profile_id(self.profile_id)
        if not isinstance(self.snapshot_ref, str) or not self.snapshot_ref.startswith('snapshot:'):
            raise WiFiError('Private snapshot reference required')
        profile_id(self.snapshot_ref.removeprefix('snapshot:'))
        if type(self.confirmation_timeout) is not int or not 15 <= self.confirmation_timeout <= 300:
            raise WiFiError('Confirmation timeout must be 15–300 seconds')
        if self.preserve_admin_access is not True or self.rollback_on_timeout is not True or self.recover_after_reboot is not True:
            raise WiFiError('Admin access, rollback and reboot recovery required')


class SafeApply(Protocol):
    def snapshot(self) -> str: ...
    def preflight(self, profile_id: str, snapshot_ref: str) -> ApplyPlan: ...
    def stage(self, plan: ApplyPlan) -> str: ...
    def confirm(self, operation_id: str) -> None: ...
    def rollback(self, operation_id: str) -> None: ...
    def recover(self) -> None: ...
