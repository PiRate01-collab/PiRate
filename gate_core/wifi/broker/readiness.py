"""Explicit mock evidence. Unknown never approves mutation."""
from dataclasses import dataclass
from .contracts import BrokerError


@dataclass(frozen=True)
class ReadinessEvidence:
    profile_id: str
    resource_id: str
    hardware: bool | None = None
    resources: bool | None = None
    watchdog: bool | None = None
    snapshot: bool | None = None
    rollback: bool | None = None
    secrets: bool | None = None


class MockReadinessProvider:
    def __init__(self,evidence):
        if type(evidence) is not ReadinessEvidence:raise BrokerError('readiness_unknown')
        self.evidence=evidence

    def check(self,profile_id,resource_id):
        evidence=self.evidence
        if evidence.profile_id!=profile_id or evidence.resource_id!=resource_id or any(getattr(evidence,x) is not True for x in ('hardware','resources','watchdog','snapshot','rollback','secrets')):
            raise BrokerError('readiness_unknown')
        return evidence
