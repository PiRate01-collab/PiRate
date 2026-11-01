"""Private synthetic reference registry; no caller-supplied credential persistence."""
from ..broker.secrets import SecretContext, SecretMaterial, validate_context
from ..broker.contracts import BrokerError
from ..system.storage import PrivateRecords, FoundationError, digest

class SyntheticReferenceStore:
    def __init__(self, root):self.records=PrivateRecords(root)

    @staticmethod
    def _record(reference, context):
        validate_context(reference,context)
        return {'owner':'pirate-synthetic-reference','mode':'synthetic-only','reference':reference,
                'uid':context.owner_uid,'profile_id':context.profile_id,
                'scope':context.scope,'purpose':context.purpose.value}

    @staticmethod
    def _id(data):
        # Canonical UUID-shaped ID from scoped metadata. Contents are revalidated on read.
        import uuid
        return str(uuid.UUID(digest(data)[:32]))

    def register(self, reference, context):
        record=self._record(reference,context);identifier=self._id(record)
        try:
            with self.records.lock():
                if self.records.exists(identifier):
                    if self.records.read(identifier)!=record:raise BrokerError('secret_denied')
                else:self.records.write(identifier,record,create=True)
        except (FoundationError,OSError,TimeoutError):raise BrokerError('secret_denied') from None

    def available(self, reference, context):
        record=self._record(reference,context)
        try:
            with self.records.lock():
                if self.records.read(self._id(record))!=record:raise BrokerError('secret_denied')
            return True
        except (FoundationError,OSError,TimeoutError):raise BrokerError('secret_denied') from None

    def resolve(self, reference, context):
        self.available(reference,context)
        return SecretMaterial(context.purpose,'SYNTHETIC_ONLY_'+context.purpose.value+'_NOT_FOR_DEPLOYMENT')
