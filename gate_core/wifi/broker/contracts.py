"""Authentication and action authorization are separate, fail-closed checks."""
from dataclasses import dataclass
from ..models import profile_id
from ..system.executor import RESOURCE

ACTIONS=frozenset(('apply','confirm','rollback','status'))
ERROR_CODES=frozenset(('invalid_policy','identity_denied','action_denied','invalid_request',
    'secret_denied','readiness_unknown','dry_run_only','invalid_grant','resource_denied',
    'recovery_required','transaction_denied','authorization_expired','state_denied',
    'message_too_large','identity_unavailable','timeout','disconnected','invalid_json',
    'invalid_transport','socket_ownership_unknown','socket_busy','not_listening','internal_error',
    'transaction_not_applied','busy'))


class BrokerError(ValueError):
    def __init__(self, code):
        code=code if type(code) is str and code in ERROR_CODES else 'internal_error'
        super().__init__(code)
        self.code=code


@dataclass(frozen=True)
class PeerIdentity:
    pid: int
    uid: int
    gid: int


class PeerPolicy:
    def __init__(self, permissions):
        self.permissions={}
        for subject, actions in permissions.items():
            if not isinstance(subject,tuple) or len(subject)!=2 or any(type(x) is not int or x<0 for x in subject) or not isinstance(actions,(set,frozenset)) or not actions<=ACTIONS:
                raise BrokerError('invalid_policy')
            self.permissions[subject]=frozenset(actions)

    def authenticate(self, peer):
        if type(peer) is not PeerIdentity or type(peer.uid) is not int or type(peer.gid) is not int or (peer.uid,peer.gid) not in self.permissions:
            raise BrokerError('identity_denied')

    def authorize(self, peer, action):
        self.authenticate(peer)
        if action not in self.permissions[(peer.uid,peer.gid)]:
            raise BrokerError('action_denied')


def request_schema(data):
    if not isinstance(data,dict) or set(data)!={'version','action','operation_id','resource_id'} or type(data['version']) is not int or data['version']!=1 or type(data['action']) is not str or data['action'] not in ACTIONS or data['resource_id']!=RESOURCE:
        raise BrokerError('invalid_request')
    try:profile_id(data['operation_id'])
    except ValueError:raise BrokerError('invalid_request') from None
    return data



def public_response(data):
    """Closed outbound schema: accidental private object fields never reach a peer."""
    from ..system.transaction import STATES,CODES
    if not isinstance(data,dict) or set(data)-{'ok','error','result','dry_run','real_execution_available'} or type(data.get('ok')) is not bool or data.get('dry_run') is not True or data.get('real_execution_available') is not False:
        raise BrokerError('internal_error')
    if 'error' in data and (type(data['error']) is not str or data['error'] not in ERROR_CODES):
        raise BrokerError('internal_error')
    if data['ok'] is False and 'error' not in data:
        raise BrokerError('internal_error')
    if 'result' not in data:
        if data['ok']:raise BrokerError('internal_error')
        return data
    result=data['result']
    if not isinstance(result,dict) or set(result)-{'operation_id','state','deadline','diagnostics','dry_run','real_execution_available'} or result.get('dry_run') is not True or result.get('real_execution_available') is not False or type(result.get('state')) is not str or result['state'] not in STATES|{'authorized'}:
        raise BrokerError('internal_error')
    try:profile_id(result.get('operation_id'))
    except ValueError:raise BrokerError('internal_error') from None
    if 'deadline' in result and (type(result['deadline']) is not int or not 0<=result['deadline']<=2**63-1):
        raise BrokerError('internal_error')
    if 'diagnostics' in result and (not isinstance(result['diagnostics'],list) or len(result['diagnostics'])>len(CODES) or any(type(x) is not str or x not in CODES for x in result['diagnostics'])):
        raise BrokerError('internal_error')
    return data
