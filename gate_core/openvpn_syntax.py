"""Lossless, bounded OpenVPN lexical representation; no policy or file access.

Token rules follow OpenVPN 2.6 options.c:parse_line, not shell/shlex rules.
Comments start only BETWEEN parameters; quotes start only at a parameter boundary.
Backslash escapes double quote, backslash and whitespace except in single quotes.
Original lines (including CRLF, quotes/comments) and opaque inline bodies stay
private. Consumers must not log the document or arguments.
"""
import re
from typing import TypedDict


class Directive(TypedDict):
    line: int  # zero-based physical source line
    key: str
    args: list[str]
    context: int | None


class InlineBlock(TypedDict):
    kind: str
    start: int
    end: int
    context: int | None
    content: str


class ConnectionBlock(TypedDict):
    start: int
    end: int | None


class Document(TypedDict):
    lines: list[str]  # exact text, including original quotes/comments/newlines
    directives: list[Directive]
    blocks: list[InlineBlock]
    connections: list[ConnectionBlock]


class OpenVPNSyntaxError(ValueError):
    category = 'invalid_syntax'

    def __init__(self, line, reason):
        self.line = line
        super().__init__(f'OpenVPN line {line}: {reason}')


def tokens(line, number=1):
    """Decode a single option line, without interpreting any directive."""
    result=[];word=[];state='initial';escaped=False
    for char in line.rstrip('\r\n')+'\0':
        if not escaped and char=='\\' and state!='single':
            escaped=True;continue
        if escaped and char not in ('\\','"',' ','\t','\r','\n'):
            raise OpenVPNSyntaxError(number,'invalid backslash escape')
        if state=='initial':
            if char in ('#',';'):break
            if char in (' ','\t','\r','\n','\0'):
                escaped=False;continue
            if not escaped and char in ('"',"'"):
                state='double' if char=='"' else 'single'
            else:word.append(char);state='plain'
        elif state=='plain':
            if not escaped and char in (' ','\t','\r','\n','\0'):
                result.append(''.join(word));word=[];state='initial'
            else:word.append(char)
        elif not escaped and char==('"' if state=='double' else "'"):
            result.append(''.join(word));word=[];state='initial'
        elif char=='\0':
            raise OpenVPNSyntaxError(number,'malformed quoting')
        else:word.append(char)
        escaped=False
    if escaped or state!='initial':raise OpenVPNSyntaxError(number,'unfinished parameter')
    return result


def parse_document(content: str) -> Document:
    if not isinstance(content,str):raise OpenVPNSyntaxError(1,'configuration must be text')
    try:size=len(content.encode('utf-8'))
    except UnicodeError:raise OpenVPNSyntaxError(1,'invalid Unicode') from None
    if not content.strip() or size>512*1024:raise OpenVPNSyntaxError(1,'configuration empty or exceeds 512 KiB')
    if any(ord(c)<32 and c not in '\r\n\t' or 127<=ord(c)<=159 for c in content):raise OpenVPNSyntaxError(1,'control characters unsupported')
    lines=content.splitlines(keepends=True)
    if len(lines)>8192:raise OpenVPNSyntaxError(1,'exceeds 8192 lines')
    directives=[];blocks=[];connections=[];context=None;active=None;start=0
    for number,line in enumerate(lines):
        if len(line)>16384:raise OpenVPNSyntaxError(number+1,'line exceeds 16384 characters')
        text=line.strip()
        if active:
            closing='</'+active+'>'
            if text.startswith(closing):
                if tokens(text,number+1)!=[closing]:raise OpenVPNSyntaxError(number+1,'invalid inline closing tag')
                blocks.append({'kind':active,'start':start,'end':number,'context':context,'content':''.join(lines[start+1:number])});active=None
            continue
        parts=tokens(line,number+1)
        if not parts:continue
        if parts==['<connection>']:
            if context is not None:raise OpenVPNSyntaxError(number+1,'nested connection block')
            context=len(connections);connections.append({'start':number,'end':None});continue
        if parts==['</connection>']:
            if context is None:raise OpenVPNSyntaxError(number+1,'unmatched connection closing tag')
            connections[context]['end']=number;context=None;continue
        tag=re.fullmatch(r'<([A-Za-z0-9_-]+)>',parts[0])
        if tag and len(parts)==1:active=tag[1];start=number;continue
        if parts[0].startswith('</'):raise OpenVPNSyntaxError(number+1,'unmatched inline closing tag')
        directives.append({'line':number,'key':parts[0].removeprefix('--'),'args':parts[1:],'context':context})
    if active or context is not None:raise OpenVPNSyntaxError(start+1 if active else connections[-1]['start']+1,'unterminated inline/connection block')
    return {'lines':lines,'directives':directives,'blocks':blocks,'connections':connections}
