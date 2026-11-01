"""Value-level diagnostic redaction, shared by UI and exports."""
import re

def sanitize_diagnostic(text, known=()):
    """Diagnostic values only; words like 'password' are not themselves secrets.

    This is deliberately separate from the conservative general log exporter.
    Callers export a selected error line, never dump PPP options/CHAP tables.
    """
    text = str(text)
    values = [v for v in known if isinstance(v, str) and v]
    values += [v.replace('\\', '\\\\').replace('"', '\\"') for v in values]
    if values:
        # One substitution avoids matching a short secret inside our replacement.
        text = re.sub('|'.join(re.escape(v) for v in sorted(set(values), key=len, reverse=True)),
                      lambda match: '[REDACTED]', text)
    value = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|<[^>]*>|[^\s,;]+)'''
    labels = r'(?:username|user|name|password|passwd|passphrase|secret|chap[-_ ]secret|response|challenge|authorization|cookie|token|psk)'
    text = re.sub(r'(?i)(\b' + labels + r'\s*[:=]\s*)' + value,
                  lambda match: match[1] + '[REDACTED]', text)
    # PPP option-format credentials and debug CHAP payloads, if present in an error.
    text = re.sub(r'(?i)(\b(?:user|username|password|passwd|secret)\s+)(["\'])(?:\\.|(?!\2).)*?\2',
                  lambda match: match[1] + '[REDACTED]', text)
    text = re.sub(r'(?im)^(\s*(?:user|username|password|passwd|secret)\s+)\S.*$',
                  lambda match: match[1] + '[REDACTED]', text)
    text = re.sub(r'(?i)(\b(?:challenge|response)\b[^\n<>]*?)<[^>]*>',
                  lambda match: match[1] + '<REDACTED>', text)
    text = re.sub(r'(?i)(\bC=)[0-9a-f]{16,}', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(https?|socks5?)://[^\s/@]+:[^\s/@]+@', r'\1://[REDACTED]@', text)
    text = re.sub(r'(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/=._-]+', r'\1 [REDACTED]', text)
    return ' '.join(''.join(c for c in text if c.isprintable() or c.isspace()).split())

