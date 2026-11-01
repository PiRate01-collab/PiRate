"""gate-native core: metadata, diagnostics and future engine contracts."""
from pathlib import Path

VERSION = (Path(__file__).resolve().parent.parent / 'VERSION').read_text().strip()
__version__ = VERSION
