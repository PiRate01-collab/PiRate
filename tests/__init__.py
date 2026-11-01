"""Default discovery deliberately includes unit tests only."""
from pathlib import Path

def load_tests(loader, tests, pattern):
    return loader.discover(str(Path(__file__).parent / 'unit'), pattern=pattern or 'test*.py')
