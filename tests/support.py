import importlib.util
import atexit
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
ROOT = Path(__file__).resolve().parents[1]

def entry():
    name = 'plugin_fixture'
    spec = importlib.util.spec_from_file_location(name, ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    # Durable runtime storage is isolated from real Hermes profiles in tests.
    directory = TemporaryDirectory(prefix='exfilbar-test-')
    atexit.register(directory.cleanup)
    ledger_type = module.Ledger
    module.Ledger = lambda: ledger_type(directory.name)
    module._test_directory = directory
    return module

class Context:
    def __init__(self, **settings):
        self.settings, self.hooks, self.commands = settings, {}, {}
    def get_config(self, key, default):
        return self.settings.get(key, default)
    def register_hook(self, name, callback):
        self.hooks[name] = callback
    def register_command(self, name, callback, **kwargs):
        self.commands[name] = callback


def admission_clock(ledger_type, now=None):
    """Inject only the ledger deadline clock; elapsed measurements stay real."""
    from unittest.mock import patch
    now = [10.0] if now is None else now
    return patch.object(sys.modules[ledger_type.__module__], 'monotonic', lambda: now[0])
