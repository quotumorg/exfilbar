"""Offline source-contract checks, not a full Hermes installation validator."""
import ast
import json
from pathlib import Path
import re
import sys
import unittest
from urllib.parse import urlsplit
from support import Context, ROOT, entry
from test_integration import source_root


def mapping_fixture(path):
    # This bundle uses only nested mappings and JSON-compatible inline scalars.
    # Reject other YAML syntax instead of pretending to provide a YAML parser.
    result = {}
    stack = [(-2, result)]
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        indent = len(line) - len(line.lstrip())
        key, sep, raw = line.strip().partition(':')
        if not sep or not re.fullmatch(r'[a-z_]+', key):
            raise ValueError('unsupported fixture YAML')
        while indent <= stack[-1][0]:
            stack.pop()
        raw = raw.strip()
        if not raw:
            value = {}
        else:
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                if not re.fullmatch(r'[a-zA-Z0-9_.-]+', raw):
                    raise ValueError('unsupported fixture scalar')
                value = raw
        stack[-1][1][key] = value
        if not raw:
            stack.append((indent, value))
    return result


def definitions(path, names, namespace):
    nodes = [n for n in ast.parse(path.read_text()).body
             if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    if len(nodes) != len(names):
        raise AssertionError('source contract changed')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)


class CatalogTests(unittest.TestCase):
    def test_manifest_source_contract(self):
        root = source_root()
        source = ast.parse((root / 'hermes_cli/plugins_manifest.py').read_text())
        constants = {}
        for node in source.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in {
                    '_KNOWN_MANIFEST_FIELDS', '_CONFIG_SCHEMA_TYPES'}:
                if node.target.id == '_KNOWN_MANIFEST_FIELDS':
                    constants[node.target.id] = ast.literal_eval(node.value)
                else:
                    constants[node.target.id] = [ast.literal_eval(k) for k in node.value.keys]
        data = mapping_fixture(ROOT / 'plugin.yaml')
        self.assertFalse(set(data) - constants['_KNOWN_MANIFEST_FIELDS'])
        namespace = {'ValidationReport': object, '_CONFIG_TYPES': constants['_CONFIG_SCHEMA_TYPES'],
                     '_UPPER_SNAKE_RE': re.compile(r'^[A-Z][A-Z0-9_]*$')}
        names = {'_check_manifest_fields', '_check_config_spec', '_check_requires_env'}
        definitions(root / 'hermes_cli/plugin_validate.py', names, namespace)
        class Report:
            def add(self, name, ok, detail):
                if not ok:
                    raise AssertionError(detail)
        for name in names:
            namespace[name](Report(), data)
        self.assertRegex(data['name'], r'^[a-z0-9_-]{1,64}$')
        ctx = Context()
        entry().register(ctx)
        self.assertEqual(data['provides_hooks'], list(ctx.hooks))
        self.assertEqual(data['provides_tools'], [])
        self.assertEqual(data['python_dependencies'], [])
        self.assertEqual(set(data['config_schema']), set(__import__('inspect').signature(
            __import__('exfilbar.policy', fromlist=['Policy']).Policy).parameters) | {'integrity_hmac'})

    def test_catalog_source_contract_and_placeholders(self):
        path = source_root() / 'scripts/validate_plugin_catalog.py'
        tree = ast.parse(path.read_text())
        # Execute only constants and pure schema functions from genuine source.
        names = {'validate_entry', '_is_allowed_image_url', '_is_nonempty_str', '_repo_host',
                 '_check_page_fields', '_check_requires_hermes', '_check_attested_binaries'}
        nodes = [n for n in tree.body if isinstance(n, ast.Assign) or
                 isinstance(n, ast.FunctionDef) and n.name in names]
        namespace = {'re': re, 'urlsplit': urlsplit}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
        data = mapping_fixture(ROOT / 'catalog/exfilbar.yaml')
        errors, warnings = namespace['validate_entry'](data)
        self.assertEqual(len(errors), 1)
        self.assertIn('sha', errors[0])
        self.assertEqual(warnings, [])
        self.assertEqual(data['repo'], 'https://github.com/quotumorg/exfilbar')
        self.assertEqual(data['maintainer'], 'quotumorg')
        # Shape only: this is a test pin, never a claimed publication commit.
        data['sha'] = 'a' * 40
        self.assertEqual(namespace['validate_entry'](data), ([], []))
        manifest = mapping_fixture(ROOT / 'plugin.yaml')
        for key in ('name', 'version', 'requires_hermes'):
            self.assertEqual(data[key], manifest[key])
        for key in ('provides_hooks', 'provides_tools', 'requires_env'):
            self.assertEqual(data['capabilities'][key], manifest[key])
        self.assertFalse((source_root() / 'plugin-catalog/exfilbar.yaml').exists())

    def test_publication_imports_use_only_documented_hermes_api(self):
        # Hermes API used by this plugin: plugin_data_dir only (index.md:1161).
        # Context arrives via register(ctx); no core context import is needed.
        public_api = {'plugins.plugin_storage': {'plugin_data_dir'}}
        local = {'exfilbar', '_exfilbar_dashboard_lib'}
        dependencies = {'fastapi': {'APIRouter', 'HTTPException'}}
        seen = set()
        for path in ROOT.rglob('*.py'):
            if 'tests' in path.relative_to(ROOT).parts:
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertIn(alias.name.split('.')[0], sys.stdlib_module_names | local,
                                      f'{path}:{node.lineno}: {alias.name}')
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    root = node.module.split('.')[0]
                    if root in sys.stdlib_module_names | local:
                        continue
                    allowed = {**public_api, **dependencies}
                    self.assertIn(node.module, allowed, f'{path}:{node.lineno}')
                    self.assertLessEqual({alias.name for alias in node.names}, allowed[node.module])
                    if node.module in public_api:
                        seen.update((node.module, alias.name) for alias in node.names)
        self.assertEqual(seen, {('plugins.plugin_storage', 'plugin_data_dir')})

    def test_runtime_imports_and_docs(self):
        runtime = [ROOT / '__init__.py', *sorted((ROOT / 'exfilbar').glob('*.py'))]
        allowed = {'ast', 'collections', 'dataclasses', 'fnmatch', 'json', 'pathlib',
                   'posixpath', 're', 'shlex', 'threading', 'urllib', 'contextlib', 'datetime',
                   'hashlib', 'sqlite3', 'tempfile', 'weakref', 'contextvars', 'time',
                   'argparse', 'hmac', 'os', 'secrets'}
        for path in runtime:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(x.name.split('.')[0] in allowed for x in node.names))
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    if node.module == 'plugins.plugin_storage':
                        # Documented in website/docs/developer-guide/plugins/index.md:1161.
                        self.assertEqual([x.name for x in node.names], ['plugin_data_dir'])
                    else:
                        self.assertIn(node.module.split('.')[0], allowed)
        readme = (ROOT / 'README.md').read_text()
        for phrase in ('What you see', 'Install', 'not a sandbox', 'plugins.entries.exfilbar.settings'):
            self.assertIn(phrase, readme[:3000])
        self.assertTrue((ROOT / 'CATALOG.md').is_file())
        version = mapping_fixture(ROOT / 'plugin.yaml')['version']
        self.assertEqual(version, '0.5.5')
        self.assertEqual(json.loads((ROOT / 'dashboard/manifest.json').read_text())['version'], version)
        self.assertTrue(readme.startswith('# exfilbar\n\nVersion ' + version + ' '))
        self.assertIn('MIT', (ROOT / 'LICENSE').read_text())
