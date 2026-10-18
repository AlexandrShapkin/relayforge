import unittest
from relayforge.policy import Grant, Policy, confined_path


class PolicyTests(unittest.TestCase):
    def test_deny_by_default(self):
        self.assertFalse(Policy().allows('alice', 'laptop', 'process.read'))

    def test_exact_scoped_grants(self):
        policy = Policy([Grant('alice', 'laptop', 'process.read')])
        self.assertTrue(policy.allows('alice', 'laptop', 'process.read'))
        self.assertFalse(policy.allows('alice', 'vps', 'process.read'))
        self.assertFalse(policy.allows('bob', 'laptop', 'process.read'))
        self.assertFalse(policy.allows('alice', 'laptop', 'process.exec'))

    def test_paths_have_boundary_and_traversal_checks(self):
        self.assertTrue(confined_path('/srv/work', '/srv/work/file.txt'))
        self.assertFalse(confined_path('/srv/work', '/srv/worker/file.txt'))
        self.assertFalse(confined_path('/srv/work', '/srv/work/../etc/passwd'))
        self.assertFalse(confined_path('/srv/work', '/etc/passwd'))
