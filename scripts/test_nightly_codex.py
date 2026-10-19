#!/usr/bin/env python3
"""Offline tests: no Codex, API, SSH, device, or GitHub interaction."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("nightly_codex.py")
spec = importlib.util.spec_from_file_location("nightly_codex", SCRIPT)
executor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(executor)


class NightlyPolicyTests(unittest.TestCase):
    def test_exactly_eight_single_file_scopes(self):
        self.assertEqual(len(executor.TASKS), 8)
        self.assertEqual(executor.MAX_CHANGED_FILES, 1)
        self.assertLessEqual(executor.MAX_CHANGED_LINES, 180)
        for name, prompt, paths in executor.TASKS:
            self.assertTrue(name and prompt)
            self.assertEqual(len(paths), 1)
            self.assertIn(paths[0], executor.ALLOWED)
            self.assertTrue(paths[0].endswith(".rs"))

    def test_codex_environment_drops_github_and_ssh_secrets(self):
        with mock.patch.dict(os.environ, {
            "OPENAI_API_KEY": "test-api-key", "GH_TOKEN": "secret",
            "GITHUB_TOKEN": "secret", "SSH_AUTH_SOCK": "/tmp/socket",
            "ACTIONS_RUNTIME_TOKEN": "runtime-secret",
            "GITHUB_ACTIONS": "true", "RUNNER_TEMP": "/tmp",
            "HOME": "/tmp"
        }):
            env = executor.agent_env()
        self.assertEqual(env["OPENAI_API_KEY"], "test-api-key")
        for name in ("GH_TOKEN", "GITHUB_TOKEN",
                     "SSH_AUTH_SOCK", "ACTIONS_RUNTIME_TOKEN"):
            self.assertNotIn(name, env)

    def test_key_and_runner_required(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "x",
                                          "HOME": "/tmp"}, clear=True):
            with self.assertRaises(executor.Blocked):
                executor.agent_env()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true",
                                          "RUNNER_TEMP": "/tmp",
                                          "HOME": "/tmp"}, clear=True):
            with self.assertRaises(executor.Blocked):
                executor.agent_env()

    def test_prompts_cannot_authorize_host_operations(self):
        for index in range(8):
            prompt = executor.safe_prompt(index)
            self.assertIn("No network", prompt)
            self.assertIn("Do not commit, push", prompt)
            self.assertIn(executor.TASKS[index][2][0], prompt)

    def test_single_tracked_change_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            path = executor.ALLOWED[1]
            (repo / path).parent.mkdir(parents=True)
            (repo / path).write_text("test")
            outputs = iter([" M " + path + "\0", "2\t1\t" + path + "\n"])
            with mock.patch.object(executor, "run",
                  side_effect=lambda *a, **k: mock.Mock(stdout=next(outputs))):
                self.assertEqual(executor.inspect_diff(repo, (path,)), (path,))

    def test_refuses_non_allowlisted_paths_deletes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for status in [
                " M .github/workflows/inject.yml\0",
                " D " + executor.ALLOWED[0] + "\0",
                "?? .env\0",
                "R  " + executor.ALLOWED[0] + "\0",
            ]:
                with mock.patch.object(executor, "run",
                    return_value=mock.Mock(stdout=status)):
                    with self.assertRaises(executor.Blocked):
                        executor.inspect_diff(repo, (executor.ALLOWED[0],))
            path = repo / executor.ALLOWED[0]
            path.parent.mkdir(parents=True)
            path.symlink_to(Path(tmp) / "secret")
            with mock.patch.object(executor, "run",
                  return_value=mock.Mock(stdout=" M " + executor.ALLOWED[0] + "\0")):
                with self.assertRaises(executor.Blocked):
                    executor.inspect_diff(repo, (executor.ALLOWED[0],))

    def test_refuses_binary_giant_and_empty_diffs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            path = executor.ALLOWED[0]
            (repo / path).parent.mkdir(parents=True)
            (repo / path).write_text("test")
            for numstat in [
                "181\t0\t" + path + "\n",
                "-\t-\t" + path + "\n",
                "0\t0\t" + path + "\n"
            ]:
                outputs = iter([" M " + path + "\0", numstat])
                with mock.patch.object(executor, "run",
                    side_effect=lambda *a, **k: mock.Mock(stdout=next(outputs))):
                    with self.assertRaises(executor.Blocked):
                        executor.inspect_diff(repo, (path,))

    def test_plan_does_not_need_secret_or_external_tools(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(executor.main(["--plan"]), 0)

    def test_invalid_stage_ranges_refused(self):
        for arguments in (
            ["--start", "0"],
            ["--start", "8", "--count", "2"],
            ["--count", "5"],
            ["--interval-seconds", "0"]
        ):
            with self.assertRaises(SystemExit):
                executor.main(arguments)


if __name__ == "__main__":
    unittest.main()
