#!/usr/bin/env python3
"""lurescan: tell a malware-lure GitHub repo from a real project before you run anything from it.

    python3 lurescan.py owner/repo [owner/repo ...]
    python3 lurescan.py https://github.com/owner/repo --json
    python3 lurescan.py ./path/to/clone

It reads file names, a few text files (README, HTML pages, workflow files) and recent
git history. It never checks out a working tree and never runs anything from the
repository. Standard library only; needs `git` on PATH to scan a remote repo.

Exit codes: 0 no lure found, 1 at least one lure (or suspicious with --strict),
2 at least one target could not be checked.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

__version__ = "0.1.0"

LURE_AT = 5
SUSPICIOUS_AT = 3
MAX_READ = 600_000
DAY = 86400

SOURCE_EXT = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".go", ".rs",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".fs", ".vb", ".java", ".kt", ".kts",
    ".scala", ".groovy", ".gradle", ".swift", ".m", ".mm", ".rb", ".php", ".lua", ".pl", ".pm",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".zig", ".nim", ".dart",
    ".ex", ".exs", ".erl", ".hrl", ".hs", ".ml", ".mli", ".clj", ".cljs", ".r", ".jl", ".lean",
    ".sql", ".vue", ".svelte", ".astro", ".gd", ".asm", ".s", ".v", ".sv", ".vhd", ".vhdl",
    ".tcl", ".cmake", ".nix", ".hcl", ".tf", ".sol", ".move", ".cairo", ".elm", ".purs", ".rkt",
    ".scm", ".lisp", ".el", ".vim", ".f90", ".f", ".pas", ".d", ".cr", ".hx", ".ahk", ".au3",
    ".wgsl", ".glsl", ".hlsl", ".metal", ".cu", ".proto", ".thrift", ".graphql",
}
SOURCE_NAMES = {"makefile", "dockerfile", "cmakelists.txt", "build.zig", "justfile", "rakefile"}
SKIP_DIRS = ("node_modules/", "vendor/", "third_party/", "site-packages/", ".venv/", "dist/")

# Letter pairs that are common in English words. A name made of random letters
# ("RBerAZirJwdLsk") has far fewer of them than a real name ("BuildAndTest").
COMMON_BIGRAMS = set("""
ab ac ad ag ai ak al am an ap ar as at au av aw ax ay ba be bi bj bl bo br bu by ca ce ch ci ck
cl co cr cs ct cu da dd de di dl do dr ds dt du ea ec ed ee ef eg ei el em en eo ep eq er es et
ev ew ex ey fa fe ff fi fl fo fr fs ft fu ge gh gi gl gn gr gs gu ha he hi ho hr ht ia ib ic id
ie if ig il im in io ip ir is it iv ix iz je ke ki ks kw la ld le lf li ll lo ls lt lu ly ma mb
me mi mm mo mp ms mu na nc nd ne nf ng ni nl nn no np ns nt nu nv oa ob oc od of og oi ok ol om
on oo op or os ot ou ov ow ox pa pd pe pi pl po pp pr ps pt pu py qu ra rc rd re rg ri rk rl rm
rn ro rr rs rt ru ry sa sc se sf sh si sk sl so sp ss st su sy ta tc te th ti tl tm to tp tr ts
tt tu ty ua ub uc ue uf ui ul um un up ur us ut va ve vi wa we wh wi wo wr xc xe xi xp xt yl yn
yp ys yt ze
""".split())

STANDARD_GITHUB_NAMES = {
    "codeowners", "funding", "dependabot", "renovate", "labeler", "release", "stale", "settings",
    "copilot-instructions", "pull_request_template", "issue_template", "contributing", "security",
    "support", "code_of_conduct", "config", "linters", "mergify", "workflows", "actions",
}


# --------------------------------------------------------------------------- data


@dataclass
class Commit:
    sha: str
    parents: list
    author: str
    email: str
    author_ts: int
    subject: str


@dataclass
class Finding:
    id: str
    weight: int
    title: str
    evidence: list = field(default_factory=list)

    def as_dict(self):
        return {"id": self.id, "weight": self.weight, "title": self.title, "evidence": self.evidence}


@dataclass
class Report:
    target: str
    verdict: str = "unchecked"
    score: int = 0
    findings: list = field(default_factory=list)
    checked: dict = field(default_factory=dict)
    error: str | None = None

    def as_dict(self):
        return {
            "target": self.target,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.as_dict() for f in self.findings],
            "checked": self.checked,
            "error": self.error,
        }


class Snapshot:
    """What lurescan knows about a repository: file paths, readable text, history, metadata."""

    name = ""
    owner = ""
    files: list = []
    commits: list | None = None
    total_commits: int | None = None
    shallow = False
    meta: dict = {}

    def read(self, path: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError


class DirSnapshot(Snapshot):
    """A plain directory (no git history)."""

    def __init__(self, root: str, name: str | None = None, meta: dict | None = None):
        self.root = os.path.abspath(root)
        self.name = name or os.path.basename(self.root.rstrip("/"))
        self.owner = self.name.split("/")[0] if "/" in self.name else ""
        self.meta = meta or {}
        self.files = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                self.files.append(os.path.relpath(full, self.root).replace(os.sep, "/"))
        self.files.sort()

    def read(self, path):
        full = os.path.join(self.root, path)
        try:
            if os.path.getsize(full) > MAX_READ:
                return None
            with open(full, "rb") as fh:
                return fh.read().decode("utf-8", "replace")
        except OSError:
            return None


def _git(gitdir, *args, check=False):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    res = subprocess.run(["git", "-C", gitdir, *args], capture_output=True, env=env)
    if check and res.returncode != 0:
        raise RuntimeError(res.stderr.decode("utf-8", "replace").strip() or "git failed")
    return res


class GitSnapshot(Snapshot):
    """A git repository (bare or not). Reads objects from HEAD; never touches the work tree."""

    def __init__(self, gitdir: str, name: str | None = None, meta: dict | None = None, history: int = 60):
        self.gitdir = gitdir
        self.name = name or os.path.basename(os.path.abspath(gitdir).rstrip("/")).removesuffix(".git")
        self.owner = self.name.split("/")[0] if "/" in self.name else ""
        self.meta = meta or {}
        out = _git(gitdir, "ls-tree", "-r", "-z", "--name-only", "HEAD", check=True).stdout
        self.files = sorted(p.decode("utf-8", "replace") for p in out.split(b"\0") if p)
        self.shallow = _git(gitdir, "rev-parse", "--is-shallow-repository").stdout.strip() == b"true"
        count = _git(gitdir, "rev-list", "--count", "HEAD").stdout.strip()
        self.total_commits = int(count) if count.isdigit() else None
        fmt = "%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s%x1e"
        raw = _git(gitdir, "log", f"-n{history}", f"--format={fmt}", "HEAD").stdout.decode("utf-8", "replace")
        self.commits = []
        for rec in raw.split("\x1e"):
            parts = rec.strip("\n").split("\x1f")
            if len(parts) != 6:
                continue
            sha, parents, an, ae, at, subj = parts
            self.commits.append(Commit(sha, parents.split(), an, ae, int(at or 0), subj))

    def read(self, path):
        res = _git(self.gitdir, "cat-file", "-s", f"HEAD:{path}")
        size = res.stdout.strip()
        if res.returncode != 0 or not size.isdigit() or int(size) > MAX_READ:
            return None
        res = _git(self.gitdir, "cat-file", "blob", f"HEAD:{path}")
        if res.returncode != 0:
            return None
        return res.stdout.decode("utf-8", "replace")


# --------------------------------------------------------------------------- helpers


def looks_random(stem: str) -> bool:
    """True for names like 'RBerAZirJwdLsk' or 'hTOdRWdBSrUyLWRm', False for 'BuildAndTest'."""
    if not re.fullmatch(r"[A-Za-z]{8,40}", stem):
        return False
    if stem.lower() in STANDARD_GITHUB_NAMES:
        return False
    upper = sum(c.isupper() for c in stem)
    lower = len(stem) - upper
    if upper < 2 or lower < 2:
        return False
    low = stem.lower()
    pairs = [low[i:i + 2] for i in range(len(low) - 1)]
    common = sum(p in COMMON_BIGRAMS for p in pairs) / len(pairs)
    switches = sum(1 for a, b in zip(stem, stem[1:]) if a.isupper() != b.isupper())
    # CamelCase words switch case at word starts and keep common letter pairs.
    return common < 0.6 or (switches >= 6 and common < 0.72)


def defang(s: str, limit: int = 160) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def snippet(text: str, m: re.Match, before: int = 40, after: int = 100) -> str:
    start = max(0, m.start() - before)
    if start > 0:  # don't open on half a word
        space = text.find(" ", start, m.start())
        start = space + 1 if space != -1 else m.start()
    end = m.end() + after
    if end < len(text):
        space = text.rfind(" ", m.end(), end)
        end = space if space != -1 else end
    return defang(text[start:end])


def is_source(path: str) -> bool:
    low = path.lower()
    if any(seg in low for seg in SKIP_DIRS):
        return False
    base = low.rsplit("/", 1)[-1]
    if base in SOURCE_NAMES:
        return True
    if low.startswith(".github/"):
        return False
    return os.path.splitext(base)[1] in SOURCE_EXT


def find_readme(files):
    for f in files:
        if "/" not in f and re.fullmatch(r"(?i)readme(\.(md|markdown|rst|txt))?", f):
            return f
    for f in files:
        if f.count("/") == 1 and f.lower().startswith((".github/", "docs/")) and re.fullmatch(
            r"(?i)readme\.(md|markdown)", f.rsplit("/", 1)[1]
        ):
            return f
    return None


def html_pages(files, limit=6):
    pages = [f for f in files if f.lower().endswith((".html", ".htm")) and f.count("/") <= 2
             and not any(seg in f.lower() for seg in SKIP_DIRS)]
    pages.sort(key=lambda f: (f.count("/"), not f.lower().endswith("index.html"), f))
    return pages[:limit]


def workflow_files(files, limit=12):
    return [f for f in files if f.startswith(".github/workflows/") and f.lower().endswith((".yml", ".yaml"))][:limit]


# --------------------------------------------------------------------------- patterns

FRAG = r"""(?:'[A-Za-z-]{1,16}'|"[A-Za-z-]{1,16}")"""
CONCAT_RE = re.compile(FRAG + r"(?:\s*\+\s*" + FRAG + r")+")
TICK_TOKEN_RE = re.compile(r"\b[A-Za-z]+(?:`+[A-Za-z-]+)+\b")
DANGER_WORDS = {"iex", "invoke-expression", "irm", "iwr", "invoke-restmethod", "invoke-webrequest",
                "downloadstring", "start-process", "powershell"}

OBFUSCATION = [
    ("reversed-string", re.compile(r"-join\s*\(?\s*['\"][^'\"\n]{8,}['\"]\s*\)?\s*\[\s*-1\s*\.\.")),
    ("base64-to-iex", re.compile(r"(?is)FromBase64String.{0,300}?\b(?:iex|Invoke-Expression)\b|\b(?:iex|Invoke-Expression)\b.{0,300}?FromBase64String")),
    ("encoded-command", re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]{0,80}?\s-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{40,}")),
    ("mshta-url", re.compile(r"(?i)\bmshta(?:\.exe)?\s+['\"]?(?:https?|vbscript|javascript):")),
    ("certutil-download", re.compile(r"(?i)\bcertutil(?:\.exe)?\s+[^\n]{0,40}?-urlcache")),
    ("bitsadmin-download", re.compile(r"(?i)\bbitsadmin(?:\.exe)?\s+/transfer")),
    ("hidden-window", re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]{0,60}?\s-w(?:indowstyle)?\s+h(?:idden)?\b")),
    ("env-index-iex", re.compile(r"(?i)\$(?:env:comspec|pshome|shellid)\s*\[\s*\d+")),
    ("wildcard-command", re.compile(r"(?i)[&.]\s*\(\s*(?:gcm|get-command)\s+['\"]?[a-z]*\*")),
    ("char-array-join", re.compile(r"(?i)\[char\[\]\][^\n]{0,200}?-join")),
    ("base64-to-shell", re.compile(r"base64\s+(?:-d|--decode|-D)\b[^\n|]{0,40}\|\s*(?:ba|z|da)?sh\b")),
]

PIPE_TO_SHELL_RE = re.compile(
    r"(?i)\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\b[^\n]{0,200}?(?:\|\s*&?\s*\(?\s*['\"]?(?:iex|invoke-expression)|\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b)"
)
RUN_DIALOG_RE = re.compile(
    r"(?i)\bWin(?:dows)?(?:\s*key)?\s*(?:</kbd>\s*)?\+\s*(?:<kbd>\s*)?[RX]\b|\bRun dialog\b|\bWin\s*\+\s*R\b"
)
CLIPBOARD_RE = re.compile(r"navigator\.clipboard\.writeText|execCommand\(\s*['\"]copy")

DOWNLOAD_WORD_RE = re.compile(r"(?i)\b(?:download|installer|install(?:ation)?|setup)\b")
DESKTOP_RE = re.compile(r"(?i)\bWindows[\s_]*(?:10|11)\b|\bWindows x64\b|\bx64\b|\bwin64\b|\b64-bit Windows\b|\bWindows (?:PC|desktop)\b")
PIRACY_RE = re.compile(
    r"(?i)\b(?:pre[- ]?activated|activator|cracked|crack|keygen|serial key|license key generator|full version"
    r"|alternative access|ready to run|all[- ]plugins edition|unlocked edition|god mode|infinite (?:health|ammo|money)"
    r"|one[- ]hit kill|aimbot|wallhack|triggerbot|no recoil|undetected|bypass anti[- ]?cheat|unlock all|free download"
    r"|no license (?:needed|required)|lifetime activation)\b"
)
BUTTON_IMG_RE = re.compile(r"(?i)button|\bbtn|_btn|download|setup|install|get[-_ ]?it\b")
ARCHIVE_RE = re.compile(r"(?i)\.(?:zip|rar|7z|exe|msi|scr|lnk|iso|img|dmg|apk)(?:$|[?#])")
STORE_HOSTS = ("apps.microsoft.com", "www.microsoft.com", "play.google.com", "apps.apple.com",
               "flathub.org", "snapcraft.io", "chromewebstore.google.com", "chrome.google.com",
               "addons.mozilla.org", "marketplace.visualstudio.com", "f-droid.org", "aur.archlinux.org",
               "testflight.apple.com", "img.shields.io")
MD_IMG_LINK_RE = re.compile(r"\[!\[(?P<alt>[^\]]*)\]\((?P<img>[^)\s]+)[^)]*\)\]\((?P<url>[^)\s]+)[^)]*\)")
HTML_IMG_LINK_RE = re.compile(r"(?is)<a\s[^>]*href=[\"'](?P<url>[^\"']+)[\"'][^>]*>(?P<body>.{0,800}?)</a>")
RELEASE_LINK_RE = re.compile(r"(?i)github\.com/[^/\s)]+/[^/\s)]+/releases(?:/latest|/download)?")

RANDOM_BOT_MSG_RE = re.compile(r"^[a-z]{2,12}(?: [a-z]{2,12}){1,2} (?:#\d{3,6}|\(\d{3,6}\))$")
CRON_RE = re.compile(r"(?m)^\s*schedule\s*:|cron\s*:")
REPO_WRITE_RE = re.compile(r"createOrUpdateFileContents|\bgit\s+commit\b|\bgit\s+push\b|repos\.createCommit|git\.createCommit")
RANDOM_IN_WF_RE = re.compile(r"Math\.random|\$RANDOM|\bshuf\b|random\.choice")
HEARTBEAT_RE = re.compile(r"\bdate\b[^\n|>]*>\s*[\w./-]+|new Date\(\)\.toISOString\(\)[^\n]{0,80}(?:writeFile|content)")


# --------------------------------------------------------------------------- checks


def _loader_features(script: str) -> set:
    feats = set()
    if re.search(r"\batob\(|fromCharCode\(\s*parseInt\(", script):
        feats.add("decode")
    if re.search(r"getElementById\(\s*['\"][^'\"]+['\"]\s*\+\s*\w+\s*\)", script):
        feats.add("chunks")
    if re.search(r"\w\]?\s*\^\s*\w|\^=", script) and ("charCodeAt" in script or "Uint8Array" in script):
        feats.add("xor")
    if re.search(r"createElement\(\s*['\"]script['\"]\s*\)|document\.write\(|new Function\(|\beval\(", script) or (
        "DOMParser" in script and "importNode" in script
    ):
        feats.add("inject")
    return feats


def check_pages(snap, texts, few_source):
    findings = []
    clickfix_ev, obf_ev, cloak_ev = [], [], []
    for path, text in texts.items():
        if not text:
            continue
        is_html = path.lower().endswith((".html", ".htm"))
        # 1. obfuscated commands, in README and pages
        for m in CONCAT_RE.finditer(text):
            joined = "".join(re.findall(r"['\"]([^'\"]*)['\"]", m.group(0))).lower()
            if joined in DANGER_WORDS:
                obf_ev.append(f"{path}: builds '{joined}' out of string pieces: {snippet(text, m)}")
                break
        for m in TICK_TOKEN_RE.finditer(text):
            if m.group(0).replace("`", "").lower() in DANGER_WORDS:
                obf_ev.append(f"{path}: hides '{m.group(0).replace('`', '')}' with backticks: {snippet(text, m)}")
                break
        for name, rx in OBFUSCATION:
            m = rx.search(text)
            if m:
                obf_ev.append(f"{path}: {name}: {snippet(text, m)}")
        if not is_html:
            continue
        # 2. ClickFix: page copies a command and tells the reader to open Win+R / Win+X and paste it
        dialog = RUN_DIALOG_RE.search(text)
        clip = CLIPBOARD_RE.search(text)
        cmd = PIPE_TO_SHELL_RE.search(text) or re.search(r"(?i)\b(?:irm|iwr)\b[^\n]{0,120}", text)
        if dialog and clip and cmd:
            clickfix_ev.append(f"{path}: tells the reader to press {defang(dialog.group(0)).replace('<kbd>', '').replace('</kbd>', '')} and paste a copied command")
            clickfix_ev.append(f"{path}: command: {snippet(text, cmd, 0, 120)}")
        # 3. cloaked page: an encrypted blob decoded in the browser and injected as scripts
        scripts = " ".join(re.findall(r"(?is)<script[^>]*>(.*?)</script>", text))
        feats = _loader_features(scripts)
        big_blob = re.search(r"[A-Za-z0-9+/=%\\]{1500,}", text) or len(re.findall(r"[A-Za-z0-9+/=%\\]{200,}", text)) >= 5
        if {"decode", "inject"} <= feats and feats & {"xor", "chunks"} and big_blob and "crypto.subtle" not in text:
            how = " + ".join(x for x in ("chunks", "xor") if x in feats).replace("chunks", "pieces hidden in page elements").replace("xor", "XOR")
            cloak_ev.append(f"{path}: decodes a hidden blob ({how}) and injects the result as live scripts")
    w = 5 if few_source else 2
    if clickfix_ev:
        findings.append(Finding("clickfix-page", 5, "A page tells you to paste a command into Win+R or PowerShell", clickfix_ev))
    if obf_ev:
        findings.append(Finding("obfuscated-command", w, "An install command is deliberately obfuscated", obf_ev[:6]))
    if cloak_ev:
        findings.append(Finding("cloaked-page", w, "A page hides its real content in an encrypted blob", cloak_ev))
    return findings


def check_workflows(snap, wf_texts, few_source, no_source):
    ev = []
    for path, text in wf_texts.items():
        if not text:
            continue
        if CRON_RE.search(text) and REPO_WRITE_RE.search(text):
            why = []
            if RANDOM_IN_WF_RE.search(text):
                why.append("random commit messages")
            stamp = re.search(r"['\"](\.github/[A-Za-z]{8,40})['\"]", text)
            if stamp and looks_random(stamp.group(1).split("/")[-1]):
                why.append(f"writes to stamp file {stamp.group(1)}")
            names = re.findall(r"(?m)^\s*(?:name\s*:\s*|)([A-Za-z]{8,40})\s*:?\s*$", text)
            if looks_random(os.path.splitext(path.rsplit("/", 1)[-1])[0]) or any(looks_random(n) for n in names):
                why.append("random-letter workflow or job names")
            if why:
                ev.append(f"{path}: scheduled job commits to the repo ({', '.join(why)})")
    bot_noise = []
    for c in snap.commits or []:
        if ("[bot]" in c.author or "github-actions" in c.author) and RANDOM_BOT_MSG_RE.match(c.subject):
            bot_noise.append(c.subject)
    if len(bot_noise) >= 5:
        ev.append(f"history: {len(bot_noise)} recent bot commits with made-up messages, e.g. "
                  + "; ".join(f"'{s}'" for s in bot_noise[:3]))
    if ev:
        w = 5 if few_source else 2
        return [Finding("keepalive-commits", w, "A scheduled job makes fake commits so the repo looks active", ev)]
    if not no_source:
        return []
    beat = []
    for path, text in wf_texts.items():
        if text and CRON_RE.search(text) and REPO_WRITE_RE.search(text) and HEARTBEAT_RE.search(text):
            beat.append(f"{path}: scheduled job writes the current time to a file and commits it")
    if beat:
        return [Finding("heartbeat-commits", 2, "A scheduled job commits a timestamp so the repo looks recently updated", beat[:3])]
    return []


def check_names(snap):
    odd = []
    for f in snap.files:
        if not f.startswith(".github/"):
            continue
        base = f.rsplit("/", 1)[-1]
        stem = os.path.splitext(base)[0] if f.startswith(".github/workflows/") else base
        if f.count("/") <= 2 and looks_random(stem):
            odd.append(f)
    if not odd:
        return []
    return [Finding("random-names", 2, "Files under .github/ have random-letter names", odd[:6])]


def _link_targets(readme):
    for m in MD_IMG_LINK_RE.finditer(readme):
        yield m.group("alt"), m.group("img"), m.group("url")
    for m in HTML_IMG_LINK_RE.finditer(readme):
        body = m.group("body")
        if "<img" not in body.lower() and "<picture" not in body.lower():
            continue
        img = re.search(r"(?i)(?:src|srcset)=[\"']([^\"']+)", body)
        alt = re.search(r"(?i)alt=[\"']([^\"']*)", body)
        yield (alt.group(1) if alt else ""), (img.group(1) if img else ""), m.group("url")


def check_readme(snap, readme, few_source, no_source):
    findings = []
    if not readme:
        return findings
    owner = (snap.owner or "").lower()
    desc = snap.meta.get("description") or ""
    text = readme + "\n" + desc
    if no_source:
        btn = []
        for alt, img, url in _link_targets(readme):
            if not (BUTTON_IMG_RE.search(img.rsplit("/", 1)[-1]) or BUTTON_IMG_RE.search(alt)):
                continue
            if not re.match(r"(?i)https?://", url):
                continue
            host = re.sub(r"(?i)^https?://", "", url).split("/")[0].lower()
            if not host or any(host.endswith(s) for s in STORE_HOSTS):
                continue
            own_pages = owner and host == f"{owner}.github.io"
            off_github = not host.endswith(("github.com", "github.io", "githubusercontent.com"))
            if own_pages or off_github:
                btn.append(f"README: image button '{alt or img.rsplit('/', 1)[-1]}' links to {defang(url, 90)}")
        if btn:
            findings.append(Finding("setup-button", 2, "The README's main call to action is an image button to a page outside the repo", btn[:3]))
        if DESKTOP_RE.search(text) and DOWNLOAD_WORD_RE.search(text):
            findings.append(Finding("no-code-product", 2, "The README sells a desktop program, but the repo has no source code",
                                    [f"README mentions {defang(DESKTOP_RE.search(text).group(0))!r} and {DOWNLOAD_WORD_RE.search(text).group(0)!r}; no source files in the repo"]))
        rel = RELEASE_LINK_RE.search(readme)
        arch = next((u for _a, _i, u in _link_targets(readme) if ARCHIVE_RE.search(u)), None)
        if (rel or arch) and len(readme) > 1500:
            target = rel.group(0) if rel else arch
            findings.append(Finding("binary-only", 2, "The only way to use it is a downloaded binary with no source to check",
                                    [f"README download link: {defang(target, 90)}"]))
    m = PIRACY_RE.search(text)
    if m and few_source:
        findings.append(Finding("piracy-pitch", 2, "It promises cracked, unlocked or cheat software",
                                [f"README/description: {snippet(text, m, 30, 50)}"]))
    return findings


def check_history(snap):
    commits = snap.commits or []
    if len(commits) < 3 or (snap.total_commits or 0) > 12:
        return []
    # Walk oldest to newest. A commit can't be written before the commits it sits on top of,
    # so one dated more than a day earlier than anything below it was backdated.
    back, newest_below = 0, None
    for c in reversed(commits):
        if newest_below is not None and c.author_ts < newest_below - DAY:
            back += 1
        newest_below = c.author_ts if newest_below is None else max(newest_below, c.author_ts)
    if back >= 2:
        return [Finding("backdated-history", 1, "Commit dates were faked to make the repo look older",
                        [f"{back} commits are dated earlier than the commit they were made on top of"])]
    return []


def _parse_time(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def check_meta(snap, few_source):
    m = snap.meta or {}
    findings = []
    created = _parse_time(m.get("created_at"))
    stars = m.get("stars")
    now = _parse_time(m.get("checked_at")) or time.time()
    if created and isinstance(stars, int) and few_source:
        days = max((now - created) / DAY, 1.0)
        if days <= 90 and stars >= 150 and stars / days >= 40:
            findings.append(Finding("star-burst", 2, "Lots of stars, very fast, for a repo with no code",
                                    [f"{stars} stars in {days:.0f} day(s)"]))
    owner_created = _parse_time(m.get("owner_created_at"))
    if created and owner_created is not None and 0 <= created - owner_created <= 14 * DAY:
        hrs = (created - owner_created) / 3600
        when = f"{hrs:.0f} hour(s)" if hrs < 48 else f"{hrs / 24:.0f} day(s)"
        findings.append(Finding("fresh-owner", 1, "The owner account was created just before the repo",
                                [f"account created {when} before the repository"]))
    return findings


def scan(snap: Snapshot) -> Report:
    rep = Report(target=snap.name)
    files = [f for f in snap.files if not f.startswith(".git/")]
    sources = [f for f in files if is_source(f)]
    n_source = len(sources)
    few_source = n_source <= 2
    # "No real code": nothing, or a token stub (a few short files) dressed up as a project.
    source_lines = None
    if n_source <= 3:
        source_lines = sum((snap.read(f) or "").count("\n") for f in sources)
    no_source = n_source == 0 or (source_lines is not None and source_lines < 120)
    few_source = no_source or (n_source <= 2 and (source_lines or 0) < 300)
    readme_path = find_readme(files)
    readme = snap.read(readme_path) if readme_path else None
    pages = html_pages(files)
    texts = {}
    if readme_path:
        texts[readme_path] = readme
    for p in pages:
        texts[p] = snap.read(p)
    wfs = {p: snap.read(p) for p in workflow_files(files)}

    findings = []
    findings += check_pages(snap, texts, few_source)
    findings += check_workflows(snap, wfs, few_source, no_source)
    findings += check_names(snap)
    findings += check_readme(snap, readme, few_source, no_source)
    findings += check_history(snap)
    findings += check_meta(snap, few_source)
    findings.sort(key=lambda f: -f.weight)

    rep.findings = findings
    rep.score = sum(f.weight for f in findings)
    rep.verdict = "lure" if rep.score >= LURE_AT else "suspicious" if rep.score >= SUSPICIOUS_AT else "no-known-signs"
    rep.checked = {
        "files": len(files),
        "source_files": n_source,
        "source_lines": source_lines,
        "no_real_code": no_source,
        "readme": readme_path,
        "pages": pages,
        "workflows": list(wfs),
        "commits_seen": len(snap.commits) if snap.commits is not None else None,
        "total_commits": snap.total_commits,
        "shallow": snap.shallow,
        "metadata": sorted(k for k, v in (snap.meta or {}).items() if v is not None),
    }
    return rep


# --------------------------------------------------------------------------- fetching

REPO_RE = re.compile(r"^(?:https?://github\.com/|git@github\.com:|github\.com/)?([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")


def parse_target(t: str):
    t = t.strip()
    if os.path.exists(t):
        return ("path", t)
    m = REPO_RE.match(t)
    if m:
        return ("github", f"{m.group(1)}/{m.group(2)}")
    return ("bad", t)


def fetch_meta(full: str, timeout=10) -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": f"lurescan/{__version__}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def get(url):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    meta = {"checked_at": datetime.now(timezone.utc).isoformat()}
    try:
        repo = get(f"https://api.github.com/repos/{full}")
        meta.update(stars=repo.get("stargazers_count"), created_at=repo.get("created_at"),
                    description=repo.get("description"), default_branch=repo.get("default_branch"))
        owner = (repo.get("owner") or {}).get("login") or full.split("/")[0]
        user = get(f"https://api.github.com/users/{owner}")
        meta["owner_created_at"] = user.get("created_at")
    except (urllib.error.URLError, OSError, ValueError) as e:
        meta["meta_error"] = str(e)[:120]
    return meta


def clone(full: str, dest: str, depth: int):
    url = f"https://github.com/{full}.git"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    # A bare clone has no working tree, so no checkout, no hooks, no LFS smudge, nothing executes.
    cmd = ["git", "clone", "--quiet", "--bare", "--no-tags", "--single-branch",
           "--template=", "--filter=blob:limit=1m", f"--depth={depth}", url, dest]
    res = subprocess.run(cmd, capture_output=True, env=env, timeout=180)
    if res.returncode != 0:
        msg = res.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(msg[-1] if msg else "git clone failed")


def scan_target(target: str, offline=False, depth=60) -> Report:
    kind, value = parse_target(target)
    if kind == "bad":
        return Report(target=target, verdict="error", error="not a GitHub repo (owner/repo or URL) or a local path")
    try:
        if kind == "path":
            gitdir = value
            if os.path.isdir(os.path.join(value, ".git")) or os.path.isfile(os.path.join(value, "HEAD")):
                return scan(GitSnapshot(value, name=os.path.basename(os.path.abspath(value)), history=depth))
            return scan(DirSnapshot(value))
        if shutil.which("git") is None:
            return Report(target=value, verdict="error", error="git is not installed")
        meta = {} if offline else fetch_meta(value)
        tmp = tempfile.mkdtemp(prefix="lurescan-")
        try:
            gitdir = os.path.join(tmp, "repo.git")
            clone(value, gitdir, depth)
            rep = scan(GitSnapshot(gitdir, name=value, meta=meta, history=depth))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if meta.get("meta_error"):
            rep.checked["metadata_error"] = meta["meta_error"]
        return rep
    except (RuntimeError, subprocess.SubprocessError, OSError) as e:
        return Report(target=value, verdict="error", error=str(e)[:200])


# --------------------------------------------------------------------------- output

VERDICT_TEXT = {
    "lure": "LURE",
    "suspicious": "SUSPICIOUS",
    "no-known-signs": "no known lure signs",
    "error": "COULD NOT CHECK",
}
ADVICE = {
    "lure": "Do not run, download or paste anything from this repo or its pages.",
    "suspicious": "Read the evidence before you run anything. Get the software from its official site instead.",
    "no-known-signs": "Nothing lurescan knows about matched. That lowers the risk; it does not prove the repo is safe.",
}


def render(rep: Report, color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    tone = {"lure": "1;31", "suspicious": "1;33", "no-known-signs": "1;32", "error": "1;35"}.get(rep.verdict, "1")
    head = f"{rep.target}  {c(tone, VERDICT_TEXT.get(rep.verdict, rep.verdict))}"
    if rep.verdict != "error":
        head += f"  (score {rep.score})"
    lines = [head]
    if rep.error:
        lines.append(f"  {rep.error}")
        return "\n".join(lines)
    for f in rep.findings:
        mark = c("31", "✗") if f.weight >= 5 else c("33", "!") if f.weight >= 2 else c("2", "·")
        lines.append(f"  {mark} {f.id} (+{f.weight}): {f.title}")
        for e in f.evidence:
            lines.append(f"      {e}")
    lines.append(f"  → {ADVICE[rep.verdict]}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lurescan", description="Check GitHub repos for malware-lure fingerprints without running them.")
    ap.add_argument("targets", nargs="*", help="owner/repo, a github.com URL, or a local path")
    ap.add_argument("--list", metavar="FILE", help="read more targets from FILE, one per line")
    ap.add_argument("--json", action="store_true", help="print one JSON object per target")
    ap.add_argument("--strict", action="store_true", help="exit 1 for 'suspicious' too")
    ap.add_argument("--offline", action="store_true", help="skip the GitHub API metadata lookup (stars, owner age)")
    ap.add_argument("--depth", type=int, default=60, help="commits of history to read (default 60)")
    ap.add_argument("--version", action="version", version=f"lurescan {__version__}")
    args = ap.parse_args(argv)

    targets = list(args.targets)
    if args.list:
        with open(args.list, encoding="utf-8") as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        ap.print_usage(sys.stderr)
        return 2

    if hasattr(sys.stdout, "reconfigure"):  # a Windows console or pipe may not take ✗ and →
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not args.json
    code = 0
    for i, t in enumerate(targets):
        rep = scan_target(t, offline=args.offline, depth=args.depth)
        if args.json:
            print(json.dumps(rep.as_dict(), ensure_ascii=False))
        else:
            if i:
                print()
            print(render(rep, color))
        if rep.verdict == "error":
            code = max(code, 2) if code != 1 else 1
        elif rep.verdict == "lure" or (args.strict and rep.verdict == "suspicious"):
            code = 1
    return code


if __name__ == "__main__":
    sys.exit(main())
