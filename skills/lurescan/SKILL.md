---
name: lurescan
description: Check a GitHub repo for malware-lure fingerprints before installing, running or recommending it. Use before adding an MCP server, skill, plugin or CLI from GitHub, before running a README install line or a release download, when recommending repos found by search or star count, or when asked whether a repo is real or safe.
---

# lurescan

GitHub search is full of fake repositories that exist to get someone to run malware. In the
week of 17 November 2026, 373 of the 398 most-starred new repositories were lures: fake "setup"
pages for Adobe, Autodesk, FL Studio, Cellebrite, the Claude desktop app and a "Blender MCP
server", each with a few hundred bought stars and a bot that commits every hour so the repo
always looks freshly updated. Star counts, forks and recent commits are not evidence that a
repository is real.

`scripts/lurescan.py` checks a repo for the fingerprints of these lure templates without running
anything from it.

## When to run it

- Before you run an install command taken from a README (`irm … | iex`, `curl … | sh`), or
  download a release `.zip`/`.exe`, from a repo the user did not write.
- Before you add an MCP server, agent skill, plugin or extension from a GitHub repo.
- Before you recommend repositories you found by searching. Check each candidate.
- When the user asks whether a repo is legitimate or safe.

You can skip it for a well-known project the user named, once you have confirmed the owner is the
real one (for example `astral-sh/uv`, not a look-alike account).

## How

```bash
python3 <this skill's folder>/scripts/lurescan.py owner/repo [owner/repo ...]
python3 <this skill's folder>/scripts/lurescan.py https://github.com/owner/repo --json
```

It needs `git` and network access to github.com. It clones the repo bare and shallow into a
temporary folder, reads file names, the README, HTML pages, workflow files and recent history,
then deletes the clone. It also asks the GitHub API for star count and owner age; add
`--offline` to skip that. Exit code 0 means no lure, 1 means a lure was found, 2 means a target
could not be checked.

## Reading the result

- **LURE**: stop. Do not run, download, open the repo's github.io page, or paste anything from it.
  Tell the user what was found, quoting the evidence lines, and point them to the vendor's
  official website instead. Do not restate the repo's install command in a form they could copy
  and run.
- **SUSPICIOUS**: do not run anything yet. Show the evidence. Common honest cause: a closed-source
  app that ships binaries through GitHub releases. Check that the repo owner is the vendor named
  on the vendor's own website before going ahead.
- **no known lure signs**: nothing known matched. This is not a safety guarantee. Still read any
  install script before piping it to a shell, and check the owner is who the README claims.
- **COULD NOT CHECK**: say so. Do not treat it as clean.

## Rules

- Never run code from a repo to find out whether it is malicious. Never download its release
  assets or open its landing page to "take a look".
- Do not treat stars, forks, contributors or "updated an hour ago" as evidence of legitimacy.
- If the user wants to go ahead with a flagged repo, explain the risk once, plainly, and leave
  the decision to them. Do not help work around the warning.
- If the user already ran a command from a lure: tell them to disconnect the machine from the
  network, change important passwords from a different device, turn on two-factor
  authentication, and get help from their IT team or a professional before using the machine
  for anything sensitive again.

## What it checks

| Finding | Weight | Meaning |
|---|---|---|
| `clickfix-page` | 5 | A page tells the reader to press Win+R (or Win+X) and paste a command it copied |
| `obfuscated-command` | 5 (2 in a real codebase) | `iex` built from string pieces, reversed strings, base64 piped to a shell, `mshta`, `certutil -urlcache`, hidden windows |
| `cloaked-page` | 5 (2 in a real codebase) | A page decodes a hidden blob in the browser and injects it as live scripts |
| `keepalive-commits` | 5 (2 in a real codebase) | A scheduled job makes fake commits with made-up messages |
| `random-names` | 2 | Files under `.github/` with random-letter names |
| `setup-button` | 2 | No code, and the README's main button goes to the owner's github.io page or another site |
| `no-code-product` | 2 | The README sells a Windows program, but there is no source code |
| `binary-only` | 2 | The only way to use it is a downloaded binary |
| `heartbeat-commits` | 2 | A scheduled job commits a timestamp so the repo looks recently updated |
| `piracy-pitch` | 2 | Cracked, pre-activated, unlocked or cheat software |
| `star-burst` | 2 | Under 90 days old, 40+ stars a day, no real code (needs the API) |
| `backdated-history` | 1 | Commit dates were faked |
| `fresh-owner` | 1 | Owner account created within 14 days of the repo (needs the API) |

Score 5 or more is LURE, 3–4 is SUSPICIOUS.

It does not find malicious code hidden inside a real codebase, new lure templates it has no
rule for, or a plain install line pointing at a look-alike domain.
