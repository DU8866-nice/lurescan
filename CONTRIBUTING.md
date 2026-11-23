# Contributing

## Report a miss or a false alarm

Open an issue with the repo name and what lurescan said (`--json` output is ideal).

Please don't paste payload URLs, install commands or archive passwords from a lure. The repo
name is enough for me to look at it safely.

## Add a rule

1. Add a small fixture under `tests/fixtures/` that reproduces the template. Point every URL at
   `example.invalid`. If the template needs tokens that antivirus engines flag, store them as
   `@@PLACEHOLDERS@@` and add them to `PLACEHOLDERS` in `tests/test_lurescan.py`, so the repo
   never holds a working lure.
2. Add a legitimate look-alike fixture that the rule must not flag.
3. Change `lurescan.py`, then copy it into the skill: `cp lurescan.py skills/lurescan/scripts/`.
4. Run the tests: `python3 -m unittest discover -s tests`.

lurescan stays one file with no dependencies, so it can be read in one sitting and dropped into
any machine.
