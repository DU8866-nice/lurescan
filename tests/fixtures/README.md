# Test fixtures

Small, synthetic copies of the lure templates lurescan was written against, plus
legitimate repos that look a bit like them. None of them is a working lure:

- URLs point at `example.invalid`, a domain that cannot exist.
- The tokens antivirus engines look for (the obfuscated `iex`, the Win+R
  instruction) are stored as `@@PLACEHOLDERS@@` and only filled in by the tests,
  in a temporary copy.
- Git history (bot commits, backdated dates) is created by the tests too.
