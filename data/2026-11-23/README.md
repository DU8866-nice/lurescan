# Measurement, 23 November 2026

## Files

- `top-new-repos.tsv`: the 398 most-starred repositories created on GitHub between 17 and
  22 November 2026, as returned by the search API on 23 November (`created:>2026-11-16`, sorted
  by stars, first 400 results, 398 unique). One row per repo: stars, creation date, my label,
  the lure template, lurescan's verdict with and without API metadata, and the findings.
- `controls.tsv`: 161 real repositories picked to look a bit like lures, with the category each
  was picked for and lurescan's verdict with and without API metadata.

## How the repos were read

Every repo was cloned with `git clone --bare --filter=blob:limit=300k` (controls with
`--depth 30`). Nothing was checked out and nothing was run. No landing page, release asset or
payload URL was opened. The users API was not reachable from where I ran this, so `fresh-owner`
never fired here; star counts and creation dates came from the search results.

## How the labels were assigned

- **lure**: the repo matches one of the templates described in the main README, and its
  description advertises third-party paid software, a cheat or an unlock tool. I read the file
  list and description of every repo, and the full README, landing page and workflow of samples
  from each template.
- **legit**: a real project with real code or real content (21 repos).
- **unclear**: four large "native PC recompilation" repos for games released days earlier. I
  could not tell whether they are what they claim, so they are excluded from both counts.

The labels came first; the rules were then written against the lures, which makes the lure row
an in-sample result. The control set is the out-of-sample test.

## A note on the account names

Many owner accounts look like throwaway or hijacked accounts. This list says which repositories
were lures on 23 November 2026. It says nothing about the people whose names appear in it.
