# ⚡ Raijin Secrets

[![CI](https://github.com/protonnegativo/raijin-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-secrets/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-secrets)](https://github.com/protonnegativo/raijin-secrets/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-secrets)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-secrets.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-secrets)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-secrets)](https://goreportcard.com/report/github.com/protonnegativo/raijin-secrets)

**trufflehog for AI agents: verified secrets first, with the minimal context line, never the full file.**

`raijin-secrets` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [trufflehog](https://github.com/trufflesecurity/trufflehog) on local paths and git repositories and returns the **Raijin Schema**: one compact JSON where each secret is one entry listing every file, line and commit it was found at, verified secrets are ranked first, the secret value is redacted, the line it was found on is kept as a short redacted context, and secrets that only sit in tests, docs and vendored code are collapsed into groups.

## Why not just run trufflehog?

trufflehog is built for people and pipelines. An agent pays for every byte it reads. Its JSON is one line per place a secret was found, and every line repeats the detector's description, the source name, the repository path, the author and the full secret value. A key copied into 25 test fixtures is 25 lines. The text output is shorter, but it is the same list, one block per place, with every secret in clear text.

Here are the same results read by an agent (tokens, `o200k_base`):

```
Noisy: a project tree, 413 results, 35 secrets, 31 of them only in tests, docs and vendored code
  raijin-secrets  █▌                     7,197 tokens
  trufflehog text ██████▎               30,232 tokens
  trufflehog JSON ████████████████████  96,543 tokens

Findings: a git history, 28 results, 12 secrets, 11 findings
  raijin-secrets  ██▋                    1,242 tokens
  trufflehog text ████████████▋          5,871 tokens
  trufflehog JSON ████████████████████   9,289 tokens

Verified (synthetic): the same history with 5 secrets marked verified and 1 with a verification error
  raijin-secrets  ██▉                    1,303 tokens
  trufflehog JSON ████████████████████   9,194 tokens
```

raijin-secrets reads **7× to 13×** fewer tokens than trufflehog's JSON, and **4.2× to 4.7×** fewer than its text output. Each scenario's bars are drawn to scale against the JSON. The fixtures are local files and a local git repository full of **fake** secrets; trufflehog ran with `--no-verification`, so nothing was sent anywhere. The verified scenario is trufflehog's JSON from the findings run with `Verified` set by the benchmark script, since no fake secret can pass a real verification.

- **Nothing is lost.** Every result trufflehog reported, a detector plus a secret plus a place, is in the output with its verification status. `bench/verify.py` checked all 469 results in the three scenarios and none were missing.
- **No secret value leaves the raw file.** The output shows `AKIA…(20)#d2def24d`: the first characters, the length and a short hash. `bench/verify.py` also checks that no secret value appears in the output.
- **The real leads come first.** A verified cloud key is critical, an unverified one is medium. A token copied into 25 test fixtures is one group that lists all 25 places.
- **Output is bounded.** On a huge run, `--max-bytes` cuts the least important data first (places of grouped secrets) and counts every cut.
- **Details are one file away.** trufflehog's full JSON is saved to disk, and its path is in `raw`. It holds the full secret values, the commit authors and dates, costs no tokens until the agent opens it, and replays with `--input`.

Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-secrets/cmd/raijin-secrets@latest
```

This installs the latest release. You also need `trufflehog` on `PATH`, or pass `--trufflehog <path>`. `git` is needed for the context lines of git results.

### Versions

Releases are tagged automatically on every change and every passing engine update. `raijin-secrets --version` shows the release and the tested engine version, e.g. `raijin-secrets v0.1.0 (tested with trufflehog 3.99.7)`. `raijin-mcp update` updates every Raijin tool at once.

## Usage

```bash
raijin-secrets --scope scope.txt -p ./app                    # files under a path (trufflehog filesystem)
raijin-secrets --scope scope.txt -g ./app                    # a local repository and its history (trufflehog git)
raijin-secrets --scope scope.txt -g https://github.com/acme/api
raijin-secrets --scope scope.txt -l targets.txt --max-items 20
raijin-secrets --scope scope.txt --input raw.jsonl           # replay a saved run, nothing is scanned
raijin-secrets --scope scope.txt -p ./app --state run.json   # mark findings that are new since last run
raijin-secrets --scope scope.txt -p ./app --verify           # let trufflehog verify (sends each secret to its provider)
raijin-secrets --scope scope.txt -g ./app -- --branch dev   # anything after -- goes to trufflehog
```

`--scope` is required. One rule per line:

```
/srv/app
./checkout
https://github.com/acme/api
https://github.com/acme/*
!/srv/app/vendor
```

A path rule covers the path and everything under it (a relative one is taken from the working directory). A URL rule covers the repository and the files in it; with a trailing `*` it covers every URL that starts with the text before it. `file://` repositories are matched by the path rules too. Exclusions win. Targets outside the scope are dropped before trufflehog runs, and results in files outside it (an excluded `vendor/` inside a scanned path) are dropped after. Both are counted in `omitted.out_of_scope`.

`-l` reads one target per line: a line with `://` is a git repository, anything else a path. A local path given to `-g` becomes a `file://` URL.

**Verification is off by default.** trufflehog verifies a secret by sending it to the provider's API (AWS, GitHub, Stripe...). raijin-secrets passes `--no-verification` unless you pass `--verify`, so by default no secret leaves the machine and every result is unverified. Only use `--verify` on secrets you are authorized to test.

## Output

```json
{
  "tool": "raijin-secrets",
  "version": "0.1.0",
  "target": "../findings/trufflehog.jsonl",
  "summary": "28 results, 12 secrets, 11 findings (11 medium), 0 verified, 1 groups",
  "findings": [
    {
      "id": "postgres-f43cc5a2",
      "title": "Postgres",
      "severity": "medium",
      "tags": ["database"],
      "secret": "post…(53)#f43cc5a2",
      "extra": {"database": "app", "host": "db.internal:5432", "sslmode": "<unset>", "username": "app_user"},
      "context": "DATABASE_URL=post…(53)#f43cc5a2/app",
      "locations": [
        "782f7ffbf138:services/auth/config.env:2",
        "782f7ffbf138:services/cart/config.env:2",
        "... 6 more",
        "7f663a7998d6:app/settings.py:4"
      ]
    },
    {
      "id": "aws-b91558c6",
      "title": "AWS",
      "severity": "medium",
      "tags": ["cloud"],
      "secret": "AKIA…(20)#d2def24d",
      "extra": {"resource_type": "Access key"},
      "context": "AWS_ACCESS_KEY_ID = \"AKIA…(20)#d2def24d\"",
      "locations": ["7f663a7998d6:app/settings.py:2"]
    }
  ],
  "groups": [
    {
      "id": "github-b4314065",
      "detector": "Github",
      "secret": "ghp_…(40)#b4314065",
      "extra": {"token_type": "Personal Access Token (classic)"},
      "locations": ["5b6ce0d12149:tests/test_notify.py:2"]
    }
  ]
}
```

That is the real findings run from the benchmark (`--input` on the saved trufflehog JSON of the fixture git repository), pretty-printed here. Two things are shortened: 9 of the 11 findings are left out, and the Postgres finding lists all 9 places in the real output (6 are replaced by `"... 6 more"` here). The tool writes it as one line.

In the synthetic verified scenario, the same Postgres secret is `"severity": "critical", "confidence": "verified"`, and a secret whose verification failed has `"status": "unknown"` and trufflehog's `"error"`.

**Nothing trufflehog found is dropped silently.** Every result is in exactly one finding or group. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One entry per secret.** A secret is a detector, a value and a verification status. The value is trufflehog's `RawV2` when it sets one (it pairs an AWS key id with its secret key, or a token with its host), `Raw` otherwise. Each entry lists every place it was found, so a key copied into 25 files is one entry with 25 locations. The same value found by two detectors is two entries. The same secret verified at one place and with a verification error at another is two entries, so no status is lost.
- **Locations** are `file:line` for a filesystem result and `commit:file:line` for a git result, with the commit cut to 12 hex digits. When the results come from more than one repository, the repository comes first: `https://github.com/acme/api 0123456789ab:config.env:3`. ` [BASE64]` (or another decoder) is added when trufflehog found the secret in decoded text. They are sorted by repository, commit, file and line.
- **Redaction.** `secret` is trufflehog's `Raw` (the key itself) as its first characters, its length and the first 8 hex digits of its SHA-256: `AKIA…(20)#d2def24d`. It shows 4 characters of a secret of 16 or more, 2 of one of 8 or more, none of a shorter one. The hash tells apart secrets with the same start, and an agent that has a value can check `sha256sum` against it. The `id` is the detector and the first 8 hex digits of the SHA-256 of the identifying value (`RawV2` or `Raw`), so for most detectors it ends in the same hash as `secret`.
- **Context** is the line the secret was found on, at the first location raijin-secrets can read: the file for a filesystem result, `git show commit:file` for a local (`file://`) repository. Every secret value of the run on that line is redacted, and so is any other run of 32 or more token characters, so a secret in base64 or one trufflehog did not report never reaches the output. It is cut to 120 characters around the secret. A line with no redacted secret on it (the secret was found in decoded text), a remote repository, or a file that is gone gives no context. Groups have none. `--no-context` turns it off.
- **Extra** is trufflehog's `ExtraData` (token type, database host and user, account details some detectors add...), redacted the same way, without the rotation guide link and the detector version.
- **Findings** are every secret that is verified, or that was found at least once outside test, example, documentation and vendored code. Severity is fixed by the status and the detector's class:

  | | Detector with a class | Any other detector |
  |---|---|---|
  | verified | critical | high |
  | unverified or unknown | medium | low |

  The classes are the tag: `cloud` (AWS, GCP, Azure, DigitalOcean, Heroku, Cloudflare...), `key` (private keys, JWT), `code` (GitHub, GitLab, Bitbucket, CI services, npm, PyPI, Docker Hub...), `database` (Postgres, MongoDB, MySQL, JDBC, Redis, URI with credentials...), `payment` (Stripe, Square, PayPal, Shopify...), `messaging` (Slack, Twilio, SendGrid, Mailgun...) and `ai` (OpenAI, Anthropic, Hugging Face...). The full list is in `internal/reduce`. They give access to infrastructure, code, data, money, or an account that sends messages or bills by use.

  `confidence` is `verified` when the provider accepted the secret; it is left out otherwise. `status` is `unknown` when verification was attempted and failed with an error, with trufflehog's `error`; it is left out for unverified. When trufflehog ran with `--no-verification` (the default), unverified only means not checked.
- **Groups** are the unverified secrets found only in test, example, documentation or vendored code, by path: a directory named `test`, `tests`, `testdata`, `fixtures`, `examples`, `docs`, `mocks`, `vendor`, `node_modules`, `third_party` and similar, or a file like `foo_test.go`, `foo.spec.ts`, `test_foo.py`, `.env.example`, `README.md`. A verified secret is never a group. A group has `id`, `detector`, `secret`, `status`, `error`, `extra` and `locations`: no title, severity or context.
- **Ranking:** findings by severity, then confidence (verified first), then status (`unknown` before unverified), then the number of locations, then `id`. Groups by the number of locations, then `id`. The same input always gives the same order.
- **`id`** is stable: the same secret has the same `id` in the next run. The less verified of two entries for the same secret gets its status in its id: `slack-65df3f74-unknown`.
- **`raw`** is trufflehog's full JSON, saved to a file only the user can read (mode 0600). It holds the full secret values, the commit authors, emails and dates, the detector descriptions and the rotation guides. `--input` replays it. `--raw <file>` picks the path.
- **Budget:** `--max-bytes` (32,000 by default) keeps the output bounded on huge runs. It cuts in this order until the JSON fits:
  1. group locations;
  2. groups;
  3. the context of the lowest-ranked findings;
  4. the locations of the lowest-ranked findings, each keeping one plus its `count`;
  5. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If trufflehog is missing, nothing runs and the exit code is 2.

Fields an agent can rebuild are left out to save tokens:

- `confidence` and `status` are left out for unverified; `tags` for a detector with no class; `extra`, `error` and `context` when empty.
- `count` appears only when the budget cut `locations`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 23% to 37% more tokens in the benchmark; `--pretty` indents it (the example above is pretty-printed, with short arrays kept on one line). `--format table` prints a short human view of the same result; it lists finding locations but only counts group locations.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-p` / `-g` / `-l` / `--input` | | local path (repeatable) / git repository URL or local path (repeatable) / target file / existing trufflehog JSON (repeatable) |
| `--verify` | false | let trufflehog verify each secret; this sends the secret to the provider |
| `--no-context` | false | do not read the source line of each finding |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 32000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save trufflehog's full JSON (mode 0600) |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--trufflehog` | trufflehog | path to the binary |
| `--banner` | false | print the banner to stderr |

## Engine versions

The trufflehog version Raijin is tested with is in `engines.json` (built into the binary). Before a scan, raijin-secrets runs `trufflehog --version`; when the installed major version differs or it is older than the tested one, it adds an `engine_version` entry to `errors`. When trufflehog's output lines lack the fields Raijin reads, it adds `engine_format` and counts them in `omitted.unparsed`. Neither changes the exit code. A weekly GitHub Actions job runs the benchmark with the latest trufflehog and commits the bump to `engines.json` and tags a release when it passes, or an issue when it breaks.

## Development

```bash
go test ./...
go vet ./...
```

Standard library only. trufflehog runs as a subprocess, once with `filesystem --json --no-update --no-verification <paths>` for all paths and once with `git --json --no-update --no-verification <url>` per repository, so the binary stays small and the engine can be updated on its own. The CLI tests run the live path offline with a small fake trufflehog; `testdata/sample.jsonl` is synthetic trufflehog output with fake values that hits every rule, including verified and unknown results.

## Responsible use

Only scan code you are authorized to test, and only verify secrets you are authorized to test: `--verify` sends each secret to its provider. The raw file holds every secret in full; treat it like the secrets themselves.
