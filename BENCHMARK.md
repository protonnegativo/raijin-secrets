# Token benchmark: trufflehog vs raijin-secrets

How many tokens does an AI agent spend reading the result of a secret scan, and does it lose anything? This benchmark scans a local project tree and a local git repository full of fake secrets with trufflehog, counts the tokens in each output shape, and checks that every result is in the raijin-secrets output and that no secret value is.

Reproduce: `bench/run.sh [workdir]` (needs go, git, trufflehog and python3 with tiktoken; `PY=<python>` picks the python that has it).

## Setup

- **Fixtures:** `bench/gen_fixtures.py` writes them on every run. Every secret is a random string from a fixed seed, shaped like a real key so trufflehog's detectors match it, and the git commits have fixed dates and authors, so the files and the commit hashes are the same on every run. **None of them is a real credential.**
- **No network.** trufflehog ran with `--no-verification` (no secret is sent to any provider) and `--no-update`. Nothing left the machine.
- **trufflehog:** v3.99.7. Run on 2026-10-29.
- **raijin-secrets:** replays trufflehog's saved JSON with `--input`, from the fixtures' directory so it reads the context lines, so every row sees the same results. Defaults apply: no limit on findings, and `--max-bytes 32000`, which was not reached. `bench/run.sh` also runs the live path (`-p`, `-g`) once per real scenario and checks it gives the same findings and groups as the replay.
- **Baselines**, as an agent would read trufflehog:
  - JSON: `trufflehog filesystem|git --json --no-verification`, one line per result.
  - Text: the same command without `--json` (`--no-color`), one block per result.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy (filesystem)

A project tree: 40 vendored npm packages that share 4 npm tokens (in `.npmrc` and README), 30 vendored Go libraries that share 3 GitHub tokens in test files, 25 test suites with the same fixture file (3 AWS key pairs, a SendGrid key, a Mailgun key), 12 docs pages that share one OpenAI key and each have a Slack token of their own, and 4 secrets in the application itself (AWS and Postgres in `config/production.env`, Stripe in `src/billing/client.py`, a Slack webhook in `scripts/deploy.sh`). trufflehog reported 413 results; the AWS detector pairs every key id with every secret key in a file, so the fixture files alone give 225. raijin-secrets returned 35 secrets: 4 findings (the application's own, all medium, with their context line) and 31 groups.

| Output | Bytes | Tokens | vs. trufflehog JSON |
|---|---:|---:|---:|
| trufflehog `--json` | 324,344 | 96,543 | 1× |
| trufflehog text | 88,955 | 30,232 | 3.2× |
| **raijin-secrets JSON (default)** | 23,681 | **7,206** | **13.4×** |
| raijin-secrets `--pretty` | 29,988 | 8,882 | 10.9× |
| raijin-secrets `--format table` | 1,697 | 693 | 139× |

## Scenario 2: findings (git history)

A git repository of 9 commits: settings with an AWS key, a Postgres URL and a Stripe key; a CI file with a GitHub token in a clone URL and a GitLab token; 8 services that each get the same Postgres URL and Slack token; a mailer with SendGrid and Mailgun keys; a tool with an OpenAI key; the Stripe key rotated; the settings file rewritten to read the environment; a test with a copy of the Slack token and a GitHub token of its own; and the services' credentials removed. Every secret is still in the history. trufflehog reported 28 results (a secret is reported at the commit that added it). raijin-secrets returned 12 secrets: 11 findings, all medium (no verification ran), and 1 group (the GitHub token only in the test). The Postgres URL and the Slack token are one finding each, with 9 places.

| Output | Bytes | Tokens | vs. trufflehog JSON |
|---|---:|---:|---:|
| trufflehog `--json` | 29,430 | 9,233 | 1× |
| trufflehog text | 15,909 | 5,815 | 1.6× |
| **raijin-secrets JSON (default)** | 3,715 | **1,251** | **7.4×** |
| raijin-secrets `--pretty` | 5,185 | 1,701 | 5.4× |
| raijin-secrets `--format table` | 1,956 | 708 | 13× |

## Scenario 3: verified (synthetic)

**This scenario is synthetic.** No fake secret passes a real verification, and the benchmark never verifies anything. `bench/run.sh` takes the JSON of scenario 2 and sets `Verified: true` on its AWS, GitHub, Postgres and first Stripe results, and a `VerificationError` on its Slack results. trufflehog never wrote this file, so there is no text row. It shows the verified path: raijin-secrets returned 12 findings, 5 critical and verified first (Postgres with its 9 places, AWS, both GitHub tokens, the old Stripe key), then the Slack token with `status: unknown` and its error, then the rest, medium. The GitHub token in the test is now a finding: a verified secret is never a group.

| Output | Bytes | Tokens | vs. trufflehog JSON |
|---|---:|---:|---:|
| trufflehog `--json` (edited) | 29,551 | 9,138 | 1× |
| **raijin-secrets JSON (default)** | 3,995 | **1,312** | **7.0×** |
| raijin-secrets `--pretty` | 5,558 | 1,794 | 5.1× |
| raijin-secrets `--format table` | 2,010 | 722 | 12.7× |

The edited file is re-encoded by Python, which writes `<` where trufflehog writes `<`, so it is 95 tokens shorter than scenario 2's.

The trufflehog JSON of scenarios 2 and 3 includes the absolute path of the fixture repository in every result (`repository`), here 127 characters long. A shorter workdir makes that baseline a little smaller; the raijin-secrets output does not contain it.

## Nothing is lost

For each scenario, `bench/verify.py` checks trufflehog's JSON against the raijin-secrets output. A result is the triple (detector, SHA-256 of the secret, location) plus its verification status. The secret is `RawV2` when trufflehog sets it, `Raw` otherwise; the location is `file:line` or `commit:file:line`. It is present when a finding or group has that detector, an `id` that ends in the hash, the same status and the location in its `locations`. The check also fails if any `Raw` or `RawV2` value appears anywhere in the output.

Results:

- Scenario 1: 413 results, 413 distinct triples, **0 missing**, 0 secret values in the output.
- Scenario 2: 28 results, 28 distinct triples, **0 missing**, 0 secret values in the output.
- Scenario 3: 28 results, 28 distinct triples, **0 missing**, 0 secret values in the output.

What the JSON leaves out stays in `raw`, which raijin-secrets saves to disk with mode 0600: the full secret values, the commit authors, emails and dates, the full commit hashes, the detector descriptions and the rotation guides.

## Reading the numbers

- **Against trufflehog's JSON**, the structured output an agent would parse, raijin-secrets uses **7× to 13× fewer tokens**. Most of the JSON is repeated per result: the detector description, the source name, the repository path, the author, `SecretParts` and the secret itself, often twice (`Raw` and `RawV2`).
- **Against trufflehog's text output**, raijin-secrets uses **4.2× fewer tokens** on the noisy run (30,232 → 7,206) and **4.6× fewer** on the git history (5,815 → 1,251). The text output is one block per place, so a secret copied 25 times is written 25 times; raijin-secrets writes it once with 25 locations. It also has no ranking, no grouping of test and vendored code, and every secret in clear text.
- **The cost that is left** is the locations: every place a secret was found is listed, because that is what an agent acts on (the file to fix, the commit to rewrite). In the noisy run, the 9 AWS key pairs of the test fixtures list the same 25 files each.
- **The output stays bounded.** On a run too big for `--max-bytes`, raijin-secrets cuts the least important data first: places of grouped secrets, then groups, then context lines, then extra places of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. trufflehog's output has no upper bound.
