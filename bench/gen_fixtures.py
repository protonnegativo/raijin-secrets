"""Builds the benchmark's fixture trees: local files and a local git repository full of FAKE secrets.

Every secret is a random string from a fixed seed, shaped like a real key so trufflehog's detectors match
it. None of them is a real credential, and the benchmark runs trufflehog with --no-verification, so
nothing is sent anywhere. The same seed and the fixed git dates give the same files and the same commit
hashes on every run.

  noisy/     a project tree where most secrets sit in vendored packages, test fixtures and docs, and a
             few in the application's own config
  findings/  a git repository whose history adds secrets, copies them to other services, moves one
             into a test and deletes the config file: the secrets stay in the history

usage: python gen_fixtures.py <dir>
"""
import os
import random
import shutil
import string
import subprocess
import sys

root = sys.argv[1]
rng = random.Random(20261024)
ALNUM = string.ascii_letters + string.digits
UPPER = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
SERVICES = ("orders", "payments", "users", "search", "cart", "catalog", "auth", "reports")


def rand(n, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(n))


# One maker per detector: each returns a fresh fake value, shaped so the detector matches it.
def aws():
    return f"AKIA{rand(16, UPPER)}", rand(40)


def github():
    return f"ghp_{rand(36)}"


def gitlab():
    return f"glpat-{rand(20)}"


def stripe():
    return f"sk_live_{rand(24)}"


def slack():
    return f"xoxb-{rand(11, string.digits)}-{rand(12, string.digits)}-{rand(24)}"


def webhook():
    return f"https://hooks.slack.com/services/T{rand(8, UPPER)}/B{rand(8, UPPER)}/{rand(24)}"


def sendgrid():
    return f"SG.{rand(22)}.{rand(43)}"


def openai():
    return f"sk-{rand(20)}T3BlbkFJ{rand(20)}"


def npm():
    return f"npm_{rand(36)}"


def mailgun():
    return f"key-{rand(32, HEX)}"


def twilio():
    return f"SK{rand(32, HEX)}"


def postgres(host):
    return f"postgres://app_user:{rand(16)}@{host}:5432/app"


def write(path, text):
    path = os.path.join(root, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def noisy():
    # The application's own config: the secrets that matter.
    key_id, secret = aws()
    write("noisy/config/production.env", f"""# production settings
APP_ENV=production
AWS_ACCESS_KEY_ID={key_id}
AWS_SECRET_ACCESS_KEY={secret}
DATABASE_URL={postgres("db.prod.internal")}
""")
    sk = stripe()
    write("noisy/src/billing/client.py", f"""import stripe

stripe.api_key = "{sk}"


def charge(amount):
    return stripe.Charge.create(amount=amount, currency="usd")
""")
    write("noisy/scripts/deploy.sh", f"""#!/bin/sh
curl -X POST -d '{{"text":"deployed"}}' {webhook()}
""")
    # Vendored packages: the same tokens copied in many files, as bundlers and lockfiles do.
    pkg_tokens = [npm() for _ in range(4)]
    for i in range(40):
        tok = pkg_tokens[i % len(pkg_tokens)]
        write(f"noisy/node_modules/pkg-{i:02d}/.npmrc", f"//registry.npmjs.org/:_authToken={tok}\n")
        write(f"noisy/node_modules/pkg-{i:02d}/README.md", f"# pkg-{i:02d}\n\nSet `NPM_TOKEN={tok}` before publishing.\n")
    vendor_keys = [github() for _ in range(3)]
    for i in range(30):
        write(f"noisy/vendor/github.com/lib{i:02d}/client_test.go",
              f'package lib\n\nconst testToken = "{vendor_keys[i % 3]}"\n')
    # Test fixtures: one fixture set copied per test suite.
    fixtures = [aws() for _ in range(3)] + [(sendgrid(), None), (mailgun(), None), (twilio(), None)]
    for suite in range(25):
        lines = []
        for j, (a, b) in enumerate(fixtures):
            lines.append(f"key_{j} = {a}")
            if b:
                lines.append(f"secret_{j} = {b}")
        write(f"noisy/tests/suite{suite:02d}/fixtures/credentials.ini", "\n".join(lines) + "\n")
    # Docs: example snippets with keys.
    oa = openai()
    for page in range(12):
        write(f"noisy/docs/guide-{page:02d}.md", f"""# Guide {page}

```python
client = OpenAI(api_key="{oa}")
```

Notifications go to `{slack()}`.
""")


def git(*args, env=None):
    subprocess.run(["git", "-C", os.path.join(root, "findings"), *args], check=True, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def findings():
    repo = os.path.join(root, "findings")
    os.makedirs(repo)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Dev One")
    git("config", "user.email", "dev1@example.invalid")
    git("config", "commit.gpgsign", "false")
    day = [0]

    def commit(msg):
        day[0] += 1
        when = f"2026-01-{day[0]:02d}T12:00:00+0000"
        env = dict(os.environ, GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
        git("add", "-A")
        git("commit", "-q", "-m", msg, env=env)

    def put(path, text):
        write(os.path.join("findings", path), text)

    key_id, secret = aws()
    gh, gl, sk, sl, sg, oa, mg = github(), gitlab(), stripe(), slack(), sendgrid(), openai(), mailgun()
    db = postgres("db.internal")
    put("README.md", "# shop\n")
    put("app/settings.py", f"""DEBUG = False
AWS_ACCESS_KEY_ID = "{key_id}"
AWS_SECRET_ACCESS_KEY = "{secret}"
DATABASE_URL = "{db}"
STRIPE_KEY = "{sk}"
""")
    commit("Add settings")
    put("ci/release.yml", f"""steps:
  - run: git clone https://x:{gh}@github.com/acme/shop
  - run: curl -H "PRIVATE-TOKEN: {gl}" https://gitlab.com/api/v4/projects
""")
    commit("Add release pipeline")
    for svc in SERVICES:
        put(f"services/{svc}/config.env", f"""SERVICE={svc}
DATABASE_URL={db}
SLACK_TOKEN={sl}
""")
    commit("Add services")
    put("services/mailer/config.env", f"SENDGRID_API_KEY={sg}\nMAILGUN_KEY={mg}\n")
    commit("Add mailer")
    put("tools/ask.py", f'import openai\nopenai.api_key = "{oa}"\n')
    commit("Add ask tool")
    # A new Stripe key replaces the old one; the old one is still in history.
    sk2 = stripe()
    put("app/settings.py", f"""DEBUG = False
AWS_ACCESS_KEY_ID = "{key_id}"
AWS_SECRET_ACCESS_KEY = "{secret}"
DATABASE_URL = "{db}"
STRIPE_KEY = "{sk2}"
""")
    commit("Rotate Stripe key")
    # The settings move to the environment; the keys stay in history.
    os.remove(os.path.join(repo, "app/settings.py"))
    put("app/settings.py", 'import os\nAWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n')
    commit("Read settings from the environment")
    # A test gets a copy of the Slack token and a fake GitHub token of its own.
    put("tests/test_notify.py", f'SLACK = "{sl}"\nGH = "{github()}"\n')
    commit("Add notify test")
    for svc in SERVICES:
        put(f"services/{svc}/config.env", f"SERVICE={svc}\n")
    commit("Remove credentials from services")


shutil.rmtree(os.path.join(root, "noisy"), ignore_errors=True)
shutil.rmtree(os.path.join(root, "findings"), ignore_errors=True)
noisy()
findings()
