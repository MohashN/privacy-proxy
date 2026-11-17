# Contributing

Thanks for helping. A security problem goes through [`SECURITY.md`](SECURITY.md),
not a public issue.

## Setting up

You need [uv](https://docs.astral.sh/uv/) and Python 3.11 or later.

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

CI runs these four and a secret scan on every pull request, and all must pass.
`uv run ruff format .` fixes the formatting.

## Sending a change

- **Open an issue first** for anything larger than a fix, so the approach is agreed
  before the work.
- **One change per pull request**, with tests. A fix comes with a test that fails
  without it.
- **Conventional Commits** for commit messages and the pull request title:
  `<type>(<scope>): <description>`, such as `fix(detection): read a phone split by a
  tab`. Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
  `ci`, `chore`, `revert`. A breaking change takes a `!` before the colon and a
  `BREAKING CHANGE:` footer saying what an Operator must do.
- **Add a line to [`CHANGELOG.md`](CHANGELOG.md)** under `Unreleased` for anything
  an Operator or a caller would notice.
- **Use the project's words** from [`CONTEXT.md`](CONTEXT.md): Operator, Detector,
  Detection, Refusal, Masking, Placeholder, Deny-list, Policy file.

## A new Detector

A Detector decides what leaves, so it has to be shown from both sides. A pull
request that adds one, or a country to `national_id`, needs:

- **Refused samples**: valid values in every spelling the Detector claims to read
  (grouped, run together, with a country code), each asserted to give a Detection.
  Use published test numbers or values you generated, never a real person's.
- **Passed samples**: what must not count, each asserted to give none. Invalid
  checksums, and the things coding traffic is full of: ids, timestamps, hashes,
  version numbers, floats. A Detector that refuses ordinary code gets switched off,
  and then it protects nobody.
- **Validation**: a checksum or a rule that rejects invalid values. A pattern with
  no validation is not accepted.
- **Time**: the check of a whole request has 10 s. A new Detector must read the
  deadline it is given and stay well inside it on a large body.
- **Docs**: the Policy file key in `policy.example.yaml` and the README, and whether
  it is on by default. On by default only if it rarely reads a bare number in code
  as a hit.

The existing tests in `tests/test_phone.py` and `tests/test_national_id.py` show the
shape.

## Principles a change must keep

- **Fail closed.** A request the proxy can't read or can't finish checking is
  refused, never passed.
- **The log is metadata.** No request text, key or header value is ever written,
  and an error message names a key or a kind, never a value.
- **No fallback.** The proxy never retries a request at another model or provider.
- **The Subscription lane never rewrites a request.** Masking is the API lane's
  alone ([ADR-0001](docs/adr/0001-inspect-refuse-by-default-mask-only-on-the-api-lane.md)).

## Licence

By contributing you agree that your contribution is licensed under
[Apache-2.0](LICENSE).
