# privacy-proxy

A self-hosted proxy that sits between your AI tools and a cloud model API. It inspects
every request and stops phone numbers, national IDs, card numbers, IBANs and your own
listed identifiers from leaving. Each check is a **Detector**; a hit is a **Detection**,
and by default it ends in a **Refusal**: the request is not sent, and the caller gets
an error naming the kind of data found, never the data. The **Operator** (whoever runs
the proxy) sets what it does in one **Policy file**. The words are defined in
[`CONTEXT.md`](CONTEXT.md).

It fails closed: a request it can't read, can't finish checking, or can't forward is
refused, never passed on unread and never retried somewhere else.

- [Quickstart](#quickstart)
- [What it stops, and what it doesn't](#what-it-stops-and-what-it-doesnt)
- [The two lanes](#the-two-lanes)
- [The Policy file](#the-policy-file)
- [Environment variables](#environment-variables)
- [The Deny-list](#the-deny-list)
- [API keys](#api-keys)
- [The log](#the-log)
- [Running it as a service](#running-it-as-a-service)
- [Development](#development)

## Quickstart

You need Docker with Compose, and a clone of this repository. From the clone:

```bash
git clone https://github.com/MohashN/privacy-proxy.git && cd privacy-proxy
cp docker-compose.example.yml docker-compose.yml
mkdir config
docker compose pull
docker compose up -d
```

`docker compose pull` fetches the published image named in the compose file. To run
your own build instead, replace that line with:

```bash
docker build -t privacy-proxy:local .
export PRIVACY_PROXY_IMAGE=privacy-proxy:local
```

The proxy now listens on `127.0.0.1:8787` with every Detector on and refusing. It
needs no configuration to do that. Send it a request that carries a phone number:

```bash
curl -sS http://127.0.0.1:8787/v1/messages \
  -H 'content-type: application/json' \
  -d '{"model": "claude-haiku-5-5", "max_tokens": 16, "messages": [{"role": "user", "content": "Call me on +44 20 7946 0958"}]}'
```

It is refused, and nothing was sent to the provider:

```json
{"type":"error","error":{"type":"invalid_request_error","message":"privacy-proxy: refused (PHONE_NUMBER)"}}
```

The same request without the phone number goes through to Anthropic, which answers
with its own `401`, since the `curl` carries no login.

To put Claude Code behind the proxy, point it at the proxy and use it as usual:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

`docker compose logs -f` shows one line per request: metadata, never text.

Next steps, each optional: write a [Policy file](#the-policy-file), add a
[Deny-list](#the-deny-list) of your own names and addresses, or mint
[API keys](#api-keys) so your apps can call a provider through the proxy.

## What it stops, and what it doesn't

The proxy is a backstop that catches data with a recognisable shape. It is not a
filter that makes private text safe to send.

### What it catches

In every text the model would see (the system prompt, tool definitions, each message,
tool calls and tool results):

- **Phone numbers**, for any country, written with a `+` (`+44 20 7946 0958`). For
  each region you list in the Policy file, also that country's national format
  (`070-123 45 67` with `SE` listed). By default a number counts only when it is
  written the way people write phones, with a `+` or a separator; a bare run of
  digits (`timeout=12345678`) never does.
- **National ID numbers**, one Detector per country, each validated by a checksum or
  a rule that rejects invalid numbers:

  | Country | Code | Refused as | On by default |
  |---|---|---|---|
  | Sweden | `SE` | `SE_PERSONNUMMER` | yes |
  | Finland | `FI` | `FI_PERSONAL_IDENTITY_CODE` | yes |
  | Spain | `ES` | `ES_NIF`, `ES_NIE` | yes |
  | Italy | `IT` | `IT_FISCAL_CODE` | yes |
  | South Africa | `ZA` | `ZA_ID_NUMBER` | yes |
  | Germany | `DE` | `DE_TAX_ID`, `DE_SOCIAL_SECURITY` | no |
  | United Kingdom | `GB` | `UK_NHS` | no |
  | United States | `US` | `US_SSN` | no |
  | Poland | `PL` | `PL_PESEL` | no |
  | Canada | `CA` | `CA_SIN` | no |
  | Australia | `AU` | `AU_TFN`, `AU_MEDICARE` | no |
  | India | `IN` | `IN_AADHAAR` | no |
  | South Korea | `KR` | `KR_RRN` | no |
  | Thailand | `TH` | `TH_TNIN` | no |
  | Turkey | `TR` | `TR_NATIONAL_ID` | no |
  | Nigeria | `NG` | `NG_NIN` | no |

  The five on by default have IDs that don't read as ordinary numbers in code. The
  others also read a bare 9- to 13-digit number (an id, a Unix timestamp) as an ID
  often enough to refuse coding traffic: `US` takes almost any nine digits. Switch
  one on only if your traffic carries few bare numbers of that length.
- **Card numbers** (`CREDIT_CARD`, Luhn-checked) and **IBANs** (`IBAN_CODE`, checksum).
- **Deny-list entries**: names, addresses and other identifiers you list yourself,
  matched whatever their case, accents or punctuation ([below](#the-deny-list)).
- **The text layer of a PDF** sent as base64, each page read in memory and checked
  like message text, with each link's description and address. A PDF with a form or
  annotations other than plain links is refused whole (`PDF_NOT_FLAT`), as is one
  that can't be parsed or is encrypted (`PDF_UNREADABLE`), runs over 100 pages
  (`PDF_TOO_LONG`) or takes over 2 s to extract (`PDF_TOO_SLOW`).

A body the proxy can't read the way a provider would is refused as
`UNREADABLE_BODY`: not JSON, a key given twice, or compressed, and on the API lane
also `NaN`, `Infinity` or a number with more digits than a float holds. The check of
a whole request has 10 s; one that takes longer is refused as `SCAN_TOO_SLOW`.

### What it doesn't catch

- **Names, addresses and free text**, unless you put them on the Deny-list. A request
  about someone's health or money with no number in it goes through.
- **A number split across two parts of a request**: half in one message and half in
  the next, or in two separate fields.
- **Text inside an image, and scanned PDFs** (pages that are pictures). Only OCR
  would read them. An image's data is not read at all. A PDF or image given by URL
  or file id is not fetched, and a PDF's embedded files and metadata are not read.
- **A national ID of a country that isn't switched on**, or a phone in national
  format for a region that isn't listed.
- **A Swedish personnummer run together as 12 digits and dated since 1 January of
  last year**, which is far more often a timestamp (`202610260008`) than a person.
  A young child's number is caught in that spelling only from the Deny-list.
- **Data that is encoded or spelled out**: base64, or a number written in words.
  The Detectors read what is written, so anyone, or any agent, set on getting a
  value past them can.
- **Requests to other paths on the Subscription lane.** Only `/v1/messages` (and
  everything under it), `/v1/complete` and `/v1/chat/completions` are inspected.
  Any other path, a file upload included, passes unread.
- **Fields the Subscription lane skips.** There the proxy reads text, not plumbing:
  `metadata`, the values of `type`, `id`, `tool_use_id`, `signature` and
  `media_type`, and bare numbers outside a tool call's input are not checked. The
  API lane reads all of them.
- **Anything after the provider has it.** The proxy controls what leaves, not what
  the provider stores, logs or trains on.
- **The reply.** What the model sends back is relayed, not inspected.

**Masking is one-way.** Where you choose Masking over Refusal, the model sees a
Placeholder such as `<PHONE_NUMBER_1>` and its reply keeps the Placeholder: the
proxy never puts the original back.

## The two lanes

The credential on each request picks its lane.

### The Subscription lane

For a Claude Code session on a claude.ai login. A request with no proxy key takes
this lane and, once checked, goes to `https://api.anthropic.com` unchanged: same
method, path, query and body, byte for byte, with every header except the hop-by-hop
ones and `host`. The response streams back as it arrives.

This lane never rewrites a request, because signed thinking blocks and prompt
caching need byte-identical history. So it **always refuses** on a Detection, even
for a Detector the Policy file sets to `mask`, and the proxy says so at startup.

A body over 32 MiB on a path the proxy inspects is refused with a `413`; other
paths stream through with no limit. If Anthropic can't be reached the caller
gets a `502`; nothing is retried elsewhere.

The lane has no authentication of its own: it carries the caller's login. Keep it
on loopback or a network you trust.

### The API lane

For your own apps and agents. A caller that sends a **proxy key** (`pp_…`) in
`x-api-key` or `Authorization: Bearer` takes this lane. The caller never holds a
provider key: the proxy calls the provider with its own, and counts what each proxy
key spends.

The lane speaks two request formats and translates neither: Anthropic's
`POST /v1/messages` and `/v1/messages/count_tokens`, and OpenAI's
`POST /v1/chat/completions`. Point an SDK's base URL at the proxy and give it a
proxy key as its API key:

| Format | Base URL | Key goes in |
|---|---|---|
| Anthropic | `http://127.0.0.1:8787` | `x-api-key` or `Authorization: Bearer` |
| OpenAI | `http://127.0.0.1:8787/v1` | `Authorization: Bearer` |

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key=proxy_key)
```

Each request goes through these checks in order, and a refused request is never
sent. A refusal comes in the format's own error shape, so the caller's SDK reads it
as an error:

1. the proxy key is known: else `401`;
2. the model is on the key's list and priced in [`providers.yaml`](providers.yaml):
   else `403`. The proxy never falls back to another model or provider. A model
   matches a listed name, or that name plus a dated snapshot (`-YYYY-MM-DD`,
   `-YYYYMMDD`), nothing longer. A model whose provider doesn't serve the request's
   format is a `404`;
3. the key's spend this month (UTC) is under its cap: else `429`;
4. nothing bills outside the price table: request fields and tools that run another
   model or bill at a rate the proxy doesn't count (`fallbacks`, `mcp_servers`, code
   execution, OpenAI's `web_search_options` and audio, `store: true`, and the like)
   are refused with a `400`;
5. the Detectors, stricter than on the Subscription lane: `metadata`, ids and
   numbers anywhere in the body are read too. Else `400`, or Masking where the
   Policy file says so.

Then the body goes on to the provider that serves the model, with the provider's
key. Of the caller's headers only `content-type`, `accept` and, in the Anthropic
format, `anthropic-version` and the `anthropic-beta` values that provider is set
to allow go with it: no credential, cookie, session id or client
detail reaches the provider. A provider whose key isn't set answers `503`.

**Providers.** [`providers.yaml`](providers.yaml) lists each provider's endpoints,
the environment variable that holds its key, and its prices per model. It ships with
Anthropic and OpenAI as examples; the prices are illustrative, so check them against
each provider's pricing page. `PROVIDERS_PATH` points the proxy at your own copy.
Each provider is marked `trusted: true` or `false`. A request carrying any image,
PDF, file or audio part to a provider that is not trusted is refused as
`MEDIA_TO_UNTRUSTED`, since the proxy can't check all that such a part holds.

**Spend.** The answer's `usage` is priced from `providers.yaml` and added to a
SQLite table, `spend (key_name, month, usd)`, at `SPEND_DB_PATH`. A stream cut off
mid-way still costs, and an answer whose usage never arrives is charged an estimate
from the request's size and its output bound (`estimated: true` in the log). The cap
is checked before a call and the cost is known only after it, so the call that
crosses the cap completes and the next one is refused. Keep a prepaid balance or a
limit at the provider as the backstop.

**Masking.** With `action: mask` on a Detector, a request on this lane goes on with
each of that Detector's hits replaced by a Placeholder, `<KIND_N>`: the kind as
refusals name it, and a number counting the distinct values of that kind in the
request. One value has one Placeholder wherever it is written, so
`+46 70 123 45 67` and `070-123 45 67` both become `<PHONE_NUMBER_1>`. Masking
happens only when every Detection in the request is of a kind set to `mask`. The
masked body is checked again before it is sent, and the request is refused if
anything is left: a hit where no Placeholder can go (a key, an id, a number, a PDF,
a signed thinking block) or a hit from a Detector that refuses.

## The Policy file

One YAML file says which Detectors run and what each does on a hit. Copy
[`policy.example.yaml`](policy.example.yaml), edit it, and point `POLICY_PATH` at
it. With the compose example: put it at `config/policy.yaml`, uncomment
`POLICY_PATH` in `docker-compose.yml`, and run `docker compose up -d` again. The
proxy reads it once at startup; restart after a change.

With no Policy file, every Detector is on and refuses, exactly as below:

```yaml
detectors:
  national_id:
    action: refuse
    countries: [SE, FI, ES, IT, ZA]
  phone:
    action: refuse
    regions: []
    match: grouped
  card:
    action: refuse
  iban:
    action: refuse
  deny_list:
    action: refuse
```

| Key | Values | Default | What it does |
|---|---|---|---|
| `detectors.<name>.action` | `refuse`, `mask`, `off` | `refuse` | `refuse`: a hit refuses the whole request. `mask`: on the API lane the request goes on with each hit replaced by a Placeholder; the Subscription lane refuses instead. `off`: the Detector does not run. `<name>` is `national_id`, `phone`, `card`, `iban` or `deny_list`. |
| `detectors.deny_list.action` | `refuse`, `off` | `refuse` | As above, but never `mask`: a Deny-list hit is a hash of words, with no place in the text to put a Placeholder. With no Deny-list loaded there is nothing to match. |
| `detectors.national_id.countries` | a non-empty list of the codes in the [table above](#what-it-catches) | `[SE, FI, ES, IT, ZA]` | The countries whose ID numbers are checked. The list replaces the default, so name every country you want. |
| `detectors.phone.regions` | a list of ISO 3166 two-letter codes in capitals | `[]` | Each listed region adds that country's national format (`070-123 45 67` for `SE`). Numbers written with a `+` are read for every country whatever this holds. |
| `detectors.phone.match` | `grouped`, `valid` | `grouped` | `grouped`: only numbers written with a `+` or a separator (space, dash, brackets, dot). `valid`: any valid number, bare runs of digits included. |

A Detector left out of the file is `refuse`: the proxy never starts with a check
silently missing. A file the proxy can't use (bad YAML, an unknown key, Detector,
country or region) stops startup with a message naming the key, never a value. At
startup the proxy prints which Detectors are on and, if any is set to `mask`, that
the Subscription lane refuses those instead.

## Environment variables

Secrets and paths come from the environment. All are optional.

| Variable | What it is | Unset |
|---|---|---|
| `POLICY_PATH` | The [Policy file](#the-policy-file). | Every Detector is on and refuses. |
| `DENYLIST_PATH` | The hashed [Deny-list](#the-deny-list). | No Deny-list is loaded, and startup says so. |
| `KEYS_PATH` | The hashed proxy keys, `keys.yaml` ([API keys](#api-keys)). | The API lane refuses every proxy key. |
| `SPEND_DB_PATH` | The SQLite spend database. Its directory must be writable. | Required once `KEYS_PATH` is set; the image sets it to `/var/lib/privacy-proxy/spend.db`. |
| `PROVIDERS_PATH` | Your own `providers.yaml`. | The copy shipped with the proxy. |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | The proxy's own key for each provider: whatever `key_env` names in `providers.yaml`. | That provider answers `503` on the API lane. |

A path that is set but can't be read stops startup: a broken mount must never
quietly drop a file you meant to have. `DENYLIST_PATH` set to an empty value stops
startup too; an empty `POLICY_PATH` counts as unset.

The command takes `--host` (default `127.0.0.1`) and `--port` (default `8787`). The
image listens on `0.0.0.0` inside the container; the compose example publishes it on
the host's loopback only.

## The Deny-list

The Detectors find data by its shape. The Deny-list is for what has no shape: your
family's names, your address, an account number in an odd format. It is optional.

Write your entries one per line in a plain file kept outside any repository
([`denylist.template.txt`](denylist.template.txt) explains the format), then hash it:

```bash
uv run privacy-proxy hash-denylist ~/private/denylist.txt denylist.json
```

or with the image, run from the private directory that holds the plain file:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" privacy-proxy:local \
  hash-denylist /work/denylist.txt /work/denylist.json
```

Only the hashed file goes to the proxy: the plain one never belongs in a directory
the proxy can read. Point `DENYLIST_PATH` at the result. With the compose example:
copy `denylist.json` into `config`, uncomment `DENYLIST_PATH` in
`docker-compose.yml`, and run `docker compose up -d`.

Keep `denylist.json` private all the same. It holds no plain entry, but it holds the
salt, and someone with the file can test guesses against it: a short entry or a
phone number is quickly found that way.

`denylist.json` holds a fresh random salt and the SHA-256 of each normalised entry.
The proxy never holds the plain entries. It normalises what it sees the same way
(case folded, accents and invisible characters dropped, punctuation and symbols to
spaces), hashes every run of 1 to 6 words, and refuses on a match as `DENYLIST`. So:

- `Anna-Karin Söderberg` matches `ANNA KARIN soderberg` and `anna.karin+soderberg`;
- an entry matches as whole words, at most six of them: split a long address into
  separate lines;
- a single common word (`Anna`) refuses every request that mentions it. Prefer full
  names.

**Numbers.** List a number in its plain form, run together (`0701234567`). A number
of 10 or 12 digits is then caught in any grouping (`070-123 45 67`), glued inside a
longer run of digits, split by any gap that is neither letters nor digits, and
written in non-ASCII digits. A number of any other length matches only as you wrote
it: list each grouping you expect on its own line. A number that starts with Sweden's country code (`+46`, `0046`) is also
looked up in its national `0` form. To catch a Swedish personnummer in every
spelling, list it three ways (this one is the public test number):

```text
19121212 1212
121212 1212
191212121212
```

## API keys

Each caller on the API lane gets its own proxy key, so the log and the spend table
tell callers apart.

### Getting a key

```bash
uv run privacy-proxy new-key my-app
```

or, with the compose example:

```bash
docker compose run --rm privacy-proxy new-key my-app
```

prints a new key, once, and below it a `keys.yaml` holding the new entry. Give the
key to the caller and keep no copy: `keys.yaml` holds only its SHA-256. For a new
file, paste everything from `keys:` down; to add to a file, paste the entry under
its `keys:` line. Fill in the models the key may use and its monthly cap in USD:

```yaml
keys:
  - name: "my-app"
    sha256: 52a9…5f39
    models: [claude-haiku-5-5, gpt-5.6-luna]
    monthly_cap_usd: 5
```

Point `KEYS_PATH` at the file and set the provider keys. With the compose example:
save it as `config/keys.yaml`, uncomment `KEYS_PATH` in `docker-compose.yml`, export
`ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in the shell (or put them in a `.env` file
beside it, which this repository's `.gitignore` keeps out of a commit), and run
`docker compose up -d`. The proxy reads `keys.yaml` at startup;
restart after a change.

```bash
curl -sS http://127.0.0.1:8787/v1/messages \
  -H "x-api-key: $PROXY_KEY" -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model": "claude-haiku-5-5", "max_tokens": 16, "messages": [{"role": "user", "content": "say ok"}]}'
```

Which provider may see what is set by each key's model list: put a model of a
provider you don't trust with real material only on a key whose caller sends public
or made-up material.

## The log

One JSON line per request on stdout, built from a fixed list of fields. No key, no
body text and no header value but the session id is ever written: a content log
would be a copy of what passed through.

```json
{"time": "2026-11-15T20:31:15.690+00:00", "session": null, "caller": "172.20.0.1", "method": "POST", "path": "/v1/messages", "status": 200, "outcome": "complete", "duration_ms": 2412, "lane": "subscription", "check_ms": 3, "upstream_ttfb_ms": 1180}
```

| Field | What it holds |
|---|---|
| `time` | When the line was written, UTC. |
| `session` | The `x-claude-code-session-id` header, if the caller sent one. |
| `caller` | The client's IP address. |
| `method`, `path`, `status` | The request and the status the caller got. |
| `outcome` | How the request ended (below). |
| `duration_ms` | From the proxy receiving the request to the response ending. |
| `lane` | `subscription` or `api`. |
| `check_ms` | The time spent parsing and checking the body. On every inspected request, refused ones too. |
| `upstream_ttfb_ms` | The wait from sending the request on to the provider's response headers. Missing when no response came. |
| `detections` | On a refused or masked request: each Detection's `type` and a salted `hash` of what matched, so two hits of the same value can be told apart without the value. |
| `masked` | `true` when the request went on with Placeholders. |
| `key`, `model`, `provider` | API lane: the proxy key's name, the model and the provider. |
| `tokens_in`, `tokens_out`, `usd` | API lane, for a turn: tokens in (cached ones included), tokens out and the cost. `estimated: true` when no usage arrived. |
| `cache_read`, `cache_write`, `cache_write_5m`, `cache_write_1h` | Both lanes, when the response carried usage: prompt-cache tokens read and written. |

`outcome` is one of:

- `complete`;
- `refused`: a Detection, with `detections`;
- `caller_gone`: the caller hung up;
- `upstream_error`: the provider broke off mid-stream;
- `upstream_unreachable`: the `502`;
- `provider_auth`: the provider refused the proxy's own key. The caller gets the
  proxy's error, not the provider's, which may quote the key;
- `proxy_error`;
- on the API lane, before the Detectors run: `refused_key`, `refused_path`,
  `refused_model`, `refused_cap`, `refused_format`, `refused_feature` and
  `refused_size`;
- on the API lane, after the Detectors pass: `provider_unconfigured`, the `503`.

The `hash` in `detections` is salted with the Deny-list's salt, or with a random
one per start when no Deny-list is loaded. It is there to tell values apart, not to
keep them secret from someone who holds both the log and `denylist.json`: a phone
number has few enough possibilities to try them all. Keep both private.

A refused request and a masked one:

```json
{"…": "…", "status": 400, "outcome": "refused", "lane": "subscription", "check_ms": 98, "detections": [{"type": "PHONE_NUMBER", "hash": "8999…11f2"}]}
{"…": "…", "status": 200, "outcome": "complete", "lane": "api", "key": "my-app", "model": "claude-haiku-5-5", "provider": "anthropic", "masked": true, "detections": [{"type": "PHONE_NUMBER", "hash": "8999…11f2"}], "tokens_in": 1200, "tokens_out": 300, "usd": 0.00027}
```

## Running it as a service

[`docker-compose.example.yml`](docker-compose.example.yml) is a starting point: the
image, a volume for the spend database, a health check, and a `config` directory
mounted read-only at `/etc/privacy-proxy` for the Policy file, the Deny-list and
`keys.yaml`.

- **Put TLS in front of it** for anything beyond loopback. The proxy speaks plain
  HTTP, and the Subscription lane carries the caller's login. A reverse proxy in
  front must not buffer responses, or streams arrive in one piece.
- **File permissions.** The container runs as uid and gid `10001` and must be able
  to read its files. On a machine other people use, don't leave `keys.yaml` and
  `denylist.json` readable by everyone: give them to group `10001` with mode `0640`
  (`sudo chgrp 10001 config/keys.yaml config/denylist.json && chmod 0640 …`).
- **Stopping.** On shutdown the proxy reads in-flight API-lane answers to their
  end, so it can charge and log them. A stop that kills it sooner loses those
  charges; the example gives it 30 s, and a long stream can outlast that.
- **Logs.** Everything the proxy writes is metadata. If you put another server in
  front of it, check that its log drops request headers, which hold keys and
  logins.

Without Docker, the same proxy runs from a clone:

```bash
uv sync
uv run privacy-proxy --port 8787
```

with the variables [above](#environment-variables) in its environment.

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

CI runs the same, plus a secret scan. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for
how to send a change, [`SECURITY.md`](SECURITY.md) for reporting a vulnerability,
and [`CHANGELOG.md`](CHANGELOG.md) for what changed.

## Licence

[Apache-2.0](LICENSE).
