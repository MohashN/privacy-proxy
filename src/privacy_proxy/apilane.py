"""The API lane: a caller holds a proxy key, the proxy calls the provider with its own.

The rules this follows:

- the credential picks the lane: a proxy key (``pp_…``) in ``x-api-key`` or
  ``Authorization: Bearer`` means the API lane, anything else the Subscription lane;
- each proxy key carries a model list and a monthly cap in USD; a model off the list
  is refused, and the proxy never falls back to another provider, since a fallback
  could move material to one that is not Trusted;
- the provider keys stay here; a caller only ever holds its own proxy key.

Proxy keys live in ``keys.yaml``, mounted outside the repo, as the SHA-256 of each key:
the proxy never holds a proxy key in the clear. Providers and their prices live in
``providers.yaml`` in the repo. Spend is a SQLite table of ``(key_name, month, usd)``.
"""

import hashlib
import json
import math
import re
import secrets
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import yaml

KEY_PREFIX = "pp_"

# The repo's providers.yaml: packed beside this module in a wheel, at the repo root
# in a checkout. PROVIDERS_PATH overrides it.
_PACKED = Path(__file__).resolve().parent / "providers.yaml"
PROVIDERS_FILE = (
    _PACKED if _PACKED.exists() else Path(__file__).resolve().parents[2] / "providers.yaml"
)

AUTH_SCHEMES = ("x-api-key", "bearer")

# The request formats a caller may speak: Anthropic's Messages and OpenAI's Chat
# Completions. A provider serves the ones it has a base URL for.
FORMATS = ("anthropic", "openai")

# A non-streamed answer is read whole for its usage; past this it is passed on
# unread and the cost is estimated, so one huge answer can't grow the proxy.
JSON_USAGE_MAX = 32 * 1024 * 1024

# A caller that hangs up before the usage arrives leaves the answer to be read on
# without it, so it can be priced; past this many bytes the read stops and the cost
# is estimated (the time limit is ``DRAIN_SECONDS`` in app.py).
DRAIN_MAX_BYTES = 32 * 1024 * 1024

# With no usage at all, input is estimated at four bytes of request per token, and
# output at four bytes of answer per token where that beats the request's bound.
BYTES_PER_TOKEN = 4

# An OpenAI-format stream told to report usage sends "usage": null in every chunk
# but the last; those chunks are passed by unparsed.
_NULL_USAGE = re.compile(rb'"usage"\s*:\s*null')


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def new_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def proxy_key(headers: list[tuple[bytes, bytes]]) -> str | None:
    """The proxy key a request carries, if any; its presence alone picks the API lane.

    Any ``x-api-key`` or ``authorization`` value that is a ``pp_`` key counts, with or
    without the ``Bearer`` scheme, quoted or not, in any case, so a proxy key is never
    forwarded to Anthropic in the Subscription lane by being spelled oddly. One that
    is spelled oddly is then simply not found: a 401.
    """
    for name, value in headers:
        if name.lower() not in (b"x-api-key", b"authorization"):
            continue
        # Every word counts, wherever it sits: "Bearer pp_…", "x, pp_…", "'pp_…'".
        for word in value.decode("latin-1").replace(",", " ").split():
            token = word.strip("\"'")
            if token.lower().startswith(KEY_PREFIX):
                return token
    return None


class ConfigError(ValueError):
    """A config file that reads but says something the proxy won't run with.

    Its message names the entry and is safe to print: it never quotes a value.
    """


def _read_yaml(path: Path):
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        # Re-raised bare: a YAML error's message quotes the line it failed on.
        raise ValueError("not valid YAML") from error


def month(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y-%m")


@dataclass(frozen=True)
class ProxyKey:
    name: str
    models: frozenset[str]
    monthly_cap_usd: float


class Keys:
    """The proxy keys, found by the hash of what a caller presents."""

    def __init__(self, keys: list[ProxyKey], hashes: list[str]) -> None:
        self._by_hash = dict(zip(hashes, keys, strict=True))

    def find(self, key: str) -> ProxyKey | None:
        return self._by_hash.get(hash_key(key))

    @classmethod
    def from_dict(cls, data: dict) -> "Keys":
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            # A bare list of entries, pasted without its "keys:" line, is the usual slip.
            raise ConfigError(
                'keys.yaml must be a mapping with a "keys:" list; see README "Getting a key"'
            )
        keys, hashes, names = [], [], set()
        for entry in data["keys"]:
            name = str(entry["name"])
            digest = str(entry["sha256"]).lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"key {name!r}: sha256 is not a SHA-256 hex digest")
            if name in names or digest in hashes:
                raise ValueError(f"key {name!r} is listed twice")
            cap = float(entry["monthly_cap_usd"])
            # NaN would compare false against any spend and never cap the key.
            if not math.isfinite(cap) or cap < 0:
                raise ValueError(f"key {name!r}: monthly_cap_usd is not a finite amount >= 0")
            models = entry["models"]
            if not isinstance(models, list) or not all(isinstance(m, str) for m in models):
                raise ValueError(f"key {name!r}: models is not a list of names")
            names.add(name)
            hashes.append(digest)
            keys.append(ProxyKey(name, frozenset(models), cap))
        return cls(keys, hashes)

    @classmethod
    def load(cls, path: Path) -> "Keys":
        return cls.from_dict(_read_yaml(path))


@dataclass(frozen=True)
class Price:
    """USD per million tokens; ``long`` takes over for a prompt over ``above`` tokens."""

    input: float
    output: float
    cache_read: float
    cache_write: float
    cache_write_1h: float = 0.0
    # USD per web search, billed on top of tokens.
    web_search: float = 0.0
    above: int | None = None
    long: "Price | None" = None

    def cost(self, usage: "Usage") -> float:
        if self.long and self.above is not None and usage.tokens_in > self.above:
            return self.long.cost(usage)
        return (
            usage.input_tokens * self.input
            + usage.cache_read_tokens * self.cache_read
            + (usage.cache_write_tokens - usage.cache_write_1h_tokens) * self.cache_write
            + usage.cache_write_1h_tokens * self.cache_write_1h
            + usage.output_tokens * self.output
        ) / 1_000_000 + usage.web_searches * self.web_search


@dataclass(frozen=True)
class Provider:
    name: str
    # Base URL per request format, for the formats this provider serves.
    urls: Mapping[str, str]
    key_env: str
    auth: str
    # The anthropic-beta values this provider may be sent. A beta can switch on a
    # feature billed outside what the proxy prices (a second model, a premium
    # speed), so none goes on unless it is listed.
    betas: frozenset[str] = frozenset()
    # A Trusted provider may be sent images and PDFs; any other is
    # refused them, since what they hold can't all be checked (#10).
    trusted: bool = False


@dataclass(frozen=True)
class Route:
    provider: Provider
    price: Price
    # The most output tokens the provider gives one answer: what an answer is charged
    # when its usage never arrives and the request named no bound.
    max_out: int


def _price(entry: dict, web_search: float = 0.0) -> Price:
    long = entry.get("long")
    web_search = float(entry.get("web_search", web_search))
    return Price(
        input=float(entry["in"]),
        output=float(entry["out"]),
        # A provider that doesn't discount cached input bills it as input.
        cache_read=float(entry.get("cache_read", entry["in"])),
        cache_write=float(entry.get("cache_write", entry["in"])),
        cache_write_1h=float(entry.get("cache_write_1h", entry.get("cache_write", entry["in"]))),
        web_search=web_search,
        above=int(long["above"]) if long else None,
        long=_price(long, web_search) if long else None,
    )


SNAPSHOT = re.compile(r"-(\d{4}-\d{2}-\d{2}|\d{8})", re.ASCII)


def _priced_by(model: str, prefix: str) -> bool:
    """The model is the listed name or its dated snapshot, nothing longer.

    `-search-preview`, `-pro` or `-audio-` variants bill differently, so they match
    no entry here unless providers.yaml lists them by their own name.
    """
    return model.startswith(prefix) and (
        len(model) == len(prefix) or SNAPSHOT.fullmatch(model, len(prefix)) is not None
    )


class Providers:
    """Model name to provider and price: a listed name or its dated snapshot.

    Of the names that match, the longest wins.
    """

    def __init__(self, routes: dict[str, Route]) -> None:
        self._routes = routes

    def route(self, model: str) -> Route | None:
        matches = [prefix for prefix in self._routes if _priced_by(model, prefix)]
        return self._routes[max(matches, key=len)] if matches else None

    @property
    def key_envs(self) -> set[str]:
        return {route.provider.key_env for route in self._routes.values()}

    @classmethod
    def from_dict(cls, data: dict) -> "Providers":
        routes: dict[str, Route] = {}
        for name, entry in data["providers"].items():
            auth = entry.get("auth", "x-api-key")
            if auth not in AUTH_SCHEMES:
                raise ValueError(f"provider {name!r}: auth is not one of {AUTH_SCHEMES}")
            betas = entry.get("betas", [])
            if not isinstance(betas, list) or not all(isinstance(b, str) for b in betas):
                raise ValueError(f"provider {name!r}: betas is not a list of names")
            urls = entry["urls"]
            if not isinstance(urls, dict) or not urls or not set(urls) <= set(FORMATS):
                raise ValueError(f"provider {name!r}: urls is not a map of {FORMATS} to URLs")
            trusted = entry.get("trusted")
            if not isinstance(trusted, bool):
                # Never assumed either way: which providers are Trusted is a decision.
                raise ConfigError(f"provider {name!r}: trusted is not true or false")
            provider = Provider(
                name,
                {fmt: str(url) for fmt, url in urls.items()},
                str(entry["key_env"]),
                auth,
                frozenset(betas),
                trusted,
            )
            for prefix, price in entry["models"].items():
                if prefix in routes:
                    raise ValueError(f"model prefix {prefix!r} is listed twice")
                max_out = price.get("max_out") if isinstance(price, dict) else None
                if not isinstance(max_out, int) or isinstance(max_out, bool) or max_out < 1:
                    raise ConfigError(f"model {prefix!r}: max_out is not a positive integer")
                routes[prefix] = Route(
                    provider, _price(price, entry.get("web_search", 0.0)), max_out
                )
        return cls(routes)

    @classmethod
    def load(cls, path: Path) -> "Providers":
        return cls.from_dict(_read_yaml(path))


class Spend:
    """Month-to-date spend per proxy key, in SQLite on the VM's volume."""

    def __init__(self, path: Path | str) -> None:
        # One connection, used from the event loop only; each write commits on its own.
        # A short timeout: these calls run on the event loop, and a locked database
        # must not hold every stream for sqlite's default five seconds.
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=1.0)
        self._db.execute("PRAGMA journal_mode=WAL")
        # In WAL mode this syncs at checkpoints, not on every write: a write per
        # answer stays off the disk's latency, and a crash loses at most the last few.
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS spend ("
            "key_name TEXT NOT NULL, month TEXT NOT NULL, usd REAL NOT NULL, "
            "PRIMARY KEY (key_name, month))"
        )

    def month_to_date(self, key_name: str, when: str) -> float:
        row = self._db.execute(
            "SELECT usd FROM spend WHERE key_name = ? AND month = ?", (key_name, when)
        ).fetchone()
        return row[0] if row else 0.0

    def add(self, key_name: str, when: str, usd: float) -> None:
        self._db.execute(
            "INSERT INTO spend (key_name, month, usd) VALUES (?, ?, ?) "
            "ON CONFLICT (key_name, month) DO UPDATE SET usd = usd + excluded.usd",
            (key_name, when, usd),
        )

    def close(self) -> None:
        self._db.close()


@dataclass
class ApiLane:
    keys: Keys
    providers: Providers
    spend: Spend
    # The provider keys by env var name. Kept out of repr so no traceback or debug
    # print can carry one.
    secrets: Mapping[str, str] = field(repr=False)


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # Of cache_write_tokens, those written to the one-hour cache, priced higher.
    cache_write_1h_tokens: int = 0
    web_searches: int = 0
    estimated: bool = False

    @property
    def tokens_in(self) -> int:
        return self.input_tokens + self.cache_read_tokens + self.cache_write_tokens


def _counts(fields: dict) -> dict:
    """The usage counters: top-level integers, one-hour cache writes, web searches."""
    counts = {k: v for k, v in fields.items() if isinstance(v, int) and not isinstance(v, bool)}
    creation = fields.get("cache_creation")
    if isinstance(creation, dict) and isinstance(creation.get("ephemeral_1h_input_tokens"), int):
        counts["ephemeral_1h_input_tokens"] = creation["ephemeral_1h_input_tokens"]
    tools = fields.get("server_tool_use")
    if isinstance(tools, dict) and isinstance(tools.get("web_search_requests"), int):
        counts["web_search_requests"] = tools["web_search_requests"]
    return counts


def _openai_counts(fields: dict) -> dict:
    """OpenAI-format usage as the Anthropic counters ``Usage`` is built from.

    ``prompt_tokens`` includes cached input in every provider that speaks it: OpenAI
    and Moonshot report cache reads in ``prompt_tokens_details.cached_tokens``,
    DeepSeek in ``prompt_cache_hit_tokens`` too, and Moonshot its cache writes in
    ``prompt_tokens_details.cache_write_tokens``. A write's lifetime isn't reported,
    so it is priced at the one-hour rate, the higher one.
    """
    counts = _counts(fields)
    details = fields.get("prompt_tokens_details")
    details = _counts(details) if isinstance(details, dict) else {}
    prompt = counts.get("prompt_tokens", 0)
    cached = min(
        max(
            details.get("cached_tokens", 0),
            counts.get("prompt_cache_hit_tokens", 0),
            counts.get("cached_tokens", 0),
        ),
        prompt,
    )
    written = min(details.get("cache_write_tokens", 0), prompt - cached)
    usage = {
        "input_tokens": prompt - cached - written,
        "cache_read_input_tokens": cached,
        "cache_creation_input_tokens": written,
        "ephemeral_1h_input_tokens": written,
    }
    if "completion_tokens" in counts:
        usage["output_tokens"] = counts["completion_tokens"]
    return usage if counts else {}


class Meter:
    """Reads ``usage`` out of a response as it passes, without holding the stream.

    A streamed answer reports usage in ``message_start`` and, cumulatively, in
    ``message_delta``; the highest value of each counter wins, so a provider that
    reports a counter as 0 in the last event can't erase it. A plain JSON answer
    carries it at the top level. ``message_start``'s output count is only a start
    (about 1), so a stream cut off before ``message_delta`` is priced on its input
    as reported and its output estimated, as if no usage had come.

    In the OpenAI format (``fmt="openai"``) a stream carries usage only in its last
    chunk, at the top level (Moonshot: also in its choice), so one cut off before it
    is estimated.
    """

    def __init__(self, streaming: bool, fmt: str = "anthropic") -> None:
        self.streaming = streaming
        self.fmt = fmt
        self.fields: dict = {}
        self._buffer = bytearray()
        self._overflow = False
        self.seen = 0
        # An Anthropic stream's final output count has arrived (in message_delta).
        self._final = False

    @property
    def overflowed(self) -> bool:
        """The response outgrew what is buffered for its usage; nothing more is read."""
        return self._overflow

    def feed(self, chunk: bytes) -> None:
        self.seen += len(chunk)
        if self._overflow:
            return
        self._buffer += chunk
        if not self.streaming:
            if len(self._buffer) > JSON_USAGE_MAX:
                self._overflow = True
                self._buffer.clear()
            return
        *lines, rest = self._buffer.split(b"\n")
        self._buffer = bytearray(rest)
        for line in lines:
            # Only the few events that carry usage are parsed; text deltas pass by.
            if not line.startswith(b"data:"):
                continue
            if line.count(b'"usage"') > len(_NULL_USAGE.findall(line)):
                self._event(line[5:])
        if len(self._buffer) > JSON_USAGE_MAX:
            self._overflow = True
            self._buffer.clear()

    def _event(self, data: bytes) -> None:
        try:
            event = json.loads(data)
        except (ValueError, RecursionError):
            return
        if not isinstance(event, dict):
            return
        if self.fmt == "openai":
            usage = event.get("usage")
            choices = event.get("choices")
            for choice in choices if isinstance(choices, list) else []:
                if isinstance(choice, dict) and isinstance(choice.get("usage"), dict):
                    self._merge(choice["usage"])
        elif event.get("type") == "message_start" and isinstance(event.get("message"), dict):
            usage = event["message"].get("usage")
        elif event.get("type") == "message_delta":
            usage = event.get("usage")
            # Only a real output count ends the answer; an empty usage does not.
            if isinstance(usage, dict) and "output_tokens" in _counts(usage):
                self._final = True
        else:
            return
        if isinstance(usage, dict):
            self._merge(usage)

    def _merge(self, usage: dict) -> None:
        counts = _openai_counts(usage) if self.fmt == "openai" else _counts(usage)
        for name, value in counts.items():
            self.fields[name] = max(value, self.fields.get(name, 0))

    def cache_log(self, usage: Usage) -> dict:
        """The cache counts for the log line, counts only; empty when no usage arrived.

        ``usage`` is what ``usage()`` returned. The 5-minute / one-hour split is there
        only when an Anthropic-format response carried ``cache_creation``: an
        OpenAI-format write's lifetime isn't reported.
        """
        if not self.fields:
            return {}
        fields = {"cache_read": usage.cache_read_tokens, "cache_write": usage.cache_write_tokens}
        if self.fmt == "anthropic" and "ephemeral_1h_input_tokens" in self.fields:
            fields["cache_write_5m"] = usage.cache_write_tokens - usage.cache_write_1h_tokens
            fields["cache_write_1h"] = usage.cache_write_1h_tokens
        return fields

    def usage(
        self,
        request_bytes: int,
        answered: bool,
        max_tokens: int = 0,
        choices: int = 1,
        max_out: int = 0,
    ) -> Usage:
        if not self.streaming and not self._overflow and self._buffer:
            try:
                body = json.loads(self._buffer)
            except (ValueError, RecursionError):
                body = None
            if isinstance(body, dict) and isinstance(body.get("usage"), dict):
                self._merge(body["usage"])
        if not self.fields:
            # An answer whose usage never arrived still cost something; a refusal
            # upstream (4xx, 5xx) did not.
            if not answered:
                return Usage()
            return Usage(
                input_tokens=request_bytes // BYTES_PER_TOKEN,
                output_tokens=self._most_output(max_tokens, choices, max_out),
                estimated=True,
            )
        usage = Usage(
            input_tokens=self.fields.get("input_tokens", 0),
            output_tokens=self.fields.get("output_tokens", 0),
            cache_read_tokens=self.fields.get("cache_read_input_tokens", 0),
            cache_write_tokens=self.fields.get("cache_creation_input_tokens", 0),
            cache_write_1h_tokens=min(
                self.fields.get("ephemeral_1h_input_tokens", 0),
                self.fields.get("cache_creation_input_tokens", 0),
            ),
            web_searches=self.fields.get("web_search_requests", 0),
        )
        if self.streaming and self.fmt == "anthropic" and not self._final and answered:
            # Cut off before message_delta: the input counts are message_start's,
            # its output count (about 1) is not the answer's.
            output = self._most_output(max_tokens, choices, max_out)
            return replace(usage, output_tokens=output, estimated=True)
        return usage

    def _most_output(self, max_tokens: int, choices: int, max_out: int) -> int:
        """The most output an answer whose count never came could have cost.

        For each of its choices: the request's bound, or, where it named none (an
        OpenAI-format request may not), the model's max_out, which also caps a
        bound past what the model can write. Hidden reasoning is never relayed, so
        the bytes read are only a floor.
        """
        bound = max_tokens if max_tokens > 0 else max_out
        if max_out > 0:
            bound = min(bound, max_out)
        return max(bound * choices, self.seen // BYTES_PER_TOKEN)
