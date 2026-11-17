"""The Subscription lane: forward a Claude Code session to Anthropic untouched.

A session on the operator's claude.ai login points ``ANTHROPIC_BASE_URL`` here, and
every request goes on to ``https://api.anthropic.com`` with the same method, path,
query, headers and body. Anthropic's gateway protocol sets the rules this follows
(https://code.claude.com/docs/en/llm-gateway-protocol, read 2026-10-26):

- every ``anthropic-*`` header is forwarded verbatim; the OAuth capability rides in
  ``anthropic-beta``, and dropping it gives a 401;
- bodies are never rewritten, because thinking signatures and prompt caching need
  byte-identical history;
- the response streams back as it arrives, ``ping`` events included.

Only hop-by-hop headers and ``host`` are dropped, in both directions. The response
is read with ``aiter_raw``, so a gzip body stays gzip and its ``content-encoding``
still describes it.

Before a Messages request goes on, it is checked against the Detectors
(``detection.py``); a hit gets a 400 in Anthropic's error shape and nothing is sent.
Only the check reads the body: what goes on is still the bytes that came in.

The proxy fails closed: when Anthropic can't be reached the
caller gets a 502, and nothing is retried or sent anywhere else.

A request carrying a proxy key (``pp_…``) takes the API lane instead (``apilane.py``):
the key is checked, then the model against its list, then the month's spend against
its cap, then the Detectors; the caller's credential is replaced by the provider's
and the answer streams back while its ``usage`` is read and priced. The API lane
speaks Anthropic's Messages format and OpenAI's Chat Completions format, each to
the provider's endpoint for that format; nothing is translated between them.

The API lane alone may rewrite a body (ADR-0001, #66): where the Policy sets a Detector
to ``mask``, each of its Detections is replaced by a Placeholder (``<PHONE_NUMBER_1>``)
and the request goes on, once a second check of the masked body finds nothing left.
The Subscription lane refuses the same request.
"""

import json
import math
import posixpath
import sys
import time
import zlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TextIO
from urllib.parse import unquote

import anyio
import httpx
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from privacy_proxy.apilane import DRAIN_MAX_BYTES, JSON_USAGE_MAX, ApiLane, Meter, month, proxy_key
from privacy_proxy.detection import Detection, Scanner

ANTHROPIC = "https://api.anthropic.com"

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
    }
)

METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

# Claude Code's requests run to minutes when thinking is long, and a stream can
# sit quiet between events; a short read timeout would cut those off mid-answer.
TIMEOUT = httpx.Timeout(connect=10.0, read=600.0, write=60.0, pool=10.0)

# An API-lane answer whose caller hung up is read on, unrelayed, for its usage: for
# this long in all after the caller went, as long as one read may take. The byte
# limit is DRAIN_MAX_BYTES (apilane.py).
DRAIN_SECONDS = 600.0

# Every path whose body carries a conversation to the model: everything under
# /v1/messages (a turn, count_tokens, batches), the legacy completion's prompt, and
# Anthropic's OpenAI-compatible /v1/chat/completions (``API_CHAT``), which an OpenAI
# SDK pointed at the proxy without a proxy key would reach.
MESSAGES = "/v1/messages"
COMPLETE = "/v1/complete"

# The API lane serves a turn in either format, and counting a Messages turn's tokens:
# path -> (format, the path after the provider's base URL for that format). Batches
# and files would spend or store outside what the proxy can price and check.
API_TURN = "/v1/messages"
API_CHAT = "/v1/chat/completions"
API_PATHS = {
    API_TURN: ("anthropic", API_TURN),
    "/v1/messages/count_tokens": ("anthropic", "/v1/messages/count_tokens"),
    # An OpenAI-format base URL ends in /v1, as the OpenAI SDK expects.
    API_CHAT: ("openai", "/chat/completions"),
}
API_TURNS = frozenset({API_TURN, API_CHAT})

# The only caller headers that go on in the API lane: what the provider needs to read
# the request. Credentials, cookies, session ids, OpenAI organisation and project ids
# and client details stay here, since the provider may not be a Trusted one.
# content-length is set again from what is sent; accept-encoding is set to identity
# so the answer comes back readable for its usage.
API_HEADERS = {
    "anthropic": frozenset({"content-type", "accept", "anthropic-version"}),
    "openai": frozenset({"content-type", "accept"}),
}
# The one query an Anthropic-format client sends (the SDK's beta marker); any other
# query is dropped rather than passed on unchecked.
API_QUERY = b"beta=true"

# Anthropic's request limit; both lanes read the whole body before they check it, so
# a larger one is refused before it can fill memory (the Subscription lane since #54).
API_BODY_MAX = 32 * 1024 * 1024

# Request fields that bill outside what the proxy prices, or run another model than
# the one checked against the key's list: refused rather than passed on.
API_UNPRICED_FIELDS = frozenset(
    {"fallbacks", "speed", "inference_geo", "container", "mcp_servers", "context_management"}
)
API_UNPRICED_TOOLS = ("advisor_", "code_execution_", "mcp_")
# In the OpenAI format: web search and audio bill per call or at audio rates, and a
# service tier other than these bills at a premium. Only function tools are priced;
# a provider's built-in tools (Moonshot's $web_search) bill per call. Audio input
# parts bill at audio rates. `store` keeps the conversation at the provider, as
# files and batches would.
OPENAI_UNPRICED_FIELDS = frozenset({"web_search_options", "audio"})
OPENAI_UNPRICED_PARTS = frozenset({"input_audio"})
OPENAI_PRICED_TIERS = frozenset({"auto", "default", "flex"})
OPENAI_PRICED_TOOLS = frozenset({"function", "custom"})

# What a provider's answer says about the account behind the proxy stays here.
API_RESPONSE_DROP = frozenset(
    {"anthropic-organization-id", "openai-organization", "openai-project", "set-cookie"}
)

# The session id is the one header value the log keeps (the ticket's field list).
# It comes from the caller, so it is capped rather than trusted.
SESSION_ID_MAX = 128

# OpenAI documents 128 as the most choices (`n`) a request may ask for. A caller's `n`
# is capped here before an estimate multiplies by it, so a huge one cannot overflow.
OPENAI_CHOICES_MAX = 128


def _forwardable(
    headers: list[tuple[bytes, bytes]], drop: frozenset[str]
) -> list[tuple[bytes, bytes]]:
    """Headers minus hop-by-hop ones, the ones a ``Connection`` header names, and ``drop``.

    Works on the raw pairs, so repeated headers (``set-cookie``) and the caller's
    own casing and order survive.
    """
    named = set()
    for name, value in headers:
        if name.lower() == b"connection":
            named.update(t.strip().lower() for t in value.decode("latin-1").split(","))
    skip = HOP_BY_HOP | drop | named
    return [
        (name, value)
        for name, value in headers
        if name.decode("latin-1").lower() not in skip and not name.lower().startswith(b"proxy-")
    ]


class _Relay(StreamingResponse):
    """A streamed upstream response that logs once and closes upstream however it ends.

    Starlette cancels the response when the caller hangs up, and the body
    generator may never start; cleanup lives here, around the whole send, so it
    runs on every path.
    """

    def __init__(
        self, upstream: httpx.Response, done, watch=None, drop: frozenset[str] = frozenset()
    ) -> None:
        self.upstream = upstream
        self.outcome = "caller_gone"
        self.done = done
        self.watch = watch
        super().__init__(self._body(), status_code=upstream.status_code)
        self.raw_headers = _forwardable(upstream.headers.raw, drop)

    async def _body(self):
        try:
            async for chunk in self.upstream.aiter_raw():
                if self.watch:
                    self.watch(chunk)
                yield chunk
        except httpx.TransportError:
            # Too late for a 502: the status has gone out. Raising makes the
            # server abort the connection, so the caller sees a broken stream
            # rather than a short one that looks complete.
            self.outcome = "upstream_error"
            raise
        self.outcome = "complete"

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            # Log first: it is synchronous, so a cancelled scope can't skip it.
            self.done(self.upstream.status_code, self.outcome)
            with anyio.CancelScope(shield=True):
                await self.upstream.aclose()


class _MeteredRelay(_Relay):
    """An API-lane answer, read by a task of its own so that a hang-up can't cut it short.

    Starlette cancels the response when the caller hangs up; a read cancelled
    mid-way closes the upstream connection, and the usage still to come is lost
    (an OpenAI-format stream sends it last, after ``finish_reason``). So a pump
    task reads upstream and hands each chunk on; once the caller is gone, it reads
    on without relaying, for at most ``DRAIN_SECONDS`` and ``DRAIN_MAX_BYTES``, and
    only then is the answer priced and logged, once.
    """

    def __init__(self, upstream: httpx.Response, done, watch, drop: frozenset[str]) -> None:
        super().__init__(upstream, done, watch, drop)
        # No buffer: the pump reads one chunk ahead of the caller, as a plain relay does.
        self._chunks_in, self._chunks_out = anyio.create_memory_object_stream[bytes](0)
        self._failure: Exception | None = None
        self._pump_scope = anyio.CancelScope()
        self.body_iterator = self._relayed()

    async def _relayed(self):
        async for chunk in self._chunks_out:
            yield chunk
        if self._failure is not None:
            # As in _Relay._body: too late for a 502, so the stream is broken.
            # Only a transport failure is the provider's; anything else is ours.
            upstream = isinstance(self._failure, httpx.TransportError)
            self.outcome = "upstream_error" if upstream else "proxy_error"
            raise self._failure
        self.outcome = "complete"

    async def _pump(self) -> None:
        drained = 0
        relaying = True
        with self._pump_scope:
            try:
                async for chunk in self.upstream.aiter_raw():
                    self.watch(chunk)
                    if relaying:
                        try:
                            await self._chunks_in.send(chunk)
                            continue
                        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                            relaying = False
                    drained += len(chunk)
                    if drained >= DRAIN_MAX_BYTES:
                        return
            except Exception as error:  # noqa: BLE001 -- the relay must still end and log
                self._failure = error
            finally:
                # Set before the close, so the relay sees why it ended.
                self._chunks_in.close()

    async def __call__(self, scope, receive, send) -> None:
        caller_error: Exception | None = None
        try:
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(self._pump)
                try:
                    await StreamingResponse.__call__(self, scope, receive, send)
                except Exception as error:  # noqa: BLE001 -- re-raised once the drain is done
                    # A hang-up seen on send (ClientDisconnect), or the upstream
                    # failure the relay re-raised: either way the pump finishes first.
                    caller_error = error
                finally:
                    # The caller has all it will get; the pump reads on, unrelayed,
                    # until the answer ends or the limits run out. uvicorn's shutdown
                    # waits for it (no timeout_graceful_shutdown is set); a cancel
                    # from outside stops it, and the finally below still logs.
                    self._chunks_out.close()
                    self._pump_scope.deadline = anyio.current_time() + DRAIN_SECONDS
        finally:
            # After the drain, so the usage it read is priced; synchronous, so a
            # cancelled scope can't skip it.
            self.done(self.upstream.status_code, self.outcome)
            with anyio.CancelScope(shield=True):
                await self.upstream.aclose()
        if caller_error is not None:
            raise caller_error


# The most a streamed answer is unzipped for its usage, in total; read at call time.
UNZIP_MAX = JSON_USAGE_MAX


def _usage_watch(meter: Meter, content_encoding: str):
    """A ``watch`` feeding a response's chunks to ``meter`` for logging, never raising.

    The relay passes the bytes on untouched; this reads a copy, unzipping gzip and
    deflate on the way. Any other encoding can't be read, so it logs nothing.
    """
    encoding = content_encoding.strip().lower()
    if encoding in ("", "identity"):
        unzip = None
    elif encoding in ("gzip", "x-gzip", "deflate"):
        unzip = zlib.decompressobj(zlib.MAX_WBITS | 16 if "gzip" in encoding else zlib.MAX_WBITS)
    else:
        return None
    broken = False
    unzipped = 0

    def watch(chunk: bytes) -> None:
        nonlocal broken, unzipped
        # Past the meter's cap nothing more is read, so neither is it unzipped.
        if broken or meter.overflowed:
            return
        try:
            if unzip is None:
                meter.feed(chunk)
                return
            data = unzip.decompress(chunk, 1 << 20)
            while data:
                meter.feed(data)
                unzipped += len(data)
                if unzipped > UNZIP_MAX:
                    # Many short lines never trip the meter's cap; this bounds them.
                    broken = True
                    break
                if meter.overflowed or not unzip.unconsumed_tail:
                    break
                data = unzip.decompress(unzip.unconsumed_tail, 1 << 20)
        except Exception:  # noqa: BLE001 -- reading for the log must never break the relay
            broken = True

    return watch


def _error(status: int, kind: str, message: str, fmt: str = "anthropic") -> JSONResponse:
    # Each format's own error shape, so the caller's SDK reads a refusal as an error.
    if fmt == "openai":
        error = {"message": message, "type": kind, "param": None, "code": None}
        return JSONResponse({"error": error}, status_code=status)
    return JSONResponse(
        {"type": "error", "error": {"type": kind, "message": message}}, status_code=status
    )


def _bad_gateway(message: str, fmt: str = "anthropic") -> JSONResponse:
    return _error(502, "api_error", message, fmt)


def _has_body(request: Request) -> bool:
    return "content-length" in request.headers or "transfer-encoding" in request.headers


def _inspected(*paths: str) -> bool:
    """Whether any spelling of these paths could reach an endpoint that takes a turn.

    Read the way a lenient edge might: percent-decoded again, backslashes as
    slashes, ";params" dropped, dot segments and repeated slashes resolved, case
    ignored. Wrongly checking a path costs a few milliseconds; wrongly skipping
    one sends text out unchecked.
    """
    for path in paths:
        path = unquote(path).replace("\\", "/").split(";")[0]
        # normpath keeps a leading "//" (POSIX allows it to mean something else).
        path = posixpath.normpath("/" + path.lstrip("/")).lower()
        if path in (MESSAGES, COMPLETE, API_CHAT) or path.startswith(MESSAGES + "/"):
            return True
    return False


def _refused(reason: str, fmt: str = "anthropic") -> JSONResponse:
    # Names the detection type only: the caller already has the text, and the
    # message may be shown or logged somewhere the text shouldn't be.
    return _error(400, "invalid_request_error", f"privacy-proxy: refused ({reason})", fmt)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    parsed = dict(pairs)
    if len(parsed) != len(pairs):
        raise ValueError("duplicate key")
    return parsed


def _parse(body: bytes) -> dict | None:
    """A Messages body as JSON, or None when it can't be read the one way upstream will."""
    try:
        # A key given twice could be read one way here and the other way upstream.
        parsed = json.loads(body, object_pairs_hook=_unique_keys)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _unpriced(body: dict, fmt: str = "anthropic") -> str | None:
    """The first field or server tool in ``body`` the API lane can't price, if any."""
    if fmt == "openai":
        return _openai_unpriced(body)
    for name in body:
        if name in API_UNPRICED_FIELDS:
            return name
    tools = body.get("tools")
    for tool in tools if isinstance(tools, list) else []:
        kind = tool.get("type") if isinstance(tool, dict) else None
        if isinstance(kind, str) and kind.startswith(API_UNPRICED_TOOLS):
            return kind[:64]
    return None


def _openai_unpriced(body: dict) -> str | None:
    for name in body:
        if name in OPENAI_UNPRICED_FIELDS:
            return name
    # A stream named any other way than true or false could stream with no usage.
    if not isinstance(body.get("stream", False), bool):
        return "stream"
    if body.get("store") not in (None, False):
        return "store"
    tier = body.get("service_tier")
    if tier is not None and tier not in OPENAI_PRICED_TIERS:
        return "service_tier"
    modalities = body.get("modalities")
    if isinstance(modalities, list) and "audio" in modalities:
        return "audio"
    tools = body.get("tools")
    for tool in tools if isinstance(tools, list) else []:
        kind = tool.get("type") if isinstance(tool, dict) else None
        if not (isinstance(kind, str) and kind in OPENAI_PRICED_TOOLS):
            return str(kind)[:64]
    messages = body.get("messages")
    for message in messages if isinstance(messages, list) else []:
        content = message.get("content") if isinstance(message, dict) else None
        for part in content if isinstance(content, list) else []:
            kind = part.get("type") if isinstance(part, dict) else None
            if isinstance(kind, str) and kind in OPENAI_UNPRICED_PARTS:
                return kind
    return None


def _usage_forced(parsed: dict) -> bytes:
    """A streamed OpenAI-format body that asks for usage in its last chunk.

    Without ``stream_options.include_usage`` a stream reports no usage at all, and
    every call would be priced by estimate. Re-encoded from what was checked, so what
    goes on is what the Detectors read.
    """
    options = parsed.get("stream_options")
    parsed["stream_options"] = {
        **(options if isinstance(options, dict) else {}),
        "include_usage": True,
    }
    return json.dumps(parsed).encode("utf-8")


def _exact_float(text: str) -> float:
    """A JSON number as a float, only when the float holds every digit that was sent.

    The Detectors read a number as Python prints it; digits past a float's 17 would
    go on to the provider without ever being read.
    """
    digits = text.lower().split("e")[0].lstrip("-").replace(".", "").strip("0")
    value = float(text)
    if len(digits) > 17 or not math.isfinite(value):
        raise ValueError("number not held exactly")
    return value


def _no_constant(name: str):
    raise ValueError(f"{name} is not JSON")


def _api_parse(body: bytes) -> dict | None:
    """``_parse``, plus top-level keys in lower case only, and only exact numbers.

    Every field of both formats is lower case. A provider whose decoder matches field
    names without case ("Model" for "model") could otherwise serve a model other than
    the one checked against the key's list, or a feature checked under another name.
    """
    try:
        parsed = json.loads(
            body,
            object_pairs_hook=_unique_keys,
            parse_float=_exact_float,
            parse_constant=_no_constant,
        )
    except ValueError:
        return None
    if not isinstance(parsed, dict) or any(k != k.lower() for k in parsed):
        return None
    return parsed


async def _read_capped(request: Request, limit: int) -> bytes | None:
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def _ms_since(start: float) -> int:
    return round((time.monotonic() - start) * 1000)


def _check(scanner: Scanner, body: bytes) -> list[Detection]:
    """The Detections in a Messages body; a body that can't be read refuses too."""
    parsed = _parse(body)
    if parsed is None:
        return [Detection("UNREADABLE_BODY", None)]
    # Anthropic is a Trusted provider: a PDF's text is read, an image passes (#10).
    return scanner.check(parsed, trusted=True)


def create_app(
    scanner: Scanner,
    upstream: str = ANTHROPIC,
    transport: httpx.AsyncBaseTransport | None = None,
    log: TextIO = sys.stdout,
    api: ApiLane | None = None,
) -> Starlette:
    def new_client(base_url: str = "") -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=TIMEOUT,
            # Never HTTPS_PROXY, SSL_CERT_FILE or .netrc from the environment: one
            # stray variable would route the caller's login through another host.
            trust_env=False,
            # A Claude Code stream holds its connection for minutes; httpx's default
            # cap of 100 would turn a busy hour into 502s while Anthropic is up.
            limits=httpx.Limits(max_connections=None, max_keepalive_connections=20),
        )
        # httpx would otherwise add its own accept, accept-encoding, connection and
        # user-agent to every request; the caller's headers go out as they came.
        client.headers.clear()
        return client

    client = new_client(upstream)
    # The API lane builds each URL from its provider's base, so it has none.
    api_client = new_client()
    base_path = client.base_url.raw_path.rstrip(b"/")

    def write_log(
        request: Request,
        started: float,
        status: int | None,
        outcome: str,
        detections: list[Detection] | None = None,
        api_fields: dict | None = None,
        check_ms: int | None = None,
        upstream_ttfb_ms: int | None = None,
        cache: dict | None = None,
    ) -> None:
        # Built from an allow-list of fields, never by dumping headers: a header
        # value here would put the operator's login token into the log.
        session = request.headers.get("x-claude-code-session-id")
        line = {
            "time": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "session": session[:SESSION_ID_MAX] if session else None,
            "caller": request.client.host if request.client else None,
            "method": request.method,
            "path": request.url.path,
            "status": status,
            "outcome": outcome,
            "duration_ms": _ms_since(started),
            "lane": "subscription" if api_fields is None else "api",
        }
        # The Detectors' own time, and the wait for the provider's response headers:
        # what is left of duration_ms is reading the body and streaming the answer.
        if check_ms is not None:
            line["check_ms"] = check_ms
        if upstream_ttfb_ms is not None:
            line["upstream_ttfb_ms"] = upstream_ttfb_ms
        if api_fields is not None:
            line.update(api_fields)
        if cache:
            line.update(cache)
        if detections:
            line["detections"] = [{"type": d.type, "hash": d.hash} for d in detections]
        log.write(json.dumps(line) + "\n")
        log.flush()

    async def api_forward(request: Request, key: str, started: float) -> Response:
        fields: dict = {"key": None, "model": None, "provider": None}
        path = request.scope["path"]
        served = API_PATHS.get(path) if request.method == "POST" else None
        fmt = served[0] if served else "anthropic"
        timings: dict = {}
        # The Detections a Placeholder replaced: logged by kind and hash with the
        # request's line, like a refusal's.
        masked: list[Detection] = []

        def finish(status: int | None, outcome: str, detections=None) -> None:
            write_log(request, started, status, outcome, detections or masked, fields, **timings)

        def refuse(status: int, kind: str, message: str, outcome: str) -> Response:
            finish(status, outcome)
            return _error(status, kind, f"privacy-proxy: {message}", fmt)

        try:
            proxy_key_entry = api.keys.find(key) if api else None
            if proxy_key_entry is None:
                return refuse(401, "authentication_error", "invalid proxy key", "refused_key")
            fields["key"] = proxy_key_entry.name
            if served is None:
                return refuse(404, "not_found_error", "not served in the API lane", "refused_path")

            body = await _read_capped(request, API_BODY_MAX)
            if body is None:
                return refuse(413, "request_too_large", "request too large", "refused_size")
            parsed = None
            # check_ms counts the parse too, as the Subscription lane's _check does.
            checking = time.monotonic()
            if request.headers.get("content-encoding", "identity") == "identity":
                # Off the event loop: parsing a large body would stall every stream.
                parsed = await anyio.to_thread.run_sync(_api_parse, body)
            check_s = time.monotonic() - checking
            timings["check_ms"] = round(check_s * 1000)
            if parsed is None:
                finish(400, "refused", [Detection("UNREADABLE_BODY", None)])
                return _refused("UNREADABLE_BODY", fmt)
            model = parsed.get("model")
            if not isinstance(model, str):
                return refuse(400, "invalid_request_error", "no model named", "refused_model")
            route = api.providers.route(model)
            if model not in proxy_key_entry.models or route is None:
                # The name stays out of the log: off the list, it is unchecked body text.
                return refuse(
                    403, "permission_error", "model not allowed for this key", "refused_model"
                )
            fields["model"] = model
            fields["provider"] = route.provider.name
            base_url = route.provider.urls.get(fmt)
            if base_url is None:
                # No translation between formats: a provider is called only in a
                # format it serves itself.
                return refuse(
                    404,
                    "not_found_error",
                    f"model not served in the {fmt} format",
                    "refused_format",
                )
            when = month()
            if api.spend.month_to_date(proxy_key_entry.name, when) >= (
                proxy_key_entry.monthly_cap_usd
            ):
                return refuse(429, "rate_limit_error", "monthly cap reached", "refused_cap")
            unpriced = _unpriced(parsed, fmt)
            if unpriced:
                return refuse(
                    400,
                    "invalid_request_error",
                    f"{unpriced} is not served in the API lane",
                    "refused_feature",
                )

            if fmt == "openai" and parsed.get("stream") is True:
                body = await anyio.to_thread.run_sync(_usage_forced, parsed)

            # metadata, ids and numbers too: in this lane the body may go to a
            # provider that is not Trusted, and every byte of it goes on. Any image
            # or PDF to one is refused before anything is read (#10).
            def check(checked: dict) -> list[Detection]:
                return scanner.check(
                    checked, skip=frozenset(), strict=True, trusted=route.provider.trusted
                )

            def mask() -> tuple[dict, bytes, list[Detection]]:
                # Re-encoded from what is then checked, as _usage_forced does, and
                # checked again: only a masked body with nothing left in it goes on.
                rewritten, left = scanner.mask(parsed)
                encoded = json.dumps(rewritten).encode("utf-8")
                return rewritten, encoded, left or check(rewritten)

            checking = time.monotonic()
            detections = await anyio.to_thread.run_sync(check, parsed)
            kinds = scanner.policy.masked_entities()
            # Masking only when every Detection is of a kind set to mask: one from a
            # Detector that refuses, the Deny-list, or a body that couldn't be read
            # (too slow, a PDF, media to an untrusted provider) refuses as before.
            if detections and all(d.type in kinds for d in detections):
                rewritten, encoded, left = await anyio.to_thread.run_sync(mask)
                if not left:
                    masked.extend(detections)
                    fields["masked"] = True
                    parsed, body, detections = rewritten, encoded, []
                else:
                    # What a Placeholder could not replace: a key, an id, a number.
                    detections = left
            check_s += time.monotonic() - checking
            timings["check_ms"] = round(check_s * 1000)
            if detections:
                finish(400, "refused", detections)
                return _refused(", ".join(sorted({d.type for d in detections})), fmt)

            secret = api.secrets.get(route.provider.key_env)
            if not secret:
                # Removing a provider's key from the environment is the rollback: every
                # call to it is refused, and nothing goes elsewhere.
                return refuse(503, "api_error", "provider not configured", "provider_unconfigured")
            headers = [
                (name, value)
                for name, value in request.headers.raw
                if name.decode("latin-1").lower() in API_HEADERS[fmt]
            ]
            betas = [
                beta.strip()
                for value in request.headers.getlist("anthropic-beta")
                for beta in value.split(",")
                if fmt == "anthropic" and beta.strip() in route.provider.betas
            ]
            if betas:
                headers.append((b"anthropic-beta", ",".join(betas).encode("latin-1")))
            headers.append((b"accept-encoding", b"identity"))
            if fmt == "openai" or route.provider.auth == "bearer":
                headers.append((b"authorization", f"Bearer {secret}".encode("latin-1")))
            else:
                headers.append((b"x-api-key", secret.encode("latin-1")))
            base = httpx.URL(base_url)
            query = b""
            if fmt == "anthropic" and request.scope["query_string"] == API_QUERY:
                query = API_QUERY
            url = base.copy_with(
                raw_path=base.raw_path.rstrip(b"/")
                + served[1].encode("ascii")
                + (b"?" + query if query else b"")
            )
            sending = time.monotonic()
            upstream_response = await api_client.send(
                api_client.build_request("POST", url, headers=headers, content=body),
                stream=True,
            )
            timings["upstream_ttfb_ms"] = _ms_since(sending)
        except httpx.TransportError:
            finish(502, "upstream_unreachable")
            return _bad_gateway("The Privacy proxy could not reach the provider.", fmt)
        except ClientDisconnect:
            finish(None, "caller_gone")
            return Response(status_code=400)
        except Exception:  # noqa: BLE001 -- every other failure must still fail closed
            finish(502, "proxy_error")
            return _bad_gateway("The Privacy proxy could not forward this request.", fmt)
        except BaseException:
            finish(None, "caller_gone")
            raise

        if upstream_response.status_code in (401, 403):
            # The provider refused the proxy's own key. Its message may quote part of
            # that key, so the caller gets the proxy's error, not the provider's.
            with anyio.CancelScope(shield=True):
                await upstream_response.aclose()
            finish(upstream_response.status_code, "provider_auth")
            return _error(
                upstream_response.status_code,
                "authentication_error"
                if upstream_response.status_code == 401
                else "permission_error",
                "privacy-proxy: the provider refused the proxy's key",
                fmt,
            )

        meter = None
        if path in API_TURNS:
            content_type = upstream_response.headers.get("content-type", "")
            meter = Meter(streaming=content_type.startswith("text/event-stream"), fmt=fmt)

        def done(status: int, outcome: str) -> None:
            # Runs in _Relay's finally: nothing here may raise, or the log line and
            # the upstream close behind it would be skipped.
            try:
                if meter is not None:
                    # Anthropic's format names its bound `max_tokens` alone; OpenAI's
                    # newer name comes first, then the older one.
                    if fmt == "openai":
                        bounds = (parsed.get("max_completion_tokens"), parsed.get("max_tokens"))
                    else:
                        bounds = (parsed.get("max_tokens"),)
                    max_tokens = next(
                        (
                            b
                            for b in bounds
                            if isinstance(b, int) and not isinstance(b, bool) and b > 0
                        ),
                        0,
                    )
                    choices = parsed.get("n") if fmt == "openai" else 1
                    usage = meter.usage(
                        len(body),
                        answered=status == 200,
                        max_tokens=max_tokens,
                        choices=(
                            min(choices, OPENAI_CHOICES_MAX)
                            if isinstance(choices, int) and choices > 1
                            else 1
                        ),
                        max_out=route.max_out,
                    )
                    usd = route.price.cost(usage)
                    fields.update(meter.cache_log(usage))
                    fields.update(
                        tokens_in=usage.tokens_in,
                        tokens_out=usage.output_tokens,
                        usd=round(usd, 6),
                    )
                    if usage.estimated:
                        fields["estimated"] = True
                    if usd:
                        api.spend.add(proxy_key_entry.name, when, usd)
            except Exception:  # noqa: BLE001 -- the log line must still be written
                fields["spend_error"] = True
            finish(status, outcome)

        if meter is None:
            return _Relay(upstream_response, done, drop=API_RESPONSE_DROP)
        return _MeteredRelay(upstream_response, done, meter.feed, drop=API_RESPONSE_DROP)

    async def forward(request: Request) -> Response:
        started = time.monotonic()
        key = proxy_key(request.headers.raw)
        if key is not None:
            return await api_forward(request, key, started)
        timings: dict = {}
        try:
            raw_path = request.scope.get("raw_path") or request.url.path.encode()
            query = request.scope["query_string"]
            url = client.base_url.copy_with(
                raw_path=base_path + raw_path + (b"?" + query if query else b"")
            )
            # Streamed as it arrives; the caller's content-length goes with it, so
            # httpx doesn't switch to chunked. No length and no chunking means no
            # body, and none is invented.
            content = request.stream() if _has_body(request) else None
            # The path as received and as httpx will send it: httpx resolves dot
            # segments, so "/v1/./messages" reaches /v1/messages.
            sent_path = url.path.removeprefix(client.base_url.path.rstrip("/"))
            raw = request.scope.get("raw_path") or b""
            if content is not None and _inspected(
                request.scope["path"], raw.decode("latin-1"), sent_path
            ):
                # The whole body is needed to check it, and what goes on is these
                # same bytes. A compressed body can't be read, so it can't pass.
                content = await _read_capped(request, API_BODY_MAX)
                if content is None:
                    write_log(request, started, 413, "refused_size", **timings)
                    return _error(413, "request_too_large", "privacy-proxy: request too large")
                checking = time.monotonic()
                if request.headers.get("content-encoding", "identity") != "identity":
                    detections = [Detection("UNREADABLE_BODY", None)]
                else:
                    # Off the event loop: a megabyte takes a few hundred ms, and
                    # other sessions' streams keep flowing meanwhile.
                    detections = await anyio.to_thread.run_sync(_check, scanner, content)
                timings["check_ms"] = _ms_since(checking)
                if detections:
                    write_log(request, started, 400, "refused", detections, **timings)
                    return _refused(", ".join(sorted({d.type for d in detections})))
            sending = time.monotonic()
            upstream_response = await client.send(
                client.build_request(
                    request.method,
                    url,
                    headers=_forwardable(request.headers.raw, frozenset({"host"})),
                    content=content,
                ),
                stream=True,
            )
            timings["upstream_ttfb_ms"] = _ms_since(sending)
        except httpx.TransportError:
            write_log(request, started, 502, "upstream_unreachable", **timings)
            return _bad_gateway("The Privacy proxy could not reach Anthropic.")
        except ClientDisconnect:
            write_log(request, started, None, "caller_gone", **timings)
            return Response(status_code=400)
        except Exception:  # noqa: BLE001 -- every other failure must still fail closed
            # A request the proxy can't pass on as received (a URL httpx won't
            # build, a body longer than its content-length) still fails closed
            # and still leaves its log line.
            write_log(request, started, 502, "proxy_error", **timings)
            return _bad_gateway("The Privacy proxy could not forward this request.")
        except BaseException:
            write_log(request, started, None, "caller_gone", **timings)
            raise

        # A Messages answer is also read, for the cache counts in its log line only:
        # nothing is priced and the bytes relayed are the ones received.
        meter = watch = None
        if request.method == "POST" and request.scope["path"] == API_TURN:
            content_type = upstream_response.headers.get("content-type", "")
            meter = Meter(streaming=content_type.startswith("text/event-stream"))
            watch = _usage_watch(meter, upstream_response.headers.get("content-encoding", ""))

        def done(status: int, outcome: str) -> None:
            cache = None
            try:
                if watch is not None and status == 200:
                    cache = meter.cache_log(meter.usage(0, answered=True))
            except Exception:  # noqa: BLE001 -- the log line must still be written
                cache = None
            write_log(request, started, status, outcome, cache=cache, **timings)

        return _Relay(upstream_response, done, watch)

    @asynccontextmanager
    async def lifespan(app: Starlette):
        yield
        await client.aclose()
        await api_client.aclose()

    # `/{path:path}` matches `/` too: every path goes to Anthropic.
    return Starlette(routes=[Route("/{path:path}", forward, methods=METHODS)], lifespan=lifespan)
