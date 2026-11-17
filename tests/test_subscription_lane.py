import asyncio
import gzip
import io
import json
import socket

import httpx
import pytest

from privacy_proxy.app import create_app
from privacy_proxy.detection import Denylist, Scanner

# Made-up entries only: no test ever sees the Operator's real list (ADR-0006).
DENYLIST = Denylist.build(["Testa Testsson", "Påhittade vägen 7, 999 99 Ingenstans"])
SCANNER = Scanner(Denylist.from_dict(DENYLIST))

TOKEN = "sk-ant-oat01-test-token-that-must-never-be-logged"
BETA = "oauth-2025-04-20,interleaved-thinking-2025-05-14"
SESSION = "3f6c1d2e-session"


def caller_headers(**extra: str) -> dict[str, str]:
    return {
        "authorization": f"Bearer {TOKEN}",
        "anthropic-beta": BETA,
        "anthropic-version": "2023-06-01",
        "x-claude-code-session-id": SESSION,
        "content-type": "application/json",
        **extra,
    }


class Upstream(httpx.AsyncBaseTransport):
    """A stand-in for api.anthropic.com that records what reached it.

    Not httpx.MockTransport: that reads the whole response before returning it,
    which would hide whether the proxy streams.
    """

    def __init__(self, respond):
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self.respond = respond

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.bodies.append(await request.aread())
        response = self.respond(request)
        if isinstance(response.stream, httpx.ByteStream):
            # httpx reads a body given as bytes on the spot, as no real transport
            # does; hand it over unread, like the network would.
            response = httpx.Response(
                response.status_code,
                headers=response.headers.raw,
                stream=Chunks([response.content]),
            )
        return response


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(0)
            yield chunk


def proxied(upstream, log=None):
    app = create_app(SCANNER, transport=upstream, log=log or io.StringIO())
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.0.0.7", 51000)),
        base_url="http://proxy",
    )


async def test_headers_path_query_and_body_reach_anthropic_unchanged():
    upstream = Upstream(lambda r: httpx.Response(200, json={"ok": True}))
    body = b'{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"hi \\u00e9"}]}'
    async with proxied(upstream) as client:
        response = await client.post(
            "/v1/messages?beta=true",
            headers=caller_headers(connection="close", **{"user-agent": "claude-cli/2.1.0"}),
            content=body,
        )

    assert response.status_code == 200
    (sent,) = upstream.requests
    assert str(sent.url) == "https://api.anthropic.com/v1/messages?beta=true"
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert sent.headers["anthropic-beta"] == BETA
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert sent.headers["x-claude-code-session-id"] == SESSION
    assert upstream.bodies == [body]
    # Hop-by-hop headers stop here, and the proxy adds none of httpx's own.
    assert "connection" not in sent.headers
    assert sent.headers["user-agent"] == "claude-cli/2.1.0"
    assert sent.headers["host"] == "api.anthropic.com"


async def test_proxy_adds_no_headers_of_its_own():
    upstream = Upstream(lambda r: httpx.Response(200))
    async with proxied(upstream) as client:
        client.headers.clear()
        await client.get("/v1/models", headers={"authorization": f"Bearer {TOKEN}"})

    (sent,) = upstream.requests
    assert sorted(k.lower() for k in sent.headers) == ["authorization", "host"]


async def test_connection_named_headers_are_dropped():
    upstream = Upstream(lambda r: httpx.Response(200))
    async with proxied(upstream) as client:
        await client.get("/v1/models", headers=caller_headers(connection="x-hop", **{"x-hop": "1"}))

    (sent,) = upstream.requests
    assert "x-hop" not in sent.headers


SSE_EVENTS = [
    b'event: message_start\ndata: {"type":"message_start"}\n\n',
    b'event: ping\ndata: {"type": "ping"}\n\n',
    b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"ok"}}\n\n',
    b'event: ping\ndata: {"type": "ping"}\n\n',
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
]


async def drive(
    app, hang_up_after: int | None = None, raw_path: bytes = b"/v1/messages"
) -> list[dict]:
    """Run one POST through the ASGI app directly and return what it sent.

    httpx's ASGITransport buffers the whole body, which would hide whether the
    proxy streams. `hang_up_after` disconnects the caller once that many body
    chunks have arrived.
    """
    sent: list[dict] = []
    requests = [{"type": "http.request", "body": b"{}", "more_body": False}]
    hung_up = asyncio.Event()

    async def receive():
        if requests:
            return requests.pop()
        await hung_up.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)
        bodies = [m for m in sent if m["type"] == "http.response.body" and m["body"]]
        if hang_up_after is not None and len(bodies) >= hang_up_after:
            hung_up.set()

    headers = caller_headers(**{"content-length": "2"})
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/messages",
        "raw_path": raw_path,
        "query_string": b"",
        "root_path": "",
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8787),
    }
    await app(scope, receive, send)
    return sent


def sse_upstream(stream: httpx.AsyncByteStream) -> Upstream:
    return Upstream(
        lambda r: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
    )


async def test_sse_streams_back_chunk_by_chunk_with_pings_intact():
    upstream = sse_upstream(Chunks(SSE_EVENTS))
    sent = await drive(create_app(SCANNER, transport=upstream, log=io.StringIO()))

    start = sent[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 200
    chunks = [m["body"] for m in sent[1:] if m["type"] == "http.response.body" and m["body"]]
    assert len(chunks) > 1
    assert b"".join(chunks) == b"".join(SSE_EVENTS)
    assert b"".join(chunks).count(b"event: ping") == 2
    assert upstream.bodies == [b"{}"]


class Endless(httpx.AsyncByteStream):
    """An answer that keeps coming until someone closes it."""

    closed = False

    async def __aiter__(self):
        while True:
            await asyncio.sleep(0.01)
            yield b'event: ping\ndata: {"type": "ping"}\n\n'

    async def aclose(self):
        self.closed = True


async def test_caller_hanging_up_mid_stream_closes_upstream_and_logs_once():
    log = io.StringIO()
    stream = Endless()
    app = create_app(SCANNER, transport=sse_upstream(stream), log=log)

    await asyncio.wait_for(drive(app, hang_up_after=2), timeout=5)

    assert stream.closed
    (line,) = log.getvalue().splitlines()
    assert json.loads(line)["status"] == 200
    assert json.loads(line)["outcome"] == "caller_gone"


class Broken(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield SSE_EVENTS[0]
        raise httpx.RemoteProtocolError("peer closed connection")


async def test_upstream_failing_mid_stream_breaks_the_stream_and_logs_once():
    log = io.StringIO()
    app = create_app(SCANNER, transport=sse_upstream(Broken()), log=log)

    # The status has already gone out, so the error propagates and the server
    # aborts the connection instead of ending the stream as if it were whole.
    with pytest.raises(httpx.RemoteProtocolError):
        await drive(app)

    (line,) = log.getvalue().splitlines()
    assert json.loads(line)["outcome"] == "upstream_error"


async def test_upstream_path_prefix_is_kept():
    upstream = Upstream(lambda r: httpx.Response(200))
    app = create_app(SCANNER, upstream="https://gateway.test/anthropic/", transport=upstream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        await client.get("/v1/models?limit=1", headers=caller_headers())

    assert str(upstream.requests[0].url) == "https://gateway.test/anthropic/v1/models?limit=1"


async def test_compressed_response_passes_through_undecoded():
    payload = gzip.compress(b'{"ok": true}')
    upstream = Upstream(
        lambda r: httpx.Response(
            200,
            headers={"content-encoding": "gzip", "content-type": "application/json"},
            stream=Chunks([payload]),
        )
    )
    async with (
        proxied(upstream) as client,
        client.stream(
            "GET", "/v1/models", headers=caller_headers(**{"accept-encoding": "gzip"})
        ) as response,
    ):
        raw = b"".join([c async for c in response.aiter_raw()])

    assert response.headers["content-encoding"] == "gzip"
    assert raw == payload
    assert upstream.requests[0].headers["accept-encoding"] == "gzip"


async def test_upstream_status_and_repeated_headers_pass_through():
    upstream = Upstream(
        lambda r: httpx.Response(
            429,
            headers=[
                ("retry-after", "7"),
                ("set-cookie", "a=1"),
                ("set-cookie", "b=2"),
                ("connection", "keep-alive"),
            ],
            json={"type": "error", "error": {"type": "rate_limit_error", "message": "slow"}},
        )
    )
    async with proxied(upstream) as client:
        response = await client.post("/v1/messages", headers=caller_headers(), content=b"{}")

    assert response.status_code == 429
    assert response.headers["retry-after"] == "7"
    assert response.headers.get_list("set-cookie") == ["a=1", "b=2"]
    assert response.json()["error"]["type"] == "rate_limit_error"


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_upstream_down_gives_502_in_anthropic_error_shape():
    log = io.StringIO()
    app = create_app(SCANNER, upstream=f"http://127.0.0.1:{closed_port()}", log=log)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        response = await client.post("/v1/messages", headers=caller_headers(), content=b"{}")

    assert response.status_code == 502
    body = response.json()
    assert body["type"] == "error"
    assert body["error"]["type"] == "api_error"
    assert json.loads(log.getvalue())["status"] == 502


async def test_log_is_one_metadata_line_with_no_header_value():
    log = io.StringIO()
    upstream = Upstream(lambda r: httpx.Response(200, json={"content": "secret answer"}))
    async with proxied(upstream, log=log) as client:
        await client.post(
            "/v1/messages?beta=true",
            headers=caller_headers(cookie="sessionKey=cookie-secret"),
            content=b'{"messages":[{"content":"body-secret"}]}',
        )

    text = log.getvalue()
    lines = text.splitlines()
    assert len(lines) == 1
    line = json.loads(lines[0])
    assert set(line) == {
        "time",
        "session",
        "caller",
        "method",
        "path",
        "status",
        "outcome",
        "duration_ms",
        "lane",
        "check_ms",
        "upstream_ttfb_ms",
    }
    assert line["session"] == SESSION
    assert line["caller"] == "10.0.0.7"
    assert line["method"] == "POST"
    assert line["path"] == "/v1/messages"
    assert line["status"] == 200
    assert line["outcome"] == "complete"
    assert line["lane"] == "subscription"
    for secret in (TOKEN, "oauth-2025-04-20", "cookie-secret", "body-secret", "secret answer"):
        assert secret not in text


@pytest.mark.parametrize("session", [None, "x" * 1000])
async def test_session_id_is_optional_and_capped(session):
    log = io.StringIO()
    headers = caller_headers()
    del headers["x-claude-code-session-id"]
    if session:
        headers["x-claude-code-session-id"] = session
    async with proxied(Upstream(lambda r: httpx.Response(200)), log=log) as client:
        await client.get("/v1/models", headers=headers)

    logged = json.loads(log.getvalue())["session"]
    assert logged == (session[:128] if session else None)


async def test_environment_proxy_settings_are_ignored(monkeypatch):
    # A real network path: httpx ignores environment proxies whenever a
    # transport is injected, so a mock upstream would hide the setting.
    connections = []

    async def proxy_host(reader, writer):
        connections.append(await reader.read(1024))
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(proxy_host, "127.0.0.1", 0)
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    app = create_app(SCANNER, upstream=f"http://127.0.0.1:{closed_port()}", log=io.StringIO())
    async with (
        server,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://proxy"
        ) as client,
    ):
        response = await client.get("/v1/models", headers=caller_headers())

    # Upstream is down, so the proxy fails closed instead of taking the detour.
    assert response.status_code == 502
    assert connections == []


async def test_request_that_cannot_be_forwarded_fails_closed_and_is_logged():
    log = io.StringIO()
    upstream = Upstream(lambda r: httpx.Response(200))
    sent = await drive(create_app(SCANNER, transport=upstream, log=log), raw_path=b"/x#frag")

    assert sent[0]["status"] == 502
    assert upstream.requests == []
    line = json.loads(log.getvalue())
    assert (line["status"], line["outcome"]) == (502, "proxy_error")


class SlowHeaders(Upstream):
    """Anthropic taking a while before its response headers arrive."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Past the asserted 50 ms: a timer may fire a clock tick early.
        await asyncio.sleep(0.06)
        return await super().handle_async_request(request)


async def test_forwarded_line_splits_the_check_from_the_wait_for_anthropic():
    log = io.StringIO()
    upstream = SlowHeaders(lambda r: httpx.Response(200, json={"ok": True}))
    async with proxied(upstream, log=log) as client:
        await client.post("/v1/messages", headers=caller_headers(), content=b'{"messages":[]}')

    line = json.loads(log.getvalue())
    for field in ("check_ms", "upstream_ttfb_ms"):
        assert type(line[field]) is int
        assert 0 <= line[field] <= line["duration_ms"]
    assert line["upstream_ttfb_ms"] >= 50


async def test_refused_line_has_the_check_time_and_no_wait():
    log = io.StringIO()
    upstream = Upstream(lambda r: httpx.Response(200))
    async with proxied(upstream, log=log) as client:
        response = await client.post(
            "/v1/messages",
            headers=caller_headers(),
            content=b'{"messages":[{"role":"user","content":"Testa Testsson"}]}',
        )

    assert response.status_code == 400
    line = json.loads(log.getvalue())
    assert line["outcome"] == "refused"
    assert type(line["check_ms"]) is int
    assert 0 <= line["check_ms"] <= line["duration_ms"]
    assert "upstream_ttfb_ms" not in line


async def test_uninspected_line_has_the_wait_and_no_check_time():
    log = io.StringIO()
    async with proxied(Upstream(lambda r: httpx.Response(200)), log=log) as client:
        await client.get("/v1/models", headers=caller_headers())

    line = json.loads(log.getvalue())
    assert set(line) == {
        "time",
        "session",
        "caller",
        "method",
        "path",
        "status",
        "outcome",
        "duration_ms",
        "lane",
        "upstream_ttfb_ms",
    }
    assert 0 <= line["upstream_ttfb_ms"] <= line["duration_ms"]


CACHE_USAGE = {
    "input_tokens": 10,
    "output_tokens": 5,
    "cache_read_input_tokens": 500,
    "cache_creation_input_tokens": 3000,
    "cache_creation": {"ephemeral_5m_input_tokens": 1000, "ephemeral_1h_input_tokens": 2000},
}


async def post_turn(upstream) -> tuple[bytes, dict]:
    log = io.StringIO()
    async with proxied(upstream, log=log) as client:
        response = await client.post("/v1/messages", headers=caller_headers(), content=b"{}")
    return response.content, json.loads(log.getvalue())


async def test_json_answer_logs_cache_counts_and_relays_it_unchanged():
    body = json.dumps({"content": "answer", "usage": CACHE_USAGE}).encode()
    upstream = Upstream(
        lambda r: httpx.Response(200, headers={"content-type": "application/json"}, content=body)
    )
    relayed, line = await post_turn(upstream)

    assert relayed == body
    assert (line["cache_read"], line["cache_write"]) == (500, 3000)
    assert (line["cache_write_5m"], line["cache_write_1h"]) == (1000, 2000)
    assert "tokens_in" not in line
    assert "usd" not in line


async def test_streamed_answer_logs_cache_counts_without_buffering():
    start = {"type": "message_start", "message": {"usage": CACHE_USAGE}}
    delta = {"type": "message_delta", "delta": {}, "usage": {"output_tokens": 9}}
    events = [
        f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode()
        for e in (start, {"type": "ping"}, delta)
    ]
    upstream = sse_upstream(Chunks(events))
    relayed, line = await post_turn(upstream)

    assert relayed == b"".join(events)
    assert (line["cache_read"], line["cache_write"]) == (500, 3000)
    assert line["cache_write_1h"] == 2000


async def test_gzip_answer_logs_cache_counts_and_passes_through_compressed():
    payload = gzip.compress(json.dumps({"usage": {"cache_read_input_tokens": 42}}).encode())
    upstream = Upstream(
        lambda r: httpx.Response(
            200,
            headers={"content-encoding": "gzip", "content-type": "application/json"},
            stream=Chunks([payload]),
        )
    )
    log = io.StringIO()
    async with (
        proxied(upstream, log=log) as client,
        client.stream("POST", "/v1/messages", headers=caller_headers(), content=b"{}") as response,
    ):
        raw = b"".join([c async for c in response.aiter_raw()])

    assert raw == payload
    line = json.loads(log.getvalue())
    assert (line["cache_read"], line["cache_write"]) == (42, 0)


async def test_answer_without_usage_or_unreadable_encoding_logs_no_cache_fields():
    plain = Upstream(lambda r: httpx.Response(200, json={"content": "no usage here"}))
    _, line = await post_turn(plain)
    assert "cache_read" not in line

    brotli = Upstream(
        lambda r: httpx.Response(
            200, headers={"content-encoding": "br"}, stream=Chunks([b"\x0b\x02\x80binary"])
        )
    )
    _, line = await post_turn(brotli)
    assert "cache_read" not in line and line["status"] == 200


async def test_usage_without_cache_fields_logs_zeros():
    upstream = Upstream(lambda r: httpx.Response(200, json={"usage": {"input_tokens": 3}}))
    _, line = await post_turn(upstream)
    assert (line["cache_read"], line["cache_write"]) == (0, 0)


async def test_a_meter_that_raises_does_not_break_the_relay(monkeypatch):
    def broken(self, chunk):
        raise RuntimeError("meter bug")

    monkeypatch.setattr("privacy_proxy.app.Meter.feed", broken)
    body = json.dumps({"usage": CACHE_USAGE}).encode()
    upstream = Upstream(lambda r: httpx.Response(200, content=body))
    relayed, line = await post_turn(upstream)

    assert relayed == body
    assert line["status"] == 200 and line["outcome"] == "complete"
    assert "cache_read" not in line


def test_unzipping_stops_once_the_meter_is_past_its_cap(monkeypatch):
    import zlib

    from privacy_proxy.apilane import Meter
    from privacy_proxy.app import _usage_watch

    monkeypatch.setattr("privacy_proxy.apilane.JSON_USAGE_MAX", 1000)
    meter = Meter(streaming=False)
    watch = _usage_watch(meter, "gzip")
    zipper = zlib.compressobj(wbits=31)
    chunks = [zipper.compress(b" " * (4 << 20)) + zipper.flush(zlib.Z_SYNC_FLUSH) for _ in range(4)]
    watch(chunks[0])
    assert meter.overflowed
    seen = meter.seen
    for chunk in chunks[1:]:
        watch(chunk)

    assert meter.seen == seen


def test_unzipping_stops_once_the_total_passes_its_limit(monkeypatch):
    import zlib

    from privacy_proxy.apilane import Meter
    from privacy_proxy.app import _usage_watch

    monkeypatch.setattr("privacy_proxy.app.UNZIP_MAX", 1000)
    meter = Meter(streaming=True)
    watch = _usage_watch(meter, "gzip")
    zipper = zlib.compressobj(wbits=31)
    line = b"data: " + b"x" * 40 + b"\n"
    chunks = [zipper.compress(line * 100) + zipper.flush(zlib.Z_SYNC_FLUSH) for _ in range(4)]
    watch(chunks[0])
    assert not meter.overflowed
    seen = meter.seen
    assert seen > 1000
    for chunk in chunks[1:]:
        watch(chunk)

    assert meter.seen == seen


def test_a_chunk_unzipping_past_1_mib_still_yields_its_last_events_cache_count():
    import zlib

    from privacy_proxy.apilane import Meter
    from privacy_proxy.app import _usage_watch

    last = {"type": "message_delta", "usage": {"output_tokens": 5, "cache_read_input_tokens": 77}}
    body = b"data: " + b"x" * (3 << 20) + b"\n" + b"data: " + json.dumps(last).encode() + b"\n"
    meter = Meter(streaming=True)
    _usage_watch(meter, "gzip")(zlib.compress(body, wbits=31))

    assert meter.seen == len(body)
    assert meter.fields["cache_read_input_tokens"] == 77


# A body the lane checks is read whole first, so it is capped as the API lane's is
# (#54): Anthropic's own 32 MiB limit.
async def test_a_body_over_32_mib_is_refused_before_it_is_read_whole():
    log = io.StringIO()
    upstream = Upstream(lambda r: httpx.Response(200, json={"ok": True}))
    body = b'{"messages":[{"content":"' + b"a" * (32 * 1024 * 1024) + b'"}]}'
    body = body[: 32 * 1024 * 1024 + 1]
    async with proxied(upstream, log=log) as client:
        response = await client.post("/v1/messages", headers=caller_headers(), content=body)

    assert response.status_code == 413
    assert response.json()["error"]["type"] == "request_too_large"
    assert upstream.requests == []
    line = json.loads(log.getvalue())
    assert (line["status"], line["outcome"]) == (413, "refused_size")


@pytest.mark.parametrize("over", [0, 1])
async def test_the_cap_falls_one_byte_past_its_limit(monkeypatch, over):
    body = b'{"messages":[{"role":"user","content":"hi"}]}'
    monkeypatch.setattr("privacy_proxy.app.API_BODY_MAX", len(body) - over)
    upstream = Upstream(lambda r: httpx.Response(200, json={"ok": True}))
    async with proxied(upstream) as client:
        response = await client.post("/v1/messages", headers=caller_headers(), content=body)

    if over:
        assert response.status_code == 413
        assert upstream.requests == []
    else:
        assert response.status_code == 200
        assert upstream.bodies == [body]
