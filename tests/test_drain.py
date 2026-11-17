"""#13: an API-lane answer whose caller hung up is read on for its usage, then priced."""

import asyncio
import io
import json

import httpx
import pytest
import yaml
from test_api_lane import DELTA as TEXT
from test_api_lane import MESSAGE_START, PROVIDER_KEYS, PROVIDERS_FILE, log_line
from test_api_lane import sse as anthropic_events
from test_openai_format import CHAT, DELTA, FINAL, KEYS, chat, chunks, openai_headers
from test_subscription_lane import SCANNER, Upstream

from privacy_proxy import app as app_module
from privacy_proxy import cli
from privacy_proxy.apilane import (
    ApiLane,
    ConfigError,
    Keys,
    Meter,
    Providers,
    Spend,
    month,
)
from privacy_proxy.app import create_app

FINISH = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": None}
LUNA_MAX_OUT = 128_000  # gpt-5.6-luna's max_out in providers.yaml
LUNA_OUT = 1.20  # USD per million output tokens


@pytest.fixture
def lane(tmp_path):
    spend = Spend(tmp_path / "spend.db")
    yield ApiLane(Keys.from_dict(KEYS), Providers.load(PROVIDERS_FILE), spend, PROVIDER_KEYS)
    spend.close()


class Paced(httpx.AsyncByteStream):
    """An answer whose chunks after the first ``prompt`` come only after a pause.

    ``tail`` repeats for ever once ``parts`` run out, as a stalled or runaway answer
    would; ``None`` ends the answer there.
    """

    def __init__(self, parts: list[bytes], prompt: int, pause=0.05, tail: bytes | None = None):
        self.parts, self.prompt, self.pause, self.tail = parts, prompt, pause, tail
        self.closed = False
        self.sent = 0

    async def __aiter__(self):
        for i, part in enumerate(self.parts):
            await asyncio.sleep(0 if i < self.prompt else self.pause)
            self.sent += len(part)
            yield part
        while self.tail is not None:
            await asyncio.sleep(0)
            self.sent += len(self.tail)
            yield self.tail

    async def aclose(self):
        self.closed = True


def sse(stream: httpx.AsyncByteStream) -> Upstream:
    return Upstream(
        lambda r: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
    )


async def hang_up(lane, upstream, body: bytes, after: int, spec: str = "2.3", path: str = CHAT):
    """One turn through ASGI whose caller leaves after ``after`` body chunks.

    OpenAI format by default; ``path="/v1/messages"`` makes it an Anthropic one.

    Under ASGI spec 2.3 (uvicorn's) Starlette hears the disconnect and cancels the
    response; under 2.4 the next send fails instead. Returns what reached the caller
    and the log.
    """
    log = io.StringIO()
    app = create_app(SCANNER, transport=upstream, log=log, api=lane)
    sent: list[bytes] = []
    requests = [{"type": "http.request", "body": body, "more_body": False}]
    gone = asyncio.Event()

    async def receive():
        if requests:
            return requests.pop()
        await gone.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if gone.is_set():
            if spec == "2.4":
                raise OSError("caller gone")
            return
        if message["type"] == "http.response.body" and message["body"]:
            sent.append(message["body"])
            if len(sent) >= after:
                gone.set()

    headers = [(k.encode(), v.encode()) for k, v in openai_headers().items()]
    headers.append((b"content-length", str(len(body)).encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": spec},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8787),
    }
    try:
        await asyncio.wait_for(app(scope, receive, send), timeout=5)
    except Exception as error:  # noqa: BLE001 -- 2.4 surfaces the hang-up as an error
        assert spec == "2.4", error
    return b"".join(sent), log


@pytest.mark.parametrize("spec", ["2.3", "2.4"])
async def test_hang_up_after_finish_reason_is_priced_from_the_usage_that_followed(lane, spec):
    # The usage chunk comes a moment after finish_reason, by when the caller has gone.
    stream = Paced(chunks(DELTA, FINISH, FINAL), prompt=2)
    body = chat(stream=True, max_completion_tokens=None)
    relayed, log = await hang_up(lane, sse(stream), body, after=2, spec=spec)

    assert b"completion_tokens" not in relayed  # read for its usage, never relayed
    line = log_line(log)
    assert line["outcome"] == "caller_gone"
    assert "estimated" not in line
    assert (line["tokens_in"], line["tokens_out"]) == (3000, 400)
    usd = (2000 * 0.20 + 1000 * 0.02 + 400 * LUNA_OUT) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)
    assert stream.closed


@pytest.mark.parametrize(
    ("bound", "tokens_out"),
    [({"max_completion_tokens": None}, 2 * LUNA_MAX_OUT), ({"max_completion_tokens": 500}, 1000)],
    ids=["unbounded-max_out", "bounded"],
)
async def test_no_usage_after_the_drain_charges_max_out_or_the_bound(lane, bound, tokens_out):
    # The answer ends with no usage chunk at all: nothing to price but the estimate.
    stream = Paced(chunks(DELTA, FINISH), prompt=2)
    body = chat(stream=True, n=2, **bound)
    _, log = await hang_up(lane, sse(stream), body, after=2)

    line = log_line(log)
    assert (line["outcome"], line["estimated"], line["tokens_out"]) == (
        "caller_gone",
        True,
        tokens_out,
    )
    assert lane.spend.month_to_date("smoke", month()) >= tokens_out * LUNA_OUT / 1e6


async def test_a_drain_past_its_time_limit_stops_and_is_estimated(lane, monkeypatch):
    monkeypatch.setattr(app_module, "DRAIN_SECONDS", 0.2)
    # After finish_reason the provider goes quiet and never sends the usage.
    stream = Paced(chunks(DELTA, FINISH, FINAL), prompt=2, pause=60)
    body = chat(stream=True, max_completion_tokens=None)
    _, log = await hang_up(lane, sse(stream), body, after=2)

    line = log_line(log)
    assert (line["outcome"], line["estimated"], line["tokens_out"]) == (
        "caller_gone",
        True,
        LUNA_MAX_OUT,
    )
    assert stream.closed


async def test_a_drain_past_its_byte_limit_stops_and_is_estimated(lane, monkeypatch):
    monkeypatch.setattr(app_module, "DRAIN_MAX_BYTES", 10_000)
    # A runaway answer that never ends and never reports its usage.
    filler = chunks(DELTA)[0]
    stream = Paced(chunks(DELTA, FINISH)[:2], prompt=2, tail=filler)
    body = chat(stream=True, max_completion_tokens=5000)
    _, log = await hang_up(lane, sse(stream), body, after=2)

    line = log_line(log)
    assert (line["outcome"], line["estimated"], line["tokens_out"]) == ("caller_gone", True, 5000)
    assert 10_000 <= stream.sent < 10_000 + 2 * len(filler) + 200
    assert stream.closed


HAIKU_OUT = 0.50  # USD per million output tokens


async def test_an_anthropic_drain_cut_before_its_final_delta_charges_the_bound(lane, monkeypatch):
    # #18: the caller leaves after message_start, and the drain stops at its byte
    # limit before message_delta: message_start's output count of 1 is not the price.
    monkeypatch.setattr(app_module, "DRAIN_MAX_BYTES", 10_000)
    filler = anthropic_events(TEXT)[0]
    stream = Paced(anthropic_events(MESSAGE_START, TEXT), prompt=2, tail=filler)
    body = json.dumps(
        {
            "model": "claude-haiku-5-5",
            "max_tokens": 5000,
            "stream": True,
            "messages": [{"role": "user", "content": "say ok"}],
        }
    ).encode()
    _, log = await hang_up(lane, sse(stream), body, after=2, path="/v1/messages")

    line = log_line(log)
    assert (line["outcome"], line["estimated"]) == ("caller_gone", True)
    assert (line["tokens_in"], line["tokens_out"]) == (3000, 5000)
    usd = (2000 * 0.10 + 1000 * 0.01 + 5000 * HAIKU_OUT) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)
    assert stream.closed


async def test_a_caller_that_stays_gets_the_whole_answer_and_one_log_line(lane):
    stream = Paced(chunks(DELTA, FINISH, FINAL), prompt=2)
    relayed, log = await hang_up(lane, sse(stream), chat(stream=True), after=100)

    assert relayed == b"".join(chunks(DELTA, FINISH, FINAL))
    line = log_line(log)
    assert (line["outcome"], line["tokens_out"]) == ("complete", 400)


def test_with_no_bound_the_bytes_read_still_floor_the_estimate():
    meter = Meter(streaming=True, fmt="openai")
    meter.feed(b"data: " + b"x" * 4000 + b"\n")

    usage = meter.usage(request_bytes=0, answered=True, max_out=10)
    assert (usage.output_tokens, usage.estimated) == (meter.seen // 4, True)


@pytest.mark.parametrize("max_out", [None, 0, -1, "128000", 1.5, True])
def test_a_model_without_a_positive_max_out_stops_the_proxy_naming_it(
    monkeypatch, tmp_path, max_out
):
    config = yaml.safe_load(PROVIDERS_FILE.read_text())
    entry = config["providers"]["openai"]["models"]["gpt-5.4-nano"]
    if max_out is None:
        del entry["max_out"]
    else:
        entry["max_out"] = max_out
    with pytest.raises(ConfigError, match="gpt-5.4-nano"):
        Providers.from_dict(config)

    providers = tmp_path / "providers.yaml"
    providers.write_text(yaml.safe_dump(config))
    keys = tmp_path / "keys.yaml"
    keys.write_text(json.dumps(KEYS))
    monkeypatch.setenv("KEYS_PATH", str(keys))
    monkeypatch.setenv("PROVIDERS_PATH", str(providers))
    monkeypatch.setenv("SPEND_DB_PATH", str(tmp_path / "spend.db"))
    with pytest.raises(SystemExit, match="'gpt-5.4-nano': max_out"):
        cli.load_api_lane()


async def test_a_failure_of_the_proxys_own_is_not_blamed_on_the_provider(lane, monkeypatch):
    def broken(self, chunk):
        raise RuntimeError("meter bug")

    monkeypatch.setattr(Meter, "feed", broken)
    stream = Paced(chunks(DELTA, FINISH, FINAL), prompt=3)
    # The relay re-raises it to break the stream; hang_up's 2.4 mode absorbs that.
    relayed, log = await hang_up(lane, sse(stream), chat(stream=True), after=100, spec="2.4")

    assert relayed == b""
    assert log_line(log)["outcome"] == "proxy_error"
    assert stream.closed
