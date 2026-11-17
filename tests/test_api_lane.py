import asyncio
import io
import json
from pathlib import Path

import httpx
import pytest
import yaml
from test_subscription_lane import SCANNER, TOKEN, Chunks, Upstream, caller_headers

from privacy_proxy import cli
from privacy_proxy.apilane import (
    ApiLane,
    Keys,
    Meter,
    Providers,
    Spend,
    Usage,
    hash_key,
    month,
)
from privacy_proxy.app import create_app

# Test-only providers, with the untrusted ones the shipped providers.yaml leaves out.
PROVIDERS_FILE = Path(__file__).parent / "fixtures" / "providers.yaml"

# Made-up keys only: none of these is, or was, a real key.
SMOKE = "pp_smoke-test-key-that-must-never-be-logged"
CHEAP = "pp_cheap-test-key-with-a-tiny-cap"
PROVIDER_KEYS = {
    "ANTHROPIC_API_KEY": "sk-ant-api03-provider-key-that-must-never-leak",
    "DEEPSEEK_API_KEY": "sk-deepseek-provider-key-that-must-never-leak",
    "MOONSHOT_API_KEY": "sk-moonshot-provider-key-that-must-never-leak",
    "OPENAI_API_KEY": "sk-proj-openai-provider-key-that-must-never-leak",
}
PNR = "19121212-1212"

KEYS = {
    "keys": [
        {
            "name": "smoke",
            "sha256": hash_key(SMOKE),
            "models": ["claude-haiku-5-5", "deepseek-flash", "kimi-k3.1-pro", "unpriced-model"],
            "monthly_cap_usd": 5,
        },
        {
            "name": "cheap",
            "sha256": hash_key(CHEAP),
            "models": ["claude-haiku-5-5"],
            "monthly_cap_usd": 0.01,
        },
    ]
}


def turn(model="claude-haiku-5-5", text="say ok", **extra) -> bytes:
    body = {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": text}]}
    return json.dumps({**body, **extra}).encode()


def api_headers(key=SMOKE, scheme="x-api-key", **extra) -> dict[str, str]:
    credential = {"x-api-key": key} if scheme == "x-api-key" else {"authorization": f"Bearer {key}"}
    return {
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "accept-encoding": "gzip, br",
        **credential,
        **extra,
    }


def answer(usage=None, status=200) -> httpx.Response:
    body = {"type": "message", "content": [{"type": "text", "text": "ok"}]}
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(status, json=body)


@pytest.fixture
def lane(tmp_path):
    spend = Spend(tmp_path / "spend.db")
    yield ApiLane(Keys.from_dict(KEYS), Providers.load(PROVIDERS_FILE), spend, PROVIDER_KEYS)
    spend.close()


async def post(lane, upstream, body=None, path="/v1/messages", log=None, **headers):
    log = log if log is not None else io.StringIO()
    app = create_app(SCANNER, transport=upstream, log=log, api=lane)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.0.0.9", 52000)),
        base_url="http://proxy",
    ) as client:
        response = await client.post(
            path, headers=headers or api_headers(), content=body if body is not None else turn()
        )
    return response, log


def error_of(response: httpx.Response) -> tuple[int, str]:
    body = response.json()
    assert body["type"] == "error"
    return response.status_code, body["error"]["type"]


def log_line(log: io.StringIO) -> dict:
    (line,) = log.getvalue().splitlines()
    return json.loads(line)


async def test_wrong_proxy_key_is_401_and_nothing_is_sent(lane):
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, **api_headers(key="pp_not-a-key-anyone-holds"))

    assert error_of(response) == (401, "authentication_error")
    assert upstream.requests == []
    line = log_line(log)
    assert (line["lane"], line["outcome"], line["key"]) == ("api", "refused_key", None)


async def test_proxy_key_is_refused_when_the_api_lane_is_not_configured():
    upstream = Upstream(lambda r: answer())
    response, _ = await post(None, upstream)

    assert error_of(response) == (401, "authentication_error")
    assert upstream.requests == []


@pytest.mark.parametrize("model", ["claude-opus-5-5", "unpriced-model"])
async def test_model_off_the_list_or_unpriced_is_403(lane, model):
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, turn(model=model))

    assert error_of(response) == (403, "permission_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_model"


async def test_over_the_monthly_cap_is_429(lane):
    lane.spend.add("cheap", month(), 0.01)
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, **api_headers(key=CHEAP))

    assert error_of(response) == (429, "rate_limit_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_cap"


async def test_last_month_spend_does_not_count_against_the_cap(lane):
    lane.spend.add("cheap", "1999-12", 100.0)
    upstream = Upstream(lambda r: answer({"input_tokens": 3, "output_tokens": 1}))
    response, _ = await post(lane, upstream, **api_headers(key=CHEAP))

    assert response.status_code == 200


async def test_personnummer_is_refused_in_the_api_lane(lane):
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, turn(text=f"my number is {PNR}"))

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []
    line = log_line(log)
    assert line["outcome"] == "refused"
    assert line["detections"][0]["type"] == "SE_PERSONNUMMER"
    assert PNR not in log.getvalue()
    assert type(line["check_ms"]) is int
    assert 0 <= line["check_ms"] <= line["duration_ms"]
    assert "upstream_ttfb_ms" not in line


@pytest.mark.parametrize(
    "body",
    [b"not json", b'{"model": "claude-haiku-5-5", "model": "claude-opus-5-5"}'],
)
async def test_unreadable_body_is_refused(lane, body):
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, body)

    assert response.json()["error"]["message"] == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []
    line = log_line(log)
    assert 0 <= line["check_ms"] <= line["duration_ms"]
    assert "upstream_ttfb_ms" not in line


async def test_caller_credential_is_swapped_for_the_provider_key(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 10, "output_tokens": 2}))
    body = turn()
    response, _ = await post(lane, upstream, body, **api_headers(authorization=f"Bearer {TOKEN}"))

    assert response.status_code == 200
    (sent,) = upstream.requests
    assert str(sent.url) == "https://api.anthropic.com/v1/messages"
    assert sent.headers["x-api-key"] == PROVIDER_KEYS["ANTHROPIC_API_KEY"]
    assert "authorization" not in sent.headers
    assert sent.headers["accept-encoding"] == "identity"
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert upstream.bodies == [body]


async def test_bearer_proxy_key_picks_the_api_lane_too(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    response, log = await post(lane, upstream, **api_headers(scheme="bearer"))

    assert response.status_code == 200
    assert upstream.requests[0].headers["x-api-key"] == PROVIDER_KEYS["ANTHROPIC_API_KEY"]
    assert log_line(log)["lane"] == "api"


@pytest.mark.parametrize(
    ("model", "url", "header", "value"),
    [
        (
            "deepseek-flash",
            "https://api.deepseek.com/anthropic/v1/messages?beta=true",
            "x-api-key",
            PROVIDER_KEYS["DEEPSEEK_API_KEY"],
        ),
        (
            "kimi-k3.1-pro",
            "https://api.moonshot.ai/anthropic/v1/messages?beta=true",
            "authorization",
            f"Bearer {PROVIDER_KEYS['MOONSHOT_API_KEY']}",
        ),
    ],
)
async def test_other_providers_get_their_base_url_and_key(lane, model, url, header, value):
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    response, log = await post(lane, upstream, turn(model=model), path="/v1/messages?beta=true")

    assert response.status_code == 200
    (sent,) = upstream.requests
    assert str(sent.url) == url
    assert sent.headers[header] == value
    assert SMOKE not in str(sent.headers)
    assert log_line(log)["provider"] == model.split("-")[0].replace("kimi", "moonshot")


async def test_no_key_ever_appears_in_logs_or_responses(lane):
    leaky = {"input_tokens": 1, "output_tokens": 1}
    upstream = Upstream(lambda r: answer(leaky))
    outputs = []
    for body in (turn(), turn(model="claude-opus-5-5"), turn(text=PNR)):
        response, log = await post(lane, upstream, body)
        outputs += [log.getvalue(), response.text, str(response.headers)]
    response, log = await post(lane, upstream, **api_headers(key="pp_wrong-key"))
    outputs += [log.getvalue(), response.text]

    text = "\n".join(outputs)
    for secret in (*PROVIDER_KEYS.values(), SMOKE, "pp_wrong-key"):
        assert secret not in text
    assert "provider-key" not in repr(lane)


async def test_missing_provider_key_refuses_and_sends_nothing(lane):
    lane.secrets = {}
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream)

    assert error_of(response) == (503, "api_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "provider_unconfigured"


async def test_paths_other_than_messages_are_404(lane):
    upstream = Upstream(lambda r: answer())
    response, _ = await post(lane, upstream, path="/v1/messages/batches")

    assert error_of(response) == (404, "not_found_error")
    assert upstream.requests == []


async def test_count_tokens_is_checked_forwarded_and_not_billed(lane):
    upstream = Upstream(lambda r: httpx.Response(200, json={"input_tokens": 12}))
    response, log = await post(lane, upstream, path="/v1/messages/count_tokens")

    assert response.status_code == 200
    assert str(upstream.requests[0].url) == "https://api.anthropic.com/v1/messages/count_tokens"
    assert lane.spend.month_to_date("smoke", month()) == 0
    assert "usd" not in log_line(log)

    response, _ = await post(lane, upstream, turn(text=PNR), path="/v1/messages/count_tokens")
    assert response.status_code == 400


async def test_json_answer_usage_is_priced_and_recorded(lane):
    usage = {
        "input_tokens": 1_000_000,
        "output_tokens": 100_000,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }
    upstream = Upstream(lambda r: answer(usage))
    _, log = await post(lane, upstream)
    _, _ = await post(lane, upstream)

    # Haiku 5.5's long-prompt prices: $0.50 in, $2.50 out per MTok.
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(2 * (0.50 + 0.25))
    line = log_line(log)
    assert (line["key"], line["model"], line["provider"]) == (
        "smoke",
        "claude-haiku-5-5",
        "anthropic",
    )
    assert (line["tokens_in"], line["tokens_out"], line["usd"]) == (1_000_000, 100_000, 0.75)
    assert line["outcome"] == "complete"


def sse(*events: dict) -> list[bytes]:
    return [f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events]


MESSAGE_START = {
    "type": "message_start",
    "message": {
        "id": "msg_01",
        "usage": {"input_tokens": 2000, "cache_read_input_tokens": 1000, "output_tokens": 1},
    },
}
DELTA = {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "ok"}}
MESSAGE_DELTA = {"type": "message_delta", "delta": {}, "usage": {"output_tokens": 400}}


def stream_upstream(chunks: list[bytes]) -> Upstream:
    return Upstream(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=Chunks(chunks)
        )
    )


async def test_streamed_usage_comes_from_message_start_and_the_final_delta(lane):
    events = sse(MESSAGE_START, DELTA, MESSAGE_DELTA, {"type": "message_stop"})
    # Split mid-event, as the network does.
    raw = b"".join(events)
    chunks = [raw[i : i + 7] for i in range(0, len(raw), 7)]
    response, log = await post(lane, stream_upstream(chunks), turn(stream=True))

    assert response.content == raw
    usd = (2000 * 0.10 + 1000 * 0.01 + 400 * 0.50) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)
    line = log_line(log)
    assert (line["tokens_in"], line["tokens_out"]) == (3000, 400)


class CutOff(httpx.AsyncByteStream):
    async def __aiter__(self):
        for chunk in sse(MESSAGE_START, DELTA):
            await asyncio.sleep(0)
            yield chunk
        raise httpx.RemoteProtocolError("peer closed connection")


async def test_stream_cut_before_its_final_delta_charges_the_bound_for_output(lane):
    # #18: message_start's output count (about 1) is not the answer's; with no
    # message_delta the output is charged at the request's bound, the input as sent.
    upstream = Upstream(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=CutOff()
        )
    )
    log = io.StringIO()
    with pytest.raises(httpx.RemoteProtocolError):
        await post(lane, upstream, turn(stream=True, max_tokens=1000), log=log)

    line = log_line(log)
    assert (line["outcome"], line["estimated"]) == ("upstream_error", True)
    assert (line["tokens_in"], line["tokens_out"]) == (3000, 1000)
    usd = (2000 * 0.10 + 1000 * 0.01 + 1000 * 0.50) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)


async def test_anthropic_bound_is_max_tokens_whatever_else_the_body_carries(lane):
    # #22: `max_completion_tokens` is OpenAI's name; an Anthropic-format call is not
    # bounded by it, so a caller cannot shrink the estimate with it.
    upstream = Upstream(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=CutOff()
        )
    )
    log = io.StringIO()
    with pytest.raises(httpx.RemoteProtocolError):
        await post(
            lane, upstream, turn(stream=True, max_tokens=1000, max_completion_tokens=1), log=log
        )

    assert log_line(log)["tokens_out"] == 1000


@pytest.mark.parametrize("n", [10**6, 10**400])
async def test_a_huge_n_without_usage_is_priced_at_128_choices(lane, n):
    # #22: with no usage, bound x n is the estimate; an unbounded n overflowed the price.
    body = json.dumps(
        {
            "model": "deepseek-flash",
            "max_completion_tokens": 100,
            "n": n,
            "messages": [{"role": "user", "content": "say ok"}],
        }
    ).encode()
    upstream = Upstream(lambda r: httpx.Response(200, json={"choices": []}))
    response, log = await post(lane, upstream, body, path="/v1/chat/completions")

    line = log_line(log)
    assert response.status_code == 200
    assert "spend_error" not in line
    assert (line["estimated"], line["tokens_out"]) == (True, 128 * 100)
    assert lane.spend.month_to_date("smoke", month()) > 0


@pytest.mark.parametrize(
    ("bounds", "tokens_out"),
    [
        ({"max_tokens": 50}, 50),
        ({"max_completion_tokens": 100, "max_tokens": 50}, 100),
        ({"max_completion_tokens": 0, "max_tokens": 50}, 50),
        ({"max_completion_tokens": True, "max_tokens": 50}, 50),
    ],
)
async def test_openai_bound_is_max_completion_tokens_then_max_tokens(lane, bounds, tokens_out):
    body = json.dumps(
        {"model": "deepseek-flash", "messages": [{"role": "user", "content": "say ok"}], **bounds}
    ).encode()
    upstream = Upstream(lambda r: httpx.Response(200, json={"choices": []}))
    _, log = await post(lane, upstream, body, path="/v1/chat/completions")

    assert log_line(log)["tokens_out"] == tokens_out


def test_a_cut_stream_whose_answer_outran_its_bound_is_charged_its_bytes():
    meter = Meter(streaming=True)
    events = sse(MESSAGE_START, *[DELTA] * 50)
    for chunk in events:
        meter.feed(chunk)

    usage = meter.usage(request_bytes=0, answered=True, max_tokens=16, max_out=128_000)
    assert usage.estimated
    assert usage.output_tokens == len(b"".join(events)) // 4 > 16
    assert (usage.input_tokens, usage.cache_read_tokens) == (2000, 1000)


def test_a_final_delta_without_an_output_count_does_not_end_the_answer():
    meter = Meter(streaming=True)
    for chunk in sse(MESSAGE_START, DELTA, {"type": "message_delta", "usage": {}}):
        meter.feed(chunk)

    usage = meter.usage(request_bytes=0, answered=True, max_tokens=1000)
    assert (usage.output_tokens, usage.estimated) == (1000, True)


def test_a_bound_past_the_models_max_out_is_charged_at_max_out():
    meter = Meter(streaming=True)
    for chunk in sse(MESSAGE_START, DELTA):
        meter.feed(chunk)

    usage = meter.usage(request_bytes=0, answered=True, max_tokens=10**400, max_out=128_000)
    assert (usage.output_tokens, usage.estimated) == (128_000, True)


def test_a_stream_that_reaches_its_final_delta_is_not_estimated():
    meter = Meter(streaming=True)
    for chunk in sse(MESSAGE_START, DELTA, MESSAGE_DELTA):
        meter.feed(chunk)

    usage = meter.usage(request_bytes=0, answered=True, max_tokens=128_000)
    assert not usage.estimated
    assert (usage.input_tokens, usage.output_tokens) == (2000, 400)


async def test_answer_without_usage_is_estimated_from_the_input(lane):
    body = turn(text="x" * 4000)
    response, log = await post(lane, Upstream(lambda r: answer()), body)

    assert response.status_code == 200
    line = log_line(log)
    assert line["estimated"] is True
    assert line["tokens_in"] == len(body) // 4
    assert lane.spend.month_to_date("smoke", month()) > 0


async def test_upstream_error_costs_nothing(lane):
    upstream = Upstream(
        lambda r: httpx.Response(
            529, json={"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}
        )
    )
    response, log = await post(lane, upstream)

    assert response.status_code == 529
    assert lane.spend.month_to_date("smoke", month()) == 0
    assert log_line(log)["usd"] == 0


async def test_request_without_a_proxy_key_stays_in_the_subscription_lane(lane):
    upstream = Upstream(lambda r: httpx.Response(200, json={"ok": True}))
    response, log = await post(lane, upstream, b"{}", **caller_headers())

    assert response.status_code == 200
    (sent,) = upstream.requests
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert "x-api-key" not in sent.headers
    line = log_line(log)
    assert line["lane"] == "subscription"
    assert "key" not in line and "usd" not in line
    assert lane.spend.month_to_date("smoke", month()) == 0


def test_meter_ignores_events_that_carry_no_usage():
    meter = Meter(streaming=True)
    for chunk in sse(DELTA, {"type": "ping"}):
        meter.feed(chunk)
    meter.feed(b'data: {"type": "message_delta", "usage": "nonsense"}\n')
    meter.feed(b"data: {not json\n")

    # With no bound named, the bytes relayed are the floor for the output.
    assert meter.usage(request_bytes=400, answered=True) == Usage(
        input_tokens=100, output_tokens=meter.seen // 4, estimated=True
    )


def test_repo_providers_price_every_model_a_smoke_key_needs():
    providers = Providers.load(PROVIDERS_FILE)
    for model in ("claude-haiku-5-5", "deepseek-flash", "kimi-k3.1-pro"):
        assert providers.route(model) is not None
    assert providers.route("gpt-5") is None
    assert providers.key_envs == set(PROVIDER_KEYS)


@pytest.mark.parametrize(
    "entry",
    [
        {"sha256": "abc"},
        {"monthly_cap_usd": -1},
        {"models": "claude-haiku-5-5"},
    ],
)
def test_bad_keys_file_is_rejected(entry):
    good = {"name": "a", "sha256": "0" * 64, "models": [], "monthly_cap_usd": 1}
    with pytest.raises(ValueError):
        Keys.from_dict({"keys": [{**good, **entry}]})


def test_new_key_prints_a_proxy_key_and_only_its_hash_for_the_file(capsys):
    cli.main(["new-key", "smoke"])
    out = capsys.readouterr().out

    key = next(word for word in out.split() if word.startswith("pp_"))
    assert len(key) > 40
    assert f"sha256: {hash_key(key)}" in out
    assert out.count(key) == 1


def test_api_lane_needs_a_spend_database(monkeypatch, tmp_path):
    keys = tmp_path / "keys.yaml"
    keys.write_text(json.dumps(KEYS))
    monkeypatch.setenv("KEYS_PATH", str(keys))
    monkeypatch.delenv("SPEND_DB_PATH", raising=False)
    with pytest.raises(SystemExit):
        cli.load_api_lane()

    monkeypatch.setenv("SPEND_DB_PATH", str(tmp_path / "spend.db"))
    for env in PROVIDER_KEYS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("PROVIDERS_PATH", str(PROVIDERS_FILE))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-test")
    monkeypatch.setenv("UNRELATED_SECRET", "nope")
    lane = cli.load_api_lane()
    assert lane.secrets == {"DEEPSEEK_API_KEY": "sk-deepseek-test"}
    lane.spend.close()


def test_unreadable_keys_file_stops_the_proxy_without_quoting_it(monkeypatch, tmp_path, capsys):
    keys = tmp_path / "keys.yaml"
    keys.write_text("keys: [ {name: secret-looking-line\n")
    monkeypatch.setenv("KEYS_PATH", str(keys))
    monkeypatch.setenv("SPEND_DB_PATH", str(tmp_path / "spend.db"))
    with pytest.raises(SystemExit) as stopped:
        cli.load_api_lane()
    assert "secret-looking-line" not in str(stopped.value)


async def test_personnummer_in_metadata_is_refused_in_the_api_lane(lane):
    upstream = Upstream(lambda r: answer())
    body = turn(model="deepseek-flash", metadata={"user_id": PNR})
    response, _ = await post(lane, upstream, body)

    assert response.status_code == 400
    assert upstream.requests == []


async def test_refused_model_name_stays_out_of_the_log(lane):
    response, log = await post(lane, Upstream(lambda r: answer()), turn(model=f"x {PNR}"))

    assert response.status_code == 403
    assert log_line(log)["model"] is None
    assert PNR not in log.getvalue()


async def test_only_listed_headers_and_the_beta_query_reach_the_provider(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    headers = api_headers(
        cookie="sessionKey=secret",
        **{"x-claude-code-session-id": "s-1", "user-agent": "claude-cli/2", "x-custom": "1"},
    )
    await post(lane, upstream, path="/v1/messages?note=19121212-1212", **headers)

    (sent,) = upstream.requests
    assert sorted(sent.headers) == [
        "accept",
        "accept-encoding",
        "anthropic-version",
        "content-length",
        "content-type",
        "host",
        "x-api-key",
    ]
    assert str(sent.url) == "https://api.anthropic.com/v1/messages"


@pytest.mark.parametrize(
    "header",
    [
        {"authorization": f"Bearer\t{SMOKE}"},
        {"authorization": f"bearer   {SMOKE}"},
        {"x-api-key": f'"{SMOKE}"'},
        {"x-api-key": SMOKE.upper()},
    ],
)
async def test_oddly_spelled_proxy_keys_never_reach_the_subscription_lane(lane, header):
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    _, log = await post(lane, upstream, **{"content-type": "application/json", **header})

    assert log_line(log)["lane"] == "api"
    assert all(SMOKE.lower() not in str(r.headers).lower() for r in upstream.requests)


async def test_web_searches_are_priced_on_top_of_tokens(lane):
    usage = {"input_tokens": 0, "output_tokens": 0, "server_tool_use": {"web_search_requests": 3}}
    _, log = await post(lane, Upstream(lambda r: answer(usage)))

    assert log_line(log)["usd"] == pytest.approx(0.03)


async def test_deeply_nested_answer_still_logs_closes_and_estimates(lane):
    nested = b'{"usage": ' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    upstream = Upstream(
        lambda r: httpx.Response(200, headers={"content-type": "application/json"}, content=nested)
    )
    response, log = await post(lane, upstream)

    assert response.status_code == 200
    line = log_line(log)
    assert line["estimated"] is True
    assert lane.spend.month_to_date("smoke", month()) > 0


def test_a_counter_reported_as_zero_later_does_not_erase_it():
    meter = Meter(streaming=True)
    for chunk in sse(
        MESSAGE_START,
        {"type": "message_delta", "usage": {"input_tokens": 0, "output_tokens": 9}},
    ):
        meter.feed(chunk)

    usage = meter.usage(request_bytes=0, answered=True)
    assert (usage.input_tokens, usage.output_tokens) == (2000, 9)


@pytest.mark.parametrize("cap", [float("nan"), float("inf"), ".nan"])
def test_cap_must_be_a_finite_amount(cap):
    entry = {"name": "a", "sha256": "0" * 64, "models": [], "monthly_cap_usd": cap}
    with pytest.raises(ValueError):
        Keys.from_dict({"keys": [entry]})


def test_answer_never_read_is_charged_its_full_max_tokens():
    # A caller that hangs up before a non-streamed answer arrives: the meter saw nothing.
    usage = Meter(streaming=False).usage(request_bytes=400, answered=True, max_tokens=128_000)

    assert (usage.input_tokens, usage.output_tokens, usage.estimated) == (100, 128_000, True)


async def test_caller_gone_before_a_non_streamed_answer_is_priced_from_its_usage(lane):
    # Driven straight through ASGI: the caller disconnects before reading the body.
    # The answer is read on without it (#13), so its own usage prices it.
    log = io.StringIO()
    app = create_app(
        SCANNER,
        transport=Upstream(lambda r: answer({"input_tokens": 10, "output_tokens": 100_000})),
        log=log,
        api=lane,
    )
    body = turn(max_tokens=100_000)
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop() if messages else {"type": "http.disconnect"}

    async def send(message):
        pass

    headers = [(k.encode(), v.encode()) for k, v in api_headers().items()]
    headers.append((b"content-length", str(len(body)).encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/messages",
        "raw_path": b"/v1/messages",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8787),
    }
    # Starlette sees the disconnect and cancels the relay before the body is read.
    await app(scope, receive, send)

    line = log_line(log)
    assert line["outcome"] == "caller_gone"
    assert "estimated" not in line
    assert (line["tokens_in"], line["tokens_out"]) == (10, 100_000)
    usd = (10 * 0.10 + 100_000 * 0.50) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)


@pytest.mark.parametrize(
    "extra",
    [
        {"fallbacks": "default"},
        {"speed": "fast"},
        {"inference_geo": "us"},
        {"context_management": {"edits": []}},
        {"tools": [{"type": "advisor_20260301", "name": "advisor", "model": "claude-fable-5-1"}]},
        {"tools": [{"type": "code_execution_20260521", "name": "code_execution"}]},
    ],
)
async def test_features_billed_outside_the_price_table_are_refused(lane, extra):
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, turn(**extra))

    assert error_of(response) == (400, "invalid_request_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_feature"


async def test_only_listed_betas_reach_the_provider(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    await post(lane, upstream, **api_headers(**{"anthropic-beta": "fast-mode-2026-02-01"}))
    assert "anthropic-beta" not in upstream.requests[0].headers

    config = yaml.safe_load(PROVIDERS_FILE.read_text())
    config["providers"]["anthropic"]["betas"] = ["listed-beta"]
    lane.providers = Providers.from_dict(config)
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    await post(lane, upstream, **api_headers(**{"anthropic-beta": "advisor-x, listed-beta"}))
    assert upstream.requests[0].headers["anthropic-beta"] == "listed-beta"


async def test_one_hour_cache_writes_are_priced_at_their_own_rate(lane):
    usage = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 3000,
        "cache_creation": {"ephemeral_5m_input_tokens": 1000, "ephemeral_1h_input_tokens": 2000},
    }
    _, log = await post(lane, Upstream(lambda r: answer(usage)))

    assert log_line(log)["usd"] == pytest.approx((1000 * 0.125 + 2000 * 0.20) / 1e6)


@pytest.mark.parametrize(
    "extra",
    [
        {"tools": [{"name": "t", "input_schema": {"default": 191212121212}}]},
        {"metadata": {"user_id": 191212121212}},
        {"metadata": {"user_id": "x", "id": PNR}},
        {"system": [{"type": "text", "text": "hi", "params": {"metadata": PNR}}]},
    ],
)
async def test_numbers_ids_and_nested_metadata_are_checked_in_the_api_lane(lane, extra):
    upstream = Upstream(lambda r: answer())
    response, _ = await post(lane, upstream, turn(model="deepseek-flash", **extra))

    assert response.status_code == 400
    assert upstream.requests == []


async def test_top_level_keys_differing_only_in_case_are_refused(lane):
    body = b'{"model": "deepseek-flash", "Model": "deepseek-v4-pro", "messages": []}'
    upstream = Upstream(lambda r: answer())
    response, _ = await post(lane, upstream, body)

    assert response.json()["error"]["message"] == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []


async def test_oversized_body_is_refused_before_it_is_read_whole(lane, monkeypatch):
    monkeypatch.setattr("privacy_proxy.app.API_BODY_MAX", 1000)
    upstream = Upstream(lambda r: answer())
    response, log = await post(lane, upstream, turn(text="x" * 2000))

    assert error_of(response) == (413, "request_too_large")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_size"


async def test_account_details_in_the_answer_stay_with_the_proxy(lane):
    upstream = Upstream(
        lambda r: httpx.Response(
            200,
            headers=[
                ("anthropic-organization-id", "org-123"),
                ("set-cookie", "a=1"),
                ("request-id", "req_1"),
            ],
            json={"usage": {"input_tokens": 1, "output_tokens": 1}},
        )
    )
    response, _ = await post(lane, upstream)

    assert "anthropic-organization-id" not in response.headers
    assert "set-cookie" not in response.headers
    assert response.headers["request-id"] == "req_1"


async def test_proxy_key_after_a_comma_still_picks_the_api_lane(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 1, "output_tokens": 1}))
    _, log = await post(
        lane, upstream, **{"content-type": "application/json", "authorization": f"Bearer, {SMOKE}"}
    )

    assert log_line(log)["lane"] == "api"


@pytest.mark.parametrize(
    ("model", "priced"),
    [
        ("gpt-5.4-mini", True),
        ("gpt-5.4-mini-2026-03-17", True),
        ("gpt-5.4-mini-20260317", True),
        ("gpt-5.4-mini-search-preview", False),
        ("gpt-5.4-mini-audio-preview", False),
        ("gpt-5.6-sol-pro", False),
        ("gpt-5.6-sol-2026-13", False),
        ("gpt-5.6-sol-٢٠٢٦٠٣١٧", False),
        ("gpt-5.6-sol-2026-03-17-x", False),
    ],
)
def test_a_model_is_priced_by_its_name_or_dated_snapshot_only(model, priced):
    price = {"in": 1, "out": 1, "max_out": 1000}
    providers = Providers.from_dict(
        {
            "providers": {
                "openai": {
                    "urls": {"openai": "https://example.test"},
                    "key_env": "K",
                    "trusted": True,
                    "models": {"gpt-5.4-mini": price, "gpt-5.6-sol": price},
                }
            }
        }
    )
    assert (providers.route(model) is not None) is priced


@pytest.mark.parametrize(
    "text",
    [
        '- name: "smoke"\n  sha256: ' + "0" * 64 + "\n  models: []\n  monthly_cap_usd: 0\n",
        "",
        "keys:\n",
        "keys: {name: smoke}\n",
        "other: []\n",
    ],
    ids=["bare-list", "empty", "no-entries", "keys-not-a-list", "no-keys"],
)
def test_a_keys_file_without_its_keys_list_says_what_is_wrong(monkeypatch, tmp_path, text):
    keys = tmp_path / "keys.yaml"
    keys.write_text(text)
    monkeypatch.setenv("KEYS_PATH", str(keys))
    monkeypatch.setenv("SPEND_DB_PATH", str(tmp_path / "spend.db"))
    with pytest.raises(SystemExit) as stopped:
        cli.load_api_lane()
    assert str(stopped.value).endswith(
        'keys.yaml must be a mapping with a "keys:" list; see README "Getting a key"'
    )


def test_the_new_key_output_pasted_whole_loads(tmp_path, capsys):
    cli.main(["new-key", "smoke"])
    out = capsys.readouterr().out
    key = next(word for word in out.split() if word.startswith("pp_"))
    # Everything from "keys:" down, as the README says to paste it.
    pasted = out[out.index("\nkeys:\n") + 1 :]
    assert key not in pasted
    keys_file = tmp_path / "keys.yaml"
    keys_file.write_text(pasted)
    assert Keys.load(keys_file).find(key).models == frozenset()

    filled = pasted.replace("models: []", "models: [claude-haiku-5-5]").replace(
        "monthly_cap_usd: 0", "monthly_cap_usd: 5"
    )
    keys_file.write_text(filled)
    found = Keys.load(keys_file).find(key)
    assert (found.name, found.models, found.monthly_cap_usd) == (
        "smoke",
        frozenset({"claude-haiku-5-5"}),
        5.0,
    )


@pytest.mark.parametrize("streamed", [False, True])
async def test_forwarded_line_splits_the_check_from_the_wait_for_the_provider(lane, streamed):
    if streamed:
        upstream = stream_upstream(sse(MESSAGE_START, DELTA, MESSAGE_DELTA))
    else:
        upstream = Upstream(lambda r: answer({"input_tokens": 3, "output_tokens": 1}))
    response, log = await post(lane, upstream, turn(stream=streamed))

    assert response.status_code == 200
    line = log_line(log)
    assert line["outcome"] == "complete"
    for field in ("check_ms", "upstream_ttfb_ms"):
        assert type(line[field]) is int
        assert 0 <= line[field] <= line["duration_ms"]


async def test_cache_counts_are_logged_with_the_five_minute_and_one_hour_split(lane):
    usage = {
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_read_input_tokens": 500,
        "cache_creation_input_tokens": 3000,
        "cache_creation": {"ephemeral_5m_input_tokens": 1000, "ephemeral_1h_input_tokens": 2000},
    }
    _, log = await post(lane, Upstream(lambda r: answer(usage)))

    line = log_line(log)
    assert line["tokens_in"] == 3510  # unchanged: the cache counts are folded in
    assert (line["cache_read"], line["cache_write"]) == (500, 3000)
    assert (line["cache_write_5m"], line["cache_write_1h"]) == (1000, 2000)


async def test_cache_counts_without_a_split_log_no_split(lane):
    usage = {"input_tokens": 10, "output_tokens": 5, "cache_creation_input_tokens": 700}
    _, log = await post(lane, Upstream(lambda r: answer(usage)))

    line = log_line(log)
    assert (line["cache_read"], line["cache_write"]) == (0, 700)
    assert "cache_write_5m" not in line
    assert "cache_write_1h" not in line


async def test_usage_without_cache_logs_zero_cache_counts(lane):
    _, log = await post(lane, Upstream(lambda r: answer({"input_tokens": 10, "output_tokens": 5})))

    line = log_line(log)
    assert (line["cache_read"], line["cache_write"]) == (0, 0)


async def test_streamed_cache_counts_are_logged(lane):
    events = sse(MESSAGE_START, DELTA, MESSAGE_DELTA, {"type": "message_stop"})
    _, log = await post(lane, stream_upstream(events), turn(stream=True))

    line = log_line(log)
    assert (line["cache_read"], line["cache_write"]) == (1000, 0)
