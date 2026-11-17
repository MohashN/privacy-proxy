"""The API lane's OpenAI format: #4's tests again, for ``/v1/chat/completions``."""

import asyncio
import io
import json

import httpx
import pytest
from test_api_lane import PNR, PROVIDER_KEYS, PROVIDERS_FILE, log_line
from test_subscription_lane import SCANNER, TOKEN, Chunks, Upstream, caller_headers

from privacy_proxy.apilane import (
    ApiLane,
    Keys,
    Meter,
    Providers,
    Spend,
    hash_key,
    month,
)
from privacy_proxy.app import create_app

# Made-up keys only: none of these is, or was, a real key.
SMOKE = "pp_openai-smoke-test-key-that-must-never-be-logged"
CHEAP = "pp_openai-cheap-test-key-with-a-tiny-cap"
CHAT = "/v1/chat/completions"

KEYS = {
    "keys": [
        {
            "name": "smoke",
            "sha256": hash_key(SMOKE),
            "models": [
                "gpt-5.6-luna",
                "deepseek-flash",
                "kimi-k3.1-pro",
                "claude-haiku-5-5",
                "unpriced-model",
            ],
            "monthly_cap_usd": 5,
        },
        {
            "name": "cheap",
            "sha256": hash_key(CHEAP),
            "models": ["gpt-5.6-luna"],
            "monthly_cap_usd": 0.01,
        },
    ]
}


def chat(model="gpt-5.6-luna", content="say ok", **extra) -> bytes:
    body = {
        "model": model,
        "max_completion_tokens": 16,
        "messages": [{"role": "user", "content": content}],
    }
    return json.dumps({**body, **extra}).encode()


def openai_headers(key=SMOKE, **extra) -> dict[str, str]:
    return {
        "authorization": f"Bearer {key}",
        "content-type": "application/json",
        "accept-encoding": "gzip, br",
        **extra,
    }


def completion(usage=None, status=200) -> httpx.Response:
    body = {
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
    }
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(status, json=body)


@pytest.fixture
def lane(tmp_path):
    spend = Spend(tmp_path / "spend.db")
    yield ApiLane(Keys.from_dict(KEYS), Providers.load(PROVIDERS_FILE), spend, PROVIDER_KEYS)
    spend.close()


async def post(lane, upstream, body=None, path=CHAT, log=None, **headers):
    log = log if log is not None else io.StringIO()
    app = create_app(SCANNER, transport=upstream, log=log, api=lane)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.0.0.9", 52000)),
        base_url="http://proxy",
    ) as client:
        response = await client.post(
            path, headers=headers or openai_headers(), content=body if body is not None else chat()
        )
    return response, log


def error_of(response: httpx.Response) -> tuple[int, str]:
    # OpenAI's error shape, so an OpenAI SDK reads the refusal as an error.
    body = response.json()
    assert "type" not in body
    return response.status_code, body["error"]["type"]


async def test_wrong_proxy_key_is_401_and_nothing_is_sent(lane):
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, **openai_headers(key="pp_not-a-key-anyone-holds"))

    assert error_of(response) == (401, "authentication_error")
    assert upstream.requests == []
    line = log_line(log)
    assert (line["lane"], line["outcome"], line["key"]) == ("api", "refused_key", None)


@pytest.mark.parametrize("model", ["gpt-5.6-sol", "unpriced-model"])
async def test_model_off_the_list_or_unpriced_is_403(lane, model):
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, chat(model=model))

    assert error_of(response) == (403, "permission_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_model"


async def test_over_the_monthly_cap_is_429(lane):
    lane.spend.add("cheap", month(), 0.01)
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, **openai_headers(key=CHEAP))

    assert error_of(response) == (429, "rate_limit_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_cap"


@pytest.mark.parametrize(
    "body",
    [
        chat(content=f"my number is {PNR}"),
        chat(content=[{"type": "text", "text": f"my number is {PNR}"}]),
        chat(
            model="deepseek-flash",
            messages=[
                {"role": "user", "content": "look it up"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": json.dumps({"pnr": PNR})},
                        }
                    ],
                },
            ],
        ),
        chat(model="kimi-k3.1-pro", user=PNR),
    ],
    ids=["string", "parts", "tool-call-arguments", "user-field"],
)
async def test_personnummer_is_refused_in_the_openai_format(lane, body):
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, body)

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []
    assert log_line(log)["detections"][0]["type"] == "SE_PERSONNUMMER"
    assert PNR not in log.getvalue()


@pytest.mark.parametrize(
    "body",
    [b"not json", b'{"model": "gpt-5.6-luna", "model": "gpt-5.6-sol"}'],
)
async def test_unreadable_body_is_refused(lane, body):
    upstream = Upstream(lambda r: completion())
    response, _ = await post(lane, upstream, body)

    assert response.json()["error"]["message"] == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []


async def test_caller_credential_is_swapped_for_the_provider_key(lane):
    upstream = Upstream(lambda r: completion({"prompt_tokens": 10, "completion_tokens": 2}))
    body = chat()
    headers = openai_headers(**{"openai-organization": "org-caller", "cookie": "a=1"})
    response, _ = await post(lane, upstream, body, **headers)

    assert response.status_code == 200
    (sent,) = upstream.requests
    assert str(sent.url) == "https://api.openai.com/v1/chat/completions"
    assert sent.headers["authorization"] == f"Bearer {PROVIDER_KEYS['OPENAI_API_KEY']}"
    assert sorted(sent.headers) == [
        "accept",
        "accept-encoding",
        "authorization",
        "content-length",
        "content-type",
        "host",
    ]
    assert sent.headers["accept-encoding"] == "identity"
    # A request that isn't streamed goes on byte for byte.
    assert upstream.bodies == [body]


async def test_x_api_key_proxy_key_picks_the_api_lane_too(lane):
    upstream = Upstream(lambda r: completion({"prompt_tokens": 1, "completion_tokens": 1}))
    headers = {"x-api-key": SMOKE, "content-type": "application/json"}
    response, log = await post(lane, upstream, **headers)

    assert response.status_code == 200
    assert "x-api-key" not in upstream.requests[0].headers
    assert log_line(log)["lane"] == "api"


@pytest.mark.parametrize(
    ("model", "url", "key_env", "provider"),
    [
        (
            "deepseek-flash",
            "https://api.deepseek.com/v1/chat/completions",
            "DEEPSEEK_API_KEY",
            "deepseek",
        ),
        (
            "kimi-k3.1-pro",
            "https://api.moonshot.ai/v1/chat/completions",
            "MOONSHOT_API_KEY",
            "moonshot",
        ),
    ],
)
async def test_other_providers_get_their_openai_url_and_key(lane, model, url, key_env, provider):
    upstream = Upstream(lambda r: completion({"prompt_tokens": 1, "completion_tokens": 1}))
    response, log = await post(lane, upstream, chat(model=model), path=f"{CHAT}?api-version=x")

    assert response.status_code == 200
    (sent,) = upstream.requests
    assert str(sent.url) == url
    assert sent.headers["authorization"] == f"Bearer {PROVIDER_KEYS[key_env]}"
    assert SMOKE not in str(sent.headers)
    assert log_line(log)["provider"] == provider


@pytest.mark.parametrize(
    ("model", "path"),
    [("claude-haiku-5-5", CHAT), ("gpt-5.6-luna", "/v1/messages")],
)
async def test_a_model_its_provider_does_not_serve_in_this_format_is_404(lane, model, path):
    upstream = Upstream(lambda r: completion())
    body = (
        chat(model=model)
        if path == CHAT
        else json.dumps(
            {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]}
        ).encode()
    )
    headers = (
        openai_headers()
        if path == CHAT
        else {"x-api-key": SMOKE, "content-type": "application/json"}
    )
    response, log = await post(lane, upstream, body, path=path, **headers)

    assert response.status_code == 404
    assert response.json()["error"]["type"] == "not_found_error"
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_format"


async def test_no_key_ever_appears_in_logs_or_responses(lane):
    upstream = Upstream(lambda r: completion({"prompt_tokens": 1, "completion_tokens": 1}))
    outputs = []
    for body in (chat(), chat(model="gpt-5.6-sol"), chat(content=PNR)):
        response, log = await post(lane, upstream, body)
        outputs += [log.getvalue(), response.text, str(response.headers)]
    response, log = await post(lane, upstream, **openai_headers(key="pp_wrong-key"))
    outputs += [log.getvalue(), response.text]

    text = "\n".join(outputs)
    for secret in (*PROVIDER_KEYS.values(), SMOKE, "pp_wrong-key"):
        assert secret not in text


async def test_missing_provider_key_refuses_and_sends_nothing(lane):
    lane.secrets = {}
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream)

    assert error_of(response) == (503, "api_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "provider_unconfigured"


@pytest.mark.parametrize(
    ("usage", "usd"),
    [
        # OpenAI: cached tokens are part of prompt_tokens. gpt-5.6-luna: $0.20 in,
        # $0.02 cached, $1.20 out per MTok.
        (
            {
                "prompt_tokens": 3000,
                "completion_tokens": 400,
                "prompt_tokens_details": {"cached_tokens": 1000},
            },
            (2000 * 0.20 + 1000 * 0.02 + 400 * 1.20) / 1e6,
        ),
        # Over 272,000 tokens in, the long-context prices: $0.40 in, $1.80 out.
        (
            {"prompt_tokens": 300_000, "completion_tokens": 1000},
            (300_000 * 0.40 + 1000 * 1.80) / 1e6,
        ),
    ],
)
async def test_json_answer_usage_is_priced_and_recorded(lane, usage, usd):
    _, log = await post(lane, Upstream(lambda r: completion(usage)))

    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)
    line = log_line(log)
    assert (line["key"], line["model"], line["provider"]) == ("smoke", "gpt-5.6-luna", "openai")
    assert line["tokens_in"] == usage["prompt_tokens"]
    assert line["tokens_out"] == usage["completion_tokens"]
    assert line["outcome"] == "complete"


async def test_deepseek_cache_hits_are_priced_as_cache_reads(lane):
    usage = {
        "prompt_tokens": 3000,
        "completion_tokens": 100,
        "prompt_cache_hit_tokens": 1000,
        "prompt_cache_miss_tokens": 2000,
    }
    await post(lane, Upstream(lambda r: completion(usage)), chat(model="deepseek-flash"))

    # deepseek-flash: $0.30 in, $0.006 cached, $1.20 out per MTok.
    usd = (2000 * 0.30 + 1000 * 0.006 + 100 * 1.20) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)


async def test_moonshot_cache_writes_are_priced_at_the_one_hour_rate(lane):
    usage = {
        "prompt_tokens": 3000,
        "completion_tokens": 100,
        "prompt_tokens_details": {"cached_tokens": 1000, "cache_write_tokens": 500},
    }
    _, log = await post(lane, Upstream(lambda r: completion(usage)), chat(model="kimi-k3.1-pro"))

    # kimi-k3.1-pro: $2.00 in, $0.20 cached, $4.00 per one-hour cache write, $10 out.
    usd = (1500 * 2.00 + 1000 * 0.20 + 500 * 4.00 + 100 * 10.00) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)
    assert log_line(log)["tokens_in"] == 3000


def chunks(*events) -> list[bytes]:
    return [f"data: {json.dumps(e)}\n\n".encode() for e in events] + [b"data: [DONE]\n\n"]


DELTA = {"choices": [{"index": 0, "delta": {"content": "ok"}}], "usage": None}
FINAL = {
    "choices": [],
    "usage": {
        "prompt_tokens": 3000,
        "completion_tokens": 400,
        "prompt_tokens_details": {"cached_tokens": 1000},
    },
}


def stream_upstream(parts: list[bytes]) -> Upstream:
    return Upstream(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=Chunks(parts)
        )
    )


async def test_streamed_request_is_made_to_report_usage_and_it_is_priced(lane):
    raw = b"".join(chunks(DELTA, DELTA, FINAL))
    upstream = stream_upstream([raw[i : i + 7] for i in range(0, len(raw), 7)])
    response, log = await post(
        lane, upstream, chat(stream=True, stream_options={"include_usage": False, "x": 1})
    )

    assert response.content == raw
    sent = json.loads(upstream.bodies[0])
    assert sent["stream_options"] == {"include_usage": True, "x": 1}
    assert sent["messages"] == json.loads(chat())["messages"]
    usd = (2000 * 0.20 + 1000 * 0.02 + 400 * 1.20) / 1e6
    assert lane.spend.month_to_date("smoke", month()) == pytest.approx(usd)
    assert (log_line(log)["tokens_in"], log_line(log)["tokens_out"]) == (3000, 400)


async def test_stream_options_is_added_when_the_caller_sent_none(lane):
    upstream = stream_upstream(chunks(FINAL))
    await post(lane, upstream, chat(stream=True))

    assert json.loads(upstream.bodies[0])["stream_options"] == {"include_usage": True}


class CutOff(httpx.AsyncByteStream):
    async def __aiter__(self):
        for chunk in chunks(DELTA)[:1]:
            await asyncio.sleep(0)
            yield chunk
        raise httpx.RemoteProtocolError("peer closed connection")


async def test_stream_cut_before_its_usage_is_charged_the_estimate(lane):
    upstream = Upstream(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=CutOff()
        )
    )
    log = io.StringIO()
    body = chat(stream=True, max_completion_tokens=1000)
    with pytest.raises(httpx.RemoteProtocolError):
        await post(lane, upstream, body, log=log)

    line = log_line(log)
    assert (line["outcome"], line["estimated"], line["tokens_out"]) == (
        "upstream_error",
        True,
        1000,
    )
    assert lane.spend.month_to_date("smoke", month()) >= 1000 * 1.20 / 1e6


def test_a_stream_whose_usage_is_only_null_is_estimated():
    meter = Meter(streaming=True, fmt="openai")
    meter.feed(b'data: {"choices": [], "usage": null}\n')

    usage = meter.usage(request_bytes=400, answered=True, max_tokens=50)
    assert (usage.input_tokens, usage.output_tokens, usage.estimated) == (100, 50, True)


async def test_upstream_error_costs_nothing(lane):
    upstream = Upstream(
        lambda r: httpx.Response(
            429, json={"error": {"type": "rate_limit_error", "message": "busy"}}
        )
    )
    response, log = await post(lane, upstream)

    assert response.status_code == 429
    assert lane.spend.month_to_date("smoke", month()) == 0
    assert log_line(log)["usd"] == 0


@pytest.mark.parametrize(
    "extra",
    [
        {"service_tier": "priority"},
        {"service_tier": "scale"},
        {"web_search_options": {}},
        {"audio": {"voice": "alloy", "format": "wav"}},
        {"modalities": ["text", "audio"]},
        {"tools": [{"type": "builtin_function", "function": {"name": "$web_search"}}]},
    ],
)
async def test_features_billed_outside_the_price_table_are_refused(lane, extra):
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, chat(**extra))

    assert error_of(response) == (400, "invalid_request_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_feature"


@pytest.mark.parametrize(
    "extra",
    [
        {"service_tier": "default"},
        {"service_tier": "flex"},
        {"tools": [{"type": "function", "function": {"name": "f", "parameters": {}}}]},
    ],
)
async def test_priced_tiers_and_function_tools_pass(lane, extra):
    upstream = Upstream(lambda r: completion({"prompt_tokens": 1, "completion_tokens": 1}))
    response, _ = await post(lane, upstream, chat(**extra))

    assert response.status_code == 200


async def test_request_without_a_proxy_key_stays_in_the_subscription_lane(lane):
    upstream = Upstream(lambda r: httpx.Response(404, json={"ok": False}))
    _, log = await post(lane, upstream, chat(), **caller_headers())

    (sent,) = upstream.requests
    assert str(sent.url) == "https://api.anthropic.com/v1/chat/completions"
    assert sent.headers["authorization"] == f"Bearer {TOKEN}"
    assert log_line(log)["lane"] == "subscription"
    assert lane.spend.month_to_date("smoke", month()) == 0


def test_repo_providers_price_an_openai_smoke_model():
    providers = Providers.load(PROVIDERS_FILE)
    route = providers.route("gpt-5.6-luna")
    assert route.provider.name == "openai"
    assert route.provider.urls == {"openai": "https://api.openai.com/v1"}
    assert set(providers.route("deepseek-flash").provider.urls) == {"anthropic", "openai"}
    # A plain "gpt-5" prefix would price gpt-5.5-pro at gpt-5's rates.
    assert providers.route("gpt-5.5-pro") is None


@pytest.mark.parametrize("path", [CHAT, "/v1/messages"])
@pytest.mark.parametrize("kind", ["base64", "redacted_thinking"])
async def test_an_opaque_type_does_not_hide_the_rest_of_the_body(lane, path, kind):
    body = json.loads(chat(model="deepseek-flash", content=f"my number is {PNR}"))
    body["type"] = kind
    body["messages"][0]["type"] = kind
    headers = (
        openai_headers()
        if path == CHAT
        else {"x-api-key": SMOKE, "content-type": "application/json"}
    )
    upstream = Upstream(lambda r: completion())
    response, _ = await post(lane, upstream, json.dumps(body).encode(), path=path, **headers)

    assert response.status_code == 400
    assert upstream.requests == []


@pytest.mark.parametrize(
    "body",
    [
        b'{"model": "gpt-5.6-luna", "Service_Tier": "priority", "messages": []}',
        b'{"model": "gpt-5.6-luna", "messages": [], "x": 1.00000000000000000191212121212}',
        b'{"model": "gpt-5.6-luna", "messages": [], "x": NaN}',
        b'{"model": "gpt-5.6-luna", "messages": [], "x": 1e999}',
    ],
    ids=["key-case", "digits-past-a-float", "nan", "infinity"],
)
async def test_a_body_read_another_way_upstream_is_refused(lane, body):
    upstream = Upstream(lambda r: completion())
    response, _ = await post(lane, upstream, body)

    assert response.json()["error"]["message"] == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []


@pytest.mark.parametrize(
    "extra",
    [
        {"stream": "true"},
        {"stream": 1},
        {"store": True},
        {"messages": [{"role": "user", "content": [{"type": "input_audio", "input_audio": {}}]}]},
    ],
    ids=["stream-string", "stream-number", "store", "input-audio"],
)
async def test_streams_storage_and_audio_the_lane_cannot_price_are_refused(lane, extra):
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, chat(**extra))

    assert error_of(response) == (400, "invalid_request_error")
    assert upstream.requests == []
    assert log_line(log)["outcome"] == "refused_feature"


async def test_an_estimate_counts_every_choice_and_takes_the_first_bound(lane):
    body = chat(n=3, max_completion_tokens=None, max_tokens=1000)
    _, log = await post(lane, Upstream(lambda r: completion()), body)

    line = log_line(log)
    assert (line["estimated"], line["tokens_out"]) == (True, 3000)


async def test_an_estimate_with_no_bound_charges_the_models_max_out(lane):
    # Hidden reasoning is never relayed, so the bytes relayed are only a floor (#13).
    raw = b"".join(chunks(*[DELTA] * 50))
    _, log = await post(lane, stream_upstream([raw]), chat(stream=True, max_completion_tokens=None))

    line = log_line(log)
    assert (line["estimated"], line["tokens_out"]) == (True, 128_000)


async def test_usage_inside_a_choice_is_read_too(lane):
    final = {
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop", "usage": FINAL["usage"]}],
    }
    _, log = await post(
        lane, stream_upstream(chunks(DELTA, final)), chat(model="kimi-k3.1-pro", stream=True)
    )

    line = log_line(log)
    assert "estimated" not in line
    assert (line["tokens_in"], line["tokens_out"]) == (3000, 400)


async def test_account_details_in_the_answer_stay_with_the_proxy(lane):
    upstream = Upstream(
        lambda r: httpx.Response(
            200,
            headers=[
                ("openai-organization", "org-123"),
                ("openai-project", "proj_123"),
                ("x-request-id", "req_1"),
            ],
            json={"usage": {"prompt_tokens": 1, "completion_tokens": 1}},
        )
    )
    response, _ = await post(lane, upstream)

    assert "openai-organization" not in response.headers
    assert "openai-project" not in response.headers
    assert response.headers["x-request-id"] == "req_1"


class Unreachable(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request):
        raise httpx.ConnectError("no route")


async def test_an_unreachable_provider_is_a_502_in_the_openai_shape(lane):
    response, log = await post(lane, Unreachable())

    assert error_of(response) == (502, "api_error")
    assert log_line(log)["outcome"] == "upstream_unreachable"


async def test_chat_completions_without_a_proxy_key_is_still_checked(lane):
    upstream = Upstream(lambda r: completion())
    response, log = await post(lane, upstream, chat(content=PNR), **caller_headers())

    assert response.status_code == 400
    assert upstream.requests == []
    assert log_line(log)["lane"] == "subscription"


@pytest.mark.parametrize("status", [401, 403])
async def test_a_provider_auth_error_quoting_the_key_never_reaches_the_caller(lane, status):
    body = {"error": {"message": "Incorrect API key provided: sk-proj-****abcd"}}
    upstream = Upstream(lambda r: httpx.Response(status, json=body))
    response, log = await post(lane, upstream)

    kind = "authentication_error" if status == 401 else "permission_error"
    assert error_of(response) == (status, kind)
    assert response.json()["error"]["message"] == (
        "privacy-proxy: the provider refused the proxy's key"
    )
    assert "abcd" not in response.text
    assert log_line(log)["outcome"] == "provider_auth"
