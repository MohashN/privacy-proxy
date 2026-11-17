"""Masking on the API lane (#66): a Detection replaced by a Placeholder, one way."""

import io
import json
import re

import httpx
import pytest
from test_api_lane import PROVIDER_KEYS, PROVIDERS_FILE, answer
from test_openai_format import completion
from test_subscription_lane import DENYLIST, Upstream, caller_headers

from privacy_proxy import cli
from privacy_proxy.apilane import ApiLane, Keys, Providers, Spend, hash_key
from privacy_proxy.app import create_app
from privacy_proxy.detection import Denylist, Scanner
from privacy_proxy.policy import Policy, PolicyError

# A made-up key and made-up numbers only.
KEY = "pp_masking-test-key-that-must-never-be-logged"
KEYS = {
    "keys": [
        {
            "name": "masking",
            "sha256": hash_key(KEY),
            "models": ["claude-haiku-5-5", "gpt-5.6-luna", "deepseek-flash"],
            "monthly_cap_usd": 5,
        }
    ]
}
PHONE = "+46 70 123 45 67"
OTHER_PHONE = "+46 70 123 45 68"
PNR = "19121212-1212"
CARD = "4111 1111 1111 1111"
CHAT = "/v1/chat/completions"


def scanner(**actions: str) -> Scanner:
    """A Scanner whose named Detectors mask; the rest refuse. SE's national format is read."""
    detectors: dict = {name: {"action": action} for name, action in actions.items()}
    detectors.setdefault("phone", {})["regions"] = ["SE"]
    return Scanner(Denylist.from_dict(DENYLIST), Policy.from_dict({"detectors": detectors}))


PHONE_MASKED = scanner(phone="mask")


def turn(content, model="claude-haiku-5-5", **extra) -> bytes:
    body = {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": content}]}
    return json.dumps({**body, **extra}).encode()


def chat(content, model="gpt-5.6-luna", **extra) -> bytes:
    body = {
        "model": model,
        "max_completion_tokens": 16,
        "messages": [{"role": "user", "content": content}],
    }
    return json.dumps({**body, **extra}).encode()


@pytest.fixture
def lane(tmp_path):
    spend = Spend(tmp_path / "spend.db")
    yield ApiLane(Keys.from_dict(KEYS), Providers.load(PROVIDERS_FILE), spend, PROVIDER_KEYS)
    spend.close()


async def post(lane, upstream, body, path="/v1/messages", log=None, scanner=PHONE_MASKED):
    log = log if log is not None else io.StringIO()
    app = create_app(scanner, transport=upstream, log=log, api=lane)
    headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
    headers |= {"authorization": f"Bearer {KEY}"} if path == CHAT else {"x-api-key": KEY}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.0.0.9", 52000)),
        base_url="http://proxy",
    ) as client:
        response = await client.post(path, headers=headers, content=body)
    return response, log


def sent(upstream: Upstream) -> dict:
    (body,) = upstream.bodies
    return json.loads(body)


def no_digits_of(body: bytes, *numbers: str) -> bool:
    """Whether ``body`` holds no four digits in a row of any of ``numbers``."""
    text = re.sub(r"\D", "", body.decode())
    for number in numbers:
        digits = re.sub(r"\D", "", number)
        if any(digits[i : i + 4] in text for i in range(len(digits) - 3)):
            return False
    return True


async def test_a_phone_reaches_anthropic_as_a_placeholder_and_the_reply_comes_back(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 3, "output_tokens": 1}))

    response, _ = await post(lane, upstream, turn(f"call {PHONE} today", max_tokens=1))

    assert response.status_code == 200
    assert response.json()["content"][0]["text"] == "ok"
    body = sent(upstream)
    assert body["messages"][0]["content"] == "call <PHONE_NUMBER_1> today"
    assert body["model"] == "claude-haiku-5-5"
    assert no_digits_of(upstream.bodies[0], PHONE)
    assert int(upstream.requests[0].headers["content-length"]) == len(upstream.bodies[0])


async def test_a_phone_reaches_an_openai_format_provider_as_a_placeholder(lane):
    upstream = Upstream(lambda r: completion({"prompt_tokens": 3, "completion_tokens": 1}))
    content = [{"type": "text", "text": f"call {PHONE}"}]

    response, _ = await post(lane, upstream, chat(content, stream=True), path=CHAT)

    assert response.status_code == 200
    body = sent(upstream)
    assert body["messages"][0]["content"][0] == {"type": "text", "text": "call <PHONE_NUMBER_1>"}
    # The usage a stream is made to report is still asked for.
    assert body["stream_options"] == {"include_usage": True}
    assert no_digits_of(upstream.bodies[0], PHONE)


async def test_the_same_phone_gets_the_same_placeholder_everywhere(lane):
    upstream = Upstream(lambda r: answer())
    body = turn(
        [
            {"type": "text", "text": f"mine is {PHONE}, theirs {OTHER_PHONE}"},
            # The same number in its national spelling, in another part.
            {"type": "text", "text": f"again 070-123 45 67 and {OTHER_PHONE}"},
        ],
        system=f"The user's number is {OTHER_PHONE}.",
    )

    response, _ = await post(lane, upstream, body)

    assert response.status_code == 200
    forwarded = sent(upstream)
    # Numbered by first appearance in the body, top to bottom.
    assert forwarded["messages"][0]["content"][0]["text"] == (
        "mine is <PHONE_NUMBER_1>, theirs <PHONE_NUMBER_2>"
    )
    assert forwarded["messages"][0]["content"][1]["text"] == (
        "again <PHONE_NUMBER_1> and <PHONE_NUMBER_2>"
    )
    assert forwarded["system"] == "The user's number is <PHONE_NUMBER_2>."
    assert no_digits_of(upstream.bodies[0], PHONE, OTHER_PHONE)


async def test_each_kind_counts_its_own_placeholders(lane):
    upstream = Upstream(lambda r: answer())

    response, _ = await post(
        lane,
        upstream,
        turn(f"card {CARD}, phone {PHONE}"),
        scanner=scanner(phone="mask", card="mask"),
    )

    assert response.status_code == 200
    assert sent(upstream)["messages"][0]["content"] == (
        "card <CREDIT_CARD_1>, phone <PHONE_NUMBER_1>"
    )


async def test_two_phones_with_nothing_between_them_leave_no_digits(lane):
    upstream = Upstream(lambda r: answer())

    response, _ = await post(lane, upstream, turn("+46701234567+46701234568"))

    assert response.status_code == 200
    assert sent(upstream)["messages"][0]["content"] == "<PHONE_NUMBER_1><PHONE_NUMBER_2>"
    assert no_digits_of(upstream.bodies[0], "+46701234567", "+46701234568")


async def test_a_phone_split_by_an_invisible_character_is_masked_whole(lane):
    upstream = Upstream(lambda r: answer())

    # A zero-width space and a soft hyphen: the check reads past them, so the
    # Placeholder must cover them too.
    response, _ = await post(lane, upstream, turn("x \u200b+46\u200b70 123\u00ad45 67 y\u200b"))

    assert response.status_code == 200
    assert sent(upstream)["messages"][0]["content"] == "x \u200b<PHONE_NUMBER_1> y\u200b"


async def test_a_tool_call_input_and_a_tool_result_are_masked(lane):
    upstream = Upstream(lambda r: answer())
    body = turn(
        [
            {"type": "tool_use", "id": "toolu_1", "name": "dial", "input": {"number": PHONE}},
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": f"dialled {PHONE}"},
        ]
    )

    response, _ = await post(lane, upstream, body)

    assert response.status_code == 200
    blocks = sent(upstream)["messages"][0]["content"]
    assert blocks[0]["input"] == {"number": "<PHONE_NUMBER_1>"}
    assert blocks[1]["content"] == "dialled <PHONE_NUMBER_1>"
    assert (blocks[0]["id"], blocks[1]["tool_use_id"]) == ("toolu_1", "toolu_1")


async def test_a_phone_and_a_personnummer_with_only_the_phone_masked_is_refused(lane):
    upstream = Upstream(lambda r: answer())
    log = io.StringIO()

    response, _ = await post(lane, upstream, turn(f"{PHONE} and {PNR}"), log=log)

    assert response.status_code == 400
    assert "PHONE_NUMBER, SE_PERSONNUMMER" in response.json()["error"]["message"]
    assert upstream.requests == []
    assert json.loads(log.getvalue())["outcome"] == "refused"


async def test_a_deny_list_hit_is_refused(lane):
    upstream = Upstream(lambda r: answer())

    response, _ = await post(lane, upstream, turn(f"Testa Testsson, {PHONE}"))

    assert response.status_code == 400
    assert "DENYLIST" in response.json()["error"]["message"]
    assert upstream.requests == []


@pytest.mark.parametrize(
    "extra",
    [
        # Where a Placeholder can't go: an id, a key, a number, the metadata, and
        # thinking the provider signed.
        {"metadata": {"user_id": PHONE}},
        {"tools": [{"name": "t", "input_schema": {"properties": {PHONE: {}}}}]},
        {"messages": [{"role": "user", "content": [{"type": "text", "text": "x", "id": PHONE}]}]},
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [{"type": "thinking", "thinking": PHONE, "signature": "c2ln"}],
                }
            ]
        },
    ],
)
async def test_a_phone_where_no_placeholder_can_go_is_refused(lane, extra):
    upstream = Upstream(lambda r: answer())

    response, _ = await post(lane, upstream, turn(f"call {PHONE}", **extra))

    assert response.status_code == 400
    assert "PHONE_NUMBER" in response.json()["error"]["message"]
    assert upstream.requests == []


async def test_a_phone_left_after_masking_is_refused(lane, monkeypatch):
    upstream = Upstream(lambda r: answer())
    # A mask that misses: the check on the masked body is what stops the request.
    monkeypatch.setattr(Scanner, "mask", lambda self, body: (body, []))

    response, _ = await post(lane, upstream, turn(f"call {PHONE}"))

    assert response.status_code == 400
    assert upstream.requests == []


async def test_a_request_with_nothing_to_mask_goes_on_byte_for_byte(lane):
    upstream = Upstream(lambda r: answer())
    body = b'{"model": "claude-haiku-5-5","max_tokens":16,  "messages":[]}'

    response, _ = await post(lane, upstream, body)

    assert response.status_code == 200
    assert upstream.bodies == [body]


async def test_the_subscription_lane_refuses_a_phone_set_to_mask():
    upstream = Upstream(lambda r: httpx.Response(200, json={"ok": True}))
    app = create_app(PHONE_MASKED, transport=upstream, log=io.StringIO())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://proxy"
    ) as client:
        response = await client.post(
            "/v1/messages", headers=caller_headers(), content=turn(f"call {PHONE}")
        )

    assert response.status_code == 400
    assert "PHONE_NUMBER" in response.json()["error"]["message"]
    assert upstream.requests == []


async def test_the_log_holds_the_kind_and_no_placeholder_or_digits(lane):
    upstream = Upstream(lambda r: answer({"input_tokens": 3, "output_tokens": 1}))
    log = io.StringIO()

    await post(lane, upstream, turn(f"call {PHONE} or {OTHER_PHONE}"), log=log)

    text = log.getvalue()
    line = json.loads(text)
    assert line["outcome"] == "complete"
    assert line["masked"] is True
    assert [d["type"] for d in line["detections"]] == ["PHONE_NUMBER", "PHONE_NUMBER"]
    assert all(re.fullmatch(r"[0-9a-f]{64}", d["hash"]) for d in line["detections"])
    assert "<PHONE_NUMBER" not in text
    assert no_digits_of(re.sub(r'"hash": "[0-9a-f]{64}"', "", text).encode(), PHONE, OTHER_PHONE)
    assert set(line["detections"][0]) == {"type", "hash"}


def test_mask_returns_what_it_could_not_mask():
    body = {"messages": [{"role": "user", "content": f"{PHONE} and {PNR}"}], PHONE: 1}

    masked, left = PHONE_MASKED.mask(body)

    assert masked["messages"][0]["content"] == f"<PHONE_NUMBER_1> and {PNR}"
    assert {d.type for d in left} == {"SE_PERSONNUMMER"}
    # The body given is not changed.
    assert body["messages"][0]["content"] == f"{PHONE} and {PNR}"
    # A span is never part of what a Detection shows or equals by.
    assert "span" not in repr(left) and PHONE not in repr(left)


@pytest.mark.parametrize("name", ["phone", "national_id", "card", "iban"])
def test_the_policy_accepts_mask_on_each_detector_with_a_span(name):
    policy = Policy.from_dict({"detectors": {name: {"action": "mask"}}})

    assert policy.masked_names() == [name]
    assert name in policy.on_names()


def test_the_policy_refuses_mask_on_the_deny_list():
    with pytest.raises(PolicyError, match=r"detectors\.deny_list\.action"):
        Policy.from_dict({"detectors": {"deny_list": {"action": "mask"}}})


def test_startup_warns_that_the_subscription_lane_refuses_instead(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.yaml"
    path.write_text("detectors:\n  phone: {action: mask}\n  card: {action: mask}\n")
    monkeypatch.setenv("POLICY_PATH", str(path))
    monkeypatch.delenv("DENYLIST_PATH", raising=False)

    cli.load_scanner()

    err = capsys.readouterr().err
    assert "Masking is set for phone, card; the Subscription lane refuses these instead" in err


def test_startup_stops_on_a_deny_list_set_to_mask(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    path.write_text("detectors:\n  deny_list: {action: mask}\n")
    monkeypatch.setenv("POLICY_PATH", str(path))

    with pytest.raises(SystemExit, match="not usable"):
        cli.load_scanner()


def test_startup_says_nothing_of_masking_when_none_is_set(monkeypatch, capsys):
    monkeypatch.delenv("POLICY_PATH", raising=False)
    monkeypatch.delenv("DENYLIST_PATH", raising=False)

    cli.load_scanner()

    assert "Masking" not in capsys.readouterr().err
