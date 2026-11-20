import gzip
import io
import json
from datetime import date
from pathlib import Path

import httpx
import pytest
from test_subscription_lane import SCANNER, Upstream, caller_headers, proxied

from privacy_proxy import cli, detection
from privacy_proxy.detection import (
    Denylist,
    Detection,
    Scanner,
    known_id_position,
    normalise,
    read_entries,
    recent_run_together,
)
from privacy_proxy.policy import Policy

# The public test personnummer: the positive control, never a real person's.
PNR = "19121212-1212"
ORG = "556036-0793"
FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent
# The speed tests guard against a scan that blows up (quadratic or worse: minutes on
# these inputs), not against a slow machine: normally well under 1 s, so 5 s is
# generous on a loaded runner and a quadratic scan still misses it by orders of magnitude.
BLOW_UP_SECONDS = 5.0


def ok() -> Upstream:
    return Upstream(lambda r: httpx.Response(200, json={"ok": True}))


def request(*content, system=None) -> dict:
    body = {
        "model": "claude-sonnet-5-5",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": list(content)}],
    }
    if system is not None:
        body["system"] = system
    return body


def text(value: str) -> dict:
    return {"type": "text", "text": value}


async def send(body, path="/v1/messages", upstream=None, log=None, **headers):
    upstream = upstream or ok()
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    async with proxied(upstream, log) as client:
        response = await client.post(path, headers=caller_headers(**headers), content=content)
    return response, upstream


def refusal(response: httpx.Response) -> str:
    assert response.status_code == 400
    body = response.json()
    assert body["type"] == "error"
    assert body["error"]["type"] == "invalid_request_error"
    return body["error"]["message"]


async def test_personnummer_in_a_user_message_is_refused_and_never_sent():
    response, upstream = await send(request(text(f"my number is {PNR}")))

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


async def test_personnummer_inside_a_tool_result_is_refused():
    body = request(
        {
            "type": "tool_result",
            "tool_use_id": "toolu_01",
            "content": [text("grep found:"), text(f"customer.csv:12: {PNR}")],
        }
    )
    response, upstream = await send(body)

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


async def test_tool_use_input_is_scanned_whatever_its_keys_are_called():
    body = {
        "model": "claude-sonnet-5-5",
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": "Write",
                        "input": {"type": "file", "id": {"nested": [f"pnr {PNR}"]}},
                    }
                ],
            }
        ],
    }
    response, _ = await send(body)

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"


async def test_system_prompt_is_scanned():
    response, _ = await send(request(text("hi"), system=f"The operator is {PNR}."))

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"


async def test_denylist_name_spread_over_a_line_break_is_refused():
    response, upstream = await send(request(text("Invoice for Testa\n   TESTSSON's account")))

    assert refusal(response) == "privacy-proxy: refused (DENYLIST)"
    assert upstream.requests == []


async def test_denylist_address_matches_whatever_its_punctuation():
    response, _ = await send(request(text("ship to påhittade VÄGEN 7 999-99 ingenstans.")))

    assert refusal(response) == "privacy-proxy: refused (DENYLIST)"


async def test_card_and_iban_are_refused():
    response, _ = await send(
        request(text("card 4111 1111 1111 1111"), text("IBAN SE45 5000 0000 0583 9825 7466"))
    )

    assert refusal(response) == "privacy-proxy: refused (CREDIT_CARD, IBAN_CODE)"


async def test_an_organisation_number_is_company_business_and_passes():
    body = request(text(f"Supplier Testbolaget AB, org.nr {ORG}, invoice 4411."))
    response, upstream = await send(body)

    assert response.status_code == 200
    assert upstream.bodies == [json.dumps(body).encode()]


async def test_a_captured_claude_code_request_passes_byte_for_byte():
    # Claude Code's own system prompt and tool list, captured from `claude -p "say
    # ok"` against a local recorder, with nothing of the operator's in it.
    body = (FIXTURES / "claude_code_request.json").read_bytes()
    response, upstream = await send(body, path="/v1/messages?beta=true")

    assert response.status_code == 200
    assert upstream.bodies == [body]


async def test_log_line_holds_type_and_hash_never_the_text():
    log = io.StringIO()
    await send(request(text(f"{PNR} and Testa Testsson")), log=log)

    (line,) = [json.loads(raw) for raw in log.getvalue().splitlines()]
    assert line["status"] == 400
    assert line["outcome"] == "refused"
    assert sorted(d["type"] for d in line["detections"]) == ["DENYLIST", "SE_PERSONNUMMER"]
    assert all(len(d["hash"]) == 64 for d in line["detections"])
    raw = log.getvalue()
    for leaked in ("1212", "testa", "Testa", "Testsson"):
        assert leaked not in raw


async def test_the_same_personnummer_logs_the_same_hash_in_any_format():
    hashes = []
    for written in ("191212121212", "121212-1212", "19121212+1212"):
        log = io.StringIO()
        await send(request(text(f"pnr {written}")), log=log)
        (detection,) = json.loads(log.getvalue())["detections"]
        hashes.append(detection["hash"])

    assert len(set(hashes)) == 1


@pytest.mark.parametrize(
    "path",
    [
        "/v1/messages",
        "/v1/messages/count_tokens",
        "/v1//messages/",
        "/v1/./messages",
        "/v1/x/../messages",
        "/v1/%6Dessages",
        "/v1/x/%2E%2E/messages",
        "/v1/%2e/messages",
        "/V1/Messages",
        "/v1\\messages",
        "/v1/messages;x",
    ],
)
async def test_every_path_to_the_messages_endpoint_is_checked(path):
    response, upstream = await send(request(text(PNR)), path=path)

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


@pytest.mark.parametrize(
    "written",
    [
        "19121212\u20131212",  # an en dash, as autocorrect writes it
        "1912\u200b1212-1212",  # a zero-width space
        "19121212\u00ad-1212",  # a soft hyphen
        "4111\u00a01111\u00a01111\u00a01111",  # no-break spaces, as copied from a PDF
        "4111\t1111\t1111\t1111",
        "4111.1111.1111.1111",
    ],
)
async def test_odd_spellings_of_a_number_are_still_refused(written):
    response, upstream = await send(request(text(f"see {written} here")))

    assert response.status_code == 400
    assert upstream.requests == []


async def test_a_name_joined_by_an_invisible_character_is_refused():
    response, _ = await send(request(text("hi testa\u200btestsson")))

    assert refusal(response) == "privacy-proxy: refused (DENYLIST)"


async def test_schema_properties_and_output_format_are_checked():
    schema = {"type": "object", "properties": {"id": {"description": f"pnr {PNR}"}}}
    with_tool = request(text("hi"))
    with_tool["tools"] = [{"name": "crm", "description": "crm", "input_schema": schema}]
    with_format = request(text("hi"))
    with_format["output_format"] = {"type": "json_schema", "schema": schema}

    for body in (with_tool, with_format):
        response, _ = await send(body)
        assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"


async def test_metadata_is_not_read():
    # The account's device id is long hex; a digit pattern could trip on it.
    body = request(text("hi"))
    body["metadata"] = {"user_id": f"device {PNR}"}
    response, _ = await send(body)

    assert response.status_code == 200


async def test_each_request_in_a_batch_is_checked():
    body = {"requests": [{"custom_id": "a", "params": request(text(f"pnr {PNR}"))}]}
    response, upstream = await send(body, path="/v1/messages/batches")

    assert refusal(response) == "privacy-proxy: refused (SE_PERSONNUMMER)"
    assert upstream.requests == []


@pytest.mark.parametrize(
    "tool_input",
    [{"pnr": 191212121212}, {"card": 4111111111111111}, {"Testa Testsson": True}],
)
async def test_numbers_and_keys_in_a_tool_input_are_checked(tool_input):
    call = {"type": "tool_use", "id": "toolu_01", "name": "Write", "input": tool_input}
    body = {"model": "claude-sonnet-5-5", "messages": [{"role": "assistant", "content": [call]}]}
    response, _ = await send(body)

    assert response.status_code == 400


async def test_tool_descriptions_are_checked():
    body = request(text("hi"))
    body["tools"] = [{"name": "crm", "description": "Operator: Testa Testsson", "input_schema": {}}]
    response, _ = await send(body)

    assert refusal(response) == "privacy-proxy: refused (DENYLIST)"


async def test_a_key_given_twice_is_refused():
    # Read last-wins here, but an upstream that reads first-wins would see the number.
    body = (
        b'{"model":"x","messages":[{"role":"user","content":"19121212-1212"}],'
        b'"messages":[{"role":"user","content":"hi"}]}'
    )
    response, upstream = await send(body)

    assert refusal(response) == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []


async def test_other_paths_pass_unchecked():
    body = json.dumps({"events": [{"note": PNR}]}).encode()
    response, upstream = await send(body, path="/api/event_logging/batch")

    assert response.status_code == 200
    assert upstream.bodies == [body]


async def test_a_body_that_cant_be_read_is_refused():
    response, upstream = await send(b"{not json")

    assert refusal(response) == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []


async def test_a_compressed_body_is_refused_rather_than_sent_unchecked():
    body = gzip.compress(json.dumps(request(text(PNR))).encode())
    response, upstream = await send(body, **{"content-encoding": "gzip"})

    assert refusal(response) == "privacy-proxy: refused (UNREADABLE_BODY)"
    assert upstream.requests == []


async def test_base64_images_are_not_read_as_text():
    image = {"type": "base64", "media_type": "image/png", "data": "MTkxMjEyMTIxMjEy" + "1" * 40}
    body = request({"type": "image", "source": image}, text("what is this?"))
    response, _ = await send(body)

    assert response.status_code == 200


def test_normalise_folds_case_width_accents_and_punctuation():
    assert normalise("  Ｔｅｓｔａ\n\tTESTSSON's,  Anna-Karin+Påhit\u200btade ") == [
        "testa",
        "testsson",
        "s",
        "anna",
        "karin",
        "pahittade",
    ]


async def test_denylist_matches_without_accents_or_across_symbols():
    for written in ("pahittade vagen 7 999 99 ingenstans", "mail testa+testsson@example.org"):
        response, _ = await send(request(text(written)))
        assert refusal(response) == "privacy-proxy: refused (DENYLIST)"


def test_a_text_seen_before_is_not_checked_again(monkeypatch):
    calls = []
    real = SCANNER._inspect
    monkeypatch.setattr(
        SCANNER, "_inspect", lambda t, d, *rest: calls.append(t) or real(t, d, *rest)
    )
    history = [f"turn {n} of the session the cache test runs" for n in range(50)]

    assert SCANNER.inspect(history) == []
    assert SCANNER.inspect([*history, f"the cache test, pnr {PNR}"])[0].type == "SE_PERSONNUMMER"
    assert len(calls) == 51


def test_a_megabyte_is_checked_in_well_under_a_second():
    import time

    big = " ".join(["commit a1b2c3d4 at 2026-10-26 id=123456789012345 the quick brown fox"] * 15000)
    started = time.monotonic()
    assert SCANNER.inspect([big]) == []
    assert time.monotonic() - started < BLOW_UP_SECONDS


def test_hash_denylist_writes_salt_and_hashes_only(tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("# a comment\n\nTesta Testsson\nPåhittade vägen 7\n", encoding="utf-8")
    out = tmp_path / "denylist.json"

    cli.main(["hash-denylist", str(plain), str(out)])

    written = out.read_text(encoding="utf-8")
    assert "testa" not in written.casefold()
    data = json.loads(written)
    assert sorted(data) == ["firsts", "hashes", "salt"]
    assert len(data["hashes"]) == 2
    scanner = Scanner(Denylist.load(out))
    assert [d.type for d in scanner.inspect(["hello testa testsson"])] == ["DENYLIST"]
    # A fresh salt per run: two hashings of the same list share no hash.
    cli.main(["hash-denylist", str(plain), str(out)])
    assert not set(data["hashes"]) & set(json.loads(out.read_text())["hashes"])


def test_hash_denylist_refuses_an_entry_too_long_to_match(tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("one two three four five six seven\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="7 words"):
        cli.main(["hash-denylist", str(plain), str(tmp_path / "out.json")])


def test_the_template_holds_no_entries():
    template = (ROOT / "denylist.template.txt").read_text(encoding="utf-8")

    assert template.strip()
    assert read_entries(template) == []


def test_an_unreadable_denylist_stops_the_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv("DENYLIST_PATH", str(tmp_path / "missing.json"))
    with pytest.raises(SystemExit, match="can't read the deny-list"):
        cli.main([])

    broken = tmp_path / "broken.json"
    broken.write_text('{"salt": "s", "hashes": ["Testa Testsson"], "firsts": []}')
    monkeypatch.setenv("DENYLIST_PATH", str(broken))
    with pytest.raises(SystemExit, match="can't read the deny-list") as raised:
        cli.main([])
    assert "Testa" not in str(raised.value)


# The household's numbers go on the deny-list in three spellings (#9): its
# normalising turns any separator into one gap, so these catch every spelling.
HOUSEHOLD = ["19121212 1212", "121212 1212", "191212121212"]
# A day the tests fix, so a timestamp's age doesn't depend on when they run.
TODAY = date(2026, 10, 27)


def denylist_file(tmp_path, entries=HOUSEHOLD) -> Scanner:
    plain = tmp_path / "plain.txt"
    plain.write_text("\n".join(entries) + "\n", encoding="utf-8")
    out = tmp_path / "denylist.json"
    cli.main(["hash-denylist", str(plain), str(out)])
    return Scanner(Denylist.load(out), SE_ONLY)


# The tests here predate the phone Detector (#64) and the other countries' IDs (#65):
# they check the personnummer and the Deny-list on their own, so a listed phone or a
# glued run isn't also named as a phone or another country's ID. tests/test_phone.py
# and tests/test_national_id.py check those.
SE_ONLY = Policy.from_dict(
    {"detectors": {"national_id": {"countries": ["SE"]}, "phone": {"action": "off"}}}
)


def empty_list() -> Scanner:
    return Scanner(Denylist.from_dict(Denylist.build([])), SE_ONLY)


def run_together(day: date, serial: str = "000") -> str:
    """A made-up ``YYYYMMDDNNNC`` dated ``day`` whose Luhn check passes."""
    stem = f"{day:%y%m%d}{serial}"
    total = 0
    for i, digit in enumerate(int(c) for c in stem):
        doubled = digit * 2 if i % 2 == 0 else digit
        total += doubled - 9 if doubled > 9 else doubled
    return f"{day:%Y}{stem[2:]}{(10 - total % 10) % 10}"


@pytest.mark.parametrize(
    "written", ["19121212 1212", "121212 1212", "19121212-1212", "19121212.1212", "191212121212"]
)
def test_household_entries_catch_a_personnummer_in_any_spelling(tmp_path, written):
    scanner = denylist_file(tmp_path)

    types = {d.type for d in scanner.inspect([f"my number is {written}"])}

    assert "DENYLIST" in types


def test_a_spaced_number_off_the_denylist_is_not_refused():
    # The Deny-list holds the Operator's own numbers (#9, Q1 1B).
    assert empty_list().inspect(["see 19121212 1212 here"]) == []


@pytest.mark.parametrize("written", ["20261026 0008", "202610260008"])
def test_timestamps_pass_an_empty_denylist(monkeypatch, written):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)

    assert empty_list().inspect([f"log at {written} ok"]) == []


def test_a_run_together_number_from_1_january_last_year_passes(monkeypatch):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)
    number = run_together(date(2025, 1, 1))

    assert empty_list().inspect([f"id {number}"]) == []


def test_a_run_together_number_from_before_last_year_is_still_refused(monkeypatch):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)
    number = run_together(date(2024, 12, 31))

    assert [d.type for d in empty_list().inspect([f"id {number}"])] == ["SE_PERSONNUMMER"]


def test_the_dashed_form_of_a_recent_date_is_still_refused(monkeypatch):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)
    number = run_together(date(2026, 1, 5))

    found = empty_list().inspect([f"id {number[:8]}-{number[8:]}"])

    assert [d.type for d in found] == ["SE_PERSONNUMMER"]


def test_the_planted_control_is_still_refused_by_the_general_check():
    assert [d.type for d in empty_list().inspect([f"pnr {PNR}"])] == ["SE_PERSONNUMMER"]


def test_a_recent_run_together_number_on_the_denylist_is_still_refused(tmp_path, monkeypatch):
    # A household child born last year: the general check drops the number, the
    # entry still catches it.
    monkeypatch.setattr(detection, "_today", lambda: TODAY)
    number = run_together(date(2025, 6, 1))
    scanner = denylist_file(tmp_path, [number])

    assert [d.type for d in scanner.inspect([f"id {number}"])] == ["DENYLIST"]


@pytest.mark.parametrize("glued", ["20", "42"])
def test_an_adults_short_form_with_digits_glued_in_front_is_still_refused(monkeypatch, glued):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)
    short = run_together(date(1985, 1, 1))[2:]

    found = empty_list().inspect([f"id {glued}{short}"])

    assert [d.type for d in found] == ["SE_PERSONNUMMER"]


def test_a_cached_pass_is_checked_again_in_a_new_year(monkeypatch):
    scanner = empty_list()
    written = f"id {run_together(date(2025, 6, 1))}"
    monkeypatch.setattr(detection, "_today", lambda: TODAY)
    assert scanner.inspect([written]) == []

    monkeypatch.setattr(detection, "_today", lambda: date(2027, 1, 1))
    assert [d.type for d in scanner.inspect([written])] == ["SE_PERSONNUMMER"]


@pytest.mark.parametrize(
    ("matched", "recent"),
    [
        ("202501010009", True),  # 1 January of last year
        ("202412310001", False),  # the day before
        ("202501610006", True),  # a coordination number: day 61 is the 1st
        ("202610270004", True),  # today
        ("202610280002", False),  # tomorrow: a future date is never dropped
        ("208501010006", False),  # "20" glued to an adult's short form
        ("191212121212", False),
        ("19121212-1212", False),  # a separator: never dropped
        ("2610260008", False),  # ten digits: never dropped (R2)
        # Fullwidth digits: not ASCII, never dropped.
        ("２０２５０１０１０００９", False),
        ("202513010000", False),  # no such date: never dropped
    ],
)
def test_recent_run_together_reads_the_date_from_the_digits(matched, recent):
    assert recent_run_together(matched, TODAY) is recent


# GitHub's numeric ids that read as a personnummer (#9 in this repo; Salpline's
# github-id-refusals design): a comment id dated 1970-07-07, and an 11-digit run
# id whose last ten digits are that number.
GITHUB_ID = "7007078186"
RUN_ID = "47007078186"


@pytest.mark.parametrize(
    "written",
    [
        f'{{"id": {GITHUB_ID}}}',
        f'"comment_id": {GITHUB_ID}',
        f"issues/790#issuecomment-{GITHUB_ID}",
        f"actions/runs/{RUN_ID}",
        f"#790/{GITHUB_ID}",
    ],
)
def test_a_github_id_in_a_known_id_position_passes(written):
    assert empty_list().inspect([written]) == []


def test_a_personnummer_after_pnr_is_still_refused():
    assert [d.type for d in empty_list().inspect([f"pnr {GITHUB_ID}"])] == ["SE_PERSONNUMMER"]


def test_a_look_alike_on_its_own_is_still_refused():
    assert [d.type for d in empty_list().inspect([GITHUB_ID])] == ["SE_PERSONNUMMER"]


def test_a_personnummer_under_a_personnummer_key_is_still_refused():
    found = empty_list().inspect(['{"personnummer": "700707-8186"}'])

    assert [d.type for d in found] == ["SE_PERSONNUMMER"]


def test_id_without_a_json_colon_is_still_refused():
    assert [d.type for d in empty_list().inspect([f"id {GITHUB_ID}"])] == ["SE_PERSONNUMMER"]


@pytest.mark.parametrize(
    ("before", "known"),
    [
        ('{"id": ', True),
        ('"id":', True),
        ('"id":   ', True),
        ('"comment_id": ', True),
        ('"check_suite_id": ', True),
        ("issues/1#issuecomment-", True),
        ("actions/runs/", True),
        ("actions/runs/1/jobs/", True),
        ("pull/2#pullrequestreview-", True),
        ("pull/2#discussion_r", True),
        ("#790/", True),
        ('"id": "', False),  # a string value: a form field, not a GitHub id
        ('"id":\n', False),  # only spaces between
        ('"personnummer": ', False),
        ('"valid": ', False),  # "_id", not any word ending in "id"
        ("id ", False),
        ("pnr ", False),
        ("#/", False),  # no digits before the slash
        ("issuecomment- ", False),  # directly after, no gap
        ("", False),
    ],
)
def test_known_id_position_reads_what_comes_before_the_match(before, known):
    text = f"{before}{GITHUB_ID}"

    assert known_id_position(text, len(before), len(text)) is known


@pytest.mark.parametrize(
    "written",
    [
        '{"id": 19121212-1212}',
        "#1/121212-1212",
        "actions/runs/121212+1212",
        '"id": ７００７０７８１８６',  # fullwidth digits: not how GitHub writes an id
    ],
)
def test_a_separated_or_non_ascii_number_in_an_id_position_is_still_refused(written):
    assert [d.type for d in empty_list().inspect([written])] == ["SE_PERSONNUMMER"]


# A listed number glued to other digits (#20): the deny-list looks it up inside
# any run of 11 or more digits (13 before #24); no general check runs on the windows.
GLUED_LIST = ["191212121212", "1212121212"]
GLUED = ["999191212121212", "19121212121200", "9991212121212"]


@pytest.mark.parametrize("glued", GLUED)
def test_a_listed_number_glued_inside_a_digit_run_is_refused(tmp_path, glued):
    scanner = denylist_file(tmp_path, GLUED_LIST)

    found = scanner.inspect([f"id {glued} ok"])

    assert "DENYLIST" in {d.type for d in found}


@pytest.mark.parametrize("glued", GLUED)
def test_the_readmes_three_spellings_catch_a_glued_number(tmp_path, glued):
    # #9's list has no short form run together: the window is also looked up
    # with a gap before its last four digits, as "121212 1212" is listed.
    found = denylist_file(tmp_path).inspect([f"id {glued} ok"])

    assert "DENYLIST" in {d.type for d in found}


def test_a_glued_number_is_found_when_the_text_also_holds_a_format_character(tmp_path):
    scanner = denylist_file(tmp_path, GLUED_LIST)

    found = scanner.inspect(["id\u200b 999191212121212 ok"])

    assert {d.type for d in found} == {"DENYLIST"}


def test_a_glued_match_logs_each_entrys_own_hash(tmp_path):
    scanner = denylist_file(tmp_path, GLUED_LIST)
    # The long form holds the short one, so both entries fire.
    entries = {Detection("DENYLIST", scanner.denylist.hash([e]).hex()) for e in GLUED_LIST}

    assert set(scanner.inspect(["id 999191212121212"])) == entries


@pytest.mark.parametrize("glued", ["999191212121212", "9991212121212"])
def test_a_glued_number_passes_an_empty_denylist(glued):
    assert empty_list().inspect([f"id {glued} ok"]) == []


def test_digits_glued_after_a_number_are_left_to_the_general_check():
    # Presidio reads the first 12 digits of the run, so this was refused before #20
    # and still is; the deny-list adds nothing for an empty list.
    found = empty_list().inspect(["id 19121212121200 ok"])

    assert [d.type for d in found] == ["SE_PERSONNUMMER"]


def test_a_long_id_passes_with_the_numbers_listed(tmp_path):
    scanner = denylist_file(tmp_path, GLUED_LIST)

    assert scanner.inspect(["id 48213907561234098765 ok"]) == []


def test_a_glued_number_in_fullwidth_digits_is_refused(tmp_path):
    scanner = denylist_file(tmp_path, GLUED_LIST)

    found = scanner.inspect(["id ９９９１９１２１２１２１２１２ ok"])

    assert {d.type for d in found} == {"DENYLIST"}


# Glued and disguised spellings the deny-list also finds (#24): runs of 11 or 12
# digits, a dashed form with digits glued in front, and non-ASCII digits. Each is an
# exact lookup of a listed entry; the general check reads nothing new.
def arabic(written: str) -> str:
    return written.translate({ord(d): chr(0x0660 + int(d)) for d in "0123456789"})


def devanagari(written: str) -> str:
    return written.translate({ord(d): chr(0x0966 + int(d)) for d in "0123456789"})


@pytest.mark.parametrize("written", ["id 121212121200", "id 12121212120"])
def test_a_short_form_glued_into_an_eleven_or_twelve_digit_run_is_refused(tmp_path, written):
    assert "DENYLIST" in {d.type for d in denylist_file(tmp_path).inspect([written])}
    assert empty_list().inspect([written]) == []


def test_a_dashed_form_with_digits_glued_in_front_is_refused(tmp_path):
    written = "id 99919121212-1212"

    assert "DENYLIST" in {d.type for d in denylist_file(tmp_path).inspect([written])}
    assert empty_list().inspect([written]) == []


@pytest.mark.parametrize("dash", ["\u2013", "\uff0d", "\u2212", "\u207b", "\u208b"])
def test_a_dashed_glued_form_is_found_with_any_dash(tmp_path, dash):
    found = denylist_file(tmp_path).inspect([f"id 99919121212{dash}1212"])

    assert "DENYLIST" in {d.type for d in found}


def test_a_dashed_run_holding_no_listed_number_passes(tmp_path):
    assert denylist_file(tmp_path).inspect(["id 48213907561-2340 ok"]) == []


@pytest.mark.parametrize(
    "written",
    [
        arabic("id 999191212121212"),
        arabic("id 9991212121212"),
        arabic("pnr 121212 1212"),
        devanagari("pnr 19121212 1212"),
        arabic("id 99919121212-1212"),
    ],
)
def test_a_listed_number_in_non_ascii_digits_is_refused(tmp_path, written):
    assert "DENYLIST" in {d.type for d in denylist_file(tmp_path).inspect([written])}


def test_a_listed_phone_in_arabic_indic_digits_is_refused(tmp_path):
    scanner = denylist_file(tmp_path, ["0701234567"])

    found = scanner.inspect([arabic("tel 0701234567")])

    assert {d.type for d in found} == {"DENYLIST"}


@pytest.mark.parametrize(
    "written", ["log 202610260008", "log 20261026 0008", "id 48213907561234098765"]
)
def test_ids_and_timestamps_with_no_listed_number_still_pass(monkeypatch, tmp_path, written):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)

    assert denylist_file(tmp_path).inspect([written]) == []


def test_a_dashed_personnummer_is_still_the_general_checks_alone():
    assert [d.type for d in empty_list().inspect(["pnr 19121212-1212"])] == ["SE_PERSONNUMMER"]


@pytest.mark.parametrize(
    ("written", "types"),
    [
        (arabic("pnr 19121212-1212"), ["SE_PERSONNUMMER"]),
        (devanagari("pnr 191212121212"), ["SE_PERSONNUMMER"]),
        (arabic("id 999191212121212"), []),
        (arabic("tel 0701234567"), []),
    ],
)
def test_the_general_checks_verdict_on_non_ascii_digits_is_unchanged(written, types):
    assert [d.type for d in empty_list().inspect([written])] == types


def test_the_text_presidio_reads_keeps_its_non_ascii_digits():
    assert detection._presidio_view(arabic("19121212")) == arabic("19121212")


@pytest.mark.parametrize(
    "written",
    ["id 9991912121\u034f2-1212", "id 9991912121\ufe0f2-1212", "id 9991912121\u00b2-1212"],
)
def test_a_dashed_glued_form_is_found_through_marks_and_odd_digits(tmp_path, written):
    # A combining mark is dropped and a superscript digit read as a digit, as the
    # deny-list's words have them.
    assert "DENYLIST" in {d.type for d in denylist_file(tmp_path).inspect([written])}


def test_a_huge_digit_run_beside_a_dash_is_read_in_linear_time(tmp_path):
    import time

    denylist = denylist_file(tmp_path).denylist
    started = time.monotonic()
    assert list(denylist.split_run_matches("1" * 1_000_000 + "-")) == []
    assert time.monotonic() - started < BLOW_UP_SECONDS


# A listed number glued to other digits across any gap that is neither letters nor
# digits (#43): "+", spaces, a spaced dash, "/", ".", a newline. The README's list.
README_LIST = [*HOUSEHOLD, "0701234567"]
GLUED_SPLIT = [
    "id 99919121212-1212",
    "id 99919121212+1212",
    "id 99919121212 - 1212",
    "id 99919121212 1212",
    "id 99919121212 + 1212",
    "id 99919121212/1212",
    "id 99919121212.1212",
    "id 99919121212_1212",
    "id 99919121212, 1212",
    "id 99919121212:1212",
    "id 99919121212 \u2013 1212",
    "id 99919121212\n1212",
    "id 99919121212\t1212",
    "id 999121212 1212",
    "id 9919121212 1212",
    "id 19121212 121299",
    "id 99919121212 121299",
]


@pytest.mark.parametrize("written", GLUED_SPLIT)
def test_a_glued_split_form_is_refused_across_any_gap(tmp_path, written):
    found = denylist_file(tmp_path, README_LIST).inspect([written])

    assert "DENYLIST" in {d.type for d in found}


@pytest.mark.parametrize("written", GLUED_SPLIT)
def test_a_glued_split_form_is_no_denylist_hit_with_an_empty_list(written):
    assert "DENYLIST" not in {d.type for d in empty_list().inspect([written])}


def test_a_spaced_timestamp_still_passes_beside_the_glued_search(monkeypatch, tmp_path):
    monkeypatch.setattr(detection, "_today", lambda: TODAY)

    assert denylist_file(tmp_path, README_LIST).inspect(["log 20261026 0008"]) == []


def test_a_glued_split_with_a_letter_in_the_gap_is_not_read():
    # A letter ends a chain (#50): the two runs are read apart, never joined.
    assert detection._DIGIT_CHAIN.findall("19121212 nr 1212") == ["19121212", "1212"]


def test_a_glued_chain_of_three_runs_is_read_as_one():
    chains = detection._DIGIT_CHAIN.findall("1111111111 2222222222 3333")

    assert chains == ["1111111111 2222222222 3333"]


def test_a_glued_listed_number_late_in_a_chain_is_refused(tmp_path):
    found = denylist_file(tmp_path, README_LIST).inspect(["id 48213907 99919121212 + 1212"])

    assert "DENYLIST" in {d.type for d in found}


@pytest.mark.parametrize(
    "text", [("1234567 " * 200_000), ("1" * 1_000_000 + " " * 1_000_000 + "x")]
)
def test_glued_spaced_digit_groups_are_read_in_linear_time(tmp_path, text):
    import time

    denylist = denylist_file(tmp_path).denylist
    started = time.monotonic()
    assert list(denylist.split_run_matches(text)) == []
    assert time.monotonic() - started < BLOW_UP_SECONDS


# A listed number split anywhere, not only before its last four (#50): every chain
# of digit groups whose gaps hold no letters is joined, and each 10- and 12-digit
# window of it looked up.
SPLIT_ANYWHERE = ["191212 121212", "0701234 567", "070-123 45 67"]


@pytest.mark.parametrize("written", SPLIT_ANYWHERE)
@pytest.mark.parametrize("glue", [("", ""), ("999", ""), ("", "99"), ("999", "99")])
def test_a_listed_number_split_anywhere_is_refused(tmp_path, written, glue):
    text = f"id {glue[0]}{written}{glue[1]} ok"

    assert "DENYLIST" in {d.type for d in denylist_file(tmp_path, README_LIST).inspect([text])}
    assert "DENYLIST" not in {d.type for d in empty_list().inspect([text])}


@pytest.mark.parametrize(
    "written", ["08-123 456 78", "070 123 45 67", "0701-23 45 67", "08 12 34 56 78"]
)
def test_a_listed_phone_in_any_grouping_is_refused(tmp_path, written):
    found = denylist_file(tmp_path, [*README_LIST, "0812345678"]).inspect([f"tel {written}"])

    assert {d.type for d in found} == {"DENYLIST"}


def test_a_split_number_across_a_letter_is_not_joined(tmp_path):
    assert denylist_file(tmp_path, README_LIST).inspect(["id 191212 nr 121212"]) == []


def test_a_listed_number_split_across_a_line_break_is_refused(tmp_path):
    found = denylist_file(tmp_path, README_LIST).inspect(["070\n123 45\t67"])

    assert {d.type for d in found} == {"DENYLIST"}


@pytest.mark.parametrize(
    "text",
    [
        "13 " * 600_000,
        "1234567890123 " * 100_000,
        "-".join(str(n) for n in range(500_000, 520_000)),
    ],
    ids=["short-groups", "long-groups", "counting"],
)
def test_long_chains_of_digit_groups_are_read_in_linear_time(tmp_path, text):
    import time

    denylist = denylist_file(tmp_path).denylist
    started = time.monotonic()
    assert list(denylist.split_run_matches(text)) == []
    assert time.monotonic() - started < BLOW_UP_SECONDS


def test_the_windows_remembered_are_capped(tmp_path, monkeypatch):
    # Past the cap a window is still hashed, so a listed number late in a long run of
    # distinct digits is found; only memory is bounded.
    monkeypatch.setattr(detection, "SEEN_WINDOWS", 10)
    denylist = denylist_file(tmp_path, README_LIST).denylist
    run = "-".join(str(n) for n in range(500_000, 500_200)) + " 070-123 45 67"

    assert len(list(denylist.split_run_matches(run))) == 1


# Hangul fillers render blank but are letters (Lo), so a listed number with one as
# its gap passed (#49). They are read as a format character: gone, or a gap.
BLANK_LETTERS = ["\u115f", "\u1160", "\u3164", "\uffa0"]


@pytest.mark.parametrize("blank", BLANK_LETTERS)
@pytest.mark.parametrize("template", ["19121212{}1212", "99919121212{}1212"])
def test_a_blank_letter_as_the_gap_is_refused(tmp_path, template, blank):
    written = template.format(blank)

    assert "DENYLIST" in {d.type for d in denylist_file(tmp_path, README_LIST).inspect([written])}
    assert "DENYLIST" not in {d.type for d in empty_list().inspect([written])}


@pytest.mark.parametrize("blank", BLANK_LETTERS)
def test_a_name_joined_by_a_blank_letter_is_refused(tmp_path, blank):
    found = denylist_file(tmp_path, ["Anna Testsson"]).inspect([f"hi anna{blank}testsson"])

    assert {d.type for d in found} == {"DENYLIST"}


# --- A decimal's fractional digits are never a card or a personnummer (#45) ---

# Claude Code's budget note, as Salpline sessions carried it on 2026-11-12: each
# amount was refused, four as CREDIT_CARD and the last as SE_PERSONNUMMER.
BUDGET_AMOUNTS = [
    "0.11679960000000002",
    "0.14618850000000003",
    "0.10487199999999999",
    "0.10825699999999999",
    "0.12650820000000002",
    # Amounts of $1 or more print fewer digits after the point (decided on #45, 1C).
    "2.549992499999999",
    "2.539074350000001",
    "2.358778750000001",
    "2.479228799999999",
]


@pytest.mark.parametrize("amount", BUDGET_AMOUNTS)
def test_a_budget_note_with_float_digits_passes(amount):
    note = f"<system-reminder>\nUSD budget: ${amount}/$3; $2.88 remaining\n</system-reminder>"

    assert empty_list().inspect([note]) == []


def test_a_budget_note_behind_a_zero_width_space_passes():
    # A format character is dropped from Presidio's view: the offsets must still line up.
    assert empty_list().inspect(["\u200b$\u200b0.11679960000000002/$3"]) == []


def test_a_dotted_card_number_is_still_refused():
    assert [d.type for d in empty_list().inspect(["card 4111.1111.1111.1111"])] == ["CREDIT_CARD"]


def test_a_card_number_after_a_full_stop_is_not_a_decimal():
    found = empty_list().inspect(["Paid. 4111 1111 1111 1111", "Paid.4111111111111111"])

    assert [d.type for d in found] == ["CREDIT_CARD"]


def test_a_personnummer_after_a_numbered_heading_is_not_a_decimal():
    assert [d.type for d in empty_list().inspect([f"v1. {PNR}"])] == ["SE_PERSONNUMMER"]


@pytest.mark.parametrize(
    "written",
    [
        "1.4111111111111111",
        "x1.4111111111111111",
        "1.4111 1111 1111 1111",
        "1.4111-1111-1111-1111",
        "2.4111.1111.1111.1111",
        # A card holding a run of zeros, but split into groups.
        "0.4000 0000 0000 0002",
    ],
)
def test_a_card_behind_a_decimal_point_is_still_refused(written):
    # The security pass on #45: a "1." prefix alone must not let a number out.
    assert [d.type for d in empty_list().inspect([written])] == ["CREDIT_CARD"]


@pytest.mark.parametrize("written", ["1.19121212-1212", "1.121212-1212", "1.191212121212"])
def test_a_personnummer_behind_a_decimal_point_is_still_refused(written):
    assert [d.type for d in empty_list().inspect([written])] == ["SE_PERSONNUMMER"]


# --- A listed phone written with Sweden's country code (#52) ---

PLUS_46 = ["+46 70 123 45 67", "+46701234567", "0046 70 123 45 67"]


@pytest.mark.parametrize("written", PLUS_46)
def test_a_listed_phone_with_the_country_code_is_refused(tmp_path, written):
    found = denylist_file(tmp_path, README_LIST).inspect([f"ring {written} ikväll"])

    assert {d.type for d in found} == {"DENYLIST"}
    assert "DENYLIST" not in {d.type for d in empty_list().inspect([f"ring {written}"])}


@pytest.mark.parametrize(
    "written",
    ["08-123 45 67, +46 70 123 45 67", "id 999+46 70 123 45 67", "tel:+46-70-123 45 67"],
)
def test_a_country_code_after_a_plus_inside_a_chain_is_read(tmp_path, written):
    found = denylist_file(tmp_path, README_LIST).inspect([written])

    assert {d.type for d in found} == {"DENYLIST"}


@pytest.mark.parametrize(
    "written",
    [
        "070-111 22 33, 0046 70 123 45 67",
        "14:32 0046 70 123 45 67",
        "08-123 45 67 0046-70-123 45 67",
        "070-111 22 33, +46 70 123 45 67",
        "14:32 +46 70 123 45 67",
        "14:32 00 46 70 123 45 67",
        "070-111 22 33, 00 46 70 123 45 67",
        "070-111 22 33, 0 046 70 123 45 67",
        "14:32 + 46 70 123 45 67",
        "070-111 22 33, +4 6 70 123 45 67",
    ],
)
def test_a_country_code_starting_a_group_inside_a_chain_is_read(tmp_path, written):
    found = denylist_file(tmp_path, README_LIST).inspect([written])

    assert {d.type for d in found} == {"DENYLIST"}
    assert "DENYLIST" not in {d.type for d in empty_list().inspect([written])}


@pytest.mark.parametrize(
    "written", ["id 1246701234567", "id 12 46 70 123 45 67", "id 12 4670123456 7"]
)
def test_a_run_holding_46_in_the_middle_is_not_changed(tmp_path, written):
    assert denylist_file(tmp_path, README_LIST).inspect([written]) == []


@pytest.mark.parametrize("text", ["+46 1 " * 150_000, "+0046-7" * 120_000, "0046 7 " * 120_000])
def test_many_country_codes_in_a_chain_are_read_in_linear_time(tmp_path, text):
    # Each "+" adds a short national run; the deadline bounds the rest (#54).
    import time

    denylist = denylist_file(tmp_path).denylist
    started = time.monotonic()
    assert list(denylist.split_run_matches(text)) == []
    assert time.monotonic() - started < BLOW_UP_SECONDS


# --- One time budget for the whole request's scan (#54) ---


def digit_groups(count: int, seed: int = 54) -> str:
    """``count`` random six-digit groups: no window repeats, so none is skipped."""
    import random

    rng = random.Random(seed)
    return " ".join(f"{rng.randrange(10**6):06d}" for _ in range(count))


async def test_a_body_too_slow_to_scan_is_refused_within_the_limit(monkeypatch):
    import time

    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", 0.2)
    # ~1 MB of digit groups: about 3 s to scan in full.
    started = time.monotonic()
    response, upstream = await send(request(text(digit_groups(150_000, seed=1))))
    elapsed = time.monotonic() - started

    assert refusal(response) == "privacy-proxy: refused (SCAN_TOO_SLOW)"
    assert upstream.requests == []
    assert elapsed < 0.2 + 1.0


def test_the_deadline_holds_across_text_parts(tmp_path, monkeypatch):
    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", 0.3)
    scanner = denylist_file(tmp_path, README_LIST)
    # Each part scans in ~0.05 s, well under the limit; forty of them do not.
    parts = [digit_groups(3_000, seed=n) for n in range(40)]
    calls = []
    real = scanner._inspect
    monkeypatch.setattr(scanner, "_inspect", lambda *a: calls.append(a) or real(*a))

    found = scanner.inspect(parts)

    assert Detection("SCAN_TOO_SLOW", None) in found
    assert 1 < len(calls) < len(parts)


def test_a_part_cut_short_is_not_cached(tmp_path, monkeypatch):
    scanner = denylist_file(tmp_path, README_LIST)
    written = digit_groups(60_000) + " tel 070-123 45 67"
    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", 0.01)

    assert scanner.inspect([written]) == [Detection("SCAN_TOO_SLOW", None)]

    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", 10.0)
    assert {d.type for d in scanner.inspect([written])} == {"DENYLIST"}


def test_the_country_code_search_stops_at_the_deadline(tmp_path):
    import time

    denylist = denylist_file(tmp_path).denylist
    started = time.monotonic()
    with pytest.raises(detection._ScanTooSlow):
        list(denylist.split_run_matches("+46 1 " * 300_000, deadline=started - 1))
    with pytest.raises(detection._ScanTooSlow):
        list(denylist.digit_run_matches(["46701234567"] * 10, deadline=started - 1))


def test_a_pdf_read_past_the_deadline_refuses_the_request(monkeypatch):
    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", -1.0)
    body = request(text("nothing listed here"))

    assert SCANNER.check(body, trusted=True) == [Detection("SCAN_TOO_SLOW", None)]


def test_many_pdfs_share_the_request_deadline(monkeypatch):
    import base64
    import time

    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", 0.2)
    read = []

    class SlowPdfs:
        def text(self, data):
            read.append(data)
            time.sleep(0.1)
            return "nothing listed here"

    monkeypatch.setattr(SCANNER, "pdfs", SlowPdfs())
    source = {"type": "base64", "media_type": "application/pdf"}
    documents = [
        {
            "type": "document",
            "source": {**source, "data": base64.b64encode(b"%%PDF-%d" % n).decode()},
        }
        for n in range(20)
    ]

    assert SCANNER.check(request(*documents), trusted=True) == [Detection("SCAN_TOO_SLOW", None)]
    assert 1 < len(read) < 20


def test_pattern_matches_past_the_deadline_refuse(tmp_path, monkeypatch):
    import time

    scanner = denylist_file(tmp_path, README_LIST)
    hashed = []
    real = scanner.denylist.hash
    monkeypatch.setattr(scanner.denylist, "hash", lambda v: hashed.append(v) or real(v))
    personnummer = " ".join(["19121212-1212"] * 50)

    with pytest.raises(detection._ScanTooSlow):
        scanner._inspect(personnummer, date.today(), time.monotonic() - 1)
    # Stopped at the first match, not after reading all fifty.
    assert hashed == []
