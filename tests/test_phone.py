"""The phone Detector (#64): a number written the way people write phones is refused."""

import time

import phonenumbers
import pytest
from test_detection import BLOW_UP_SECONDS, refusal, request, send, text

from privacy_proxy import detection
from privacy_proxy.detection import Detection, Scanner, phones
from privacy_proxy.policy import Policy, PolicyError


def scanner(**phone) -> Scanner:
    return Scanner(policy=Policy.from_dict({"detectors": {"phone": phone}}))


DEFAULT = scanner()
SE = scanner(regions=["SE"])
SE_VALID = scanner(regions=["SE"], match="valid")
OFF = scanner(action="off", regions=["SE"])


def kinds(scan: Scanner, written: str) -> set[str]:
    return {d.type for d in scan.inspect([f"ring {written} ikväll"])}


# --- Refused ---


@pytest.mark.parametrize("written", ["+44 20 7946 0958", "+46 70 123 45 67", "+1 (415) 555-0132"])
def test_an_international_number_is_refused_with_no_region_listed(written):
    assert kinds(DEFAULT, written) == {"PHONE_NUMBER"}


@pytest.mark.parametrize("written", ["070-123 45 67", "070 123 45 67", "070.123.45.67"])
def test_a_national_number_is_refused_once_its_region_is_listed(written):
    # "070.123.45.67" reaches the matcher as "070 123 45 67": Presidio's view folds dots.
    assert kinds(SE, written) == {"PHONE_NUMBER"}
    assert kinds(DEFAULT, written) == set()


@pytest.mark.parametrize(
    "written",
    ["+46 70 1234567", "+1 212 5551234", "＋４６ ７０ １２３ ４５ ６７", "+٤٦ ٧٠ ١٢٣ ٤٥ ٦٧"],
)
def test_a_phone_grouped_its_own_way_or_in_other_digits_is_refused(written):
    # From #64's security pass: EXACT_GROUPING let the first two out, and a text with
    # no ASCII digit was never read.
    assert kinds(DEFAULT, written) == {"PHONE_NUMBER"}


def test_a_national_number_grouped_its_own_way_is_refused():
    assert kinds(SE, "070-1234567") == {"PHONE_NUMBER"}


def test_valid_also_refuses_a_bare_run_of_digits():
    assert kinds(SE_VALID, "0701234567") == {"PHONE_NUMBER"}
    assert kinds(SE, "0701234567") == set()


def test_two_phones_glued_together_are_both_found():
    found = DEFAULT.inspect(["+46701234567+46701234568"])

    assert [d.type for d in found] == ["PHONE_NUMBER", "PHONE_NUMBER"]


def test_one_number_hashes_alike_however_it_is_written():
    # E.164 is hashed, so a refusal's log line tells the same phone apart from others.
    one = SE.inspect(["+46 70 123 45 67"])
    other = SE.inspect(["070-123 45 67"])

    assert one == other
    assert one[0].hash is not None


async def test_a_fresh_install_refuses_a_phone_and_names_the_kind():
    response, upstream = await send(request(text("call me on +44 20 7946 0958")))

    assert refusal(response) == "privacy-proxy: refused (PHONE_NUMBER)"
    assert upstream.requests == []


# --- Passed ---


CODE = [
    "20240101123456",
    "timeout=12345678",
    "550e8400-e29b-41d4-a716-446655440000",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "version 1.20.300",
    "2024-01-15T08:30:00Z",
    "3.4612345678",
    "commit 3f2a9c1",
    "192.168.100.200:8080",
    "x = [1, 2, 3, 4, 5, 6, 7, 8, 9]",
]


@pytest.mark.parametrize("written", [*CODE, "0701234567"])
def test_coding_traffic_passes_with_a_region_listed(written):
    assert kinds(SE, written) == set()
    assert kinds(DEFAULT, written) == set()


def test_a_json_integer_is_a_bare_run_and_passes():
    # The API lane reads numbers as text (strict=True): 46701234567 has no "+" and no
    # grouping, so under ``grouped`` it is not a phone. Intended (#64's Traps).
    body = request({"type": "tool_use", "id": "t", "name": "x", "input": {"to": 46701234567}})

    assert SE.check(body, strict=True, trusted=True) == []


@pytest.mark.parametrize("written", ["+44 20 7946 0958", "070-123 45 67", "0701234567"])
def test_off_lets_every_phone_through(written):
    assert kinds(OFF, written) == set()


# --- Long texts (#54) ---


def test_a_phone_after_many_failed_candidates_is_still_found():
    # The matcher gives up after 65,535 candidates per call; read in windows, each
    # call sees far fewer, so a phone at the end of a long text is still found.
    junk = "1-2 x " * 70_000
    whole = list(phonenumbers.PhoneNumberMatcher(junk + "+46 70 123 45 67", None))

    assert whole == []  # the reason for the windows
    assert kinds(DEFAULT, junk + "+46 70 123 45 67") == {"PHONE_NUMBER"}


def test_a_phone_across_a_window_edge_is_found_once(monkeypatch):
    monkeypatch.setattr(detection, "PHONE_WINDOW", 100)
    written = ("word " * 17 + "+46 70 123 45 67 ") * 50

    found = list(phones(written, (), "grouped"))

    assert len(found) == 50
    assert len({f.start for f in found}) == 50
    assert all(written[f.start : f.end] == "+46 70 123 45 67" for f in found)


def test_the_deadline_is_read_between_windows(monkeypatch):
    monkeypatch.setattr(detection, "SCAN_MAX_SECONDS", 0.2)
    # ~1 MB of digit groups: seconds for the phone matcher alone.
    body = " ".join(f"{n:06d}" for n in range(150_000))
    started = time.monotonic()

    found = SE.inspect([body])

    assert found == [Detection("SCAN_TOO_SLOW", None)]
    assert time.monotonic() - started < BLOW_UP_SECONDS


# --- The Policy file ---


def test_the_default_is_on_with_no_regions_and_grouped():
    phone = Policy.default().phone

    assert Policy.default().on("phone")
    assert (phone.regions, phone.match) == ((), "grouped")


@pytest.mark.parametrize(
    "rule", [{"regions": ["XX"]}, {"regions": ["se"]}, {"regions": "SE"}, {"match": "loose"}]
)
def test_a_bad_phone_rule_is_refused(rule):
    with pytest.raises(PolicyError):
        Policy.from_dict({"detectors": {"phone": rule}})
