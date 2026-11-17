"""National ID Detectors per country (#65).

Samples come from Presidio's own recogniser tests (presidio-analyzer,
``tests/test_*_recognizer.py``), never a real person's number.
"""

import pytest

from privacy_proxy.detection import Scanner
from privacy_proxy.policy import COUNTRIES, Policy


def verhoeff(digits: str) -> str:
    """The Verhoeff check digit, as Presidio's NG_NIN test builds its samples."""
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 7, 8, 6, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    inverse = [0, 4, 3, 2, 1, 5, 9, 8, 7, 6]
    check = 0
    for i, digit in enumerate(reversed(digits)):
        check = d[check][p[(i + 1) % 8][int(digit)]]
    return str(inverse[check])


NG_NIN = "1234567890" + verhoeff("1234567890")

# (country, valid sample, its entity type, the same sample made invalid)
SAMPLES = [
    ("SE", "19121212-1212", "SE_PERSONNUMMER", "19121212-1213"),
    ("FI", "131052-308T", "FI_PERSONAL_IDENTITY_CODE", "131052-308A"),
    ("DE", "12345678903", "DE_TAX_ID", "12345678904"),
    ("DE", "15070649C103", "DE_SOCIAL_SECURITY", "15070649C104"),
    ("GB", "401-023-2137", "UK_NHS", "401-023-2138"),
    # No checksum exists: Presidio rejects invalid numbers instead (serial 1120 is
    # the Woolworth wallet number).
    ("US", "078-05-1123", "US_SSN", "078-05-1120"),
    ("PL", "44051401458", "PL_PESEL", "44051401459"),
    ("ES", "55555555K", "ES_NIF", "55555555A"),
    ("ES", "Z8078221M", "ES_NIE", "Z8078221A"),
    ("IT", "AAAAAA00B11C333Y", "IT_FISCAL_CODE", "AAAAAA00B11C333N"),
    ("CA", "130 692 544", "CA_SIN", "130 692 545"),
    ("AU", "876 543 210", "AU_TFN", "876 543 211"),
    # The check digit is the ninth; the tenth is the card's issue number.
    ("AU", "2123 45670 1", "AU_MEDICARE", "2123 45671 1"),
    ("IN", "3123 4567 8909", "IN_AADHAAR", "3123 4567 8908"),
    ("KR", "960121-1234567", "KR_RRN", "960121-1234568"),
    ("TH", "1234567890121", "TH_TNIN", "1234567890122"),
    ("TR", "10000000146", "TR_NATIONAL_ID", "10000000147"),
    ("ZA", "8001015009087", "ZA_ID_NUMBER", "8001015009088"),
    ("NG", NG_NIN, "NG_NIN", NG_NIN[:-1] + str((int(NG_NIN[-1]) + 1) % 10)),
]
# Presidio keeps these with a bad check character, at a lower score, and the proxy
# refuses them too (decided on #65, 2026-11-15): a fiscal-code-shaped string is
# almost never anything but a fiscal code, mistyped or not. KR numbers issued since
# October 2020 end in random digits, with no check digit to test.
KEEPS_INVALID = {"IT_FISCAL_CODE", "KR_RRN"}


def only(*countries: str) -> Scanner:
    """National IDs from ``countries`` and nothing else: no phone, card or IBAN."""
    off = {"action": "off"}
    return Scanner(
        policy=Policy.from_dict(
            {
                "detectors": {
                    "national_id": {"countries": list(countries)},
                    "phone": off,
                    "card": off,
                    "iban": off,
                }
            }
        )
    )


def kinds(scanner: Scanner, written: str) -> set[str]:
    return {d.type for d in scanner.inspect([f"id {written} ok"])}


def ids(samples):
    return [entity for _, _, entity, _ in samples]


def test_every_country_has_a_sample():
    assert {country for country, *_ in SAMPLES} == set(COUNTRIES)
    assert {entity for _, _, entity, _ in SAMPLES} == {e for es in COUNTRIES.values() for e in es}


@pytest.mark.parametrize(("country", "sample", "entity", "invalid"), SAMPLES, ids=ids(SAMPLES))
def test_a_valid_id_is_refused_with_its_type(country, sample, entity, invalid):
    assert kinds(only(country), sample) == {entity}


CHECKED = [s for s in SAMPLES if s[2] not in KEEPS_INVALID]
UNCHECKED = [s for s in SAMPLES if s[2] in KEEPS_INVALID]


@pytest.mark.parametrize(("country", "sample", "entity", "invalid"), CHECKED, ids=ids(CHECKED))
def test_the_same_id_made_invalid_passes(country, sample, entity, invalid):
    assert kinds(only(country), invalid) == set()


@pytest.mark.parametrize(("country", "sample", "entity", "invalid"), UNCHECKED, ids=ids(UNCHECKED))
def test_an_italian_or_korean_id_made_invalid_is_still_refused(country, sample, entity, invalid):
    assert kinds(only(country), invalid) == {entity}


@pytest.mark.parametrize(("country", "sample", "entity", "invalid"), SAMPLES, ids=ids(SAMPLES))
def test_a_country_left_off_the_list_passes(country, sample, entity, invalid):
    # Italy's code holds letters, so none of the digit samples reads as one; Italy's
    # own sample is checked against Sweden.
    other = "SE" if country == "IT" else "IT"

    assert kinds(only(other), sample) == set()


DEFAULT_SAMPLES = [s for s in SAMPLES if s[0] in {"SE", "FI", "ES", "IT", "ZA"}]


def test_the_default_reads_the_five_countries_whose_ids_dont_read_as_code():
    # Decided on #65 (2026-11-15): the other 11 read a bare 9- to 13-digit number
    # (an id, a timestamp) as an ID often enough to refuse coding traffic.
    assert set(Policy.default().national_id.countries) == {"SE", "FI", "ES", "IT", "ZA"}


@pytest.mark.parametrize(
    ("country", "sample", "entity", "invalid"), DEFAULT_SAMPLES, ids=ids(DEFAULT_SAMPLES)
)
def test_a_default_country_is_refused_with_no_policy_file(country, sample, entity, invalid):
    assert entity in kinds(Scanner(), sample)


@pytest.mark.parametrize("sample", ["12345678903", "401-023-2137", "078-05-1123"])
def test_a_german_uk_or_us_id_passes_with_no_policy_file(sample):
    # DE_TAX_ID, UK_NHS, US_SSN: opt-in only.
    assert kinds(Scanner(), sample) == set()


def test_every_country_can_be_listed_at_once():
    scanner = only(*COUNTRIES)

    assert kinds(scanner, "131052-308T") == {"FI_PERSONAL_IDENTITY_CODE"}
    assert kinds(scanner, "AAAAAA00B11C333Y") == {"IT_FISCAL_CODE"}


def test_a_float_holding_an_eleven_digit_fraction_passes():
    # DE_TAX_ID is 11 digits; the "." is folded to a space, so it stands alone, and
    # 12345678901 has no valid check digit.
    assert kinds(only("DE"), "3.12345678901") == set()


def test_the_swedish_rules_still_hold_with_every_country_on():
    scanner = only(*COUNTRIES)

    # A personnummer still hashes its last ten digits, however it is written.
    short = scanner.inspect(["121212-1212"])
    long = scanner.inspect(["19121212-1212"])
    assert [d.type for d in short] == ["SE_PERSONNUMMER"]
    assert short == long
