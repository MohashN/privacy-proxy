import pytest
from test_detection import PNR
from test_subscription_lane import SCANNER

from privacy_proxy import cli
from privacy_proxy.detection import Denylist, Scanner
from privacy_proxy.policy import Policy, PolicyError

ROOT = __import__("pathlib").Path(__file__).parent.parent
# The public test card number (Luhn-valid) and a documentation IBAN.
CARD = "4111 1111 1111 1111"
IBAN = "GB82 WEST 1234 5698 7654 32"


def kinds(scanner: Scanner, text: str) -> set[str]:
    return {d.type for d in scanner.inspect([text])}


def policy_file(tmp_path, text: str):
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_default_policy_refuses_personnummer_card_and_iban():
    scanner = Scanner(policy=Policy.default())

    assert kinds(scanner, f"pnr {PNR}") == {"SE_PERSONNUMMER"}
    assert kinds(scanner, f"card {CARD}") == {"CREDIT_CARD"}
    assert kinds(scanner, f"iban {IBAN}") == {"IBAN_CODE"}
    # The shared test scanner builds with no policy at all and is the same.
    assert kinds(SCANNER, f"card {CARD}") == {"CREDIT_CARD"}


def test_a_detector_turned_off_lets_its_kind_through(tmp_path):
    policy = Policy.load(policy_file(tmp_path, "detectors:\n  card: {action: off}\n"))
    scanner = Scanner(policy=policy)

    assert kinds(scanner, f"card {CARD}") == set()
    assert kinds(scanner, f"pnr {PNR}") == {"SE_PERSONNUMMER"}
    assert kinds(scanner, f"iban {IBAN}") == {"IBAN_CODE"}


def test_every_detector_off_lets_everything_through(tmp_path):
    text = "detectors:\n" + "".join(
        f"  {n}: {{action: off}}\n" for n in ("national_id", "phone", "card", "iban", "deny_list")
    )
    scanner = Scanner(policy=Policy.load(policy_file(tmp_path, text)))

    assert kinds(scanner, f"{PNR} {CARD} {IBAN}") == set()


def test_a_detector_left_out_of_the_file_stays_on(tmp_path):
    policy = Policy.load(policy_file(tmp_path, "detectors: {}\n"))

    assert policy.on_names() == ["national_id", "phone", "card", "iban", "deny_list"]
    assert Policy.load(policy_file(tmp_path, "")) == Policy.default()


def test_the_deny_list_off_is_not_consulted():
    denylist = Denylist.from_dict(Denylist.build(["Testa Testsson"]))
    on = Scanner(denylist, Policy.default())
    off = Scanner(denylist, Policy.from_dict({"detectors": {"deny_list": {"action": "off"}}}))

    assert kinds(on, "hello Testa Testsson") == {"DENYLIST"}
    assert kinds(off, "hello Testa Testsson") == set()


def test_the_example_file_loads():
    assert Policy.load(ROOT / "policy.example.yaml") == Policy.default()


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("detectors:\n  card: {action: maybe}\n", "card"),
        ("detectors:\n  cards: {action: off}\n", "cards"),
        ("detectors:\n  card: {mode: off}\n", "mode"),
        ("detectors:\n  card: off\n", "card"),
        ("detectors:\n  iban: {countries: [SE]}\n", "countries"),
        ("detectors:\n  national_id: {countries: [XX]}\n", "countries"),
        ("detectors:\n  national_id: {countries: SE}\n", "countries"),
        ("detectors:\n  national_id: {countries: [[SE]]}\n", "countries"),
        ("detectors:\n  phone: {regions: [XX]}\n", "regions"),
        ("detectors:\n  phone: {regions: [se]}\n", "regions"),
        ("detectors:\n  phone: {regions: SE}\n", "regions"),
        ("detectors:\n  phone: {match: maybe}\n", "match"),
        ("detectors:\n  card: {regions: [SE]}\n", "regions"),
        ("detectors: [card]\n", "detectors"),
        ("extra: 1\n", "extra"),
        ("- card\n", "mapping"),
    ],
)
def test_a_bad_file_exits_naming_the_path_and_the_key(monkeypatch, tmp_path, text, key):
    path = policy_file(tmp_path, text)
    monkeypatch.setenv("POLICY_PATH", str(path))
    monkeypatch.delenv("DENYLIST_PATH", raising=False)

    with pytest.raises(SystemExit) as raised:
        cli.main([])

    assert str(path) in str(raised.value)
    assert key in str(raised.value)
    assert "maybe" not in str(raised.value)


def test_a_file_that_is_not_yaml_exits_without_quoting_it(monkeypatch, tmp_path):
    path = policy_file(tmp_path, "detectors: [unclosed SECRET-VALUE\n")
    monkeypatch.setenv("POLICY_PATH", str(path))

    with pytest.raises(SystemExit) as raised:
        cli.main([])

    assert str(path) in str(raised.value)
    assert "SECRET-VALUE" not in str(raised.value)


def test_a_missing_policy_file_exits(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICY_PATH", str(tmp_path / "missing.yaml"))

    with pytest.raises(SystemExit, match="can't read the Policy file"):
        cli.main([])


def test_with_no_denylist_the_proxy_starts_and_still_refuses(monkeypatch, capsys):
    monkeypatch.delenv("DENYLIST_PATH", raising=False)
    monkeypatch.setenv("POLICY_PATH", "")

    scanner = cli.load_scanner()

    err = capsys.readouterr().err
    assert "no Deny-list loaded" in err
    assert "Detectors on: national_id, phone, card, iban\n" in err
    assert kinds(scanner, f"pnr {PNR}") == {"SE_PERSONNUMMER"}
    assert kinds(scanner, "Testa Testsson") == set()


def test_without_a_denylist_hashes_use_a_salt_of_their_own():
    one, other = Scanner(), Scanner()

    first = one.inspect([f"pnr {PNR}"])
    assert first == one.inspect([f"pnr {PNR}"])
    assert first != other.inspect([f"pnr {PNR}"])


def test_an_unreadable_denylist_still_stops_the_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICY_PATH", "")
    monkeypatch.setenv("DENYLIST_PATH", str(tmp_path / "missing.json"))
    with pytest.raises(SystemExit, match="can't read the deny-list"):
        cli.main([])

    empty = tmp_path / "empty.json"
    empty.write_text("")
    monkeypatch.setenv("DENYLIST_PATH", str(empty))
    with pytest.raises(SystemExit, match="can't read the deny-list"):
        cli.main([])


def test_a_policy_error_is_a_value_error():
    with pytest.raises(PolicyError):
        Policy.from_dict({"detectors": {"card": {"action": "redact"}}})


def test_a_bare_off_is_read_as_the_word_not_as_false(tmp_path):
    # PyYAML reads an unquoted `off` as the boolean False; both spellings work.
    bare = Policy.load(policy_file(tmp_path, "detectors:\n  card: {action: off}\n"))
    quoted = Policy.load(policy_file(tmp_path, 'detectors:\n  card: {action: "off"}\n'))

    assert bare == quoted
    assert not bare.on("card")


@pytest.mark.parametrize("empty", ["", "   "])
def test_an_empty_denylist_path_stops_the_proxy(monkeypatch, empty):
    monkeypatch.setenv("POLICY_PATH", "")
    monkeypatch.setenv("DENYLIST_PATH", empty)

    with pytest.raises(SystemExit, match="DENYLIST_PATH is set but empty"):
        cli.main([])
