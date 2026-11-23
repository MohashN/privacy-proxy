"""The Detectors: what a request may not carry out of the house.

Two checks run over every text the model would see, and either one refuses:

- **Presidio**, pattern recognisers only: a national ID number from each country the
  Policy lists (#65), a card number or an IBAN. Each is validated (a checksum, or a
  rule that rejects invalid numbers), so a random run of digits rarely counts.
  Organisation numbers are company business and pass, and so does a float's printed
  rounding noise ("0.11679960000000002", #45).
- **A phone number** (#64), read by Google's ``phonenumbers``: written with a "+", or
  in a listed region's national format, and by default only when written the way
  people write phones, never as a bare run of digits.
- **The Operator's deny-list**: names and addresses, stored salted and hashed (R25). The
  proxy never holds the plain entries; it normalises what it sees, hashes every run of
  1 to 6 words with the same salt, and looks the hash up; inside a run of 11 or
  more digits, every 10- and 12-digit window too, and the same inside each chain of
  digit groups joined across their gaps ("999" + "191212 121212" + "99",
  "070-123 45 67"), so a listed number glued to other digits or split anywhere is
  still found. A number written with Sweden's country code ("+46 70 123 45 67",
  "0046 70 123 45 67") is looked up in its "0" form too (#52).
  Any Unicode digit (Arabic-Indic, Devanagari) is read as its ASCII digit here.

A PDF sent as base64 is read too: its text layer is extracted with pypdf, in memory,
and checked like message text (#10). An image is not: its text could only be read by
OCR. Neither may go to a provider that is not Trusted.

A hit refuses the whole request, and the caller fixes it at the source. The one
exception is Masking (#66, ADR-0001): where the Policy sets a Detector to ``mask``, the
API lane forwards the request with each of its hits replaced by a Placeholder
(``Scanner.mask``). A request whose text takes longer than ``SCAN_MAX_SECONDS`` to
check is refused as ``SCAN_TOO_SLOW`` (#54), never passed.
"""

import base64
import hashlib
import io
import json
import logging
import math
import queue
import re
import secrets
import sys
import threading
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, date, datetime
from pathlib import Path

import phonenumbers
import pypdf
from presidio_analyzer import AnalyzerEngine, EntityRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NoOpNlpEngine
from presidio_analyzer.predefined_recognizers import (
    AuMedicareRecognizer,
    AuTfnRecognizer,
    CaSinRecognizer,
    CreditCardRecognizer,
    DeSocialSecurityRecognizer,
    DeTaxIdRecognizer,
    EsNieRecognizer,
    EsNifRecognizer,
    FiPersonalIdentityCodeRecognizer,
    IbanRecognizer,
    InAadhaarRecognizer,
    ItFiscalCodeRecognizer,
    KrRrnRecognizer,
    NgNinRecognizer,
    NhsRecognizer,
    PlPeselRecognizer,
    SePersonnummerRecognizer,
    ThTninRecognizer,
    TrNationalIdRecognizer,
    UsSsnRecognizer,
    ZaIdNumberRecognizer,
)

from privacy_proxy.policy import GROUPED, Policy

# The longest entry the deny-list can match, in words. "Storgatan 12 123 45 Stockholm"
# is five once punctuation is gone.
MAX_WORDS = 6

# Presidio needs one language code to pick recognisers by; the text itself is never
# parsed, so its value only has to agree between the registry and each call.
LANGUAGE = "xx"

# Each Presidio type's recogniser; a Policy decides which of them run. Each is built
# with ``LANGUAGE``: Presidio defaults them to "en", "de", ..., and the registry would
# then drop them without a word.
_RECOGNISERS: dict[str, type[EntityRecognizer]] = {
    "SE_PERSONNUMMER": SePersonnummerRecognizer,
    "FI_PERSONAL_IDENTITY_CODE": FiPersonalIdentityCodeRecognizer,
    "DE_TAX_ID": DeTaxIdRecognizer,
    "DE_SOCIAL_SECURITY": DeSocialSecurityRecognizer,
    "UK_NHS": NhsRecognizer,
    "US_SSN": UsSsnRecognizer,
    "PL_PESEL": PlPeselRecognizer,
    "ES_NIF": EsNifRecognizer,
    "ES_NIE": EsNieRecognizer,
    "IT_FISCAL_CODE": ItFiscalCodeRecognizer,
    "CA_SIN": CaSinRecognizer,
    "AU_TFN": AuTfnRecognizer,
    "AU_MEDICARE": AuMedicareRecognizer,
    "IN_AADHAAR": InAadhaarRecognizer,
    "KR_RRN": KrRrnRecognizer,
    "TH_TNIN": ThTninRecognizer,
    "TR_NATIONAL_ID": TrNationalIdRecognizer,
    "ZA_ID_NUMBER": ZaIdNumberRecognizer,
    "NG_NIN": NgNinRecognizer,
    "CREDIT_CARD": CreditCardRecognizer,
    "IBAN_CODE": IbanRecognizer,
}
PHONE = "PHONE_NUMBER"
# The types read from a bare run of digits, which a decimal's fraction can be (#45):
# all but the IDs that hold letters and the IBAN.
_NUMBERS = (
    *(e for e in _RECOGNISERS if e not in ("IT_FISCAL_CODE", "ES_NIF", "ES_NIE", "IBAN_CODE")),
    PHONE,
)
# A phone's leniency per ``phone.match`` (#64). Both read any valid number;
# ``grouped`` then drops a bare run of digits ("0701234567"), so only a number
# written with a "+" or a separator counts. Not EXACT_GROUPING: it also drops valid
# numbers grouped another way than the library's own ("+46 70 1234567",
# "070-1234567"), which would leak (#64's security pass).
_LENIENCY = {
    GROUPED: phonenumbers.Leniency.VALID,
    "valid": phonenumbers.Leniency.VALID,
}
# The phone matcher reads a text in windows of this many characters, so the deadline
# is read between them (#54) and one call's work stays bounded. Each window is read
# with ``PHONE_OVERLAP`` characters of context on either side, more than the longest
# text its candidate pattern can span (about 550: twenty-one digit blocks of 20, gaps
# of up to 4, and an extension), and keeps only the matches that start in its own
# part: each phone is found once.
PHONE_WINDOW = 65_536
_ANY_DIGIT = re.compile(r"\d")
PHONE_OVERLAP = 1_024

# The shortest run of digits the deny-list also searches inside (#20, #24). The
# deny-list sees a run as one word, and Presidio reads at most a run's first 12
# digits, so a listed number with digits glued on ("999" + "191212121212", or
# "1212121212" + "00") passed both. Runs of 11 and 12 can hold a glued 10-digit
# number; a run of exactly 10 is a word the list matches whole.
MIN_DIGIT_RUN = 11
# The lengths of a personnummer's digits: the short form and the long one.
PERSONNUMMER_DIGITS = (10, 12)
_DIGIT_RUN = re.compile(rf"[0-9]{{{MIN_DIGIT_RUN},}}")
# A chain of digit groups (#24, #43, #50): "999191212 12121299", "070-123 45 67".
# Each gap is one or more characters that are neither letters nor digits (a dash,
# "+", spaces, a newline, "/", ".", "_", ...), the breaks the list already splits
# words on; a letter in it ends the chain. Read on ``_dash_view``'s text. The
# quantifiers are possessive and the classes disjoint, so a failed match backs off
# nothing, and the lookbehind starts each match at a group's first digit: each
# character is read a bounded number of times.
_DIGIT_CHAIN = re.compile(r"(?<![0-9])[0-9]++(?:[\W_]++[0-9]++)*+")
_NOT_DIGIT = re.compile(r"[^0-9]+")
# The distinct windows ``_window_matches`` remembers (#50's security pass): ~80 B
# each, so a few MB whatever the body holds; a 32 MB body of random digits would
# otherwise keep ~64M windows (~5 GB).
SEEN_WINDOWS = 50_000
# Sweden's country code, as a run of digits starts with it (#52): "+46 70 123 45 67"
# and "0046 70 123 45 67" are "070 123 45 67". Read only where the run starts, or
# right after a "+", so a run that merely holds "46" is not changed.
_COUNTRY_CODES = (b"0046", b"46")
_DIGIT_GROUP = re.compile(r"[0-9]+")

# How many texts' verdicts are kept. Every turn resends the whole conversation, so
# all but the newest blocks have been checked before; ~50 bytes per entry.
CACHE_SIZE = 100_000

# A PDF's limits (#10, R2): pypdf parses untrusted input, so a crafted or huge PDF is
# refused rather than allowed to stall the proxy. Its extracted text is cached by the
# SHA-256 of its base64 data, since every turn resends it (R3).
PDF_MAX_PAGES = 100
PDF_MAX_SECONDS = 2.0
PDF_CACHE_SIZE = 64
# Extractions that may run at once. One that overruns its time is abandoned, not
# killed: it stops itself at its next page, and the spare workers keep the next
# PDF moving meanwhile.
PDF_WORKERS = 4

# One time budget for all the text parts of a request (#54): past it the request is
# refused as SCAN_TOO_SLOW, never passed. The slowest real scan took 258 ms; a 32 MiB
# body of digit groups would take ~90 s. Checked cooperatively (a thread can't be
# stopped): between parts, between a part's stages, and every ``SCAN_TICK`` windows
# or words, so the work itself ends.
SCAN_MAX_SECONDS = 10.0
SCAN_TICK = 4096

# Letters that render blank, the Hangul fillers (#49): category Lo, so neither a
# gap nor a format character to Unicode, yet "19121212\u31641212" looks spaced.
# Every view reads them as a format character. NFKC maps U+3164 and U+FFA0 to
# U+1160, but Presidio's view is not NFKC'd, so all four are listed.
_BLANK_LETTERS = frozenset({0x115F, 0x1160, 0x3164, 0xFFA0})

# pypdf logs a malformed file's quirks as warnings; the proxy's own log line says
# what happened, and nothing else may write beside it.
logging.getLogger("pypdf").setLevel(logging.CRITICAL)


Table = dict[int, str | None]


def _tables() -> tuple[Table, Table, Table, Table, Table]:
    """Per-character rules as ``str.translate`` tables, built once at import.

    A loop in Python over each character costs ~0.2 s per megabyte; a table
    lookup in C costs a tenth of that.
    """
    joined: Table = {}  # normalise: format characters vanish
    split: Table = {}  # normalise: format characters are a gap
    presidio: Table = {}
    # The deny-list only (#24, R1): every Unicode decimal digit as its ASCII one.
    # Presidio already reads them, and #9's date rules depend on its input.
    digits: Table = {}
    # The split-run search (#24, #43): digits made ASCII, combining marks and format
    # characters gone, any dash or minus sign "-".
    dash: Table = {0x2212: "-"}
    for code in range(sys.maxunicode + 1):
        category = unicodedata.category(chr(code))
        if code in _BLANK_LETTERS:
            category = "Cf"
        if category == "Nd" and code > 0x7F:
            digit = str(unicodedata.decimal(chr(code)))
            joined[code] = split[code] = digits[code] = dash[code] = digit
        elif category == "Mn":
            joined[code] = split[code] = dash[code] = None
        elif category == "Cf":
            joined[code] = None
            split[code] = " "
        elif category[0] in "PS":
            joined[code] = split[code] = " "
        if category == "Cf":
            presidio[code] = dash[code] = None
        elif category == "Pd":
            presidio[code] = dash[code] = "-"
        elif chr(code).isspace() and chr(code) not in "\n\r":
            presidio[code] = " "
    presidio[ord(".")] = " "
    return joined, split, presidio, digits, dash


_JOINED, _SPLIT, _PRESIDIO, _DIGITS, _DASH = _tables()
# The characters that read as one word or as two (a zero-width space, a Hangul
# filler): those ``normalise`` drops, or with ``split_format`` makes a gap.
_FORMAT = frozenset(
    chr(code) for code, rule in _JOINED.items() if rule is None and _SPLIT[code] == " "
)
# Presidio's view with "." kept: each character at the same offset, so what comes
# before a match can be read (#45).
_FRACTION = {code: rule for code, rule in _PRESIDIO.items() if code != ord(".")}


def normalise(text: str, split_format: bool = False) -> list[str]:
    """The words of ``text`` as the deny-list compares them.

    NFKC and casefold, so "Ｔｅｓｔａ" and "TESTA" are "testa"; any Unicode digit
    made ASCII, so "١٢١٢" is "1212"; accents dropped, so
    "vägen" and "vagen" are one word; invisible format characters (a zero-width
    space) removed, or with ``split_format`` read as a gap; punctuation and symbols
    become a space, so "Testsson's", "Anna-Karin" and "testa+testsson" split where
    an entry would; any run of whitespace, line breaks included, is one gap.
    """
    folded = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text).casefold())
    return folded.translate(_SPLIT if split_format else _JOINED).split()


def _presidio_view(text: str) -> str:
    """``text`` with the spellings Presidio's patterns don't expect made plain.

    Invisible format characters (a zero-width space, a soft hyphen) removed, any
    dash ("–" from autocorrect) made "-", any space (no-break, tab) or "." made
    " ". Only the check reads this; the request is never changed.
    """
    return text.translate(_PRESIDIO)


def _fraction_view(text: str) -> str:
    """``text`` as ``_presidio_view`` makes it, at the same offsets, "." kept (#45)."""
    return text.translate(_FRACTION)


# A digit and a decimal point: what comes before a decimal's fractional part.
_DECIMAL_POINT = re.compile(r"[0-9]\.")
_DIGIT_RUN_AT = re.compile(r"[0-9]+")
# A double printed in full has 16 or 17 significant digits, the last of them
# rounding noise: "0.11679960000000002", "2.549992499999999".
FLOAT_DIGITS = 16
_ROUNDING_NOISE = re.compile(r"0{6}|9{6}")


def _integer_digits(fraction_view: str, point: int) -> str:
    """The unbroken run of ASCII digits that ends right before ``point``."""
    begin = point
    while begin > 0 and "0" <= fraction_view[begin - 1] <= "9":
        begin -= 1
    return fraction_view[begin:point]


def float_noise(fraction_view: str, start: int, end: int) -> bool:
    """Whether a match is the fractional part of a float printed in full (#45).

    Claude Code adds a note to each turn of a session with a dollar cap, its spend
    a raw float: "USD budget: $0.11679960000000002/$3". The digits after the point
    read as a card number about one time in ten, and their first 12 as a
    personnummer when they form a date.

    All of these hold, or the match is still refused: a digit and "." come right
    before it; it lies inside one unbroken run of ASCII digits starting there, so
    no space or dash splits it; the number has at least ``FLOAT_DIGITS``
    significant digits, counting those before the point and dropping leading
    zeros, as a double printed in full does ("2.549992499999999" has 16); the
    digits after the point hold six 0s or six 9s in a row. A card behind "1."
    ("1.4111111111111111"), in dotted or spaced groups, or after a full stop has
    no such run and is refused.

    Accepted, as decided on #45 (R2): a card that itself holds six 0s or six 9s
    in a row, written right after "<digit>." ("0.4000000000000002"), passes, and
    so does a personnummer padded with six 0s ("1.191212121212000000"). The digits
    before the point count toward the 16, so a shorter card holding six 0s passes
    behind a long integer part too ("9999999999.<card>").
    """
    if start < 2 or not _DECIMAL_POINT.fullmatch(fraction_view[start - 2 : start]):
        return False
    run = _DIGIT_RUN_AT.match(fraction_view, start)
    if run is None or run.end() < end:
        return False
    significant = (_integer_digits(fraction_view, start - 1) + run.group()).lstrip("0")
    return len(significant) >= FLOAT_DIGITS and _ROUNDING_NOISE.search(run.group()) is not None


def _dash_view(text: str) -> str:
    """``text`` as the deny-list's split-run search reads it (#24, #43).

    Folded as ``normalise`` folds it (NFKC then NFKD, so "²" is "2" and accents
    split off), then every Unicode digit made ASCII, combining marks and format
    characters removed, and any dash or minus sign made "-".
    """
    return unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text)).translate(_DASH)


class _ScanTooSlow(Exception):
    """The request's scan ran past its deadline; it is refused, never passed."""


def _on_time(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _ScanTooSlow


class _Starts(bytes):
    """A run of which only the windows at its start are read: a national number."""


def _national(run: bytes, at: int = 0) -> bytes | None:
    """The national number a country code at ``at`` in ``run`` starts (#52), or None.

    "0" and the digits after the code, as many as the longest window holds: only a
    window that starts at the "0" is a number written with the code; every other
    window is in ``run`` already, or runs across the code.
    """
    for code in _COUNTRY_CODES:
        if run.startswith(code, at):
            after = at + len(code)
            return _Starts(b"0" + run[after : after + max(PERSONNUMMER_DIGITS) - 1])
    return None


def _today() -> date:
    return datetime.now(UTC).date()


def recent_run_together(matched: str, today: date) -> bool:
    """Whether a personnummer match is a run-together timestamp, not a person (#9).

    Presidio reads any 12 digits in a row whose date and Luhn check pass as a
    personnummer, and about one ``YYYYMMDDHHMM`` timestamp in ten passes. Each one
    refuses its session on every later turn, since the whole conversation is resent.
    No adult's number is dated since 1 January of last year (UTC), so a match that
    is exactly 12 ASCII digits with no separator and a date from then up to today is
    dropped. A coordination number's day is read as day − 60. A household child born
    that recently is still caught by their deny-list entry; dashed, spaced and
    10-digit forms are never dropped.

    A future date is never dropped: an adult's short form with two digits glued in
    front ("20" + "8501010006") reads as a 12-digit number dated 2085.
    """
    if not re.fullmatch(r"[0-9]{12}", matched):
        return False
    year, month, day = int(matched[:4]), int(matched[4:6]), int(matched[6:8])
    if day > 60:
        day -= 60
    try:
        born = date(year, month, day)
    except ValueError:
        return False
    return date(today.year - 1, 1, 1) <= born <= today


# What comes right before a GitHub id (#9): a JSON "id" or "<name>_id" key and
# its colon, then only spaces; a comment, run, job, review or review-comment URL;
# or "#<issue>/" as Salpline writes a comment.
_ID_POSITION = re.compile(
    r"""(?:"(?:[A-Za-z0-9_]*_)?id": *"""
    r"|issuecomment-|/runs/|/jobs/|#pullrequestreview-|#discussion_r|#[0-9]+/)\Z"
)
# A GitHub id as written: plain ASCII digits, no separator.
_ID_DIGITS = re.compile(r"[0-9]{10,12}")
# How far back a key is read: a longer one is never dropped.
_ID_LOOKBACK = 64


def known_id_position(text: str, start: int, end: int) -> bool:
    """Whether a personnummer match at ``start`` sits where GitHub puts an id (#9).

    GitHub's numeric ids now read as personnummer: about 5-6% of ids between
    7.000 and 7.013 billion pass the date and Luhn check, as does about 1% of
    11-digit Actions run ids, since only the last ten digits are checked. They
    reach sessions in API output, URLs, CI logs and files, and each one refuses
    its session on every later turn. Salpline's design (ShoVaz/salpline
    ``arc/docs/design/github-id-refusals.md``, "The gateway carve-out") drops a
    match in a position only an id takes: after a JSON ``"id":`` or
    ``"<name>_id":`` with only spaces between, or right after ``issuecomment-``,
    ``/runs/``, ``/jobs/``, ``#pullrequestreview-``, ``#discussion_r`` or
    ``#<digits>/``, and only when the match is 10 to 12 ASCII digits with no
    separator, as a GitHub id is: a dashed, plus-separated or non-ASCII-digit form
    is refused wherever it stands. ``text`` is ``_presidio_view``'s, so a tab or
    no-break space reads as a space.

    Accepted: a real personnummer stored as a number under an ``"id"`` or
    ``"<name>_id"`` key, or written after one of those URL pieces, passes. One in
    a string value (``"id": "..."``), in prose or under any other key is refused.
    """
    if not _ID_DIGITS.fullmatch(text, start, end):
        return False
    return _ID_POSITION.search(text, max(0, start - _ID_LOOKBACK), start) is not None


# Four groups of four ASCII digits, one space between them.
_FOUR_GROUPS = re.compile(r"[0-9]{4}(?: [0-9]{4}){3}")
# The number right beside a match, across one separator a card may be written with.
# Any Unicode digit, as Presidio reads them.
_NUMBER_BEFORE = re.compile(r"(\d+)[ .-]\Z")
_NUMBER_AFTER = re.compile(r"[ .-](\d+)")
# How many numbers are read on each side of a match before the list is too long to
# let through: the time a match takes stays bounded (#54).
_LIST_NEIGHBOURS = 100
# How far one is read: a longer one is never the next in a list.
_NUMBER_LOOK = 16


def consecutive_numbers(text: str, start: int, end: int) -> bool:
    """Whether a card match is part of a list of consecutive numbers (#12).

    Four issue numbers in a row ("4003 4004 4005 4006") are 16 digits in four
    groups, and about one such list in ten passes the Luhn check. All of these hold,
    or the match is still refused: it is four groups of four ASCII digits with one
    space between them; each group is the one before plus one; and every
    number beside it, across one space, "." or "-", carries the same list on to both
    its ends, at most ``_LIST_NEIGHBOURS`` each way. Any other number there could be
    part of a card: Presidio's next match starts inside the list and can straddle
    the list's end, which hides a card right after it. ``text`` is
    ``_fraction_view``'s: a tab or no-break space reads as a space, and a "." not.

    Accepted, as decided on #12 (1B): a card whose four spaced groups ascend by one
    passes. 903 such values are Luhn-valid and start as a card does.
    """
    if not _FOUR_GROUPS.fullmatch(text, start, end):
        return False
    first, *rest = (int(group) for group in text[start:end].split(" "))
    if rest != [first + 1, first + 2, first + 3]:
        return False
    at = start
    for step in range(1, _LIST_NEIGHBOURS + 1):
        before = _NUMBER_BEFORE.search(text[max(0, at - _NUMBER_LOOK) : at])
        if before is None:
            break
        if before[1] != str(first - step):
            return False
        at -= len(before[0])
    else:
        return False
    at = end
    for step in range(1, _LIST_NEIGHBOURS + 1):
        after = _NUMBER_AFTER.match(text, at, at + _NUMBER_LOOK)
        if after is None:
            break
        if after[1] != str(rest[-1] + step):
            return False
        at = after.end()
    else:
        return False
    return True


@dataclass(frozen=True)
class _Found:
    """One Presidio or phone match on ``_presidio_view``'s text."""

    entity_type: str
    start: int
    end: int
    # The number in E.164 for a phone, so "+46 70 ..." and "070-..." hash alike.
    value: str | None = None


def phones(
    view: str, regions: tuple[str, ...], match: str, deadline: float = math.inf
) -> Iterator[_Found]:
    """Every phone number in ``view`` (#64), each span once.

    Read once with no region, which finds only numbers written with a "+", and once
    per listed region, which adds that country's national format. With ``grouped``
    a match must hold something besides digits (a "+", a space, a dash, brackets):
    a bare run of digits is an id, a timestamp or a count far more often than a
    phone. The deadline is read between windows (#54).
    """
    # Any Unicode digit: the matcher reads fullwidth and Arabic-Indic digits too.
    if _ANY_DIGIT.search(view) is None:
        return
    leniency = _LENIENCY[match]
    seen: set[tuple[int, int]] = set()
    for region in (None, *regions):
        for own in range(0, len(view), PHONE_WINDOW):
            _on_time(deadline)
            begin = max(0, own - PHONE_OVERLAP)
            window = view[begin : own + PHONE_WINDOW + PHONE_OVERLAP]
            # No cap on tries: one inner group can cost a try, so any cap could be
            # reached and later phones go unread. The window bounds the work.
            matcher = phonenumbers.PhoneNumberMatcher(window, region, leniency, sys.maxsize)
            for found in matcher:
                start, end = begin + found.start, begin + found.end
                if not own <= start < own + PHONE_WINDOW:
                    continue
                if match == GROUPED and found.raw_string.isdigit():
                    continue
                if (start, end) in seen:
                    continue
                seen.add((start, end))
                e164 = phonenumbers.format_number(found.number, phonenumbers.PhoneNumberFormat.E164)
                yield _Found(PHONE, start, end, e164)


# Where a Detection sits: the keys and indexes down to its string in the parsed body,
# then the start and end of the match in that string.
Span = tuple[tuple[str | int, ...], int, int]


@dataclass(frozen=True)
class Detection:
    type: str
    # The salted hash of the matched words: enough to tell two refusals apart or
    # find the entry that fired, never the text. None when nothing could be read.
    hash: str | None
    # Set only by ``Scanner.mask``, for the hits it replaces (#66). Never logged or
    # printed, and no part of what makes two Detections equal.
    span: Span | None = dataclass_field(default=None, compare=False, repr=False)


class Denylist:
    """The Operator's entries as salted SHA-256 hashes of their normalised words."""

    def __init__(self, salt: str, hashes: set[str], firsts: set[str]) -> None:
        self.salt = salt
        self._salted = hashlib.sha256(salt.encode())
        self._hashes = {bytes.fromhex(h) for h in hashes}
        # The hash of each entry's first word, so a window that can't start an
        # entry costs one hash rather than six.
        self._firsts = {bytes.fromhex(h) for h in firsts}

    def hash(self, words: list[str]) -> bytes:
        h = self._salted.copy()
        h.update(" ".join(words).encode())
        return h.digest()

    def matches(self, words: list[str], deadline: float = math.inf) -> Iterator[str]:
        """The hex hash of every 1-to-``MAX_WORDS`` window of ``words`` on the list."""
        if not self._hashes:
            return
        encoded = [w.encode() for w in words]
        for start in range(len(encoded)):
            if not start % SCAN_TICK:
                _on_time(deadline)
            h = self._salted.copy()
            h.update(encoded[start])
            if h.copy().digest() not in self._firsts:
                continue
            # Each window extends the one before it by a word, so the hash state
            # is carried forward rather than rebuilt.
            for end in range(start + 1, min(start + MAX_WORDS, len(encoded)) + 1):
                if end > start + 1:
                    h.update(b" " + encoded[end - 1])
                digest = h.copy().digest()
                if digest in self._hashes:
                    yield digest.hex()

    def digit_run_matches(self, words: list[str], deadline: float = math.inf) -> Iterator[str]:
        """The hex hash of every listed number inside a long run of digits (#20).

        Each run of ``MIN_DIGIT_RUN`` or more ASCII digits in ``words`` has every
        10- and 12-digit window looked up as an entry, in two spellings: run
        together ("1212121212") and with a gap before the last four digits
        ("121212 1212"), the way the README has the Operator list the numbers. Exact
        lookups only: no general check runs on a window, so an id or timestamp
        that merely looks like a personnummer passes. A run that starts with the
        country code ("46701234567", "0046701234567") is read in its "0" form too
        (#52).
        """
        if not self._hashes:
            return

        def runs() -> Iterator[bytes]:
            for n, word in enumerate(words):
                if not n % SCAN_TICK:
                    _on_time(deadline)
                for found in _DIGIT_RUN.findall(word):
                    run = found.encode()
                    yield run
                    national = _national(run)
                    if national is not None:
                        yield national

        yield from self._window_matches(runs(), deadline)

    def split_run_matches(self, text: str, deadline: float = math.inf) -> Iterator[str]:
        """The hex hash of every listed number split across gaps (#24, #43, #50).

        ``text`` is ``_dash_view``'s. Each chain of two or more digit groups whose
        gaps hold no letters ("999191212 12121299", "070-123 45 67") has its digits
        joined, and every 10- and 12-digit window of the joined run looked up as
        ``digit_run_matches`` does, so a listed number split anywhere, with digits
        glued on either side, is found. Exact lookups only, as there.

        A country code where the chain starts, right after a "+" in a gap
        ("+46 70 123 45 67", "08-123 45 67, +46 70 123 45 67"), or written "0046"
        at the start of any group ("14:32 0046 70 123 45 67"), is read as "0" too
        (#52), as ``_national`` reads it.
        """
        if not self._hashes:
            return

        def runs() -> Iterator[bytes]:
            for n, chain in enumerate(_DIGIT_CHAIN.finditer(text)):
                if not n % SCAN_TICK:
                    _on_time(deadline)
                written = chain.group()
                joined = _NOT_DIGIT.sub("", written)
                # One group alone is a word, which ``digit_run_matches`` reads.
                if len(joined) == len(written) or len(joined) < min(PERSONNUMMER_DIGITS):
                    continue
                run = joined.encode()
                yield run
                national = _national(run)
                if national is not None:
                    yield national
                # "0046" in the digits, however it is split ("00 46").
                if "+" in written or b"0046" in run:
                    yield from _inside_chain(written, run, deadline)

        yield from self._window_matches(runs(), deadline)

    def _window_matches(self, runs: Iterable[bytes], deadline: float = math.inf) -> Iterator[str]:
        """The hex hash of each 10- and 12-digit window of ``runs`` on the list.

        In two spellings: run together ("1212121212") and with a gap before the last
        four digits ("121212 1212"). Windows are read lazily, and up to
        ``SEEN_WINDOWS`` distinct ones are remembered and hashed once, so a run that
        repeats itself ("1234567" * 200_000) costs a few hashes. Past that cap each
        window is hashed as it comes: memory stays bounded on a body of random
        digits, and the work stays linear in the runs' length. Of a ``_Starts`` run
        only the windows at its start are read. The deadline is read once every
        ``SCAN_TICK`` windows or so, however short the runs (#54).
        """
        seen: set[bytes] = set()
        read = 0
        for run in runs:
            read += len(run)
            if read >= SCAN_TICK:
                read = 0
                _on_time(deadline)
            for size in PERSONNUMMER_DIGITS:
                stop = len(run) - size + 1
                if isinstance(run, _Starts):
                    stop = min(stop, 1)
                for start in range(stop):
                    if start and not start % SCAN_TICK:
                        _on_time(deadline)
                    window = run[start : start + size]
                    if window in seen:
                        continue
                    if len(seen) < SEEN_WINDOWS:
                        seen.add(window)
                    for spelling in (window, window[:-4] + b" " + window[-4:]):
                        h = self._salted.copy()
                        h.update(spelling)
                        digest = h.digest()
                        if digest in self._hashes:
                            yield digest.hex()

    @classmethod
    def load(cls, path: Path) -> "Denylist":
        """Read the file ``hash-denylist`` writes; anything else raises."""
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, data: dict) -> "Denylist":
        """``{salt, hashes, firsts}``, as ``build`` returns it; anything else raises."""
        salt = data["salt"]
        if not isinstance(salt, str) or not salt:
            raise ValueError("salt must be a non-empty string")
        for field in ("hashes", "firsts"):
            if not isinstance(data[field], list) or not all(
                isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h) for h in data[field]
            ):
                raise ValueError(f"{field} must be a list of SHA-256 hex digests")
        return cls(salt, set(data["hashes"]), set(data["firsts"]))

    @staticmethod
    def build(entries: list[str]) -> dict:
        """Hash plain entries under a fresh salt, in the form ``from_dict`` reads."""
        salt = secrets.token_hex(16)
        hashed = Denylist(salt, set(), set())
        hashes, firsts = set(), set()
        for entry in entries:
            words = normalise(entry)
            if not words:
                continue
            if len(words) > MAX_WORDS:
                # Never echo the entry: this runs in the Operator's shell, but its
                # output may end up in a transcript.
                raise ValueError(f"an entry has {len(words)} words; at most {MAX_WORDS} match")
            hashes.add(hashed.hash(words).hex())
            firsts.add(hashed.hash(words[:1]).hex())
        return {"salt": salt, "hashes": sorted(hashes), "firsts": sorted(firsts)}


def _inside_chain(written: str, run: bytes, deadline: float) -> Iterator[bytes]:
    """The national number each country code starting a later group of a chain starts (#52).

    ``written`` is the chain as matched and ``run`` its digits. After a gap with a
    "+" in it, "46" or "0046"; after any other gap only "0046": a bare "46" there is
    as likely any other digits. One pass, each group read once.
    """
    offset = 0
    end = None
    for n, group in enumerate(_DIGIT_GROUP.finditer(written)):
        if not n % SCAN_TICK:
            _on_time(deadline)
        if end is not None and (
            "+" in written[end : group.start()] or run.startswith(b"0046", offset)
        ):
            national = _national(run, offset)
            if national is not None:
                yield national
        offset += group.end() - group.start()
        end = group.end()


def read_entries(text: str) -> list[str]:
    """One entry per line; blank lines and lines starting with ``#`` are skipped."""
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@dataclass
class Media:
    """The images and PDFs a body carries, as the walk finds them."""

    # The base64 data of each PDF, in the order found.
    pdfs: list[str] = dataclass_field(default_factory=list)
    # Any image or PDF at all, whatever its source: base64, a URL or a file id.
    attached: bool = False


class _PdfRefused(Exception):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


# What a plain link may hold: where it sits, how it looks as a box, and where it goes.
# Anything else, an appearance of its own above all, could draw text on the page.
_LINK_KEYS = frozenset(
    {"/Type", "/Subtype", "/Rect", "/Border", "/BS", "/C", "/H", "/F", "/P", "/NM", "/M"}
    | {"/StructParent", "/QuadPoints", "/Dest", "/A", "/Contents"}
)
# /SD: the structure element a GoTo jumps to (PDF 2.0; InDesign writes it), no text.
_ACTION_KEYS = frozenset({"/Type", "/S", "/URI", "/D", "/SD", "/IsMap"})


def _flat_texts(reader: pypdf.PdfReader) -> list[str] | None:
    """The text a flat PDF's links carry, or None if the PDF has a form or notes.

    A form's values and a note's text can be stored, encoded and drawn in more ways
    than a check can follow (#10's reviews found gap after gap), so a PDF holding
    either is refused whole; flattened (printed to PDF), it passes. A plain link is
    allowed, and its description (which accessible exports add) and web address are
    checked as text; a link holding anything more counts as a note.
    """
    form = reader.trailer["/Root"].get("/AcroForm")
    if form is not None:
        form = form.get_object()
        if form.get("/Fields") or form.get("/XFA") is not None:
            return None
    texts = []
    for page in reader.pages:
        for annotation in page.get("/Annots") or []:
            annotation = annotation.get_object()
            if (
                not isinstance(annotation, pypdf.generic.DictionaryObject)
                or isinstance(annotation, pypdf.generic.StreamObject)
                or annotation.get("/Subtype") != "/Link"
                or not set(annotation) <= _LINK_KEYS
            ):
                return None
            action = annotation.get("/A")
            if action is not None:
                action = action.get_object()
                if action.get("/S") not in ("/URI", "/GoTo") or not set(action) <= _ACTION_KEYS:
                    return None
            for value in (annotation.get("/Contents"), action and action.get("/URI")):
                if value is None:
                    continue
                if isinstance(value, bytes):
                    value = value.decode("latin-1")
                if not isinstance(value, str):
                    return None
                texts.append(value)
    return texts


def _pdf_text(data: str, seconds: float) -> str | Detection:
    """What a PDF shows as text, or the refusal it earns.

    Each page's text layer and its links' text; a PDF with a form or notes is refused
    (``_flat_texts``).
    Encrypted is refused, even with an
    empty password (#10's decision).
    """
    # The time starts when a worker picks the PDF up, not while it waits for one.
    deadline = time.monotonic() + seconds
    try:
        raw = base64.b64decode("".join(data.split()), validate=True)
        reader = pypdf.PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            raise _PdfRefused("PDF_UNREADABLE")
        if len(reader.pages) > PDF_MAX_PAGES:
            raise _PdfRefused("PDF_TOO_LONG")
        links = _flat_texts(reader)
        if links is None:
            raise _PdfRefused("PDF_NOT_FLAT")
        texts = list(links)
        for page in reader.pages:
            # Checked between pages, so an abandoned extraction ends soon after.
            if time.monotonic() > deadline:
                raise _PdfRefused("PDF_TOO_SLOW")
            texts.append(page.extract_text() or "")
        if time.monotonic() > deadline:
            raise _PdfRefused("PDF_TOO_SLOW")
    except _PdfRefused as refused:
        return Detection(refused.kind, None)
    except Exception:  # noqa: BLE001 -- whatever pypdf can't parse is refused
        return Detection("PDF_UNREADABLE", None)
    return "\n".join(texts)


class _Workers:
    """A few daemon threads for PDF extraction.

    Not a ThreadPoolExecutor: its threads are joined at exit, so one stuck inside a
    single pypdf call would keep the proxy from stopping.
    """

    def __init__(self, count: int) -> None:
        self._count = count
        self._jobs: queue.SimpleQueue = queue.SimpleQueue()
        self._started = False
        self._lock = threading.Lock()

    def submit(self, fn, *args) -> Future:
        with self._lock:
            if not self._started:
                for n in range(self._count):
                    threading.Thread(target=self._run, name=f"pdf-{n}", daemon=True).start()
                self._started = True
        future: Future = Future()
        self._jobs.put((future, fn, args))
        return future

    def _run(self) -> None:
        while True:
            future, fn, args = self._jobs.get()
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(fn(*args))
            except BaseException as error:  # noqa: BLE001 -- handed to whoever waits
                future.set_exception(error)


_WORKERS = _Workers(PDF_WORKERS)


class PdfTexts:
    """Each PDF's extracted text, or its refusal, by the SHA-256 of its base64 data.

    In memory only, ``PDF_CACHE_SIZE`` entries, least recently used out; nothing is
    written to disk, and it is gone at restart. Only an extraction's own verdict is
    kept: a caller that gave up waiting is told ``PDF_TOO_SLOW``, but the PDF is not
    marked so for later turns unless its own extraction overran too. One PDF in
    several requests at once is extracted once.
    """

    def __init__(self) -> None:
        self._cache: OrderedDict[bytes, str | Detection] = OrderedDict()
        self._running: dict[bytes, Future] = {}
        self._lock = threading.Lock()

    def text(self, data: str) -> str | Detection:
        key = hashlib.sha256(data.encode("utf-8", "surrogatepass")).digest()
        with self._lock:
            found = self._cache.get(key)
            if found is not None:
                self._cache.move_to_end(key)
                return found
            future = self._running.get(key)
            started = future is None
            if started:
                future = _WORKERS.submit(_pdf_text, data, PDF_MAX_SECONDS)
                self._running[key] = future
        if started:
            # Outside the lock: a future already done runs the callback right here.
            future.add_done_callback(lambda done: self._keep(key, done))
        try:
            return future.result(timeout=PDF_MAX_SECONDS)
        except FutureTimeout:
            return Detection("PDF_TOO_SLOW", None)
        except Exception:  # noqa: BLE001 -- never let a failure pass a PDF unread
            return Detection("PDF_UNREADABLE", None)

    def _keep(self, key: bytes, done: Future) -> None:
        error = done.exception()
        found = Detection("PDF_UNREADABLE", None) if error is not None else done.result()
        with self._lock:
            self._running.pop(key, None)
            self._cache[key] = found
            if len(self._cache) > PDF_CACHE_SIZE:
                self._cache.popitem(last=False)


class Scanner:
    """Presidio and the deny-list, loaded once at start-up and shared by every request.

    Only the Detectors the ``policy`` has on run. Without a ``denylist`` there is
    nothing to match, and a Presidio hit's logged hash uses a salt made for this
    process: hits tell apart within a run, not across restarts (R3).
    """

    def __init__(self, denylist: Denylist | None = None, policy: Policy | None = None) -> None:
        self.policy = policy or Policy.default()
        self.has_denylist = denylist is not None
        self.denylist = denylist or Denylist(secrets.token_hex(16), set(), set())
        entities = self.policy.entities()
        self._phone_on = PHONE in entities
        self._entities = [e for e in entities if e != PHONE]
        self._numbers = tuple(e for e in _NUMBERS if e in entities)
        self._deny_on = self.policy.on("deny_list") and self.has_denylist
        registry = RecognizerRegistry(supported_languages=[LANGUAGE])
        for entity in self._entities:
            registry.add_recognizer(_RECOGNISERS[entity](supported_language=LANGUAGE))
        # No spaCy model: every recogniser here is a validated pattern, and a model
        # would add a gigabyte and seconds per request for nothing.
        self.analyzer = AnalyzerEngine(
            registry=registry,
            nlp_engine=NoOpNlpEngine(models=[{"lang_code": LANGUAGE, "model_name": "none"}]),
            supported_languages=[LANGUAGE],
        )
        # Verdicts by a hash of the text, never the text itself.
        self._cache: OrderedDict[bytes, tuple[Detection, ...]] = OrderedDict()
        self._lock = threading.Lock()
        self.pdfs = PdfTexts()

    def check(
        self,
        body: dict,
        skip: frozenset[str] | None = None,
        strict: bool = False,
        *,
        trusted: bool,
    ) -> list[Detection]:
        """Every Detection in a request body, each PDF's text included.

        Bound for a provider that is not Trusted, a body carrying any image or PDF
        is refused before anything else is read (D25): what it holds can't all be
        checked. A PDF that can't be read, or is over a limit, refuses too. The
        whole request, PDFs included, has ``SCAN_MAX_SECONDS`` (#54).
        """
        deadline = time.monotonic() + SCAN_MAX_SECONDS
        media = Media()
        texts = message_texts(body, _NOT_READ if skip is None else skip, strict, media)
        if media.attached and not trusted:
            return [Detection("MEDIA_TO_UNTRUSTED", None)]
        refused: dict[Detection, None] = {}
        for data in dict.fromkeys(media.pdfs):
            # Each PDF may take its own 2 s; many of them share the request's limit.
            if time.monotonic() > deadline:
                return [*refused, Detection("SCAN_TOO_SLOW", None)]
            text = self.pdfs.text(data)
            if isinstance(text, Detection):
                refused[text] = None
            else:
                texts.append(text)
        if refused:
            return list(refused)
        # A PDF keeps its own limit; the request's is read again once they're done.
        if time.monotonic() > deadline:
            return [Detection("SCAN_TOO_SLOW", None)]
        return self.inspect(texts, deadline)

    def inspect(self, texts: list[str], deadline: float | None = None) -> list[Detection]:
        """Every Detection in ``texts``, each type and hash once.

        All of ``texts`` share one deadline, ``SCAN_MAX_SECONDS`` from now unless
        given. Past it the scan stops and ``SCAN_TOO_SLOW`` refuses the request
        (#54); the part cut short is not cached, so it gets its real verdict later.
        """
        if deadline is None:
            deadline = time.monotonic() + SCAN_MAX_SECONDS
        found: dict[Detection, None] = {}
        today = _today()
        for text in dict.fromkeys(texts):
            try:
                _on_time(deadline)
                verdict = self._verdict(text, today, deadline)
            except _ScanTooSlow:
                return [*found, Detection("SCAN_TOO_SLOW", None)]
            found.update(dict.fromkeys(verdict))
        return list(found)

    def _verdict(self, text: str, today: date, deadline: float) -> tuple[Detection, ...]:
        """One text's verdict, from the cache if it was read before."""
        # The year is in the key: a run-together number let through as recent this
        # year may be old enough to refuse after New Year.
        year = str(today.year).encode()
        key = hashlib.blake2b(text.encode(), digest_size=16, person=year).digest()
        with self._lock:
            verdict = self._cache.get(key)
            if verdict is not None:
                self._cache.move_to_end(key)
        if verdict is None:
            verdict = self._inspect(text, today, deadline)
            with self._lock:
                self._cache[key] = verdict
                if len(self._cache) > CACHE_SIZE:
                    self._cache.popitem(last=False)
        return verdict

    def mask(self, body: dict) -> tuple[dict, list[Detection]]:
        """``body`` with each hit of a ``mask`` Detector replaced by a Placeholder (#66).

        Returns the new body and the Detections that still refuse; ``body`` itself is
        not changed. A Placeholder is ``<KIND_N>`` (``<PHONE_NUMBER_1>``): N counts
        the distinct values of that kind by first appearance in the body, so one
        value has one Placeholder wherever it is written ("+46 70 123 45 67" and
        "070-123 45 67" are one phone).

        Only a string the model reads as text is rewritten: message text, a system
        prompt, a tool's description, a tool call's input, a tool result. Never a
        key, a number, an id, a ``type``, the ``model``, ``metadata``, an image or
        PDF, or a block the provider signed (thinking). A hit in any of those is left
        where it is, so the caller's check of the masked body still finds it and
        refuses: this never decides alone that a body may go on.
        """
        deadline = time.monotonic() + SCAN_MAX_SECONDS
        today = _today()
        kinds = self.policy.masked_entities()
        left: dict[Detection, None] = {}
        # Per kind, each value's N by its hash.
        numbers: dict[str, dict[str | None, int]] = {}

        def write(text: str, path: tuple[str | int, ...]) -> str:
            _on_time(deadline)
            verdict = self._verdict(text, today, deadline)
            left.update(dict.fromkeys(d for d in verdict if d.type not in kinds))
            if all(d.type not in kinds for d in verdict):
                return text
            # Right to left, so the offsets still to come hold.
            for hit in reversed(self._spans(text, path, kinds, numbers, today, deadline)):
                _, start, end = hit.span
                n = numbers[hit.type][hit.hash]
                text = f"{text[:start]}<{hit.type}_{n}>{text[end:]}"
            return text

        try:
            return _rewritten(body, write), list(left)
        except _ScanTooSlow:
            return body, [Detection("SCAN_TOO_SLOW", None)]

    def _spans(
        self,
        text: str,
        path: tuple[str | int, ...],
        kinds: frozenset[str],
        numbers: dict[str, dict[str | None, int]],
        today: date,
        deadline: float,
    ) -> list[Detection]:
        """The hits in ``text`` to mask, left to right, none overlapping, each numbered.

        The same hits ``_inspect`` refuses on, read once more for where they are.
        Their offsets are the view's, which has the invisible format characters
        removed, so each is mapped back to ``text``: a hit covers the invisible
        characters inside it and none beside it. Hits that overlap (a phone read in
        two regions, a number two Detectors claim) become one, from the first one's
        start to the furthest end, under the first one's kind.
        """
        view = _presidio_view(text)
        at = None
        if len(view) != len(text):
            # The place in ``text`` of each character the view kept.
            at = [i for i, c in enumerate(text) if _PRESIDIO.get(ord(c), c) is not None]
        merged: list[list] = []
        found = [(f, d) for f, d in self._matches(text, view, today, deadline) if d.type in kinds]
        for result, hit in sorted(found, key=lambda m: (m[0].start, -m[0].end)):
            start, end = result.start, result.end
            if at is not None:
                start, end = at[start], at[end - 1] + 1
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end, hit])
        spans = []
        for start, end, hit in merged:
            seen = numbers.setdefault(hit.type, {})
            seen.setdefault(hit.hash, len(seen) + 1)
            spans.append(Detection(hit.type, hit.hash, (path, start, end)))
        return spans

    def _inspect(self, text: str, today: date, deadline: float = math.inf) -> tuple[Detection, ...]:
        """One text's verdict; raises ``_ScanTooSlow`` past ``deadline``."""
        view = _presidio_view(text)
        found: dict[Detection, None] = dict.fromkeys(
            hit for _, hit in self._matches(text, view, today, deadline)
        )
        _on_time(deadline)
        if not self._deny_on:
            return tuple(found)
        spellings = [normalise(text)]
        if not _FORMAT.isdisjoint(text):
            # "anna\u200btestsson" (or a Hangul filler) reads as one word or two;
            # check both.
            spellings.append(normalise(text, split_format=True))
        for words in spellings:
            for digest in self.denylist.matches(words, deadline):
                found[Detection("DENYLIST", digest)] = None
        _on_time(deadline)
        # Both spellings at once: their runs of digits are usually the same.
        words = [w for ws in spellings for w in ws]
        for digest in self.denylist.digit_run_matches(words, deadline):
            found[Detection("DENYLIST", digest)] = None
        _on_time(deadline)
        # Any chain of digit groups, split anywhere (#43, #50).
        for digest in self.denylist.split_run_matches(_dash_view(text), deadline):
            found[Detection("DENYLIST", digest)] = None
        return tuple(found)

    def _matches(
        self, text: str, view: str, today: date, deadline: float
    ) -> Iterator[tuple[_Found, Detection]]:
        """Each Presidio and phone match in ``text`` that counts, with its Detection.

        ``view`` is ``_presidio_view``'s, and the matches' offsets are its own. What
        ``float_noise``, ``consecutive_numbers``, ``recent_run_together`` and
        ``known_id_position`` let pass is not among them, so what is masked is
        exactly what would refuse.
        """
        fraction = _fraction_view(text)
        # One recogniser per call, so the deadline is read between them (#54): a
        # call can't be stopped, and each takes up to ~0.3 s per MB of digits.
        # (Presidio with no entity asked for would run every recogniser it has.)
        results: list[_Found] = []
        for entity in self._entities:
            _on_time(deadline)
            results.extend(
                _Found(r.entity_type, r.start, r.end)
                for r in self.analyzer.analyze(view, language=LANGUAGE, entities=[entity])
            )
        _on_time(deadline)
        if self._phone_on:
            phone = self.policy.phone
            results.extend(phones(view, phone.regions, phone.match, deadline))
        for result in results:
            _on_time(deadline)
            if result.entity_type in self._numbers and float_noise(
                fraction, result.start, result.end
            ):
                continue
            if result.entity_type == "CREDIT_CARD" and consecutive_numbers(
                fraction, result.start, result.end
            ):
                continue
            matched = view[result.start : result.end]
            # Letters and digits only, so "121212-1212" and "191212121212" log
            # the same hash: a personnummer is its last ten digits.
            value = result.value or "".join(c for c in matched if c.isalnum())
            if result.entity_type in ("SE_PERSONNUMMER", PHONE) and recent_run_together(
                matched, today
            ):
                continue
            if result.entity_type == "SE_PERSONNUMMER" and known_id_position(
                view, result.start, result.end
            ):
                continue
            if result.entity_type == "SE_PERSONNUMMER":
                value = value[-10:]
            digest = self.denylist.hash([value.casefold()]).hex()
            yield result, Detection(result.entity_type, digest)


# Fields whose string value is never text the model reads as text: ids,
# signatures, block types. Only a string value is dropped, so a schema property
# named "id" is still read; a tool's input is read whole, whatever its keys.
_NOT_TEXT = frozenset({"type", "id", "tool_use_id", "signature", "media_type"})

# Top-level fields the model never reads: the account's device and session ids,
# long hex strings a digit pattern could trip on.
_NOT_READ = frozenset({"metadata"})

# Blocks and parts that put an image, a file or a recording in front of the model,
# whatever their source: Anthropic's image, document and container_upload blocks,
# OpenAI's image_url, file, video_url and input_audio parts, and the Responses API's
# input_image and input_file. A document whose source is text is read as text.
_MEDIA_BLOCKS = frozenset(
    {
        "image",
        "document",
        "container_upload",
        "image_url",
        "file",
        "video_url",
        "input_audio",
        "input_image",
        "input_file",
    }
)


# Where the OpenAI format carries a base64 payload as a data URL, inside a media part
# only: an image_url's url (or a bare image_url string) and a file's file_data.
_DATA_URL_KEYS = frozenset({"url", "image_url", "file_data"})
_DATA_URL = re.compile(r"data:([^,;]*)((?:;[^,;]*)*);base64,", re.IGNORECASE)
# How a PDF's base64 starts ("%PDF-"), whatever type it is labelled with.
_PDF_BASE64 = "JVBERi"


def _is_pdf(media_type: object, data: str) -> bool:
    """Anything not labelled an image, and anything that starts like a PDF, is a PDF.

    So a file pypdf can't open is refused rather than passed unread, and a PDF
    labelled an image is still read.
    """
    is_image = isinstance(media_type, str) and media_type.strip().lower().startswith("image/")
    return not is_image or data.lstrip()[: len(_PDF_BASE64)] == _PDF_BASE64


def _data_url(key: str, value: str, media: "Media") -> bool:
    """Whether ``value`` is a base64 payload; if so it is media, and not read as text.

    A file part's ``file_data`` is a file whatever its label, and is read as a PDF.
    """
    match = _DATA_URL.match(value)
    if match is None and key != "file_data":
        return False
    media.attached = True
    data = value[match.end() :] if match else value
    if key == "file_data" or _is_pdf(match.group(1), data):
        media.pdfs.append(data)
    return True


def message_texts(
    body: dict,
    skip: frozenset[str] = _NOT_READ,
    strict: bool = False,
    media: Media | None = None,
) -> list[str]:
    """Every string in a Messages request the model may see.

    The whole body but ``metadata``, walked recursively: ``system``, ``tools``,
    ``output_format``, every message's content (text, thinking, ``tool_result``
    content), every key, and every value in ``tool_use.input``, numbers included.
    A field or block type this doesn't know is walked the same way, so a new one is
    scanned, not skipped. Base64 sources (images, PDFs) and redacted thinking are
    opaque and their ``data`` is skipped. A batch's requests and a legacy ``prompt`` are read too.

    Given ``media``, each image and PDF is noted there, and an OpenAI-format data URL
    is skipped like a base64 source; each PDF's data is kept for ``Scanner.check``
    to extract and read.

    ``strict`` is for a body that may go to a provider that is not Trusted, where
    every byte that goes on matters, not only what the model reads: ids and types
    are read as text and numbers anywhere as digits.
    """
    texts: list[str] = []
    _walk({k: v for k, v in body.items() if k not in skip}, texts, skip, strict, media)
    return texts


def _walk(
    node,
    texts: list[str],
    skip: frozenset[str] = _NOT_READ,
    strict: bool = False,
    media: Media | None = None,
    in_media: bool = False,
) -> None:
    if isinstance(node, str):
        texts.append(node)
    elif strict and isinstance(node, (int, float)) and not isinstance(node, bool):
        texts.append(str(node))
    elif isinstance(node, list):
        for item in node:
            _walk(item, texts, skip, strict, media, in_media)
    elif isinstance(node, dict):
        # A type that isn't a string (a list, an object) is no block type, and no key.
        kind = node.get("type") if isinstance(node.get("type"), str) else None
        if media is not None and kind in _MEDIA_BLOCKS:
            source = node.get("source")
            text_source = isinstance(source, dict) and source.get("type") in ("text", "content")
            if not (kind == "document" and text_source):
                media.attached = True
                in_media = True
        # Only the opaque payload itself is skipped: a "type" alone must not hide the
        # rest of the object, a whole message or the whole body.
        opaque = kind in ("base64", "redacted_thinking")
        for key, value in node.items():
            texts.append(key)
            if opaque and key == "data" and isinstance(value, str):
                if kind == "base64" and media is not None:
                    media.attached = True
                    if _is_pdf(node.get("media_type"), value):
                        media.pdfs.append(value)
                continue
            if (
                in_media
                and key in _DATA_URL_KEYS
                and isinstance(value, str)
                and _data_url(key, value, media)
            ):
                continue
            if key == "input":
                _values(value, texts)
            elif key == "params" and isinstance(value, dict):
                # A batch request's params is a Messages body of its own.
                texts.extend(message_texts(value, skip, strict, media))
            elif strict or not (key in _NOT_TEXT and isinstance(value, str)):
                _walk(value, texts, skip, strict, media, in_media)


# Top-level fields ``Scanner.mask`` leaves as they came: the model was checked against
# the key's list as written, and metadata is ids.
_NOT_MASKED = _NOT_READ | {"model"}


def _rewritten(node, write, path: tuple[str | int, ...] = (), in_media=False, in_input=False):
    """A copy of ``node`` with ``write(text, path)`` in place of each free-text string.

    Walks as ``_walk`` does, and rewrites less than it reads: a key, a number, a
    ``_NOT_TEXT`` field, an image's or PDF's payload and any string beside a
    ``signature`` (signed thinking must go back as it came) stay as they are. A tool
    call's ``input`` is the caller's own data, so every string value in it is text.
    """
    if isinstance(node, str):
        return write(node, path)
    if isinstance(node, list):
        return [
            _rewritten(item, write, (*path, n), in_media, in_input) for n, item in enumerate(node)
        ]
    if not isinstance(node, dict):
        return node
    kind = node.get("type") if isinstance(node.get("type"), str) else None
    signed = False
    if not in_input:
        if kind in _MEDIA_BLOCKS:
            in_media = True
        signed = isinstance(node.get("signature"), str)
    opaque = kind in ("base64", "redacted_thinking")
    out = {}
    for key, value in node.items():
        text = isinstance(value, str)
        kept = not in_input and (
            (not path and key in _NOT_MASKED)
            or (opaque and key == "data" and text)
            or (in_media and key in _DATA_URL_KEYS and text and _data_url(key, value, Media()))
            or (text and (signed or key in _NOT_TEXT))
        )
        out[key] = (
            value
            if kept
            else _rewritten(value, write, (*path, key), in_media, in_input or key == "input")
        )
    return out


def _values(node, texts: list[str]) -> None:
    # The model reads a tool call's input as JSON: keys and numbers included.
    if isinstance(node, str):
        texts.append(node)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        texts.append(str(node))
    elif isinstance(node, list):
        for item in node:
            _values(item, texts)
    elif isinstance(node, dict):
        for key, value in node.items():
            texts.append(key)
            _values(value, texts)
