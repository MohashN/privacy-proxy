"""The Policy file: which Detectors run and what each does on a hit.

One YAML file the Operator writes, read once at start-up (``POLICY_PATH``)::

    detectors:
      national_id: {action: refuse, countries: [SE, FI, ES, IT, ZA, DE]}
      phone: {action: refuse, regions: [SE], match: grouped}
      card: {action: refuse}
      iban: {action: refuse}
      deny_list: {action: refuse}

``action`` is ``refuse``, ``mask`` or ``off``. A Detector left out of the file, or no
file at all, is ``refuse``: the proxy never starts with a check silently missing. A
file the loader can't use stops the proxy; its message names the path and the key,
never a value or any of the file's contents.

``mask`` (#66, ADR-0001) forwards the request with each hit replaced by a Placeholder
(``<PHONE_NUMBER_1>``), on the API lane only: the Subscription lane refuses instead.
``deny_list`` can't mask: its hits are hashes of normalised words, with no place in
the text to put a Placeholder.

``national_id.countries`` picks the countries whose ID numbers are checked (default:
``DEFAULT_COUNTRIES``; any key of ``COUNTRIES``). ``phone.regions`` adds each listed country's national format
("070-123 45 67" for SE) to the international one ("+46 70 123 45 67"), which is
always read; ``phone.match`` is ``grouped`` (any valid number written with a "+" or
a separator, never a bare run of digits) or ``valid`` (any valid number).
"""

from dataclasses import dataclass, field
from pathlib import Path

import phonenumbers
import yaml

REFUSE = "refuse"
MASK = "mask"
OFF = "off"
ACTIONS = (REFUSE, MASK, OFF)
# The Detectors whose hits have a span in the text, so a Placeholder can replace them.
MASKABLE = frozenset({"national_id", "phone", "card", "iban"})

# The national ID types each country's Detector reads (#65): Presidio's recognisers
# that check a checksum or reject invalid numbers. Those with no validation (UK_NINO,
# US_ITIN, SG_NRIC_FIN, KR_FRN, IN_PAN, PH_UMID) are left out: they would refuse
# coding traffic.
COUNTRIES: dict[str, tuple[str, ...]] = {
    "SE": ("SE_PERSONNUMMER",),
    "FI": ("FI_PERSONAL_IDENTITY_CODE",),
    "DE": ("DE_TAX_ID", "DE_SOCIAL_SECURITY"),
    "GB": ("UK_NHS",),
    "US": ("US_SSN",),
    "PL": ("PL_PESEL",),
    "ES": ("ES_NIF", "ES_NIE"),
    "IT": ("IT_FISCAL_CODE",),
    "CA": ("CA_SIN",),
    "AU": ("AU_TFN", "AU_MEDICARE"),
    "IN": ("IN_AADHAAR",),
    "KR": ("KR_RRN",),
    "TH": ("TH_TNIN",),
    "TR": ("TR_NATIONAL_ID",),
    "ZA": ("ZA_ID_NUMBER",),
    "NG": ("NG_NIN",),
}

# Each Detector's entity types, other than ``national_id``'s, which its countries
# pick. ``deny_list`` has none: it isn't Presidio's.
DETECTORS: dict[str, tuple[str, ...]] = {
    "national_id": (),
    "phone": ("PHONE_NUMBER",),
    "card": ("CREDIT_CARD",),
    "iban": ("IBAN_CODE",),
    "deny_list": (),
}

# How a phone must be written to count (#64).
GROUPED = "grouped"
VALID = "valid"
MATCHES = (GROUPED, VALID)

# The keys each Detector's rule may hold besides ``action``.
_OPTIONS = {"national_id": {"countries"}, "phone": {"regions", "match"}}


# The countries read with no Policy file (decided on #65, 2026-11-15): those whose
# IDs don't read as code numbers. FI, ES and IT need letters; ZA needs a valid birth
# date plus Luhn. Together they add at most 0.1 points to SE alone on random code
# numbers (ids, timestamps). Each of the other 11 refuses 8-99% of bare code numbers
# of its ID's length (a random 9-digit number passes US_SSN 99% of the time), so
# they are opt-in.
DEFAULT_COUNTRIES = ("SE", "FI", "ES", "IT", "ZA")


@dataclass(frozen=True)
class NationalId:
    """Which countries' ID numbers ``national_id`` reads."""

    countries: tuple[str, ...] = DEFAULT_COUNTRIES


@dataclass(frozen=True)
class Phone:
    """Which national formats ``phone`` reads, and how a number must be written."""

    regions: tuple[str, ...] = ()
    match: str = GROUPED


class PolicyError(ValueError):
    """The Policy file isn't usable. The message names a key, never a value."""


@dataclass(frozen=True)
class Policy:
    """What each Detector does; ``actions`` holds every Detector in ``DETECTORS``."""

    actions: tuple[tuple[str, str], ...]
    national_id: NationalId = field(default_factory=NationalId)
    phone: Phone = field(default_factory=Phone)

    @classmethod
    def default(cls) -> "Policy":
        """Every Detector on and refusing: what the proxy does with no Policy file."""
        return cls(tuple((name, REFUSE) for name in DETECTORS))

    @classmethod
    def load(cls, path: Path) -> "Policy":
        """Read ``path``; anything unusable raises ``PolicyError`` (or ``OSError``)."""
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            # A YAML error quotes the line it stopped at: say only that it didn't parse.
            raise PolicyError("it is not valid YAML") from error
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: object) -> "Policy":
        if data is None:
            return cls.default()
        if not isinstance(data, dict):
            raise PolicyError("the top level must be a mapping")
        for key in data:
            if key != "detectors":
                raise PolicyError(f"unknown key {_name(key)!r}")
        detectors = data.get("detectors")
        if detectors is None:
            detectors = {}
        if not isinstance(detectors, dict):
            raise PolicyError("detectors must be a mapping")
        actions = dict.fromkeys(DETECTORS, REFUSE)
        national_id = NationalId()
        phone = Phone()
        for name, rule in detectors.items():
            if name not in DETECTORS:
                raise PolicyError(f"unknown Detector {_name(name)!r} under detectors")
            if not isinstance(rule, dict):
                raise PolicyError(f"detectors.{name} must be a mapping")
            allowed = {"action"} | _OPTIONS.get(name, set())
            for key in rule:
                if key not in allowed:
                    raise PolicyError(f"unknown key {_name(key)!r} under detectors.{name}")
            if "action" in rule:
                # YAML 1.1, which PyYAML reads, turns a bare ``off`` into False.
                if rule["action"] is False:
                    rule = {**rule, "action": OFF}
                allowed_actions = [a for a in ACTIONS if a != MASK or name in MASKABLE]
                if rule["action"] not in allowed_actions:
                    raise PolicyError(
                        f"detectors.{name}.action must be one of {', '.join(allowed_actions)}"
                    )
                actions[name] = rule["action"]
            if "countries" in rule:
                national_id = NationalId(_countries(rule["countries"]))
            if name == "phone":
                phone = Phone(_regions(rule.get("regions", [])), _match(rule.get("match", GROUPED)))
        return cls(tuple(actions.items()), national_id, phone)

    def on(self, name: str) -> bool:
        """Whether the Detector ``name`` runs."""
        return dict(self.actions)[name] != OFF

    def on_names(self) -> list[str]:
        """The Detectors that run, by kind only."""
        return [name for name, action in self.actions if action != OFF]

    def masked_names(self) -> list[str]:
        """The Detectors set to Masking, by kind only."""
        return [name for name, action in self.actions if action == MASK]

    def masked_entities(self) -> frozenset[str]:
        """The entity types whose hits are masked on the API lane."""
        return frozenset(self._entities(self.masked_names()))

    def entities(self) -> tuple[str, ...]:
        """The Presidio entity types that run."""
        return self._entities(self.on_names())

    def _entities(self, names: list[str]) -> tuple[str, ...]:
        found: list[str] = []
        for name in names:
            if name == "national_id":
                found.extend(e for c in self.national_id.countries for e in COUNTRIES[c])
            else:
                found.extend(DETECTORS[name])
        return tuple(dict.fromkeys(found))


def _name(key: object) -> str:
    # A key is the Operator's own word, but a non-string one is shown by its type.
    return key if isinstance(key, str) else type(key).__name__


def _countries(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError("detectors.national_id.countries must be a non-empty list")
    for country in value:
        if not isinstance(country, str) or country not in COUNTRIES:
            raise PolicyError(
                f"detectors.national_id.countries holds an unknown country; known: "
                f"{', '.join(COUNTRIES)}"
            )
    return tuple(dict.fromkeys(value))


def _regions(value: object) -> tuple[str, ...]:
    # An empty list is the default: "+" numbers only, for any country.
    if not isinstance(value, list):
        raise PolicyError("detectors.phone.regions must be a list")
    for region in value:
        if not isinstance(region, str) or region not in phonenumbers.SUPPORTED_REGIONS:
            raise PolicyError(
                "detectors.phone.regions holds an unknown region; use ISO 3166 alpha-2 "
                "codes in capitals, such as SE"
            )
    return tuple(dict.fromkeys(value))


def _match(value: object) -> str:
    if value not in MATCHES:
        raise PolicyError(f"detectors.phone.match must be one of {', '.join(MATCHES)}")
    return value
