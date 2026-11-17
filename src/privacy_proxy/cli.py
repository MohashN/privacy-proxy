"""``privacy-proxy``: serve the proxy with uvicorn, hash the Operator's deny-list, or mint a proxy key."""

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from privacy_proxy.apilane import (
    PROVIDERS_FILE,
    ApiLane,
    ConfigError,
    Keys,
    Providers,
    Spend,
    hash_key,
    new_key,
)
from privacy_proxy.app import create_app
from privacy_proxy.detection import Denylist, Scanner, read_entries
from privacy_proxy.policy import Policy, PolicyError


def hash_denylist(plain: Path, out: Path) -> None:
    """Write ``out`` as ``{salt, hashes, firsts}`` from ``plain``, one entry per line.

    The plain file is the Operator's and never enters the repo; only ``out`` goes to
    the proxy.
    """
    try:
        hashed = Denylist.build(read_entries(plain.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        sys.exit(f"privacy-proxy: {error}")
    out.write_text(json.dumps(hashed, indent=2) + "\n", encoding="utf-8")
    print(f"privacy-proxy: wrote {len(hashed['hashes'])} hashed entries to {out}")


def print_new_key(name: str) -> None:
    """Print a fresh proxy key, once, and the ``keys.yaml`` entry that holds only its hash."""
    key = new_key()
    print(f"proxy key (shown once; give it to the caller, keep no copy): {key}")
    # From "keys:" down is a whole keys.yaml; to add to one, paste the lines below it.
    print("keys.yaml (fill in models and the cap; to add to a file, skip the keys: line):")
    print("keys:")
    print(f"  - name: {json.dumps(name)}")
    print(f"    sha256: {hash_key(key)}")
    print("    models: []")
    print("    monthly_cap_usd: 0")


def _load(label: str, path: Path, load):
    try:
        return load(path)
    except ConfigError as error:
        # Names the entry, never a value: safe to print, and says what to fix.
        sys.exit(f"privacy-proxy: the {label} file at {path} is not usable: {error}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        # The error's type and the path only, as for the deny-list.
        sys.exit(f"privacy-proxy: can't read the {label} file at {path} ({type(error).__name__})")


def load_api_lane() -> ApiLane | None:
    """The API lane from ``KEYS_PATH``; unset, the lane refuses every proxy key.

    Once ``KEYS_PATH`` is set, an unreadable keys, providers or spend file stops the
    proxy from starting: a lane that can't check caps must not serve.
    """
    keys_path = os.environ.get("KEYS_PATH")
    if not keys_path:
        return None
    providers_path = Path(os.environ.get("PROVIDERS_PATH") or PROVIDERS_FILE)
    spend_path = os.environ.get("SPEND_DB_PATH")
    if not spend_path:
        sys.exit("privacy-proxy: KEYS_PATH is set but SPEND_DB_PATH is not; refusing to start")
    keys = _load("keys", Path(keys_path), Keys.load)
    providers = _load("providers", providers_path, Providers.load)
    try:
        spend = Spend(spend_path)
    except Exception as error:  # noqa: BLE001 -- sqlite3 raises several kinds
        sys.exit(
            f"privacy-proxy: can't open the spend database at {spend_path} ({type(error).__name__})"
        )
    # Only the provider keys are read from the environment, nothing else.
    secrets = {env: os.environ[env] for env in providers.key_envs if os.environ.get(env)}
    return ApiLane(keys, providers, spend, secrets)


def load_policy() -> Policy:
    """The Policy from ``POLICY_PATH``; unset, every Detector is on and refuses.

    Set but unreadable or invalid, the proxy doesn't start: a Policy the Operator
    wrote and the proxy can't read must not quietly turn into another one.
    """
    path = os.environ.get("POLICY_PATH")
    if not path:
        return Policy.default()
    try:
        return Policy.load(Path(path))
    except PolicyError as error:
        # Names the key, never a value: safe to print, and says what to fix.
        sys.exit(f"privacy-proxy: the Policy file at {path} is not usable: {error}")
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit(f"privacy-proxy: can't read the Policy file at {path} ({type(error).__name__})")


def load_scanner() -> Scanner:
    """The Detectors the Policy has on, and the deny-list from ``DENYLIST_PATH`` if set.

    Unset, the proxy starts with no deny-list. Set but empty or unreadable, it
    doesn't: a broken mount or a blank variable must never silently drop a list the
    Operator meant to have.
    """
    policy = load_policy()
    path = os.environ.get("DENYLIST_PATH")
    denylist = None
    if path is not None and not path.strip():
        sys.exit("privacy-proxy: DENYLIST_PATH is set but empty; refusing to start")
    if path is not None:
        try:
            denylist = Denylist.load(Path(path))
        except (OSError, ValueError, KeyError, TypeError) as error:
            # The error's type and the path only: a parse error can quote the file.
            sys.exit(f"privacy-proxy: can't read the deny-list at {path} ({type(error).__name__})")
    else:
        print("privacy-proxy: no Deny-list loaded", file=sys.stderr)
    # With no deny-list loaded the deny-list check has nothing to run on: don't claim it.
    running = [n for n in policy.on_names() if n != "deny_list" or denylist is not None]
    print(f"privacy-proxy: Detectors on: {', '.join(running) or 'none'}", file=sys.stderr)
    masked = policy.masked_names()
    if masked:
        # ADR-0001: Masking is the API lane's alone, and the Operator is told so.
        print(
            f"privacy-proxy: Masking is set for {', '.join(masked)}; "
            "the Subscription lane refuses these instead",
            file=sys.stderr,
        )
    return Scanner(denylist, policy)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="privacy-proxy", description=__doc__)
    # Loopback until it is deliberately widened: the proxy has no authentication
    # of its own in the Subscription lane, and it carries the caller's login.
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    commands = parser.add_subparsers(dest="command")
    hashing = commands.add_parser(
        "hash-denylist", help="hash a plain deny-list (one entry per line) for DENYLIST_PATH"
    )
    hashing.add_argument("plain", type=Path)
    hashing.add_argument("out", type=Path)
    minting = commands.add_parser(
        "new-key", help="print a new proxy key for the API lane and its keys.yaml entry"
    )
    minting.add_argument("name")
    args = parser.parse_args(argv)

    if args.command == "hash-denylist":
        hash_denylist(args.plain, args.out)
        return
    if args.command == "new-key":
        print_new_key(args.name)
        return

    uvicorn.run(
        # Loaded before the port opens: a request is never served unchecked.
        create_app(load_scanner(), api=load_api_lane()),
        host=args.host,
        port=args.port,
        # The proxy writes its own metadata line per request; uvicorn's access
        # log would be a second, unvetted one.
        access_log=False,
        # Anthropic's own `server` and `date` pass through; uvicorn's would
        # duplicate them.
        server_header=False,
        date_header=False,
    )
