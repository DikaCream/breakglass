"""Shared helpers for AI Marketplace direct mode tests."""

import json
import sys
from datetime import datetime, timedelta, timezone

import pytest

# A fixed "now" for deterministic time travel. Unix 1767225600.
BASE_ISO = "2030-01-01T00:00:00Z"


def to_hex(addr_bytes):
    """Convert address bytes to checksummed hex matching contract output."""
    if hasattr(addr_bytes, "as_hex"):
        return addr_bytes.as_hex
    from genlayer.py.types import Address

    return Address(addr_bytes).as_hex


def addr(addr_bytes):
    """Build an Address object for TreeMap[Address, ...] lookups."""
    from genlayer.py.types import Address

    if isinstance(addr_bytes, Address):
        return addr_bytes
    return Address(addr_bytes)


def set_time(iso_str: str) -> None:
    """Advance the contract's view of block time.

    The direct VM's ``warp()`` does not refresh ``message_raw['datetime']``,
    which is what the contract's ``_now()`` reads, so we mutate it directly.
    """
    import genlayer.gl as gl

    gl.message_raw["datetime"] = iso_str


@pytest.fixture(autouse=True)
def _reset_block_time():
    """Keep block time deterministic across tests.

    ``genlayer.gl`` is imported once per session, so ``message_raw['datetime']``
    leaks between tests. Reset it to a fixed base before and after each test.
    """
    _reset()
    yield
    _reset()


def _reset():
    if "genlayer.gl" in sys.modules:
        gl = sys.modules["genlayer.gl"]
        if getattr(gl, "message_raw", None) is not None:
            gl.message_raw["datetime"] = BASE_ISO


GOOD_URL = "https://example.com/skill"
GOOD_DESCRIPTION = "A well-described skill that fetches web pages and returns structured JSON data."
# The content body every mock serves. Moderation pins it as the immutable
# content version, the purchase drift-check must still see it, and disputes
# adjudicate the pinned snapshot.
CONTENT_BODY = "Skill content: does the job."

# ---------------------------------------------------------------- Truth Bets
# Base block time is 2030-01-01T00:00:00Z (see BASE_ISO above).
BET_CLAIM = "Bitcoin closes above $100,000 USD on 2026-01-01."
EVIDENCE_URL = "https://example.com/evidence"
# Resolution one day after BASE_ISO, i.e. 2030-01-02T00:00:00Z.
RESOLUTION_ISO = "2030-01-02T00:00:00Z"


def iso_to_ts(iso_str: str) -> int:
    return int(
        datetime.fromisoformat(iso_str.replace("Z", "+00:00")).timestamp()
    )


RESOLUTION_TS = iso_to_ts(RESOLUTION_ISO)


def mock_resolution(vm, verdict="TRUE", reason="Claim is verifiably correct.", evidence_body="Evidence: on-chain data supports the claim."):
    """Mock the validator's web fetch and judge LLM for a Truth Bets resolution."""
    if evidence_body is not None:
        vm.mock_web(r".*example\.com.*", {"status": 200, "body": evidence_body})
    vm.mock_llm(
        r".*truth bet.*",
        json.dumps({"verdict": verdict, "reason": reason}),
    )


def create_bet(
    contract, vm, proposer, claim=BET_CLAIM, evidence_url="", stake=100,
    side="TRUE", resolution_ts=RESOLUTION_TS,
):
    """Proposer creates a bet with the exact stake; returns its int id."""
    vm.sender = proposer
    vm.value = stake
    bid = int(contract.create_bet(claim, evidence_url, resolution_ts, stake, side))
    vm.value = 0
    return bid


def funded_bet(contract, vm, proposer, acceptor, **kwargs):
    """Create a bet and have the acceptor match it; returns its int id."""
    stake = kwargs.get("stake", 100)
    bid = create_bet(contract, vm, proposer, **kwargs)
    vm.sender = acceptor
    vm.value = stake
    contract.accept_bet(bid)
    vm.value = 0
    return bid


# ---------------------------------------------------------------- SkillBadge
SKILL_SKILL = "solidity"
# A commit-pinned raw file (full 40-hex SHA) — the only form the contract
# accepts as evidence: the content is immutable, so validators read exactly
# what was claimed. The owner-proof file carries the holder's own address.
SKILL_SHA = "a" * 40
SKILL_OWNER = "example-dev"
SKILL_REPO = "contracts"
SKILL_EVIDENCE_URL = (
    f"https://raw.githubusercontent.com/{SKILL_OWNER}/{SKILL_REPO}/"
    f"{SKILL_SHA}/src/contract.sol"
)
SKILL_NOTE = "A documented Solidity project with tests, audits and a deployed contract."
# Body served for every mocked fetch; the judge LLM sees this as evidence.
SKILL_PAGE = "Solidity code, tests, audits, deployment addresses, README."
SKILL_PROOF_BODY = "skillbadge-owner-proof\nwallet: 0xSOMEADDRESS"


def skill_proof_url(holder, sha=SKILL_SHA, owner=SKILL_OWNER, repo=SKILL_REPO):
    """Owner-proof URL naming the holder's wallet, pinned to a commit."""
    return (
        f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/"
        f"skillbadge-verify/{to_hex(holder).lower()}.txt"
    )


def mock_verification(vm, verdict="VERIFIED", tier="silver", reason="Repo shows real, working Solidity.", body=SKILL_PAGE):
    """Mock the validator's web fetch and judge LLM for a SkillBadge verification."""
    vm.mock_web(r".*(github\.com|githubusercontent\.com).*", {"status": 200, "body": body})
    vm.mock_llm(
        r".*hiring panel.*",
        json.dumps({"verdict": verdict, "tier": tier, "reason": reason}),
    )


def claim_badge(contract, vm, holder, proof_url=None, evidence_url=SKILL_EVIDENCE_URL, skill=SKILL_SKILL, note=SKILL_NOTE):
    """Holder claims a skill with owner-proof + evidence; returns its int badge id."""
    if proof_url is None:
        proof_url = skill_proof_url(holder)
    vm.sender = holder
    return int(contract.claim_skill(proof_url, evidence_url, skill, note))


def verified_badge(contract, vm, holder, verdict="VERIFIED", tier="silver", **kwargs):
    """Claim a badge and verify it with a mocked verdict; returns its int id."""
    bid = claim_badge(contract, vm, holder, **kwargs)
    vm.sender = holder
    mock_verification(vm, verdict=verdict, tier=tier)
    contract.verify_badge(bid)
    vm.clear_mocks()
    return bid


def mock_moderation(vm, verdict="APPROVE", score=85, reason="Matches the description.", body=CONTENT_BODY):
    vm.mock_web(r".*example\.com.*", {"status": 200, "body": body})
    vm.mock_llm(
        r".*moderator.*",
        json.dumps({"verdict": verdict, "score": score, "reason": reason}),
    )


def mock_adjudication(vm, refund_pct=0, reason="Skill works as described."):
    # Adjudication reads the committed content snapshot stored on-chain; it no
    # longer fetches the (mutable) URL, so only the LLM verdict is mocked.
    vm.mock_llm(
        r".*arbitrator.*",
        json.dumps({"refund_pct": refund_pct, "reason": reason}),
    )


def submit_approved_skill(
    contract, vm, creator, title="Web Scraper", price=100, url=GOOD_URL,
    description=GOOD_DESCRIPTION, category="automation",
):
    """Submit a skill and have moderation approve it; returns its int id."""
    vm.sender = creator
    mock_moderation(vm)
    sid = int(contract.submit_skill(title, description, category, price, url))
    vm.clear_mocks()
    return sid


def purchase(contract, vm, buyer, skill_id, price=100, body=CONTENT_BODY):
    """Buyer pays exact price into escrow; returns the purchase id.

    purchase_skill re-verifies under consensus that the URL still serves the
    content version approved at moderation, so the same body must be mocked.
    """
    vm.sender = buyer
    vm.value = price
    vm.mock_web(r".*example\.com.*", {"status": 200, "body": body})
    pid = int(contract.purchase_skill(skill_id))
    vm.clear_mocks()
    vm.value = 0
    return pid


# ---------------------------------------------------------------- RainGuard
# Base block time is 2030-01-01T00:00:00Z (see BASE_ISO above). Policies cover
# the window RG_START_DATE..RG_END_DATE (2030-01-02..2030-01-06), which is
# entirely AFTER base time, so creation and buying happen strictly before the
# coverage begins (as the contract now requires) and before settlement.
RG_START_DATE = "2030-01-02"
RG_END_DATE = "2030-01-06"
# The daily values the weather mock serves. Sum of precipitation = 1.5 mm;
# max daily temperature = 31.5 C. Both metrics are requested in one fetch.
RG_PRECIP = [0.3, 0.2, 0.5, 0.4, 0.1]
RG_TEMPS = [29.0, 30.1, 31.5, 28.4, 30.2]
# Settlement is eligible the day after RG_END_DATE + 1h buffer
# (2030-01-07T01:00:00Z), which is what SETTLE_ELIGIBLE_ISO must clear.


def mock_weather(vm, precip=None, temps=None, lat="-6.2", lon="106.8", tz="GMT", tz_offset=0, days=None):
    """Mock the Open-Meteo archive response the validators fetch.

    Defaults echo what a real archive response carries: the requested
    coordinates, the UTC timezone (Open-Meteo labels UTC+0 "GMT"), the zero
    UTC offset, and one row per covered day for the exact dates. Pass
    ``days``/``lat``/``lon``/``tz``/``tz_offset`` to serve a wrong-but-plausible
    source for the settlement-validation tests.
    """
    if days is None:
        days = [f"2030-01-{d:02d}" for d in range(2, 7)]
    body = json.dumps(
        {
            "latitude": float(lat),
            "longitude": float(lon),
            "timezone": tz,
            "utc_offset_seconds": tz_offset,
            "daily": {
                "time": days,
                "precipitation_sum": precip if precip is not None else RG_PRECIP,
                "temperature_2m_max": temps if temps is not None else RG_TEMPS,
            },
        }
    )
    vm.mock_web(
        r".*archive-api\.open-meteo\.com.*", {"status": 200, "body": body}
    )


def create_policy(
    contract, vm, insurer, metric="rainfall", lat="-6.2", lon="106.8",
    start=RG_START_DATE, end=RG_END_DATE, threshold="2.0", condition="below",
    premium=100, payout=200,
):
    """Insurer creates a policy with the exact payout; returns its int id."""
    vm.sender = insurer
    vm.value = payout
    pid = int(contract.create_policy(
        metric, lat, lon, start, end, threshold, condition, premium, payout,
    ))
    vm.value = 0
    return pid


def funded_policy(contract, vm, insurer, buyer, **kwargs):
    """Create a policy and have the buyer purchase it; returns its int id."""
    premium = kwargs.get("premium", 100)
    pid = create_policy(contract, vm, insurer, **kwargs)
    vm.sender = buyer
    vm.value = premium
    contract.buy_policy(pid)
    vm.value = 0
    return pid
